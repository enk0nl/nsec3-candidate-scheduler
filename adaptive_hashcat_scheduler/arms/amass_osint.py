from __future__ import annotations
import json, math, os, re, signal, subprocess, time
from pathlib import Path
from typing import Any

from adaptive_hashcat_scheduler.arms.base import Arm, SliceResult
from adaptive_hashcat_scheduler.feedback.normalize import normalize_dns_name
from adaptive_hashcat_scheduler.hashcat.runner import build_hashcat_command, run_cmd
from adaptive_hashcat_scheduler.hashcat.status import latest_summary

MIN_AMASS_VERSION = (5, 1, 1)


def parse_domains(value: Any) -> tuple[list[str], str]:
    if isinstance(value, str):
        raw = value.split(',')
    elif isinstance(value, list):
        raw = value
    else:
        raw = []
    domains: list[str] = []
    for item in raw:
        d = normalize_dns_name(str(item)) if item is not None else None
        if d and d not in domains:
            domains.append(d)
    return domains, ','.join(domains)


def extract_candidates(raw_names: list[str], domains_list: list[str], *, include_single_label: bool = True,
                       include_multi_label: bool = True, dedupe: bool = True,
                       max_candidates: int | None = None) -> tuple[list[str], dict[str, int]]:
    bases = sorted([d.rstrip('.').lower() for d in domains_list], key=len, reverse=True)
    seen: set[str] = set()
    out: list[str] = []
    by_domain = {d: 0 for d in bases}
    for raw in raw_names:
        name = normalize_dns_name(raw)
        if not name:
            continue
        matched = None
        for base in bases:
            if name == base:
                matched = base
                break
            if name.endswith('.' + base):
                matched = base
                cand = name[:-(len(base) + 1)]
                break
        else:
            continue
        if name == matched:
            continue
        cand = normalize_dns_name(cand)
        if not cand:
            continue
        labels = cand.count('.') + 1
        if labels == 1 and not include_single_label:
            continue
        if labels > 1 and not include_multi_label:
            continue
        if dedupe and cand in seen:
            continue
        seen.add(cand)
        out.append(cand)
        by_domain[matched] = by_domain.get(matched, 0) + 1
        if max_candidates is not None and len(out) >= int(max_candidates):
            break
    return out, by_domain


class AmassOsintArm(Arm):
    STATES = {'not_started', 'running', 'collecting_results', 'ready', 'exhausted', 'failed'}

    def __init__(self, name, arm_type, config):
        super().__init__(name, arm_type, config)
        self.warmup_eligible = False
        self.amass_binary = config.get('amass_binary', 'amass')
        self.domains_list = list(config['domains_list'])
        self.domains_arg = config['domains_arg']
        self.start_on_run_start = bool(config.get('start_on_run_start', True))
        self.poll_interval_seconds = float(config.get('poll_interval_seconds', 5))
        self.run_immediately_when_ready = bool(config.get('run_immediately_when_ready', True))
        self.keep_running_on_exit = bool(config.get('keep_running_on_exit', False))
        self.state = 'not_started'
        self.process: subprocess.Popen | None = None
        self.first_run_pending = False
        self.keyspace: int | None = None
        self.state_dir: Path | None = None
        self.wordlist_path: Path | None = None
        self._last_poll = 0.0
        self.metrics: dict[str, Any] = {}

    def _ensure_paths(self, context):
        if self.state_dir is None:
            self.state_dir = Path(context.out_dir) / 'osint' / self.name
            self.state_dir.mkdir(parents=True, exist_ok=True)
            if self.wordlist_path is None:
                self.wordlist_path = self.state_dir / 'candidates.txt'
        return self.state_dir

    def _write_state(self):
        if not self.state_dir:
            return
        data = {'state': self.state, 'domains_list': self.domains_list, 'domains_arg': self.domains_arg,
                'first_run_pending': self.first_run_pending, 'pid': self.process.pid if self.process else None,
                **self.metrics}
        (self.state_dir / 'state.json').write_text(json.dumps(data, indent=2), encoding='utf-8')
        (self.state_dir / 'amass.status.json').write_text(json.dumps(data, indent=2), encoding='utf-8')

    def start(self, context):
        self._ensure_paths(context)
        if self.state != 'not_started' or not self.start_on_run_start:
            return
        log = open(self.state_dir / 'amass.log', 'w', encoding='utf-8')
        err = open(self.state_dir / 'amass.err', 'w', encoding='utf-8')
        cmd = [self.amass_binary, 'enum', '-d', self.domains_arg]
        self.process = subprocess.Popen(cmd, stdout=log, stderr=err, start_new_session=True)
        (self.state_dir / 'amass.pid').write_text(str(self.process.pid), encoding='utf-8')
        self.state = 'running'; self.metrics.update({'osint_process_started': True})
        self._write_state()
        print(f'[osint] {self.name} started amass enum for {self.domains_arg}', flush=True)

    def poll(self, context):
        self._ensure_paths(context)
        if self.state != 'running' or self.process is None:
            return
        now = time.time()
        rc = self.process.poll()
        if rc is None:
            self.metrics.update({'osint_process_running': True})
            if now - self._last_poll >= self.poll_interval_seconds:
                self._last_poll = now
            self._write_state(); return
        if rc != 0:
            self.state = 'failed'; self.exhausted = True; self.first_run_pending = False
            self.metrics.update({'osint_process_failed': True, 'osint_exit_code': rc, 'osint_stderr_path': str(self.state_dir / 'amass.err')})
            self._write_state(); return
        self.state = 'collecting_results'; self.metrics.update({'osint_process_completed': True}); self._write_state()
        self._collect_results(context)

    def _collect_results(self, context):
        cmd = [self.amass_binary, 'subs', '-names', '-d', self.domains_arg]
        rc, out, err = run_cmd(cmd)
        if rc != 0:
            self.state = 'failed'; self.exhausted = True; self.first_run_pending = False
            self.metrics.update({'osint_subs_exit_code': rc, 'osint_subs_stderr': err})
            self._write_state(); return
        raw = [line.strip() for line in out.splitlines() if line.strip()]
        (self.state_dir / 'raw_names.txt').write_text('\n'.join(raw) + ('\n' if raw else ''), encoding='utf-8')
        maxc = self.config.get('max_candidates')
        cands, by_domain = extract_candidates(raw, self.domains_list,
            include_single_label=bool(self.config.get('include_single_label', True)),
            include_multi_label=bool(self.config.get('include_multi_label', True)),
            dedupe=bool(self.config.get('dedupe', True)), max_candidates=maxc)
        (self.state_dir / 'candidates.txt').write_text('\n'.join(cands) + ('\n' if cands else ''), encoding='utf-8')
        (self.state_dir / 'generated_candidates.txt').write_text('\n'.join(cands) + ('\n' if cands else ''), encoding='utf-8')
        self.keyspace = len(cands)
        self.metrics.update({'osint_domains': self.domains_list, 'osint_domains_arg': self.domains_arg,
            'osint_amass_binary': self.amass_binary, 'osint_raw_names_total': len(raw),
            'osint_candidates_generated': len(cands), 'osint_candidates_written': len(cands),
            'osint_candidates_deduped': len(cands), 'candidates_generated_by_domain': by_domain,
            'osint_result_wordlist': str(self.state_dir / 'candidates.txt'), 'osint_state_dir': str(self.state_dir)})
        if cands:
            self.state = 'ready'; self.exhausted = False; self.first_run_pending = self.run_immediately_when_ready
            print(f'[osint] {self.name} ready raw={len(raw)} candidates={len(cands)} wordlist={self.state_dir / "candidates.txt"} first_run_pending={str(self.first_run_pending).lower()}', flush=True)
        else:
            self.state = 'exhausted'; self.exhausted = True; self.first_run_pending = False
        self._write_state()

    def is_available(self, context):
        self.poll(context)
        return self.state == 'ready' and not self.exhausted and self.wordlist_path and self.wordlist_path.exists() and (self.keyspace is None or self.next_skip < self.keyspace)

    def run_slice(self, context):
        if not self.is_available(context):
            return SliceResult(executed=False, valid_work=False, execution_status=f'osint_{self.state}', extra=self.logging_fields())
        skip = self.next_skip
        cmd = build_hashcat_command(context.hashcat_bin, context.hash_mode, 0, context.slice_seconds, context.potfile, context.hashes,
                                    candidate=str(self.wordlist_path), skip=skip, limit=None,
                                    optimized_kernels=context.hashcat_optimized_kernels,
                                    potfile_path_override=getattr(context, 'potfile_path_override', None))
        rc, out, err = run_cmd(cmd); summ = latest_summary(out + '\n' + err)
        cursor = None; next_skip = skip; src = 'unknown'
        pc = summ.get('progress_cur'); salts = summ.get('recovered_salts_total')
        if isinstance(pc, int) and isinstance(salts, int) and salts > 0:
            cursor = math.floor(pc / salts)
        if isinstance(cursor, int) and cursor > skip:
            next_skip = min(cursor, self.keyspace or cursor); src = 'progress_scaled_by_salts'
        self.next_skip = next_skip
        if self.keyspace is not None and self.next_skip >= self.keyspace: self.exhausted = True
        if rc == 1: self.exhausted = True
        valid = rc in (0, 1, 4)
        if valid: self.first_run_pending = False
        return SliceResult(exit_code=rc, stdout=out, stderr=err, skip_before=skip, next_skip_after=next_skip,
                           progress_source=src, dictionary_candidate_cursor=cursor, exhausted=self.exhausted,
                           valid_work=valid, extra=self.logging_fields())

    def cleanup(self):
        if self.keep_running_on_exit:
            return
        if self.process is not None and self.process.poll() is None:
            try:
                self.process.terminate()
            except Exception:
                try: os.killpg(self.process.pid, signal.SIGTERM)
                except Exception: pass

    def logging_fields(self):
        return {'osint_state': self.state, 'first_run_pending': self.first_run_pending,
                'run_immediately_when_ready': self.run_immediately_when_ready, **self.metrics}


def parse_amass_version(text: str):
    m = re.search(r'(\d+)\.(\d+)\.(\d+)', text or '')
    return tuple(map(int, m.groups())) if m else None
