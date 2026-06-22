from __future__ import annotations
import json, math, os, re, signal, subprocess, time
from pathlib import Path
from typing import Any

from nsec3_candidate_scheduler.arms.base import Arm, SliceResult
from nsec3_candidate_scheduler.hashcat.runner import build_hashcat_command, run_cmd
from nsec3_candidate_scheduler.hashcat.status import latest_summary
from nsec3_candidate_scheduler.logging_utils import append_jsonl, utc_now
from nsec3_candidate_scheduler.naming import safe_name
from nsec3_candidate_scheduler.arms.osint_common import extract_relative_osint_candidates

class SubfinderOsintArm(Arm):
    STATES = {'not_started', 'running', 'collecting_results', 'ready', 'exhausted', 'failed'}

    def __init__(self, name, arm_type, config):
        super().__init__(name, arm_type, config)
        self.warmup_eligible = False
        self.subfinder_binary = config.get('subfinder_binary', 'subfinder')
        self.domain = config['domain']
        self.domains_list = [self.domain]
        self.domains_arg = self.domain
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
        self.completion_event_emitted = False
        self._state_loaded = False

    def _ensure_paths(self, context):
        if self.state_dir is None:
            self.state_dir = Path(context.out_dir) / 'osint' / safe_name(self.name)
            self.state_dir.mkdir(parents=True, exist_ok=True)
            if self.wordlist_path is None:
                self.wordlist_path = self.state_dir / 'candidates.txt'
        if not self._state_loaded:
            self._load_state()
        return self.state_dir

    def _write_state(self):
        if not self.state_dir:
            return
        data = {'state': self.state, 'domains_list': self.domains_list, 'domains_arg': self.domains_arg,
                'first_run_pending': self.first_run_pending, 'completion_event_emitted': self.completion_event_emitted, 'pid': self.process.pid if self.process else None,
                **self.metrics}
        (self.state_dir / 'state.json').write_text(json.dumps(data, indent=2), encoding='utf-8')
        (self.state_dir / 'subfinder.status.json').write_text(json.dumps(data, indent=2), encoding='utf-8')

    def _load_state(self):
        self._state_loaded = True
        if not self.state_dir:
            return
        path = self.state_dir / 'state.json'
        if not path.exists():
            return
        try:
            data = json.loads(path.read_text(encoding='utf-8'))
        except (OSError, json.JSONDecodeError):
            return
        self.completion_event_emitted = bool(data.get('completion_event_emitted', False))
        if data.get('state') in self.STATES and self.completion_event_emitted:
            self.state = data['state']
            self.first_run_pending = bool(data.get('first_run_pending', False))
            self.metrics.update({k: v for k, v in data.items() if k.startswith('osint_') or k == 'candidates_generated_by_domain'})
            if self.state in {'exhausted', 'failed'}:
                self.exhausted = True

    def _emit_osint_completed_event(self, context, *, status: str, exit_code: int | None, reason: str | None,
                                    raw_names_total: int | None = None, candidates_written: int = 0,
                                    wordlist: Path | None = None, raw_names: Path | None = None,
                                    stderr: Path | None = None) -> None:
        if self.completion_event_emitted:
            return
        raw_total = raw_names_total if raw_names_total is not None else self.metrics.get('osint_raw_names_total')
        written = candidates_written if candidates_written is not None else int(self.metrics.get('osint_candidates_written', 0) or 0)
        wordlist_s = str(wordlist) if wordlist is not None else None
        raw_s = str(raw_names) if raw_names is not None else None
        stderr_s = str(stderr) if stderr is not None else None
        rejected = max(0, int(raw_total) - int(written)) if isinstance(raw_total, int) else None
        if status == 'ready':
            print(f'[osint] {self.name} completed status=ready raw={raw_total} candidates={written} wordlist={wordlist_s}', flush=True)
        elif status == 'exhausted':
            extra = f' rejected={rejected}' if rejected else ''
            print(f'[osint] {self.name} completed status=exhausted raw={raw_total} candidates=0{extra} reason={reason} raw_names={raw_s}', flush=True)
        else:
            print(f'[osint] {self.name} completed status=failed exit_code={exit_code} reason={reason} stderr={stderr_s}', flush=True)
        append_jsonl(os.path.join(context.out_dir, 'jobs.jsonl'), {
            'timestamp': utc_now(), 'event': 'osint_completed', 'arm': self.name, 'arm_type': self.type,
            'status': status, 'raw_names_total': raw_total, 'candidates_written': written,
            'candidates_deduped': self.metrics.get('osint_candidates_deduped') if status == 'ready' else (rejected if status == 'exhausted' else None),
            'wordlist': wordlist_s, 'raw_names': raw_s, 'stderr': stderr_s,
            'exit_code': exit_code, 'reason': reason,
        })
        self.completion_event_emitted = True
        self._write_state()

    def start(self, context):
        self._ensure_paths(context)
        if self.state != 'not_started' or not self.start_on_run_start:
            return
        log = open(self.state_dir / 'subfinder.log', 'w', encoding='utf-8')
        err = open(self.state_dir / 'subfinder.err', 'w', encoding='utf-8')
        cmd = [self.subfinder_binary, '-silent', '-d', self.domain]
        self.process = subprocess.Popen(cmd, stdout=log, stderr=err, start_new_session=True)
        (self.state_dir / 'subfinder.pid').write_text(str(self.process.pid), encoding='utf-8')
        self.state = 'running'; self.metrics.update({'osint_process_started': True})
        self._write_state()
        print(f'[osint] {self.name} started subfinder for {self.domain}', flush=True)

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
            self.metrics.update({'osint_process_failed': True, 'osint_exit_code': rc, 'osint_stderr_path': str(self.state_dir / 'subfinder.err')})
            self._emit_osint_completed_event(context, status='failed', exit_code=rc, reason='process_exit_nonzero',
                                             candidates_written=0, stderr=self.state_dir / 'subfinder.err')
            self._write_state(); return
        self.state = 'collecting_results'; self.metrics.update({'osint_process_completed': True}); self._write_state()
        self._collect_results(context)

    def _collect_results(self, context):
        out = (self.state_dir / 'subfinder.log').read_text(encoding='utf-8') if (self.state_dir / 'subfinder.log').exists() else ''
        raw = [line.strip() for line in out.splitlines() if line.strip()]
        (self.state_dir / 'raw_names.txt').write_text('\n'.join(raw) + ('\n' if raw else ''), encoding='utf-8')
        maxc = self.config.get('max_candidates')
        cands, by_domain = extract_relative_osint_candidates(raw, self.domains_list,
            include_single_label=bool(self.config.get('include_single_label', True)),
            include_multi_label=bool(self.config.get('include_multi_label', True)),
            dedupe=bool(self.config.get('dedupe', True)), max_candidates=maxc)
        (self.state_dir / 'candidates.txt').write_text('\n'.join(cands) + ('\n' if cands else ''), encoding='utf-8')
        self.keyspace = len(cands)
        self.metrics.update({'osint_tool': 'subfinder', 'osint_domain': self.domain,
            'osint_subfinder_binary': self.subfinder_binary, 'osint_raw_names_total': len(raw),
            'osint_candidates_generated': len(cands), 'osint_candidates_written': len(cands),
            'osint_candidates_deduped': len(cands), 'candidates_generated_by_domain': by_domain,
            'osint_result_wordlist': str(self.state_dir / 'candidates.txt'), 'osint_state_dir': str(self.state_dir)})
        if cands:
            self.state = 'ready'; self.exhausted = False; self.first_run_pending = self.run_immediately_when_ready
            self._emit_osint_completed_event(context, status='ready', exit_code=0, reason=None,
                                             raw_names_total=len(raw), candidates_written=len(cands),
                                             wordlist=self.state_dir / 'candidates.txt', raw_names=self.state_dir / 'raw_names.txt',
                                             stderr=self.state_dir / 'subfinder.err')
        else:
            self.state = 'exhausted'; self.exhausted = True; self.first_run_pending = False
            self._emit_osint_completed_event(context, status='exhausted', exit_code=0, reason='no_candidates',
                                             raw_names_total=len(raw), candidates_written=0,
                                             raw_names=self.state_dir / 'raw_names.txt', stderr=self.state_dir / 'subfinder.err')
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
        return {'osint_state': self.state, 'osint_tool': 'subfinder', 'osint_domain': self.domain, 'osint_subfinder_binary': self.subfinder_binary, 'first_run_pending': self.first_run_pending,
                'run_immediately_when_ready': self.run_immediately_when_ready, **self.metrics}
