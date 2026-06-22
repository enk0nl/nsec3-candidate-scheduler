from __future__ import annotations
import logging
import math
import os
from pathlib import Path

from adaptive_hashcat_scheduler.arms.base import Arm, SliceResult
from adaptive_hashcat_scheduler.hashcat.runner import build_hashcat_command, run_cmd
from adaptive_hashcat_scheduler.hashcat.status import latest_summary

LARGE_WORDLIST_SCAN_WARNING_BYTES = 1_073_741_824


def count_lines(path):
    with open(path, 'rb') as f:
        return sum(1 for _ in f)


class DictionaryArm(Arm):
    def __init__(self, name, arm_type, config):
        super().__init__(name, arm_type, config)
        self.wordlist_path = Path(config['wordlist'])
        self.wordlist_size = self._validate_wordlist_metadata(self.wordlist_path)
        self.count_candidates_at_startup = bool(config.get('count_candidates_at_startup', False))
        self.large_wordlist_scan_warning_bytes = int(
            config.get('large_wordlist_scan_warning_bytes', LARGE_WORDLIST_SCAN_WARNING_BYTES)
        )
        configured_count = config.get('candidate_count')
        self.candidate_count: int | None = None
        self.total_candidates: int | None = None
        self.candidate_count_source = 'unknown'
        if configured_count is not None:
            self.candidate_count = int(configured_count)
            self.total_candidates = self.candidate_count
            self.candidate_count_source = 'config'
        elif self.count_candidates_at_startup:
            if self.wordlist_size >= self.large_wordlist_scan_warning_bytes:
                logging.warning(
                    'Counting candidates for large wordlist may take a long time: %s size=%s',
                    self.wordlist_path,
                    self.wordlist_size,
                )
            self.candidate_count = count_lines(self.wordlist_path)
            self.total_candidates = self.candidate_count
            self.candidate_count_source = 'counted'
        self.keyspace = self.candidate_count
        if self._should_log_startup_metadata():
            candidate_count_log = self.candidate_count if self.candidate_count is not None else 'unknown'
            print(
                f'[arm] name={self.name} type={self.type} wordlist={self.wordlist_path} '
                f'size={self.wordlist_size} candidate_count={candidate_count_log} '
                f'candidate_count_source={self.candidate_count_source} '
                f'count_candidates_at_startup={str(self.count_candidates_at_startup).lower()}',
                flush=True,
            )

    def _should_log_startup_metadata(self) -> bool:
        return any(bool(self.config.get(key, False)) for key in ('verbose', 'debug', 'debug_startup', 'debug_arms'))

    @staticmethod
    def _validate_wordlist_metadata(path: Path) -> int:
        try:
            st = path.stat()
        except FileNotFoundError as exc:
            raise ValueError(f'wordlist path does not exist: {path}') from exc
        if not path.is_file():
            raise ValueError(f'wordlist path is not a regular file: {path}')
        if not os.access(path, os.R_OK):
            raise ValueError(f'wordlist path is not readable: {path}')
        if st.st_size <= 0:
            raise ValueError(f'wordlist file is empty: {path}')
        return st.st_size

    def is_available(self, context):
        return (not self.exhausted) and (self.keyspace is None or self.next_skip < self.keyspace)

    def run_slice(self, context):
        skip = self.next_skip
        cmd = build_hashcat_command(
            context.hashcat_bin, context.hash_mode, 0, context.slice_seconds, context.potfile,
            context.hashes, candidate=self.config['wordlist'], skip=skip, limit=None,
            optimized_kernels=context.hashcat_optimized_kernels,
            potfile_path_override=getattr(context, 'potfile_path_override', None),
        )
        rc, out, err = run_cmd(cmd)
        summ = latest_summary(out + '\n' + err)
        cursor = None
        next_skip = skip
        src = 'unknown'
        pc = summ.get('progress_cur')
        salts = summ.get('recovered_salts_total')
        if isinstance(pc, int) and isinstance(salts, int) and salts > 0:
            cursor = math.floor(pc / salts)
        if isinstance(cursor, int) and cursor > skip:
            next_skip = min(cursor, self.keyspace) if self.keyspace is not None else cursor
            src = 'progress_scaled_by_salts'
        self.next_skip = next_skip
        if self.keyspace is not None and self.next_skip >= self.keyspace:
            self.exhausted = True
        if rc == 1:
            self.exhausted = True
        return SliceResult(
            exit_code=rc, stdout=out, stderr=err, skip_before=skip, next_skip_after=next_skip,
            progress_source=src, dictionary_candidate_cursor=cursor, exhausted=self.exhausted,
        )
