from __future__ import annotations

from adaptive_hashcat_scheduler.arms.base import Arm, SliceResult
from adaptive_hashcat_scheduler.hashcat.runner import build_hashcat_command, run_cmd
from adaptive_hashcat_scheduler.hashcat.status import latest_summary

_BUILTIN_CHARSET_SIZES = {
    'l': 26,
    'u': 26,
    'd': 10,
    'h': 16,
    'H': 16,
    's': 33,
    'a': 95,
    'b': 256,
}


class BruteForceArm(Arm):
    def __init__(self, name, arm_type, config):
        super().__init__(name, arm_type, config)
        self.masks = config.get('masks') or [config.get('mask')]
        self.current_mask_index = 0
        self.current_mask_skip = 0
        self.current_mask_keyspace = None
        self._mask_keyspaces: dict[int, int | None] = {}
        # Backwards-compatible aliases used by older callers/tests.
        self.mask_index = self.current_mask_index

    def charset_args(self):
        args = []
        for i in range(1, 5):
            v = self.config.get(f'custom_charset_{i}', self.config.get(f'custom_charset{i}'))
            if v is not None:
                args += [f'-{i}', str(v)]
        return args

    def is_available(self, context):
        return (not self.exhausted) and self.current_mask_index < len(self.masks)

    def _custom_charset_sizes(self) -> dict[str, int]:
        sizes = {}
        for i in range(1, 5):
            v = self.config.get(f'custom_charset_{i}', self.config.get(f'custom_charset{i}'))
            if v is not None:
                sizes[str(i)] = len(str(v))
        return sizes

    def _estimate_mask_keyspace(self, mask: str) -> int | None:
        custom_sizes = self._custom_charset_sizes()
        total = 1
        i = 0
        while i < len(mask):
            ch = mask[i]
            if ch != '?':
                total *= 1
                i += 1
                continue
            if i + 1 >= len(mask):
                return None
            token = mask[i + 1]
            if token == '?':
                total *= 1
            elif token in custom_sizes:
                total *= custom_sizes[token]
            elif token in _BUILTIN_CHARSET_SIZES:
                total *= _BUILTIN_CHARSET_SIZES[token]
            else:
                return None
            i += 2
        return total

    def _parse_keyspace_output(self, text: str) -> int | None:
        for raw in reversed(text.splitlines()):
            value = raw.strip()
            if value.isdigit():
                return int(value)
        return None

    def _load_mask_keyspace(self, context, mask: str) -> int | None:
        if self.current_mask_index in self._mask_keyspaces:
            return self._mask_keyspaces[self.current_mask_index]
        keyspace = self._estimate_mask_keyspace(mask)
        if keyspace is None:
            cmd = [context.hashcat_bin, '-m', str(context.hash_mode), '-a', '3', '--keyspace']
            cmd.extend(self.charset_args())
            cmd.append(mask)
            rc, out, err = run_cmd(cmd)
            if rc == 0:
                keyspace = self._parse_keyspace_output(out + '\n' + err)
        self._mask_keyspaces[self.current_mask_index] = keyspace
        return keyspace

    def _progress_from_status(self, output: str, skip_before: int, keyspace: int | None) -> tuple[int | None, str]:
        summ = latest_summary(output)
        salts = summ.get('recovered_salts_total')
        pc = summ.get('progress_cur')
        pt = summ.get('progress_total')
        rp = summ.get('restore_point')
        if isinstance(pc, int) and isinstance(salts, int) and salts > 0:
            scaled = pc // salts
            total_scaled = pt // salts if isinstance(pt, int) else None
            if keyspace is not None and total_scaled == keyspace and scaled > skip_before:
                return scaled, 'progress_scaled_by_salts_absolute'
            if scaled > 0:
                return skip_before + scaled, 'progress_scaled_by_salts_delta'
        if isinstance(pc, int) and isinstance(pt, int) and keyspace is not None and pt == keyspace and pc > skip_before:
            return pc, 'progress_absolute'
        if isinstance(rp, int) and rp > skip_before:
            return min(rp, keyspace) if keyspace is not None else rp, 'restore_point'
        return None, 'unknown'

    def _advance_to_next_mask(self) -> None:
        self.current_mask_index += 1
        self.mask_index = self.current_mask_index
        self.current_mask_skip = 0
        self.next_skip = 0
        self.current_mask_keyspace = None
        if self.current_mask_index >= len(self.masks):
            self.exhausted = True

    def run_slice(self, context):
        mask = self.masks[self.current_mask_index]
        keyspace = self._load_mask_keyspace(context, mask)
        self.current_mask_keyspace = keyspace
        skip_before = self.current_mask_skip
        limit = context.default_limit
        if keyspace is not None:
            remaining = max(0, keyspace - skip_before)
            limit = min(limit, remaining) if remaining else 0
        if limit == 0:
            self._advance_to_next_mask()
            return SliceResult(exit_code=1, stdout='', stderr='', skip_before=skip_before, next_skip_after=0,
                               progress_source='already_exhausted', exhausted=self.exhausted, extra={
                                   'brute_force_mask': mask,
                                   'brute_force_mask_index': self.current_mask_index - 1,
                                   'brute_force_mask_keyspace': keyspace,
                                   'brute_force_mask_skip_before': skip_before,
                                   'brute_force_mask_next_skip_after': 0,
                                   'brute_force_progress_source': 'already_exhausted',
                                   'brute_force_mask_exhausted': True,
                               })
        cmd = build_hashcat_command(
            context.hashcat_bin, context.hash_mode, 3, context.slice_seconds,
            context.potfile, context.hashes, candidate=mask, skip=skip_before,
            limit=limit, extra_args=self.charset_args(),
        )
        rc, out, err = run_cmd(cmd)
        progress_skip, progress_source = self._progress_from_status(out + '\n' + err, skip_before, keyspace)
        next_skip = skip_before
        mask_exhausted = False
        warning = None

        if rc == 1:
            if progress_skip is not None and progress_skip > skip_before:
                next_skip = progress_skip
            else:
                next_skip = skip_before + int(limit)
                progress_source = 'limit_completed'
            if keyspace is not None:
                next_skip = min(next_skip, keyspace)
                mask_exhausted = next_skip >= keyspace
            else:
                mask_exhausted = True
        elif rc == 4:
            if progress_skip is not None and progress_skip > skip_before:
                next_skip = min(progress_skip, keyspace) if keyspace is not None else progress_skip
            else:
                progress_source = 'unknown'
                warning = 'hashcat runtime reached but no reliable brute-force progress was reported; retaining previous skip'
        elif progress_skip is not None and progress_skip > skip_before:
            next_skip = min(progress_skip, keyspace) if keyspace is not None else progress_skip
            if keyspace is not None and next_skip >= keyspace:
                mask_exhausted = True

        if mask_exhausted:
            reported_next_skip = next_skip
            self._advance_to_next_mask()
        else:
            self.current_mask_skip = next_skip
            self.next_skip = next_skip
            reported_next_skip = next_skip

        return SliceResult(
            exit_code=rc, stdout=out, stderr=err, skip_before=skip_before,
            next_skip_after=reported_next_skip, progress_source=progress_source,
            dictionary_candidate_cursor=progress_skip, exhausted=self.exhausted, extra={
                'brute_force_mask': mask,
                'brute_force_mask_index': self.current_mask_index - 1 if mask_exhausted else self.current_mask_index,
                'brute_force_mask_keyspace': keyspace,
                'brute_force_mask_skip_before': skip_before,
                'brute_force_mask_next_skip_after': reported_next_skip,
                'brute_force_progress_source': progress_source,
                'brute_force_mask_exhausted': mask_exhausted,
                'brute_force_progress_warning': warning,
            },
        )
