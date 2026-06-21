from __future__ import annotations

import math
import os

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
        self.current_mask_text = self.masks[0] if self.masks else None
        self._mask_keyspaces: dict[int, int | None] = {}
        self._mask_cursors: dict[tuple[int, str], int] = {}
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
                i += 1
                continue
            if i + 1 >= len(mask):
                return None
            token = mask[i + 1]
            if token == '?':
                pass
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
        keyspace = None
        cmd = [context.hashcat_bin, '-m', str(context.hash_mode), '-a', '3', '--keyspace']
        cmd.extend(self.charset_args())
        cmd.append(mask)
        rc, out, err = run_cmd(cmd)
        if rc == 0:
            keyspace = self._parse_keyspace_output(out + '\n' + err)
        if keyspace is None:
            keyspace = self._estimate_mask_keyspace(mask)
        self._mask_keyspaces[self.current_mask_index] = keyspace
        return keyspace

    def _configured_limit(self, context) -> int:
        return int(self.config.get('limit', self.config.get('chunk_size', context.default_limit)))

    def _cursor_key(self, index: int, mask: str) -> tuple[int, str]:
        return (index, mask)

    def _load_current_cursor(self, mask: str) -> tuple[int, str | None]:
        key = self._cursor_key(self.current_mask_index, mask)
        warning = None
        if self.current_mask_text != mask:
            self.current_mask_skip = self._mask_cursors.get(key, 0)
            self.current_mask_text = mask
            warning = 'mask_changed_cursor_reset'
        elif key in self._mask_cursors:
            self.current_mask_skip = self._mask_cursors[key]
        return self.current_mask_skip, warning

    def _store_current_cursor(self, mask: str, skip: int) -> None:
        self.current_mask_skip = skip
        self.next_skip = skip
        self.current_mask_text = mask
        self._mask_cursors[self._cursor_key(self.current_mask_index, mask)] = skip

    def _progress_from_status(self, output: str, skip_before: int, keyspace: int, runtime_reached: bool) -> tuple[int | None, str, str | None]:
        summ = latest_summary(output)
        pc = summ.get('progress_cur')
        pt = summ.get('progress_total')
        rp = summ.get('restore_point')
        if isinstance(pc, int) and isinstance(pt, int) and pt > 0:
            scaled = math.floor((pc / pt) * keyspace)
            scaled = max(0, min(scaled, keyspace))
            if runtime_reached and scaled <= skip_before:
                return skip_before, 'progress_scaled_to_keyspace_non_advancing', 'non_advancing_progress'
            return scaled, 'progress_scaled_to_keyspace', None
        if isinstance(rp, int) and rp > skip_before:
            return max(0, min(rp, keyspace)), 'restore_point', None
        if runtime_reached:
            return skip_before, 'unknown', 'non_advancing_progress'
        return None, 'unknown', None

    def _advance_to_next_mask(self) -> None:
        self.current_mask_index += 1
        self.mask_index = self.current_mask_index
        self.current_mask_skip = 0
        self.next_skip = 0
        self.current_mask_keyspace = None
        self.current_mask_text = self.masks[self.current_mask_index] if self.current_mask_index < len(self.masks) else None
        if self.current_mask_index >= len(self.masks):
            self.exhausted = True

    def _prepare_runnable_mask(self, context) -> dict:
        skipped = []
        cursor_warning = None
        while self.current_mask_index < len(self.masks):
            mask = self.masks[self.current_mask_index]
            keyspace = self._load_mask_keyspace(context, mask)
            self.current_mask_keyspace = keyspace
            skip, mask_warning = self._load_current_cursor(mask)
            cursor_warning = cursor_warning or mask_warning
            if skip < 0:
                skip = 0
                cursor_warning = 'negative_skip_reset'
                self._store_current_cursor(mask, skip)
            if keyspace is None or keyspace <= 0:
                raise RuntimeError(f'Unable to determine positive keyspace for brute-force mask: {mask}')
            if skip >= keyspace:
                skipped.append({
                    'mask': mask,
                    'mask_index': self.current_mask_index,
                    'keyspace': keyspace,
                    'skip': skip,
                    'reason': 'cursor_at_or_beyond_keyspace',
                    'cursor_warning': 'skip_greater_than_keyspace' if skip > keyspace else None,
                })
                self._advance_to_next_mask()
                continue
            remaining = keyspace - skip
            configured_limit = self._configured_limit(context)
            limit = min(configured_limit, remaining)
            if limit <= 0:
                skipped.append({
                    'mask': mask,
                    'mask_index': self.current_mask_index,
                    'keyspace': keyspace,
                    'skip': skip,
                    'reason': 'non_positive_limit',
                    'cursor_warning': None,
                })
                self._advance_to_next_mask()
                continue
            if not (0 <= skip < keyspace and 1 <= limit <= remaining):
                raise RuntimeError(f'Invalid brute-force cursor state for mask {mask}: skip={skip}, keyspace={keyspace}, limit={limit}')
            return {
                'mask': mask,
                'mask_index': self.current_mask_index,
                'keyspace': keyspace,
                'skip': skip,
                'remaining': remaining,
                'limit': limit,
                'cursor_valid': True,
                'cursor_warning': cursor_warning,
                'skipped': skipped,
            }
        self.exhausted = True
        return {'cursor_valid': False, 'skipped': skipped}

    def _session_name(self, mask_index: int) -> str:
        safe_arm = ''.join(ch if ch.isalnum() else '_' for ch in self.name)
        return f'adaptive_{os.getpid()}_{self.runs + 1}_{safe_arm}_{mask_index}'

    def run_slice(self, context):
        state = self._prepare_runnable_mask(context)
        if not state.get('cursor_valid'):
            return SliceResult(exit_code=1, stdout='', stderr='', skip_before=0, next_skip_after=0,
                               progress_source='no_runnable_mask', exhausted=self.exhausted, extra={
                                   'brute_force_cursor_valid': False,
                                   'brute_force_prelaunch_skipped_masks': state.get('skipped', []),
                               })
        mask = state['mask']
        mask_index = state['mask_index']
        keyspace = state['keyspace']
        skip_before = state['skip']
        limit = state['limit']
        cmd = build_hashcat_command(
            context.hashcat_bin, context.hash_mode, 3, context.slice_seconds,
            context.potfile, context.hashes, candidate=mask, skip=skip_before,
            limit=limit, extra_args=[*self.charset_args(), '--session', self._session_name(mask_index)],
        )
        rc, out, err = run_cmd(cmd)
        runtime_reached = rc == 4
        progress_skip, progress_source, progress_warning = self._progress_from_status(out + '\n' + err, skip_before, keyspace, runtime_reached)
        next_skip = skip_before
        mask_exhausted = False
        advance_reason = None

        if rc == 1:
            next_skip = progress_skip if progress_skip is not None and progress_skip > skip_before else skip_before + int(limit)
            progress_source = progress_source if progress_skip is not None and progress_skip > skip_before else 'limit_completed'
        elif progress_skip is not None:
            next_skip = progress_skip

        next_skip = max(skip_before, min(next_skip, keyspace))
        if next_skip >= keyspace:
            mask_exhausted = True
            advance_reason = 'cursor_at_or_beyond_keyspace' if skip_before >= keyspace else 'mask_keyspace_reached'

        reported_next_skip = next_skip
        if mask_exhausted:
            self._advance_to_next_mask()
        else:
            self._store_current_cursor(mask, next_skip)

        return SliceResult(
            exit_code=rc, stdout=out, stderr=err, skip_before=skip_before,
            next_skip_after=reported_next_skip, progress_source=progress_source,
            dictionary_candidate_cursor=progress_skip, exhausted=self.exhausted, extra={
                'brute_force_mask': mask,
                'brute_force_mask_index': mask_index,
                'brute_force_mask_keyspace': keyspace,
                'brute_force_mask_skip_before': skip_before,
                'brute_force_mask_remaining': state['remaining'],
                'brute_force_effective_limit': limit,
                'brute_force_cursor_valid': True,
                'brute_force_mask_next_skip_after': reported_next_skip,
                'brute_force_progress_source': progress_source,
                'brute_force_mask_exhausted': mask_exhausted,
                'brute_force_advance_reason': advance_reason,
                'brute_force_cursor_warning': state.get('cursor_warning'),
                'brute_force_progress_warning': progress_warning,
                'brute_force_prelaunch_skipped_masks': state.get('skipped', []),
            },
        )
