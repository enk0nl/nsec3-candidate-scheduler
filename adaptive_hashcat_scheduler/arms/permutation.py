from __future__ import annotations

import itertools
import json
import re
from pathlib import Path
from typing import Any, Iterable

from adaptive_hashcat_scheduler.arms.base import Arm, SliceResult
from adaptive_hashcat_scheduler.feedback.normalize import normalize_dns_name
from adaptive_hashcat_scheduler.feedback.queue import FeedbackQueueState
from adaptive_hashcat_scheduler.feedback.execution import run_feedback_dictionary_slice

_PATTERNS = [
    re.compile(r'^([a-z][a-z-]*[a-z])([-_])([0-9]+)$'),
    re.compile(r'^([a-z]+)([-_])([0-9]+)$'),
    re.compile(r'^([a-z]+)([0-9]+)$'),
    re.compile(r'^([0-9]+)([-_])([a-z]+)$'),
    re.compile(r'^([0-9]+)([a-z]+)$'),
]


class PermutationArm(Arm):
    """Combined feedback arm for structure-preserving numeric and alpha permutations."""

    def __init__(self, name: str, arm_type: str, config: dict[str, Any]):
        super().__init__(name=name, type=arm_type, config=config)
        self.queue_state: FeedbackQueueState | None = None
        self.warmup_eligible = False
        self.last_expansion = self._empty_metrics()

    def _numeric_config(self) -> dict[str, Any]:
        cfg = {
            'enabled': True,
            'min_width': 1,
            'max_width': 3,
            'generate_full_range': True,
            'generate_width_variants': True,
            'generate_local_radius': True,
            'allow_wider_width_variants': False,
            'allow_large_numeric_ranges': False,
            'local_radius': 50,
        }
        cfg.update(self.config.get('numeric') or {})
        return cfg

    def _alpha_config(self) -> dict[str, Any]:
        cfg = {
            'enabled': False,
            'charset': 'abcdefghijklmnopqrstuvwxyz',
            'min_width': 1,
            'max_width': 3,
            'generate_full_range': True,
            'generate_width_variants': True,
            'allow_wider_width_variants': False,
            'allow_large_alpha_ranges': False,
            'require_numeric_context': True,
        }
        cfg.update(self.config.get('alpha') or {})
        return cfg

    def _queue(self, context) -> FeedbackQueueState:
        if self.queue_state is None or str(self.queue_state.out_dir) != context.out_dir:
            self.queue_state = FeedbackQueueState(context.out_dir, self.name, self.config)
            self._cursor_path(context).touch(exist_ok=True)
            if self._cursor_path(context).stat().st_size == 0:
                self._write_cursor(context, {'pending_numeric_streams': 0, 'pending_alpha_streams': 0})
        return self.queue_state

    def _cursor_path(self, context) -> Path:
        if self.queue_state is not None and str(self.queue_state.out_dir) == context.out_dir:
            return self.queue_state.root / 'cursor.json'
        from adaptive_hashcat_scheduler.naming import safe_name
        return Path(context.out_dir) / 'feedback' / safe_name(self.name) / 'cursor.json'

    def _read_cursor(self, context) -> dict[str, Any]:
        path = self._cursor_path(context)
        if not path.exists() or path.stat().st_size == 0:
            return {'pending_numeric_streams': 0, 'pending_alpha_streams': 0}
        try:
            with path.open('r', encoding='utf-8') as f:
                data = json.load(f)
            if isinstance(data, dict):
                return data
        except (OSError, json.JSONDecodeError):
            pass
        return {'pending_numeric_streams': 0, 'pending_alpha_streams': 0}

    def _write_cursor(self, context, data: dict[str, Any]) -> None:
        self._cursor_path(context).write_text(json.dumps(data, separators=(',', ':')) + '\n', encoding='utf-8')

    def _empty_metrics(self) -> dict[str, int]:
        return {
            'permutation_patterns_matched': 0,
            'numeric_candidates_generated': 0,
            'numeric_candidates_enqueued': 0,
            'alpha_candidates_generated': 0,
            'alpha_candidates_enqueued': 0,
            'numeric_duplicates_skipped': 0,
            'alpha_duplicates_skipped': 0,
            'permutation_duplicates_skipped': 0,
            'permutation_rejected_candidates': 0,
            'candidates_enqueued': 0,
            'pending_numeric_streams': 0,
            'pending_alpha_streams': 0,
        }

    def is_available(self, context) -> bool:
        q = self._queue(context)
        return (not self.exhausted) and (q.queue_has_items() or q.active_slice_is_active() or self.pending_virtual_stream_count(context) > 0)

    def pending_virtual_stream_count(self, context) -> int:
        cursor = self._read_cursor(context)
        return int(cursor.get('pending_numeric_streams', 0) or 0) + int(cursor.get('pending_alpha_streams', 0) or 0)

    def run_slice(self, context) -> SliceResult:
        cursor = self._read_cursor(context)
        return run_feedback_dictionary_slice(self, context, {
            **self.last_expansion,
            'pending_numeric_streams': cursor.get('pending_numeric_streams', 0),
            'pending_alpha_streams': cursor.get('pending_alpha_streams', 0),
        })

    def _match_label(self, label: str, label_index: int) -> dict[str, Any] | None:
        ncfg = self._numeric_config(); acfg = self._alpha_config()
        for i, pat in enumerate(_PATTERNS):
            m = pat.match(label)
            if not m:
                continue
            if i in (0, 1):
                alpha, sep, num = m.group(1), m.group(2), m.group(3)
                alpha_pos, num_pos = 'prefix', 'suffix'
            elif i == 2:
                alpha, sep, num = m.group(1), '', m.group(2)
                alpha_pos, num_pos = 'prefix', 'suffix'
            elif i == 3:
                num, sep, alpha = m.group(1), m.group(2), m.group(3)
                alpha_pos, num_pos = 'suffix', 'prefix'
            else:
                num, sep, alpha = m.group(1), '', m.group(2)
                alpha_pos, num_pos = 'suffix', 'prefix'
            if not (int(ncfg['min_width']) <= len(num) <= int(ncfg['max_width'])):
                return None
            return {
                'original_label': label, 'label_index': label_index,
                'alpha_value': alpha, 'alpha_width': len(alpha),
                'separator': sep, 'separator_present': bool(sep),
                'numeric_value': int(num), 'numeric_width': len(num),
                'number_position': num_pos, 'alpha_position': alpha_pos,
            }
        return None

    def _render_label(self, match: dict[str, Any], *, alpha: str | None = None, number: str | None = None) -> str:
        a = alpha if alpha is not None else match['alpha_value']
        n = number if number is not None else str(match['numeric_value']).zfill(match['numeric_width'])
        sep = match['separator']
        return f'{a}{sep}{n}' if match['alpha_position'] == 'prefix' else f'{n}{sep}{a}'

    def _replace_label(self, name: str, index: int, label: str) -> str | None:
        labels = name.split('.')
        labels[index] = label
        return normalize_dns_name('.'.join(labels))

    def _value_variant_widths(self, observed: int, ncfg: dict[str, Any], *, observed_first: bool = False) -> list[int]:
        minw = int(ncfg['min_width'])
        if not ncfg.get('generate_width_variants', True):
            return [observed]
        widths = list(range(minw, observed + 1))
        if observed_first:
            return [observed] + [w for w in widths if w != observed]
        return widths

    def _emit_numeric_value(self, name: str, match: dict[str, Any], width: int, value: int) -> str | None:
        if value >= 10 ** width:
            return None
        return self._replace_label(
            name,
            match['label_index'],
            self._render_label(match, number=str(value).zfill(width)),
        )

    def _numeric_candidates(self, name: str, match: dict[str, Any]) -> Iterable[str]:
        ncfg = self._numeric_config()
        if not ncfg.get('enabled', True):
            return
        emitted_numbers: set[tuple[int, int]] = set()
        value = int(match['numeric_value'])
        observed = int(match['numeric_width'])

        # 1. Observed-value width variants: shortest valid representation first,
        # then observed width, matching examples such as srv7, srv07, srv007.
        for w in self._value_variant_widths(observed, ncfg):
            if (w, value) in emitted_numbers:
                continue
            cand = self._emit_numeric_value(name, match, w, value)
            if cand:
                emitted_numbers.add((w, value))
                yield cand

        # 2. Local-radius permutations: alternate below/above by distance so
        # nearby values are tested before broad full-range coverage.
        if ncfg.get('generate_local_radius', True):
            radius = int(ncfg.get('local_radius', 50))
            for distance in range(1, radius + 1):
                for v in (value - distance, value + distance):
                    if v < 0:
                        continue
                    # Preserve the observed structure first for neighboring
                    # values, then shorter valid width variants if enabled.
                    for w in self._value_variant_widths(observed, ncfg, observed_first=True):
                        if (w, v) in emitted_numbers:
                            continue
                        cand = self._emit_numeric_value(name, match, w, v)
                        if cand:
                            emitted_numbers.add((w, v))
                            yield cand

        if not ncfg.get('generate_full_range', True):
            # 5. Wider observed-value variants, if enabled, still run after
            # local candidates even when broad full-range generation is off.
            if ncfg.get('allow_wider_width_variants'):
                for w in range(observed + 1, int(ncfg['max_width']) + 1):
                    if (w, value) in emitted_numbers:
                        continue
                    cand = self._emit_numeric_value(name, match, w, value)
                    if cand:
                        emitted_numbers.add((w, value))
                        yield cand
            return

        # 3. Full-range observed-width permutations.
        for v in range(0, 10 ** observed):
            if (observed, v) in emitted_numbers:
                continue
            cand = self._emit_numeric_value(name, match, observed, v)
            if cand:
                emitted_numbers.add((observed, v))
                yield cand

        # 4. Full-range shorter-width permutations.
        if ncfg.get('generate_width_variants', True):
            for w in range(int(ncfg['min_width']), observed):
                for v in range(0, 10 ** w):
                    if (w, v) in emitted_numbers:
                        continue
                    cand = self._emit_numeric_value(name, match, w, v)
                    if cand:
                        emitted_numbers.add((w, v))
                        yield cand

        # 5. Wider observed-value variants, if explicitly enabled.
        if ncfg.get('allow_wider_width_variants'):
            for w in range(observed + 1, int(ncfg['max_width']) + 1):
                if (w, value) in emitted_numbers:
                    continue
                cand = self._emit_numeric_value(name, match, w, value)
                if cand:
                    emitted_numbers.add((w, value))
                    yield cand

    def _alpha_widths(self, observed: int, acfg: dict[str, Any]) -> list[int]:
        if not acfg.get('generate_width_variants', True):
            widths = [observed]
        else:
            widths = [observed] + [w for w in range(int(acfg['min_width']), observed) if w != observed]
        if acfg.get('allow_wider_width_variants'):
            widths.extend(w for w in range(observed + 1, int(acfg['max_width']) + 1) if w not in widths)
        return widths

    def _alpha_candidates(self, name: str, match: dict[str, Any]) -> Iterable[str]:
        acfg = self._alpha_config()
        if not acfg.get('enabled', False) or not acfg.get('generate_full_range', True):
            return
        if acfg.get('require_numeric_context', True) and match.get('numeric_value') is None:
            return
        if not (int(acfg['min_width']) <= int(match['alpha_width']) <= int(acfg['max_width'])):
            return
        charset = str(acfg.get('charset', ''))
        for w in self._alpha_widths(int(match['alpha_width']), acfg):
            for chars in itertools.product(charset, repeat=w):
                cand = self._replace_label(name, match['label_index'], self._render_label(match, alpha=''.join(chars)))
                if cand: yield cand

    def on_new_discoveries(self, discoveries, context) -> dict[str, Any]:
        q = self._queue(context)
        queued = q.load_queue_candidates_set()
        active = q.load_active_slice_candidates_set()
        expanded = q.load_expanded_bases()
        metrics = self._empty_metrics()
        metrics['candidates_skipped_batch_duplicate'] = 0
        metrics['candidates_skipped_queue_duplicate'] = 0
        metrics['candidates_skipped_active_slice_duplicate'] = 0
        metrics['candidates_skipped_already_cracked'] = 0
        numeric_to_enqueue: list[str] = []
        alpha_to_enqueue: list[str] = []
        expansion_seen: set[str] = set()
        expanded_keys: list[str] = []

        for raw in discoveries:
            name = normalize_dns_name(raw)
            if name is None:
                metrics['permutation_rejected_candidates'] += 1
                continue
            labels = name.split('.')
            for idx, label in enumerate(labels):
                match = self._match_label(label, idx)
                if match is None:
                    continue
                key = f'{name}|{idx}|{label}'
                if key in expanded:
                    continue
                metrics['permutation_patterns_matched'] += 1
                for cand in self._numeric_candidates(name, match):
                    metrics['numeric_candidates_generated'] += 1
                    if cand in queued:
                        metrics['numeric_duplicates_skipped'] += 1
                        metrics['permutation_duplicates_skipped'] += 1
                        metrics['candidates_skipped_queue_duplicate'] += 1
                        continue
                    if cand in active:
                        metrics['numeric_duplicates_skipped'] += 1
                        metrics['permutation_duplicates_skipped'] += 1
                        metrics['candidates_skipped_active_slice_duplicate'] += 1
                        continue
                    if cand in expansion_seen:
                        metrics['numeric_duplicates_skipped'] += 1
                        metrics['permutation_duplicates_skipped'] += 1
                        metrics['candidates_skipped_batch_duplicate'] += 1
                        continue
                    expansion_seen.add(cand); queued.add(cand); numeric_to_enqueue.append(cand)
                for cand in self._alpha_candidates(name, match):
                    metrics['alpha_candidates_generated'] += 1
                    if cand in queued:
                        metrics['alpha_duplicates_skipped'] += 1
                        metrics['permutation_duplicates_skipped'] += 1
                        metrics['candidates_skipped_queue_duplicate'] += 1
                        continue
                    if cand in active:
                        metrics['alpha_duplicates_skipped'] += 1
                        metrics['permutation_duplicates_skipped'] += 1
                        metrics['candidates_skipped_active_slice_duplicate'] += 1
                        continue
                    if cand in expansion_seen:
                        metrics['alpha_duplicates_skipped'] += 1
                        metrics['permutation_duplicates_skipped'] += 1
                        metrics['candidates_skipped_batch_duplicate'] += 1
                        continue
                    expansion_seen.add(cand); queued.add(cand); alpha_to_enqueue.append(cand)
                expanded.add(key); expanded_keys.append(key)

        numeric_stats = q.enqueue_generated_candidates(numeric_to_enqueue)
        alpha_stats = q.enqueue_generated_candidates(alpha_to_enqueue)
        metrics['numeric_candidates_enqueued'] = numeric_stats['candidates_enqueued']
        metrics['alpha_candidates_enqueued'] = alpha_stats['candidates_enqueued']
        numeric_dup = numeric_stats['candidates_skipped_generated_duplicate']
        alpha_dup = alpha_stats['candidates_skipped_generated_duplicate']
        metrics['numeric_duplicates_skipped'] += numeric_dup
        metrics['alpha_duplicates_skipped'] += alpha_dup
        metrics['permutation_duplicates_skipped'] += numeric_dup + alpha_dup
        batch_dup = numeric_stats['candidates_skipped_batch_duplicate'] + alpha_stats['candidates_skipped_batch_duplicate']
        metrics['generated_candidates_backend'] = numeric_stats['generated_candidates_backend']
        metrics['persistent_generated_dedupe'] = numeric_stats['persistent_generated_dedupe']
        metrics['candidates_skipped_generated_duplicate'] = numeric_dup + alpha_dup
        metrics['candidates_skipped_batch_duplicate'] += batch_dup
        metrics['candidates_skipped_queue_duplicate'] += numeric_stats['candidates_skipped_queue_duplicate'] + alpha_stats['candidates_skipped_queue_duplicate']
        metrics['candidates_skipped_active_slice_duplicate'] += numeric_stats['candidates_skipped_active_slice_duplicate'] + alpha_stats['candidates_skipped_active_slice_duplicate']
        metrics['candidates_enqueued'] = metrics['numeric_candidates_enqueued'] + metrics['alpha_candidates_enqueued']
        metrics['candidates_enqueued_total'] = metrics['candidates_enqueued']
        q.mark_bases_expanded(expanded_keys)
        self._write_cursor(context, {'pending_numeric_streams': 0, 'pending_alpha_streams': 0})
        self.last_expansion = metrics
        return metrics
