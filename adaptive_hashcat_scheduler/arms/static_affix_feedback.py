from __future__ import annotations

from pathlib import Path
from typing import Any

from adaptive_hashcat_scheduler.arms.base import Arm, SliceResult
from adaptive_hashcat_scheduler.feedback.common_affixes import is_feedback_affix_label, normalize_affix_source
from adaptive_hashcat_scheduler.feedback.normalize import normalize_dns_name
from adaptive_hashcat_scheduler.feedback.queue import FeedbackQueueState
from adaptive_hashcat_scheduler.hashcat.potfile import iter_potfile_cracks
from adaptive_hashcat_scheduler.feedback.execution import run_feedback_dictionary_slice


def _load_affixes(path: str, limit: int) -> list[str]:
    labels: list[str] = []
    seen: set[str] = set()
    with Path(path).open('r', encoding='utf-8', errors='replace') as f:
        for raw in f:
            value = raw.strip()
            if not value:
                continue
            label = value.split('\t', 1)[0].strip().lower()
            if label in seen:
                continue
            if not is_feedback_affix_label(label, allow_numeric=False, allow_underscore=True):
                continue
            labels.append(label)
            seen.add(label)
            if len(labels) >= limit:
                break
    return labels


class StaticAffixFeedbackArm(Arm):
    def __init__(self, name: str, arm_type: str, config: dict[str, Any]):
        super().__init__(name=name, type=arm_type, config=config)
        self.warmup_eligible = False
        self.prefixes = _load_affixes(config['prefixes'], int(config.get('top_prefixes', 50)))
        self.suffixes = _load_affixes(config['suffixes'], int(config.get('top_suffixes', 50)))
        self.queue_state: FeedbackQueueState | None = None
        self.last_expansion = self._empty_metrics()

    def _queue(self, context) -> FeedbackQueueState:
        if self.queue_state is None or str(self.queue_state.out_dir) != context.out_dir:
            self.queue_state = FeedbackQueueState(context.out_dir, self.name, self.config)
        return self.queue_state

    def _empty_metrics(self):
        return {
            'affix_prefixes_loaded': len(getattr(self, 'prefixes', [])),
            'affix_suffixes_loaded': len(getattr(self, 'suffixes', [])),
            'affix_bases_expanded': 0,
            'affix_prefix_candidates_generated': 0,
            'affix_suffix_candidates_generated': 0,
            'candidates_enqueued': 0,
            'duplicates_skipped': 0,
            'affix_duplicates_generated': 0,
            'affix_duplicates_queued': 0,
            'affix_duplicates_already_cracked': 0,
            'rejected_candidates': 0,
        }

    def is_available(self, context) -> bool:
        q = self._queue(context)
        return (not self.exhausted) and (q.queue_has_items() or q.active_slice_is_active())

    def run_slice(self, context) -> SliceResult:
        return run_feedback_dictionary_slice(self, context, {
            'base_mode': self.config.get('base_mode', 'full'),
            **self.last_expansion,
        })

    def on_new_discoveries(self, discoveries, context) -> dict[str, Any]:
        q = self._queue(context)
        queued = set(q.load_queue())
        expanded = q.load_expanded_bases()
        expansion_seen: set[str] = set()
        cracked = {value for _, value in iter_potfile_cracks(context.potfile)}
        to_enqueue: list[str] = []
        bases: list[str] = []
        metrics = self._empty_metrics()
        metrics['candidates_skipped_batch_duplicate'] = 0
        gen_prefix = bool(self.config.get('generate_prefixes', True))
        gen_suffix = bool(self.config.get('generate_suffixes', True))
        for raw in discoveries:
            base = normalize_affix_source(raw)
            if base is None:
                metrics['rejected_candidates'] += 1
                continue
            if self.config.get('base_mode', 'full') != 'full':
                metrics['rejected_candidates'] += 1
                continue
            if base in expanded:
                continue
            candidates: list[tuple[str, str]] = []
            if gen_prefix:
                candidates.extend(('prefix', f'{prefix}.{base}') for prefix in self.prefixes)
            if gen_suffix:
                candidates.extend(('suffix', f'{base}.{suffix}') for suffix in self.suffixes)
            for direction, candidate in candidates:
                cand = normalize_affix_source(candidate)
                if direction == 'prefix':
                    metrics['affix_prefix_candidates_generated'] += 1
                else:
                    metrics['affix_suffix_candidates_generated'] += 1
                if cand is None:
                    metrics['rejected_candidates'] += 1
                    continue
                if cand in cracked:
                    metrics['affix_duplicates_already_cracked'] += 1; metrics['duplicates_skipped'] += 1
                    continue
                if cand in queued:
                    metrics['affix_duplicates_queued'] += 1; metrics['duplicates_skipped'] += 1
                    continue
                if cand in expansion_seen:
                    metrics['duplicates_skipped'] += 1; metrics['candidates_skipped_batch_duplicate'] += 1
                    continue
                expansion_seen.add(cand); queued.add(cand)
                to_enqueue.append(cand)
            expanded.add(base)
            bases.append(base)
            metrics['affix_bases_expanded'] += 1
        enq_stats = q.enqueue_generated_candidates(to_enqueue)
        metrics['candidates_enqueued'] = enq_stats['candidates_enqueued']
        metrics['affix_duplicates_generated'] += enq_stats['candidates_skipped_generated_duplicate']
        metrics['duplicates_skipped'] += enq_stats['candidates_skipped_generated_duplicate']
        metrics['generated_candidates_backend'] = enq_stats['generated_candidates_backend']
        metrics['persistent_generated_dedupe'] = enq_stats['persistent_generated_dedupe']
        metrics['candidates_skipped_generated_duplicate'] = enq_stats['candidates_skipped_generated_duplicate']
        metrics['candidates_skipped_batch_duplicate'] += enq_stats['candidates_skipped_batch_duplicate']
        metrics['candidates_enqueued_total'] = enq_stats['candidates_enqueued_total']
        q.mark_bases_expanded(bases)
        self.last_expansion = metrics
        return {f'{self.name}_{k}': v for k, v in metrics.items()}
