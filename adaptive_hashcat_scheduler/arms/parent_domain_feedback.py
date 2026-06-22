from __future__ import annotations

from typing import Any

from adaptive_hashcat_scheduler.arms.base import Arm, SliceResult
from adaptive_hashcat_scheduler.feedback.execution import run_feedback_dictionary_slice
from adaptive_hashcat_scheduler.feedback.normalize import normalize_dns_name
from adaptive_hashcat_scheduler.feedback.queue import FeedbackQueueState
from adaptive_hashcat_scheduler.hashcat.potfile import iter_potfile_cracks


class ParentDomainFeedbackArm(Arm):
    """Feedback arm that enqueues parent DNS names from cracked discoveries."""

    def __init__(self, name: str, arm_type: str, config: dict[str, Any]):
        super().__init__(name=name, type=arm_type, config=config)
        self.warmup_eligible = False
        self.queue_state: FeedbackQueueState | None = None
        self.last_expansion = self._empty_metrics()

    def _queue(self, context) -> FeedbackQueueState:
        if self.queue_state is None or str(self.queue_state.out_dir) != context.out_dir:
            self.queue_state = FeedbackQueueState(context.out_dir, self.name, self.config)
        return self.queue_state

    def _empty_metrics(self) -> dict[str, int]:
        return {
            'parent_bases_expanded': 0,
            'parent_candidates_generated': 0,
            'parent_candidates_enqueued': 0,
            'parent_duplicates_skipped': 0,
            'parent_duplicates_generated': 0,
            'parent_duplicates_queued': 0,
            'parent_duplicates_already_cracked': 0,
            'parent_rejected_candidates': 0,
        }

    def is_available(self, context) -> bool:
        q = self._queue(context)
        return (not self.exhausted) and (q.queue_has_items() or q.active_slice_is_active())

    def run_slice(self, context) -> SliceResult:
        return run_feedback_dictionary_slice(self, context, {
            **self.last_expansion,
            'candidates_enqueued': self.last_expansion.get('parent_candidates_enqueued', 0),
            'duplicates_skipped': self.last_expansion.get('parent_duplicates_skipped', 0),
            'rejected_candidates': self.last_expansion.get('parent_rejected_candidates', 0),
        })

    def _effective_min_parent_labels(self) -> int:
        min_labels = int(self.config.get('min_parent_labels', 1))
        if not bool(self.config.get('include_single_label_parent', True)):
            min_labels = max(min_labels, 2)
        return max(1, min_labels)

    def _parents_for(self, name: str) -> list[str]:
        labels = name.split('.')
        if len(labels) <= 1:
            return []
        min_labels = self._effective_min_parent_labels()
        max_parents = self.config.get('max_parents_per_discovery')
        limit = None if max_parents is None else max(0, int(max_parents))
        parents: list[str] = []
        for drop_count in range(1, len(labels)):
            parent_labels = labels[drop_count:]
            if len(parent_labels) < min_labels:
                continue
            parent = normalize_dns_name('.'.join(parent_labels))
            if parent is not None:
                parents.append(parent)
            if limit is not None and len(parents) >= limit:
                break
        return parents

    def on_new_discoveries(self, discoveries, context) -> dict[str, Any]:
        q = self._queue(context)
        queued = set(q.load_queue())
        expanded = q.load_expanded_bases()
        expansion_seen: set[str] = set()
        cracked = {normalize_dns_name(value) for _, value in iter_potfile_cracks(context.potfile)}
        cracked.discard(None)
        to_enqueue: list[str] = []
        bases: list[str] = []
        metrics: dict[str, Any] = self._empty_metrics()
        metrics['candidates_skipped_batch_duplicate'] = 0
        debug_enabled = bool(self.config.get('debug_expansions', False))
        debug_sample_size = max(0, int(self.config.get('debug_sample_size', 20)))
        parent_samples: list[str] = []
        debug_records: list[dict[str, Any]] = []

        for raw in discoveries:
            base = normalize_dns_name(raw)
            if base is None:
                metrics['parent_rejected_candidates'] += 1
                continue
            if base in expanded:
                continue

            record = {
                'base': base,
                'generated_parents': [],
                'enqueued': [],
                'skipped_already_cracked': [],
                'skipped_generated': [],
                'skipped_queued': [],
                'rejected': [],
            }
            parents = self._parents_for(base)
            for parent in parents:
                metrics['parent_candidates_generated'] += 1
                if len(parent_samples) < debug_sample_size:
                    parent_samples.append(parent)
                record['generated_parents'].append(parent)
                # _parents_for normalizes each candidate; keep this guard for validator parity.
                cand = normalize_dns_name(parent)
                if cand is None:
                    metrics['parent_rejected_candidates'] += 1
                    record['rejected'].append(parent)
                    continue
                if cand in cracked:
                    metrics['parent_duplicates_already_cracked'] += 1
                    metrics['parent_duplicates_skipped'] += 1
                    record['skipped_already_cracked'].append(cand)
                    continue
                if cand in queued:
                    metrics['parent_duplicates_queued'] += 1
                    metrics['parent_duplicates_skipped'] += 1
                    record['skipped_queued'].append(cand)
                    continue
                if cand in expansion_seen:
                    metrics['parent_duplicates_skipped'] += 1
                    metrics['candidates_skipped_batch_duplicate'] += 1
                    record['skipped_generated'].append(cand)
                    continue
                expansion_seen.add(cand)
                queued.add(cand)
                to_enqueue.append(cand)
                record['enqueued'].append(cand)
            expanded.add(base)
            bases.append(base)
            metrics['parent_bases_expanded'] += 1
            if debug_enabled and len(debug_records) < debug_sample_size:
                debug_records.append(record)

        enq_stats = q.enqueue_generated_candidates(to_enqueue)
        metrics['parent_candidates_enqueued'] = enq_stats['candidates_enqueued']
        metrics['parent_duplicates_generated'] += enq_stats['candidates_skipped_generated_duplicate']
        metrics['parent_duplicates_skipped'] += enq_stats['candidates_skipped_generated_duplicate']
        metrics['generated_candidates_backend'] = enq_stats['generated_candidates_backend']
        metrics['persistent_generated_dedupe'] = enq_stats['persistent_generated_dedupe']
        metrics['candidates_skipped_generated_duplicate'] = enq_stats['candidates_skipped_generated_duplicate']
        metrics['candidates_skipped_batch_duplicate'] += enq_stats['candidates_skipped_batch_duplicate']
        metrics['candidates_enqueued_total'] = enq_stats['candidates_enqueued_total']
        if debug_sample_size > 0:
            metrics['parent_generated_samples'] = parent_samples
        if debug_enabled:
            metrics['parent_debug_expansions'] = debug_records
        q.mark_bases_expanded(bases)
        self.last_expansion = metrics
        return metrics
