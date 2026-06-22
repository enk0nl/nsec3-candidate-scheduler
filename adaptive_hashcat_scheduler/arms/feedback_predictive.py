from __future__ import annotations
from typing import Any

from adaptive_hashcat_scheduler.arms.base import Arm, SliceResult
from adaptive_hashcat_scheduler.feedback.normalize import normalize_dns_name, leftmost_label
from adaptive_hashcat_scheduler.feedback.predictive_model import PredictiveModel
from adaptive_hashcat_scheduler.feedback.queue import FeedbackQueueState
from adaptive_hashcat_scheduler.feedback.execution import run_feedback_dictionary_slice

class PredictiveFeedbackArm(Arm):
    def __init__(self, name: str, arm_type: str, config: dict[str, Any]):
        super().__init__(name=name, type=arm_type, config=config)
        self.warmup_eligible = False
        self.model = PredictiveModel.load_tsv(config['model'])
        self.queue_state: FeedbackQueueState | None = None
        self.last_expansion = self._empty_metrics()

    def _queue(self, context) -> FeedbackQueueState:
        if self.queue_state is None or str(self.queue_state.out_dir) != context.out_dir:
            self.queue_state = FeedbackQueueState(context.out_dir, self.name, self.config)
        return self.queue_state

    def _empty_metrics(self):
        return {'bases_expanded': 0, 'predictions_generated': 0, 'candidates_enqueued': 0,
                'duplicates_skipped': 0, 'rejected_candidates': 0}

    def is_available(self, context) -> bool:
        q = self._queue(context)
        return (not self.exhausted) and (q.queue_has_items() or q.active_slice_is_active())

    def run_slice(self, context) -> SliceResult:
        return run_feedback_dictionary_slice(self, context, {
            'model_path': self.config['model'],
            'base_mode': self.config.get('base_mode', 'full'),
            'prediction_source': self.config.get('prediction_source', 'leftmost'),
            **self.last_expansion,
        })

    def on_new_discoveries(self, discoveries, context) -> dict[str, Any]:
        q = self._queue(context)
        queued = set(q.load_queue())
        expanded = q.load_expanded_bases()
        expansion_seen: set[str] = set()
        to_enqueue, bases = [], []
        metrics = self._empty_metrics()
        for raw in discoveries:
            name = normalize_dns_name(raw)
            if name is None:
                metrics['rejected_candidates'] += 1; continue
            base = name if self.config.get('base_mode', 'full') == 'full' else leftmost_label(name)
            source = name if self.config.get('prediction_source', 'leftmost') == 'full' else leftmost_label(name)
            if not base or not source or base in expanded:
                continue
            preds = self.model.predict(source, min_sim=float(self.config.get('min_sim', 0.7)), tau=float(self.config.get('tau', 2.0)),
                                       gamma=float(self.config.get('gamma', 0.0)), score_floor=float(self.config.get('score_floor', -5.0)),
                                       k_neighbors=int(self.config.get('k_neighbors', 30)),
                                       top_predictions_per_neighbor=int(self.config.get('top_predictions_per_neighbor', 100)),
                                       max_predictions=int(self.config.get('max_predictions', 100)))
            metrics['predictions_generated'] += len(preds)
            for pred in preds:
                cand = f'{pred}.{base}' if self.type == 'predictive_prefix' else f'{base}.{pred}'
                cand = normalize_dns_name(cand)
                if cand is None:
                    metrics['rejected_candidates'] += 1; continue
                if cand in queued or cand in expansion_seen:
                    metrics['duplicates_skipped'] += 1; continue
                expansion_seen.add(cand); queued.add(cand); to_enqueue.append(cand)
            expanded.add(base); bases.append(base); metrics['bases_expanded'] += 1
        enq_stats = q.enqueue_generated_candidates(to_enqueue)
        metrics['candidates_enqueued'] = enq_stats['candidates_enqueued']
        metrics['duplicates_skipped'] += enq_stats['candidates_skipped_generated_duplicate']
        metrics['generated_candidates_backend'] = enq_stats['generated_candidates_backend']
        metrics['candidates_skipped_generated_duplicate'] = enq_stats['candidates_skipped_generated_duplicate']
        q.mark_bases_expanded(bases)
        self.last_expansion = metrics
        return {f'{self.name}_{k}': v for k, v in metrics.items()}
