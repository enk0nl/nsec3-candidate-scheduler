from __future__ import annotations
from adaptive_hashcat_scheduler.arms.feedback_predictive import PredictiveFeedbackArm
from adaptive_hashcat_scheduler.arms.base import Arm, SliceResult
from adaptive_hashcat_scheduler.feedback.normalize import normalize_dns_name
from adaptive_hashcat_scheduler.feedback.queue import FeedbackQueueState
from adaptive_hashcat_scheduler.feedback.execution import run_feedback_dictionary_slice

class CommonFeedbackArm(Arm):
    def __init__(self, name, arm_type, config):
        super().__init__(name, arm_type, config); self.warmup_eligible = False; self.queue_state=None; self.last_expansion={}
    def _queue(self, context):
        if self.queue_state is None: self.queue_state=FeedbackQueueState(context.out_dir, self.name, self.config)
        return self.queue_state
    def is_available(self, context):
        q = self._queue(context)
        return (not self.exhausted) and (q.queue_has_items() or q.active_slice_is_active())
    def run_slice(self, context):
        return run_feedback_dictionary_slice(self, context, self.last_expansion)
    def on_new_discoveries(self, discoveries, context):
        q=self._queue(context); queued=set(q.load_queue()); expanded=q.load_expanded_bases(); expansion_seen=set(); cands=[]; bases=[]; gen=dup=rej=0
        for raw in discoveries:
            base=normalize_dns_name(raw)
            if base is None or base in expanded: rej+=1; continue
            for lab in self.config.get('common_labels',[]):
                lab=normalize_dns_name(lab)
                if not lab: continue
                for cand in (f'{base}.{lab}', f'{lab}.{base}'):
                    gen+=1; cand=normalize_dns_name(cand)
                    if cand in queued or cand in expansion_seen: dup+=1; continue
                    expansion_seen.add(cand); queued.add(cand); cands.append(cand)
            expanded.add(base); bases.append(base)
        enq_stats=q.enqueue_generated_candidates(cands); enq=enq_stats['candidates_enqueued']; dup+=enq_stats['candidates_skipped_generated_duplicate']; q.mark_bases_expanded(bases)
        self.last_expansion={'bases_expanded':len(bases),'predictions_generated':gen,'candidates_enqueued':enq,'duplicates_skipped':dup,'rejected_candidates':rej,'generated_candidates_backend':enq_stats['generated_candidates_backend'],'persistent_generated_dedupe':enq_stats['persistent_generated_dedupe'],'candidates_skipped_generated_duplicate':enq_stats['candidates_skipped_generated_duplicate'],'candidates_skipped_batch_duplicate':enq_stats['candidates_skipped_batch_duplicate'],'candidates_enqueued_total':enq_stats['candidates_enqueued_total']}
        return self.last_expansion
