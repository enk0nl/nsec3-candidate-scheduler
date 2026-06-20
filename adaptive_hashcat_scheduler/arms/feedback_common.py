from __future__ import annotations
from adaptive_hashcat_scheduler.arms.feedback_predictive import PredictiveFeedbackArm
from adaptive_hashcat_scheduler.arms.base import Arm, SliceResult
from adaptive_hashcat_scheduler.feedback.normalize import normalize_dns_name
from adaptive_hashcat_scheduler.feedback.queue import FeedbackQueueState
from adaptive_hashcat_scheduler.hashcat.runner import build_hashcat_command, run_cmd

class CommonFeedbackArm(Arm):
    def __init__(self, name, arm_type, config):
        super().__init__(name, arm_type, config); self.queue_state=None; self.last_expansion={}
    def _queue(self, context):
        if self.queue_state is None: self.queue_state=FeedbackQueueState(context.out_dir, self.name)
        return self.queue_state
    def is_available(self, context): return (not self.exhausted) and self._queue(context).queue_has_items()
    def run_slice(self, context):
        q=self._queue(context); before=q.queue_size_lines(); sf,w,after=q.move_queue_to_slice_file()
        rc,out,err=run_cmd(build_hashcat_command(context.hashcat_bin, context.hash_mode,0,context.slice_seconds,context.potfile,context.hashes,candidate=sf))
        return SliceResult(exit_code=rc, stdout=out, stderr=err, extra={'queue_size_before_slice':before,'candidates_written_to_slice':w,'queue_size_after_slice':after, **self.last_expansion})
    def on_new_discoveries(self, discoveries, context):
        q=self._queue(context); seen=q.load_seen_candidates(); expanded=q.load_expanded_bases(); cands=[]; bases=[]; gen=dup=rej=0
        for raw in discoveries:
            base=normalize_dns_name(raw)
            if base is None or base in expanded: rej+=1; continue
            for lab in self.config.get('common_labels',[]):
                lab=normalize_dns_name(lab)
                if not lab: continue
                for cand in (f'{base}.{lab}', f'{lab}.{base}'):
                    gen+=1; cand=normalize_dns_name(cand)
                    if cand in seen: dup+=1; continue
                    seen.add(cand); cands.append(cand)
            expanded.add(base); bases.append(base)
        enq=q.append_candidates(cands); q.mark_bases_expanded(bases)
        self.last_expansion={'bases_expanded':len(bases),'predictions_generated':gen,'candidates_enqueued':enq,'duplicates_skipped':dup,'rejected_candidates':rej}
        return self.last_expansion
