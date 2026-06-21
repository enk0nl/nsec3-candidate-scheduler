from __future__ import annotations
import math
from adaptive_hashcat_scheduler.arms.base import Arm, SliceResult
from adaptive_hashcat_scheduler.hashcat.runner import build_hashcat_command, run_cmd
from adaptive_hashcat_scheduler.hashcat.status import latest_summary

def count_lines(path):
    with open(path,'rb') as f: return sum(1 for _ in f)

class DictionaryArm(Arm):
    def __init__(self,name,arm_type,config):
        super().__init__(name,arm_type,config); self.keyspace=count_lines(config['wordlist'])
    def is_available(self, context): return (not self.exhausted) and (self.keyspace is None or self.next_skip < self.keyspace)
    def run_slice(self, context):
        skip=self.next_skip
        cmd=build_hashcat_command(context.hashcat_bin,context.hash_mode,0,context.slice_seconds,context.potfile,context.hashes,candidate=self.config['wordlist'],skip=skip,limit=None,optimized_kernels=context.hashcat_optimized_kernels)
        rc,out,err=run_cmd(cmd); summ=latest_summary(out+'\n'+err)
        cursor=None; next_skip=skip; src='unknown'
        pc=summ.get('progress_cur'); salts=summ.get('recovered_salts_total')
        if isinstance(pc,int) and isinstance(salts,int) and salts>0:
            cursor=math.floor(pc/salts)
        if isinstance(cursor,int) and cursor>skip:
            next_skip=min(cursor,self.keyspace); src='progress_scaled_by_salts'
        self.next_skip=next_skip
        if self.keyspace is not None and self.next_skip>=self.keyspace: self.exhausted=True
        if rc==1: self.exhausted=True
        return SliceResult(exit_code=rc,stdout=out,stderr=err,skip_before=skip,next_skip_after=next_skip,progress_source=src,dictionary_candidate_cursor=cursor,exhausted=self.exhausted)
