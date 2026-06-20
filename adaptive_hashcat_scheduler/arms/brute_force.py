from __future__ import annotations
from adaptive_hashcat_scheduler.arms.base import Arm, SliceResult
from adaptive_hashcat_scheduler.hashcat.runner import build_hashcat_command, run_cmd

class BruteForceArm(Arm):
    def __init__(self,name,arm_type,config):
        super().__init__(name,arm_type,config); self.masks=config.get('masks') or [config.get('mask')]; self.mask_index=0
    def charset_args(self):
        args=[]
        for i in range(1,5):
            v=self.config.get(f'custom_charset_{i}', self.config.get(f'custom_charset{i}'))
            if v is not None: args += [f'-{i}', str(v)]
        return args
    def is_available(self, context): return (not self.exhausted) and self.mask_index < len(self.masks)
    def run_slice(self, context):
        mask=self.masks[self.mask_index]
        cmd=build_hashcat_command(context.hashcat_bin,context.hash_mode,3,context.slice_seconds,context.potfile,context.hashes,candidate=mask,skip=self.next_skip,limit=context.default_limit,extra_args=self.charset_args())
        rc,out,err=run_cmd(cmd)
        if rc==1:
            self.mask_index+=1; self.next_skip=0
            if self.mask_index>=len(self.masks): self.exhausted=True
        return SliceResult(exit_code=rc,stdout=out,stderr=err,skip_before=self.next_skip,next_skip_after=self.next_skip,exhausted=self.exhausted,extra={'brute_force_mask':mask})
