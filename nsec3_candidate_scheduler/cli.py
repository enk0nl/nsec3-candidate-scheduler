from __future__ import annotations
import argparse
from nsec3_candidate_scheduler.scheduler import run_scheduler
from nsec3_candidate_scheduler.feedback.train_pairs import train_to_files
from nsec3_candidate_scheduler.feedback.predictive_model import PredictiveModel
from nsec3_candidate_scheduler.feedback.common_affixes import mine_to_files

def main(argv=None):
    ap=argparse.ArgumentParser(prog='nsec3-candidate-scheduler')
    sub=ap.add_subparsers(dest='cmd', required=True)
    r=sub.add_parser('run'); r.add_argument('--hashes',required=True); r.add_argument('--hash-mode',type=int,default=8300); r.add_argument('--config',required=True); r.add_argument('--out-dir',required=True); r.add_argument('--schedule',choices=['sequential','round_robin','adaptive'],required=True); r.add_argument('--total-slices',type=int,required=True); r.add_argument('--slice-seconds',type=int,default=60); r.add_argument('--alpha',type=float); r.add_argument('--epsilon',type=float); r.add_argument('--random-seed',type=int); r.add_argument('--default-limit',type=int,default=1000000); r.add_argument('--hashcat-bin',default='hashcat'); r.add_argument('--quiet',action='store_true'); r.add_argument('--verbose',action='store_true'); r.add_argument('--no-optimized-kernels', action='store_true', help='Disable hashcat optimized kernels from the start. Slower, but more compatible with long/problematic candidates.'); r.add_argument('--optimized-kernel-failover', dest='optimized_kernel_failover', action='store_true', default=None, help='Automatically retry with unoptimized kernels if an optimized-kernel-specific hashcat failure is detected. Enabled by default.'); r.add_argument('--no-optimized-kernel-failover', dest='optimized_kernel_failover', action='store_false', help='Keep optimized kernels enabled after optimized-kernel-specific failures. Failed slices are logged but not retried unoptimized.')
    t=sub.add_parser('train-predictive-feedback'); t.add_argument('--input',required=True); t.add_argument('--input-format',choices=['auto','potfile','names'],default='auto'); t.add_argument('--output-prefix-model',required=True); t.add_argument('--output-suffix-model',required=True)
    p=sub.add_parser('predict-feedback'); p.add_argument('--model',required=True); p.add_argument('--source',required=True); p.add_argument('--max-predictions',type=int,default=100)
    m=sub.add_parser('mine-common-affixes'); m.add_argument('--potfile',required=True); m.add_argument('--output-prefixes',required=True); m.add_argument('--output-suffixes',required=True); m.add_argument('--top-n',type=int,default=50); m.add_argument('--min-count',type=int,default=1); m.add_argument('--input-format',choices=['auto','potfile','names'],default='auto'); m.add_argument('--include-single-labels',type=lambda v: str(v).lower() in {'1','true','yes','y'},default=False); m.add_argument('--labels-only',action='store_true'); m.add_argument('--allow-numeric-affixes',action='store_true'); m.add_argument('--allow-underscore-affixes',type=lambda v: str(v).lower() in {'1','true','yes','y'},default=True)
    args=ap.parse_args(argv)
    if args.cmd=='run' and args.quiet and args.verbose:
        ap.error('--quiet and --verbose cannot be used together')
    if args.cmd=='run': return run_scheduler(args)
    if args.cmd=='train-predictive-feedback': train_to_files(args.input,args.input_format,args.output_prefix_model,args.output_suffix_model); return 0
    if args.cmd=='predict-feedback':
        for pred in PredictiveModel.load_tsv(args.model).predict(args.source,max_predictions=args.max_predictions): print(pred)
        return 0
    if args.cmd=='mine-common-affixes':
        if args.top_n <= 0: ap.error('--top-n must be positive')
        if args.min_count <= 0: ap.error('--min-count must be positive')
        mine_to_files(args); return 0
    return 2
if __name__=='__main__': raise SystemExit(main())
