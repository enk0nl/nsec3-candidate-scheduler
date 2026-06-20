from __future__ import annotations
import argparse
from adaptive_hashcat_scheduler.scheduler import run_scheduler
from adaptive_hashcat_scheduler.feedback.train_pairs import train_to_files
from adaptive_hashcat_scheduler.feedback.predictive_model import PredictiveModel

def main(argv=None):
    ap=argparse.ArgumentParser(prog='adaptive_hashcat_scheduler')
    sub=ap.add_subparsers(dest='cmd', required=True)
    r=sub.add_parser('run'); r.add_argument('--hashes',required=True); r.add_argument('--hash-mode',type=int,default=8300); r.add_argument('--config',required=True); r.add_argument('--out-dir',required=True); r.add_argument('--schedule',choices=['sequential','round_robin','adaptive'],required=True); r.add_argument('--total-slices',type=int,required=True); r.add_argument('--slice-seconds',type=int,default=60); r.add_argument('--alpha',type=float); r.add_argument('--epsilon',type=float); r.add_argument('--random-seed',type=int); r.add_argument('--default-limit',type=int,default=1000000); r.add_argument('--hashcat-bin',default='hashcat'); r.add_argument('--verbose',action='store_true')
    t=sub.add_parser('train-predictive-feedback'); t.add_argument('--input',required=True); t.add_argument('--input-format',choices=['auto','potfile','names'],default='auto'); t.add_argument('--output-prefix-model',required=True); t.add_argument('--output-suffix-model',required=True)
    p=sub.add_parser('predict-feedback'); p.add_argument('--model',required=True); p.add_argument('--source',required=True); p.add_argument('--max-predictions',type=int,default=100)
    args=ap.parse_args(argv)
    if args.cmd=='run': return run_scheduler(args)
    if args.cmd=='train-predictive-feedback': train_to_files(args.input,args.input_format,args.output_prefix_model,args.output_suffix_model); return 0
    if args.cmd=='predict-feedback':
        for pred in PredictiveModel.load_tsv(args.model).predict(args.source,max_predictions=args.max_predictions): print(pred)
        return 0
    return 2
if __name__=='__main__': raise SystemExit(main())
