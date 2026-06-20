from __future__ import annotations
from dataclasses import dataclass
import datetime as dt, json, os, random, time
from typing import Any

FEEDBACK_TYPES = {'feedback', 'predictive_prefix', 'predictive_suffix'}

from adaptive_hashcat_scheduler.config import load_config
from adaptive_hashcat_scheduler.hashcat.potfile import iter_potfile_cracks
from adaptive_hashcat_scheduler.hashcat.runner import EXIT_MEANINGS
from adaptive_hashcat_scheduler.arms.dictionary import DictionaryArm
from adaptive_hashcat_scheduler.arms.brute_force import BruteForceArm
from adaptive_hashcat_scheduler.arms.feedback_common import CommonFeedbackArm
from adaptive_hashcat_scheduler.arms.feedback_predictive import PredictiveFeedbackArm

@dataclass
class SchedulerContext:
    hashes: str; hash_mode: int; out_dir: str; slice_seconds: int; potfile: str
    hashcat_bin: str='hashcat'; default_limit: int=1000000

def utc_now(): return dt.datetime.now(dt.timezone.utc).isoformat()
def ensure_dir(p): os.makedirs(p, exist_ok=True)

def pot_values(path):
    if not os.path.exists(path): return {}
    return {h:v for h,v in iter_potfile_cracks(path)}

def make_arm(cfg):
    t=cfg['type']; name=cfg['name']
    if t=='dictionary': return DictionaryArm(name,t,cfg)
    if t=='brute_force': return BruteForceArm(name,t,cfg)
    if t=='feedback': return CommonFeedbackArm(name,t,cfg)
    if t in {'predictive_prefix','predictive_suffix'}: return PredictiveFeedbackArm(name,t,cfg)
    raise ValueError(f'unknown arm type: {t}')

def _feedback_availability(arm, context, current_adaptive_slice, force_queue: bool = False) -> dict[str, Any]:
    queue_size = arm._queue(context).queue_size_lines()
    min_queue_size = int(arm.config.get('min_queue_size', 1))
    min_slices = int(arm.config.get('min_slices_between_runs', 0))
    slices_since = current_adaptive_slice - arm.last_run_adaptive_slice
    reason = None
    if arm.exhausted:
        reason = 'exhausted'
    elif slices_since < min_slices:
        reason = 'cooldown'
    elif queue_size < min_queue_size and not force_queue:
        reason = 'queue_below_minimum'
    return {
        'available': reason is None,
        'availability_reason': reason,
        'min_slices_between_runs': min_slices,
        'slices_since_last_run': slices_since,
        'min_queue_size': min_queue_size,
        'queue_size': queue_size,
    }

def _availability(arm, context, current_adaptive_slice, force_queue: bool = False) -> dict[str, Any]:
    if arm.type in FEEDBACK_TYPES:
        return _feedback_availability(arm, context, current_adaptive_slice, force_queue)
    available = arm.is_available(context)
    return {'available': available, 'availability_reason': None if available else 'unavailable'}

def choose_arm(arms, schedule, warmup, epsilon, rng, current_adaptive_slice):
    context = choose_arm.context
    choose_arm.unavailable = []
    normal=[]
    for a in arms:
        info = _availability(a, context, current_adaptive_slice)
        a.last_availability = info
        if info['available']:
            normal.append(a)
        elif info.get('availability_reason'):
            choose_arm.unavailable.append({'arm': a.name, **info})
    if schedule=='round_robin':
        return (sorted(normal,key=lambda a:(a.runs, arms.index(a)))[0],'round_robin') if normal else (None,'none')
    if schedule=='sequential':
        return (normal[0],'sequential_budget') if normal else (None,'none')
    if warmup:
        for a in normal:
            if a.name in warmup:
                warmup.remove(a.name); return a,'warmup'
    due=[]
    for a in arms:
        n=a.config.get('force_every_slices')
        if not n: continue
        since=current_adaptive_slice-a.last_run_adaptive_slice
        if since < n: continue
        info = _availability(a, context, current_adaptive_slice, force_queue=True)
        if info['available']:
            a.last_availability = info
            due.append((since/n,a.runs,a.total_runtime,a.name,a))
        elif info.get('availability_reason'):
            forced_skip = {'arm': a.name, 'forced_cadence_due': True, **info}
            choose_arm.unavailable.append(forced_skip)
    if due: return sorted(due,key=lambda x:(-x[0],x[1],x[2],x[3]))[0][4],'forced_cadence'
    live=normal
    if not live: return None,'none'
    if rng.random()<epsilon: return rng.choice(live),'epsilon_exploration'
    return sorted(live,key=lambda a:(-a.score,a.runs,a.total_runtime,a.name))[0],'highest_score'

def _fmt_float(value, digits=3):
    if value is None:
        return "n/a"
    return f"{float(value):.{digits}f}"

def _feedback_queue_fields(rec):
    return (
        rec.get('queue_size_before_slice'),
        rec.get('queue_size_after_slice'),
        rec.get('candidates_written_to_slice'),
        rec.get('candidates_enqueued', 0),
    )

def format_slice_oneline(rec: dict[str, Any], total_slices: int) -> str:
    prefix = (
        f"[{rec['job_id']}/{total_slices}] {rec['phase']} {rec['arm']} "
        f"reason={rec['selection_reason']}"
    )
    details = ""
    if rec.get('attack_type') == 'dictionary':
        details = (
            f" skip={rec.get('skip_before')}->{rec.get('next_skip_after')}"
            f" progress={rec.get('progress_source')}"
        )
    elif rec.get('queue_size_before_slice') is not None:
        before, after, written, enqueued = _feedback_queue_fields(rec)
        details = (f" queue={before}->{after} written={written} enq={enqueued}"
                   f" gate_queue={rec.get('queue_size')}/{rec.get('min_queue_size')}"
                   f" cooldown={rec.get('slices_since_last_run')}/{rec.get('min_slices_between_runs')}")
    return (
        f"{prefix}{details} new={rec['new_cracks']} total={rec['total_cracks']} "
        f"reward={_fmt_float(rec['reward'])} "
        f"score={_fmt_float(rec['score_before'], 2)}->{_fmt_float(rec['score_after'], 2)} "
        f"runtime={_fmt_float(rec['runtime_seconds'], 1)}s"
    )

def format_slice_verbose(rec: dict[str, Any], total_slices: int) -> str:
    lines = [
        f"[{rec['job_id']}/{total_slices}] {rec['phase'].upper()}",
        f"Arm: {rec['arm']}",
        f"Reason: {rec['selection_reason']}",
    ]
    if rec.get('attack_type') == 'dictionary':
        lines.extend([
            f"Skip: {rec.get('skip_before')} -> {rec.get('next_skip_after')}",
            f"Progress source: {rec.get('progress_source')}",
        ])
    elif rec.get('queue_size_before_slice') is not None:
        before, after, written, enqueued = _feedback_queue_fields(rec)
        lines.extend([
            f"Queue: {before} -> {after}",
            f"Candidates written: {written}",
            f"Candidates enqueued: {enqueued}",
            f"Queue gate: {rec.get('queue_size')} / {rec.get('min_queue_size')}",
            f"Cooldown: {rec.get('slices_since_last_run')} / {rec.get('min_slices_between_runs')}",
        ])
    lines.extend([
        f"New discoveries: {rec['new_cracks']}",
        f"Total discoveries: {rec['total_cracks']}",
        f"Reward: {_fmt_float(rec['reward'])}",
        f"Score: {_fmt_float(rec['score_before'], 2)} -> {_fmt_float(rec['score_after'], 2)}",
        f"Runtime: {_fmt_float(rec['runtime_seconds'], 1)}s",
    ])
    return "\n".join(lines)

def print_slice_progress(rec: dict[str, Any], total_slices: int, mode: str) -> None:
    if mode == 'quiet':
        return
    if mode == 'verbose':
        print(format_slice_verbose(rec, total_slices), flush=True)
        return
    print(format_slice_oneline(rec, total_slices), flush=True)

def format_final_summary(completed_slices: int, total_discoveries: int, runtime_seconds: float, arms, jobs_path: str) -> str:
    lines = [
        "Scheduler summary",
        f"Total slices completed: {completed_slices}",
        f"Total discoveries: {total_discoveries}",
        f"Runtime: {_fmt_float(runtime_seconds, 1)}s",
        f"Output log: {jobs_path}",
        "Per-arm:",
    ]
    for arm in arms:
        lines.append(f"  - {arm.name}: runs={arm.runs} discoveries={arm.total_new_cracks}")
    return "\n".join(lines)

def run_scheduler(args) -> int:
    ensure_dir(args.out_dir); ensure_dir(os.path.join(args.out_dir,'hashcat_logs'))
    potfile=os.path.join(args.out_dir,'run.pot'); open(potfile,'a').close()
    jobs_path=os.path.join(args.out_dir,'jobs.jsonl'); open(jobs_path,'w').close()
    cfg=load_config(args.config)
    arms=[make_arm(a) for a in cfg['arms']]
    if not arms: raise ValueError('config has no enabled arms')
    ctx=SchedulerContext(args.hashes,args.hash_mode,args.out_dir,args.slice_seconds,potfile,getattr(args,'hashcat_bin','hashcat'),getattr(args,'default_limit',1000000))
    choose_arm.context=ctx
    alpha=float(args.alpha if args.alpha is not None else cfg.get('alpha',0.2)); epsilon=float(args.epsilon if args.epsilon is not None else cfg.get('epsilon',0.1))
    rng=random.Random(args.random_seed if args.random_seed is not None else cfg.get('random_seed',0))
    warmup=[a.name for a in arms]
    prev=pot_values(potfile); current_adaptive_slice=0
    total_slices=args.total_slices or 0
    completed_slices = 0
    start_time = time.time()
    console_mode = 'quiet' if getattr(args, 'quiet', False) else ('verbose' if getattr(args, 'verbose', False) else 'default')
    for job in range(1,total_slices+1):
        arm,reason=choose_arm(arms,args.schedule,warmup if args.schedule=='adaptive' else [],epsilon,rng,current_adaptive_slice)
        if arm is None:
            if console_mode == 'verbose':
                for unavailable in getattr(choose_arm, 'unavailable', []):
                    print('Unavailable arm: '+json.dumps(unavailable,separators=(',',':')), flush=True)
            break
        score_before=arm.score; t0=time.time(); res=arm.run_slice(ctx); res.runtime_seconds=max(0.0,time.time()-t0)
        after=pot_values(potfile); new_pairs=[(h,v) for h,v in after.items() if h not in prev]; prev=after
        discoveries=[v for _,v in new_pairs]
        for a in arms: a.on_new_discoveries(discoveries, ctx)
        marginal=len(new_pairs); reward=(marginal/res.runtime_seconds) if res.runtime_seconds>0 else 0.0
        arm.score=arm.score+alpha*(reward-arm.score); arm.runs+=1; arm.total_runtime+=res.runtime_seconds; arm.total_new_cracks+=marginal
        phase='warmup' if reason=='warmup' else 'adaptive'
        if args.schedule=='adaptive' and reason!='warmup':
            arm.last_run_adaptive_slice=current_adaptive_slice; current_adaptive_slice+=1
        n=arm.config.get('force_every_slices'); since=(current_adaptive_slice-arm.last_run_adaptive_slice) if n else None
        availability_fields = {k: v for k, v in getattr(arm, 'last_availability', {}).items() if k != 'available'}
        if console_mode == 'verbose':
            for unavailable in getattr(choose_arm, 'unavailable', []):
                print('Unavailable arm: '+json.dumps(unavailable,separators=(',',':')), flush=True)
        rec={'timestamp':utc_now(),'job_id':job,'phase':phase,'arm':arm.name,'attack_type':arm.type,'selection_reason':reason,
             'skip_before':res.skip_before,'next_skip_after':res.next_skip_after,'runtime_seconds':res.runtime_seconds,
             'exit_code':res.exit_code,'exit_meaning':EXIT_MEANINGS.get(res.exit_code,'error'),'progress_source':res.progress_source,
             'dictionary_candidate_cursor':res.dictionary_candidate_cursor,'new_cracks':marginal,'marginal_new_cracks':marginal,
             'total_cracks':len(after),'reward':reward,'score_before':score_before,'score_after':arm.score,'exhausted':arm.exhausted,
             'forced_cadence_interval':n,'slices_since_last_run':since,'overdue_ratio':(since/n if n and since is not None else None),
             'unavailable_arms':getattr(choose_arm, 'unavailable', []) if console_mode == 'verbose' else None, **availability_fields, **res.extra}
        with open(jobs_path,'a',encoding='utf-8') as f: f.write(json.dumps(rec,separators=(',',':'))+'\n')
        with open(os.path.join(args.out_dir,'hashcat_logs',f'job_{job:06d}.log'),'w',encoding='utf-8') as f: f.write(res.stdout+'\n'+res.stderr)
        completed_slices = job
        print_slice_progress(rec, total_slices, console_mode)
    final_discoveries = len(prev)
    print(format_final_summary(completed_slices, final_discoveries, time.time() - start_time, arms, jobs_path), flush=True)
    return 0
