from __future__ import annotations
from dataclasses import dataclass
import datetime as dt, json, os, random, re, shutil, time
from typing import Any

FEEDBACK_TYPES = {'feedback', 'predictive_prefix', 'predictive_suffix', 'permutation', 'static_affix_feedback', 'parent_domain_feedback'}

from adaptive_hashcat_scheduler.config import load_config
from adaptive_hashcat_scheduler.hashcat.potfile import iter_potfile_cracks
from adaptive_hashcat_scheduler.hashcat.runner import EXIT_MEANINGS
from adaptive_hashcat_scheduler.arms.dictionary import DictionaryArm
from adaptive_hashcat_scheduler.arms.brute_force import BruteForceArm
from adaptive_hashcat_scheduler.arms.feedback_common import CommonFeedbackArm
from adaptive_hashcat_scheduler.arms.feedback_predictive import PredictiveFeedbackArm
from adaptive_hashcat_scheduler.arms.permutation import PermutationArm
from adaptive_hashcat_scheduler.arms.static_affix_feedback import StaticAffixFeedbackArm
from adaptive_hashcat_scheduler.arms.parent_domain_feedback import ParentDomainFeedbackArm
from adaptive_hashcat_scheduler.arms.amass_osint import AmassOsintArm
from adaptive_hashcat_scheduler.arms.subfinder_osint import SubfinderOsintArm

@dataclass
class SchedulerContext:
    hashes: str; hash_mode: int; out_dir: str; slice_seconds: int; potfile: str
    hashcat_bin: str='hashcat'; default_limit: int=1000000; hashcat_optimized_kernels: bool=True
    potfile_path_override: str | None = None

def utc_now(): return dt.datetime.now(dt.timezone.utc).isoformat()
def ensure_dir(p): os.makedirs(p, exist_ok=True)

def pot_values(path):
    if not os.path.exists(path): return {}
    return {h:v for h,v in iter_potfile_cracks(path)}


def _safe_potfile_stem(name: str) -> str:
    safe = re.sub(r'[^A-Za-z0-9._-]+', '_', name).strip('._')
    return safe or 'arm'

def _copy_potfile_baseline(source: str, dest: str) -> None:
    ensure_dir(os.path.dirname(dest))
    if os.path.exists(source) and os.path.getsize(source) > 0:
        shutil.copyfile(source, dest)
    else:
        open(dest, 'w', encoding='utf-8').close()

def _append_potfile_pairs(path: str, pairs: list[tuple[str, str]]) -> None:
    if not pairs:
        return
    with open(path, 'a', encoding='utf-8') as f:
        for h, value in pairs:
            f.write(f'{h}:{value}\n')

def make_arm(cfg):
    t=cfg['type']; name=cfg['name']
    if t=='dictionary': return DictionaryArm(name,t,cfg)
    if t=='brute_force': return BruteForceArm(name,t,cfg)
    if t=='feedback': return CommonFeedbackArm(name,t,cfg)
    if t in {'predictive_prefix','predictive_suffix'}: return PredictiveFeedbackArm(name,t,cfg)
    if t=='permutation': return PermutationArm(name,t,cfg)
    if t=='static_affix_feedback': return StaticAffixFeedbackArm(name,t,cfg)
    if t=='parent_domain_feedback': return ParentDomainFeedbackArm(name,t,cfg)
    if t=='amass_osint': return AmassOsintArm(name,t,cfg)
    if t=='subfinder_osint': return SubfinderOsintArm(name,t,cfg)
    raise ValueError(f'unknown arm type: {t}')

def _feedback_pending_virtual_streams(arm, context) -> int:
    counter = getattr(arm, 'pending_virtual_stream_count', None)
    if callable(counter):
        try:
            return max(0, int(counter(context)))
        except (TypeError, ValueError):
            return 0
    return 0

def _feedback_availability(arm, context, current_adaptive_slice, force_queue: bool = False) -> dict[str, Any]:
    queue_size = arm._queue(context).queue_size_lines()
    pending_virtual_streams = _feedback_pending_virtual_streams(arm, context)
    min_queue_size = int(arm.config.get('min_queue_size', 1))
    min_slices = int(arm.config.get('min_slices_between_runs', 0))
    slices_since = current_adaptive_slice - arm.last_run_adaptive_slice
    active_slice = arm._queue(context).active_slice_is_active()
    runnable = active_slice or queue_size > 0 or pending_virtual_streams > 0
    reason = None
    if arm.exhausted:
        reason = 'exhausted'
    elif slices_since < min_slices:
        reason = 'cooldown'
    elif not runnable:
        reason = 'forced_cadence_empty_queue' if force_queue else 'empty_queue'
    elif queue_size < min_queue_size and pending_virtual_streams == 0 and not active_slice and not force_queue:
        reason = 'queue_below_minimum'
    return {
        'available': reason is None,
        'availability_reason': reason,
        'min_slices_between_runs': min_slices,
        'slices_since_last_run': slices_since,
        'min_queue_size': min_queue_size,
        'queue_size': queue_size,
        'pending_virtual_streams': pending_virtual_streams,
        'active_slice': active_slice,
        'cooldown_satisfied': slices_since >= min_slices,
        'runnable': runnable,
    }

def _availability(arm, context, current_adaptive_slice, force_queue: bool = False) -> dict[str, Any]:
    if arm.type in FEEDBACK_TYPES:
        return _feedback_availability(arm, context, current_adaptive_slice, force_queue)
    available = arm.is_available(context)
    reason = None if available else 'unavailable'
    state = getattr(arm, 'state', None)
    if getattr(arm, 'type', None) in {'amass_osint', 'subfinder_osint'} and not available:
        if state in {'not_started', 'running', 'collecting_results'}:
            reason = 'osint_running'
        elif state == 'exhausted':
            reason = 'osint_no_candidates'
        elif state == 'failed':
            reason = 'osint_failed'
    return {'available': available, 'availability_reason': reason, 'runnable': available, 'osint_state': state}

def choose_arm(arms, schedule, warmup, epsilon, rng, current_adaptive_slice):
    context = choose_arm.context
    choose_arm.unavailable = []
    skipped_once = getattr(choose_arm, 'skip_once', set())
    normal=[]
    for a in arms:
        if a.name in skipped_once:
            continue
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
    first_ready=[a for a in normal if getattr(a, 'first_run_pending', False)]
    if first_ready:
        return sorted(first_ready, key=lambda a:(a.runs,a.total_runtime,a.name))[0], 'first_run_ready'
    due=[]
    for a in arms:
        if a.name in skipped_once:
            continue
        n=a.config.get('force_every_slices')
        if not n: continue
        since=current_adaptive_slice-a.last_run_adaptive_slice
        if since < n: continue
        info = _availability(a, context, current_adaptive_slice, force_queue=True)
        if info['available']:
            a.last_availability = info
            due.append((since/n,a.runs,a.total_runtime,a.name,a))
        elif info.get('availability_reason'):
            forced_skip = {'arm': a.name, 'forced_due': True, 'forced_cadence_due': True, **info}
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


def _optimized_kernel_failure_hint(enabled: bool, exit_code: int, stdout: str, stderr: str) -> str | None:
    if not enabled or exit_code in (0, 1, 4):
        return None
    text = (stdout + '\n' + stderr).lower()
    if 'optimized' in text and ('length' in text or 'plaintext' in text):
        return 'Hashcat failed with optimized kernels enabled. Try rerunning with --no-optimized-kernels.'
    return None

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
        slice_detail = ""
        if rec.get('active_slice_total_candidates') is not None:
            slice_detail = (
                f" slice={rec.get('active_slice_skip_before')}->"
                f"{rec.get('active_slice_next_skip_after')}/"
                f"{rec.get('active_slice_total_candidates')}"
            )
        details = (f" queue={before}->{after} written={written} enq={enqueued}"
                   f"{slice_detail}"
                   f" gate_queue={rec.get('queue_size')}/{rec.get('min_queue_size')}"
                   f" cooldown={rec.get('slices_since_last_run')}/{rec.get('min_slices_between_runs')}")
    if rec.get('phase') == 'warmup' and rec.get('warmup_scoring') == 'arm_local':
        return (
            f"{prefix}{details} local={rec.get('arm_local_new_cracks')} "
            f"shared_new={rec.get('shared_new_cracks')} dup={rec.get('duplicate_cracks_vs_shared')} "
            f"reward={_fmt_float(rec['reward_used_for_score'])} "
            f"score={_fmt_float(rec['score_before'], 2)}->{_fmt_float(rec['score_after'], 2)} "
            f"runtime={_fmt_float(rec['runtime_seconds'], 1)}s"
        )
    return (
        f"{prefix}{details} new={rec['new_cracks']} total={rec['total_cracks']} "
        f"reward={_fmt_float(rec['reward_used_for_score'])} "
        f"score={_fmt_float(rec['score_before'], 2)}->{_fmt_float(rec['score_after'], 2)} "
        f"runtime={_fmt_float(rec['runtime_seconds'], 1)}s"
    )

def format_slice_verbose(rec: dict[str, Any], total_slices: int) -> str:
    lines = [
        f"[{rec['job_id']}/{total_slices}] {rec['phase'].upper()}",
        f"Arm: {rec['arm']}",
        f"Reason: {rec['selection_reason']}",
        f"Hashcat optimized kernels: {'enabled' if rec.get('hashcat_optimized_kernels') else 'disabled'}",
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
        if rec.get('active_slice_total_candidates') is not None:
            lines.extend([
                f"Active slice: {rec.get('active_slice_file')}",
                f"Active slice skip: {rec.get('active_slice_skip_before')} -> {rec.get('active_slice_next_skip_after')} / {rec.get('active_slice_total_candidates')}",
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
    cfg_warmup = cfg.get('warmup') or {}
    warmup_scoring = cfg_warmup.get('scoring', 'arm_local')
    cfg_hashcat = cfg.get('hashcat') or {}
    optimized_kernels = bool(cfg_hashcat.get('optimized_kernels', True))
    if getattr(args, 'no_optimized_kernels', False):
        optimized_kernels = False
    ctx=SchedulerContext(args.hashes,args.hash_mode,args.out_dir,args.slice_seconds,potfile,getattr(args,'hashcat_bin','hashcat'),getattr(args,'default_limit',1000000),optimized_kernels)
    ctx.verbose_osint = bool(getattr(args, 'verbose', False))
    choose_arm.context=ctx
    for _arm in arms:
        starter=getattr(_arm, 'start', None)
        if callable(starter): starter(ctx)
    alpha=float(args.alpha if args.alpha is not None else cfg.get('alpha',0.2)); epsilon=float(args.epsilon if args.epsilon is not None else cfg.get('epsilon',0.1))
    rng=random.Random(args.random_seed if args.random_seed is not None else cfg.get('random_seed',0))
    warmup=[a.name for a in arms if getattr(a, 'warmup_eligible', True)]
    warmup_baseline_potfile=os.path.join(args.out_dir,'warmup_baseline.potfile')
    shutil.copyfile(potfile, warmup_baseline_potfile)
    warmup_baseline=pot_values(warmup_baseline_potfile)
    warmup_potfiles_dir=os.path.join(args.out_dir,'warmup_potfiles')
    if warmup_scoring == 'arm_local': ensure_dir(warmup_potfiles_dir)
    prev=pot_values(potfile); current_adaptive_slice=0
    total_slices=args.total_slices or 0
    completed_slices = 0
    start_time = time.time()
    console_mode = 'quiet' if getattr(args, 'quiet', False) else ('verbose' if getattr(args, 'verbose', False) else 'default')
    attempted_jobs = 0
    skipped_this_completed_slice = set()
    try:
        while completed_slices < total_slices:
            job = completed_slices + 1
            choose_arm.skip_once = skipped_this_completed_slice
            arm,reason=choose_arm(arms,args.schedule,warmup if args.schedule=='adaptive' else [],epsilon,rng,current_adaptive_slice)
            if arm is None:
                if console_mode == 'verbose':
                    for unavailable in getattr(choose_arm, 'unavailable', []):
                        print('Unavailable arm: '+json.dumps(unavailable,separators=(',',':')), flush=True)
                break
            attempted_jobs += 1
            phase='warmup' if reason=='warmup' else 'adaptive'
            use_arm_local = phase == 'warmup' and warmup_scoring == 'arm_local'
            arm_local_potfile = None
            if use_arm_local:
                arm_local_potfile = os.path.join(warmup_potfiles_dir, f'{_safe_potfile_stem(arm.name)}.potfile')
                _copy_potfile_baseline(warmup_baseline_potfile, arm_local_potfile)
                ctx.potfile_path_override = arm_local_potfile
            else:
                ctx.potfile_path_override = None
            score_before=arm.score; t0=time.time(); res=arm.run_slice(ctx); res.runtime_seconds=max(0.0,time.time()-t0)
            ctx.potfile_path_override = None
            if not res.executed:
                skipped_this_completed_slice.add(arm.name)
                if console_mode == 'verbose':
                    print('[skip] '+json.dumps({'arm': arm.name, 'reason': res.execution_status, **getattr(arm, 'last_availability', {}), **res.extra}, separators=(',', ':')), flush=True)
                continue
            arm_local_cracks = arm_local_new_cracks = duplicate_cracks_vs_shared = 0
            if use_arm_local:
                arm_local_after = pot_values(arm_local_potfile)
                arm_local_new_pairs=[(h,v) for h,v in arm_local_after.items() if h not in warmup_baseline]
                arm_local_cracks=len(arm_local_after)
                arm_local_new_cracks=len(arm_local_new_pairs)
                shared_before=pot_values(potfile)
                new_pairs=[(h,v) for h,v in arm_local_new_pairs if h not in shared_before]
                duplicate_cracks_vs_shared=arm_local_new_cracks-len(new_pairs)
                _append_potfile_pairs(potfile, new_pairs)
                after=pot_values(potfile); prev=after
            else:
                after=pot_values(potfile); new_pairs=[(h,v) for h,v in after.items() if h not in prev]; prev=after
            discoveries=[v for _,v in new_pairs]
            feedback_expansion_metrics = {}
            for a in arms:
                expansion = a.on_new_discoveries(discoveries, ctx)
                if discoveries and expansion:
                    feedback_expansion_metrics[a.name] = expansion
                    if (console_mode == 'verbose' or a.config.get('debug_expansions')) and expansion.get('parent_debug_expansions'):
                        for debug_record in expansion.get('parent_debug_expansions', []):
                            print('Feedback expansion: '+json.dumps({'arm': a.name, **debug_record}, separators=(',', ':')), flush=True)
            valid_work = bool(res.valid_work and res.extra.get('feedback_valid_work', True))
            marginal=len(new_pairs)
            reward_count = arm_local_new_cracks if use_arm_local else marginal
            reward=(reward_count/res.runtime_seconds) if res.runtime_seconds>0 and valid_work else 0.0
            if valid_work:
                arm.score=arm.score+alpha*(reward-arm.score)
            arm.runs+=1; arm.total_runtime+=res.runtime_seconds; arm.total_new_cracks+=marginal
            if args.schedule=='adaptive' and reason!='warmup' and valid_work:
                arm.last_run_adaptive_slice=current_adaptive_slice; current_adaptive_slice+=1
            n=arm.config.get('force_every_slices'); since=(current_adaptive_slice-arm.last_run_adaptive_slice) if n else None
            availability_fields = {k: v for k, v in getattr(arm, 'last_availability', {}).items() if k != 'available'}
            optimized_hint = _optimized_kernel_failure_hint(ctx.hashcat_optimized_kernels, res.exit_code, res.stdout, res.stderr)
            if console_mode == 'verbose':
                for unavailable in getattr(choose_arm, 'unavailable', []):
                    print('Unavailable arm: '+json.dumps(unavailable,separators=(',',':')), flush=True)
            rec={'timestamp':utc_now(),'job_id':job,'phase':phase,'arm':arm.name,'attack_type':arm.type,'selection_reason':reason,
                 'skip_before':res.skip_before,'next_skip_after':res.next_skip_after,'runtime_seconds':res.runtime_seconds,
                 'exit_code':res.exit_code,'exit_meaning':EXIT_MEANINGS.get(res.exit_code,'error'),'execution_status':res.execution_status,'valid_work':valid_work,'progress_source':res.progress_source,
                 'hashcat_optimized_kernels':ctx.hashcat_optimized_kernels,'hashcat_optimized_kernel_hint':optimized_hint,
                 'dictionary_candidate_cursor':res.dictionary_candidate_cursor,'new_cracks':marginal,'marginal_new_cracks':marginal,'shared_new_cracks':marginal,
                 'warmup_scoring':warmup_scoring if phase == 'warmup' else 'shared_marginal',
                 'potfile_scope':'arm_local' if use_arm_local else 'shared',
                 'arm_local_cracks':arm_local_cracks if phase == 'warmup' else None,
                 'arm_local_new_cracks':arm_local_new_cracks if phase == 'warmup' else None,
                 'duplicate_cracks_vs_shared':duplicate_cracks_vs_shared if phase == 'warmup' else None,
                 'reward_used_for_score':reward,
                 'total_cracks':len(after),'reward':reward,'score_before':score_before,'score_after':arm.score,'exhausted':arm.exhausted,
                 'forced_cadence_interval':n,'slices_since_last_run':since,'overdue_ratio':(since/n if n and since is not None else None),
                 'unavailable_arms':getattr(choose_arm, 'unavailable', []) if console_mode == 'verbose' else None,
                 'feedback_expansion_metrics':feedback_expansion_metrics or None, **availability_fields, **res.extra}
            with open(jobs_path,'a',encoding='utf-8') as f: f.write(json.dumps(rec,separators=(',',':'))+'\n')
            with open(os.path.join(args.out_dir,'hashcat_logs',f'job_{job:06d}.log'),'w',encoding='utf-8') as f: f.write(res.stdout+'\n'+res.stderr)
            completed_slices += 1
            skipped_this_completed_slice = set()
            print_slice_progress(rec, total_slices, console_mode)
    finally:
        for _arm in arms:
            cleaner=getattr(_arm, 'cleanup', None)
            if callable(cleaner): cleaner()
    final_discoveries = len(prev)
    print(format_final_summary(completed_slices, final_discoveries, time.time() - start_time, arms, jobs_path), flush=True)
    return 0
