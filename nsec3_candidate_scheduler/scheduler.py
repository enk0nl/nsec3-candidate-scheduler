from __future__ import annotations
from dataclasses import dataclass
import datetime as dt, json, os, random, re, shutil, time
from typing import Any

from nsec3_candidate_scheduler.config import load_config
from nsec3_candidate_scheduler.hashcat.potfile import iter_potfile_cracks
from nsec3_candidate_scheduler.hashcat.runner import EXIT_MEANINGS
from nsec3_candidate_scheduler.arms.registry import FEEDBACK_TYPES, OSINT_TYPES, make_arm
from nsec3_candidate_scheduler.naming import safe_name, arm_family, arm_short_name

@dataclass
class HashcatFailureClassification:
    reason: str
    hint: str
    retryable_with_unoptimized: bool
    parse_error_count: int | None = None
    parse_error_total: int | None = None

@dataclass
class SchedulerContext:
    hashes: str; hash_mode: int; out_dir: str; slice_seconds: int; potfile: str
    hashcat_bin: str='hashcat'; default_limit: int=1000000; hashcat_optimized_kernels: bool=True
    optimized_kernel_failover: bool=True
    potfile_path_override: str | None = None

def utc_now(): return dt.datetime.now(dt.timezone.utc).isoformat()
def ensure_dir(p): os.makedirs(p, exist_ok=True)

def pot_values(path, *, allow_empty_plaintext: bool = True):
    if not os.path.exists(path): return {}
    return {h:v for h,v in iter_potfile_cracks(path, allow_empty_plaintext=allow_empty_plaintext)}



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
    if arm.type in OSINT_TYPES and not available:
        state = getattr(arm, 'state', None)
        reason = {
            'not_started': 'osint_not_started',
            'running': 'osint_running',
            'collecting_results': 'osint_collecting_results',
            'exhausted': 'osint_no_candidates',
            'failed': 'osint_failed',
        }.get(state, 'unavailable')
        return {'available': False, 'availability_reason': reason, 'runnable': False, 'osint_state': state}
    return {'available': available, 'availability_reason': None if available else 'unavailable'}

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


TOKEN_LENGTH_SUMMARY_RE = re.compile(r"Token length exception:\s*(\d+)\s*/\s*(\d+)\s*hashes", re.IGNORECASE)
OPTIMIZED_KERNEL_RETRY_REASONS = {"optimized_kernel_failure", "optimized_kernel_all_hashes_token_length"}

def _parse_token_length_summary(text: str) -> tuple[int | None, int | None]:
    match = TOKEN_LENGTH_SUMMARY_RE.search(text)
    if not match:
        return None, None
    return int(match.group(1)), int(match.group(2))

def classify_hashcat_failure(
    *,
    optimized_kernels: bool,
    exit_code: int,
    exit_meaning: str,
    stdout: str,
    stderr: str,
    failover_enabled: bool = True,
) -> HashcatFailureClassification | None:
    text = stdout + '\n' + stderr
    text_lc = text.lower()
    parse_error_count, parse_error_total = _parse_token_length_summary(text)
    all_hashes_token_length = (
        parse_error_count is not None
        and parse_error_total is not None
        and parse_error_total > 0
        and parse_error_count == parse_error_total
        and 'no hashes loaded' in text_lc
    )

    if exit_code in (0, 1, 4) or exit_meaning != 'error':
        return None

    if all_hashes_token_length and not optimized_kernels:
        return HashcatFailureClassification(
            reason='hashfile_parse_error_all_hashes_token_length',
            hint='Hashcat rejected all hashes with Token length exception and no hashes were loaded. This looks like a hashfile, hash-mode, or input-format error.',
            retryable_with_unoptimized=False,
            parse_error_count=parse_error_count,
            parse_error_total=parse_error_total,
        )

    if optimized_kernels and 'optimized' in text_lc and ('length' in text_lc or 'plaintext' in text_lc):
        if failover_enabled:
            hint = 'Hashcat failed with optimized kernels enabled. Retrying with unoptimized kernels.'
        else:
            hint = 'Hashcat failed with optimized kernels enabled. Automatic failover is disabled; continuing with optimized kernels.'
        return HashcatFailureClassification('optimized_kernel_failure', hint, failover_enabled, parse_error_count, parse_error_total)

    if all_hashes_token_length and optimized_kernels:
        if failover_enabled:
            hint = 'Hashcat rejected all hashes with Token length exception while optimized kernels were enabled. Retrying with unoptimized kernels.'
        else:
            hint = 'Hashcat rejected all hashes with Token length exception while optimized kernels were enabled. Automatic failover is disabled; continuing with optimized kernels.'
        return HashcatFailureClassification('optimized_kernel_all_hashes_token_length', hint, failover_enabled, parse_error_count, parse_error_total)

    return None

def _optimized_kernel_failure_hint(enabled: bool, exit_code: int, stdout: str, stderr: str, failover_enabled: bool = True) -> str | None:
    classification = classify_hashcat_failure(optimized_kernels=enabled, exit_code=exit_code, exit_meaning=EXIT_MEANINGS.get(exit_code, 'error'), stdout=stdout, stderr=stderr, failover_enabled=failover_enabled)
    if classification and classification.reason in OPTIMIZED_KERNEL_RETRY_REASONS:
        return classification.hint
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
    startup_debug_flags = {
        'verbose': getattr(args, 'verbose', False) or bool(cfg.get('verbose', False)),
        'debug': bool(cfg.get('debug', False)),
        'debug_startup': bool(cfg.get('debug_startup', False)),
        'debug_arms': bool(cfg.get('debug_arms', False)),
    }
    arm_configs = [{**a, **{k: v for k, v in startup_debug_flags.items() if v}} for a in cfg['arms']]
    arms=[make_arm(a) for a in arm_configs]
    if not arms: raise ValueError('config has no enabled arms')
    cfg_warmup = cfg.get('warmup') or {}
    warmup_scoring = cfg_warmup.get('scoring', 'arm_local')
    cfg_hashcat = cfg.get('hashcat') or {}
    optimized_kernels = bool(cfg_hashcat.get('optimized_kernels', True))
    optimized_kernel_failover = bool(cfg_hashcat.get('optimized_kernel_failover', True))
    if getattr(args, 'optimized_kernel_failover', None) is not None:
        optimized_kernel_failover = bool(args.optimized_kernel_failover)
    if getattr(args, 'no_optimized_kernels', False):
        optimized_kernels = False
    ctx=SchedulerContext(args.hashes,args.hash_mode,args.out_dir,args.slice_seconds,potfile,getattr(args,'hashcat_bin','hashcat'),getattr(args,'default_limit',1000000),optimized_kernels,optimized_kernel_failover)
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
    pending_retry = None
    try:
        while completed_slices < total_slices or pending_retry is not None:
            job = attempted_jobs + 1
            choose_arm.skip_once = skipped_this_completed_slice
            if pending_retry is not None:
                arm, reason, retry_of_job_id, retry_reason = pending_retry
                pending_retry = None
            else:
                retry_of_job_id = None
                retry_reason = None
                arm,reason=choose_arm(arms,args.schedule,warmup if args.schedule=='adaptive' else [],epsilon,rng,current_adaptive_slice)
            if arm is None:
                if skipped_this_completed_slice:
                    skipped_this_completed_slice = set()
                    continue
                if console_mode == 'verbose':
                    for unavailable in getattr(choose_arm, 'unavailable', []):
                        print('Unavailable arm: '+json.dumps(unavailable,separators=(',',':')), flush=True)
                break
            attempted_jobs += 1
            phase='warmup' if reason=='warmup' else 'adaptive'
            use_arm_local = phase == 'warmup' and warmup_scoring == 'arm_local'
            arm_local_potfile = None
            if use_arm_local:
                arm_local_potfile = os.path.join(warmup_potfiles_dir, f'{safe_name(arm.name)}.potfile')
                _copy_potfile_baseline(warmup_baseline_potfile, arm_local_potfile)
                ctx.potfile_path_override = arm_local_potfile
            else:
                ctx.potfile_path_override = None
            score_before=arm.score; requested_slice_seconds=int(arm.config.get('slice_seconds', args.slice_seconds)); original_slice_seconds=ctx.slice_seconds; ctx.slice_seconds=requested_slice_seconds
            t0=time.time(); res=arm.run_slice(ctx); res.runtime_seconds=max(0.0,time.time()-t0)
            ctx.slice_seconds=original_slice_seconds; ctx.potfile_path_override = None
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
            discoveries=[v for _,v in new_pairs if v]
            feedback_expansion_metrics = {}
            for a in arms:
                expansion = a.on_new_discoveries(discoveries, ctx)
                if discoveries and expansion:
                    feedback_expansion_metrics[a.name] = expansion
                    if (console_mode == 'verbose' or a.config.get('debug_expansions')) and expansion.get('parent_debug_expansions'):
                        for debug_record in expansion.get('parent_debug_expansions', []):
                            print('Feedback expansion: '+json.dumps({'arm': a.name, **debug_record}, separators=(',', ':')), flush=True)
            exit_meaning = EXIT_MEANINGS.get(res.exit_code,'error')
            classification = classify_hashcat_failure(optimized_kernels=ctx.hashcat_optimized_kernels, exit_code=res.exit_code, exit_meaning=exit_meaning, stdout=res.stdout, stderr=res.stderr, failover_enabled=ctx.optimized_kernel_failover)
            optimized_hint = classification.hint if classification and classification.reason in OPTIMIZED_KERNEL_RETRY_REASONS else None
            optimized_failure = bool(classification and classification.retryable_with_unoptimized and classification.reason in OPTIMIZED_KERNEL_RETRY_REASONS)
            invalid_classified_failure = bool(classification and classification.reason in (OPTIMIZED_KERNEL_RETRY_REASONS | {'hashfile_parse_error_all_hashes_token_length'}))
            valid_work = bool(res.valid_work and res.extra.get('feedback_valid_work', True)) and not invalid_classified_failure
            marginal=len(new_pairs) if valid_work else 0
            reward_count = arm_local_new_cracks if use_arm_local else marginal
            reward=(reward_count/res.runtime_seconds) if res.runtime_seconds>0 and valid_work else 0.0
            scored = bool(valid_work)
            if valid_work:
                arm.score=arm.score+alpha*(reward-arm.score)
                arm.runs+=1; arm.total_runtime+=res.runtime_seconds; arm.total_new_cracks+=marginal
            if args.schedule=='adaptive' and reason!='warmup' and valid_work:
                arm.last_run_adaptive_slice=current_adaptive_slice; current_adaptive_slice+=1
            n=arm.config.get('force_every_slices'); since=(current_adaptive_slice-arm.last_run_adaptive_slice) if n else None
            availability_fields = {k: v for k, v in getattr(arm, 'last_availability', {}).items() if k != 'available'}
            if classification and classification.reason in OPTIMIZED_KERNEL_RETRY_REASONS and not ctx.optimized_kernel_failover:
                availability_fields['availability_reason'] = 'optimized_kernel_failure_no_failover'
                arm.optimized_kernel_failure_count = getattr(arm, 'optimized_kernel_failure_count', 0) + 1
                arm.last_optimized_kernel_failure_job_id = job
                arm.optimized_kernel_failure_cooldown_slices = 1
            if console_mode == 'verbose':
                for unavailable in getattr(choose_arm, 'unavailable', []):
                    print('Unavailable arm: '+json.dumps(unavailable,separators=(',',':')), flush=True)
            rec={'timestamp':utc_now(),'job_id':job,'phase':phase,'arm':arm.name,'arm_family':arm_family(arm.name),'arm_short_name':arm_short_name(arm.name),'arm_type':arm.type,'attack_type':arm.type,'selection_reason':reason,'requested_slice_seconds':requested_slice_seconds,
                 'skip_before':res.skip_before,'next_skip_after':res.next_skip_after,'runtime_seconds':res.runtime_seconds,
                 'exit_code':res.exit_code,'exit_meaning':exit_meaning,'execution_status':res.execution_status,'valid_work':valid_work,'scored':scored,'progress_source':res.progress_source,
                 'hashcat_optimized_kernels':ctx.hashcat_optimized_kernels,'hashcat_optimized_kernel_hint':optimized_hint,
                 'optimized_kernel_failover_enabled':ctx.optimized_kernel_failover if (classification and classification.reason in OPTIMIZED_KERNEL_RETRY_REASONS) else None,
                 'retryable':classification.retryable_with_unoptimized if (classification and classification.reason in OPTIMIZED_KERNEL_RETRY_REASONS) else None,
                 'retry_reason':classification.reason if classification and classification.reason in OPTIMIZED_KERNEL_RETRY_REASONS else retry_reason,
                 'retry_scheduled':optimized_failure if (classification and classification.reason in OPTIMIZED_KERNEL_RETRY_REASONS) else False if (classification and classification.reason == 'hashfile_parse_error_all_hashes_token_length') else None,
                 'retry_of_job_id':retry_of_job_id,
                 'hashcat_failure_class':classification.reason if classification and classification.reason == 'hashfile_parse_error_all_hashes_token_length' else None,
                 'hashcat_parse_error_count':classification.parse_error_count if classification else None,
                 'hashcat_parse_error_total':classification.parse_error_total if classification else None,
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
            if optimized_failure and ctx.optimized_kernel_failover:
                if hasattr(arm, 'next_skip') and res.skip_before is not None:
                    arm.next_skip = res.skip_before
                ctx.hashcat_optimized_kernels = False
                pending_retry = (arm, reason, job, classification.reason)
            elif classification and classification.reason in OPTIMIZED_KERNEL_RETRY_REASONS:
                if hasattr(arm, 'next_skip') and res.skip_before is not None:
                    arm.next_skip = res.skip_before
                skipped_this_completed_slice.add(arm.name)
            elif classification and classification.reason == 'hashfile_parse_error_all_hashes_token_length':
                if hasattr(arm, 'next_skip') and res.skip_before is not None:
                    arm.next_skip = res.skip_before
                skipped_this_completed_slice.add(arm.name)
            else:
                skipped_this_completed_slice = set()
            print_slice_progress(rec, total_slices, console_mode)
    finally:
        for _arm in arms:
            cleaner=getattr(_arm, 'cleanup', None)
            if callable(cleaner): cleaner()
    final_discoveries = len(prev)
    print(format_final_summary(completed_slices, final_discoveries, time.time() - start_time, arms, jobs_path), flush=True)
    return 0
