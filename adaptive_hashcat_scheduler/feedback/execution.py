from __future__ import annotations

from typing import Any

from adaptive_hashcat_scheduler.arms.base import SliceResult
from adaptive_hashcat_scheduler.feedback.queue import FeedbackQueueState
from adaptive_hashcat_scheduler.hashcat.runner import EXIT_MEANINGS, build_hashcat_command, run_cmd
from adaptive_hashcat_scheduler.hashcat.status import latest_summary


def candidate_cursor_from_summary(summary: dict[str, Any], total_candidates: int, skip_before: int) -> tuple[int, str]:
    cursor = None
    source = 'unknown'
    salts = summary.get('recovered_salts_total')
    progress_cur = summary.get('progress_cur')
    restore_point = summary.get('restore_point')
    if isinstance(progress_cur, int) and isinstance(salts, int) and salts > 0:
        cursor = progress_cur // salts
        source = 'progress_scaled_by_salts'
    elif isinstance(restore_point, int) and restore_point > skip_before:
        cursor = restore_point
        source = 'restore_point'
    if cursor is None:
        return skip_before, source
    return max(0, min(int(cursor), int(total_candidates))), source


def run_feedback_dictionary_slice(arm, context, extra: dict[str, Any] | None = None) -> SliceResult:
    q: FeedbackQueueState = arm._queue(context)
    before = q.queue_size_lines()
    active = q.prepare_active_slice()
    if not active.get('active'):
        return SliceResult(exit_code=1, stdout='', stderr='', exhausted=arm.exhausted, extra={
            'queue_size_before_slice': before,
            'candidates_written_to_slice': 0,
            'queue_size_after_slice': before,
            'feedback_valid_work': False,
            **(extra or {}),
        })

    slice_file = str(q.out_dir / active['slice_file'])
    total = int(active.get('total_candidates', 0) or 0)
    skip_before = int(active.get('skip', 0) or 0)
    if total <= 0 or skip_before >= total:
        q.clear_active_slice(delete_file=True)
        return SliceResult(exit_code=1, stdout='', stderr='active feedback slice already exhausted; cleared without launching hashcat\n', exhausted=arm.exhausted, extra={
            'active_slice': False,
            'active_slice_file': active.get('slice_file'),
            'active_slice_total_candidates': total,
            'active_slice_skip_before': skip_before,
            'active_slice_next_skip_after': total,
            'active_slice_remaining_before': max(0, total - skip_before),
            'active_slice_remaining_after': 0,
            'feedback_slice_exit_meaning': 'exhausted',
            'queue_size_before_slice': before,
            'candidates_written_to_slice': total,
            'queue_size_after_slice': q.queue_size_lines(),
            'feedback_valid_work': False,
            **(extra or {}),
        })

    remaining_before = total - skip_before
    session = f"adaptive_{int(__import__('time').time())}_{arm.name.replace('/', '_').replace('-', '_')}"
    cmd = build_hashcat_command(context.hashcat_bin, context.hash_mode, 0, context.slice_seconds,
                                context.potfile, context.hashes, candidate=slice_file,
                                skip=skip_before, limit=remaining_before,
                                extra_args=['--session', session],
                                optimized_kernels=context.hashcat_optimized_kernels, potfile_path_override=getattr(context, 'potfile_path_override', None))
    rc, out, err = run_cmd(cmd)
    summary = latest_summary(out + '\n' + err)
    exit_meaning = EXIT_MEANINGS.get(rc, 'error')
    next_skip = skip_before
    progress_source = 'unknown'
    valid_work = True
    if exit_meaning == 'exhausted':
        next_skip = total
        progress_source = 'exhausted'
        q.clear_active_slice(delete_file=True)
    elif exit_meaning == 'runtime_reached':
        next_skip, progress_source = candidate_cursor_from_summary(summary, total, skip_before)
        if next_skip <= skip_before:
            valid_work = False
            err += '\nwarning: feedback slice reached runtime without measurable candidate progress; preserving active slice skip\n'
            next_skip = skip_before
        q.update_active_slice_skip(next_skip)
    else:
        cursor, progress_source = candidate_cursor_from_summary(summary, total, skip_before)
        if cursor > skip_before:
            next_skip = cursor
            q.update_active_slice_skip(next_skip)
        else:
            valid_work = False
            err += '\nwarning: hashcat failed before useful feedback progress; preserving active slice skip\n'
            q.update_active_slice_skip(skip_before)

    after = q.queue_size_lines()
    remaining_after = max(0, total - next_skip) if q.load_active_slice().get('active') else 0
    return SliceResult(exit_code=rc, stdout=out, stderr=err, skip_before=skip_before, next_skip_after=next_skip,
                       progress_source=progress_source, dictionary_candidate_cursor=next_skip,
                       exhausted=arm.exhausted, extra={
        'active_slice': q.load_active_slice().get('active', False),
        'active_slice_file': active.get('slice_file'),
        'active_slice_total_candidates': total,
        'active_slice_skip_before': skip_before,
        'active_slice_next_skip_after': next_skip,
        'active_slice_remaining_before': remaining_before,
        'active_slice_remaining_after': remaining_after,
        'feedback_progress_source': progress_source,
        'feedback_progress_cur': summary.get('progress_cur'),
        'feedback_progress_total': summary.get('progress_total'),
        'feedback_recovered_salts_total': summary.get('recovered_salts_total'),
        'feedback_slice_exit_meaning': exit_meaning,
        'feedback_valid_work': valid_work,
        'queue_size_before_slice': before,
        'candidates_written_to_slice': total,
        'queue_size_after_slice': after,
        **(extra or {}),
    })
