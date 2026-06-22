from nsec3_candidate_scheduler.feedback.execution import candidate_cursor_from_summary, run_feedback_dictionary_slice
from nsec3_candidate_scheduler.arms.parent_domain_feedback import ParentDomainFeedbackArm


def test_progress_scaled_by_salts(fake_hashcat_summary):
    assert candidate_cursor_from_summary(fake_hashcat_summary(progress_cur=73_500_000, recovered_salts_total=50_000), 3184, 0) == (1470, 'progress_scaled_by_salts')


def test_progress_scaled_by_salts_clamps_to_total(fake_hashcat_summary):
    cursor, source = candidate_cursor_from_summary(fake_hashcat_summary(progress_cur=999_999_999, recovered_salts_total=1), 3184, 0)
    assert cursor == 3184
    assert source == 'progress_scaled_by_salts'


def test_progress_uses_restore_point_fallback(fake_hashcat_summary):
    assert candidate_cursor_from_summary(fake_hashcat_summary(restore_point=123), 3184, 100) == (123, 'restore_point')


def test_progress_unknown_when_no_valid_signal(fake_hashcat_summary):
    assert candidate_cursor_from_summary(fake_hashcat_summary(restore_point=100), 3184, 100) == (None, 'unknown')


def test_feedback_runtime_reached_unknown_progress_does_not_reset_skip(monkeypatch, tmp_path, make_context, write_lines):
    ctx = make_context(tmp_path)
    arm = ParentDomainFeedbackArm('parent-domain', 'parent_domain_feedback', {})
    state = arm._queue(ctx)
    write_lines(state.slice_path, ['x'] * 1000)
    state.save_active_slice({'active': True, 'slice_file': 'slice_candidates.txt', 'total_candidates': 1000, 'skip': 100})
    monkeypatch.setattr('nsec3_candidate_scheduler.feedback.execution.run_cmd', lambda cmd: (4, '{}', ''))
    result = run_feedback_dictionary_slice(arm, ctx)
    assert result.valid_work is False
    assert result.execution_status == 'failed_no_progress'
    assert state.load_active_slice()['skip'] == 100
