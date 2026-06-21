from adaptive_hashcat_scheduler.arms.parent_domain_feedback import ParentDomainFeedbackArm
from adaptive_hashcat_scheduler.feedback.execution import run_feedback_dictionary_slice


def _active_parent_arm(tmp_path, make_context, write_lines, *, total=3184, skip=0):
    ctx = make_context(tmp_path)
    arm = ParentDomainFeedbackArm('parent-domain', 'parent_domain_feedback', {})
    state = arm._queue(ctx)
    write_lines(state.slice_path, ['x'] * total)
    state.save_active_slice({'active': True, 'slice_file': 'slice_candidates.txt', 'total_candidates': total, 'skip': skip})
    return ctx, arm, state


def test_runtime_reached_updates_skip_from_scaled_progress(monkeypatch, tmp_path, make_context, write_lines):
    ctx, arm, state = _active_parent_arm(tmp_path, make_context, write_lines, total=3184, skip=0)
    monkeypatch.setattr('adaptive_hashcat_scheduler.feedback.execution.run_cmd', lambda cmd: (4, '{"progress":[73500000,999],"recovered_salts":[0,50000]}', ''))
    result = run_feedback_dictionary_slice(arm, ctx)
    active = state.load_active_slice()
    assert result.executed is True
    assert active['active'] is True
    assert active['skip'] == 1470
    assert active['slice_file'] == 'slice_candidates.txt'


def test_runtime_reached_resume_uses_skip(monkeypatch, tmp_path, make_context, write_lines):
    ctx, arm, state = _active_parent_arm(tmp_path, make_context, write_lines, total=3184, skip=1470)
    commands = []
    monkeypatch.setattr('adaptive_hashcat_scheduler.feedback.execution.run_cmd', lambda cmd: commands.append(cmd) or (1, '', ''))
    run_feedback_dictionary_slice(arm, ctx)
    assert '--skip' in commands[0]
    assert commands[0][commands[0].index('--skip') + 1] == '1470'
    assert str(state.slice_path) == commands[0][-1]


def test_runtime_reached_without_progress_preserves_skip(monkeypatch, tmp_path, make_context, write_lines, read_lines):
    ctx, arm, state = _active_parent_arm(tmp_path, make_context, write_lines, total=1000, skip=100)
    monkeypatch.setattr('adaptive_hashcat_scheduler.feedback.execution.run_cmd', lambda cmd: (4, '{}', ''))
    result = run_feedback_dictionary_slice(arm, ctx)
    assert state.load_active_slice()['skip'] == 100
    assert state.load_active_slice()['active'] is True
    assert result.execution_status == 'failed_no_progress'
    assert result.valid_work is False
    assert len(read_lines(state.slice_path)) == 1000


def test_exhausted_clears_active_slice(monkeypatch, tmp_path, make_context, write_lines, read_lines):
    ctx, arm, state = _active_parent_arm(tmp_path, make_context, write_lines, total=1000, skip=400)
    monkeypatch.setattr('adaptive_hashcat_scheduler.feedback.execution.run_cmd', lambda cmd: (1, '', ''))
    result = run_feedback_dictionary_slice(arm, ctx)
    assert result.executed is True
    assert state.load_active_slice()['active'] is False
    assert read_lines(state.slice_path) == []


def test_feedback_execution_never_launches_with_skip_equal_total(monkeypatch, tmp_path, make_context, write_lines):
    ctx, arm, state = _active_parent_arm(tmp_path, make_context, write_lines, total=100, skip=100)
    launched = []
    monkeypatch.setattr('adaptive_hashcat_scheduler.feedback.execution.run_cmd', lambda cmd: launched.append(cmd) or (0, '', ''))
    result = run_feedback_dictionary_slice(arm, ctx)
    assert launched == []
    assert result.executed is False


def test_feedback_execution_uses_shared_potfile(monkeypatch, tmp_path, make_context, write_lines):
    ctx, arm, state = _active_parent_arm(tmp_path, make_context, write_lines, total=5, skip=0)
    ctx.potfile_path_override = None
    commands = []
    monkeypatch.setattr('adaptive_hashcat_scheduler.feedback.execution.run_cmd', lambda cmd: commands.append(cmd) or (1, '', ''))
    run_feedback_dictionary_slice(arm, ctx)
    assert commands[0][commands[0].index('--potfile-path') + 1] == str(tmp_path / 'run.pot')
