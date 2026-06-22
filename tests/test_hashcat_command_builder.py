from nsec3_candidate_scheduler.arms.parent_domain_feedback import ParentDomainFeedbackArm
from nsec3_candidate_scheduler.feedback.execution import run_feedback_dictionary_slice
from nsec3_candidate_scheduler.hashcat.runner import build_hashcat_command


def test_hashcat_command_supports_potfile_override(tmp_path):
    cmd = build_hashcat_command('hashcat', 8300, 0, 60, str(tmp_path / 'run.pot'), 'hashes', candidate='words', potfile_path_override=tmp_path / 'local.pot')
    assert cmd[cmd.index('--potfile-path') + 1] == str(tmp_path / 'local.pot')


def test_hashcat_command_uses_shared_potfile_without_override(tmp_path):
    cmd = build_hashcat_command('hashcat', 8300, 0, 60, str(tmp_path / 'run.pot'), 'hashes', candidate='words')
    assert cmd[cmd.index('--potfile-path') + 1] == str(tmp_path / 'run.pot')


def test_hashcat_command_includes_optimized_kernels_by_default(tmp_path):
    cmd = build_hashcat_command('hashcat', 8300, 0, 60, str(tmp_path / 'run.pot'), 'hashes', candidate='words')
    assert '-O' in cmd


def test_hashcat_command_no_optimized_kernels_flag(tmp_path):
    cmd = build_hashcat_command('hashcat', 8300, 0, 60, str(tmp_path / 'run.pot'), 'hashes', candidate='words', optimized_kernels=False)
    assert '-O' not in cmd


def test_feedback_resume_command_includes_skip(monkeypatch, tmp_path, make_context, write_lines):
    ctx = make_context(tmp_path)
    arm = ParentDomainFeedbackArm('parent-domain', 'parent_domain_feedback', {})
    state = arm._queue(ctx)
    write_lines(state.slice_path, ['x'] * 3184)
    state.save_active_slice({'active': True, 'slice_file': 'slice_candidates.txt', 'total_candidates': 3184, 'skip': 1470})
    commands = []
    monkeypatch.setattr('nsec3_candidate_scheduler.feedback.execution.run_cmd', lambda cmd: commands.append(cmd) or (1, '', ''))
    run_feedback_dictionary_slice(arm, ctx)
    assert commands[0][commands[0].index('--skip') + 1] == '1470'


def test_hashcat_command_does_not_include_invalid_skip(monkeypatch, tmp_path, make_context, write_lines):
    ctx = make_context(tmp_path)
    arm = ParentDomainFeedbackArm('parent-domain', 'parent_domain_feedback', {})
    state = arm._queue(ctx)
    write_lines(state.slice_path, ['x'] * 10)
    state.save_active_slice({'active': True, 'slice_file': 'slice_candidates.txt', 'total_candidates': 10, 'skip': 10})
    commands = []
    monkeypatch.setattr('nsec3_candidate_scheduler.feedback.execution.run_cmd', lambda cmd: commands.append(cmd) or (1, '', ''))
    result = run_feedback_dictionary_slice(arm, ctx)
    assert commands == []
    assert result.executed is False
