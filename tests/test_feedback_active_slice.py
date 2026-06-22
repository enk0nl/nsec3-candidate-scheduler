from nsec3_candidate_scheduler.arms.parent_domain_feedback import ParentDomainFeedbackArm
from nsec3_candidate_scheduler.feedback.execution import run_feedback_dictionary_slice
from nsec3_candidate_scheduler.feedback.queue import FeedbackQueueState


def test_prepare_active_slice_moves_selected_prefix(tmp_path, read_lines, read_json):
    state = FeedbackQueueState(tmp_path, 'permutation')
    state.write_queue(['a', 'b', 'c'])
    active = state.prepare_active_slice(max_candidates=2)
    assert active['active'] is True
    assert read_lines(state.slice_path) == ['a', 'b']
    assert read_lines(state.queue_path) == ['c']
    saved = read_json(state.active_slice_path)
    assert saved['active'] is True
    assert saved['total_candidates'] == 2
    assert saved['skip'] == 0


def test_prepare_active_slice_returns_existing_active_slice(tmp_path, read_lines):
    state = FeedbackQueueState(tmp_path, 'permutation')
    state.write_queue(['a', 'b', 'c'])
    first = state.prepare_active_slice(max_candidates=2)
    state.slice_path.write_text('custom\n', encoding='utf-8')
    second = state.prepare_active_slice(max_candidates=1)
    assert second == first
    assert read_lines(state.queue_path) == ['c']
    assert read_lines(state.slice_path) == ['custom']


def test_prepare_active_slice_empty_queue_returns_inactive_reason(tmp_path):
    state = FeedbackQueueState(tmp_path, 'parent-domain')
    assert state.prepare_active_slice() == {'active': False, 'reason': 'empty_queue'}


def test_clear_active_slice(tmp_path, read_lines, read_json):
    state = FeedbackQueueState(tmp_path, 'parent-domain')
    state.write_queue(['a'])
    state.prepare_active_slice()
    state.clear_active_slice()
    assert read_json(state.active_slice_path) == {'active': False}
    assert read_lines(state.slice_path) == []


def test_invalid_active_slice_skip_is_cleared_without_hashcat(monkeypatch, tmp_path, make_context, write_lines):
    ctx = make_context(tmp_path)
    arm = ParentDomainFeedbackArm('parent-domain', 'parent_domain_feedback', {})
    state = arm._queue(ctx)
    write_lines(state.slice_path, ['x'] * 100)
    state.save_active_slice({'active': True, 'slice_file': 'slice_candidates.txt', 'total_candidates': 100, 'skip': 100})
    launched = False
    def fail_if_launched(cmd):
        nonlocal launched
        launched = True
        return 0, '', ''
    monkeypatch.setattr('nsec3_candidate_scheduler.feedback.execution.run_cmd', fail_if_launched)
    result = run_feedback_dictionary_slice(arm, ctx)
    assert launched is False
    assert result.executed is False
    assert state.load_active_slice()['active'] is False
