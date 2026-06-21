from adaptive_hashcat_scheduler.feedback.queue import FeedbackQueueState, safe_arm_name


def test_feedback_state_uses_per_arm_subdirectory(tmp_path, assert_no_root_feedback_files):
    state = FeedbackQueueState(tmp_path, 'parent-domain')
    root = tmp_path / 'feedback' / 'parent-domain'
    assert state.root == root
    assert state.queue_path == root / 'queue.txt'
    assert state.generated_path == root / 'generated_candidates.txt'
    assert state.expanded_path == root / 'expanded_bases.txt'
    assert state.slice_path == root / 'slice_candidates.txt'
    assert state.active_slice_path == root / 'active_slice.json'
    assert_no_root_feedback_files(tmp_path, 'parent-domain')


def test_feedback_state_safe_arm_name():
    assert safe_arm_name('parent-domain') == 'parent-domain'
    assert safe_arm_name('predictive-prefix') == 'predictive-prefix'
    assert safe_arm_name('static-affix-top50') == 'static-affix-top50'
    assert safe_arm_name('foo/bar') == 'foo-bar'
    assert safe_arm_name('../bad/name') == 'bad-name'
    assert safe_arm_name('foo  bar') == 'foo-bar'


def test_feedback_state_does_not_migrate_legacy_root_files(tmp_path, write_lines):
    write_lines(tmp_path / 'parent-domain_queue.txt', ['oldq'])
    write_lines(tmp_path / 'parent-domain_seen_candidates.txt', ['oldseen'])
    write_lines(tmp_path / 'parent-domain_expanded_bases.txt', ['oldbase'])
    state = FeedbackQueueState(tmp_path, 'parent-domain')
    assert state.load_queue() == []
    assert state.load_generated_candidates() == set()
    assert state.load_expanded_bases() == set()


def test_generated_candidates_is_dedupe_ledger(tmp_path, read_lines):
    state = FeedbackQueueState(tmp_path, 'permutation')
    assert state.append_candidates(['spf0', 'spf1']) == 2
    assert read_lines(state.queue_path) == ['spf0', 'spf1']
    assert read_lines(state.generated_path) == ['spf0', 'spf1']
    assert not (state.root / 'seen_candidates.txt').exists()


def test_expanded_bases_written_separately_from_generated_candidates(tmp_path, read_lines):
    state = FeedbackQueueState(tmp_path, 'parent-domain')
    state.append_expanded_bases(['dev.api.test'])
    assert read_lines(state.expanded_path) == ['dev.api.test']
    assert read_lines(state.generated_path) == []
