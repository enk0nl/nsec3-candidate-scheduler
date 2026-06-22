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


def test_generated_candidates_sqlite_is_default(tmp_path):
    state = FeedbackQueueState(tmp_path, 'permutation')
    assert state.generated_candidates_backend == 'sqlite'
    assert state.retain_generated_candidates_text is False


def test_sqlite_backend_dedupes_without_text_file(tmp_path, read_lines):
    state = FeedbackQueueState(tmp_path, 'permutation')
    first = state.enqueue_generated_candidates(['spf0'])
    second = state.enqueue_generated_candidates(['spf0'])
    assert first['candidates_enqueued'] == 1
    assert second['candidates_enqueued'] == 0
    assert second['candidates_skipped_generated_duplicate'] == 1
    assert read_lines(state.queue_path) == ['spf0']
    assert state.generated_sqlite_path.exists()
    assert read_lines(state.generated_path) == []
    assert state.generated_candidates_count() == 1
    assert not (state.root / 'seen_candidates.txt').exists()


def test_retain_generated_candidates_text_writes_audit_file(tmp_path, read_lines):
    state = FeedbackQueueState(tmp_path, 'permutation', {'retain_generated_candidates_text': True})
    assert state.enqueue_generated_candidates(['spf0', 'spf0'])['candidates_enqueued'] == 1
    assert read_lines(state.generated_path) == ['spf0']


def test_text_backend_preserves_legacy_behavior(tmp_path, read_lines):
    state = FeedbackQueueState(tmp_path, 'permutation', {'generated_candidates_backend': 'text'})
    assert state.enqueue_generated_candidates(['spf0', 'spf0'])['candidates_enqueued'] == 1
    assert read_lines(state.generated_path) == ['spf0']


def test_none_backend_allows_historical_regeneration(tmp_path, read_lines):
    state = FeedbackQueueState(tmp_path, 'permutation', {'generated_candidates_backend': 'none'})
    assert state.enqueue_generated_candidates(['spf0'])['candidates_enqueued'] == 1
    assert state.enqueue_generated_candidates(['spf0'])['candidates_enqueued'] == 1
    assert read_lines(state.queue_path) == ['spf0', 'spf0']


def test_expanded_bases_written_separately_from_generated_candidates(tmp_path, read_lines):
    state = FeedbackQueueState(tmp_path, 'parent-domain')
    state.append_expanded_bases(['dev.api.test'])
    assert read_lines(state.expanded_path) == ['dev.api.test']
    assert read_lines(state.generated_path) == []


def test_legacy_generated_candidates_txt_imported_once(tmp_path, write_lines):
    root = tmp_path / 'feedback' / 'permutation'
    root.mkdir(parents=True)
    write_lines(root / 'generated_candidates.txt', ['spf0', 'spf1', 'spf1'])
    state = FeedbackQueueState(tmp_path, 'permutation')
    assert state.generated_candidates_count() == 2
    stats = state.enqueue_generated_candidates(['spf0', 'spf2'])
    assert stats['candidates_enqueued'] == 1
    with state._connect_generated_sqlite() as conn:
        marker = conn.execute("SELECT value FROM metadata WHERE key='imported_generated_candidates_txt'").fetchone()[0]
    assert marker == 'true'


def test_legacy_generated_candidates_txt_not_reimported_after_marker(tmp_path, write_lines):
    root = tmp_path / 'feedback' / 'permutation'
    root.mkdir(parents=True)
    write_lines(root / 'generated_candidates.txt', ['spf0'])
    state = FeedbackQueueState(tmp_path, 'permutation')
    assert state.generated_candidates_count() == 1
    write_lines(root / 'generated_candidates.txt', ['spf0', 'spf1'])
    state = FeedbackQueueState(tmp_path, 'permutation')
    assert state.generated_candidates_count() == 1


def test_generated_candidates_count_does_not_load_text_ledger(tmp_path, monkeypatch):
    state = FeedbackQueueState(tmp_path, 'permutation')
    state.enqueue_generated_candidates(['spf0'])
    def boom():
        raise AssertionError('full generated ledger load should not be used')
    monkeypatch.setattr(state, 'load_generated_candidates', boom)
    assert state.generated_candidates_count() == 1
