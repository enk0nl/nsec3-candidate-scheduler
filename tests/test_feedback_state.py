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
    state.write_queue([])
    second = state.enqueue_generated_candidates(['spf0'])
    assert first['candidates_enqueued'] == 1
    assert second['candidates_enqueued'] == 0
    assert second['candidates_skipped_generated_duplicate'] == 1
    assert read_lines(state.queue_path) == []
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
    state.write_queue([])
    state.clear_active_slice()
    assert state.enqueue_generated_candidates(['spf0'])['candidates_enqueued'] == 1
    assert read_lines(state.queue_path) == ['spf0']


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



def test_backend_none_still_dedupes_against_queue(tmp_path, read_lines):
    state = FeedbackQueueState(tmp_path, 'none-queue', {'generated_candidates_backend': 'none'})
    state.write_queue(['vpn'])
    stats = state.enqueue_generated_candidates(['vpn'])
    assert stats['candidates_enqueued'] == 0
    assert stats['candidates_skipped_queue_duplicate'] == 1
    assert stats['candidates_skipped_generated_duplicate'] == 0
    assert read_lines(state.queue_path) == ['vpn']


def test_backend_none_still_dedupes_against_active_slice(tmp_path, read_lines):
    state = FeedbackQueueState(tmp_path, 'none-active', {'generated_candidates_backend': 'none'})
    state._write_lines(state.slice_path, ['dev'])
    state.save_active_slice({'active': True, 'slice_file': state.slice_path.name, 'total_candidates': 1, 'skip': 0})
    stats = state.enqueue_generated_candidates(['dev'])
    assert stats['candidates_enqueued'] == 0
    assert stats['candidates_skipped_active_slice_duplicate'] == 1
    assert read_lines(state.queue_path) == []


def test_backend_none_reports_queue_duplicates_separately_from_generated_duplicates(tmp_path):
    state = FeedbackQueueState(tmp_path, 'none-separate', {'generated_candidates_backend': 'none'})
    state.write_queue(['vpn'])
    stats = state.enqueue_generated_candidates(['vpn'])
    assert stats['candidates_skipped_queue_duplicate'] == 1
    assert stats['candidates_skipped_generated_duplicate'] == 0

def test_backend_none_creates_no_generated_candidate_ledger(tmp_path):
    state = FeedbackQueueState(tmp_path, 'none-arm', {'generated_candidates_backend': 'none'})
    assert not state.generated_sqlite_path.exists()
    assert not state.generated_path.exists()
    state.enqueue_generated_candidates(['one.example'])
    assert not state.generated_sqlite_path.exists()
    assert not state.generated_path.exists()


def test_backend_none_still_dedupes_current_batch(tmp_path, read_lines):
    state = FeedbackQueueState(tmp_path, 'none-batch', {'generated_candidates_backend': 'none'})
    stats = state.enqueue_generated_candidates(['dup.example', 'dup.example'])
    assert stats['persistent_generated_dedupe'] is False
    assert stats['candidates_skipped_batch_duplicate'] == 1
    assert stats['candidates_skipped_generated_duplicate'] == 0
    assert stats['candidates_enqueued_total'] == 1
    assert read_lines(state.queue_path) == ['dup.example']


def test_backend_none_ignores_legacy_generated_candidates_files(tmp_path, write_lines, read_lines):
    root = tmp_path / 'feedback' / 'none-legacy'
    root.mkdir(parents=True)
    sqlite_path = root / 'generated_candidates.sqlite'
    sqlite_path.write_bytes(b'legacy sqlite placeholder')
    write_lines(root / 'generated_candidates.txt', ['old.example'])
    state = FeedbackQueueState(tmp_path, 'none-legacy', {'generated_candidates_backend': 'none'})
    stats = state.enqueue_generated_candidates(['old.example'])
    assert stats['candidates_enqueued'] == 1
    assert sqlite_path.exists()
    assert read_lines(root / 'generated_candidates.txt') == ['old.example']


def test_backend_none_does_not_warn_in_normal_mode(tmp_path, capsys):
    FeedbackQueueState(tmp_path, 'none-normal', {'generated_candidates_backend': 'none'})
    out = capsys.readouterr().out
    assert 'persistent generated-candidate dedupe disabled' not in out
    assert 'duplicate generated work may occur' not in out


def test_backend_text_does_not_warn_in_normal_mode(tmp_path, capsys):
    FeedbackQueueState(tmp_path, 'text-normal', {'generated_candidates_backend': 'text'})
    out = capsys.readouterr().out
    assert 'generated_candidates_backend=text may consume significant disk and memory' not in out
    assert 'warning=disk_memory_heavy' not in out


def test_backend_none_logs_config_in_verbose_mode(tmp_path, capsys):
    FeedbackQueueState(tmp_path, 'none-verbose', {'generated_candidates_backend': 'none', 'verbose': True})
    out = capsys.readouterr().out
    assert 'generated_candidates_backend=none' in out
    assert 'persistent_dedupe=false' in out
    assert 'warning arm=' not in out


def test_backend_text_logs_config_in_verbose_mode(tmp_path, capsys):
    FeedbackQueueState(tmp_path, 'text-verbose', {'generated_candidates_backend': 'text', 'verbose': True})
    out = capsys.readouterr().out
    assert 'generated_candidates_backend=text' in out
    assert 'persistent_dedupe=true' in out
    assert 'warning=disk_memory_heavy' in out


def test_disk_threshold_warning_still_prints_in_normal_mode(tmp_path, capsys):
    root = tmp_path / 'feedback' / 'disk-warning'
    root.mkdir(parents=True)
    (root / 'queue.txt').write_text('x' * 32, encoding='utf-8')
    FeedbackQueueState(tmp_path, 'disk-warning', {'feedback_disk_warning_bytes': 1})
    out = capsys.readouterr().out
    assert '[feedback] warning arm=disk-warning file=queue.txt' in out
    assert 'exceeds feedback_disk_warning_bytes=1' in out


def test_backend_policy_messages_are_not_emitted_as_runtime_warnings(tmp_path, capsys):
    FeedbackQueueState(tmp_path, 'none-policy-normal', {'generated_candidates_backend': 'none'})
    FeedbackQueueState(tmp_path, 'text-policy-normal', {'generated_candidates_backend': 'text'})
    out = capsys.readouterr().out
    assert 'persistent generated-candidate dedupe disabled' not in out
    assert 'generated_candidates_backend=text may consume significant disk and memory' not in out
    assert 'warning=disk_memory_heavy' not in out
