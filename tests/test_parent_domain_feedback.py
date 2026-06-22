from adaptive_hashcat_scheduler.arms.parent_domain_feedback import ParentDomainFeedbackArm


def test_parent_domain_generates_all_parents():
    arm = ParentDomainFeedbackArm('parent-domain', 'parent_domain_feedback', {})
    assert arm._parents_for('dev.api.test') == ['api.test', 'test']


def test_parent_domain_generates_chain():
    arm = ParentDomainFeedbackArm('parent-domain', 'parent_domain_feedback', {})
    assert arm._parents_for('www.dev.api.test') == ['dev.api.test', 'api.test', 'test']


def test_parent_domain_single_label_generates_nothing():
    arm = ParentDomainFeedbackArm('parent-domain', 'parent_domain_feedback', {})
    assert arm._parents_for('test') == []


def test_parent_domain_include_single_label_false():
    arm = ParentDomainFeedbackArm('parent-domain', 'parent_domain_feedback', {'include_single_label_parent': False})
    assert arm._parents_for('dev.api.test') == ['api.test']


def test_parent_domain_max_parents_per_discovery():
    arm = ParentDomainFeedbackArm('parent-domain', 'parent_domain_feedback', {'max_parents_per_discovery': 1})
    assert arm._parents_for('a.b.c.d') == ['b.c.d']


def test_parent_domain_already_cracked_diagnostics(tmp_path, make_context, make_fake_potfile):
    pot = make_fake_potfile(tmp_path / 'run.pot', [('h1:.example.nl::0', 'api.test'), ('h2:.example.nl::0', 'test')])
    ctx = make_context(tmp_path, potfile=pot)
    arm = ParentDomainFeedbackArm('parent-domain', 'parent_domain_feedback', {})
    metrics = arm.on_new_discoveries(['dev.api.test'], ctx)
    state = arm._queue(ctx)
    assert metrics['parent_candidates_generated'] == 2
    assert metrics['parent_candidates_enqueued'] == 0
    assert metrics['parent_duplicates_already_cracked'] == 2
    assert state.load_generated_candidates() == set()
    assert state.load_queue() == []
    assert state.load_expanded_bases() == {'dev.api.test'}


def test_parent_domain_writes_state_under_feedback_dir(tmp_path, make_context, assert_no_root_feedback_files):
    ctx = make_context(tmp_path)
    arm = ParentDomainFeedbackArm('parent-domain', 'parent_domain_feedback', {})
    arm.on_new_discoveries(['dev.api.test'], ctx)
    assert (tmp_path / 'feedback' / 'parent-domain' / 'queue.txt').exists()
    assert_no_root_feedback_files(tmp_path, 'parent-domain')


def test_parent_domain_can_still_use_sqlite_backend(tmp_path, make_context):
    ctx = make_context(tmp_path)
    arm = ParentDomainFeedbackArm('parent-domain-sqlite', 'parent_domain_feedback', {'generated_candidates_backend': 'sqlite'})
    metrics = arm.on_new_discoveries(['dev.api.test'], ctx)
    state = arm._queue(ctx)
    assert metrics['parent_candidates_enqueued'] == 2
    assert metrics['generated_candidates_backend'] == 'sqlite'
    assert metrics['persistent_generated_dedupe'] is True
    assert state.generated_sqlite_path.exists()
