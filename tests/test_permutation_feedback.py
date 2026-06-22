from nsec3_candidate_scheduler.arms.permutation import PermutationArm


def _spf_config():
    return {
        'numeric': {'enabled': True, 'min_width': 1, 'max_width': 4, 'generate_full_range': True,
                    'generate_local_radius': True, 'local_radius': 2},
        'alpha': {'enabled': True, 'charset': 'abcdefghijklmnopqrstuvwxyz', 'min_width': 1, 'max_width': 3,
                  'generate_full_range': True, 'require_numeric_context': True},
    }


def test_permutation_spf1_numeric_candidates(tmp_path, make_context):
    ctx = make_context(tmp_path)
    arm = PermutationArm('permutation', 'permutation', _spf_config())
    arm.on_new_discoveries(['spf1'], ctx)
    items = arm._queue(ctx).load_queue()
    for value in ['spf1', 'spf0', 'spf2', 'spf3', 'spf4', 'spf5', 'spf6', 'spf7', 'spf8', 'spf9']:
        assert value in items


def test_permutation_spf1_alpha_candidates(tmp_path, make_context):
    ctx = make_context(tmp_path)
    arm = PermutationArm('permutation', 'permutation', _spf_config())
    arm.on_new_discoveries(['spf1'], ctx)
    items = arm._queue(ctx).load_queue()
    for value in ['aaa1', 'aab1', 'zzz1']:
        assert value in items


def test_permutation_numeric_candidates_before_alpha_candidates(tmp_path, make_context):
    ctx = make_context(tmp_path)
    arm = PermutationArm('permutation', 'permutation', _spf_config())
    arm.on_new_discoveries(['spf1'], ctx)
    items = arm._queue(ctx).load_queue()
    assert items.index('spf9') < items.index('aaa1')


def test_permutation_no_alpha_numeric_cross_product(tmp_path, make_context):
    ctx = make_context(tmp_path)
    arm = PermutationArm('permutation', 'permutation', _spf_config())
    arm.on_new_discoveries(['spf1'], ctx)
    items = arm._queue(ctx).load_queue()
    for value in ['a0', 'aa00', 'zzz9999']:
        assert value not in items


def test_permutation_preserves_separator_suffix_number(tmp_path, make_context):
    ctx = make_context(tmp_path)
    arm = PermutationArm('permutation', 'permutation', {'numeric': {'local_radius': 1, 'generate_full_range': False}})
    arm.on_new_discoveries(['vpn-01'], ctx)
    items = arm._queue(ctx).load_queue()
    for value in ['vpn-00', 'vpn-01', 'vpn-02']:
        assert value in items
    for value in ['vpn00', 'vpn_00', '00-vpn']:
        assert value not in items


def test_permutation_preserves_order_prefix_number(tmp_path, make_context):
    ctx = make_context(tmp_path)
    arm = PermutationArm('permutation', 'permutation', {'numeric': {'local_radius': 1, 'generate_full_range': False}})
    arm.on_new_discoveries(['01-web'], ctx)
    items = arm._queue(ctx).load_queue()
    for value in ['00-web', '01-web', '02-web']:
        assert value in items
    assert 'web-00' not in items


def test_permutation_compound_stem_numeric(tmp_path, make_context):
    ctx = make_context(tmp_path)
    arm = PermutationArm('permutation', 'permutation', {'numeric': {'local_radius': 1, 'generate_full_range': False}})
    arm.on_new_discoveries(['web-int-01'], ctx)
    items = arm._queue(ctx).load_queue()
    for value in ['web-int-00', 'web-int-01', 'web-int-02']:
        assert value in items


def test_permutation_state_under_feedback_dir(tmp_path, make_context, assert_no_root_feedback_files):
    ctx = make_context(tmp_path)
    arm = PermutationArm('permutation', 'permutation', {})
    arm._queue(ctx)
    assert (tmp_path / 'feedback' / 'permutation' / 'cursor.json').exists()
    assert_no_root_feedback_files(tmp_path, 'permutation')


def test_permutation_can_still_use_sqlite_backend(tmp_path, make_context):
    ctx = make_context(tmp_path)
    arm = PermutationArm('permutation-sqlite', 'permutation', {'generated_candidates_backend': 'sqlite', 'numeric': {'generate_full_range': False, 'local_radius': 1}})
    metrics = arm.on_new_discoveries(['spf1'], ctx)
    state = arm._queue(ctx)
    assert metrics['generated_candidates_backend'] == 'sqlite'
    assert metrics['persistent_generated_dedupe'] is True
    assert metrics['candidates_enqueued'] > 0
    assert state.generated_sqlite_path.exists()
