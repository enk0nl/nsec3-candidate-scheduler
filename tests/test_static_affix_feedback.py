from adaptive_hashcat_scheduler.arms.static_affix_feedback import StaticAffixFeedbackArm, _load_affixes


def _arm(tmp_path, write_lines, config=None):
    prefixes = tmp_path / 'prefixes.txt'; suffixes = tmp_path / 'suffixes.txt'
    write_lines(prefixes, ['dev', 'staging'])
    write_lines(suffixes, ['internal'])
    cfg = {'prefixes': str(prefixes), 'suffixes': str(suffixes)}
    cfg.update(config or {})
    return StaticAffixFeedbackArm('static-affix-top50', 'static_affix_feedback', cfg)


def test_static_affix_generates_prefix_and_suffix_candidates(tmp_path, make_context, write_lines):
    ctx = make_context(tmp_path)
    arm = _arm(tmp_path, write_lines)
    arm.on_new_discoveries(['api.test'], ctx)
    assert arm._queue(ctx).load_queue() == ['dev.api.test', 'staging.api.test', 'api.test.internal']


def test_static_affix_expands_base_once(tmp_path, make_context, write_lines):
    ctx = make_context(tmp_path)
    arm = _arm(tmp_path, write_lines)
    arm.on_new_discoveries(['api.test', 'api.test'], ctx)
    state = arm._queue(ctx)
    assert state.load_expanded_bases() == {'api.test'}
    assert state.load_queue() == ['dev.api.test', 'staging.api.test', 'api.test.internal']


def test_static_affix_skips_already_generated_candidates(tmp_path, make_context, write_lines):
    ctx = make_context(tmp_path)
    arm = _arm(tmp_path, write_lines)
    state = arm._queue(ctx)
    state.append_generated_candidates(['dev.api.test'])
    metrics = arm.on_new_discoveries(['api.test'], ctx)
    assert metrics['static-affix-top50_affix_duplicates_generated'] == 1
    assert 'dev.api.test' not in state.load_queue()


def test_static_affix_skips_already_cracked_candidates(tmp_path, make_context, make_fake_potfile, write_lines):
    pot = make_fake_potfile(tmp_path / 'run.pot', [('h1:.example.nl::0', 'dev.api.test')])
    ctx = make_context(tmp_path, potfile=pot)
    arm = _arm(tmp_path, write_lines)
    metrics = arm.on_new_discoveries(['api.test'], ctx)
    assert metrics['static-affix-top50_affix_duplicates_already_cracked'] == 1
    assert 'dev.api.test' not in arm._queue(ctx).load_queue()


def test_static_affix_loads_label_count_files(tmp_path, write_lines):
    path = tmp_path / 'labels.txt'
    write_lines(path, ['dev\t123', 'staging\t42'])
    assert _load_affixes(str(path), 10) == ['dev', 'staging']
    write_lines(path, ['dev', 'staging'])
    assert _load_affixes(str(path), 10) == ['dev', 'staging']
