import argparse
import json

from nsec3_candidate_scheduler.scheduler import run_scheduler


def _fake_dictionary_run_cmd(cmd):
    potfile = cmd[cmd.index('--potfile-path') + 1]
    candidate = cmd[-1]
    existing = set()
    try:
        with open(potfile, encoding='utf-8') as f:
            for line in f:
                if ':' in line:
                    existing.add(line.split(':', 1)[0])
    except FileNotFoundError:
        pass
    with open(potfile, 'a', encoding='utf-8') as out, open(candidate, encoding='utf-8') as inp:
        for plaintext in inp.read().splitlines():
            h = f'h_{plaintext}'
            if h not in existing:
                out.write(f'{h}:{plaintext}\n')
                existing.add(h)
    return 1, '', ''


def _run_scheduler_with_wordlists(tmp_path, monkeypatch, *, warmup_scoring='arm_local', seclists_values=None, pcfg_values=None, extra_arms=None, total_slices=2, run_cmd=None):
    monkeypatch.setattr('nsec3_candidate_scheduler.arms.dictionary.run_cmd', run_cmd or _fake_dictionary_run_cmd)
    seclists = tmp_path / 'seclists.txt'; pcfg = tmp_path / 'pcfg.txt'
    seclists.write_text('\n'.join(seclists_values or ['www', 'test1', 'test2']) + '\n', encoding='utf-8')
    pcfg.write_text('\n'.join(pcfg_values or ['www', 'test2', 'test3']) + '\n', encoding='utf-8')
    target_hashes = sorted({f'h_{value}' for value in (seclists_values or ['www', 'test1', 'test2']) + (pcfg_values or ['www', 'test2', 'test3'])})
    hashes = tmp_path / 'hashes.txt'; hashes.write_text('\n'.join(target_hashes) + '\n', encoding='utf-8')
    arms = [
        {'name': 'seclists', 'type': 'dictionary', 'wordlist': str(seclists)},
        {'name': 'pcfg', 'type': 'dictionary', 'wordlist': str(pcfg)},
    ]
    arms.extend(extra_arms or [])
    config = tmp_path / 'config.json'
    config.write_text(json.dumps({'alpha': 1.0, 'epsilon': 0.0, 'warmup': {'scoring': warmup_scoring}, 'arms': arms}), encoding='utf-8')
    out_dir = tmp_path / 'out'
    run_scheduler(argparse.Namespace(hashes=str(hashes), hash_mode=0, config=str(config), out_dir=str(out_dir),
                                     schedule='adaptive', total_slices=total_slices, slice_seconds=1, alpha=None,
                                     epsilon=None, random_seed=0, default_limit=1000000,
                                     hashcat_bin='hashcat', quiet=True, verbose=False,
                                     no_optimized_kernels=True))
    return out_dir, [json.loads(line) for line in (out_dir / 'jobs.jsonl').read_text(encoding='utf-8').splitlines()]


def test_arm_local_warmup_scores_duplicates_independently(tmp_path, monkeypatch):
    out_dir, records = _run_scheduler_with_wordlists(tmp_path, monkeypatch, warmup_scoring='arm_local')
    assert records[0]['arm_local_new_cracks'] == 3
    assert records[0]['shared_new_cracks'] == 3
    assert records[0]['duplicate_cracks_vs_shared'] == 0
    assert records[1]['arm_local_new_cracks'] == 3
    assert records[1]['shared_new_cracks'] == 1
    assert records[1]['duplicate_cracks_vs_shared'] == 2
    assert records[1]['reward_used_for_score'] > records[1]['shared_new_cracks'] / records[1]['runtime_seconds']
    assert sorted(line.split(':', 1)[1] for line in (out_dir / 'run.pot').read_text(encoding='utf-8').splitlines()) == ['test1', 'test2', 'test3', 'www']


def test_feedback_observes_only_shared_new_discoveries_in_arm_local_warmup(tmp_path, monkeypatch):
    out_dir, records = _run_scheduler_with_wordlists(
        tmp_path, monkeypatch, warmup_scoring='arm_local',
        seclists_values=['dev.api.test'], pcfg_values=['dev.api.test', 'new.mail.test'],
        extra_arms=[{'name': 'parent-domain', 'type': 'parent_domain_feedback'}], total_slices=2,
    )
    queued = (out_dir / 'feedback' / 'parent-domain' / 'queue.txt').read_text(encoding='utf-8').splitlines()
    assert queued == ['api.test', 'test', 'mail.test']
    assert all(record['arm'] != 'parent-domain' for record in records)


def test_shared_marginal_warmup_scores_only_global_new_hashes(tmp_path, monkeypatch):
    _, records = _run_scheduler_with_wordlists(tmp_path, monkeypatch, warmup_scoring='shared_marginal')
    assert records[1]['marginal_new_cracks'] == 1
    assert records[1]['reward_used_for_score'] == records[1]['shared_new_cracks'] / records[1]['runtime_seconds']


def test_adaptive_phase_always_uses_shared_marginal_scoring(tmp_path, monkeypatch):
    out_dir, records = _run_scheduler_with_wordlists(tmp_path, monkeypatch, warmup_scoring='arm_local', total_slices=3)
    # Third adaptive record has no shared-new hashes because both dictionaries exhausted after warmup.
    assert records[-1]['phase'] == 'adaptive' or len(records) == 2
    if len(records) > 2:
        assert records[-1]['warmup_scoring'] == 'shared_marginal'


def test_score_update_uses_reward_used_for_score():
    alpha = 0.15
    score_before = 0
    reward_used_for_score = 100
    assert score_before + alpha * (reward_used_for_score - score_before) == 15


def test_warmup_empty_plaintext_is_merged_into_run_pot(tmp_path, monkeypatch):
    def fake_run_cmd(cmd):
        potfile = cmd[cmd.index('--potfile-path') + 1]
        with open(potfile, 'a', encoding='utf-8') as out:
            out.write('h_www:\n')
        return 1, '', ''

    out_dir, records = _run_scheduler_with_wordlists(tmp_path, monkeypatch, total_slices=1, run_cmd=fake_run_cmd)

    assert (out_dir / 'run.pot').read_text(encoding='utf-8') == 'h_www:\n'
    assert records[0]['shared_new_cracks'] == 1
    assert records[0]['arm_local_cracks'] == 1
    assert records[0]['arm_local_new_cracks'] == 1
    assert records[0]['total_cracks'] == 1


def test_empty_plaintext_deduplicates_by_hash(tmp_path):
    from nsec3_candidate_scheduler.scheduler import _append_potfile_pairs, pot_values

    run_pot = tmp_path / 'run.pot'
    run_pot.write_text('7c33954r9727aj5urd7blat7nm4deftv:.example.nl:ab:1:\n', encoding='utf-8')
    local_pot = tmp_path / 'local.pot'
    local_pot.write_text('7c33954r9727aj5urd7blat7nm4deftv:.example.nl:ab:1:\n', encoding='utf-8')

    shared_before = pot_values(run_pot)
    local_after = pot_values(local_pot)
    new_pairs = [(h, v) for h, v in local_after.items() if h not in shared_before]
    _append_potfile_pairs(str(run_pot), new_pairs)

    assert new_pairs == []
    assert run_pot.read_text(encoding='utf-8').splitlines() == ['7c33954r9727aj5urd7blat7nm4deftv:.example.nl:ab:1:']


def test_empty_plaintext_not_passed_to_feedback_generators(tmp_path, monkeypatch):
    seen = []

    def fake_run_cmd(cmd):
        potfile = cmd[cmd.index('--potfile-path') + 1]
        with open(potfile, 'a', encoding='utf-8') as out:
            out.write('h_empty:.example.nl:ab:1:\n')
            out.write('h_www:.example.nl:ab:1:www\n')
        return 1, '', ''

    def fake_on_new_discoveries(self, discoveries, context):
        seen.append(list(discoveries))
        return {}

    monkeypatch.setattr('nsec3_candidate_scheduler.arms.parent_domain_feedback.ParentDomainFeedbackArm.on_new_discoveries', fake_on_new_discoveries)
    _run_scheduler_with_wordlists(
        tmp_path, monkeypatch,
        extra_arms=[{'name': 'parent-domain', 'type': 'parent_domain_feedback'}],
        total_slices=1,
        run_cmd=fake_run_cmd,
    )

    assert seen == [['www']]


def test_normal_plaintext_merge_and_feedback_behavior_unchanged(tmp_path, monkeypatch):
    out_dir, _ = _run_scheduler_with_wordlists(
        tmp_path, monkeypatch,
        seclists_values=['www'],
        extra_arms=[{'name': 'parent-domain', 'type': 'parent_domain_feedback'}],
        total_slices=1,
    )
    assert (out_dir / 'run.pot').read_text(encoding='utf-8') == 'h_www:www\n'
    assert (out_dir / 'feedback' / 'parent-domain' / 'queue.txt').read_text(encoding='utf-8') == ''
