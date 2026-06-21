from tests.test_scheduler_scoring import _run_scheduler_with_wordlists


def test_dictionary_discovery_populates_parent_domain_feedback_queue(tmp_path, monkeypatch, assert_no_root_feedback_files):
    out_dir, _ = _run_scheduler_with_wordlists(
        tmp_path, monkeypatch, seclists_values=['dev.api.test'], pcfg_values=[],
        extra_arms=[{'name': 'parent-domain', 'type': 'parent_domain_feedback'}], total_slices=1,
    )
    assert (out_dir / 'feedback' / 'parent-domain' / 'queue.txt').read_text(encoding='utf-8').splitlines() == ['api.test', 'test']
    assert_no_root_feedback_files(out_dir, 'parent-domain')


def test_feedback_generated_during_warmup_but_not_executed_until_adaptive(tmp_path, monkeypatch):
    out_dir, records = _run_scheduler_with_wordlists(
        tmp_path, monkeypatch, seclists_values=['dev.api.test'], pcfg_values=[],
        extra_arms=[{'name': 'parent-domain', 'type': 'parent_domain_feedback', 'min_queue_size': 1}], total_slices=1,
    )
    assert (out_dir / 'feedback' / 'parent-domain' / 'queue.txt').read_text(encoding='utf-8').splitlines() == ['api.test', 'test']
    assert all(not (record['phase'] == 'warmup' and record['arm'] == 'parent-domain') for record in records)


def test_empty_feedback_forced_cadence_does_not_consume_budget(tmp_path, monkeypatch):
    out_dir, records = _run_scheduler_with_wordlists(
        tmp_path, monkeypatch, seclists_values=['www'], pcfg_values=[],
        extra_arms=[{'name': 'parent-domain', 'type': 'parent_domain_feedback', 'force_every_slices': 1}], total_slices=1,
    )
    assert len(records) == 1
    assert records[0]['arm'] == 'seclists'
