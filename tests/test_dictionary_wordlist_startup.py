from __future__ import annotations

import builtins
import logging

import pytest

from adaptive_hashcat_scheduler.arms.dictionary import DictionaryArm


def test_wordlist_arm_does_not_count_lines_by_default(tmp_path, monkeypatch, write_lines):
    wordlist = tmp_path / 'words.txt'
    write_lines(wordlist, ['alpha', 'beta'])

    def fail_count_lines(path):
        raise AssertionError('line counting should not be called by default')

    monkeypatch.setattr('adaptive_hashcat_scheduler.arms.dictionary.count_lines', fail_count_lines)

    arm = DictionaryArm('pcfg', 'dictionary', {'wordlist': str(wordlist)})

    assert arm.candidate_count is None
    assert arm.total_candidates is None
    assert arm.keyspace is None


def test_wordlist_arm_metadata_check_only_by_default(tmp_path, monkeypatch, write_lines):
    wordlist = tmp_path / 'words.txt'
    write_lines(wordlist, ['alpha', 'beta'])

    def fail_open(*args, **kwargs):
        raise AssertionError('startup should not open or iterate over wordlist by default')

    monkeypatch.setattr(builtins, 'open', fail_open)

    arm = DictionaryArm('seclists', 'dictionary', {'wordlist': str(wordlist)})

    assert arm.candidate_count is None
    assert arm.wordlist_size > 0


def test_count_candidates_at_startup_true_counts_lines(tmp_path, write_lines):
    wordlist = tmp_path / 'words.txt'
    write_lines(wordlist, ['alpha', 'beta', 'gamma'])

    arm = DictionaryArm(
        'seclists', 'dictionary',
        {'wordlist': str(wordlist), 'count_candidates_at_startup': True},
    )

    assert arm.candidate_count == 3
    assert arm.total_candidates == 3
    assert arm.keyspace == 3


def test_large_wordlist_counting_warns_when_enabled(tmp_path, monkeypatch, caplog, write_lines):
    wordlist = tmp_path / 'words.txt'
    write_lines(wordlist, ['alpha'])

    monkeypatch.setattr(
        'adaptive_hashcat_scheduler.arms.dictionary.DictionaryArm._validate_wordlist_metadata',
        staticmethod(lambda path: 1_073_741_824),
    )
    monkeypatch.setattr('adaptive_hashcat_scheduler.arms.dictionary.count_lines', lambda path: 1)

    with caplog.at_level(logging.WARNING):
        DictionaryArm(
            'pcfg', 'dictionary',
            {'wordlist': str(wordlist), 'count_candidates_at_startup': True},
        )

    assert f'Counting candidates for large wordlist may take a long time: {wordlist} size=1073741824' in caplog.text


def test_unknown_candidate_count_does_not_break_hashcat_command(tmp_path, monkeypatch, make_context, write_lines):
    wordlist = tmp_path / 'words.txt'
    write_lines(wordlist, ['alpha', 'beta'])
    arm = DictionaryArm('pcfg', 'dictionary', {'wordlist': str(wordlist)})
    seen = {}

    def fake_run_cmd(cmd):
        seen['cmd'] = cmd
        return 1, '', ''

    monkeypatch.setattr('adaptive_hashcat_scheduler.arms.dictionary.run_cmd', fake_run_cmd)
    monkeypatch.setattr('adaptive_hashcat_scheduler.arms.dictionary.latest_summary', lambda text: {})

    result = arm.run_slice(make_context(tmp_path))

    assert result.exit_code == 1
    assert seen['cmd'][-1] == str(wordlist)
    assert '--limit' not in seen['cmd']


def test_progress_accounting_handles_unknown_total(tmp_path, monkeypatch, make_context, write_lines):
    wordlist = tmp_path / 'words.txt'
    write_lines(wordlist, ['alpha', 'beta'])
    arm = DictionaryArm('pcfg', 'dictionary', {'wordlist': str(wordlist)})

    monkeypatch.setattr('adaptive_hashcat_scheduler.arms.dictionary.run_cmd', lambda cmd: (4, '', ''))
    monkeypatch.setattr(
        'adaptive_hashcat_scheduler.arms.dictionary.latest_summary',
        lambda text: {'progress_cur': 9, 'recovered_salts_total': 2},
    )

    result = arm.run_slice(make_context(tmp_path))

    assert result.dictionary_candidate_cursor == 4
    assert result.next_skip_after == 4
    assert arm.next_skip == 4
    assert not arm.exhausted
