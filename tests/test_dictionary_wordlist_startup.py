from __future__ import annotations

import builtins
import json
import logging

import pytest

from nsec3_candidate_scheduler.arms.dictionary import DictionaryArm


def test_wordlist_arm_does_not_count_lines_by_default(tmp_path, monkeypatch, write_lines):
    wordlist = tmp_path / 'words.txt'
    write_lines(wordlist, ['alpha', 'beta'])

    def fail_count_lines(path):
        raise AssertionError('line counting should not be called by default')

    monkeypatch.setattr('nsec3_candidate_scheduler.arms.dictionary.count_lines', fail_count_lines)

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
        'nsec3_candidate_scheduler.arms.dictionary.DictionaryArm._validate_wordlist_metadata',
        staticmethod(lambda path: 1_073_741_824),
    )
    monkeypatch.setattr('nsec3_candidate_scheduler.arms.dictionary.count_lines', lambda path: 1)

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

    monkeypatch.setattr('nsec3_candidate_scheduler.arms.dictionary.run_cmd', fake_run_cmd)
    monkeypatch.setattr('nsec3_candidate_scheduler.arms.dictionary.latest_summary', lambda text: {})

    result = arm.run_slice(make_context(tmp_path))

    assert result.exit_code == 1
    assert seen['cmd'][-1] == str(wordlist)
    assert '--limit' not in seen['cmd']


def test_progress_accounting_handles_unknown_total(tmp_path, monkeypatch, make_context, write_lines):
    wordlist = tmp_path / 'words.txt'
    write_lines(wordlist, ['alpha', 'beta'])
    arm = DictionaryArm('pcfg', 'dictionary', {'wordlist': str(wordlist)})

    monkeypatch.setattr('nsec3_candidate_scheduler.arms.dictionary.run_cmd', lambda cmd: (4, '', ''))
    monkeypatch.setattr(
        'nsec3_candidate_scheduler.arms.dictionary.latest_summary',
        lambda text: {'progress_cur': 9, 'recovered_salts_total': 2},
    )

    result = arm.run_slice(make_context(tmp_path))

    assert result.dictionary_candidate_cursor == 4
    assert result.next_skip_after == 4
    assert arm.next_skip == 4
    assert not arm.exhausted



def test_dictionary_candidate_count_config_override_used(tmp_path, write_lines):
    wordlist = tmp_path / 'words.txt'
    write_lines(wordlist, ['alpha', 'beta'])

    arm = DictionaryArm(
        'rfc1035_pcfg', 'dictionary',
        {'wordlist': str(wordlist), 'candidate_count': 100_000_000, 'count_candidates_at_startup': False},
    )

    assert arm.candidate_count == 100_000_000
    assert arm.total_candidates == 100_000_000
    assert arm.keyspace == 100_000_000
    assert arm.candidate_count_source == 'config'


def test_candidate_count_config_override_prevents_line_count(tmp_path, monkeypatch, write_lines):
    wordlist = tmp_path / 'words.txt'
    write_lines(wordlist, ['alpha', 'beta'])

    def fail_count_lines(path):
        raise AssertionError('manual candidate_count should prevent line counting')

    monkeypatch.setattr('nsec3_candidate_scheduler.arms.dictionary.count_lines', fail_count_lines)

    arm = DictionaryArm(
        'rfc1035_pcfg', 'dictionary',
        {'wordlist': str(wordlist), 'candidate_count': 100_000_000, 'count_candidates_at_startup': True},
    )

    assert arm.candidate_count == 100_000_000
    assert arm.candidate_count_source == 'config'


def test_candidate_count_unknown_when_no_override_and_no_counting(tmp_path, write_lines):
    wordlist = tmp_path / 'words.txt'
    write_lines(wordlist, ['alpha'])

    arm = DictionaryArm('foo', 'dictionary', {'wordlist': str(wordlist), 'count_candidates_at_startup': False})

    assert arm.candidate_count is None
    assert arm.candidate_count_source == 'unknown'


def test_candidate_count_counted_when_enabled_and_no_override(tmp_path, monkeypatch, write_lines):
    wordlist = tmp_path / 'words.txt'
    write_lines(wordlist, ['alpha'])
    calls = []

    def fake_count_lines(path):
        calls.append(path)
        return 7

    monkeypatch.setattr('nsec3_candidate_scheduler.arms.dictionary.count_lines', fake_count_lines)

    arm = DictionaryArm('seclists', 'dictionary', {'wordlist': str(wordlist), 'count_candidates_at_startup': True})

    assert calls == [wordlist]
    assert arm.candidate_count == 7
    assert arm.candidate_count_source == 'counted'


@pytest.mark.parametrize('candidate_count', [0, -1, 100.5, '100000000'])
def test_invalid_candidate_count_fails_validation(tmp_path, write_lines, candidate_count):
    wordlist = tmp_path / 'words.txt'
    write_lines(wordlist, ['alpha'])
    config = tmp_path / 'config.json'
    config.write_text(json.dumps({
        'arms': [{
            'name': 'rfc1035_pcfg',
            'type': 'dictionary',
            'wordlist': str(wordlist),
            'candidate_count': candidate_count,
        }],
    }), encoding='utf-8')

    from nsec3_candidate_scheduler.config import load_config
    with pytest.raises(ValueError, match='candidate_count for arm .* must be a positive integer'):
        load_config(str(config))


def test_arm_metadata_not_printed_in_normal_mode(tmp_path, capsys, write_lines):
    wordlist = tmp_path / 'words.txt'
    write_lines(wordlist, ['alpha'])

    DictionaryArm('foo', 'dictionary', {'wordlist': str(wordlist)})

    captured = capsys.readouterr()
    assert '[arm] name=' not in captured.out
    assert '[arm] name=' not in captured.err


def test_arm_metadata_printed_in_verbose_mode(tmp_path, capsys, write_lines):
    wordlist = tmp_path / 'words.txt'
    write_lines(wordlist, ['alpha'])

    DictionaryArm('foo', 'dictionary', {'wordlist': str(wordlist), 'verbose': True})

    captured = capsys.readouterr()
    assert '[arm] name=' in captured.out
    assert 'candidate_count_source=' in captured.out


def test_manual_candidate_count_appears_in_verbose_log(tmp_path, capsys, write_lines):
    wordlist = tmp_path / 'words.txt'
    write_lines(wordlist, ['alpha'])

    DictionaryArm(
        'rfc1035_pcfg', 'dictionary',
        {'wordlist': str(wordlist), 'candidate_count': 100_000_000, 'verbose': True},
    )

    captured = capsys.readouterr()
    assert 'candidate_count=100000000' in captured.out
    assert 'candidate_count_source=config' in captured.out
    assert 'candidate_count=unknown' not in captured.out
