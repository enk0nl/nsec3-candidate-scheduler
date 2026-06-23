from __future__ import annotations

import argparse
import json

from nsec3_candidate_scheduler.arms.base import Arm, SliceResult
from nsec3_candidate_scheduler.config import load_config
from nsec3_candidate_scheduler.hashcat.runner import build_hashcat_command
from nsec3_candidate_scheduler.scheduler import run_scheduler


def _args(tmp_path, *, failover=None, no_optimized=False, total_slices=2):
    config = tmp_path / 'config.json'
    config.write_text(json.dumps({'arms': [{'name': 'a', 'type': 'dictionary'}]}), encoding='utf-8')
    hashes = tmp_path / 'hashes.txt'; hashes.write_text('hash\n', encoding='utf-8')
    return argparse.Namespace(hashes=str(hashes), hash_mode=8300, config=str(config), out_dir=str(tmp_path / 'out'),
                              schedule='adaptive', total_slices=total_slices, slice_seconds=1, alpha=1.0,
                              epsilon=0.0, random_seed=0, default_limit=1000000, hashcat_bin='hashcat',
                              quiet=True, verbose=False, no_optimized_kernels=no_optimized,
                              optimized_kernel_failover=failover)


class SequenceArm(Arm):
    def __init__(self, results):
        super().__init__('a', 'dictionary', {})
        self.warmup_eligible = False
        self.results = list(results)
        self.optimized_seen = []

    def run_slice(self, context):
        self.optimized_seen.append(context.hashcat_optimized_kernels)
        result = self.results.pop(0) if self.results else SliceResult(exit_code=0, stdout='', stderr='')
        if result.exit_code == 0:
            with open(context.potfile, 'a', encoding='utf-8') as f:
                f.write(f'h{len(self.optimized_seen)}:v{len(self.optimized_seen)}\n')
        return result


def optimized_error():
    return SliceResult(exit_code=255, stdout='', stderr='Optimized kernel plaintext length exception', valid_work=True)


def test_config_optimized_kernel_failover_false(tmp_path):
    path = tmp_path / 'config.json'
    (tmp_path / 'words.txt').write_text('x\n', encoding='utf-8')
    path.write_text(json.dumps({'hashcat': {'optimized_kernel_failover': False}, 'arms': [{'name': 'a', 'type': 'dictionary', 'wordlist': 'words.txt'}]}), encoding='utf-8')
    assert load_config(str(path))['hashcat']['optimized_kernel_failover'] is False


def test_hashcat_command_omits_and_includes_O(tmp_path):
    enabled = build_hashcat_command('hashcat', 8300, 0, 60, str(tmp_path / 'p'), 'hashes', candidate='words', optimized_kernels=True)
    disabled = build_hashcat_command('hashcat', 8300, 0, 60, str(tmp_path / 'p'), 'hashes', candidate='words', optimized_kernels=False)
    assert '-O' in enabled
    assert '-O' not in disabled
    assert '--optimized-kernel-enable' not in disabled


def test_optimized_kernel_failure_triggers_failover_and_retry(monkeypatch, tmp_path):
    arm = SequenceArm([optimized_error(), SliceResult(exit_code=0)])
    monkeypatch.setattr('nsec3_candidate_scheduler.scheduler.load_config', lambda path: {'arms': [{'name': 'a', 'type': 'dictionary'}], 'hashcat': {'optimized_kernels': True, 'optimized_kernel_failover': True}})
    monkeypatch.setattr('nsec3_candidate_scheduler.scheduler.make_arm', lambda cfg: arm)
    args = _args(tmp_path, total_slices=1)
    run_scheduler(args)
    records = [json.loads(line) for line in (tmp_path / 'out' / 'jobs.jsonl').read_text().splitlines()]
    assert arm.optimized_seen[:2] == [True, False]
    assert records[0]['valid_work'] is False
    assert records[0]['scored'] is False
    assert records[0]['retry_scheduled'] is True
    assert records[1]['hashcat_optimized_kernels'] is False
    assert records[1]['retry_of_job_id'] == records[0]['job_id']


def test_no_failover_keeps_optimized_and_records_metadata(monkeypatch, tmp_path):
    arm = SequenceArm([optimized_error(), SliceResult(exit_code=0)])
    monkeypatch.setattr('nsec3_candidate_scheduler.scheduler.load_config', lambda path: {'arms': [{'name': 'a', 'type': 'dictionary'}], 'hashcat': {'optimized_kernels': True, 'optimized_kernel_failover': True}})
    monkeypatch.setattr('nsec3_candidate_scheduler.scheduler.make_arm', lambda cfg: arm)
    args = _args(tmp_path, failover=False, total_slices=2)
    run_scheduler(args)
    records = [json.loads(line) for line in (tmp_path / 'out' / 'jobs.jsonl').read_text().splitlines()]
    assert arm.optimized_seen[:2] == [True, True]
    assert records[0]['optimized_kernel_failover_enabled'] is False
    assert records[0]['retry_scheduled'] is False
    assert records[0]['retryable'] is False
    assert records[0]['retry_reason'] == 'optimized_kernel_failure'
    assert records[0]['scored'] is False

TOKEN_LENGTH_OUTPUT = """hashcat (v7.1.2) starting - session [adaptive_31696_12_bruteforce_rfc1035_len2_5_0]

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 32
Minimum salt length supported by kernel: 0
Maximum salt length supported by kernel: 51

Hashfile '/path/nsec3map_hashfile.hash' on line 1 (...): Token length exception
Hashfile '/path/nsec3map_hashfile.hash' on line 2 (...): Token length exception
...
Parsing Hashes: 0/22 (0.00%)...

* Token length exception: 22/22 hashes
  This error happens if the wrong hash type is specified, if the hashes are
  malformed, or if input is otherwise not as expected
  No hashes loaded.
"""


def token_length_error(output=TOKEN_LENGTH_OUTPUT, *, skip_before=7, next_skip_after=99):
    return SliceResult(exit_code=255, stdout=output, stderr='', valid_work=True,
                       skip_before=skip_before, next_skip_after=next_skip_after)


def _patch_scheduler(monkeypatch, arm, *, optimized=True, failover=True):
    monkeypatch.setattr('nsec3_candidate_scheduler.scheduler.load_config', lambda path: {'arms': [{'name': 'a', 'type': 'dictionary'}], 'hashcat': {'optimized_kernels': optimized, 'optimized_kernel_failover': failover}})
    monkeypatch.setattr('nsec3_candidate_scheduler.scheduler.make_arm', lambda cfg: arm)


def test_all_hashes_token_length_with_optimized_triggers_failover():
    from nsec3_candidate_scheduler.scheduler import classify_hashcat_failure
    c = classify_hashcat_failure(optimized_kernels=True, exit_code=255, exit_meaning='error', stdout=TOKEN_LENGTH_OUTPUT, stderr='', failover_enabled=True)
    assert c.reason == 'optimized_kernel_all_hashes_token_length'
    assert c.retryable_with_unoptimized is True
    assert c.parse_error_count == 22
    assert c.parse_error_total == 22


def test_all_hashes_token_length_with_failover_disabled_does_not_retry(monkeypatch, tmp_path):
    arm = SequenceArm([token_length_error(), SliceResult(exit_code=0)])
    _patch_scheduler(monkeypatch, arm, failover=False)
    run_scheduler(_args(tmp_path, failover=False, total_slices=1))
    records = [json.loads(line) for line in (tmp_path / 'out' / 'jobs.jsonl').read_text().splitlines()]
    assert records[0]['retry_reason'] == 'optimized_kernel_all_hashes_token_length'
    assert records[0]['retry_scheduled'] is False
    assert records[0]['retryable'] is False
    assert records[0]['valid_work'] is False
    assert records[0]['scored'] is False


def test_all_hashes_token_length_unoptimized_is_hashfile_error(monkeypatch, tmp_path):
    from nsec3_candidate_scheduler.scheduler import classify_hashcat_failure
    c = classify_hashcat_failure(optimized_kernels=False, exit_code=255, exit_meaning='error', stdout=TOKEN_LENGTH_OUTPUT, stderr='', failover_enabled=True)
    assert c.reason == 'hashfile_parse_error_all_hashes_token_length'
    assert c.retryable_with_unoptimized is False
    arm = SequenceArm([token_length_error()])
    _patch_scheduler(monkeypatch, arm, optimized=False)
    run_scheduler(_args(tmp_path, no_optimized=True, total_slices=1))
    rec = json.loads((tmp_path / 'out' / 'jobs.jsonl').read_text().splitlines()[0])
    assert rec['hashcat_failure_class'] == 'hashfile_parse_error_all_hashes_token_length'
    assert rec['retry_scheduled'] is False


def test_partial_token_length_does_not_trigger_global_failover(monkeypatch, tmp_path):
    out = TOKEN_LENGTH_OUTPUT.replace('Token length exception: 22/22 hashes', 'Token length exception: 2/22 hashes')
    arm = SequenceArm([token_length_error(out), SliceResult(exit_code=0)])
    _patch_scheduler(monkeypatch, arm)
    run_scheduler(_args(tmp_path, total_slices=1))
    records = [json.loads(line) for line in (tmp_path / 'out' / 'jobs.jsonl').read_text().splitlines()]
    assert records[0]['retry_reason'] is None
    assert len(records) == 1


def test_token_length_without_no_hashes_loaded_does_not_trigger_all_hashes_failover():
    from nsec3_candidate_scheduler.scheduler import classify_hashcat_failure
    out = TOKEN_LENGTH_OUTPUT.replace('  No hashes loaded.\n', '')
    c = classify_hashcat_failure(optimized_kernels=True, exit_code=255, exit_meaning='error', stdout=out, stderr='', failover_enabled=True)
    assert c is None


def test_unoptimized_retry_failure_becomes_hashfile_parse_error(monkeypatch, tmp_path):
    arm = SequenceArm([token_length_error(), token_length_error()])
    _patch_scheduler(monkeypatch, arm)
    run_scheduler(_args(tmp_path, total_slices=1))
    records = [json.loads(line) for line in (tmp_path / 'out' / 'jobs.jsonl').read_text().splitlines()]
    assert records[0]['retry_scheduled'] is True
    assert records[1]['hashcat_optimized_kernels'] is False
    assert records[1]['hashcat_failure_class'] == 'hashfile_parse_error_all_hashes_token_length'
    assert records[1]['retry_scheduled'] is False


def test_jobs_jsonl_records_parse_error_counts(monkeypatch, tmp_path):
    arm = SequenceArm([token_length_error(), SliceResult(exit_code=0)])
    _patch_scheduler(monkeypatch, arm)
    run_scheduler(_args(tmp_path, total_slices=1))
    rec = json.loads((tmp_path / 'out' / 'jobs.jsonl').read_text().splitlines()[0])
    assert rec['hashcat_parse_error_count'] == 22
    assert rec['hashcat_parse_error_total'] == 22


def test_failed_all_hashes_token_length_attempt_not_scored(monkeypatch, tmp_path):
    arm = SequenceArm([token_length_error(), SliceResult(exit_code=0)])
    arm.score = 5.0
    _patch_scheduler(monkeypatch, arm)
    run_scheduler(_args(tmp_path, total_slices=1))
    rec = json.loads((tmp_path / 'out' / 'jobs.jsonl').read_text().splitlines()[0])
    assert rec['valid_work'] is False
    assert rec['scored'] is False
    assert rec['score_before'] == rec['score_after'] == 5.0


def test_dictionary_cursor_not_advanced_on_all_hashes_token_length_failure(monkeypatch, tmp_path):
    arm = SequenceArm([token_length_error(skip_before=7, next_skip_after=99), SliceResult(exit_code=0, skip_before=7, next_skip_after=8)])
    arm.next_skip = 7
    _patch_scheduler(monkeypatch, arm)
    run_scheduler(_args(tmp_path, total_slices=1))
    records = [json.loads(line) for line in (tmp_path / 'out' / 'jobs.jsonl').read_text().splitlines()]
    assert records[0]['skip_before'] == 7
    assert arm.optimized_seen[:2] == [True, False]
    assert records[1]['skip_before'] == 7


def test_retry_after_all_hashes_token_length_runs_unoptimized(monkeypatch, tmp_path):
    arm = SequenceArm([token_length_error(), SliceResult(exit_code=0)])
    _patch_scheduler(monkeypatch, arm)
    run_scheduler(_args(tmp_path, total_slices=1))
    assert arm.optimized_seen[:2] == [True, False]
