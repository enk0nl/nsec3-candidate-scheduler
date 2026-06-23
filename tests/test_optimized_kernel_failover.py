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
