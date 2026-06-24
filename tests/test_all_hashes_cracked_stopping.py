import argparse
import json

from nsec3_candidate_scheduler.arms.base import Arm, SliceResult
from nsec3_candidate_scheduler.scheduler import (
    SchedulerContext,
    count_target_hashes,
    should_stop_all_hashes_cracked,
    run_scheduler,
)


ALL_FOUND = 'INFO: All hashes found as potfile and/or empty entries! Use --show to display them.'


class PotfileArm(Arm):
    def __init__(self, pairs=None, *, result=None):
        super().__init__('potfile-arm', 'dictionary', {})
        self.pairs = pairs or []
        self.result = result or SliceResult()
        self.run_calls = 0

    def run_slice(self, context):
        self.run_calls += 1
        if self.pairs:
            with open(context.potfile, 'a', encoding='utf-8') as f:
                for hash_side, value in self.pairs:
                    f.write(f'{hash_side}:{value}\n')
        return self.result


def _args(tmp_path, config, hashes, *, total_slices=2):
    return argparse.Namespace(
        hashes=str(hashes),
        hash_mode=8300,
        config=str(config),
        out_dir=str(tmp_path / 'out'),
        schedule='adaptive',
        total_slices=total_slices,
        slice_seconds=1,
        alpha=None,
        epsilon=None,
        random_seed=0,
        default_limit=1000000,
        hashcat_bin='hashcat',
        quiet=True,
        verbose=False,
        no_optimized_kernels=True,
        optimized_kernel_failover=None,
        stop_when_all_hashes_cracked=None,
    )


def _write_config(path, *, stop=True):
    path.write_text(json.dumps({
        'alpha': 1.0,
        'epsilon': 0.0,
        'stopping': {'stop_when_all_hashes_cracked': stop},
        'arms': [{'name': 'potfile-arm', 'type': 'dictionary'}],
    }), encoding='utf-8')


def _hashes(path, count=4):
    path.write_text(''.join(f'h{i}:.example.nl:ab:1\n' for i in range(1, count + 1)), encoding='utf-8')
    return path


def _load_jsonl(path):
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding='utf-8').splitlines()]


def test_target_hash_count_detected_from_hashfile(tmp_path):
    hashes = tmp_path / 'hashes.txt'
    hashes.write_text('\nh1\nh2\n\nh3\nh4\n', encoding='utf-8')
    assert count_target_hashes(str(hashes)) == 4


def test_all_hashes_cracked_stops_before_next_slice(tmp_path):
    hashes = _hashes(tmp_path / 'hashes.txt')
    potfile = tmp_path / 'run.pot'
    potfile.write_text(''.join(f'h{i}:.example.nl:ab:1:name{i}\n' for i in range(1, 5)), encoding='utf-8')
    ctx = SchedulerContext(str(hashes), 8300, str(tmp_path), 1, str(potfile), target_hash_count=4)
    assert should_stop_all_hashes_cracked(ctx) is True


def test_final_crack_job_is_recorded_then_scheduler_stops(tmp_path, monkeypatch):
    arm = PotfileArm([('h4:.example.nl:ab:1', 'api')])
    monkeypatch.setattr('nsec3_candidate_scheduler.scheduler.load_config', lambda _: {'alpha': 1.0, 'epsilon': 0.0, 'arms': [{'name': 'potfile-arm'}]})
    monkeypatch.setattr('nsec3_candidate_scheduler.scheduler.make_arm', lambda _: arm)
    config = tmp_path / 'config.json'; config.write_text('{}', encoding='utf-8')
    hashes = _hashes(tmp_path / 'hashes.txt')
    out_dir = tmp_path / 'out'; out_dir.mkdir()
    (out_dir / 'run.pot').write_text(''.join(f'h{i}:.example.nl:ab:1:name{i}\n' for i in range(1, 4)), encoding='utf-8')

    run_scheduler(_args(tmp_path, config, hashes, total_slices=3))

    records = _load_jsonl(out_dir / 'jobs.jsonl')
    assert len(records) == 1
    assert records[0]['total_cracks'] == 4
    assert records[0]['target_hash_count'] == 4
    assert records[0]['remaining_hash_count'] == 0
    assert json.loads((out_dir / 'summary.json').read_text())['completed_reason'] == 'all_hashes_cracked'
    assert arm.run_calls == 1


def test_all_hashes_found_as_potfile_output_causes_completion_check(tmp_path, monkeypatch):
    result = SliceResult(valid_work=True, execution_status='failed_no_progress', stdout=ALL_FOUND)
    arm = PotfileArm(result=result)
    monkeypatch.setattr('nsec3_candidate_scheduler.scheduler.load_config', lambda _: {'alpha': 1.0, 'epsilon': 0.0, 'arms': [{'name': 'potfile-arm'}]})
    monkeypatch.setattr('nsec3_candidate_scheduler.scheduler.make_arm', lambda _: arm)
    config = tmp_path / 'config.json'; config.write_text('{}', encoding='utf-8')
    hashes = _hashes(tmp_path / 'hashes.txt')
    out_dir = tmp_path / 'out'; out_dir.mkdir()
    (out_dir / 'run.pot').write_text(''.join(f'h{i}:.example.nl:ab:1:name{i}\n' for i in range(1, 5)), encoding='utf-8')

    run_scheduler(_args(tmp_path, config, hashes, total_slices=3))

    records = _load_jsonl(out_dir / 'jobs.jsonl')
    assert records == []
    assert arm.run_calls == 0
    assert json.loads((out_dir / 'summary.json').read_text())['completed_reason'] == 'all_hashes_cracked'


def test_all_hashes_found_as_potfile_not_scored_as_valid_work(tmp_path, monkeypatch):
    result = SliceResult(valid_work=True, execution_status='failed_no_progress', stdout=ALL_FOUND)
    arm = PotfileArm([('h4:.example.nl:ab:1', 'api')], result=result)
    monkeypatch.setattr('nsec3_candidate_scheduler.scheduler.load_config', lambda _: {'alpha': 1.0, 'epsilon': 0.0, 'arms': [{'name': 'potfile-arm'}]})
    monkeypatch.setattr('nsec3_candidate_scheduler.scheduler.make_arm', lambda _: arm)
    config = tmp_path / 'config.json'; config.write_text('{}', encoding='utf-8')
    hashes = _hashes(tmp_path / 'hashes.txt')
    out_dir = tmp_path / 'out'; out_dir.mkdir()
    (out_dir / 'run.pot').write_text(''.join(f'h{i}:.example.nl:ab:1:name{i}\n' for i in range(1, 4)), encoding='utf-8')

    run_scheduler(_args(tmp_path, config, hashes, total_slices=2))

    rec = _load_jsonl(out_dir / 'jobs.jsonl')[0]
    assert rec['execution_status'] == 'failed_no_progress'
    assert rec['valid_work'] is False
    assert rec['scored'] is False
    assert rec['score_after'] == rec['score_before']


def test_empty_plaintext_counts_toward_all_hashes_cracked(tmp_path):
    hashes = _hashes(tmp_path / 'hashes.txt')
    potfile = tmp_path / 'run.pot'
    potfile.write_text(
        'h1:.example.nl:ab:1:\n'
        'h2:.example.nl:ab:1:www\n'
        'h3:.example.nl:ab:1:mail\n'
        'h4:.example.nl:ab:1:api\n',
        encoding='utf-8',
    )
    ctx = SchedulerContext(str(hashes), 8300, str(tmp_path), 1, str(potfile), target_hash_count=4)
    assert should_stop_all_hashes_cracked(ctx) is True


def test_three_of_four_does_not_stop(tmp_path):
    hashes = _hashes(tmp_path / 'hashes.txt')
    potfile = tmp_path / 'run.pot'
    potfile.write_text(''.join(f'h{i}:.example.nl:ab:1:name{i}\n' for i in range(1, 4)), encoding='utf-8')
    ctx = SchedulerContext(str(hashes), 8300, str(tmp_path), 1, str(potfile), target_hash_count=4)
    assert should_stop_all_hashes_cracked(ctx) is False


def test_resume_with_complete_run_pot_exits_without_jobs(tmp_path, monkeypatch):
    arm = PotfileArm([('h5:.example.nl:ab:1', 'extra')])
    monkeypatch.setattr('nsec3_candidate_scheduler.scheduler.load_config', lambda _: {'alpha': 1.0, 'epsilon': 0.0, 'arms': [{'name': 'potfile-arm'}]})
    monkeypatch.setattr('nsec3_candidate_scheduler.scheduler.make_arm', lambda _: arm)
    config = tmp_path / 'config.json'; config.write_text('{}', encoding='utf-8')
    hashes = _hashes(tmp_path / 'hashes.txt')
    out_dir = tmp_path / 'out'; out_dir.mkdir()
    (out_dir / 'run.pot').write_text(''.join(f'h{i}:.example.nl:ab:1:name{i}\n' for i in range(1, 5)), encoding='utf-8')

    run_scheduler(_args(tmp_path, config, hashes, total_slices=2))

    assert _load_jsonl(out_dir / 'jobs.jsonl') == []
    assert arm.run_calls == 0
    summary = json.loads((out_dir / 'summary.json').read_text())
    assert summary == {
        'completed': True,
        'completed_reason': 'all_hashes_cracked',
        'target_hash_count': 4,
        'total_cracks': 4,
        'remaining_hash_count': 0,
    }


def test_stop_when_all_hashes_cracked_can_be_disabled_if_config_supported(tmp_path, monkeypatch):
    arm = PotfileArm([('h5:.example.nl:ab:1', 'extra')])
    monkeypatch.setattr('nsec3_candidate_scheduler.scheduler.load_config', lambda _: {'alpha': 1.0, 'epsilon': 0.0, 'stopping': {'stop_when_all_hashes_cracked': False}, 'arms': [{'name': 'potfile-arm'}]})
    monkeypatch.setattr('nsec3_candidate_scheduler.scheduler.make_arm', lambda _: arm)
    config = tmp_path / 'config.json'; config.write_text('{}', encoding='utf-8')
    hashes = _hashes(tmp_path / 'hashes.txt')
    out_dir = tmp_path / 'out'; out_dir.mkdir()
    (out_dir / 'run.pot').write_text(''.join(f'h{i}:.example.nl:ab:1:name{i}\n' for i in range(1, 5)), encoding='utf-8')

    run_scheduler(_args(tmp_path, config, hashes, total_slices=1))

    assert len(_load_jsonl(out_dir / 'jobs.jsonl')) == 1
    assert arm.run_calls == 1


def test_completion_metadata_written(tmp_path, monkeypatch):
    arm = PotfileArm([('h4:.example.nl:ab:1', 'api')])
    monkeypatch.setattr('nsec3_candidate_scheduler.scheduler.load_config', lambda _: {'alpha': 1.0, 'epsilon': 0.0, 'arms': [{'name': 'potfile-arm'}]})
    monkeypatch.setattr('nsec3_candidate_scheduler.scheduler.make_arm', lambda _: arm)
    config = tmp_path / 'config.json'; config.write_text('{}', encoding='utf-8')
    hashes = _hashes(tmp_path / 'hashes.txt')
    out_dir = tmp_path / 'out'; out_dir.mkdir()
    (out_dir / 'run.pot').write_text(''.join(f'h{i}:.example.nl:ab:1:name{i}\n' for i in range(1, 4)), encoding='utf-8')

    run_scheduler(_args(tmp_path, config, hashes, total_slices=1))

    summary = json.loads((out_dir / 'summary.json').read_text())
    event = _load_jsonl(out_dir / 'events.jsonl')[0]
    assert summary['completed'] is True
    assert summary['completed_reason'] == 'all_hashes_cracked'
    assert summary['target_hash_count'] == 4
    assert summary['total_cracks'] == 4
    assert summary['remaining_hash_count'] == 0
    assert event['event'] == 'scheduler_completed'
    assert event['reason'] == 'all_hashes_cracked'
