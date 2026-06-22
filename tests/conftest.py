from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from nsec3_candidate_scheduler.arms.base import Arm, SliceResult


def write_lines(path: str | Path, values) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(''.join(f'{value}\n' for value in values), encoding='utf-8')


def read_lines(path: str | Path) -> list[str]:
    path = Path(path)
    if not path.exists():
        return []
    return [line.rstrip('\n') for line in path.read_text(encoding='utf-8').splitlines() if line.rstrip('\n')]


def write_json(path: str | Path, obj: Any) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, separators=(',', ':')) + '\n', encoding='utf-8')


def read_json(path: str | Path) -> Any:
    return json.loads(Path(path).read_text(encoding='utf-8'))


def make_fake_potfile(path: str | Path, pairs) -> Path:
    path = Path(path)
    write_lines(path, [f'{hash_side}:{value}' for hash_side, value in pairs])
    return path


def make_context(tmp_path: Path, **overrides):
    potfile = Path(overrides.pop('potfile', tmp_path / 'run.pot'))
    potfile.parent.mkdir(parents=True, exist_ok=True)
    potfile.touch(exist_ok=True)
    hashes = Path(overrides.pop('hashes', tmp_path / 'hashes.txt'))
    hashes.parent.mkdir(parents=True, exist_ok=True)
    hashes.write_text('hash\n', encoding='utf-8')
    values = {
        'out_dir': str(tmp_path),
        'potfile': str(potfile),
        'hashes': str(hashes),
        'hashcat_bin': 'hashcat',
        'hash_mode': 8300,
        'slice_seconds': 60,
        'default_limit': 1_000_000,
        'hashcat_optimized_kernels': True,
        'potfile_path_override': None,
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def fake_slice_result(*, executed: bool = True, valid_work: bool = True, new_cracks: int = 0,
                      runtime_seconds: float = 1.0, exit_code: int = 0, extra: dict[str, Any] | None = None,
                      execution_status: str | None = None) -> SliceResult:
    status = execution_status or ('executed' if executed and valid_work else 'skipped' if not executed else 'failed_no_progress')
    result = SliceResult(exit_code=exit_code, runtime_seconds=runtime_seconds, executed=executed,
                         valid_work=valid_work, execution_status=status, extra=extra or {})
    result.fake_new_cracks = new_cracks
    return result


def fake_hashcat_summary(*, progress_cur: int | None = None, progress_total: int | None = None,
                         recovered_salts_total: int | None = None, restore_point: int | None = None) -> dict[str, Any]:
    summary: dict[str, Any] = {}
    if progress_cur is not None:
        summary['progress_cur'] = progress_cur
    if progress_total is not None:
        summary['progress_total'] = progress_total
    if recovered_salts_total is not None:
        summary['recovered_salts_total'] = recovered_salts_total
    if restore_point is not None:
        summary['restore_point'] = restore_point
    return summary


class FakeArm(Arm):
    def __init__(self, name='fake', arm_type='dictionary', config=None, *, result=None,
                 warmup_eligible=True, available=True):
        super().__init__(name=name, type=arm_type, config=config or {})
        self.warmup_eligible = warmup_eligible
        self._available = available
        self.result = result or fake_slice_result()
        self.discoveries_seen: list[list[str]] = []
        self.run_calls = 0

    def is_available(self, context):
        return self._available and not self.exhausted

    def run_slice(self, context):
        self.run_calls += 1
        return self.result

    def on_new_discoveries(self, discoveries, context):
        self.discoveries_seen.append(list(discoveries))
        return {}


def fake_arm(**kwargs) -> FakeArm:
    return FakeArm(**kwargs)


def assert_no_root_feedback_files(out_dir: str | Path, arm_name: str) -> None:
    out_dir = Path(out_dir)
    for suffix in ['queue.txt', 'seen_candidates.txt', 'generated_candidates.txt', 'expanded_bases.txt',
                   'slice_candidates.txt', 'active_slice.json', 'cursor.json']:
        assert not (out_dir / f'{arm_name}_{suffix}').exists()


@pytest.fixture
def parent_context(tmp_path):
    return make_context(tmp_path)

@pytest.fixture(name='write_lines')
def write_lines_fixture():
    return write_lines


@pytest.fixture(name='read_lines')
def read_lines_fixture():
    return read_lines


@pytest.fixture(name='write_json')
def write_json_fixture():
    return write_json


@pytest.fixture(name='read_json')
def read_json_fixture():
    return read_json


@pytest.fixture(name='make_fake_potfile')
def make_fake_potfile_fixture():
    return make_fake_potfile


@pytest.fixture(name='make_context')
def make_context_fixture():
    return make_context


@pytest.fixture(name='fake_slice_result')
def fake_slice_result_fixture():
    return fake_slice_result


@pytest.fixture(name='fake_hashcat_summary')
def fake_hashcat_summary_fixture():
    return fake_hashcat_summary


@pytest.fixture(name='fake_arm')
def fake_arm_fixture():
    return fake_arm


@pytest.fixture(name='assert_no_root_feedback_files')
def assert_no_root_feedback_files_fixture():
    return assert_no_root_feedback_files
