from __future__ import annotations

import importlib
import subprocess
import sys
from pathlib import Path

import pytest
import tomllib

ROOT = Path(__file__).resolve().parents[1]


def test_import_new_package_name():
    assert importlib.import_module('nsec3_candidate_scheduler') is not None


def test_old_package_name_not_importable():
    importlib.invalidate_caches()
    with pytest.raises(ModuleNotFoundError):
        importlib.import_module('adaptive' + '_hashcat_scheduler')


def test_module_entrypoint_works():
    result = subprocess.run([sys.executable, '-m', 'nsec3_candidate_scheduler', '--help'], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    assert result.returncode == 0
    assert 'nsec3-candidate-scheduler' in result.stdout


def test_cli_script_name():
    result = subprocess.run(['nsec3-candidate-scheduler', '--help'], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    assert result.returncode == 0
    assert 'nsec3-candidate-scheduler' in result.stdout


def test_old_cli_name_not_documented():
    docs = '\n'.join(path.read_text(encoding='utf-8') for path in [ROOT / 'README.md', *sorted((ROOT / 'docs').glob('*.md'))])
    assert ('adaptive' + '-hashcat-scheduler') not in docs
    assert ('adaptive' + '_hashcat_scheduler') not in docs


def test_docs_use_new_project_name():
    docs = (ROOT / 'README.md').read_text(encoding='utf-8') + '\n' + '\n'.join(path.read_text(encoding='utf-8') for path in sorted((ROOT / 'docs').glob('*.md')))
    assert 'NSEC3 Candidate Scheduler' in docs


def test_pyproject_name():
    data = tomllib.loads((ROOT / 'pyproject.toml').read_text(encoding='utf-8'))
    assert data['project']['name'] == 'nsec3-candidate-scheduler'
    assert data['project']['scripts'] == {'nsec3-candidate-scheduler': 'nsec3_candidate_scheduler.cli:main'}
