from __future__ import annotations

import base64
import csv
import hashlib
import os
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

NAME = 'nsec3_candidate_scheduler'
DIST = 'nsec3_candidate_scheduler-0.1.0.dist-info'
PROJECT = 'nsec3-candidate-scheduler'
VERSION = '0.1.0'


def _metadata() -> str:
    return f"Metadata-Version: 2.1\nName: {PROJECT}\nVersion: {VERSION}\nSummary: Adaptive scheduler for DNS/NSEC3 candidate validation with hashcat\nRequires-Python: >=3.10\nProvides-Extra: test\nRequires-Dist: pytest; extra == 'test'\n"


def _wheel() -> str:
    return "Wheel-Version: 1.0\nGenerator: nsec3-candidate-build-backend\nRoot-Is-Purelib: true\nTag: py3-none-any\n"


def _record_hash(data: bytes) -> str:
    digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b'=').decode('ascii')
    return f'sha256={digest}'


def _write_metadata_dir(path: Path) -> None:
    dist = path / DIST
    dist.mkdir(parents=True, exist_ok=True)
    (dist / 'METADATA').write_text(_metadata(), encoding='utf-8')
    (dist / 'WHEEL').write_text(_wheel(), encoding='utf-8')
    (dist / 'entry_points.txt').write_text('[console_scripts]\nnsec3-candidate-scheduler=nsec3_candidate_scheduler.cli:main\n', encoding='utf-8')


def prepare_metadata_for_build_wheel(metadata_directory, config_settings=None):
    _write_metadata_dir(Path(metadata_directory))
    return DIST


def prepare_metadata_for_build_editable(metadata_directory, config_settings=None):
    return prepare_metadata_for_build_wheel(metadata_directory, config_settings)


def get_requires_for_build_wheel(config_settings=None):
    return []


def get_requires_for_build_editable(config_settings=None):
    return []


def build_wheel(wheel_directory, config_settings=None, metadata_directory=None):
    return _build(wheel_directory, editable=False)


def build_editable(wheel_directory, config_settings=None, metadata_directory=None):
    return _build(wheel_directory, editable=True)


def _build(wheel_directory, editable: bool):
    wheel_name = 'nsec3_candidate_scheduler-0.1.0-py3-none-any.whl'
    wheel_path = Path(wheel_directory) / wheel_name
    root = Path(__file__).resolve().parent
    files: dict[str, bytes] = {
        f'{DIST}/METADATA': _metadata().encode('utf-8'),
        f'{DIST}/WHEEL': _wheel().encode('utf-8'),
        f'{DIST}/entry_points.txt': b'[console_scripts]\nnsec3-candidate-scheduler=nsec3_candidate_scheduler.cli:main\n',
    }
    if editable:
        files['nsec3_candidate_scheduler_editable.pth'] = (str(root) + os.linesep).encode('utf-8')
    else:
        for path in (root / 'nsec3_candidate_scheduler').rglob('*.py'):
            files[str(path.relative_to(root)).replace(os.sep, '/')] = path.read_bytes()
    rows = []
    for name, data in files.items():
        rows.append([name, _record_hash(data), str(len(data))])
    rows.append([f'{DIST}/RECORD', '', ''])
    record_lines = []
    for row in rows:
        from io import StringIO
        buf = StringIO(); csv.writer(buf, lineterminator='\n').writerow(row); record_lines.append(buf.getvalue())
    files[f'{DIST}/RECORD'] = ''.join(record_lines).encode('utf-8')
    with ZipFile(wheel_path, 'w', ZIP_DEFLATED) as zf:
        for name, data in files.items():
            zf.writestr(name, data)
    return wheel_name
