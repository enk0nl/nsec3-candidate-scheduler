from __future__ import annotations

import argparse
import json
from pathlib import Path

from adaptive_hashcat_scheduler.scheduler import run_scheduler


def test_warmup_arm_local_scores_independent_discoveries(tmp_path: Path) -> None:
    seclists = tmp_path / 'seclists.txt'
    seclists.write_text('www\ntest1\ntest2\n', encoding='utf-8')
    pcfg = tmp_path / 'pcfg.txt'
    pcfg.write_text('www\ntest2\ntest3\n', encoding='utf-8')
    hashes = tmp_path / 'hashes.txt'
    hashes.write_text('dummy\n', encoding='utf-8')
    fake_hashcat = tmp_path / 'fake_hashcat.py'
    fake_hashcat.write_text(
        """
#!/usr/bin/env python3
from pathlib import Path
import sys
potfile = Path(sys.argv[sys.argv.index('--potfile-path') + 1])
candidate = Path(sys.argv[-1])
existing = set()
if potfile.exists():
    for line in potfile.read_text(encoding='utf-8').splitlines():
        if ':' in line:
            existing.add(line.split(':', 1)[0])
with potfile.open('a', encoding='utf-8') as f:
    for plaintext in candidate.read_text(encoding='utf-8').splitlines():
        h = f'h_{plaintext}'
        if h not in existing:
            f.write(f'{h}:{plaintext}\\n')
            existing.add(h)
sys.exit(1)
""".lstrip(),
        encoding='utf-8',
    )
    fake_hashcat.chmod(0o755)
    config = tmp_path / 'config.json'
    config.write_text(json.dumps({
        'alpha': 1.0,
        'epsilon': 0.0,
        'warmup': {'scoring': 'arm_local'},
        'arms': [
            {'name': 'seclists', 'type': 'dictionary', 'wordlist': str(seclists)},
            {'name': 'pcfg', 'type': 'dictionary', 'wordlist': str(pcfg)},
        ],
    }), encoding='utf-8')
    out_dir = tmp_path / 'out'

    run_scheduler(argparse.Namespace(
        hashes=str(hashes), hash_mode=0, config=str(config), out_dir=str(out_dir),
        schedule='adaptive', total_slices=2, slice_seconds=1, alpha=None,
        epsilon=None, random_seed=0, default_limit=1000000,
        hashcat_bin=str(fake_hashcat), quiet=True, verbose=False,
        no_optimized_kernels=True,
    ))

    records = [json.loads(line) for line in (out_dir / 'jobs.jsonl').read_text(encoding='utf-8').splitlines()]
    assert [r['arm'] for r in records] == ['seclists', 'pcfg']
    assert records[0]['arm_local_new_cracks'] == 3
    assert records[0]['shared_new_cracks'] == 3
    assert records[0]['duplicate_cracks_vs_shared'] == 0
    assert records[1]['arm_local_new_cracks'] == 3
    assert records[1]['shared_new_cracks'] == 1
    assert records[1]['duplicate_cracks_vs_shared'] == 2
    assert records[1]['reward_used_for_score'] > records[1]['shared_new_cracks'] / records[1]['runtime_seconds']
    assert sorted(line.split(':', 1)[1] for line in (out_dir / 'run.pot').read_text(encoding='utf-8').splitlines()) == ['test1', 'test2', 'test3', 'www']
    assert (out_dir / 'warmup_potfiles' / 'seclists.potfile').exists()
    assert (out_dir / 'warmup_potfiles' / 'pcfg.potfile').exists()
