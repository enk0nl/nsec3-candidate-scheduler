from __future__ import annotations

import json
import re
from pathlib import Path

from adaptive_hashcat_scheduler.config import load_config

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE_CONFIG = ROOT / 'example_config.json'
DOCS_CONFIG = ROOT / 'docs' / 'config.md'
README = ROOT / 'README.md'


def test_single_example_config_exists():
    assert EXAMPLE_CONFIG.exists()
    assert not (ROOT / 'configs' / 'adaptive_predictive_feedback.json').exists()
    assert not (ROOT / 'examples' / 'example_config.json').exists()


def test_example_config_is_valid_json():
    with EXAMPLE_CONFIG.open(encoding='utf-8') as f:
        data = json.load(f)
    assert isinstance(data, dict)
    assert isinstance(data['arms'], list)


def test_example_config_loads_with_config_loader():
    loaded = load_config(str(EXAMPLE_CONFIG))
    assert loaded['warmup']['scoring'] == 'arm_local'
    assert loaded['hashcat']['optimized_kernels'] is True
    assert len(loaded['arms']) >= 8


def test_example_config_contains_all_arm_types():
    loaded = load_config(str(EXAMPLE_CONFIG))
    arm_types = {arm['type'] for arm in loaded['arms']}
    assert {'dictionary', 'brute_force', 'predictive_prefix', 'predictive_suffix', 'permutation',
            'static_affix_feedback', 'parent_domain_feedback'} <= arm_types
    assert sum(1 for arm in loaded['arms'] if arm['type'] == 'dictionary') >= 2


def test_example_config_existing_schema_compatible():
    loaded = load_config(str(EXAMPLE_CONFIG))
    for arm in loaded['arms']:
        assert arm['name']
        assert arm['type']
    permutation = next(arm for arm in loaded['arms'] if arm['type'] == 'permutation')
    assert 'numeric' in permutation and 'alpha' in permutation
    assert 'cross_product' not in json.dumps(permutation)
    parent = next(arm for arm in loaded['arms'] if arm['type'] == 'parent_domain_feedback')
    assert parent['include_single_label_parent'] is True


def test_removed_config_directories_are_not_required():
    test_text = ''.join(path.read_text(encoding='utf-8') for path in (ROOT / 'tests').glob('test_*.py'))
    assert ('configs/' + 'adaptive_predictive_feedback.json') not in test_text
    assert ('examples/' + 'example_config.json') not in test_text


def test_example_config_uses_new_feedback_state_layout():
    docs = README.read_text(encoding='utf-8') + '\n' + DOCS_CONFIG.read_text(encoding='utf-8')
    assert 'parent-domain_queue.txt' not in docs
    assert 'parent-domain_seen_candidates.txt' not in docs
    assert 'feedback/<arm>/queue.txt' in docs
    assert 'feedback/<arm>/generated_candidates.txt' in docs


def test_readme_references_existing_example_config():
    text = README.read_text(encoding='utf-8')
    assert '--config example_config.json' in text
    for match in re.findall(r'--config\s+([^\s\\]+)', text):
        assert (ROOT / match).exists(), match
