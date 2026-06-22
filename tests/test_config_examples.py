from __future__ import annotations

import json
import re
from pathlib import Path

from adaptive_hashcat_scheduler.config import load_config

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE_CONFIG = ROOT / 'example_config.json'
DOCS_CONFIG = ROOT / 'docs' / 'config.md'
README = ROOT / 'README.md'


def _example_json() -> dict:
    with EXAMPLE_CONFIG.open(encoding='utf-8') as f:
        return json.load(f)


def test_single_example_config_exists():
    assert EXAMPLE_CONFIG.exists()
    assert not (ROOT / 'configs' / 'adaptive_predictive_feedback.json').exists()
    assert not (ROOT / 'examples' / 'example_config.json').exists()


def test_example_config_is_valid_json():
    data = _example_json()
    assert isinstance(data, dict)
    assert isinstance(data['arms'], list)


def test_example_config_loads_with_config_loader():
    loaded = load_config(str(EXAMPLE_CONFIG))
    assert loaded['warmup']['scoring'] == 'arm_local'
    assert loaded['hashcat']['optimized_kernels'] is True
    # Disabled model-dependent placeholder arms are intentionally filtered out.
    assert {arm['type'] for arm in loaded['arms']} >= {'dictionary', 'brute_force', 'permutation', 'parent_domain_feedback'}


def test_example_config_contains_all_arm_types():
    arm_types = {arm['type'] for arm in _example_json()['arms']}
    assert {'dictionary', 'brute_force', 'predictive_prefix', 'predictive_suffix', 'permutation',
            'static_affix_feedback', 'parent_domain_feedback'} <= arm_types
    assert sum(1 for arm in _example_json()['arms'] if arm['type'] == 'dictionary') >= 2


def test_example_config_existing_schema_compatible():
    raw = _example_json()
    for arm in raw['arms']:
        assert arm['name']
        assert arm['type']
    loaded = load_config(str(EXAMPLE_CONFIG))
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
    assert 'feedback/<arm>/generated_candidates.sqlite' in docs
    assert 'generated_candidates_backend' in docs


def test_readme_references_existing_example_config():
    text = README.read_text(encoding='utf-8')
    assert '--config example_config.json' in text
    for match in re.findall(r'--config\s+([^\s\\]+)', text):
        assert (ROOT / match).exists(), match


def test_repository_does_not_ship_example_model_files():
    models_dir = ROOT / 'models'
    if not models_dir.exists():
        return
    forbidden = []
    for pattern in ['example*', 'demo*', '*prefix*', '*suffix*', '*.tsv', '*.txt']:
        forbidden.extend(path for path in models_dir.glob(pattern) if path.name != '.gitkeep')
    assert forbidden == []


def test_example_config_does_not_reference_bundled_model_paths():
    config_text = EXAMPLE_CONFIG.read_text(encoding='utf-8')
    for path in [
        'models/prefix_pairs.tsv',
        'models/suffix_pairs.tsv',
        'models/common_prefixes_top50.txt',
        'models/common_suffixes_top50.txt',
    ]:
        assert path not in config_text
    assert '/path/to/prefix_pairs.tsv' in config_text
    assert '/path/to/common_prefixes_top5000.txt' in config_text


def test_model_dependent_arms_disabled_by_default():
    arms = _example_json()['arms']
    by_type = {arm['type']: arm for arm in arms}
    assert by_type['predictive_prefix']['enabled'] is False
    assert by_type['predictive_suffix']['enabled'] is False
    assert by_type['static_affix_feedback']['enabled'] is False


def test_docs_explain_model_files_are_not_bundled():
    docs = DOCS_CONFIG.read_text(encoding='utf-8') + '\n' + README.read_text(encoding='utf-8')
    assert 'does not currently include model files' in docs
    assert 'Predictive feedback arms require trained adjacent-label pair models' in docs
    assert 'static-affix feedback arms require mined prefix/suffix files' in docs
    assert 'disabled by default' in docs


def test_unknown_enabled_arm_type_fails_config_validation(tmp_path):
    p = tmp_path / 'config.json'
    p.write_text(json.dumps({'arms': [{'name': 'osint/subfinder', 'type': 'subfinder_osint_typo', 'enabled': True}]}), encoding='utf-8')
    import pytest
    with pytest.raises(ValueError, match='unknown arm type'):
        load_config(str(p))


def test_unknown_disabled_arm_type_fails_config_validation(tmp_path):
    p = tmp_path / 'config.json'
    p.write_text(json.dumps({'arms': [{'name': 'osint/subfinder', 'type': 'subfinder_osint_typo', 'enabled': False}]}), encoding='utf-8')
    import pytest
    with pytest.raises(ValueError, match='unknown arm type'):
        load_config(str(p))


def test_disabled_placeholder_model_path_does_not_fail_resource_validation(tmp_path):
    p = tmp_path / 'config.json'
    p.write_text(json.dumps({'arms': [{'name': 'feedback/predictive-prefix', 'type': 'predictive_prefix', 'enabled': False, 'model': '/path/to/prefix_pairs.tsv'}]}), encoding='utf-8')
    assert load_config(str(p))['arms'] == []


def test_duplicate_arm_names_fail_config_validation(tmp_path):
    p = tmp_path / 'config.json'
    p.write_text(json.dumps({'arms': [
        {'name': 'wordlist/seclists', 'type': 'dictionary', 'enabled': False, 'wordlist': '/x'},
        {'name': 'wordlist/seclists', 'type': 'dictionary', 'enabled': False, 'wordlist': '/y'},
    ]}), encoding='utf-8')
    import pytest
    with pytest.raises(ValueError, match='duplicate arm name'):
        load_config(str(p))


def test_invalid_grouped_arm_name_fails(tmp_path):
    p = tmp_path / 'config.json'
    p.write_text(json.dumps({'arms': [{'name': 'feedback//x', 'type': 'parent_domain_feedback', 'enabled': False}]}), encoding='utf-8')
    import pytest
    with pytest.raises(ValueError, match='empty path segments'):
        load_config(str(p))


def test_example_config_uses_canonical_names():
    names = {arm['name'] for arm in _example_json()['arms']}
    assert {'wordlist/seclists', 'wordlist/pcfg-100m', 'bruteforce/rfc1035-len2-5', 'feedback/predictive-prefix', 'feedback/parent-domain', 'osint/amass', 'osint/subfinder'} <= names


def test_example_config_has_no_mismatched_candidate_count():
    text = EXAMPLE_CONFIG.read_text(encoding='utf-8')
    assert 'rfc1035_pcfg_top8843709.txt' not in text or '100000000' not in text


def test_safe_name_examples():
    from adaptive_hashcat_scheduler.naming import safe_name, arm_family, arm_short_name
    assert safe_name('wordlist/seclists') == 'wordlist-seclists'
    assert safe_name('wordlist/pcfg-1b') == 'wordlist-pcfg-1b'
    assert safe_name('feedback/predictive-prefix') == 'feedback-predictive-prefix'
    assert safe_name('feedback/static-affix-top5000') == 'feedback-static-affix-top5000'
    assert safe_name('osint/amass') == 'osint-amass'
    assert safe_name('../bad/name') == 'bad-name'
    assert arm_family('feedback/predictive-prefix') == 'feedback'
    assert arm_short_name('feedback/predictive-prefix') == 'predictive-prefix'


def test_docs_reference_canonical_names_and_no_removed_osint_generated_candidates():
    docs = '\n'.join(path.read_text(encoding='utf-8') for path in [README, DOCS_CONFIG, ROOT / 'docs' / 'state-and-logs.md', ROOT / 'docs' / 'feedback.md', ROOT / 'docs' / 'osint.md'])
    assert 'feedback/predictive-prefix' in docs
    assert 'feedback/parent-domain' in docs
    assert 'osint/amass' in docs
    assert 'parent-domain_seen_candidates.txt' not in docs
    assert 'OSINT arms do not write `generated_candidates.txt` by default' in docs


def test_config_docs_mention_all_arm_types():
    docs = DOCS_CONFIG.read_text(encoding='utf-8')
    for arm_type in ['dictionary', 'brute_force', 'feedback', 'predictive_prefix', 'predictive_suffix', 'permutation', 'static_affix_feedback', 'parent_domain_feedback', 'amass_osint', 'subfinder_osint']:
        assert arm_type in docs
