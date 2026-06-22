from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from nsec3_candidate_scheduler.arms.osint_common import normalize_osint_domain
from nsec3_candidate_scheduler.arms.amass_osint import parse_domains
from nsec3_candidate_scheduler.arms.registry import SUPPORTED_ARM_TYPES, FEEDBACK_TYPES, OSINT_TYPES

SUPPORTED = SUPPORTED_ARM_TYPES


def _as_positive_int(value: Any, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise ValueError(f'{field} must be a positive integer')
    return value


def _as_nonnegative_int(value: Any, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError(f'{field} must be a non-negative integer')
    return value


def _resolve_existing(base: Path, value: str, field: str) -> str:
    p = Path(value)
    full = p if p.is_absolute() or p.exists() else base / p
    if not full.exists():
        raise ValueError(f'{field} path does not exist: {value}')
    return str(full)


def _validate_arm_name(name: Any, seen: set[str]) -> str:
    if not isinstance(name, str) or not name:
        raise ValueError('arm name must be a non-empty string')
    if name != name.strip():
        raise ValueError(f'arm name has leading/trailing whitespace: {name!r}')
    if '..' in name:
        raise ValueError(f'arm name must not contain ..: {name!r}')
    if any(part == '' for part in name.split('/')):
        raise ValueError(f'arm name must not contain empty path segments: {name!r}')
    if name in seen:
        raise ValueError(f'duplicate arm name: {name}')
    seen.add(name)
    return name


def _validate_backend_fields(arm: dict[str, Any]) -> None:
    backend = str(arm.get('generated_candidates_backend', 'sqlite')).lower()
    if backend not in {'sqlite', 'text', 'none'}:
        raise ValueError('generated_candidates_backend must be sqlite, text, or none')
    if 'retain_generated_candidates_text' in arm and not isinstance(arm['retain_generated_candidates_text'], bool):
        raise ValueError('retain_generated_candidates_text must be boolean')
    for field in ('max_candidates_per_slice', 'feedback_disk_warning_bytes', 'sqlite_insert_batch_size'):
        if field in arm:
            _as_nonnegative_int(arm[field], field)
    if 'retain_completed_slices' in arm and not isinstance(arm['retain_completed_slices'], bool):
        raise ValueError('retain_completed_slices must be boolean')


def _validate_predictive(arm: dict[str, Any], base: Path, enabled: bool) -> dict[str, Any]:
    arm = dict(arm)
    if not arm.get('model'):
        raise ValueError(f'{arm["type"]} arm requires model')
    if enabled:
        arm['model'] = _resolve_existing(base, arm['model'], 'model')
    for field, default in (('max_predictions', 100), ('k_neighbors', 30), ('top_predictions_per_neighbor', 100)):
        arm[field] = _as_positive_int(int(arm.get(field, default)), field)
    min_sim = float(arm.get('min_sim', 0.7))
    if min_sim < 0 or min_sim > 1:
        raise ValueError('min_sim must be between 0 and 1')
    arm['min_sim'] = min_sim
    if float(arm.get('tau', 2.0)) <= 0:
        raise ValueError('tau > 0 required')
    if arm.get('base_mode', 'full') not in {'full', 'leftmost'}:
        raise ValueError('invalid base_mode')
    if arm.get('prediction_source', 'leftmost') not in {'full', 'leftmost'}:
        raise ValueError('invalid prediction_source')
    _validate_backend_fields(arm)
    return arm


def _validate_dictionary(arm: dict[str, Any], base: Path, enabled: bool) -> dict[str, Any]:
    arm = dict(arm)
    if not arm.get('wordlist'):
        raise ValueError('dictionary arm requires wordlist')
    if enabled:
        arm['wordlist'] = _resolve_existing(base, arm['wordlist'], 'wordlist')
    if arm.get('candidate_count') is not None:
        arm['candidate_count'] = _as_positive_int(arm['candidate_count'], f'candidate_count for arm {arm.get("name")!r}')
    count = arm.get('count_candidates_at_startup', False)
    if not isinstance(count, bool):
        raise ValueError('count_candidates_at_startup must be boolean')
    arm['count_candidates_at_startup'] = count
    warn = arm.get('large_wordlist_scan_warning_bytes', 1_073_741_824)
    arm['large_wordlist_scan_warning_bytes'] = _as_nonnegative_int(warn, 'large_wordlist_scan_warning_bytes')
    return arm


def _validate_permutation(arm: dict[str, Any]) -> dict[str, Any]:
    arm = dict(arm)
    numeric = {'enabled': True, 'min_width': 1, 'max_width': 3, 'generate_full_range': True, 'generate_width_variants': True, 'generate_local_radius': True, 'allow_wider_width_variants': False, 'allow_large_numeric_ranges': False, 'local_radius': 50}
    numeric.update(arm.get('numeric') or {})
    alpha = {'enabled': False, 'charset': 'abcdefghijklmnopqrstuvwxyz', 'min_width': 1, 'max_width': 3, 'generate_full_range': True, 'generate_width_variants': True, 'allow_wider_width_variants': False, 'allow_large_alpha_ranges': False, 'require_numeric_context': True}
    alpha.update(arm.get('alpha') or {})
    for obj, prefix in ((numeric, 'numeric'), (alpha, 'alpha')):
        obj['min_width'] = _as_positive_int(obj.get('min_width'), f'{prefix}.min_width')
        obj['max_width'] = _as_positive_int(obj.get('max_width'), f'{prefix}.max_width')
        if obj['max_width'] < obj['min_width']:
            raise ValueError(f'{prefix}.max_width >= {prefix}.min_width required')
    numeric['local_radius'] = _as_nonnegative_int(numeric.get('local_radius'), 'numeric.local_radius')
    if numeric.get('generate_full_range', True) and numeric['max_width'] > 4 and not numeric.get('allow_large_numeric_ranges'):
        raise ValueError('numeric.allow_large_numeric_ranges=true required when numeric.generate_full_range=true and numeric.max_width > 4')
    charset = alpha.get('charset')
    if not isinstance(charset, str) or not charset:
        raise ValueError('alpha.charset must be non-empty')
    if not alpha.get('allow_non_lowercase_charset') and any(ch < 'a' or ch > 'z' for ch in charset):
        raise ValueError('alpha.charset must contain only lowercase letters unless alpha.allow_non_lowercase_charset=true')
    if alpha.get('generate_full_range', True) and alpha['max_width'] > 4 and not alpha.get('allow_large_alpha_ranges'):
        raise ValueError('alpha.allow_large_alpha_ranges=true required when alpha.generate_full_range=true and alpha.max_width > 4')
    arm['numeric'] = numeric; arm['alpha'] = alpha
    _validate_backend_fields(arm)
    return arm


def _validate_static_affix(arm: dict[str, Any], base: Path, enabled: bool) -> dict[str, Any]:
    arm = dict(arm)
    for key in ('prefixes', 'suffixes'):
        if not arm.get(key):
            raise ValueError(f'static_affix_feedback arm requires {key}')
        if enabled:
            arm[key] = _resolve_existing(base, arm[key], key)
    for key, default in (('top_prefixes', 50), ('top_suffixes', 50)):
        arm[key] = _as_positive_int(int(arm.get(key, default)), key)
    if arm.get('base_mode', 'full') != 'full':
        raise ValueError('static_affix_feedback base_mode must be full')
    _validate_backend_fields(arm)
    return arm


def _validate_parent_domain(arm: dict[str, Any]) -> dict[str, Any]:
    arm = dict(arm)
    arm['min_parent_labels'] = _as_positive_int(arm.get('min_parent_labels', 1), 'min_parent_labels')
    mppd = arm.get('max_parents_per_discovery')
    if mppd is not None:
        arm['max_parents_per_discovery'] = _as_nonnegative_int(mppd, 'max_parents_per_discovery')
    for key, default in (('include_single_label_parent', True), ('debug_expansions', False)):
        val = arm.get(key, default)
        if not isinstance(val, bool):
            raise ValueError(f'{key} must be boolean')
        arm[key] = val
    arm['debug_sample_size'] = _as_nonnegative_int(arm.get('debug_sample_size', 20), 'debug_sample_size')
    _validate_backend_fields(arm)
    return arm


def _validate_amass_osint(arm: dict[str, Any]) -> dict[str, Any]:
    arm = dict(arm)
    domains_list, domains_arg = parse_domains(arm.get('domains'))
    if not domains_list:
        raise ValueError('amass_osint arm requires non-empty domains')
    arm['domains_list'] = domains_list; arm['domains_arg'] = domains_arg
    defaults = {'amass_binary': 'amass', 'start_on_run_start': True, 'poll_interval_seconds': 5, 'run_immediately_when_ready': True, 'max_candidates': None, 'dedupe': True, 'include_single_label': True, 'include_multi_label': True, 'require_min_version': True, 'keep_running_on_exit': False, 'min_slices_between_runs': 0}
    for k, v in defaults.items(): arm.setdefault(k, v)
    for k in ('start_on_run_start','run_immediately_when_ready','dedupe','include_single_label','include_multi_label','require_min_version','keep_running_on_exit'):
        if not isinstance(arm[k], bool): raise ValueError(f'{k} must be boolean')
    if not isinstance(arm['poll_interval_seconds'], (int, float)) or isinstance(arm['poll_interval_seconds'], bool) or arm['poll_interval_seconds'] <= 0:
        raise ValueError('poll_interval_seconds must be positive')
    if arm['max_candidates'] is not None: arm['max_candidates'] = _as_nonnegative_int(arm['max_candidates'], 'max_candidates')
    return arm


def _validate_subfinder_osint(arm: dict[str, Any]) -> dict[str, Any]:
    arm = dict(arm)
    domain = normalize_osint_domain(arm.get('domain', ''))
    if not domain:
        raise ValueError('subfinder_osint arm requires non-empty domain')
    arm['domain'] = domain
    defaults = {'subfinder_binary': 'subfinder', 'start_on_run_start': True, 'poll_interval_seconds': 5, 'run_immediately_when_ready': True, 'max_candidates': None, 'dedupe': True, 'include_single_label': True, 'include_multi_label': True, 'keep_running_on_exit': False, 'min_slices_between_runs': 0}
    for k, v in defaults.items(): arm.setdefault(k, v)
    for k in ('start_on_run_start','run_immediately_when_ready','dedupe','include_single_label','include_multi_label','keep_running_on_exit'):
        if not isinstance(arm[k], bool): raise ValueError(f'{k} must be boolean')
    if not isinstance(arm['poll_interval_seconds'], (int, float)) or isinstance(arm['poll_interval_seconds'], bool) or arm['poll_interval_seconds'] <= 0:
        raise ValueError('poll_interval_seconds must be positive')
    if arm['max_candidates'] is not None: arm['max_candidates'] = _as_nonnegative_int(arm['max_candidates'], 'max_candidates')
    return arm


def _validate_common_arm_fields(arm: dict[str, Any]) -> None:
    if 'enabled' in arm and not isinstance(arm['enabled'], bool):
        raise ValueError('enabled must be boolean')
    if 'slice_seconds' in arm:
        _as_positive_int(arm['slice_seconds'], 'slice_seconds')
    fe = arm.get('force_every_slices')
    if fe is not None:
        _as_positive_int(fe, 'force_every_slices')
    if arm.get('type') in FEEDBACK_TYPES | OSINT_TYPES:
        for field in ('min_slices_between_runs', 'min_queue_size'):
            if arm.get(field) is not None:
                _as_nonnegative_int(arm[field], field)


def load_config(path: str) -> dict[str, Any]:
    with open(path, 'r', encoding='utf-8') as f:
        cfg = json.load(f)
    if not isinstance(cfg, dict):
        raise ValueError('config must be an object')
    base = Path(path).parent
    if 'random_seed' in cfg and (not isinstance(cfg['random_seed'], int) or isinstance(cfg['random_seed'], bool)):
        raise ValueError('random_seed must be integer')
    for field in ('alpha', 'epsilon'):
        if field in cfg and not isinstance(cfg[field], (int, float)):
            raise ValueError(f'{field} must be numeric')
    warmup_cfg = cfg.get('warmup') or {}
    if not isinstance(warmup_cfg, dict): raise ValueError('warmup config must be an object')
    scoring = warmup_cfg.get('scoring', 'arm_local')
    if scoring not in {'arm_local', 'shared_marginal'}: raise ValueError('warmup.scoring must be arm_local or shared_marginal')
    cfg['warmup'] = {**warmup_cfg, 'scoring': scoring}
    hashcat_cfg = cfg.get('hashcat') or {}
    if not isinstance(hashcat_cfg, dict): raise ValueError('hashcat config must be an object')
    optimized = hashcat_cfg.get('optimized_kernels')
    if optimized is not None and not isinstance(optimized, bool): raise ValueError('hashcat.optimized_kernels must be boolean')
    raw_arms = cfg.get('arms')
    if not isinstance(raw_arms, list): raise ValueError('arms must be a list')
    arms: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw in raw_arms:
        if not isinstance(raw, dict): raise ValueError('arm entries must be objects')
        arm = dict(raw)
        _validate_arm_name(arm.get('name'), seen)
        t = arm.get('type')
        if not isinstance(t, str) or not t: raise ValueError(f'arm {arm.get("name")!r} requires type')
        if t not in SUPPORTED: raise ValueError(f'unknown arm type: {t}')
        enabled = arm.get('enabled', True)
        _validate_common_arm_fields(arm)
        if t == 'dictionary': arm = _validate_dictionary(arm, base, enabled)
        elif t in {'predictive_prefix', 'predictive_suffix'}: arm = _validate_predictive(arm, base, enabled)
        elif t == 'permutation': arm = _validate_permutation(arm)
        elif t == 'static_affix_feedback': arm = _validate_static_affix(arm, base, enabled)
        elif t == 'parent_domain_feedback': arm = _validate_parent_domain(arm)
        elif t == 'amass_osint': arm = _validate_amass_osint(arm)
        elif t == 'subfinder_osint': arm = _validate_subfinder_osint(arm)
        elif t == 'feedback': _validate_backend_fields(arm)
        if enabled:
            arms.append(arm)
    cfg = dict(cfg); cfg['arms'] = arms
    return cfg
