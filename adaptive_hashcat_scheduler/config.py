from __future__ import annotations
import json, os
from pathlib import Path
from typing import Any

SUPPORTED={'dictionary','brute_force','feedback','predictive_prefix','predictive_suffix','permutation','static_affix_feedback','parent_domain_feedback'}

def _validate_permutation(arm: dict[str, Any]) -> None:
    numeric = {
        'enabled': True,
        'min_width': 1,
        'max_width': 3,
        'generate_full_range': True,
        'generate_width_variants': True,
        'generate_local_radius': True,
        'allow_wider_width_variants': False,
        'allow_large_numeric_ranges': False,
        'local_radius': 50,
    }
    numeric.update(arm.get('numeric') or {})
    alpha = {
        'enabled': False,
        'charset': 'abcdefghijklmnopqrstuvwxyz',
        'min_width': 1,
        'max_width': 3,
        'generate_full_range': True,
        'generate_width_variants': True,
        'allow_wider_width_variants': False,
        'allow_large_alpha_ranges': False,
        'require_numeric_context': True,
    }
    alpha.update(arm.get('alpha') or {})
    for key in ('min_width', 'max_width'):
        if not isinstance(numeric.get(key), int) or isinstance(numeric.get(key), bool):
            raise ValueError(f'numeric.{key} must be an integer')
    if numeric['min_width'] < 1:
        raise ValueError('numeric.min_width >= 1 required')
    if numeric['max_width'] < numeric['min_width']:
        raise ValueError('numeric.max_width >= numeric.min_width required')
    if not isinstance(numeric.get('local_radius'), int) or isinstance(numeric.get('local_radius'), bool) or numeric['local_radius'] < 0:
        raise ValueError('numeric.local_radius >= 0 required')
    if numeric.get('generate_full_range', True) and numeric['max_width'] > 4 and not numeric.get('allow_large_numeric_ranges'):
        raise ValueError('numeric.allow_large_numeric_ranges=true required when numeric.generate_full_range=true and numeric.max_width > 4')
    for key in ('min_width', 'max_width'):
        if not isinstance(alpha.get(key), int) or isinstance(alpha.get(key), bool):
            raise ValueError(f'alpha.{key} must be an integer')
    if alpha['min_width'] < 1:
        raise ValueError('alpha.min_width >= 1 required')
    if alpha['max_width'] < alpha['min_width']:
        raise ValueError('alpha.max_width >= alpha.min_width required')
    charset = alpha.get('charset')
    if not isinstance(charset, str) or not charset:
        raise ValueError('alpha.charset must be non-empty')
    if not alpha.get('allow_non_lowercase_charset') and any(ch < 'a' or ch > 'z' for ch in charset):
        raise ValueError('alpha.charset must contain only lowercase letters unless alpha.allow_non_lowercase_charset=true')
    if alpha.get('generate_full_range', True) and alpha['max_width'] > 4 and not alpha.get('allow_large_alpha_ranges'):
        raise ValueError('alpha.allow_large_alpha_ranges=true required when alpha.generate_full_range=true and alpha.max_width > 4')


def load_config(path: str) -> dict[str, Any]:
    with open(path,'r',encoding='utf-8') as f: cfg=json.load(f)
    base=Path(path).parent
    hashcat_cfg = cfg.get('hashcat') or {}
    if not isinstance(hashcat_cfg, dict):
        raise ValueError('hashcat config must be an object')
    optimized = hashcat_cfg.get('optimized_kernels')
    if optimized is not None and not isinstance(optimized, bool):
        raise ValueError('hashcat.optimized_kernels must be boolean')
    arms=[]
    for arm in cfg.get('arms',[]):
        if not arm.get('enabled', True): continue
        t=arm.get('type')
        if t not in SUPPORTED: raise ValueError(f'unknown arm type: {t}')
        if t in {'predictive_prefix','predictive_suffix'}:
            if not arm.get('model'): raise ValueError(f'{t} arm requires model')
            mp=Path(arm['model'])
            if mp.is_absolute():
                full=mp
            elif mp.exists():
                full=mp
            else:
                full=base/mp
            if not full.exists(): raise ValueError(f'model path does not exist: {arm["model"]}')
            arm=dict(arm); arm['model']=str(full)
            if int(arm.get('max_predictions',100))<=0: raise ValueError('max_predictions > 0 required')
            ms=float(arm.get('min_sim',0.7))
            if ms<0 or ms>1: raise ValueError('min_sim must be between 0 and 1')
            if float(arm.get('tau',2.0))<=0: raise ValueError('tau > 0 required')
            if int(arm.get('k_neighbors',30))<=0: raise ValueError('k_neighbors > 0 required')
            if int(arm.get('top_predictions_per_neighbor',100))<=0: raise ValueError('top_predictions_per_neighbor > 0 required')
            if arm.get('base_mode','full') not in ['full','leftmost']: raise ValueError('invalid base_mode')
            if arm.get('prediction_source','leftmost') not in ['full','leftmost']: raise ValueError('invalid prediction_source')
        if t=='permutation':
            _validate_permutation(arm)
        if t=='parent_domain_feedback':
            arm=dict(arm)
            mpl=arm.get('min_parent_labels', 1)
            if not isinstance(mpl, int) or isinstance(mpl, bool) or mpl < 1: raise ValueError('min_parent_labels must be positive int')
            arm['min_parent_labels']=mpl
            mppd=arm.get('max_parents_per_discovery')
            if mppd is not None and (not isinstance(mppd, int) or isinstance(mppd, bool) or mppd < 0): raise ValueError('max_parents_per_discovery must be non-negative int or null')
            isp=arm.get('include_single_label_parent', True)
            if not isinstance(isp, bool): raise ValueError('include_single_label_parent must be boolean')
            arm['include_single_label_parent']=isp
            de=arm.get('debug_expansions', False)
            if not isinstance(de, bool): raise ValueError('debug_expansions must be boolean')
            arm['debug_expansions']=de
            dss=arm.get('debug_sample_size', 20)
            if not isinstance(dss, int) or isinstance(dss, bool) or dss < 0: raise ValueError('debug_sample_size must be non-negative int')
            arm['debug_sample_size']=dss
        if t=='static_affix_feedback':
            arm=dict(arm)
            for key in ('prefixes','suffixes'):
                if not arm.get(key): raise ValueError(f'static_affix_feedback arm requires {key}')
                mp=Path(arm[key])
                full=mp if mp.is_absolute() or mp.exists() else base/mp
                if not full.exists(): raise ValueError(f'{key} path does not exist: {arm[key]}')
                arm[key]=str(full)
            for key, default in (('top_prefixes',50),('top_suffixes',50)):
                value=int(arm.get(key, default))
                if value <= 0: raise ValueError(f'{key} > 0 required')
                arm[key]=value
            if arm.get('base_mode','full') != 'full': raise ValueError('static_affix_feedback base_mode must be full')
        fe=arm.get('force_every_slices')
        if fe is not None and (not isinstance(fe,int) or isinstance(fe,bool) or fe<=0): raise ValueError('force_every_slices must be positive int')
        if t in {'feedback','predictive_prefix','predictive_suffix','permutation','static_affix_feedback','parent_domain_feedback'}:
            msbr=arm.get('min_slices_between_runs')
            if msbr is not None and (not isinstance(msbr,int) or isinstance(msbr,bool) or msbr<0): raise ValueError('min_slices_between_runs must be non-negative int')
            mqs=arm.get('min_queue_size')
            if mqs is not None and (not isinstance(mqs,int) or isinstance(mqs,bool) or mqs<0): raise ValueError('min_queue_size must be non-negative int')
        arms.append(arm)
    cfg=dict(cfg); cfg['arms']=arms; return cfg
