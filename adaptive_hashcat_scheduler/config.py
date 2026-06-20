from __future__ import annotations
import json, os
from pathlib import Path
from typing import Any

SUPPORTED={'dictionary','brute_force','feedback','predictive_prefix','predictive_suffix'}

def load_config(path: str) -> dict[str, Any]:
    with open(path,'r',encoding='utf-8') as f: cfg=json.load(f)
    base=Path(path).parent
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
        fe=arm.get('force_every_slices')
        if fe is not None and (not isinstance(fe,int) or isinstance(fe,bool) or fe<=0): raise ValueError('force_every_slices must be positive int')
        arms.append(arm)
    cfg=dict(cfg); cfg['arms']=arms; return cfg
