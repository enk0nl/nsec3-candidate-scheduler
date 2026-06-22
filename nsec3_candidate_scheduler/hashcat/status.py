from __future__ import annotations
import json
from typing import Any


def parse_status_lines(output_text: str) -> list[dict[str, Any]]:
    out = []
    for raw in output_text.splitlines():
        try:
            obj = json.loads(raw.strip())
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            out.append(obj)
    return out


def latest_summary(output_text: str) -> dict[str, Any]:
    events = parse_status_lines(output_text)
    status = events[-1] if events else {}
    def pair(name):
        v = status.get(name)
        if isinstance(v, list):
            return (v[0] if len(v) > 0 else None, v[1] if len(v) > 1 else None)
        return (v if isinstance(v, int) else None, None)
    pc, pt = pair('progress')
    rhc, rht = pair('recovered_hashes')
    rsc, rst = pair('recovered_salts')
    rp, _ = pair('restore_point')
    return {'progress_cur': pc, 'progress_total': pt, 'restore_point': rp,
            'recovered_hashes_cur': rhc, 'recovered_hashes_total': rht,
            'recovered_salts_cur': rsc, 'recovered_salts_total': rst,
            'events': events, 'status': status.get('status')}
