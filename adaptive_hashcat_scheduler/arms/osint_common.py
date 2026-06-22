from __future__ import annotations

from typing import Any

from adaptive_hashcat_scheduler.feedback.normalize import normalize_dns_name


def normalize_osint_domain(value: str) -> str | None:
    return normalize_dns_name(value) if value is not None else None


def parse_osint_domains(value: Any) -> tuple[list[str], str]:
    if isinstance(value, str):
        raw = value.split(',')
    elif isinstance(value, list):
        raw = value
    else:
        raw = []
    domains: list[str] = []
    for item in raw:
        d = normalize_osint_domain(str(item)) if item is not None else None
        if d and d not in domains:
            domains.append(d)
    return domains, ','.join(domains)


def strip_base_domain(full_name: str, base_domains: list[str]) -> tuple[str, str] | None:
    name = normalize_dns_name(full_name)
    if not name:
        return None
    bases = sorted([d.rstrip('.').lower() for d in base_domains if d], key=len, reverse=True)
    for base in bases:
        if name == base:
            return None
        if name.endswith('.' + base):
            cand = normalize_dns_name(name[:-(len(base) + 1)])
            if cand:
                return cand, base
    return None


def extract_relative_osint_candidates(raw_names: list[str], base_domains: list[str], *,
                                      include_single_label: bool = True,
                                      include_multi_label: bool = True,
                                      dedupe: bool = True,
                                      max_candidates: int | None = None) -> tuple[list[str], dict[str, int]]:
    bases = sorted([d.rstrip('.').lower() for d in base_domains if d], key=len, reverse=True)
    seen: set[str] = set()
    out: list[str] = []
    by_domain = {d: 0 for d in bases}
    for raw in raw_names:
        stripped = strip_base_domain(raw, bases)
        if stripped is None:
            continue
        cand, matched = stripped
        labels = cand.count('.') + 1
        if labels == 1 and not include_single_label:
            continue
        if labels > 1 and not include_multi_label:
            continue
        if dedupe and cand in seen:
            continue
        seen.add(cand)
        out.append(cand)
        by_domain[matched] = by_domain.get(matched, 0) + 1
        if max_candidates is not None and len(out) >= int(max_candidates):
            break
    return out, by_domain
