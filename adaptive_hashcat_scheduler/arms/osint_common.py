from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Iterable

from adaptive_hashcat_scheduler.feedback.normalize import normalize_dns_name


def normalize_osint_domain(value: str) -> str:
    return (normalize_dns_name(str(value)) or '').rstrip('.').lower()


def parse_osint_domains(value: Any) -> tuple[list[str], str]:
    if isinstance(value, str):
        raw = value.split(',')
    elif isinstance(value, list):
        raw = value
    else:
        raw = []
    domains: list[str] = []
    for item in raw:
        d = normalize_osint_domain(str(item)) if item is not None else ''
        if d and d not in domains:
            domains.append(d)
    return domains, ','.join(domains)


def strip_base_domain(full_name: str, base_domains: list[str]) -> tuple[str | None, str | None]:
    name = normalize_osint_domain(full_name)
    if not name:
        return None, None
    bases = sorted([normalize_osint_domain(d) for d in base_domains if normalize_osint_domain(d)], key=len, reverse=True)
    for base in bases:
        if name == base:
            return None, base
        suffix = '.' + base
        if name.endswith(suffix):
            candidate = name[:-len(suffix)]
            candidate = normalize_dns_name(candidate)
            return (candidate, base) if candidate else (None, base)
    return None, None


@dataclass
class OsintExtractionOptions:
    include_single_label: bool = True
    include_multi_label: bool = True
    dedupe: bool = True
    max_candidates: int | None = None


def extract_relative_osint_candidates(raw_names: Iterable[str], base_domains: list[str], options: OsintExtractionOptions | None = None) -> tuple[list[str], dict[str, int]]:
    options = options or OsintExtractionOptions()
    bases = sorted([normalize_osint_domain(d) for d in base_domains if normalize_osint_domain(d)], key=len, reverse=True)
    seen: set[str] = set()
    out: list[str] = []
    by_domain = {d: 0 for d in bases}
    for raw in raw_names:
        cand, matched = strip_base_domain(raw, bases)
        if not cand or not matched:
            continue
        labels = cand.count('.') + 1
        if labels == 1 and not options.include_single_label:
            continue
        if labels > 1 and not options.include_multi_label:
            continue
        if options.dedupe and cand in seen:
            continue
        seen.add(cand)
        out.append(cand)
        by_domain[matched] = by_domain.get(matched, 0) + 1
        if options.max_candidates is not None and len(out) >= int(options.max_candidates):
            break
    return out, by_domain
