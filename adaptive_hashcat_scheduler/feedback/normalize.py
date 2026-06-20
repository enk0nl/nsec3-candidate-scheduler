from __future__ import annotations

from typing import Optional


def normalize_dns_name(value: str) -> Optional[str]:
    if not isinstance(value, str):
        return None
    name = value.strip().lower().rstrip('.')
    if not name:
        return None
    if any(ch.isspace() for ch in name):
        return None
    if len(name) > 253:
        return None
    parts = name.split('.')
    if any(part == '' or len(part) > 63 for part in parts):
        return None
    return name


def leftmost_label(name: str) -> Optional[str]:
    normalized = normalize_dns_name(name)
    if normalized is None:
        return None
    return normalized.split('.', 1)[0]
