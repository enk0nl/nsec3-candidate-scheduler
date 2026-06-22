from __future__ import annotations

import re


def safe_name(name: str) -> str:
    """Return a filesystem-safe representation of a configured arm name."""
    value = str(name).replace('/', '-').replace('\\', '-')
    value = value.replace('..', '-')
    value = re.sub(r'[^A-Za-z0-9._-]+', '-', value)
    value = re.sub(r'-+', '-', value).strip('-._')
    return value or 'arm'


def arm_family(name: str) -> str | None:
    parts = str(name).split('/', 1)
    return parts[0] if len(parts) == 2 and parts[0] else None


def arm_short_name(name: str) -> str:
    parts = str(name).split('/', 1)
    return parts[1] if len(parts) == 2 and parts[1] else str(name)
