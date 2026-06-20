from __future__ import annotations

from pathlib import Path
from typing import Iterator, Tuple

from adaptive_hashcat_scheduler.feedback.normalize import normalize_dns_name


def iter_potfile_cracks(path) -> Iterator[Tuple[str, str]]:
    with Path(path).open('r', encoding='utf-8', errors='replace') as f:
        for raw in f:
            line = raw.rstrip('\n')
            if not line or ':' not in line:
                continue
            hash_part, value = line.rsplit(':', 1)
            normalized = normalize_dns_name(value)
            if normalized is None:
                continue
            yield hash_part, normalized


def iter_name_file(path) -> Iterator[str]:
    with Path(path).open('r', encoding='utf-8', errors='replace') as f:
        for raw in f:
            normalized = normalize_dns_name(raw)
            if normalized is not None:
                yield normalized
