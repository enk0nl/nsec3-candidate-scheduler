from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Iterable, TextIO
import re
import sys

from adaptive_hashcat_scheduler.feedback.normalize import normalize_dns_name

_LABEL_RE = re.compile(r'^[a-z0-9_-]+$')


def name_from_line(line: str, input_format: str) -> str | None:
    line = line.strip()
    if not line:
        return None
    if input_format == 'potfile' or (input_format == 'auto' and ':' in line):
        if ':' not in line:
            return None
        return line.rsplit(':', 1)[1]
    return line


def normalize_affix_source(value: str) -> str | None:
    name = normalize_dns_name(value)
    if name is None:
        return None
    labels = name.split('.')
    if any(_LABEL_RE.fullmatch(label) is None for label in labels):
        return None
    return name


def is_feedback_affix_label(label: str, *, allow_numeric: bool = False, allow_underscore: bool = True) -> bool:
    if not label or len(label) > 63:
        return False
    if label.startswith('-') or label.endswith('-'):
        return False
    if '.' in label or any(ch.isspace() for ch in label):
        return False
    if not allow_numeric and label.isdigit():
        return False
    allowed = r'a-z0-9_-' if allow_underscore else r'a-z0-9-'
    return re.fullmatch(f'[{allowed}]+', label) is not None


def mine_common_affixes(
    path: str,
    input_format: str = 'auto',
    *,
    top_n: int = 50,
    min_count: int = 1,
    include_single_labels: bool = False,
    allow_numeric_affixes: bool = False,
    allow_underscore_affixes: bool = True,
) -> tuple[list[tuple[str, int]], list[tuple[str, int]], dict[str, int]]:
    prefix_counts: Counter[str] = Counter()
    suffix_counts: Counter[str] = Counter()
    stats = {
        'input_count': 0,
        'normalized_names_used': 0,
        'skipped_names': 0,
        'adjacent_pairs': 0,
        'rejected_prefix_labels': 0,
        'rejected_suffix_labels': 0,
    }
    with Path(path).open('r', encoding='utf-8', errors='replace') as f:
        for raw in f:
            if not raw.strip():
                continue
            stats['input_count'] += 1
            name = normalize_affix_source(name_from_line(raw, input_format) or '')
            if name is None:
                stats['skipped_names'] += 1
                continue
            labels = name.split('.')
            if len(labels) < 2 and not include_single_labels:
                stats['skipped_names'] += 1
                continue
            stats['normalized_names_used'] += 1
            for left, right in zip(labels, labels[1:]):
                stats['adjacent_pairs'] += 1
                if is_feedback_affix_label(left, allow_numeric=allow_numeric_affixes, allow_underscore=allow_underscore_affixes):
                    prefix_counts[left] += 1
                else:
                    stats['rejected_prefix_labels'] += 1
                if is_feedback_affix_label(right, allow_numeric=allow_numeric_affixes, allow_underscore=allow_underscore_affixes):
                    suffix_counts[right] += 1
                else:
                    stats['rejected_suffix_labels'] += 1

    def top(counter: Counter[str]) -> list[tuple[str, int]]:
        return [(label, count) for label, count in sorted(counter.items(), key=lambda x: (-x[1], x[0])) if count >= min_count][:top_n]

    return top(prefix_counts), top(suffix_counts), stats


def write_affix_list(items: Iterable[tuple[str, int]], path: str, *, labels_only: bool = False) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open('w', encoding='utf-8') as f:
        for label, count in items:
            f.write(f'{label}\n' if labels_only else f'{label}\t{count}\n')


def mine_to_files(args, stderr: TextIO = sys.stderr) -> None:
    prefixes, suffixes, stats = mine_common_affixes(
        args.potfile,
        args.input_format,
        top_n=args.top_n,
        min_count=args.min_count,
        include_single_labels=args.include_single_labels,
        allow_numeric_affixes=args.allow_numeric_affixes,
        allow_underscore_affixes=args.allow_underscore_affixes,
    )
    write_affix_list(prefixes, args.output_prefixes, labels_only=args.labels_only)
    write_affix_list(suffixes, args.output_suffixes, labels_only=args.labels_only)
    stats['prefixes_written'] = len(prefixes)
    stats['suffixes_written'] = len(suffixes)
    for key in sorted(stats):
        print(f'{key}: {stats[key]}', file=stderr)
    print(f'output_prefixes: {args.output_prefixes}', file=stderr)
    print(f'output_suffixes: {args.output_suffixes}', file=stderr)
