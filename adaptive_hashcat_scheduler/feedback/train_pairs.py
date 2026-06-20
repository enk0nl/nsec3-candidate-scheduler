from __future__ import annotations

from collections import Counter, defaultdict
from pathlib import Path
from typing import DefaultDict, Iterable, TextIO
import sys

from adaptive_hashcat_scheduler.feedback.normalize import normalize_dns_name

Counts = DefaultDict[str, Counter[str]]


def _name_from_line(line: str, input_format: str) -> str | None:
    line = line.strip()
    if not line:
        return None
    if input_format == 'potfile' or (input_format == 'auto' and ':' in line):
        if ':' not in line:
            return None
        return line.rsplit(':', 1)[1]
    return line


def train_directional_pairs(path: str, input_format: str = 'auto') -> tuple[Counts, Counts, dict[str, int]]:
    prefix_counts: Counts = defaultdict(Counter)
    suffix_counts: Counts = defaultdict(Counter)
    stats = {'input_count': 0, 'normalized_names_used': 0, 'skipped_names': 0, 'prefix_total_pairs': 0, 'suffix_total_pairs': 0}
    with Path(path).open('r', encoding='utf-8', errors='replace') as f:
        for raw in f:
            if not raw.strip():
                continue
            stats['input_count'] += 1
            name = normalize_dns_name(_name_from_line(raw, input_format) or '')
            if name is None:
                stats['skipped_names'] += 1
                continue
            labels = name.split('.')
            if len(labels) < 2:
                stats['skipped_names'] += 1
                continue
            stats['normalized_names_used'] += 1
            for i in range(len(labels) - 1):
                left, right = labels[i], labels[i + 1]
                prefix_counts[right][left] += 1
                suffix_counts[left][right] += 1
                stats['prefix_total_pairs'] += 1
                stats['suffix_total_pairs'] += 1
    return prefix_counts, suffix_counts, stats


def write_counts_tsv(counts: Counts, path: str) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open('w', encoding='utf-8') as f:
        for source in sorted(counts):
            for prediction, count in sorted(counts[source].items(), key=lambda x: (-x[1], x[0])):
                f.write(f'{source}\t{prediction}\t{count}\n')


def train_to_files(input_path: str, input_format: str, prefix_model: str, suffix_model: str, stderr: TextIO = sys.stderr) -> None:
    prefix, suffix, stats = train_directional_pairs(input_path, input_format)
    write_counts_tsv(prefix, prefix_model)
    write_counts_tsv(suffix, suffix_model)
    stats['prefix_unique_sources'] = len(prefix)
    stats['suffix_unique_sources'] = len(suffix)
    for k in ['input_count','normalized_names_used','skipped_names','prefix_unique_sources','suffix_unique_sources','prefix_total_pairs','suffix_total_pairs']:
        print(f'{k}: {stats[k]}', file=stderr)
    print(f'output_prefix_model: {prefix_model}', file=stderr)
    print(f'output_suffix_model: {suffix_model}', file=stderr)
