from __future__ import annotations

from pathlib import Path
from typing import Iterable


class FeedbackQueueState:
    """Text-file feedback queue state. V1 drains the full queue per slice, so partial feedback-slice resume is limited."""

    def __init__(self, out_dir: str, arm_name: str) -> None:
        self.out_dir = Path(out_dir)
        safe = arm_name.replace('/', '_')
        self.queue_path = self.out_dir / f'{safe}_queue.txt'
        self.seen_path = self.out_dir / f'{safe}_seen_candidates.txt'
        self.expanded_path = self.out_dir / f'{safe}_expanded_bases.txt'
        self.slice_path = self.out_dir / f'{safe}_slice_candidates.txt'
        self.out_dir.mkdir(parents=True, exist_ok=True)
        for p in (self.queue_path, self.seen_path, self.expanded_path, self.slice_path):
            p.touch(exist_ok=True)

    def queue_has_items(self) -> bool:
        with self.queue_path.open('r', encoding='utf-8', errors='replace') as f:
            return any(line.strip() for line in f)

    def queue_size_lines(self) -> int:
        with self.queue_path.open('rb') as f:
            return sum(1 for _ in f)

    def _load_set(self, path: Path) -> set[str]:
        with path.open('r', encoding='utf-8', errors='replace') as f:
            return {line.rstrip('\n') for line in f if line.rstrip('\n')}

    def load_seen_candidates(self) -> set[str]:
        return self._load_set(self.seen_path)

    def load_expanded_bases(self) -> set[str]:
        return self._load_set(self.expanded_path)

    def _append_lines(self, path: Path, lines: Iterable[str]) -> int:
        items = list(lines)
        if not items:
            return 0
        with path.open('a', encoding='utf-8') as f:
            for line in items:
                f.write(f'{line}\n')
        return len(items)

    def append_candidates(self, candidates: Iterable[str]) -> int:
        items = list(candidates)
        self._append_lines(self.queue_path, items)
        self._append_lines(self.seen_path, items)
        return len(items)

    def mark_bases_expanded(self, bases: Iterable[str]) -> int:
        return self._append_lines(self.expanded_path, bases)

    def move_queue_to_slice_file(self) -> tuple[str, int, int]:
        count = 0
        with self.queue_path.open('r', encoding='utf-8', errors='replace') as src, self.slice_path.open('w', encoding='utf-8') as dst:
            for line in src:
                value = line.strip()
                if value:
                    dst.write(f'{value}\n')
                    count += 1
        self.queue_path.write_text('', encoding='utf-8')
        return str(self.slice_path), count, 0
