from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable


class FeedbackQueueState:
    """Text-file feedback queue plus scheduler-owned resumable active-slice state."""

    def __init__(self, out_dir: str, arm_name: str) -> None:
        self.out_dir = Path(out_dir)
        safe = arm_name.replace('/', '_')
        self.queue_path = self.out_dir / f'{safe}_queue.txt'
        self.seen_path = self.out_dir / f'{safe}_seen_candidates.txt'
        self.expanded_path = self.out_dir / f'{safe}_expanded_bases.txt'
        self.slice_path = self.out_dir / f'{safe}_slice_candidates.txt'
        self.active_slice_path = self.out_dir / f'{safe}_active_slice.json'
        self.out_dir.mkdir(parents=True, exist_ok=True)
        for p in (self.queue_path, self.seen_path, self.expanded_path, self.slice_path):
            p.touch(exist_ok=True)
        if not self.active_slice_path.exists():
            self.save_active_slice({'active': False})

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


    def write_queue_to_slice_file(self) -> tuple[str, int, int]:
        count = 0
        with self.queue_path.open('r', encoding='utf-8', errors='replace') as src, self.slice_path.open('w', encoding='utf-8') as dst:
            for line in src:
                value = line.strip()
                if value:
                    dst.write(f'{value}\n')
                    count += 1
        return str(self.slice_path), count, count


    def load_active_slice(self) -> dict:
        try:
            data = json.loads(self.active_slice_path.read_text(encoding='utf-8'))
        except (OSError, json.JSONDecodeError):
            data = {'active': False}
        return data if isinstance(data, dict) else {'active': False}

    def save_active_slice(self, data: dict) -> None:
        tmp = self.active_slice_path.with_suffix(self.active_slice_path.suffix + '.tmp')
        tmp.write_text(json.dumps(data, separators=(',', ':')) + '\n', encoding='utf-8')
        tmp.replace(self.active_slice_path)

    def active_slice_is_active(self) -> bool:
        data = self.load_active_slice()
        return bool(data.get('active'))

    def prepare_active_slice(self) -> dict:
        active = self.load_active_slice()
        if bool(active.get('active')):
            return active
        slice_file, written, _ = self.move_queue_to_slice_file()
        if written <= 0:
            self.save_active_slice({'active': False})
            return {'active': False}
        active = {'active': True, 'slice_file': Path(slice_file).name, 'total_candidates': written, 'skip': 0}
        self.save_active_slice(active)
        return active

    def update_active_slice_skip(self, skip: int) -> dict:
        data = self.load_active_slice()
        if data.get('active'):
            data['skip'] = max(0, int(skip))
            self.save_active_slice(data)
        return data

    def clear_active_slice(self, delete_file: bool = True) -> None:
        data = self.load_active_slice()
        if delete_file and data.get('slice_file'):
            try:
                (self.out_dir / data['slice_file']).unlink()
            except FileNotFoundError:
                pass
        self.save_active_slice({'active': False})

    def discard_queue_prefix(self, count: int) -> int:
        if count <= 0:
            return self.queue_size_lines()
        tmp_path = self.queue_path.with_suffix(self.queue_path.suffix + '.tmp')
        skipped = 0
        with self.queue_path.open('r', encoding='utf-8', errors='replace') as src, tmp_path.open('w', encoding='utf-8') as dst:
            for line in src:
                value = line.strip()
                if not value:
                    continue
                if skipped < count:
                    skipped += 1
                    continue
                dst.write(f'{value}\n')
        tmp_path.replace(self.queue_path)
        return self.queue_size_lines()

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
