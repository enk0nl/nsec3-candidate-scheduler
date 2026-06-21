from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Iterable


def safe_arm_name(name: str) -> str:
    safe = re.sub(r'[^A-Za-z0-9._-]+', '-', str(name).replace('/', '-').replace('\\', '-'))
    safe = re.sub(r'-+', '-', safe).strip('-._')
    return safe or 'arm'


class FeedbackQueueState:
    """Per-arm feedback queue and resumable active-slice state."""

    def __init__(self, out_dir: str | Path, arm_name: str) -> None:
        self.out_dir = Path(out_dir)
        self.arm_name = arm_name
        self.safe_arm_name = safe_arm_name(arm_name)
        self.root = self.out_dir / 'feedback' / self.safe_arm_name
        self.queue_path = self.root / 'queue.txt'
        self.generated_path = self.root / 'generated_candidates.txt'
        self.expanded_path = self.root / 'expanded_bases.txt'
        self.slice_path = self.root / 'slice_candidates.txt'
        self.active_slice_path = self.root / 'active_slice.json'
        self.debug_expansions_path = self.root / 'debug_expansions.jsonl'
        self.root.mkdir(parents=True, exist_ok=True)
        for p in (self.queue_path, self.generated_path, self.expanded_path, self.slice_path, self.debug_expansions_path):
            p.touch(exist_ok=True)
        if not self.active_slice_path.exists():
            self.save_active_slice({'active': False})

    def queue_has_items(self) -> bool:
        return bool(self.load_queue())

    def queue_size_lines(self) -> int:
        return len(self.load_queue())

    def _load_lines(self, path: Path) -> list[str]:
        with path.open('r', encoding='utf-8', errors='replace') as f:
            return [line.rstrip('\n') for line in f if line.rstrip('\n')]

    def _load_set(self, path: Path) -> set[str]:
        return set(self._load_lines(path))

    def _write_lines(self, path: Path, items: Iterable[str]) -> None:
        values = [str(i) for i in items if str(i)]
        with path.open('w', encoding='utf-8') as f:
            for value in values:
                f.write(f'{value}\n')

    def _append_lines(self, path: Path, items: Iterable[str]) -> int:
        values = [str(i) for i in items if str(i)]
        if not values:
            return 0
        with path.open('a', encoding='utf-8') as f:
            for value in values:
                f.write(f'{value}\n')
        return len(values)

    def load_queue(self) -> list[str]:
        return self._load_lines(self.queue_path)

    def write_queue(self, items: Iterable[str]) -> None:
        self._write_lines(self.queue_path, items)

    def append_to_queue(self, items: Iterable[str]) -> None:
        self._append_lines(self.queue_path, items)

    def load_generated_candidates(self) -> set[str]:
        return self._load_set(self.generated_path)

    def append_generated_candidates(self, items: Iterable[str]) -> None:
        self._append_lines(self.generated_path, items)

    def load_expanded_bases(self) -> set[str]:
        return self._load_set(self.expanded_path)

    def append_expanded_bases(self, items: Iterable[str]) -> None:
        self._append_lines(self.expanded_path, items)

    def append_candidates(self, candidates: Iterable[str]) -> int:
        values = list(candidates)
        self.append_to_queue(values)
        self.append_generated_candidates(values)
        return len(values)

    def mark_bases_expanded(self, bases: Iterable[str]) -> int:
        values = list(bases)
        self.append_expanded_bases(values)
        return len(values)

    def load_active_slice(self) -> dict:
        try:
            data = json.loads(self.active_slice_path.read_text(encoding='utf-8'))
        except (OSError, json.JSONDecodeError):
            data = {'active': False}
        return data if isinstance(data, dict) else {'active': False}

    def save_active_slice(self, state: dict) -> None:
        tmp = self.active_slice_path.with_suffix(self.active_slice_path.suffix + '.tmp')
        tmp.write_text(json.dumps(state, separators=(',', ':')) + '\n', encoding='utf-8')
        tmp.replace(self.active_slice_path)

    def active_slice_is_active(self) -> bool:
        return bool(self.load_active_slice().get('active'))

    def clear_active_slice(self) -> None:
        try:
            self.slice_path.unlink()
        except FileNotFoundError:
            pass
        self.slice_path.touch(exist_ok=True)
        self.save_active_slice({'active': False})

    def update_active_slice_skip(self, skip: int) -> dict:
        state = self.load_active_slice()
        if state.get('active'):
            state['skip'] = max(0, int(skip))
            self.save_active_slice(state)
        return state

    def prepare_active_slice(self, max_candidates: int | None = None) -> dict:
        active = self.load_active_slice()
        if bool(active.get('active')):
            return active
        queue = self.load_queue()
        if not queue:
            self.save_active_slice({'active': False})
            return {'active': False, 'reason': 'empty_queue'}
        n = len(queue) if max_candidates is None else max(0, min(int(max_candidates), len(queue)))
        if n <= 0:
            return {'active': False, 'reason': 'empty_queue'}
        selected = queue[:n]
        self._write_lines(self.slice_path, selected)
        self.write_queue(queue[n:])
        active = {'active': True, 'slice_file': self.slice_path.name, 'total_candidates': len(selected), 'skip': 0}
        self.save_active_slice(active)
        return active
