from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any, Iterable


_WARNED: set[tuple[str, str]] = set()

from nsec3_candidate_scheduler.naming import safe_name


def safe_arm_name(name: str) -> str:
    """Legacy alias; use nsec3_candidate_scheduler.naming.safe_name in new code."""
    return safe_name(name)


class FeedbackQueueState:
    """Per-arm feedback queue and resumable active-slice state."""

    def __init__(self, out_dir: str | Path, arm_name: str, config: dict[str, Any] | None = None) -> None:
        self.out_dir = Path(out_dir)
        self.arm_name = arm_name
        self.config = config or {}
        self.generated_candidates_backend = str(self.config.get('generated_candidates_backend', 'sqlite')).lower()
        if self.generated_candidates_backend not in {'sqlite', 'text', 'none'}:
            raise ValueError(f'unsupported generated_candidates_backend={self.generated_candidates_backend!r}')
        self.retain_generated_candidates_text = bool(self.config.get('retain_generated_candidates_text', False))
        self.sqlite_insert_batch_size = max(1, int(self.config.get('sqlite_insert_batch_size', 10000)))
        self.feedback_disk_warning_bytes = int(self.config.get('feedback_disk_warning_bytes', 104857600))
        self.safe_arm_name = safe_arm_name(arm_name)
        self.root = self.out_dir / 'feedback' / self.safe_arm_name
        self.queue_path = self.root / 'queue.txt'
        self.generated_path = self.root / 'generated_candidates.txt'
        self.generated_sqlite_path = self.root / 'generated_candidates.sqlite'
        self.expanded_path = self.root / 'expanded_bases.txt'
        self.slice_path = self.root / 'slice_candidates.txt'
        self.active_slice_path = self.root / 'active_slice.json'
        self.debug_expansions_path = self.root / 'debug_expansions.jsonl'
        self.root.mkdir(parents=True, exist_ok=True)
        for p in (self.queue_path, self.expanded_path, self.slice_path):
            p.touch(exist_ok=True)
        if self.generated_candidates_backend == 'text' or self.retain_generated_candidates_text:
            self.generated_path.touch(exist_ok=True)
        if not self.active_slice_path.exists():
            self.save_active_slice({'active': False})
        if self.generated_candidates_backend == 'sqlite':
            self._init_generated_sqlite()
            self._import_legacy_generated_candidates_if_needed()
        elif self.generated_candidates_backend == 'none':
            if self._feedback_config_debug_enabled() and (self.generated_path.exists() or self.generated_sqlite_path.exists()):
                self._warn_once('none-legacy', f'[feedback] arm={self.arm_name} generated_candidates_backend=none ignoring_existing_generated_candidate_ledger=true')
        self._log_backend_policy()
        self.warn_large_state_files()

    def _feedback_config_debug_enabled(self) -> bool:
        return any(bool(self.config.get(key, False)) for key in ('verbose', 'debug', 'debug_startup', 'debug_arms', 'debug_feedback', 'config_debug'))

    def _log_backend_policy(self) -> None:
        if not self._feedback_config_debug_enabled():
            return
        backend = self.generated_candidates_backend
        persistent = 'true' if backend != 'none' else 'false'
        if backend == 'sqlite':
            self._warn_once('backend-policy', f'[feedback] arm={self.arm_name} generated_candidates_backend=sqlite persistent_dedupe=true sqlite={self.generated_sqlite_path}')
        elif backend == 'text':
            self._warn_once('backend-policy', f'[feedback] arm={self.arm_name} generated_candidates_backend=text persistent_dedupe=true warning=disk_memory_heavy')
        else:
            self._warn_once('backend-policy', f'[feedback] arm={self.arm_name} generated_candidates_backend=none persistent_dedupe={persistent}')

    def _warn_once(self, key: str, msg: str) -> None:
        marker = (self.safe_arm_name, key)
        if marker not in _WARNED:
            print(msg, flush=True)
            _WARNED.add(marker)

    def warn_large_state_files(self) -> None:
        for path in (self.queue_path, self.slice_path, self.generated_path):
            try:
                size = path.stat().st_size
            except FileNotFoundError:
                continue
            if size <= self.feedback_disk_warning_bytes:
                continue
            backend = f' generated_candidates_backend={self.generated_candidates_backend}' if path.name == 'generated_candidates.txt' else ''
            suffix = '; consider generated_candidates_backend=sqlite' if path.name == 'generated_candidates.txt' else ''
            self._warn_once(f'large:{path.name}', f'[feedback] warning arm={self.arm_name}{backend} file={path.name} size={size} exceeds feedback_disk_warning_bytes={self.feedback_disk_warning_bytes}{suffix}')

    def _connect_generated_sqlite(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.generated_sqlite_path)
        conn.execute('PRAGMA journal_mode=WAL')
        return conn

    def _init_generated_sqlite(self) -> None:
        with self._connect_generated_sqlite() as conn:
            conn.execute('CREATE TABLE IF NOT EXISTS generated_candidates (candidate TEXT PRIMARY KEY)')
            conn.execute('CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT)')
            conn.executemany('INSERT OR REPLACE INTO metadata(key,value) VALUES (?,?)', [
                ('schema_version', '1'), ('arm_name', self.arm_name), ('backend', 'sqlite')])

    def _metadata_get(self, conn: sqlite3.Connection, key: str) -> str | None:
        row = conn.execute('SELECT value FROM metadata WHERE key=?', (key,)).fetchone()
        return None if row is None else str(row[0])

    def _import_legacy_generated_candidates_if_needed(self) -> None:
        if not self.generated_path.exists() or self.generated_path.stat().st_size == 0:
            return
        with self._connect_generated_sqlite() as conn:
            if self._metadata_get(conn, 'imported_generated_candidates_txt') == 'true':
                return
            existing = conn.execute('SELECT COUNT(*) FROM generated_candidates').fetchone()[0]
            if existing:
                return
            print(f'[feedback] importing legacy generated_candidates.txt into sqlite arm={self.arm_name}', flush=True)
            imported = 0
            batch: list[tuple[str]] = []
            with self.generated_path.open('r', encoding='utf-8', errors='replace') as f:
                for raw in f:
                    value = raw.strip()
                    if not value:
                        continue
                    batch.append((value,))
                    if len(batch) >= self.sqlite_insert_batch_size:
                        before = conn.total_changes
                        conn.executemany('INSERT OR IGNORE INTO generated_candidates(candidate) VALUES (?)', batch)
                        imported += conn.total_changes - before
                        batch.clear()
                if batch:
                    before = conn.total_changes
                    conn.executemany('INSERT OR IGNORE INTO generated_candidates(candidate) VALUES (?)', batch)
                    imported += conn.total_changes - before
            conn.execute('INSERT OR REPLACE INTO metadata(key,value) VALUES (?,?)', ('imported_generated_candidates_txt', 'true'))
            print(f'[feedback] imported legacy generated candidates arm={self.arm_name} count={imported}', flush=True)

    def queue_has_items(self) -> bool:
        return bool(self.load_queue())

    def queue_size_lines(self) -> int:
        # TODO: queue.txt is still full-file loaded/re-written for slicing; large queues may need a SQLite queue or append-only cursor design later.
        return len(self.load_queue())

    def _load_lines(self, path: Path) -> list[str]:
        if not path.exists():
            return []
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
        path.parent.mkdir(parents=True, exist_ok=True)
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
        if self.generated_candidates_backend == 'none':
            return set()
        if self.generated_candidates_backend == 'sqlite':
            with self._connect_generated_sqlite() as conn:
                return {str(row[0]) for row in conn.execute('SELECT candidate FROM generated_candidates')}
        return self._load_set(self.generated_path)

    def append_generated_candidates(self, items: Iterable[str]) -> None:
        if self.generated_candidates_backend == 'none':
            return
        if self.generated_candidates_backend == 'sqlite':
            new, _ = self.mark_generated_candidates(items)
            if self.retain_generated_candidates_text:
                self._append_lines(self.generated_path, new)
            return
        self._append_lines(self.generated_path, items)

    def _generated_dedupe_stats(self, candidates_seen: int) -> dict[str, Any]:
        return {
            'generated_candidates_backend': self.generated_candidates_backend,
            'persistent_generated_dedupe': self.generated_candidates_backend != 'none',
            'candidates_seen': candidates_seen,
            'candidates_new': 0,
            'candidates_skipped_generated_duplicate': 0,
            'candidates_skipped_batch_duplicate': 0,
            'candidates_skipped_queue_duplicate': 0,
            'candidates_skipped_active_slice_duplicate': 0,
            'candidates_skipped_already_cracked': 0,
        }

    def mark_generated_candidates(self, candidates: Iterable[str], *, already_cracked: Iterable[str] | None = None) -> tuple[list[str], dict[str, Any]]:
        values = [str(c) for c in candidates if str(c)]
        stats = self._generated_dedupe_stats(len(values))
        cracked = {str(c) for c in already_cracked or [] if str(c)}
        seen_batch: set[str] = set()
        ordered: list[str] = []
        for value in values:
            if value in seen_batch:
                stats['candidates_skipped_batch_duplicate'] += 1
                continue
            seen_batch.add(value)
            if value in cracked:
                stats['candidates_skipped_already_cracked'] += 1
                continue
            ordered.append(value)
        if self.generated_candidates_backend == 'none':
            stats['candidates_new'] = len(ordered)
            return ordered, stats
        if self.generated_candidates_backend == 'text':
            generated = self.load_generated_candidates()
            new = [v for v in ordered if v not in generated]
            stats['candidates_new'] = len(new)
            stats['candidates_skipped_generated_duplicate'] += len(ordered) - len(new)
            self.append_generated_candidates(new)
            return new, stats
        new: list[str] = []
        with self._connect_generated_sqlite() as conn:
            for i in range(0, len(ordered), self.sqlite_insert_batch_size):
                for value in ordered[i:i + self.sqlite_insert_batch_size]:
                    cur = conn.execute('INSERT OR IGNORE INTO generated_candidates(candidate) VALUES (?)', (value,))
                    if cur.rowcount == 1:
                        new.append(value)
                    else:
                        stats['candidates_skipped_generated_duplicate'] += 1
        stats['candidates_new'] = len(new)
        return new, stats

    def load_queue_candidates_set(self) -> set[str]:
        # TODO: Queue dedupe currently loads queue.txt for membership checks; very large queues may need a SQLite-backed queue or compact membership index later.
        return set(self.load_queue())

    def load_active_slice_candidates_set(self) -> set[str]:
        if not self.active_slice_is_active():
            return set()
        return self._load_set(self.slice_path)

    def enqueue_generated_candidates(self, candidates: Iterable[str], *, already_cracked: Iterable[str] | None = None) -> dict[str, Any]:
        values = [str(c) for c in candidates if str(c)]
        stats = self._generated_dedupe_stats(len(values))
        cracked = {str(c) for c in already_cracked or [] if str(c)}
        queued = self.load_queue_candidates_set()
        active = self.load_active_slice_candidates_set()
        seen_batch: set[str] = set()
        operational_new: list[str] = []
        for value in values:
            if value in seen_batch:
                stats['candidates_skipped_batch_duplicate'] += 1
                continue
            seen_batch.add(value)
            if value in cracked:
                stats['candidates_skipped_already_cracked'] += 1
                continue
            if value in queued:
                stats['candidates_skipped_queue_duplicate'] += 1
                continue
            if value in active:
                stats['candidates_skipped_active_slice_duplicate'] += 1
                continue
            operational_new.append(value)
            queued.add(value)

        new, persistent_stats = self.mark_generated_candidates(operational_new)
        stats['candidates_new'] = persistent_stats['candidates_new']
        stats['candidates_skipped_generated_duplicate'] = persistent_stats['candidates_skipped_generated_duplicate']
        # mark_generated_candidates should not see these after operational filtering, but merge defensively.
        stats['candidates_skipped_batch_duplicate'] += persistent_stats['candidates_skipped_batch_duplicate']
        stats['candidates_skipped_already_cracked'] += persistent_stats['candidates_skipped_already_cracked']
        enqueued = self._append_lines(self.queue_path, new)
        if self.generated_candidates_backend == 'sqlite' and self.retain_generated_candidates_text:
            self._append_lines(self.generated_path, new)
        stats['candidates_enqueued'] = enqueued
        stats['candidates_enqueued_total'] = enqueued
        return stats

    def append_candidates(self, candidates: Iterable[str]) -> int:
        return int(self.enqueue_generated_candidates(candidates)['candidates_enqueued'])

    def generated_candidates_count(self) -> int | None:
        if self.generated_candidates_backend == 'sqlite':
            with self._connect_generated_sqlite() as conn:
                return int(conn.execute('SELECT COUNT(*) FROM generated_candidates').fetchone()[0])
        if self.generated_candidates_backend == 'text':
            return sum(1 for _ in self.generated_path.open('r', encoding='utf-8', errors='replace')) if self.generated_path.exists() else 0
        return None

    def load_expanded_bases(self) -> set[str]:
        return self._load_set(self.expanded_path)

    def append_expanded_bases(self, items: Iterable[str]) -> None:
        self._append_lines(self.expanded_path, items)

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
