from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any

@dataclass
class SliceResult:
    exit_code: int = 0
    runtime_seconds: float = 0.0
    stdout: str = ''
    stderr: str = ''
    skip_before: int = 0
    next_skip_after: int = 0
    progress_source: str = 'unknown'
    dictionary_candidate_cursor: int | None = None
    exhausted: bool = False
    executed: bool = True
    valid_work: bool = True
    execution_status: str = 'executed'
    extra: dict[str, Any] = field(default_factory=dict)

@dataclass
class Arm:
    name: str
    type: str
    config: dict[str, Any]
    score: float = 0.0
    runs: int = 0
    total_runtime: float = 0.0
    exhausted: bool = False
    last_run_adaptive_slice: int = 0
    last_run_global_slice: int | None = None
    total_new_cracks: int = 0
    next_skip: int = 0
    keyspace: int | None = None
    warmup_eligible: bool = True

    def is_available(self, context: Any) -> bool:
        return not self.exhausted
    def run_slice(self, context: Any) -> SliceResult:
        raise NotImplementedError
    def on_new_discoveries(self, discoveries, context: Any) -> dict[str, Any]:
        return {}
