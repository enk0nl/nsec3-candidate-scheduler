from __future__ import annotations
import datetime as dt, json
from typing import Any

def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()

def append_jsonl(path: str, record: dict[str, Any]) -> None:
    with open(path, 'a', encoding='utf-8') as f:
        f.write(json.dumps(record, separators=(',', ':')) + '\n')
