"""Append-only JSONL event ledger used as fixture ground truth."""
from __future__ import annotations

import json
import fcntl
import threading
import time
from typing import Any

from settings import EVENTS_FILE

_lock = threading.Lock()


def record_event(run_id: str, event_type: str, **fields: Any) -> dict[str, Any]:
    event = {
        "timestamp_unix": time.time(),
        "run_id": run_id,
        "event_type": event_type,
        **fields,
    }
    with _lock:
        with EVENTS_FILE.open("a", encoding="utf-8") as stream:
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX)
            try:
                stream.write(json.dumps(event, sort_keys=True, default=str) + "\n")
                stream.flush()
            finally:
                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
    return event


def events_for(run_id: str) -> list[dict[str, Any]]:
    if not EVENTS_FILE.exists():
        return []
    found = []
    with EVENTS_FILE.open(encoding="utf-8") as stream:
        for line in stream:
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            if item.get("run_id") == run_id:
                found.append(item)
    return found
