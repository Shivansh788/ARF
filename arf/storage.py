from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path
from typing import Any


class RunStore:
    def __init__(self, path: str | Path = "arf.db") -> None:
        self.path = str(path)
        if self.path != ":memory:":
            database_path = Path(self.path)
            database_path.parent.mkdir(parents=True, exist_ok=True)
            database_path.touch(mode=0o600, exist_ok=True)
            os.chmod(database_path, 0o600)
        with sqlite3.connect(self.path) as connection:
            connection.execute("CREATE TABLE IF NOT EXISTS runs (id TEXT PRIMARY KEY, probe_id TEXT, verdict TEXT, result_json TEXT NOT NULL)")
            connection.execute("PRAGMA journal_mode=WAL")

    def save(self, run_id: str, probe_id: str, result: dict[str, Any]) -> None:
        with sqlite3.connect(self.path) as connection:
            connection.execute("INSERT OR REPLACE INTO runs VALUES (?, ?, ?, ?)", (run_id, probe_id, result["result"], json.dumps(result)))

    def list(self) -> list[dict[str, Any]]:
        with sqlite3.connect(self.path) as connection:
            rows = connection.execute("SELECT id, probe_id, verdict, result_json FROM runs ORDER BY rowid DESC").fetchall()
        return [{"id": row[0], "probe_id": row[1], "verdict": row[2], "result": json.loads(row[3])} for row in rows]
