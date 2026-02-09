from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path


class AgentStateStore:
    def __init__(self, root: Path) -> None:
        self.db_path = root / "events" / "state.db"
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS processed_event (
                    event_id TEXT PRIMARY KEY,
                    idempotency_key TEXT NOT NULL,
                    processed_at TEXT NOT NULL
                )
                """
            )
            conn.commit()

    def seen(self, event_id: str) -> bool:
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute("SELECT 1 FROM processed_event WHERE event_id = ?", (event_id,)).fetchone()
            return row is not None

    def mark(self, event_id: str, idempotency_key: str) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO processed_event(event_id, idempotency_key, processed_at)
                VALUES (?, ?, ?)
                """,
                (event_id, idempotency_key, datetime.now(timezone.utc).isoformat()),
            )
            conn.commit()
