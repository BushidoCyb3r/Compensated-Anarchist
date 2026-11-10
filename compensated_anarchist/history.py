"""Persistent chat history - kept until the analyst deletes it.

A conversation belongs to a case and holds:
  events        the operation feed the analyst saw (messages, lead reports, subagent tasking/reports, tool
                decisions, approvals), replayed by the dashboard and the CLI when a conversation is resumed
  agent_states  the model context of the orchestrator and of every subagent, so a resumed conversation picks
                up where it left off and the orchestrator can still follow up with an earlier subagent

Nothing expires. Deleting a conversation removes its events, agent states and transcripts. The case record
(findings, IOCs, timeline, evidence), the hash-chained audit log, and the memories/skills learned from it are
kept: they are the case file and the accountability record, not chat. The deletion itself is audited.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_SCHEMA = """
CREATE TABLE IF NOT EXISTS conversations (
  id TEXT PRIMARY KEY, case_id TEXT NOT NULL, title TEXT NOT NULL DEFAULT '',
  created TEXT NOT NULL, updated TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS conv_case ON conversations(case_id, updated);
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT, conversation_id TEXT NOT NULL, session TEXT NOT NULL,
  ts REAL NOT NULL, kind TEXT NOT NULL, data TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ev_conv ON events(conversation_id, id);
CREATE TABLE IF NOT EXISTS agent_states (
  conversation_id TEXT NOT NULL, agent_key TEXT NOT NULL, state TEXT NOT NULL, updated TEXT NOT NULL,
  PRIMARY KEY (conversation_id, agent_key)
);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class ChatStore:
    def __init__(self, db_path: Path):
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self.path = db_path
        self.db = sqlite3.connect(db_path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.execute("PRAGMA secure_delete=ON")  # deleted chat is overwritten, not left in free pages
        self.db.executescript(_SCHEMA)
        self._lock = threading.Lock()

    # ---- conversations -----------------------------------------------------------
    def create(self, case_id: str, title: str = "") -> dict[str, Any]:
        cid = "conv-" + datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:6]
        with self._lock:
            self.db.execute("INSERT INTO conversations(id, case_id, title, created, updated) VALUES (?,?,?,?,?)",
                            (cid, case_id, title[:200], _now(), _now()))
            self.db.commit()
        return self.get(cid)  # type: ignore[return-value]

    def get(self, conv_id: str) -> dict[str, Any] | None:
        with self._lock:
            r = self.db.execute("SELECT c.*, (SELECT count(*) FROM events e WHERE e.conversation_id=c.id) AS events "
                                "FROM conversations c WHERE id=?", (conv_id,)).fetchone()
        return dict(r) if r else None

    def latest(self, case_id: str) -> dict[str, Any] | None:
        rows = self.list(case_id, 1)
        return rows[0] if rows else None

    def list(self, case_id: str | None = None, limit: int = 200) -> list[dict[str, Any]]:
        sql = ("SELECT c.*, (SELECT count(*) FROM events e WHERE e.conversation_id=c.id) AS events FROM conversations c"
               + (" WHERE case_id=?" if case_id else "") + " ORDER BY updated DESC LIMIT ?")
        with self._lock:
            return [dict(r) for r in self.db.execute(sql, ((case_id,) if case_id else ()) + (limit,)).fetchall()]

    def rename(self, conv_id: str, title: str) -> bool:
        with self._lock:
            n = self.db.execute("UPDATE conversations SET title=? WHERE id=?", (title[:200], conv_id)).rowcount
            self.db.commit()
        return bool(n)

    def delete(self, conv_id: str) -> bool:
        with self._lock:
            n = self.db.execute("DELETE FROM conversations WHERE id=?", (conv_id,)).rowcount
            self.db.execute("DELETE FROM events WHERE conversation_id=?", (conv_id,))
            self.db.execute("DELETE FROM agent_states WHERE conversation_id=?", (conv_id,))
            self.db.commit()
        return bool(n)

    # ---- events (the feed) ---------------------------------------------------------
    def append(self, conv_id: str, session: str, kind: str, data: dict[str, Any], ts: float) -> int:
        with self._lock:
            cur = self.db.execute("INSERT INTO events(conversation_id, session, ts, kind, data) VALUES (?,?,?,?,?)",
                                  (conv_id, session, ts, kind, json.dumps(data, default=str)))
            self.db.execute("UPDATE conversations SET updated=? WHERE id=?", (_now(), conv_id))
            self.db.commit()
            return int(cur.lastrowid)

    def events(self, conv_id: str, limit: int | None = None) -> list[dict[str, Any]]:
        """Oldest first; with `limit`, the most recent `limit` events."""
        sql = "SELECT * FROM events WHERE conversation_id=? ORDER BY id DESC" + (" LIMIT ?" if limit else "")
        with self._lock:
            rows = self.db.execute(sql, (conv_id, limit) if limit else (conv_id,)).fetchall()
        return [{"id": r["id"], "session": r["session"], "ts": r["ts"], "kind": r["kind"], "data": json.loads(r["data"])}
                for r in reversed(rows)]

    def count(self, conv_id: str) -> int:
        with self._lock:
            return int(self.db.execute("SELECT count(*) FROM events WHERE conversation_id=?", (conv_id,)).fetchone()[0])

    # ---- agent states (model context) --------------------------------------------------
    def save_agent(self, conv_id: str, key: str, state: dict[str, Any]) -> None:
        with self._lock:
            self.db.execute("INSERT INTO agent_states(conversation_id, agent_key, state, updated) VALUES (?,?,?,?) "
                            "ON CONFLICT(conversation_id, agent_key) DO UPDATE SET state=excluded.state, updated=excluded.updated",
                            (conv_id, key, json.dumps(state, default=str), _now()))
            self.db.commit()

    def load_agents(self, conv_id: str) -> dict[str, dict[str, Any]]:
        with self._lock:
            rows = self.db.execute("SELECT agent_key, state FROM agent_states WHERE conversation_id=?", (conv_id,)).fetchall()
        return {r["agent_key"]: json.loads(r["state"]) for r in rows}
