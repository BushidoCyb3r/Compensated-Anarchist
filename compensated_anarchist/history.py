"""Persistent chat history - kept until the analyst deletes it.

A conversation belongs to a case and holds:
  events        the operation feed the analyst saw (messages, lead reports, subagent tasking/reports, tool
                decisions, approvals), replayed by the dashboard and the CLI when a conversation is resumed
  agent_states  the model context of the orchestrator and of every subagent, so a resumed conversation picks
                up where it left off and the orchestrator can still follow up with an earlier subagent. They are
                checkpointed after every step, so an operation cut off by a restart can be resumed
  operations    each operation run in the conversation (a mission, a resume, an after-action review) and how it
                ended: done, stopped, failed, or interrupted by a restart (then it can be resumed or ended)
  approvals     every approval an agent asked for, and its outcome. One still waiting when the dashboard stopped
                is offered again after the restart; deciding it then applies when the operation resumes

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
CREATE TABLE IF NOT EXISTS operations (
  id TEXT PRIMARY KEY, conversation_id TEXT NOT NULL, kind TEXT NOT NULL, label TEXT NOT NULL DEFAULT '',
  playbook TEXT NOT NULL DEFAULT '', status TEXT NOT NULL, pid INTEGER NOT NULL DEFAULT 0, started REAL NOT NULL,
  ended REAL, note TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS op_conv ON operations(conversation_id, started);
CREATE TABLE IF NOT EXISTS approvals (
  id TEXT PRIMARY KEY, conversation_id TEXT NOT NULL, operation_id TEXT NOT NULL DEFAULT '',
  agent_id TEXT NOT NULL DEFAULT '', call_key TEXT NOT NULL DEFAULT '', tool TEXT NOT NULL, arguments TEXT NOT NULL,
  rationale TEXT NOT NULL DEFAULT '', why TEXT NOT NULL DEFAULT '', requested REAL NOT NULL, status TEXT NOT NULL,
  note TEXT NOT NULL DEFAULT '', decided_by TEXT NOT NULL DEFAULT '', decided REAL
);
CREATE INDEX IF NOT EXISTS ap_conv ON approvals(conversation_id, status);
"""

# approvals.status: pending (waiting) -> approved | denied | timeout | cancelled, decided live; or, for one still
# pending when the dashboard stopped: approved_later | denied_later (decided after the restart, applied when the
# operation resumes, then approved | denied) | expired (the operation was ended instead)
LATER = {"approved_later": True, "denied_later": False}


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
            self.db.execute("DELETE FROM operations WHERE conversation_id=?", (conv_id,))
            self.db.execute("DELETE FROM approvals WHERE conversation_id=?", (conv_id,))
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

    def event(self, event_id: int) -> dict[str, Any] | None:
        with self._lock:
            r = self.db.execute("SELECT * FROM events WHERE id=?", (event_id,)).fetchone()
        return {"id": r["id"], "conversation_id": r["conversation_id"], "ts": r["ts"], "kind": r["kind"],
                "data": json.loads(r["data"])} if r else None

    def first_event(self, conv_id: str, kind: str) -> dict[str, Any] | None:
        """The earliest event of this kind in the conversation (e.g. the one that put it under the approval gate)."""
        with self._lock:
            r = self.db.execute("SELECT * FROM events WHERE conversation_id=? AND kind=? ORDER BY id LIMIT 1",
                                (conv_id, kind)).fetchone()
        return {"id": r["id"], "ts": r["ts"], "kind": r["kind"], "data": json.loads(r["data"])} if r else None

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

    # ---- operations ---------------------------------------------------------------------
    def op_create(self, conv_id: str, kind: str, label: str, playbook: str, pid: int, started: float) -> dict[str, Any]:
        oid = "op-" + uuid.uuid4().hex[:12]
        with self._lock:
            self.db.execute("INSERT INTO operations(id, conversation_id, kind, label, playbook, status, pid, started) "
                            "VALUES (?,?,?,?,?,?,?,?)", (oid, conv_id, kind, label[:200], playbook[:80], "running", pid, started))
            self.db.commit()
        return self.op_get(oid)  # type: ignore[return-value]

    def op_get(self, op_id: str) -> dict[str, Any] | None:
        with self._lock:
            r = self.db.execute("SELECT * FROM operations WHERE id=?", (op_id,)).fetchone()
        return dict(r) if r else None

    def op_latest(self, conv_id: str) -> dict[str, Any] | None:
        with self._lock:
            r = self.db.execute("SELECT * FROM operations WHERE conversation_id=? ORDER BY started DESC, rowid DESC LIMIT 1",
                                (conv_id,)).fetchone()
        return dict(r) if r else None

    def ops_since(self, conv_id: str, kind: str) -> list[dict[str, Any]]:
        """The conversation's operations after its latest one of `kind` (all of them if there is none), oldest first."""
        with self._lock:
            rows = [dict(r) for r in self.db.execute("SELECT * FROM operations WHERE conversation_id=? "
                                                     "ORDER BY started, rowid", (conv_id,)).fetchall()]
        last = max((i for i, r in enumerate(rows) if r["kind"] == kind), default=-1)
        return rows[last + 1:]

    def op_update(self, op_id: str, **fields: Any) -> None:
        cols = [k for k in fields if k in ("status", "pid", "ended", "note", "kind", "label")]
        if not cols:
            return
        with self._lock:
            self.db.execute(f"UPDATE operations SET {', '.join(f'{k}=?' for k in cols)} WHERE id=?",
                            (*[fields[k] for k in cols], op_id))
            self.db.commit()

    # ---- approvals -------------------------------------------------------------------------
    def approval_add(self, row: dict[str, Any]) -> None:
        with self._lock:
            self.db.execute("INSERT INTO approvals(id, conversation_id, operation_id, agent_id, call_key, tool, arguments, "
                            "rationale, why, requested, status) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                            (row["id"], row["conversation_id"], row.get("operation_id", ""), row.get("agent_id", ""),
                             row.get("call_key", ""), row["tool"], json.dumps(row.get("arguments") or {}, default=str),
                             str(row.get("rationale") or "")[:20000], str(row.get("why") or "")[:2000], row["requested"],
                             row.get("status", "pending")))
            self.db.commit()

    def approval_update(self, aid: str, **fields: Any) -> None:
        cols = [k for k in fields if k in ("status", "note", "decided_by", "decided", "operation_id")]
        if not cols:
            return
        with self._lock:
            self.db.execute(f"UPDATE approvals SET {', '.join(f'{k}=?' for k in cols)} WHERE id=?",
                            (*[fields[k] for k in cols], aid))
            self.db.commit()

    def approvals(self, conv_id: str, statuses: tuple[str, ...], operation_id: str | None = None) -> list[dict[str, Any]]:
        sql = (f"SELECT * FROM approvals WHERE conversation_id=? AND status IN ({','.join('?' * len(statuses))})"
               + (" AND operation_id=?" if operation_id is not None else "") + " ORDER BY requested")
        args = (conv_id, *statuses) + ((operation_id,) if operation_id is not None else ())
        with self._lock:
            rows = self.db.execute(sql, args).fetchall()
        return [_approval(r) for r in rows]

    def approval_for_call(self, conv_id: str, call_key: str) -> dict[str, Any] | None:
        """The approval still open for this exact tool call (same agent, call id, tool and arguments), if any."""
        if not call_key:
            return None
        with self._lock:
            r = self.db.execute("SELECT * FROM approvals WHERE conversation_id=? AND call_key=? AND status IN "
                                "('pending','approved_later','denied_later') ORDER BY requested DESC LIMIT 1",
                                (conv_id, call_key)).fetchone()
        return _approval(r) if r else None


def _approval(r: sqlite3.Row) -> dict[str, Any]:
    d = dict(r)
    d["arguments"] = json.loads(d["arguments"] or "{}")
    return d
