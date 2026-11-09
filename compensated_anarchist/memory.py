"""Persistent DCO memory - how the harness learns over time.

Kinds of knowledge it accumulates:
  environment   facts about YOUR terrain (asset roles, subnets, index names, log sources, baselines)
  query         hunt/detection queries that worked (SPL, KQL, ES|QL, EQL, VQL, display filters)
  lesson        retrospective lessons: what worked, what wasted time, what to do first next time
  false_positive known-benign patterns that look malicious in this environment
  ttp           adversary tradecraft observed in your networks (ATT&CK-mapped)
  feedback      analyst corrections (denied actions, rejected findings, guidance)
  playbook      procedural improvements to playbooks

Poisoning defense: attacker-controlled data (logs, files, packets) flows through the agents, so
anything an *agent* writes lands as `candidate` and is NOT used for retrieval until an analyst
promotes it (`canarchist memory review`). Kinds listed in memory.auto_promote_kinds skip review.
Analyst-written memories are approved immediately. Usage/helpfulness scores re-rank retrieval.
"""

from __future__ import annotations

import json
import re
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .tools.registry import Tool, schema

KINDS = ["environment", "query", "lesson", "false_positive", "ttp", "feedback", "playbook"]

_SCHEMA = """
CREATE TABLE IF NOT EXISTS memories (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  kind TEXT NOT NULL, title TEXT NOT NULL, content TEXT NOT NULL,
  tags TEXT DEFAULT '', attack_techniques TEXT DEFAULT '',
  source TEXT DEFAULT '', case_id TEXT DEFAULT '',
  status TEXT NOT NULL DEFAULT 'candidate',
  uses INTEGER DEFAULT 0, helpful INTEGER DEFAULT 0, unhelpful INTEGER DEFAULT 0,
  created TEXT, updated TEXT
);
CREATE VIRTUAL TABLE IF NOT EXISTS memories_fts USING fts5(
  title, content, tags, attack_techniques, content='memories', content_rowid='id'
);
CREATE TRIGGER IF NOT EXISTS mem_ai AFTER INSERT ON memories BEGIN
  INSERT INTO memories_fts(rowid, title, content, tags, attack_techniques)
  VALUES (new.id, new.title, new.content, new.tags, new.attack_techniques);
END;
CREATE TRIGGER IF NOT EXISTS mem_ad AFTER DELETE ON memories BEGIN
  INSERT INTO memories_fts(memories_fts, rowid, title, content, tags, attack_techniques)
  VALUES ('delete', old.id, old.title, old.content, old.tags, old.attack_techniques);
END;
CREATE TRIGGER IF NOT EXISTS mem_au AFTER UPDATE ON memories BEGIN
  INSERT INTO memories_fts(memories_fts, rowid, title, content, tags, attack_techniques)
  VALUES ('delete', old.id, old.title, old.content, old.tags, old.attack_techniques);
  INSERT INTO memories_fts(rowid, title, content, tags, attack_techniques)
  VALUES (new.id, new.title, new.content, new.tags, new.attack_techniques);
END;
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _fts_query(text: str) -> str:
    toks = [t for t in re.findall(r"[A-Za-z0-9_.\-]{3,}", text.lower())][:40]
    return " OR ".join(f'"{t}"' for t in dict.fromkeys(toks))


class Memory:
    def __init__(self, db_path: Path, cfg: dict[str, Any] | None = None, audit=None):
        cfg = cfg or {}
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(db_path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(_SCHEMA)
        self._lock = threading.Lock()
        self.auto_promote = set(cfg.get("auto_promote_kinds", []))
        self.retrieve_k = int(cfg.get("retrieve_k", 8))
        self.audit = audit
        self.case_id = ""

    # ---- core ---------------------------------------------------------------
    def add(self, kind: str, title: str, content: str, tags: list[str] | str = "", attack_techniques: list[str] | str = "",
            source: str = "agent", case_id: str = "", status: str | None = None) -> int:
        if kind not in KINDS:
            raise ValueError(f"kind must be one of {KINDS}")
        tags = ",".join(tags) if isinstance(tags, list) else tags
        attack = ",".join(attack_techniques) if isinstance(attack_techniques, list) else attack_techniques
        if status is None:
            status = "approved" if source == "analyst" or kind in self.auto_promote else "candidate"
        with self._lock:
            row = self.db.execute("SELECT id FROM memories WHERE kind=? AND lower(title)=lower(?) AND status!='rejected'",
                                  (kind, title)).fetchone()
            if row:
                self.db.execute("UPDATE memories SET content=?, tags=?, attack_techniques=?, updated=? WHERE id=?",
                                (content, tags, attack, _now(), row["id"]))
                mid = row["id"]
            else:
                cur = self.db.execute(
                    "INSERT INTO memories(kind,title,content,tags,attack_techniques,source,case_id,status,created,updated)"
                    " VALUES (?,?,?,?,?,?,?,?,?,?)",
                    (kind, title, content, tags, attack, source, case_id or self.case_id, status, _now(), _now()))
                mid = cur.lastrowid
            self.db.commit()
        if self.audit:
            self.audit.record("memory_write", id=mid, kind=kind, title=title, source=source, status=status)
        return int(mid)

    def search(self, query: str, kinds: list[str] | None = None, limit: int = 8,
               include_candidates: bool = False) -> list[dict[str, Any]]:
        q = _fts_query(query)
        if not q:
            return []
        statuses = ("approved", "candidate") if include_candidates else ("approved",)
        sql = (f"SELECT m.*, bm25(memories_fts) AS score FROM memories_fts JOIN memories m ON m.id = memories_fts.rowid "
               f"WHERE memories_fts MATCH ? AND m.status IN ({','.join('?' * len(statuses))})")
        params: list[Any] = [q, *statuses]
        if kinds:
            sql += f" AND m.kind IN ({','.join('?' * len(kinds))})"
            params += kinds
        sql += " ORDER BY score LIMIT ?"
        params.append(limit * 3)
        with self._lock:
            rows = [dict(r) for r in self.db.execute(sql, params).fetchall()]
        # re-rank: bm25 (lower = better) adjusted by analyst/agent helpfulness feedback
        for r in rows:
            r["rank"] = r["score"] - 0.5 * (r["helpful"] - 2 * r["unhelpful"])
        rows.sort(key=lambda r: r["rank"])
        return rows[:limit]

    def mark_used(self, ids: list[int]) -> None:
        if not ids:
            return
        with self._lock:
            self.db.executemany("UPDATE memories SET uses = uses + 1 WHERE id=?", [(i,) for i in ids])
            self.db.commit()

    def feedback(self, mid: int, helpful: bool) -> str:
        col = "helpful" if helpful else "unhelpful"
        with self._lock:
            n = self.db.execute(f"UPDATE memories SET {col} = {col} + 1, updated=? WHERE id=?", (_now(), mid)).rowcount
            self.db.commit()
        return f"memory {mid} marked {col}" if n else f"memory {mid} not found"

    def set_status(self, mid: int, status: str, by: str = "") -> bool:
        with self._lock:
            n = self.db.execute("UPDATE memories SET status=?, updated=? WHERE id=?", (status, _now(), mid)).rowcount
            self.db.commit()
        if self.audit and n:
            self.audit.record("memory_status", id=mid, status=status, by=by)
        return bool(n)

    def list(self, status: str | None = None, kind: str | None = None, limit: int = 200) -> list[dict[str, Any]]:
        sql, params = "SELECT * FROM memories WHERE 1=1", []
        if status:
            sql += " AND status=?"
            params.append(status)
        if kind:
            sql += " AND kind=?"
            params.append(kind)
        sql += " ORDER BY id DESC LIMIT ?"
        params.append(limit)
        with self._lock:
            return [dict(r) for r in self.db.execute(sql, params).fetchall()]

    def stats(self) -> dict[str, Any]:
        with self._lock:
            rows = self.db.execute("SELECT kind, status, count(*) n FROM memories GROUP BY kind, status").fetchall()
        return {f"{r['kind']}/{r['status']}": r["n"] for r in rows}

    def context_block(self, text: str, kinds: list[str] | None = None) -> str:
        """Relevant approved memories, formatted for injection at mission start."""
        hits = self.search(text, kinds, self.retrieve_k)
        if not hits:
            return ""
        self.mark_used([h["id"] for h in hits])
        lines = ["# Institutional memory (analyst-approved, from previous operations)",
                 "Use these as priors, not facts: verify against current data. Cite memory IDs you rely on."]
        for h in hits:
            lines.append(f"- [M{h['id']}] ({h['kind']}) {h['title']}: {h['content'][:600]}")
        return "\n".join(lines)

    # ---- agent tools ------------------------------------------------------------
    def _t_search(self, query: str, kinds: list[str] | None = None, limit: int = 8) -> str:
        hits = self.search(query, kinds, min(limit, 20))
        self.mark_used([h["id"] for h in hits])
        if not hits:
            return "no relevant memories"
        return "\n".join(f"[M{h['id']}] ({h['kind']}, helpful={h['helpful']}) {h['title']}\n  {h['content']}" for h in hits)

    def _t_record(self, kind: str, title: str, content: str, tags: list[str] | None = None,
                  attack_techniques: list[str] | None = None) -> str:
        mid = self.add(kind, title, content, tags or [], attack_techniques or [], source="agent")
        row = self.db.execute("SELECT status FROM memories WHERE id=?", (mid,)).fetchone()
        return f"memory M{mid} saved (status={row['status']}; candidates need analyst promotion before reuse)"

    def _t_feedback(self, memory_id: int, helpful: bool) -> str:
        return self.feedback(memory_id, helpful)

    def tools(self) -> list[Tool]:
        S = {"type": "string"}
        L = {"type": "array", "items": {"type": "string"}}
        return [
            Tool("memory_search", "Search institutional memory: environment facts, proven queries, lessons, known false positives, observed TTPs. Do this BEFORE writing new queries.",
                 schema({"query": S, "kinds": {"type": "array", "items": {"type": "string", "enum": KINDS}}, "limit": {"type": "integer"}}, ["query"]),
                 self._t_search),
            Tool("memory_record", "Save durable knowledge for future operations (an environment fact, a query that worked with its platform, a lesson, a false-positive pattern, observed TTP). Be specific and self-contained. Never store secrets.",
                 schema({"kind": {"type": "string", "enum": KINDS}, "title": S, "content": S, "tags": L, "attack_techniques": L},
                        ["kind", "title", "content"]), self._t_record),
            Tool("memory_feedback", "Mark a retrieved memory as helpful or misleading so ranking improves.",
                 schema({"memory_id": {"type": "integer"}, "helpful": {"type": "boolean"}}, ["memory_id", "helpful"]),
                 self._t_feedback),
        ]


def export_training(cases_dir: Path, out_path: Path, min_rating: int = 4) -> int:
    """Export rated, successful agent transcripts as chat-format JSONL for fine-tuning local models."""
    n = 0
    with open(out_path, "w", encoding="utf-8") as out:
        for case_json in sorted(cases_dir.glob("*/case.json")):
            data = json.loads(case_json.read_text())
            ratings = {r["run"]: r["rating"] for r in data.get("ratings", [])}
            for tr in sorted((case_json.parent / "transcripts").glob("*.json")):
                session = tr.stem.split("__")[0]  # transcripts are <session>__<agent>__<n>.json
                if ratings.get(session, 0) < min_rating:
                    continue
                t = json.loads(tr.read_text())
                msgs = [{k: v for k, v in m.items() if not k.startswith("_")} for m in t["messages"]]
                out.write(json.dumps({"messages": msgs, "tools": t.get("tools", []),
                                      "meta": {"case": data["id"], "agent": t.get("agent"), "rating": ratings[session]}}) + "\n")
                n += 1
    return n
