"""Expert skills - procedures the team writes, uses, scores and revises so each expert gets better at its job.

A skill is a named, versioned procedure owned by one expert (or `shared`, or `lead` for orchestration):
when to use it (description) and how (body: steps, queries, decision points, pitfalls). Format matches the
SKILL.md convention (name + description frontmatter, markdown body), so skills export/import as files.

Learning loop
  1. retrieve   when a subagent is spawned, its brief lists the approved skills relevant to the task
                (name, description, version, track record); it loads one with skill_view before using it
  2. use        every skill_view is recorded as a use in this conversation
  3. score      the agent reports whether a skill worked (skill_feedback / submit_report), and the analyst's
                session rating settles any use still open (4-5 good, 1-2 bad)
  4. adjust     agents propose new skills (skill_create) and revisions (skill_update, with a change note);
                the retro and subagent reflections review skills with a poor track record
  5. govern     agent-written versions land as `candidate` and are not used until an analyst approves them
                (skills.require_approval, default true) - skills are instructions to the team, and agents
                learn from attacker-controlled data, so this is the poisoning defense. Analyst-written
                versions are approved immediately. Old versions are kept for diff and rollback.
"""

from __future__ import annotations

import difflib
import re
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

import yaml

from .tools.registry import Tool, schema

NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]{2,63}$")
SHARED, LEAD = "shared", "lead"
BUILTIN_DIR = Path(__file__).parent / "builtin_skills"  # <expert>/<skill>/SKILL.md, added on first start

_SCHEMA = """
CREATE TABLE IF NOT EXISTS skills (
  id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE NOT NULL, expert TEXT NOT NULL,
  active_version INTEGER, status TEXT NOT NULL DEFAULT 'active',
  uses INTEGER NOT NULL DEFAULT 0, successes INTEGER NOT NULL DEFAULT 0, failures INTEGER NOT NULL DEFAULT 0,
  created TEXT, updated TEXT
);
CREATE TABLE IF NOT EXISTS skill_versions (
  id INTEGER PRIMARY KEY AUTOINCREMENT, skill_id INTEGER NOT NULL, version INTEGER NOT NULL,
  description TEXT NOT NULL, body TEXT NOT NULL, change_note TEXT DEFAULT '',
  author TEXT DEFAULT '', source TEXT NOT NULL, case_id TEXT DEFAULT '', conversation_id TEXT DEFAULT '',
  status TEXT NOT NULL, created TEXT, reviewed_by TEXT DEFAULT '', reviewed TEXT DEFAULT '', review_note TEXT DEFAULT '',
  UNIQUE(skill_id, version)
);
CREATE TABLE IF NOT EXISTS skill_uses (
  id INTEGER PRIMARY KEY AUTOINCREMENT, skill_id INTEGER NOT NULL, version INTEGER NOT NULL,
  agent TEXT, agent_id TEXT, conversation_id TEXT, case_id TEXT,
  outcome TEXT, note TEXT DEFAULT '', ts TEXT
);
CREATE VIRTUAL TABLE IF NOT EXISTS skills_fts USING fts5(name, description, body);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _fts_query(text: str) -> str:
    toks = re.findall(r"[A-Za-z0-9_]{3,}", text.lower())[:40]
    return " OR ".join(f'"{t}"' for t in dict.fromkeys(toks))


def track_record(s: dict[str, Any]) -> str:
    if not s["uses"]:
        return "new - no track record yet"
    flag = " - POOR TRACK RECORD, verify each step and propose a fix" if needs_revision(s) else ""
    return f"{s['successes']} worked / {s['failures']} failed over {s['uses']} uses{flag}"


def needs_revision(s: dict[str, Any]) -> bool:
    return s["failures"] >= 2 and s["failures"] > s["successes"]


class SkillStore:
    def __init__(self, db_path: Path, cfg: dict[str, Any] | None = None, audit=None):
        cfg = cfg or {}
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(db_path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(_SCHEMA)
        self._lock = threading.Lock()
        self.require_approval = bool(cfg.get("require_approval", True))
        self.index_k = int(cfg.get("index_k", 12))
        self.max_body = int(cfg.get("max_body_chars", 8000))
        self.max_pending = int(cfg.get("max_pending_per_skill", 3))
        self.audit = audit

    def _audit(self, event: str, **data: Any) -> None:
        if self.audit:
            self.audit.record(event, **data)

    # ---- read ------------------------------------------------------------------------
    def get(self, name: str) -> dict[str, Any] | None:
        with self._lock:
            s = self.db.execute("SELECT * FROM skills WHERE name=?", (name,)).fetchone()
            if not s:
                return None
            out = dict(s)
            v = self.db.execute("SELECT * FROM skill_versions WHERE skill_id=? AND version=?",
                                (s["id"], s["active_version"])).fetchone() if s["active_version"] else None
        out["description"] = v["description"] if v else ""
        out["body"] = v["body"] if v else ""
        return out

    def list(self, expert: str | None = None, include_retired: bool = False) -> list[dict[str, Any]]:
        sql = ("SELECT s.*, v.description, (SELECT count(*) FROM skill_versions p WHERE p.skill_id=s.id AND p.status='candidate')"
               " AS pending FROM skills s LEFT JOIN skill_versions v ON v.skill_id=s.id AND v.version=s.active_version WHERE 1=1")
        params: list[Any] = []
        if expert:
            sql += " AND s.expert=?"
            params.append(expert)
        if not include_retired:
            sql += " AND s.status='active'"
        with self._lock:
            return [dict(r) for r in self.db.execute(sql + " ORDER BY s.expert, s.name", params).fetchall()]

    def versions(self, name: str) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(r) for r in self.db.execute(
                "SELECT v.* FROM skill_versions v JOIN skills s ON s.id=v.skill_id WHERE s.name=? ORDER BY v.version DESC",
                (name,)).fetchall()]

    def pending(self) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(r) for r in self.db.execute(
                "SELECT v.*, s.name, s.expert, s.active_version FROM skill_versions v JOIN skills s ON s.id=v.skill_id "
                "WHERE v.status='candidate' ORDER BY v.created").fetchall()]

    def versions_in(self, conversation_id: str) -> list[dict[str, Any]]:
        """Every skill version proposed in one conversation (any status), oldest first."""
        with self._lock:
            return [dict(r) for r in self.db.execute(
                "SELECT v.*, s.name, s.expert, s.active_version FROM skill_versions v JOIN skills s ON s.id=v.skill_id "
                "WHERE v.conversation_id=? ORDER BY v.id", (conversation_id,)).fetchall()]

    def version(self, version_id: int) -> dict[str, Any] | None:
        with self._lock:
            r = self.db.execute("SELECT v.*, s.name, s.expert, s.active_version FROM skill_versions v "
                                "JOIN skills s ON s.id=v.skill_id WHERE v.id=?", (version_id,)).fetchone()
        return dict(r) if r else None

    def diff(self, version_id: int) -> str:
        """Unified diff of a version against the currently active one (or against nothing for a new skill)."""
        v = self.version(version_id)
        if not v:
            raise KeyError(f"no skill version {version_id}")
        cur = self.get(v["name"])
        old = f"description: {cur['description']}\n\n{cur['body']}" if cur and cur["active_version"] else ""
        new = f"description: {v['description']}\n\n{v['body']}"
        label = f"{v['name']} v{cur['active_version']}" if cur and cur["active_version"] else "(new skill)"
        return "".join(difflib.unified_diff(old.splitlines(True), new.splitlines(True), label, f"{v['name']} v{v['version']}"))

    def relevant(self, expert: str, text: str, k: int | None = None) -> list[dict[str, Any]]:
        """Approved, active skills for this expert (plus shared), most relevant to `text` first."""
        k = k or self.index_k
        owners = (expert, SHARED)
        q = _fts_query(text)
        ranked: dict[int, float] = {}
        with self._lock:
            if q:
                for r in self.db.execute("SELECT rowid, bm25(skills_fts) AS score FROM skills_fts WHERE skills_fts MATCH ? "
                                         "ORDER BY score LIMIT 200", (q,)).fetchall():
                    ranked[r["rowid"]] = r["score"]
            rows = [dict(r) for r in self.db.execute(
                "SELECT s.*, v.description FROM skills s JOIN skill_versions v ON v.skill_id=s.id AND v.version=s.active_version "
                "WHERE s.status='active' AND s.expert IN (?,?)", owners).fetchall()]
        for r in rows:  # relevance first, then proven usefulness
            r["_rank"] = (ranked.get(r["id"], 0.0) if r["id"] in ranked else 1e6) - 0.2 * (r["successes"] - 2 * r["failures"])
        rows.sort(key=lambda r: (r["_rank"], -r["uses"]))
        return rows[:k]

    def index_block(self, expert: str, text: str) -> str:
        rows = self.relevant(expert, text)
        if not rows:
            return ("# Your skills\nNo approved skills yet for this kind of work. If you work out a reusable procedure, "
                    "save it with skill_create.")
        lines = ["# Your skills (analyst-approved procedures from previous operations)",
                 "Load a skill with skill_view BEFORE doing work it covers, follow it, and report whether it worked."]
        for r in rows:
            lines.append(f"- {r['name']} (v{r['active_version']}, {r['expert']}): {r['description']} [{track_record(r)}]")
        return "\n".join(lines)

    def stats(self) -> dict[str, int]:
        with self._lock:
            a = self.db.execute("SELECT count(*) FROM skills WHERE status='active' AND active_version IS NOT NULL").fetchone()[0]
            p = self.db.execute("SELECT count(*) FROM skill_versions WHERE status='candidate'").fetchone()[0]
        return {"active": int(a), "pending_review": int(p)}

    # ---- write -----------------------------------------------------------------------------
    def propose(self, name: str, expert: str, description: str, body: str, change_note: str = "", *,
                source: str = "agent", author: str = "", case_id: str = "", conversation_id: str = "") -> dict[str, Any]:
        name, description, body = name.strip().lower(), description.strip(), body.strip()
        if not NAME_RE.match(name):
            raise ValueError("skill name must be 3-64 chars of a-z, 0-9 and '-', e.g. zeek-beacon-triage")
        if not description or len(description) > 600:
            raise ValueError("description is required (when to use this skill), at most 600 chars")
        if not body or len(body) > self.max_body:
            raise ValueError(f"body is required, at most {self.max_body} chars")
        approved = source == "analyst" or not self.require_approval
        with self._lock:
            s = self.db.execute("SELECT * FROM skills WHERE name=?", (name,)).fetchone()
            if s and s["expert"] != expert:
                raise ValueError(f"skill '{name}' belongs to {s['expert']}")
            if not s:
                cur = self.db.execute("INSERT INTO skills(name, expert, created, updated) VALUES (?,?,?,?)",
                                      (name, expert, _now(), _now()))
                sid, version = int(cur.lastrowid), 1
            else:
                sid = s["id"]
                same = self.db.execute("SELECT * FROM skill_versions WHERE skill_id=? AND body=? AND description=? "
                                       "AND status IN ('approved','candidate')", (sid, body, description)).fetchone()
                if same:
                    return dict(same) | {"name": name, "duplicate": True}
                n_pending = self.db.execute("SELECT count(*) FROM skill_versions WHERE skill_id=? AND status='candidate'",
                                            (sid,)).fetchone()[0]
                if n_pending >= self.max_pending and not approved:
                    raise ValueError(f"skill '{name}' already has {n_pending} revisions awaiting analyst review")
                version = self.db.execute("SELECT max(version) FROM skill_versions WHERE skill_id=?", (sid,)).fetchone()[0] + 1
            cur = self.db.execute(
                "INSERT INTO skill_versions(skill_id, version, description, body, change_note, author, source, case_id, "
                "conversation_id, status, created) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (sid, version, description, body, change_note[:1000], author, source, case_id, conversation_id,
                 "candidate", _now()))
            vid = int(cur.lastrowid)
            self.db.commit()
        self._audit("skill_proposed", skill=name, version=version, expert=expert, source=source, author=author)
        if approved:
            self.approve(vid, author or source, "auto-approved" if source != "analyst" else "")
        return self.version(vid) | {"name": name}  # type: ignore[operator]

    def approve(self, version_id: int, by: str, note: str = "") -> dict[str, Any]:
        v = self.version(version_id)
        if not v or v["status"] not in ("candidate", "superseded", "approved"):
            raise ValueError(f"version {version_id} cannot be approved (status {v and v['status']})")
        with self._lock:
            self.db.execute("UPDATE skill_versions SET status='superseded' WHERE skill_id=? AND status='approved' AND id!=?",
                            (v["skill_id"], version_id))
            self.db.execute("UPDATE skill_versions SET status='approved', reviewed_by=?, reviewed=?, review_note=? WHERE id=?",
                            (by, _now(), note, version_id))
            self.db.execute("UPDATE skills SET active_version=?, status='active', updated=? WHERE id=?",
                            (v["version"], _now(), v["skill_id"]))
            self.db.execute("DELETE FROM skills_fts WHERE rowid=?", (v["skill_id"],))
            self.db.execute("INSERT INTO skills_fts(rowid, name, description, body) VALUES (?,?,?,?)",
                            (v["skill_id"], v["name"].replace("-", " "), v["description"], v["body"]))
            self.db.commit()
        self._audit("skill_approved", skill=v["name"], version=v["version"], by=by, note=note)
        return self.version(version_id)  # type: ignore[return-value]

    def reject(self, version_id: int, by: str, note: str = "") -> None:
        v = self.version(version_id)
        if not v or v["status"] != "candidate":
            raise ValueError(f"version {version_id} is not awaiting review")
        with self._lock:
            self.db.execute("UPDATE skill_versions SET status='rejected', reviewed_by=?, reviewed=?, review_note=? WHERE id=?",
                            (by, _now(), note, version_id))
            self.db.commit()
        self._audit("skill_rejected", skill=v["name"], version=v["version"], by=by, note=note)

    def rollback(self, name: str, version: int, by: str) -> dict[str, Any]:
        """Re-activate an earlier analyst-approved version."""
        v = next((x for x in self.versions(name) if x["version"] == version), None)
        if not v or v["status"] not in ("superseded", "approved"):
            raise ValueError(f"{name} v{version} was never approved, so it cannot be rolled back to")
        return self.approve(v["id"], by, f"rollback to v{version}")

    def set_status(self, name: str, status: str, by: str) -> bool:
        if status not in ("active", "retired"):
            raise ValueError("status must be active or retired")
        with self._lock:
            n = self.db.execute("UPDATE skills SET status=?, updated=? WHERE name=?", (status, _now(), name)).rowcount
            self.db.commit()
        if n:
            self._audit("skill_status", skill=name, status=status, by=by)
        return bool(n)

    # ---- outcomes --------------------------------------------------------------------------
    def record_use(self, name: str, agent: str, agent_id: str, conversation_id: str, case_id: str) -> dict[str, Any]:
        s = self.get(name)
        if not s or not s["active_version"] or s["status"] != "active":
            raise KeyError(f"no approved skill named '{name}'")
        with self._lock:
            self.db.execute("INSERT INTO skill_uses(skill_id, version, agent, agent_id, conversation_id, case_id, ts) "
                            "VALUES (?,?,?,?,?,?,?)", (s["id"], s["active_version"], agent, agent_id, conversation_id, case_id, _now()))
            self.db.execute("UPDATE skills SET uses = uses + 1 WHERE id=?", (s["id"],))
            self.db.commit()
        return s

    def feedback(self, name: str, worked: bool, note: str, agent_id: str, conversation_id: str) -> str:
        """Settle this agent's open use of the skill (or record a use) as worked / failed."""
        s = self.get(name)
        if not s:
            raise KeyError(f"no skill named '{name}'")
        outcome = "good" if worked else "bad"
        with self._lock:
            u = self.db.execute("SELECT id FROM skill_uses WHERE skill_id=? AND agent_id=? AND conversation_id=? AND outcome IS NULL "
                                "ORDER BY id DESC LIMIT 1", (s["id"], agent_id, conversation_id)).fetchone()
            if u:
                self.db.execute("UPDATE skill_uses SET outcome=?, note=? WHERE id=?", (outcome, note[:1000], u["id"]))
            else:
                self.db.execute("INSERT INTO skill_uses(skill_id, version, agent_id, conversation_id, outcome, note, ts) "
                                "VALUES (?,?,?,?,?,?,?)", (s["id"], s["active_version"] or 0, agent_id, conversation_id,
                                                           outcome, note[:1000], _now()))
                self.db.execute("UPDATE skills SET uses = uses + 1 WHERE id=?", (s["id"],))
            self.db.execute(f"UPDATE skills SET {'successes' if worked else 'failures'} = "
                            f"{'successes' if worked else 'failures'} + 1, updated=? WHERE id=?", (_now(), s["id"]))
            self.db.commit()
        self._audit("skill_feedback", skill=name, worked=worked, note=note[:300], agent=agent_id)
        return f"recorded: {name} {'worked' if worked else 'did not work'}"

    def settle_conversation(self, conversation_id: str, rating: int) -> int:
        """Analyst session rating settles skill uses still open in this conversation."""
        if 3 == rating:
            return 0
        outcome, col = ("good", "successes") if rating >= 4 else ("bad", "failures")
        with self._lock:
            rows = self.db.execute("SELECT id, skill_id FROM skill_uses WHERE conversation_id=? AND outcome IS NULL",
                                   (conversation_id,)).fetchall()
            for r in rows:
                self.db.execute("UPDATE skill_uses SET outcome=?, note='analyst session rating' WHERE id=?", (outcome, r["id"]))
                self.db.execute(f"UPDATE skills SET {col} = {col} + 1 WHERE id=?", (r["skill_id"],))
            self.db.commit()
        return len(rows)

    def conversation_usage(self, conversation_id: str) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(r) for r in self.db.execute(
                "SELECT s.name, s.expert, u.version, u.agent_id, u.outcome, u.note FROM skill_uses u JOIN skills s ON s.id=u.skill_id "
                "WHERE u.conversation_id=? ORDER BY u.id", (conversation_id,)).fetchall()]

    def struggling(self) -> list[dict[str, Any]]:
        return [s for s in self.list() if needs_revision(s)]

    # ---- files (SKILL.md) -------------------------------------------------------------------
    def export_dir(self, out: Path) -> int:
        n = 0
        for s in self.list(include_retired=True):
            full = self.get(s["name"])
            if not full or not full["active_version"]:
                continue
            d = out / full["expert"] / full["name"]
            d.mkdir(parents=True, exist_ok=True)
            meta = {"name": full["name"], "description": full["description"], "expert": full["expert"],
                    "version": full["active_version"], "status": full["status"]}
            (d / "SKILL.md").write_text(f"---\n{yaml.safe_dump(meta, sort_keys=False)}---\n\n{full['body']}\n", encoding="utf-8")
            n += 1
        return n

    def _only_by(self, name: str, by: str) -> bool:
        """True when every version of an active skill was written and approved by `by` alone, with nothing
        waiting for review: nobody has revised, rolled back, retired or proposed a change to it."""
        s = self.get(name)
        vs = self.versions(name)
        return bool(s and s["status"] == "active" and vs) and all(
            v["author"] == by and v["status"] != "candidate" and v["reviewed_by"] in (by, "") for v in vs)

    def import_dir(self, src: Path, by: str, only_new: bool = False) -> list[str]:
        """Import analyst-authored SKILL.md files (approved on import; unchanged files are skipped).
        only_new: for shipped defaults. A new skill is added, and one that only `by` has ever written is refreshed to
        the shipped text; a skill anyone revised, rolled back, retired or has a change waiting on is never touched."""
        done = []
        for f in sorted(src.rglob("SKILL.md")):
            m = re.match(r"^---\n(.*?)\n---\n(.*)$", f.read_text(encoding="utf-8"), re.S)
            if not m:
                raise ValueError(f"{f}: missing YAML frontmatter")
            meta = yaml.safe_load(m.group(1)) or {}
            name = str(meta["name"]).strip().lower()
            exists = self.get(name) is not None
            if only_new and exists and not self._only_by(name, by):
                continue
            expert = str(meta.get("expert") or f.parent.parent.name)
            note = f"updated to the shipped version from {f}" if exists else f"imported from {f}"
            v = self.propose(str(meta["name"]), expert, str(meta["description"]), m.group(2), note,
                             source="analyst", author=by)
            if not v.get("duplicate"):
                done.append(f"{v['name']} v{v['version']}")
        return done


# ---------------------------------------------------------------------------
# per-agent tools: the store knows which expert / subagent is calling
# ---------------------------------------------------------------------------
def skill_tools(store: SkillStore, expert: str, agent_id: str, ctx: Callable[[], dict[str, str]],
                experts: list[str], on_event: Callable[[str, dict[str, Any]], None]) -> list[Tool]:
    """`expert` is the owner the agent writes skills for. The orchestrator (`lead`) may also write skills for any
    expert (`for_expert`), because it sees the fused outcome of the whole operation."""
    S = {"type": "string"}
    is_lead = expert == LEAD

    def owner(shared: bool = False, for_expert: str = "") -> str:
        if shared:
            return SHARED
        if for_expert and for_expert != expert:
            if not is_lead:
                raise ValueError("only the orchestrator can write skills for another expert; use shared=true for team-wide skills")
            if for_expert not in experts and for_expert != LEAD:
                raise ValueError(f"unknown expert {for_expert}")
            return for_expert
        return expert

    def can_edit(name: str) -> dict[str, Any]:
        s = store.get(name)
        if not s:
            raise ValueError(f"no skill named '{name}' - use skill_create")
        if s["expert"] not in (expert, SHARED) and not is_lead:
            raise ValueError(f"skill '{name}' belongs to {s['expert']}; report the problem in your findings instead")
        return s

    def t_list(query: str = "") -> str:
        rows = store.relevant(expert, query or expert, 40)
        if not rows:
            return "no approved skills yet"
        return "\n".join(f"{r['name']} (v{r['active_version']}, {r['expert']}): {r['description']} [{track_record(r)}]" for r in rows)

    def t_view(name: str) -> str:
        c = ctx()
        s = store.record_use(name, expert, agent_id, c["conversation_id"], c["case_id"])  # any skill may be read
        on_event("skill_used", {"agent": expert, "agent_id": agent_id, "skill": name, "version": s["active_version"]})
        return (f"# Skill {s['name']} v{s['active_version']} ({s['expert']})\nWhen: {s['description']}\n"
                f"Track record: {track_record(s)}\n\n{s['body']}\n\n"
                f"(When done, report whether it worked: skill_feedback or skills_used in submit_report. "
                f"If a step was wrong or missing, propose a fix with skill_update.)")

    def t_create(name: str, description: str, body: str, shared: bool = False, for_expert: str = "") -> str:
        c = ctx()
        v = store.propose(name, owner(shared, for_expert), description, body, "created",
                          author=agent_id, case_id=c["case_id"], conversation_id=c["conversation_id"])
        on_event("skill_proposed", {"agent": expert, "agent_id": agent_id, "skill": v["name"], "version": v["version"],
                                    "status": v["status"], "change_note": "new skill"})
        return _proposal_msg(v)

    def t_update(name: str, body: str, change_note: str, description: str = "") -> str:
        s = can_edit(name)
        c = ctx()
        v = store.propose(name, s["expert"], description or s["description"], body, change_note,
                          author=agent_id, case_id=c["case_id"], conversation_id=c["conversation_id"])
        on_event("skill_proposed", {"agent": expert, "agent_id": agent_id, "skill": v["name"], "version": v["version"],
                                    "status": v["status"], "change_note": change_note})
        return _proposal_msg(v)

    def t_feedback(name: str, worked: bool, note: str = "") -> str:
        return store.feedback(name, worked, note, agent_id, ctx()["conversation_id"])

    body_desc = ("Markdown procedure: when it applies, ordered steps with exact queries/tool calls and field names, "
                 "decision points, how to verify, known false positives and pitfalls. Self-contained; no secrets; "
                 "no hostnames/IPs specific to one incident unless they are durable environment facts.")
    name_desc = {"type": "string", "description": "kebab-case, e.g. zeek-beacon-triage"}
    tools = [
        Tool("skill_list", "List approved skills available to you (yours + shared), most relevant first.",
             schema({"query": S}), t_list),
        Tool("skill_view", "Load the full procedure of a skill before using it. Records a use.",
             schema({"name": S}, ["name"]), t_view),
        Tool("skill_create", "Save a reusable procedure you worked out (it worked, has 3+ steps, and will recur). "
                             "It is reviewed by an analyst before the team uses it.",
             schema({"name": name_desc, "description": {"type": "string", "description": "When to use it (one or two sentences)."},
                     "body": {"type": "string", "description": body_desc},
                     "shared": {"type": "boolean", "description": "true if every expert should have it"},
                     **({"for_expert": {"type": "string", "enum": [*experts, LEAD]}} if is_lead else {})},
                    ["name", "description", "body"]), t_create),
        Tool("skill_update", "Propose a revised version of a skill that was wrong, incomplete or outdated. Send the "
                             "complete new body and say what changed and why.",
             schema({"name": S, "body": {"type": "string", "description": body_desc},
                     "change_note": {"type": "string", "description": "What changed and the evidence that it was needed."},
                     "description": S}, ["name", "body", "change_note"]), t_update),
        Tool("skill_feedback", "Report whether a skill you used worked on this task (this is how skills are scored).",
             schema({"name": S, "worked": {"type": "boolean"}, "note": S}, ["name", "worked"]), t_feedback),
    ]
    return tools


def _proposal_msg(v: dict[str, Any]) -> str:
    if v.get("duplicate"):
        return f"identical to existing {v['name']} v{v['version']} ({v['status']}) - nothing new recorded"
    if v["status"] == "approved":
        return f"skill {v['name']} v{v['version']} saved and active"
    return f"skill {v['name']} v{v['version']} proposed - awaiting analyst review before the team uses it"
