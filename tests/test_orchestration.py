"""Chat history persistence, the orchestrator/subagent model, and the skills learning loop."""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

import pytest
from starlette.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_dashboard import H, login, make, wait_for  # noqa: E402
from test_harness import ScriptedBackend, write_config  # noqa: E402

from compensated_anarchist import agent as agent_mod  # noqa: E402
from compensated_anarchist.audit import verify  # noqa: E402
from compensated_anarchist.config import load_config  # noqa: E402
from compensated_anarchist.history import ChatStore  # noqa: E402
from compensated_anarchist.skills import SkillStore  # noqa: E402
from compensated_anarchist.web.app import Dashboard, create_app  # noqa: E402

NA = "Network Security Monitoring Analyst"
EA = "Endpoint / Live Response Analyst"
CTI = "Cyber Threat Intelligence Analyst"


def tool_outputs(messages):
    return [m["content"] for m in messages if m["role"] == "tool"]


# ---------------------------------------------------------------------------
# chat history: persisted, resumed (orchestrator + subagents), deleted only on request
# ---------------------------------------------------------------------------
def test_history_resume_followup_and_delete(tmp_path, monkeypatch):
    cfg = load_config(write_config(tmp_path))
    scripts = {
        "lead": [
            ("Tasking the network analyst.", [("subagent_spawn", {"expert": "network_analyst", "task": "Find beaconing from 10.1.2.3",
                                                                   "context": "alert 42"})]),
            ("SITREP-1: beacon to 203.0.113.7 confirmed.", []),
            ("Asking SA-001.", [("subagent_message", {"subagent_id": "SA-001", "message": "What JA3 did the beacon use?"})]),
            ("SITREP-2: JA3 recorded.", []),
        ],
        NA: [
            ("checking", [("case_add_ioc", {"type": "ipv4", "value": "203.0.113.7", "context": "beacon dst"})]),
            ("done", [("submit_report", {"status": "completed", "summary": "Beacon 10.1.2.3 -> 203.0.113.7:443 every 60s",
                                         "confidence": "high"})]),
            ("ja3", [("submit_report", {"status": "completed", "summary": "JA3 72a589da586844d7f0818ce684948eea", "confidence": "medium"})]),
        ],
    }
    fake = ScriptedBackend(scripts)
    monkeypatch.setattr(agent_mod, "make_backend", lambda profile: fake)

    async def first():
        h = agent_mod.Harness(cfg, "HIST-1")
        await h.start()
        assert h.conversation is None  # nothing is created until the first message
        out = await h.mission("Investigate beacon alert 42")
        conv = h.conversation["id"]
        await h.close()
        return conv, out

    conv, out = asyncio.run(first())
    assert "SITREP-1" in out
    store = ChatStore(cfg.history_db)
    c = store.get(conv)
    assert c["title"] == "Investigate beacon alert 42" and c["case_id"] == "HIST-1"
    kinds = [e["kind"] for e in store.events(conv)]
    assert kinds[0] == "analyst_message" and {"subagent_spawn", "subagent_report", "decision", "result", "text"} <= set(kinds)
    states = store.load_agents(conv)
    assert set(states) == {"lead", "SA-001"} and states["SA-001"]["meta"]["status"] == "completed"

    async def second():  # a new process resumes the case's latest conversation
        h = agent_mod.Harness(cfg, "HIST-1")
        await h.start()
        assert h.conversation["id"] == conv
        assert any("Investigate beacon alert 42" in str(m.get("content")) for m in h.lead.messages)
        assert h.subagents["SA-001"].status == "completed" and h.subagents["SA-001"].agent is None
        out = await h.mission("What JA3?")
        sa_msgs = h.subagents["SA-001"].agent.messages
        await h.close()
        return out, sa_msgs

    out2, sa_msgs = asyncio.run(second())
    assert "SITREP-2" in out2
    # the subagent answered the follow-up with its original brief still in its context
    assert any("Find beaconing from 10.1.2.3" in str(m.get("content")) for m in sa_msgs)
    assert any("What JA3 did the beacon use?" in str(m.get("content")) for m in sa_msgs)
    assert any("Report from SA-001" in t and "JA3 72a589da" in t for t in tool_outputs(fake.seen["lead"][-1]))

    async def third():  # --new: a separate conversation; an untouched one is never saved
        h = agent_mod.Harness(cfg, "HIST-1")
        await h.start(new=True)
        assert h.conversation is None and not h.subagents and len(h.lead.messages) == 1
        await h.close()

    asyncio.run(third())
    assert [x["id"] for x in store.list("HIST-1")] == [conv]

    # deletion removes chat + transcripts; the case record and the audit chain stay
    case_dir = tmp_path / "cases" / "HIST-1"
    tdir = case_dir / "transcripts" / conv
    assert tdir.is_dir() and any(tdir.iterdir())
    assert agent_mod.delete_conversation(cfg, conv, "tester")["id"] == conv
    assert store.get(conv) is None and not store.events(conv) and not store.load_agents(conv)
    assert not tdir.exists()
    assert json.loads((case_dir / "case.json").read_text())["iocs"][0]["value"] == "203.0.113.7"
    audit = [json.loads(line) for line in (case_dir / "audit.jsonl").read_text().splitlines()]
    assert audit[-1]["event"] == "conversation_deleted" and audit[-1]["data"]["conversation"] == conv
    assert verify(case_dir / "audit.jsonl")[0]


# ---------------------------------------------------------------------------
# orchestrator / subagent relationship
# ---------------------------------------------------------------------------
class SlowBackend(ScriptedBackend):
    def __init__(self, scripts):
        super().__init__(scripts)
        self.inflight = self.peak = 0

    async def chat(self, messages, tools):
        if "Mission Lead (orchestrator)" not in messages[0]["content"]:
            self.inflight += 1
            self.peak = max(self.peak, self.inflight)
            await asyncio.sleep(0.05)
            self.inflight -= 1
        return await super().chat(messages, tools)


@pytest.mark.parametrize("max_parallel,expected_peak", [(1, 1), (4, 3)])
def test_parallel_bound_and_subagents_cannot_spawn(tmp_path, monkeypatch, max_parallel, expected_peak):
    cfg = load_config(write_config(tmp_path))
    cfg.orchestration["max_parallel"] = max_parallel
    report = ("done", [("submit_report", {"status": "completed", "summary": "ok"})])
    scripts = {
        "lead": [("Three in parallel.", [("subagent_spawn", {"expert": e, "task": "t"})
                                         for e in ("network_analyst", "endpoint_analyst", "cti_analyst")]), ("SITREP", [])],
        NA: [("I want help", [("subagent_spawn", {"expert": "threat_hunter", "task": "x"})]), report],
        EA: [report], CTI: [report],
    }
    fake = SlowBackend(scripts)
    monkeypatch.setattr(agent_mod, "make_backend", lambda profile: fake)

    async def go():
        h = agent_mod.Harness(cfg, "PAR-1")
        await h.start()
        await h.mission("go")
        await h.close()
        return h

    h = asyncio.run(go())
    assert fake.peak == expected_peak
    assert sorted(h.subagents) == ["SA-001", "SA-002", "SA-003"]
    assert all(s.status == "completed" for s in h.subagents.values())
    na = next(s for s in h.subagents.values() if s.expert == "network_analyst")
    assert any("not available to agent 'network_analyst'" in t for t in tool_outputs(na.agent.messages))
    assert "subagent_spawn" not in {t.name for t in na.agent.tools}


# ---------------------------------------------------------------------------
# skills: create -> review -> retrieve -> use -> score -> revise -> approve / roll back
# ---------------------------------------------------------------------------
BODY1 = "1. Run security_onion__beacon_candidates for the window.\n2. Check hours_active >= 20.\n3. Pivot on community_id."
BODY2 = BODY1 + "\n4. Also stack zeek.dns queries per host - DNS beacons do not show in conn pairs."


def test_skill_learning_loop(tmp_path, monkeypatch):
    cfg = load_config(write_config(tmp_path))
    scripts = {
        "lead": [
            ("Hunt.", [("subagent_spawn", {"expert": "network_analyst", "task": "hunt beacons in zeek conn logs"})]),
            ("SITREP-1", []),
            ("Hunt again.", [("subagent_spawn", {"expert": "network_analyst", "task": "hunt beacons in zeek conn logs for subnet B"}),
                             ("skill_create", {"name": "beacon-hunt-staffing", "description": "How to staff a beacon hunt",
                                               "body": "Spawn network_analyst first; endpoint_analyst only on confirmed pairs."}),
                             ("skill_create", {"name": "beacon-host-follow-up", "description": "Endpoint follow-up on a beacon",
                                               "body": "1. client_info\n2. netstat artifact\n3. process tree", "for_expert": "endpoint_analyst"})]),
            ("SITREP-2", []),
        ],
        NA: [
            ("Worked it out; saving the procedure.",
             [("skill_create", {"name": "zeek-beacon-triage", "description": "Triage periodic outbound connections in Zeek conn logs",
                                "body": BODY1}),
              ("skill_create", {"name": "endpoint-thing", "description": "x", "body": "y", "for_expert": "endpoint_analyst"})]),
            ("done", [("submit_report", {"status": "completed", "summary": "2 candidates"})]),
            # second spawn: the approved skill is in the brief
            ("Loading my skill.", [("skill_view", {"name": "zeek-beacon-triage"}), ("skill_view", {"name": "zeek-beacon-triage"})]),
            ("It missed DNS beacons; proposing a fix.",
             [("skill_update", {"name": "zeek-beacon-triage", "body": BODY2, "change_note": "missed a DNS-only beacon on host B7"})]),
            ("done", [("submit_report", {"status": "completed", "summary": "found DNS beacon",
                                         "skills_used": [{"name": "zeek-beacon-triage", "worked": False, "note": "missed DNS beacons"}]})]),
        ],
    }
    fake = ScriptedBackend(scripts)
    monkeypatch.setattr(agent_mod, "make_backend", lambda profile: fake)
    store = SkillStore(cfg.memory_db, cfg.skills)

    async def go():
        h = agent_mod.Harness(cfg, "SKL-1")
        await h.start()
        await h.mission("hunt 1")
        sa1 = h.subagents["SA-001"]
        # agent-written skill is a candidate: not in anyone's brief until an analyst approves it
        assert store.get("zeek-beacon-triage")["active_version"] is None
        assert any("only the orchestrator can write skills for another expert" in t for t in tool_outputs(sa1.agent.messages))
        assert "zeek-beacon-triage" not in store.index_block("network_analyst", "beacon zeek")
        v1 = store.pending()[0]
        assert v1["name"] == "zeek-beacon-triage" and v1["author"] == "SA-001" and v1["case_id"] == "SKL-1"
        store.approve(v1["id"], "tester")

        await h.mission("hunt 2")
        sa2 = h.subagents["SA-002"]
        brief = next(m["content"] for m in sa2.agent.messages if m["role"] == "user")
        assert "zeek-beacon-triage (v1, network_analyst)" in brief and "new - no track record yet" in brief
        assert any("# Skill zeek-beacon-triage v1" in t for t in tool_outputs(sa2.agent.messages))
        h.rate(5, "good hunt")  # settles the use that got no explicit feedback
        conv = h.conversation["id"]
        await h.close()
        return conv

    conv = asyncio.run(go())
    s = store.get("zeek-beacon-triage")
    assert (s["uses"], s["failures"], s["successes"]) == (2, 1, 1)
    vs = store.versions("zeek-beacon-triage")
    assert [(v["version"], v["status"]) for v in vs] == [(2, "candidate"), (1, "approved")]
    assert vs[0]["change_note"].startswith("missed a DNS-only beacon")
    diff = store.diff(vs[0]["id"])
    assert "+4. Also stack zeek.dns" in diff and "zeek-beacon-triage v1" in diff
    # orchestrator skills: its own, and one written for another expert
    assert store.get("beacon-hunt-staffing")["expert"] == "lead"
    assert store.get("beacon-host-follow-up")["expert"] == "endpoint_analyst"
    assert not store.get("endpoint-thing")  # the expert was refused

    # approve v2 -> v1 superseded; roll back -> v1 active again; retire hides it from briefs
    store.approve(vs[0]["id"], "tester")
    assert store.get("zeek-beacon-triage")["active_version"] == 2
    assert "Also stack zeek.dns" in store.get("zeek-beacon-triage")["body"]
    store.rollback("zeek-beacon-triage", 1, "tester")
    assert store.get("zeek-beacon-triage")["active_version"] == 1
    store.set_status("zeek-beacon-triage", "retired", "tester")
    assert "zeek-beacon-triage" not in store.index_block("network_analyst", "beacon zeek")

    events = {e["kind"] for e in ChatStore(cfg.history_db).events(conv)}
    assert {"skill_used", "skill_proposed"} <= events
    audit = (tmp_path / "cases" / "SKL-1" / "audit.jsonl").read_text()
    assert '"event":"skill_proposed"' in audit and '"event":"skill_feedback"' in audit  # agent-side learning is audited


def test_skill_store_rules(tmp_path):
    st = SkillStore(tmp_path / "m.db", {"max_pending_per_skill": 2})
    with pytest.raises(ValueError, match="kebab|a-z"):
        st.propose("Bad Name!", "network_analyst", "d", "b")
    with pytest.raises(ValueError, match="description"):
        st.propose("ok-name", "network_analyst", "", "b")
    st.propose("ok-name", "network_analyst", "d", "b1")
    st.propose("ok-name", "network_analyst", "d", "b2")
    with pytest.raises(ValueError, match="awaiting analyst review"):  # agents cannot flood the review queue
        st.propose("ok-name", "network_analyst", "d", "b3")
    assert st.propose("ok-name", "network_analyst", "d", "b2").get("duplicate")
    with pytest.raises(ValueError, match="belongs to network_analyst"):
        st.propose("ok-name", "forensicator", "d", "b4")
    # analyst-written skills are approved immediately; auto-approve mode for agent skills
    assert st.propose("analyst-one", "shared", "d", "b", source="analyst", author="op")["status"] == "approved"
    auto = SkillStore(tmp_path / "a.db", {"require_approval": False})
    assert auto.propose("auto-one", "network_analyst", "d", "b")["status"] == "approved"
    # SKILL.md round trip
    n = st.export_dir(tmp_path / "out")
    assert n == 1 and (tmp_path / "out" / "shared" / "analyst-one" / "SKILL.md").exists()
    other = SkillStore(tmp_path / "o.db")
    assert other.import_dir(tmp_path / "out", "op") == ["analyst-one v1"]
    assert other.get("analyst-one")["status"] == "active" and other.import_dir(tmp_path / "out", "op") == []


# ---------------------------------------------------------------------------
# dashboard: conversations (switch / new / delete with confirmation), replay, skills review
# ---------------------------------------------------------------------------
def test_dashboard_conversations_and_skills(tmp_path, monkeypatch):
    scripts = {"lead": [("SITREP-A", []), ("SITREP-B", [])]}
    dash, app = make(tmp_path, monkeypatch, scripts)
    with TestClient(app) as c:
        login(c)
        c.post("/api/message", json={"text": "first op"}, headers=H)
        wait_for(c, "run_end")
        st = c.get("/api/state").json()
        conv1 = st["conversation"]["id"]
        assert st["conversation"]["title"] == "first op"

        assert c.post("/api/conversations/new", json={}, headers=H).json()["ok"]
        st = c.get("/api/state").json()
        assert st["conversation"] is None
        c.post("/api/message", json={"text": "second op"}, headers=H)
        wait_for(c, "run_end", after=st["last_seq"])
        conv2 = c.get("/api/state").json()["conversation"]["id"]
        assert {x["id"] for x in c.get("/api/conversations").json()["conversations"]} == {conv1, conv2}

        # switching replays the saved feed of that conversation
        assert c.post(f"/api/conversations/{conv1}/open", json={}, headers=H).json()["ok"]
        evs = c.get("/api/events/poll?after=0").json()
        replay = [e for e in evs if e.get("replay")]
        assert replay[0]["kind"] == "analyst_message" and replay[0]["data"]["text"] == "first op"
        assert not any(e["data"].get("text") == "second op" for e in replay)

        # deletion needs an explicit confirmation carrying the conversation id
        assert c.post(f"/api/conversations/{conv2}/delete", json={}, headers=H).status_code == 400
        assert c.post(f"/api/conversations/{conv2}/delete", json={"confirm": conv2}, headers=H).json()["ok"]
        assert [x["id"] for x in c.get("/api/conversations").json()["conversations"]] == [conv1]
        assert c.post(f"/api/conversations/{conv1}/delete", json={"confirm": conv1}, headers=H).json()["ok"]
        assert c.get("/api/state").json()["conversation"] is None  # deleting the open one starts fresh

        # skills review from the browser
        st_ = dash.harness.skills
        v = st_.propose("dns-tunnel-check", "network_analyst", "Spot DNS tunnelling", "1. stack query length", author="SA-009")
        data = c.get("/api/skills").json()
        assert data["pending"][0]["name"] == "dns-tunnel-check" and "+1. stack query length" in data["pending"][0]["diff"]
        assert c.get("/api/state").json()["skills"]["pending_review"] == 1
        assert c.post(f"/api/skills/versions/{v['id']}", json={"action": "approve"}, headers={}).status_code == 403  # CSRF
        assert c.post(f"/api/skills/versions/{v['id']}", json={"action": "approve", "note": "good"}, headers=H).json()["ok"]
        assert c.get("/api/skills/dns-tunnel-check").json()["skill"]["active_version"] == 1
        assert c.post("/api/skills/dns-tunnel-check/action", json={"action": "rollback", "version": 7}, headers=H).status_code == 400
        assert c.post("/api/skills/dns-tunnel-check/action", json={"action": "retire"}, headers=H).json()["ok"]


def test_dashboard_restart_replays_saved_conversation(tmp_path, monkeypatch):
    dash, app = make(tmp_path, monkeypatch, {"lead": [("SITREP-1", [])]})
    with TestClient(app) as c:
        login(c)
        c.post("/api/message", json={"text": "remember me"}, headers=H)
        wait_for(c, "run_end")
    dash2 = Dashboard(dash.cfg, "WEB-1", token="test-token")
    with TestClient(create_app(dash2)) as c:
        login(c)
        evs = c.get("/api/events/poll?after=0").json()
        texts = [e["data"].get("text") for e in evs if e.get("replay")]
        assert "remember me" in texts and "SITREP-1" in texts
        assert c.get("/api/state").json()["conversation"]["title"] == "remember me"


# ---------------------------------------------------------------------------
# steering and stopping one subagent while the operation continues; telemetry for the status bar
# ---------------------------------------------------------------------------
class GateBackend(ScriptedBackend):
    def __init__(self, scripts):
        super().__init__(scripts)
        self.gate = asyncio.Event()

    async def chat(self, messages, tools):
        system = messages[0]["content"]
        if f"# Role: {NA}" in system and not self.gate.is_set():
            await self.gate.wait()
        if f"# Role: {EA}" in system:
            await asyncio.sleep(30)  # hangs until the analyst stops it
        return await super().chat(messages, tools)


def test_steer_and_stop_subagents(tmp_path, monkeypatch):
    cfg = load_config(write_config(tmp_path))
    scripts = {
        "lead": [("Two in parallel.", [("subagent_spawn", {"expert": "network_analyst", "task": "beacons"}),
                                       ("subagent_spawn", {"expert": "endpoint_analyst", "task": "ws01"})]),
                 ("SITREP: network done, endpoint stopped by the analyst.", [])],
        NA: [("checking", [("memory_search", {"query": "beacon"})]),
             ("done", [("submit_report", {"status": "completed", "summary": "beacon on 443"})])],
    }
    fake = GateBackend(scripts)
    monkeypatch.setattr(agent_mod, "make_backend", lambda profile: fake)
    events: list = []

    async def go():
        h = agent_mod.Harness(cfg, "STEER-1", on_event=lambda k, d: events.append((k, d)))
        await h.start()
        task = asyncio.create_task(h.mission("go"))
        for _ in range(200):
            await asyncio.sleep(0.02)
            if len(h.subagents) == 2 and all(s.job for s in h.subagents.values()):
                break
        na = next(s for s in h.subagents.values() if s.expert == "network_analyst")
        ea = next(s for s in h.subagents.values() if s.expert == "endpoint_analyst")
        h.steer_subagent(na.id, "focus on port 443", "tester")
        with pytest.raises(ValueError):
            h.steer_subagent(na.id, "   ", "tester")
        h.stop_subagent(ea.id, "tester")
        fake.gate.set()
        out = await asyncio.wait_for(task, 10)
        with pytest.raises(ValueError):
            h.stop_subagent(ea.id, "tester")  # no longer running
        await h.close()
        return h, na, ea, out

    h, na, ea, out = asyncio.run(go())
    assert "SITREP" in out
    # guidance reached the network analyst before its next model call
    assert any("[Guidance from the analyst" in str(m.get("content")) and "focus on port 443" in str(m.get("content"))
               for m in na.agent.messages)
    # the endpoint analyst was stopped alone; the lead got a 'stopped' report and finished the operation
    assert ea.status == "stopped" and na.status == "completed"
    lead_tool_out = "\n".join(t for t in tool_outputs(h.lead.messages))
    assert f"Report from {ea.id}" in lead_tool_out and "status: stopped" in lead_tool_out
    calls = {tc["id"] for m in ea.agent.messages if m.get("tool_calls") for tc in m["tool_calls"]}
    assert calls <= {m["tool_call_id"] for m in ea.agent.messages if m["role"] == "tool"}  # history still valid
    audit = (tmp_path / "cases" / "STEER-1" / "audit.jsonl").read_text()
    assert '"event":"subagent_steer"' in audit and '"event":"subagent_stopped"' in audit
    kinds = [k for k, _ in events]
    assert "subagent_steer" in kinds
    lead_tel = [d for k, d in events if k == "telemetry" and d["agent_id"] == "lead"]
    assert lead_tel and 0 <= lead_tel[-1]["context_pct"] <= 100
