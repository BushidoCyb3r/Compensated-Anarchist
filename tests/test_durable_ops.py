"""Durable operations: an operation cut off by a dashboard restart (or a crash) keeps its place and its pending
approvals, and can be resumed or ended; the analyst's Stop reaches every subagent and every process they started."""

from __future__ import annotations

import asyncio
import json
import os
import sys
import time
from pathlib import Path

from starlette.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_dashboard import H, login, wait_for  # noqa: E402
from test_harness import ScriptedBackend, write_config  # noqa: E402

from compensated_anarchist import agent as agent_mod  # noqa: E402
from compensated_anarchist.case import Case  # noqa: E402
from compensated_anarchist.config import load_config  # noqa: E402
from compensated_anarchist.tools.forensics import Forensics  # noqa: E402
from compensated_anarchist.web.app import Dashboard, create_app  # noqa: E402

NA = "Network Security Monitoring Analyst"
EA = "Endpoint / Live Response Analyst"
IR = "Incident Responder (containment / eradication / recovery)"
QUARANTINE = ("velociraptor__quarantine_host", {"client_id": "C.1111111111111111"})


def dashboard(cfg, monkeypatch, backend):
    monkeypatch.setattr(agent_mod, "make_backend", lambda profile: backend)
    dash = Dashboard(cfg, "DUR-1", token="test-token")
    return dash, create_app(dash)


def no_open_calls(messages):
    calls = {tc["id"] for m in messages if m.get("tool_calls") for tc in m["tool_calls"]}
    return calls <= {m["tool_call_id"] for m in messages if m["role"] == "tool"}


def wait_live(c, kind, timeout=15):
    """The first event of this kind that happened in this dashboard (not one replayed from before a restart)."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        evs = c.get("/api/events/poll?after=0").json()
        hit = [e for e in evs if e["kind"] == kind and not e.get("replay")]
        if hit:
            return hit[0], evs
        time.sleep(0.1)
    raise AssertionError(f"no live {kind} event")


def poll_until(c, pred, timeout=15):
    deadline = time.time() + timeout
    while time.time() < deadline:
        st = c.get("/api/state").json()
        if pred(st):
            return st
        time.sleep(0.1)
    raise AssertionError("condition not reached")


# ---------------------------------------------------------------------------
# a restart while an approval waits: the approval comes back, and deciding it carries the operation on
# ---------------------------------------------------------------------------
def test_pending_approval_survives_a_restart(tmp_path, monkeypatch):
    cfg = load_config(write_config(tmp_path))
    first = ScriptedBackend({
        "lead": [("Network check and containment in parallel.",
                  [("subagent_spawn", {"expert": "network_analyst", "task": "beacons from ws01"}),
                   ("subagent_spawn", {"expert": "incident_responder", "task": "isolate ws01"})])],
        NA: [("Checked.", [("submit_report", {"status": "completed", "summary": "beacon to 203.0.113.9 on 443"})])],
        IR: [("Action brief: quarantine ws01, active C2.", [QUARANTINE])],
    })
    dash, app = dashboard(cfg, monkeypatch, first)
    with TestClient(app) as c:
        login(c)
        assert c.post("/api/message", json={"text": "contain ws01"}, headers=H).json()["ok"]
        req, _ = wait_for(c, "approval_request")
        poll_until(c, lambda st: any(s["expert"] == "network_analyst" and s["status"] == "completed" for s in st["subagents"]))
        aid = req["data"]["id"]
    # the dashboard stopped with the approval still waiting: nothing was denied, the operation is interrupted
    store = dash.harness.history
    conv = dash.harness.conversation["id"]
    assert store.op_latest(conv)["status"] == "interrupted"
    assert [r["id"] for r in store.approvals(conv, ("pending",))] == [aid]

    second = ScriptedBackend({
        IR: [("Quarantined ws01.", [("submit_report", {"status": "completed", "summary": "ws01 quarantined"})])],
        "lead": [("SITREP: beacon confirmed, ws01 quarantined.", [])],
    })
    dash2, app2 = dashboard(cfg, monkeypatch, second)
    with TestClient(app2) as c:
        login(c)
        st = c.get("/api/state").json()
        assert st["interrupted"]["resumable"] and st["interrupted"]["waiting"] == 1
        restored = st["pending"][0]
        assert restored["id"] == aid and restored["restored"] and restored["tool"] == QUARANTINE[0]
        assert "Action brief" in restored["rationale"]
        # approving it is the go-ahead: the operation resumes and the decision is applied, not asked again
        assert c.post(f"/api/approvals/{aid}", json={"approve": True, "note": "window agreed"}, headers=H).json()["ok"]
        end, evs = wait_live(c, "run_end")
        assert end["data"]["ok"] and "SITREP" in end["data"]["text"]
        kinds = [e["kind"] for e in evs if not e.get("replay")]
        assert "operation_resumed" in kinds and "subagent_resumed" in kinds
        assert not [e for e in evs if e["kind"] == "approval_request" and not e.get("replay")]  # not asked twice
        st = c.get("/api/state").json()
        assert st["interrupted"] is None and not st["pending"]
        audit = c.get("/api/audit?limit=2000").json()
        assert audit["verified"]
        q = [r["data"] for r in audit["records"] if r["event"] == "roe_decision" and r["data"]["tool"] == QUARANTINE[0]]
        assert len(q) == 1 and q[0]["allowed"] and "decided while the operation was interrupted" in q[0]["reason"]
        assert any(r["event"] == "approval_decided_after_restart" and r["data"]["by"] == "analyst" for r in audit["records"])
    h = dash2.harness
    # the network analyst had finished: its report was reused, it never ran again
    assert NA not in second.seen
    lead_out = "\n".join(m["content"] for m in h.lead.messages if m["role"] == "tool")
    assert lead_out.count("beacon to 203.0.113.9") == 1 and "ws01 quarantined" in lead_out
    assert no_open_calls(h.lead.messages)
    ir = next(s for s in h.subagents.values() if s.expert == "incident_responder")
    assert ir.status == "completed" and sum(1 for m in ir.agent.messages if m["role"] == "user") == 1  # one brief
    assert h.history.approvals(h.conversation["id"], ("approved",))[0]["decided_by"] == "analyst"
    assert h.history.op_latest(h.conversation["id"])["status"] == "done"


# ---------------------------------------------------------------------------
# a restart while a subagent is thinking: Resume carries it on; End closes it instead
# ---------------------------------------------------------------------------
class HangingBackend(ScriptedBackend):
    """A subagent's model call that never returns (until the dashboard stops)."""

    def __init__(self, scripts, hang_for):
        super().__init__(scripts)
        self.hang_for = hang_for
        self.started = asyncio.Event()
        self.cancelled = 0

    async def chat(self, messages, tools, on_delta=None):
        if f"# Role: {self.hang_for}" in messages[0]["content"]:
            self.started.set()
            try:
                await asyncio.sleep(3600)
            except asyncio.CancelledError:
                self.cancelled += 1
                raise
        return await super().chat(messages, tools, on_delta)


def interrupt_mid_subagent(tmp_path, monkeypatch):
    cfg = load_config(write_config(tmp_path))
    first = HangingBackend({"lead": [("Tasking the endpoint analyst.",
                                      [("subagent_spawn", {"expert": "endpoint_analyst", "task": "triage ws01"})])]}, EA)
    dash, app = dashboard(cfg, monkeypatch, first)
    with TestClient(app) as c:
        login(c)
        c.post("/api/message", json={"text": "triage ws01"}, headers=H)
        poll_until(c, lambda st: any(s["status"] == "running" for s in st["subagents"]))
    assert first.cancelled == 1
    return cfg


def test_resume_after_a_restart_mid_subagent(tmp_path, monkeypatch):
    cfg = interrupt_mid_subagent(tmp_path, monkeypatch)
    second = ScriptedBackend({EA: [("Done.", [("submit_report", {"status": "completed", "summary": "ws01 clean"})])],
                              "lead": [("SITREP: ws01 clean.", [])]})
    dash, app = dashboard(cfg, monkeypatch, second)
    with TestClient(app) as c:
        login(c)
        st = c.get("/api/state").json()
        assert st["interrupted"]["resumable"] and st["interrupted"]["waiting"] == 0
        assert [s["status"] for s in st["subagents"]] == ["interrupted"]
        evs = c.get("/api/events/poll?after=0").json()
        assert any(e["kind"] == "run_end" and e["data"].get("interrupted") for e in evs)  # the feed says why
        assert c.post("/api/operation/resume", json={}, headers=H).json()["ok"]
        end, _ = wait_live(c, "run_end")
        assert end["data"]["ok"] and "ws01 clean" in end["data"]["text"]
    h = dash.harness
    ea = next(iter(h.subagents.values()))
    briefs = [m for m in ea.agent.messages if m["role"] == "user"]
    assert len(briefs) == 1 and "triage ws01" in briefs[0]["content"]  # resumed from its brief, not re-tasked
    assert len(h.subagents) == 1 and no_open_calls(h.lead.messages)


def test_end_an_interrupted_operation_then_carry_on(tmp_path, monkeypatch):
    cfg = interrupt_mid_subagent(tmp_path, monkeypatch)
    second = ScriptedBackend({"lead": [("Fresh start on the new question.", [])]})
    dash, app = dashboard(cfg, monkeypatch, second)
    with TestClient(app) as c:
        login(c)
        assert c.get("/api/state").json()["interrupted"]
        assert c.post("/api/operation/end", json={}, headers=H).json()["ok"]
        st = c.get("/api/state").json()
        assert st["interrupted"] is None
        assert c.post("/api/operation/resume", json={}, headers=H).status_code == 400  # nothing left to resume
        assert c.post("/api/message", json={"text": "new question"}, headers=H).json()["ok"]
        poll_until(c, lambda st: not st["running"] and st["conversation"])
    h = dash.harness
    assert no_open_calls(h.lead.messages)
    assert "NOT EXECUTED - the operation was interrupted and then ended" in json.dumps(h.lead.messages)
    assert h.history.op_latest(h.conversation["id"])["status"] == "done"


def test_a_new_message_ends_the_interrupted_operation(tmp_path, monkeypatch):
    cfg = interrupt_mid_subagent(tmp_path, monkeypatch)
    dash, app = dashboard(cfg, monkeypatch, ScriptedBackend({"lead": [("On it.", [])]}))
    with TestClient(app) as c:
        login(c)
        assert c.post("/api/message", json={"text": "something else"}, headers=H).json()["ok"]
        poll_until(c, lambda st: not st["running"])
        texts = [e["data"].get("text", "") for e in c.get("/api/events/poll?after=0").json() if e["kind"] == "run_end"]
        assert any("a new request was started instead" in t for t in texts)
    assert no_open_calls(dash.harness.lead.messages)


# ---------------------------------------------------------------------------
# the analyst's Stop reaches every subagent: running, queued, and the processes they started
# ---------------------------------------------------------------------------
def test_stop_cancels_running_and_queued_subagents(tmp_path, monkeypatch):
    cfg = load_config(write_config(tmp_path))
    cfg.orchestration["max_parallel"] = 1  # the second subagent waits for a slot
    fake = HangingBackend({"lead": [("Two tasks.", [("subagent_spawn", {"expert": "endpoint_analyst", "task": "ws01"}),
                                                    ("subagent_spawn", {"expert": "network_analyst", "task": "beacons"})])]}, EA)
    dash, app = dashboard(cfg, monkeypatch, fake)
    with TestClient(app) as c:
        login(c)
        c.post("/api/message", json={"text": "go"}, headers=H)
        st = poll_until(c, lambda st: sorted(s["status"] for s in st["subagents"]) == ["queued", "running"])
        assert c.post("/api/stop", json={}, headers=H).json()["ok"]
        end, _ = wait_for(c, "run_end")
        assert end["data"]["stopped"]
        st = c.get("/api/state").json()
        assert not st["running"] and st["interrupted"] is None  # Stop ends it for good; nothing to resume
    h = dash.harness
    assert fake.cancelled == 1 and NA not in fake.seen  # the queued one never started
    for sa in h.subagents.values():
        assert sa.status == "interrupted" and (sa.job is None or sa.job.done())
        assert no_open_calls(sa.agent.messages)
    assert h.history.op_latest(h.conversation["id"])["status"] == "stopped"


def test_stop_one_queued_subagent(tmp_path, monkeypatch):
    cfg = load_config(write_config(tmp_path))
    cfg.orchestration["max_parallel"] = 1
    fake = HangingBackend({"lead": [("Two tasks.", [("subagent_spawn", {"expert": "endpoint_analyst", "task": "ws01"}),
                                                    ("subagent_spawn", {"expert": "network_analyst", "task": "beacons"})])]}, EA)
    dash, app = dashboard(cfg, monkeypatch, fake)
    with TestClient(app) as c:
        login(c)
        c.post("/api/message", json={"text": "go"}, headers=H)
        st = poll_until(c, lambda st: sorted(s["status"] for s in st["subagents"]) == ["queued", "running"])
        queued = next(s["id"] for s in st["subagents"] if s["status"] == "queued")
        running = next(s["id"] for s in st["subagents"] if s["status"] == "running")
        assert c.post(f"/api/subagents/{queued}/stop", json={}, headers=H).json()["ok"]
        assert c.post(f"/api/subagents/{running}/stop", json={}, headers=H).json()["ok"]
        end, _ = wait_for(c, "run_end")
        assert end["data"]["ok"]  # the lead carried on with two 'stopped' reports
    assert NA not in fake.seen
    assert {s.status for s in dash.harness.subagents.values()} == {"stopped"}


def test_cancelling_a_forensic_tool_kills_its_processes(tmp_path):
    pidfile = tmp_path / "pid"
    child = ("import os, subprocess, sys, time; p = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)']); "
             f"open({str(pidfile)!r}, 'w').write(f'{{os.getpid()}} {{p.pid}}'); time.sleep(60)")
    f = Forensics({}, [tmp_path], Case(tmp_path / "cases", "KILL-1"))

    async def go():
        task = asyncio.create_task(f._run([sys.executable, "-c", child], timeout=120))
        for _ in range(100):
            await asyncio.sleep(0.05)
            if pidfile.exists() and len(pidfile.read_text().split()) == 2:
                break
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        await asyncio.sleep(0.3)

    asyncio.run(go())
    for pid in map(int, pidfile.read_text().split()):  # the tool and the worker it started are both gone
        try:
            state = Path(f"/proc/{pid}/stat").read_text().split(") ")[1][0]
        except (FileNotFoundError, IndexError):
            continue
        assert state in ("Z", "X"), f"pid {pid} still running ({state})"


# ---------------------------------------------------------------------------
# the CLI: an operation cut off by Ctrl+C or a crash can be resumed in a later session
# ---------------------------------------------------------------------------
def test_cli_resume_after_a_crash(tmp_path, monkeypatch):
    cfg = load_config(write_config(tmp_path))

    async def crash():
        fake = HangingBackend({"lead": [("Tasking.", [("subagent_spawn", {"expert": "endpoint_analyst", "task": "ws01"})])]}, EA)
        monkeypatch.setattr(agent_mod, "make_backend", lambda profile: fake)
        h = agent_mod.Harness(cfg, "CLI-1", interactive=False)
        await h.start()
        task = asyncio.create_task(h.operation("mission", lambda: h.mission("triage ws01"), "mission"))
        await asyncio.wait_for(fake.started.wait(), 10)
        task.cancel()  # Ctrl+C
        try:
            await task
        except asyncio.CancelledError:
            pass
        await h.close()

    async def later():
        fake = ScriptedBackend({EA: [("ok", [("submit_report", {"status": "completed", "summary": "ws01 clean"})])],
                                "lead": [("SITREP: clean.", [])]})
        monkeypatch.setattr(agent_mod, "make_backend", lambda profile: fake)
        h = agent_mod.Harness(cfg, "CLI-1", interactive=False)
        await h.start()
        op = h.interrupted_operation()
        assert op and op["resumable"] and op["status"] == "interrupted"
        out = await h.operation("resume", h.resume)
        assert h.interrupted_operation() is None
        await h.close()
        return out

    asyncio.run(crash())
    assert "SITREP" in asyncio.run(later())


# ---------------------------------------------------------------------------
# in the browser: the restored approval and the Resume / End banner after a restart
# ---------------------------------------------------------------------------
def test_restart_banner_in_the_browser(tmp_path, monkeypatch):
    import pytest
    from test_accessibility import CHROME, Served, screenshot

    if CHROME is None:
        pytest.skip("no Chrome/Chromium on this host")
    cfg = load_config(write_config(tmp_path))
    first = ScriptedBackend({"lead": [("Containment.", [("subagent_spawn", {"expert": "incident_responder", "task": "isolate ws01"})])],
                             IR: [("Action brief: quarantine ws01.", [QUARANTINE])]})
    dash, app = dashboard(cfg, monkeypatch, first)
    with TestClient(app) as c:
        login(c)
        c.post("/api/message", json={"text": "contain ws01"}, headers=H)
        wait_for(c, "approval_request")
    second = ScriptedBackend({IR: [("Done.", [("submit_report", {"status": "completed", "summary": "ws01 quarantined"})])],
                              "lead": [("SITREP: ws01 quarantined.", [])]})
    monkeypatch.setattr(agent_mod, "make_backend", lambda profile: second)
    dash2 = Dashboard(cfg, "DUR-1", token="test-token")
    out = Path(os.environ.get("CA_SCREENSHOTS", tmp_path))
    with Served(dash2, tmp_path) as chrome:
        banner = chrome.wait("!document.querySelector('.banner.resume').hidden && document.querySelector('.banner.resume').textContent")
        assert "Interrupted by a restart" in banner and "Deciding it carries the operation on" in banner
        assert chrome.js("[...document.querySelectorAll('.banner.resume button')].map((b) => b.textContent).join(',')") == "Resume,End it"
        assert "before the dashboard restarted" in chrome.js("document.querySelector('.banner:not(.resume)').textContent")
        assert chrome.js("!document.querySelector('.approval .toolbar').hidden")  # the replayed card is live again
        assert not any(chrome.js("__a11y.audit()").values())
        screenshot(chrome, out / "restart_banner.png")
        chrome.js("[...document.querySelectorAll('.banner .btn-primary')].find((b) => b.textContent === 'Review').click(); true")
        chrome.wait("!!document.querySelector('[role=dialog] .warn-card')")
        screenshot(chrome, out / "restart_approval_dialog.png")
        # Approve arms on the first press and confirms on the second
        chrome.js("const b = [...document.querySelectorAll('[role=dialog] .btn-primary')].find((x) => x.textContent === 'Approve'); b.click(); b.click(); true")
        chrome.wait("document.querySelector('.feed').textContent.includes('SITREP: ws01 quarantined.')")
        assert chrome.wait("document.querySelector('.banner.resume').hidden")
        assert "applies as the operation resumes" in chrome.js("document.querySelector('.approval .result').textContent")
        assert "Resumed the interrupted operation" in chrome.js("document.querySelector('.feed').textContent")
        screenshot(chrome, out / "restart_resumed.png")
