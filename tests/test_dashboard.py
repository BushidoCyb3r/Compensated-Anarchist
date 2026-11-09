"""Dashboard API tests: auth, CSRF, live approval flow, stop/repair, verdicts, memory, audit."""

from __future__ import annotations

import sys
import time
from pathlib import Path

from starlette.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_harness import ScriptedBackend, write_config  # noqa: E402

from compensated_anarchist import agent as agent_mod  # noqa: E402
from compensated_anarchist.config import load_config  # noqa: E402
from compensated_anarchist.web.app import Dashboard, create_app  # noqa: E402

H = {"X-CA-Request": "1"}


def wait_for(client, kind, after=0, timeout=15):
    deadline = time.time() + timeout
    while time.time() < deadline:
        evs = client.get(f"/api/events/poll?after={after}").json()
        hit = [e for e in evs if e["kind"] == kind]
        if hit:
            return hit[0], evs
        time.sleep(0.1)
    raise AssertionError(f"no {kind} event")


def make(tmp_path, monkeypatch, scripts):
    cfg = load_config(write_config(tmp_path))
    fake = ScriptedBackend(scripts)
    monkeypatch.setattr(agent_mod, "make_backend", lambda profile: fake)
    dash = Dashboard(cfg, "WEB-1", token="test-token")
    return dash, create_app(dash)


def test_auth_csrf_and_headers(tmp_path, monkeypatch):
    dash, app = make(tmp_path, monkeypatch, {})
    with TestClient(app) as c:
        assert c.get("/api/state").status_code == 401
        assert c.get("/").status_code == 401
        assert c.get("/login?token=nope", follow_redirects=False).status_code == 401
        r = c.get("/login?token=test-token", follow_redirects=False)
        assert r.status_code == 303 and "httponly" in r.headers["set-cookie"].lower() and "samesite=strict" in r.headers["set-cookie"].lower()
        assert c.get("/api/state").status_code == 200
        page = c.get("/")
        assert page.status_code == 200 and "script-src 'self'" in page.headers["content-security-policy"]
        assert c.get("/static/app.js").status_code == 200
        assert c.get("/static/../app.py").status_code == 404
        # state-changing call without the CSRF header is refused
        assert c.post("/api/message", json={"text": "hi"}).status_code == 403
        st = c.get("/api/state").json()
        assert st["case"]["id"] == "WEB-1" and st["connectors"]["velociraptor"].startswith("connected")
        assert {e["name"] for e in st["experts"]} >= {"threat_hunter", "incident_responder"}


def test_mission_with_browser_approval(tmp_path, monkeypatch):
    scripts = {
        "lead": [("Isolating ws01.", [("delegate", {"expert": "incident_responder", "task": "isolate ws01"})]),
                 ("Containment was denied by the analyst; monitoring instead.", [])],
        "Incident Responder (containment / eradication / recovery)": [
            ("Action brief: quarantine ws01 - active C2.", [("velociraptor__quarantine_host", {"client_id": "C.1111111111111111"})]),
            ("Denied; recommending monitoring.", [])],
    }
    dash, app = make(tmp_path, monkeypatch, scripts)
    with TestClient(app) as c:
        c.get("/login?token=test-token")
        assert c.post("/api/message", json={"text": "contain ws01"}, headers=H).json()["ok"]
        assert c.post("/api/message", json={"text": "again"}, headers=H).status_code == 409  # one op at a time
        ev, _ = wait_for(c, "approval_request")
        req = ev["data"]
        assert req["tool"] == "velociraptor__quarantine_host" and "Action brief" in req["rationale"]
        assert c.get("/api/state").json()["pending"][0]["id"] == req["id"]
        r = c.post(f"/api/approvals/{req['id']}", json={"approve": False, "note": "mission window"}, headers=H)
        assert r.json()["ok"]
        end, evs = wait_for(c, "run_end")
        assert end["data"]["ok"]
        kinds = [e["kind"] for e in evs]
        assert {"analyst_message", "delegate", "decision", "expert_done", "approval_resolved"} <= set(kinds)
        audit = c.get("/api/audit").json()
        assert audit["verified"]
        denied = [r for r in audit["records"] if r["event"] == "roe_decision" and r["data"]["tool"] == "velociraptor__quarantine_host"]
        assert denied and not denied[0]["data"]["allowed"] and "mission window" in denied[0]["data"]["reason"]


def test_stop_repairs_history(tmp_path, monkeypatch):
    scripts = {"lead": [("Quarantining.", [("velociraptor__quarantine_host", {"client_id": "C.1111111111111111"})])]}
    dash, app = make(tmp_path, monkeypatch, scripts)
    with TestClient(app) as c:
        c.get("/login?token=test-token")
        c.post("/api/message", json={"text": "contain"}, headers=H)
        wait_for(c, "approval_request")
        assert c.post("/api/stop", json={}, headers=H).json()["ok"]
        end, _ = wait_for(c, "run_end")
        assert end["data"]["stopped"] or not end["data"]["ok"] or "denied" in str(end["data"]).lower()
        msgs = dash.harness.lead.messages
        calls = {tc["id"] for m in msgs if m.get("tool_calls") for tc in m["tool_calls"]}
        answered = {m["tool_call_id"] for m in msgs if m["role"] == "tool"}
        assert calls <= answered  # no dangling tool calls -> next turn is valid
        assert not dash.pending


def test_verdict_memory_and_tools(tmp_path, monkeypatch):
    dash, app = make(tmp_path, monkeypatch, {})
    with TestClient(app) as c:
        c.get("/login?token=test-token")
        dash.harness.case.add_finding("Odd PowerShell", "medium", "encoded command from backup agent")
        fid = dash.harness.case.data["findings"][0]["id"]
        assert c.post("/api/verdict", json={"finding_id": fid, "verdict": "benign", "note": "backup software"}, headers=H).json()["ok"]
        assert c.post("/api/verdict", json={"finding_id": fid, "verdict": "bogus"}, headers=H).status_code == 400
        mem = c.get("/api/memory?status=approved").json()
        assert any(m["kind"] == "false_positive" for m in mem)
        r = c.post("/api/remember", json={"kind": "environment", "title": "DCs", "content": "10.1.1.5 and 10.1.1.6"}, headers=H)
        assert r.json()["ok"]
        cand = dash.harness.memory.add("lesson", "agent lesson", "x", source="agent")
        assert c.post(f"/api/memory/{cand}", json={"action": "promote"}, headers=H).json()["ok"]
        tools = c.get("/api/tools").json()
        assert any(t["name"] == "velociraptor__quarantine_host" and t["tier"] == "approve" for t in tools)
        assert c.post("/api/rate", json={"rating": 9}, headers=H).status_code == 400
        assert c.post("/api/rate", json={"rating": 5, "note": "good"}, headers=H).json()["ok"]
