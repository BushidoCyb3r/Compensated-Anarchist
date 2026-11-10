"""Dashboard API tests: auth, CSRF, live approval flow, stop/repair, verdicts, memory, audit."""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import pytest
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


def login(c, token="test-token", consent=None):
    body = {"token": token}
    if consent is not None:
        body["consent"] = consent
    return c.post("/api/login", json=body, headers=H)


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
        assert c.get("/", follow_redirects=False).headers["location"] == "/login"  # unauthenticated -> sign-in page
        page = c.get("/login?token=test-token")
        assert page.status_code == 200 and "set-cookie" not in page.headers  # a GET never signs you in
        assert c.get("/api/state").status_code == 401
        assert c.post("/api/login", json={"token": "test-token"}).status_code == 403  # CSRF header required
        assert login(c, "nope").status_code == 401
        r = login(c)
        assert r.status_code == 200 and "httponly" in r.headers["set-cookie"].lower() and "samesite=strict" in r.headers["set-cookie"].lower()
        assert c.get("/api/state").status_code == 200
        page = c.get("/")
        assert page.status_code == 200 and "script-src 'self'" in page.headers["content-security-policy"]
        for asset in ("app.js", "app.css", "login.js", "logo.svg", "favicon.svg"):
            assert c.get(f"/static/{asset}").status_code == 200
        assert c.get("/static/../app.py").status_code == 404
        # state-changing call without the CSRF header is refused
        assert c.post("/api/message", json={"text": "hi"}).status_code == 403
        st = c.get("/api/state").json()
        assert st["case"]["id"] == "WEB-1" and st["connectors"]["velociraptor"].startswith("connected")
        assert {e["name"] for e in st["experts"]} >= {"threat_hunter", "incident_responder"}
        assert c.post("/api/logout", json={}, headers=H).json()["ok"]
        assert c.get("/api/state").status_code == 401
        audit = (tmp_path / "cases" / "WEB-1" / "audit.jsonl").read_text()
        assert '"event":"dashboard_login"' in audit


def test_consent_banner_and_login_throttle(tmp_path, monkeypatch):
    cfg = load_config(write_config(tmp_path))
    cfg.raw["dashboard"] = {"classification": {"text": "UNCLASSIFIED"}, "consent_text": "You are accessing a monitored system."}
    monkeypatch.setattr(agent_mod, "make_backend", lambda profile: ScriptedBackend({}))
    app = create_app(Dashboard(cfg, "WEB-2", token="test-token"))
    with TestClient(app) as c:
        info = c.get("/api/public").json()
        assert info["consent_text"].startswith("You are accessing") and info["classification"]["text"] == "UNCLASSIFIED"
        assert not info["authed"]
        assert login(c).status_code == 400  # consent not acknowledged
        assert login(c, consent=True).status_code == 200
        assert c.get("/api/state").json()["ui"]["classification"]["background"] == "#007a33"
        for _ in range(10):
            assert login(c, "wrong", True).status_code == 401
        assert login(c, "test-token", True).status_code == 429  # throttled after repeated failures


def test_mission_with_browser_approval(tmp_path, monkeypatch):
    scripts = {
        "lead": [("Isolating ws01.", [("subagent_spawn", {"expert": "incident_responder", "task": "isolate ws01"})]),
                 ("Containment was denied by the analyst; monitoring instead.", [])],
        "Incident Responder (containment / eradication / recovery)": [
            ("Action brief: quarantine ws01 - active C2.", [("velociraptor__quarantine_host", {"client_id": "C.1111111111111111"})]),
            ("Denied; recommending monitoring.", [])],
    }
    dash, app = make(tmp_path, monkeypatch, scripts)
    with TestClient(app) as c:
        login(c)
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
        assert {"analyst_message", "subagent_spawn", "decision", "subagent_report", "approval_resolved"} <= set(kinds)
        audit = c.get("/api/audit").json()
        assert audit["verified"]
        denied = [r for r in audit["records"] if r["event"] == "roe_decision" and r["data"]["tool"] == "velociraptor__quarantine_host"]
        assert denied and not denied[0]["data"]["allowed"] and "mission window" in denied[0]["data"]["reason"]


def test_stop_repairs_history(tmp_path, monkeypatch):
    scripts = {"lead": [("Quarantining.", [("velociraptor__quarantine_host", {"client_id": "C.1111111111111111"})])]}
    dash, app = make(tmp_path, monkeypatch, scripts)
    dash.cfg.orchestration["lead_tools"] = ["*"]  # this test has the lead act directly (the default lead delegates)
    with TestClient(app) as c:
        login(c)
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
        login(c)
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


def test_classification_banner_setting(tmp_path, monkeypatch):
    dash, app = make(tmp_path, monkeypatch, {})
    with TestClient(app) as c:
        login(c)
        st = c.get("/api/state").json()["ui"]
        assert st["classification"]["text"] == "" and st["classification_source"] == "config"  # off by default
        url = "/api/settings/classification"
        secret = {"text": "  SECRET//NOFORN ", "background": "#C8102E", "color": "#ffffff"}
        assert c.post(url, json=secret).status_code == 403  # CSRF header required
        assert c.post(url, json={**secret, "background": "red"}, headers=H).status_code == 400
        assert c.post(url, json={**secret, "text": "S" * 121}, headers=H).status_code == 400
        r = c.post(url, json=secret, headers=H).json()
        assert r["classification"] == {"text": "SECRET//NOFORN", "background": "#c8102e", "color": "#ffffff"} and r["source"] == "settings"
        assert c.get("/api/public").json()["classification"]["text"] == "SECRET//NOFORN"  # the sign-in page shows it too
        assert c.get("/api/state").json()["ui"]["classification_source"] == "settings"
        lines = [json.loads(x) for x in (dash.harness.case.dir / "audit.jsonl").read_text().splitlines()]
        rec = [x for x in lines if x.get("action") == "dashboard_setting" or x.get("event") == "dashboard_setting"]
        assert rec, "banner change was not audited"
        saved = dash.settings_path
        assert saved.exists() and (saved.stat().st_mode & 0o777) == 0o600

    # survives a restart (a new Dashboard reads the saved setting)
    dash2 = Dashboard(dash.cfg, "WEB-1", token="test-token", harness=dash.harness)
    assert dash2.ui["classification"]["text"] == "SECRET//NOFORN" and dash2.classification_source() == "settings"
    assert dash2.set_classification(None)["text"] == "" and dash2.classification_source() == "config"  # back to the yaml default
    assert Dashboard(dash.cfg, "WEB-1", token="test-token", harness=dash.harness).ui["classification"]["text"] == ""

    # a config can lock it: the yaml value wins over a saved one, and the UI cannot change it
    dash2.set_classification({"text": "CUI", "background": "#502b85", "color": "#ffffff"})
    dash.cfg.raw["dashboard"] = {"classification": {"text": "UNCLASSIFIED", "locked": True}}
    dash3 = Dashboard(dash.cfg, "WEB-1", token="test-token", harness=dash.harness)
    assert dash3.ui["classification"]["text"] == "UNCLASSIFIED" and dash3.classification_source() == "locked"
    with pytest.raises(ValueError, match="locked"):
        dash3.set_classification({"text": "SECRET", "background": "#c8102e", "color": "#ffffff"})
    dash.cfg.raw["dashboard"] = {"classification": {"text": "SECRET", "background": "crimson"}}
    with pytest.raises(ValueError, match="harness.yaml"):
        Dashboard(dash.cfg, "WEB-1", token="test-token", harness=dash.harness)
