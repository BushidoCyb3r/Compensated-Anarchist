"""The Archer connector against a stand-in Archer over real HTTPS: certificate pinning, one cached login, one
re-login on 401, back-off on 429, reads only (writes refused before they are sent), capped results, server errors
surfaced, and attacker-written text cleaned and cut with an explicit flag."""

from __future__ import annotations

import importlib
import json
import shutil
import sys
from pathlib import Path

import pytest
from mcp.server.mcpserver.exceptions import ToolError

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fake_archer import PASSWORD, FakeArcher  # noqa: E402

pytestmark = pytest.mark.skipif(not shutil.which("openssl"), reason="openssl is needed for the fake Archer")


@pytest.fixture
def archer(tmp_path):
    with FakeArcher(tmp_path) as fake:
        yield fake


def load(monkeypatch, fake: FakeArcher, **env):
    base = {"ARCHER_URL": fake.url, "ARCHER_EMAIL": "ca@example.test", "ARCHER_PASSWORD": PASSWORD,
            "ARCHER_TLS_FINGERPRINT": fake.fingerprint, "ARCHER_VERIFY": "true"}
    for k, v in {**base, **env}.items():
        monkeypatch.setenv(k, v)
    return importlib.reload(importlib.import_module("compensated_anarchist.servers.archer"))


def gets(fake: FakeArcher, path: str) -> list[dict]:
    return [q for m, p, q in fake.log if m == "GET" and p == path]


def test_reads_with_one_login(monkeypatch, archer):
    m = load(monkeypatch, archer)
    outputs = []

    def call(fn, *a, **k):
        out = fn(*a, **k)
        outputs.append(out)
        return json.loads(out)

    chk = call(m.connection_check)
    assert chk["role_ok"] and chk["account"] == {"name": "Compensated Anarchist", "role": "viewer", "status": "active"}
    assert chk["version"]["version"] == "v0.55.0" and chk["tls"].startswith("pinned")
    assert chk["certificate_sha256"] == archer.fingerprint and chk["analysis"]["state"] == "running"
    assert not gets(archer, "/api/sensors/info")  # admin-only in Archer: a Viewer never calls it

    ov = call(m.overview, start="7d", q="type:beacons")
    assert ov["counts"]["total"] == 295 and ov["facets"]["types"] == ["Beacon", "Data Exfiltration"]
    assert len(ov["trend"]["days"]) == 60 and len(ov["trend"]["series"]["beaconing"]) == 60
    assert ov["trend"]["series"]["beaconing"][-1] == 89 and "last 60 of 90 days" in ov["trend"]["truncated"]
    for path in ("/api/findings/counts", "/api/findings/facets", "/api/findings/trend"):
        assert gets(archer, path)[-1]["q"] == ["type:beacons"] and len(gets(archer, path)[-1]["from"][0]) == 19

    hosts = call(m.list_hosts, limit=2, start="24h")
    assert hosts["total"] == 5 and hosts["returned"] == 2 and "3 more hosts" in hosts["omitted"]
    assert "from" in gets(archer, "/api/hosts")[-1]
    camp = call(m.list_campaigns)["campaigns"][0]
    assert camp["srcs"] == ["10.0.5.1", "10.0.5.2"] and camp["hosts"] == 2

    # the tool layer caps the page size whatever the agent asks for; the totals come from Archer's headers
    f = call(m.list_findings, limit=100000, start="24h", src_ip="10.0.5.0/24", ioc_only=True, severity="high",
             dst_port="80, 443", status="Escalated", direction="ASC", sort="timestamp")
    sent = gets(archer, "/api/findings")[-1]
    assert sent["limit"] == ["200"] and sent["src_ip"] == ["10.0.5.0/24"] and sent["ioc_only"] == ["true"]
    assert sent["severity"] == ["HIGH"] and sent["dst_port"] == ["80,443"] and sent["status"] == ["escalated"]
    assert sent["dir"] == ["asc"] and sent["sort"] == ["timestamp"] and len(sent["from"][0]) == 19
    # 200 rows do not fit the agent's budget: whole rows are dropped, and the answer says where to continue
    assert f["total"] == 300 and 10 < f["returned"] < 200 and f["has_more"] is True
    assert f["next_offset"] == f["returned"] and "rows left out" in f["cut_for_size"]
    first = f["findings"][0]  # attacker-written detail: control characters gone, cut, and flagged
    assert set(first["_truncated"]) == {"detail"} and first["_truncated"]["detail"] > 200 and len(first["detail"]) == 200
    assert "\x1b" not in first["detail"] and "\u202e" not in first["detail"] and "ignore all previous" in first["detail"]
    assert first["status"] == "open" and "analyst_note" not in first  # "" means open; other empty fields dropped
    assert first["id"] == 1 and first["dst_port"] == "443"
    nxt = call(m.list_findings, limit=20, offset=f["next_offset"])
    assert gets(archer, "/api/findings")[-1]["offset"] == [str(f["returned"])] and nxt["returned"] == 20
    last = call(m.list_findings, limit=200, offset=290)
    assert last["returned"] == 10 and last["has_more"] is False and "next_offset" not in last

    d = call(m.get_finding, 1)
    iv = d["intervals"]
    assert iv["count"] == 500 and iv["min"] == 60 and iv["max"] == 62 and iv["cv"] < 0.05 and len(iv["first"]) == 40
    assert d["ts_data"]["count"] == 300 and d["ts_data"]["first"][0] == [1794400000, 500, 2000]
    assert d["ts_score"] == 0.92 and d["fp_concern"] == "critical" and d["status"] == "open"
    assert len(d["detail"]) == 600 and d["_truncated"]["detail"] > 600  # the full view keeps more of it
    note = d["notes"][0]
    assert "\x07" not in note["text"] and note["_truncated"]["text"] > 600

    raw = call(m.get_raw_records, "1", limit=10000, window_hours=999)
    assert gets(archer, "/api/findings/1/raw")[-1] == {"limit": ["200"], "window_hours": ["168"]}
    assert raw["records"][0]["_truncated"]["user_agent"] > 300 and "window_hours" in raw["cut_for_size"]
    assert "service" not in raw["records"][0]  # Zeek's '-' (unset) is left out
    hist = call(m.get_pair_history, 1)
    assert hist["days"] == 30 and hist["history"][0]["day_utc"] == "2026-10-01"
    assert "only Beacon and HTTP Beacon" in call(m.get_pair_history, 2)["note"]
    health = call(m.sensor_health)
    assert len(health["sensors"]) == 2 and health["stale"] == ["sensor2"]
    assert "mid-refresh" in call(m.analysis_status)["note"]
    assert all(len(o) <= m.MAX_CHARS for o in outputs)  # never spilled or cut mid-JSON by the harness

    assert archer.logins == 1  # one login for the whole session (logins are rate limited)
    assert {meth for meth, p, _ in archer.log if p != "/login"} == {"GET"}
    assert not any(PASSWORD in o for o in outputs)


def test_expired_session_relogs_in_exactly_once(monkeypatch, archer):
    m = load(monkeypatch, archer)
    m.list_hosts()
    assert archer.logins == 1
    archer.expire()  # the session ended (24 hours, or Archer restarted)
    assert json.loads(m.list_hosts())["total"] == 5
    assert archer.logins == 2 and len(gets(archer, "/api/hosts")) == 3  # first try, 401, one retry
    archer.unauthorized.add("/api/hosts")  # still 401 after a fresh login: one login, one retry, then fail
    with pytest.raises(ToolError, match="again right after a fresh login"):
        m.list_hosts()
    assert archer.logins == 3 and len(gets(archer, "/api/hosts")) == 5
    archer.unauthorized.clear()
    # a new session refused at once is a session problem, not the account: a later call logs in again
    archer.expire()
    archer.reject_sessions = True
    with pytest.raises(ToolError, match="right after a fresh login.*GET /api/me"):
        m.overview()
    archer.reject_sessions = False
    assert json.loads(m.overview())["counts"]["total"] == 295 and archer.logins == 5


def test_writes_are_refused_before_they_are_sent(monkeypatch, archer):
    m = load(monkeypatch, archer)
    m.list_hosts()
    before = list(archer.log)
    for method, path in [("POST", "/api/findings/bulk"), ("PATCH", "/api/findings/1"), ("DELETE", "/api/users/1"),
                         ("POST", "/api/analyze"), ("PUT", "/api/config"), ("POST", "/api/findings/1/escalate")]:
        with pytest.raises(m.Blocked, match="never writes"):
            m.client.request(method, path)
    for path in ["/api/users", "/api/service-tokens", "/api/admin/backup", "/api/findings/1/escalate",
                 "/api/findings/1/notes", "/api/findings/bulk", "/api/findings/abc", "/events", "/api/config",
                 "/api/sensors/info", "/api/export/json", "/api/findings/../users", "/api/findings/1/position"]:
        with pytest.raises(m.Blocked, match="read routes"):
            m.client.get(path)
    with pytest.raises(m.Blocked):
        m.client._send("POST", "/api/findings/bulk", form={"action": "dismiss"})  # the lowest layer refuses too
    for bad in ["../users", "1/escalate", "bulk", "counts", "f0001", "1" * 13, "", "-1"]:
        with pytest.raises(ToolError, match="finding_id"):
            m.get_finding(bad)
    assert archer.log == before  # nothing reached Archer
    # and if a write ever were sent, Archer refuses the Viewer: shown by a write made outside the connector
    import http.client
    import ssl
    ctx = ssl.create_default_context()
    ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
    c = http.client.HTTPSConnection("127.0.0.1", int(archer.url.rsplit(":", 1)[1]), context=ctx)
    cookie = "; ".join(f"{k.name}={k.value}" for k in m.client.jar)
    c.request("POST", "/api/findings/bulk", body=b'{"action":"dismiss"}',
              headers={"Cookie": cookie, "Content-Type": "application/json"})
    r = c.getresponse()
    assert r.status == 403 and json.loads(r.read()) == {"error": "forbidden"}


def test_server_errors_reach_the_agent(monkeypatch, archer):
    m = load(monkeypatch, archer)
    with pytest.raises(ToolError, match=r"HTTP 400.*query parse error: unbalanced parenthesis"):
        m.list_findings(q="type:(Beacon")  # surfaced, never an empty result
    archer.forbid.add("/api/sensors/health")
    with pytest.raises(ToolError, match="403 Forbidden.*connector bug"):
        m.sensor_health()
    with pytest.raises(ToolError, match="404.*finding not found"):
        m.get_finding(9999)
    for kwargs, name in [({"src_ip": "10.0.0.999"}, "src_ip"), ({"start": "yesterday"}, "start"),
                         ({"dst_port": "70000"}, "dst_port"), ({"dst_port": "443;rm"}, "dst_port"),
                         ({"min_score": 101}, "min_score"), ({"direction": "sideways"}, "direction"),
                         ({"severity": "urgent"}, "severity"), ({"status": "ack"}, "status"),
                         ({"sort": "detail"}, "sort"), ({"sensor": "s1\x00"}, "sensor")]:
        with pytest.raises(ToolError, match=name):
            m.list_findings(**kwargs)


def test_tls_pinning(monkeypatch, archer):
    m = load(monkeypatch, archer, ARCHER_TLS_FINGERPRINT="00" * 32)
    with pytest.raises(ToolError, match=f"does not match ARCHER_TLS_FINGERPRINT.*Presented: {archer.fingerprint}"):
        m.list_hosts()
    assert archer.log == [] and archer.logins == 0  # the credentials were never sent
    # no pin: the self-signed certificate fails verification, and the message gives its fingerprint to pin
    m = load(monkeypatch, archer, ARCHER_TLS_FINGERPRINT="")
    with pytest.raises(ToolError, match=f"failed verification.*{archer.fingerprint}.*ARCHER_TLS_FINGERPRINT"):
        m.list_hosts()
    assert archer.log == []
    # the pin may be written with colons, as openssl prints it
    colon = ":".join(archer.fingerprint[i:i + 2] for i in range(0, 64, 2)).upper()
    m = load(monkeypatch, archer, ARCHER_TLS_FINGERPRINT=colon)
    assert json.loads(m.list_hosts())["total"] == 5
    # a CA file that holds Archer's certificate also verifies it
    m = load(monkeypatch, archer, ARCHER_TLS_FINGERPRINT="", ARCHER_VERIFY=str(archer.cert))
    assert json.loads(m.list_hosts())["total"] == 5 and m.client.tls_mode.startswith("verified against")
    # skip-verify only when asked for, and it says so
    m = load(monkeypatch, archer, ARCHER_TLS_FINGERPRINT="", ARCHER_VERIFY="false")
    assert json.loads(m.list_hosts())["total"] == 5
    assert "NOT VERIFIED" in json.loads(m.connection_check())["tls"]


def test_login_refusals_and_back_off(monkeypatch, archer):
    m = load(monkeypatch, archer, ARCHER_PASSWORD="wrong")
    with pytest.raises(ToolError, match="did not accept the login.*ARCHER_EMAIL") as e:
        m.list_hosts()  # Archer's login page comes back without a session
    assert "wrong" not in str(e.value)
    with pytest.raises(ToolError, match="will not try again"):
        m.list_hosts()
    assert archer.logins == 1  # a refused login is not retried (rate limit, account lockout)

    m = load(monkeypatch, archer, ARCHER_EMAIL="admin@example.test")
    with pytest.raises(ToolError, match="must be a Viewer.*'admin'"):
        m.list_hosts()
    with pytest.raises(ToolError, match="must be a Viewer"):
        m.overview()
    assert archer.logins == 2

    archer.login_429 = True
    m = load(monkeypatch, archer)
    with pytest.raises(ToolError, match="rate-limited the login.*30 s"):
        m.list_hosts()
    archer.login_429 = False
    sent = len(archer.log)
    with pytest.raises(ToolError, match="Backing off"):
        m.list_hosts()  # fails at once, without reaching Archer
    assert len(archer.log) == sent and archer.logins == 3


def test_config_checks(monkeypatch, archer):
    for env, msg in [({"ARCHER_URL": "http://127.0.0.1:8443"}, "https"),
                     ({"ARCHER_TLS_FINGERPRINT": "abc"}, "64 hex")]:
        with pytest.raises(SystemExit, match=msg):
            load(monkeypatch, archer, **env)
    monkeypatch.delenv("ARCHER_PASSWORD", raising=False)
    monkeypatch.setenv("ARCHER_URL", archer.url)
    with pytest.raises(SystemExit):
        importlib.reload(importlib.import_module("compensated_anarchist.servers.archer"))


def test_through_the_harness(tmp_path, monkeypatch, archer):
    """As the harness runs it: the shipped harness.yaml block starts it as a stdio connector with its environment,
    its tools are archer__*, all `auto` under the shipped ROE, the three experts get them and the review skill,
    and a call comes back wrapped as untrusted data."""
    import asyncio

    import yaml

    from compensated_anarchist import agent as agent_mod
    from compensated_anarchist.config import load_config
    from compensated_anarchist.llm.base import ToolCall
    from test_harness import ROOT, write_config

    p = write_config(tmp_path)
    cfg = yaml.safe_load(p.read_text())
    shipped = yaml.safe_load((ROOT / "config" / "harness.yaml").read_text())["mcp_servers"]["archer"]
    cfg["mcp_servers"]["archer"] = shipped  # ${ARCHER_*} expanded from the environment, as in config/.env
    p.write_text(yaml.safe_dump(cfg))
    for k, v in {"ARCHER_ENABLED": "true", "ARCHER_URL": archer.url, "ARCHER_EMAIL": "ca@example.test",
                 "ARCHER_PASSWORD": PASSWORD, "ARCHER_TLS_FINGERPRINT": archer.fingerprint}.items():
        monkeypatch.setenv(k, v)

    async def run():
        h = agent_mod.Harness(load_config(p), "ARCHER-1", interactive=False)
        await h.start()
        try:
            assert h.mcp.status["archer"].startswith("connected"), h.mcp.status
            names = {t for t in h.registry.tools if t.startswith("archer__")}
            assert names == {f"archer__{n}" for n in ("connection_check", "overview", "list_hosts", "list_campaigns",
                                                      "list_findings", "get_finding", "get_raw_records",
                                                      "get_pair_history", "sensor_health", "analysis_status")}
            for n in names:
                t = h.registry.tools[n]
                assert h.roe.classify(n, {}, t.annotations, t.server)[0] == "auto", n
            for expert in ("network_analyst", "threat_hunter", "alert_triage"):
                allowed = {s.name for s in h.registry.specs(h.experts[expert].tools)}
                assert names <= allowed, expert
            assert "archer-beacon-review" in h.experts["network_analyst"].skills
            assert h.skills.get("archer-beacon-review")["expert"] == "shared"
            allowed = h.registry.specs(h.experts["network_analyst"].tools)
            out, err = await h.executor.execute(ToolCall("c1", "archer__list_hosts", {"limit": 3}), "network_analyst",
                                                "which hosts beacon", allowed)
            return out, err
        finally:
            await h.close()

    out, err = asyncio.run(run())
    assert not err and 'source="archer" trust="untrusted-data"' in out and '"total":5' in out
    assert archer.logins == 1
