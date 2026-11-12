"""Live checks of the Archer connector against your Archer: the acceptance checks, plus one call of every tool.

Skipped unless CA_LIVE_ARCHER=1. The ARCHER_* settings come from config/.env (or the environment):
    CA_LIVE_ARCHER=1 .venv/bin/python -m pytest -q tests/test_archer_live.py
Read-only, except with CA_LIVE_ARCHER_WRITE_PROBE=1: that sends ONE write request outside the connector, to
confirm Archer refuses the Viewer with 403. The probe is harmless under any role: a PATCH to a finding id that does
not exist, with an invalid status.
"""

from __future__ import annotations

import importlib
import json
import os
import ssl
import sys
import urllib.parse
from pathlib import Path

import pytest
from mcp.server.mcpserver.exceptions import ToolError

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
pytestmark = pytest.mark.skipif(os.environ.get("CA_LIVE_ARCHER") != "1", reason="set CA_LIVE_ARCHER=1 to test against Archer")


@pytest.fixture(scope="module")
def m():
    from compensated_anarchist.config import parse_env_file

    env = ROOT / "config" / ".env"
    saved = dict(os.environ)
    if env.exists():
        for k, v in parse_env_file(env).items():
            if k.startswith("ARCHER_"):
                os.environ.setdefault(k, v)
    try:
        yield importlib.reload(importlib.import_module("compensated_anarchist.servers.archer"))
    finally:
        os.environ.clear()
        os.environ.update(saved)


def test_1_the_account_is_a_viewer(m):
    chk = json.loads(m.connection_check())
    assert chk["role_ok"], chk["account"]
    print("\nconnection:", json.dumps({k: chk[k] for k in ("url", "tls", "version", "certificate_sha256", "analysis")}))


def test_2_findings_answer_with_a_total(m):
    data, headers = m.client.get("/api/findings", {"limit": 1})
    assert headers.get("X-Total-Count") is not None, dict(headers)
    print("\nfindings total:", headers.get("X-Total-Count"), "has more:", headers.get("X-Has-More"))


def test_3_an_invalid_session_logs_in_again_once(m):
    m.list_hosts(limit=1)
    before = m.client.logins
    for c in m.client.jar:
        c.value = "invalid-session"
    json.loads(m.list_hosts(limit=1))
    assert m.client.logins == before + 1


def test_4_writes_are_blocked(m):
    with pytest.raises(m.Blocked):
        m.client.request("POST", "/api/findings/bulk")
    if os.environ.get("CA_LIVE_ARCHER_WRITE_PROBE") != "1":
        pytest.skip("server-side 403: set CA_LIVE_ARCHER_WRITE_PROBE=1 to send one refused write")
    import http.client
    import json as _json

    u = urllib.parse.urlsplit(m.client.base)
    ctx = ssl.create_default_context()
    ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
    c = http.client.HTTPSConnection(u.hostname, u.port or 443, context=ctx, timeout=30)
    c.connect()
    assert m.fingerprint(c.sock.getpeercert(binary_form=True)) == m.client.seen_fingerprint  # the same Archer
    cookie = "; ".join(f"{k.name}={k.value}" for k in m.client.jar)
    c.request("PATCH", "/api/findings/999999999999", body=_json.dumps({"status": "not-a-status"}).encode(),
              headers={"Cookie": cookie, "Content-Type": "application/json"})
    r = c.getresponse()
    assert r.status == 403, (r.status, r.read()[:200])


def test_5_a_malformed_query_is_an_error_not_an_empty_result(m):
    with pytest.raises(ToolError, match="HTTP 400"):
        m.list_findings(q="type:(Beacon")


def test_every_tool_once(m):
    for fn in (m.overview, m.list_hosts, m.list_campaigns, m.sensor_health, m.analysis_status):
        json.loads(fn())
    f = json.loads(m.list_findings(limit=5, direction="desc"))
    assert isinstance(f["total"], int)
    if f["findings"]:
        fid = f["findings"][0]["id"]
        for fn in (m.get_finding, m.get_raw_records, m.get_pair_history):
            out = fn(fid)
            assert len(out) <= m.MAX_CHARS
            json.loads(out)
