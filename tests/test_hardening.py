"""ROE scope hardening: Velociraptor client ids resolve to hostname/IP so CIDR/hostname scope rules apply;
unresolvable targets fail closed; protected-asset aliases escalate to approval."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from compensated_anarchist.audit import AuditLog  # noqa: E402
from compensated_anarchist.roe import RoeGate  # noqa: E402

ALIASES = {"C.1111111111111111": ["ws01", "ws01.corp.example", "10.1.2.3"],
           "C.2222222222222222": ["dc01", "dc01.corp.example", "10.1.1.5"],
           "C.3333333333333333": ["kiosk", "kiosk.guest", "192.168.50.9"]}


def gate(tmp_path, asked):
    roe = yaml.safe_load((ROOT / "config" / "roe.yaml").read_text())
    roe["scope"]["allowed_targets"] = ["10.0.0.0/8", "*.corp.example"]
    roe["scope"]["protected_assets"] = ["dc01*"]
    (tmp_path / "roe.yaml").write_text(yaml.safe_dump(roe))

    async def approver(tool, args, rationale, why):
        asked.append(why)
        return True, "ok"

    g = RoeGate(tmp_path / "roe.yaml", AuditLog(tmp_path / "a.jsonl", "t"), approver)

    async def resolver(tool, value):
        return ALIASES.get(value, [])

    g.target_resolver = resolver
    return g


def test_scope_resolution(tmp_path):
    asked: list[str] = []
    g = gate(tmp_path, asked)
    run = lambda tool, cid: asyncio.run(g.authorize(tool, {"client_id": cid}, "brief", "incident_responder"))  # noqa: E731

    d = run("velociraptor_admin__quarantine_host", "C.1111111111111111")
    assert d.allowed and "in scope as" in asked[-1]
    d = run("velociraptor_admin__quarantine_host", "C.3333333333333333")  # guest network, outside CIDR + domain
    assert not d.allowed and "outside authorized scope" in d.reason and "192.168.50.9" in d.reason
    d = run("velociraptor_admin__quarantine_host", "C.9999999999999999")  # unknown client -> fail closed
    assert not d.allowed and "unresolvable" in d.reason
    n = len(asked)
    d = run("velociraptor__collect_artifact", "C.2222222222222222")  # protected DC escalates even a notify-tier call
    assert d.allowed and len(asked) == n + 1 and "PROTECTED ASSET" in asked[-1]
    # read-only tools are never blocked by scope (querying about anything is fine)
    d = run("velociraptor__client_info", "C.9999999999999999")
    assert d.allowed and d.tier == "auto"


def test_local_run_tiers_for_static_parsers(tmp_path):
    """olevba and pescan only read and print: notify. Tools that can load plugin, decoder or signature scripts, or
    write files, stay at approve, and the approval note tells the analyst what to look for."""
    g = gate(tmp_path, [])
    tier = lambda binary: g.classify("local_run", {"binary": binary, "args": ["/x/sample.doc"]})  # noqa: E731
    assert tier("olevba")[0] == "notify" and tier("pescan")[0] == "notify" and tier("fls")[0] == "notify"
    for b in ("oledump.py", "pdfid.py", "pdf-parser.py", "diec", "densityscout"):
        t, why = tier(b)
        assert t == "approve" and "--plugins" in why, b
