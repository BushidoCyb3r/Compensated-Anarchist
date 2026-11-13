"""Vulnerability assessment: the gate-everything floor (vuln_assessor + playbook), and the vuln_* command runner."""

from __future__ import annotations

import asyncio
import json
import os
import stat
import sys
from pathlib import Path

import pytest
import yaml
from starlette.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_harness import ScriptedBackend, write_config  # noqa: E402

from compensated_anarchist import agent as agent_mod  # noqa: E402
from compensated_anarchist.audit import AuditLog  # noqa: E402
from compensated_anarchist.config import load_config  # noqa: E402
from compensated_anarchist.roe import RoeGate, _matches_target  # noqa: E402
from compensated_anarchist.tools import vulnscan  # noqa: E402
from compensated_anarchist.tools.vulnscan import VulnTools, hosts_in_args  # noqa: E402

VA = "Vulnerability Assessor"
REPORT = ("submit_report", {"status": "completed", "summary": "2 high findings, 1 chain", "confidence": "medium"})


def run_mission(tmp_path, monkeypatch, scripts, text="go", playbook="", posture=None, decide=None):
    """Run one mission; every approval request is recorded and decided by `decide(tool, args)` (default: approve)."""
    cfg = load_config(write_config(tmp_path))
    monkeypatch.setattr(agent_mod, "make_backend", lambda profile: ScriptedBackend(scripts))
    asked: list[tuple[str, dict, str]] = []

    async def approver(tool, args, rationale, why):
        asked.append((tool, args, why))
        return (decide(tool, args) if decide else True), "ok"

    async def go():
        h = agent_mod.Harness(cfg, "VA-1", posture=posture, interactive=True)
        h.roe.approver = approver
        await h.start()
        try:
            out = await h.mission(text, text, playbook)
        finally:
            await h.close()  # stops the connector processes (else the event loop never finishes)
        return h, out

    h, out = asyncio.run(go())
    return h, out, asked


def results(agent) -> dict[str, str]:
    return {m["name"]: m["content"] for m in agent.messages if m["role"] == "tool"}


def test_vuln_assessor_needs_approval_for_everything(tmp_path, monkeypatch):
    scripts = {
        "lead": [("Starting the assessment.", [("subagent_spawn", {"expert": "vuln_assessor", "task": "assess 10.0.0.5"})]),
                 ("Reading the case.", [("case_summary", {})]),
                 ("Done.", [])],
        VA: [("Reading first.", [("case_summary", {}), ("memory_search", {"query": "web servers"})]),
             ("Toolkit.", [("vuln_environment", {})]),
             ("Note.", [("case_add_note", {"note": "scan window agreed"})]),
             ("Report.", [REPORT])],
    }
    h, out, asked = run_mission(tmp_path, monkeypatch, scripts)
    tools = [t for t, _, _ in asked]
    # starting the assessor, every one of its actions (reads, memory, notes, the report) and the lead's later read
    assert tools.count("subagent_spawn") == 1
    assert {"memory_search", "vuln_environment", "case_add_note", "submit_report"} <= set(tools)
    assert tools.count("case_summary") == 2  # the assessor's read and the lead's read after it started
    assert all("approval" in why for t, _, why in asked)
    sa = next(iter(h.subagents.values()))
    assert sa.expert == "vuln_assessor" and sa.status == "completed"
    assert "every action in this conversation" in h.gate_reason
    assert h.history.first_event(h.conversation["id"], "gate_on")  # recorded: survives reopening


def test_denied_actions_do_not_run(tmp_path, monkeypatch):
    scripts = {
        "lead": [("Start.", [("subagent_spawn", {"expert": "vuln_assessor", "task": "assess"})]), ("Done.", [])],
        VA: [("Read.", [("case_add_note", {"note": "should not be written"})]), ("Report.", [REPORT])],
    }
    h, _, asked = run_mission(tmp_path, monkeypatch, scripts, decide=lambda tool, args: tool != "case_add_note")
    sa = next(iter(h.subagents.values()))
    assert results(sa.agent)["case_add_note"].startswith("<tool_output") is False
    assert "NOT EXECUTED" in results(sa.agent)["case_add_note"]
    assert not any("should not be written" in str(n) for n in h.case.data.get("notes", []))


def test_denied_spawn_never_starts_the_assessor(tmp_path, monkeypatch):
    scripts = {"lead": [("Start.", [("subagent_spawn", {"expert": "vuln_assessor", "task": "assess"})]), ("Okay.", [])]}
    h, _, asked = run_mission(tmp_path, monkeypatch, scripts, decide=lambda tool, args: False)
    assert [t for t, _, _ in asked] == ["subagent_spawn"] and not h.subagents and h.gate_reason == ""


def test_playbook_gates_the_lead_even_in_observe(tmp_path, monkeypatch):
    scripts = {"lead": [("Scope first.", [("case_summary", {}), ("memory_search", {"query": "scope"})]), ("Asked.", [])]}
    h, _, asked = run_mission(tmp_path, monkeypatch, scripts, playbook="vulnerability_assessment", posture="observe")
    assert [t for t, _, _ in asked] == ["case_summary", "memory_search"]  # reads ask (not denied) in OBSERVE
    assert "vulnerability assessment playbook" in h.gate_reason
    cid = h.conversation["id"]

    # a new conversation is not gated; reopening the gated one is
    h.new_conversation()
    assert h.gate_reason == "" and h._gate_hook("lead", "case_summary", {}) == ""
    h.open_conversation(cid)
    assert "vulnerability assessment playbook" in h._gate_hook("lead", "case_summary", {})


def test_other_conversations_are_unaffected(tmp_path, monkeypatch):
    scripts = {"lead": [("Look.", [("case_summary", {})]), ("Done.", [])]}
    h, _, asked = run_mission(tmp_path, monkeypatch, scripts)
    assert asked == [] and h.gate_reason == ""


def test_roe_floor_cannot_be_lowered(tmp_path):
    roe = yaml.safe_load(Path(write_config(tmp_path)).with_name("roe.yaml").read_text())
    roe["rules"] = [{"match": "vuln_*", "tier": "auto"}, {"match": "*", "tier": "auto"}] + roe["rules"]
    roe["gate_everything"] = {"experts": [], "playbooks": []}
    p = tmp_path / "roe_lax.yaml"
    p.write_text(yaml.safe_dump(roe))
    g = RoeGate(p, AuditLog(tmp_path / "a.jsonl", "t"), None)
    assert g.classify("vuln_run", {})[0] == "approve"  # HUMAN_GATED floor
    assert "vuln_assessor" in g.gate_all_experts and "vulnerability_assessment" in g.gate_all_playbooks


def test_scope_of_ranges():
    assert _matches_target("10.0.5.0/24", ["10.0.0.0/8"]) and not _matches_target("10.0.0.0/7", ["10.0.0.0/8"])
    assert not _matches_target("192.168.1.0/24", ["10.0.0.0/8"])


# ---- vuln_run --------------------------------------------------------------------------------------------
@pytest.fixture
def kit(tmp_path, monkeypatch):
    """VulnTools with a fake nmap / curl / searchsploit on PATH and scope 10.0.0.0/24 + web.lab."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for name in ("nmap", "curl", "searchsploit", "slowtool"):
        f = bin_dir / name
        f.write_text("#!/bin/sh\n" + ("sleep 30\n" if name == "slowtool" else "")
                     + "echo \"ran $0 $*\"\necho \"SECRET=${CA_T_SECRET:-unset}\"\n")
        f.chmod(f.stat().st_mode | stat.S_IEXEC)
    (bin_dir / "hydra").write_text("#!/bin/sh\necho no\n")
    (bin_dir / "hydra").chmod(0o755)
    monkeypatch.setenv("PATH", f"{bin_dir}:{os.environ['PATH']}")
    monkeypatch.setenv("CA_T_SECRET", "sk-should-not-leak")
    saved = []
    scope = {"allowed": ["10.0.0.0/24", "web.lab"], "protected": ["10.0.0.1"]}
    names = {"web.lab": ["10.0.0.80"], "evil.example": ["203.0.113.9"], "split.lab": ["10.0.0.9", "203.0.113.9"]}
    vt = VulnTools({"extra_tools": ["slowtool"]}, tmp_path / "case" / "vuln_assessment",
                   scope=lambda: (scope["allowed"], scope["protected"]), on_saved=lambda p, k: saved.append((p, k)),
                   resolve=lambda h: names.get(h, []))
    return vt, scope, saved


def test_check_refuses(kit):
    vt, scope, _ = kit
    ok = vt.check("nmap", ["-sT", "-sV", "-p", "1-1000", "--script=vuln", "-oX", "scan.xml", "10.0.0.5"], ["10.0.0.5"])
    assert ok == []
    assert vt.check("nmap", ["-sT", "10.0.0.0/26"], ["10.0.0.0/26"]) == []          # a subnet inside the scope
    assert vt.check("curl", ["-sk", "https://web.lab:8443/login"], ["web.lab"]) == []  # hostname -> in-scope address
    assert vt.check("nmap", ["-sT", "10.0.0.5"], ["10.0.0.0/24"]) == []           # host inside a listed CIDR
    cases = {
        ("hydra", ("-l", "admin", "10.0.0.5"), ("10.0.0.5",)): "allowlist",
        ("nmap", ("10.0.1.5",), ("10.0.1.5",)): "outside the authorized scope",
        ("nmap", ("10.0.0.0/23",), ("10.0.0.0/23",)): "outside the authorized scope",
        ("nmap", ("evil.example",), ("evil.example",)): "outside the authorized scope",
        ("nmap", ("split.lab",), ("split.lab",)): "outside the authorized scope",  # every address must be in scope
        ("nmap", ("10.0.0.5", "10.0.0.6"), ("10.0.0.5",)): "not in targets",
        ("curl", ("http://10.0.0.7/",), ("10.0.0.5",)): "not in targets",
        ("nmap", ("10.0.0.1-50",), ("10.0.0.0/24",)): "ranges",
        ("nmap", ("-iL", "hosts.txt"), ()): "refused option",
        ("nmap", ("-iR", "100"), ()): "refused option",
        ("nmap", ("--script", "http-brute", "10.0.0.5"), ("10.0.0.5",)): "refused option",
        ("nmap", ("--script=exploit", "10.0.0.5"), ("10.0.0.5",)): "refused option",
        ("curl", ("-X", "POST", "http://10.0.0.5/"), ("10.0.0.5",)): "refused option",
        ("curl", ("-T", "f", "http://10.0.0.5/"), ("10.0.0.5",)): "refused option",
        ("curl", ("-o", "/etc/cron.d/x", "http://10.0.0.5/"), ("10.0.0.5",)): "path",
        ("nmap", ("-oX", "/usr/share/x.xml", "10.0.0.5"), ("10.0.0.5",)): "path",
        ("nmap", ("--script", "/tmp/evil.nse", "10.0.0.5"), ("10.0.0.5",)): "path",
        ("nmap", ("http://10.0.0.5",), ("http://10.0.0.5",)): "no URLs",
    }
    for (tool, args, targets), want in cases.items():
        problems = vt.check(tool, list(args), list(targets))
        assert any(want in p for p in problems), (tool, args, problems)
    assert vt.check("nmap", ["-iL", "/usr/share/wordlists/x"], []) != []
    scope["allowed"] = []
    assert "no authorized scope" in vt.check("nmap", ["10.0.0.5"], ["10.0.0.5"])[0]


def test_run_saves_output_without_secrets(kit):
    vt, _, _ = kit
    out = asyncio.run(vt.run("nmap", ["-sT", "-oX", "scan.xml", "10.0.0.5"], ["10.0.0.5"]))
    assert "$ nmap -sT -oX scan.xml 10.0.0.5" in out and "ran " in out and "exit 0" in out
    assert "SECRET=unset" in out  # API keys in the harness environment never reach the tools
    saved = list(vt.raw.glob("*_nmap.txt"))
    assert len(saved) == 1 and saved[0].read_text().startswith("$ nmap")
    refused = asyncio.run(vt.run("nmap", ["10.9.9.9"], ["10.9.9.9"]))
    assert refused.startswith("REFUSED, nothing was run") and len(list(vt.raw.glob("*.txt"))) == 1


def test_run_timeout_kills_the_tool(kit):
    vt, _, _ = kit
    vt.timeout_s = 1
    out = asyncio.run(vt.run("slowtool", ["10.0.0.5"], ["10.0.0.5"], timeout_s=1))
    assert "TIMED OUT" in out


NMAP_XML = """<?xml version="1.0"?><nmaprun scanner="nmap" args="nmap -sV 10.0.0.5" version="7.95">
<host><status state="up"/><address addr="10.0.0.5" addrtype="ipv4"/><hostnames><hostname name="web01.lab"/></hostnames>
<ports><port protocol="tcp" portid="443"><state state="open"/><service name="https" product="Apache httpd" version="2.4.49">
<cpe>cpe:/a:apache:http_server:2.4.49</cpe></service>
<script id="http-vuln-cve2021-41773" output="VULNERABLE: Apache 2.4.49 path traversal"/></port>
<port protocol="tcp" portid="22"><state state="closed"/></port></ports></host></nmaprun>"""


def test_parse_and_report(kit):
    vt, _, saved = kit
    vt.raw.mkdir(parents=True)
    (vt.raw / "services.xml").write_text(NMAP_XML)
    s = vt.parse("services.xml")
    assert "HOST 10.0.0.5 (web01.lab)" in s and "443/tcp open  https Apache httpd 2.4.49" in s
    assert "cpe:/a:apache:http_server:2.4.49" in s and "http-vuln-cve2021-41773: VULNERABLE" in s and "22/tcp" not in s
    (vt.raw / "nuclei.jsonl").write_text(json.dumps({"template-id": "CVE-2021-41773", "matched-at": "https://10.0.0.5/",
                                                     "info": {"name": "Apache path traversal", "severity": "critical",
                                                              "classification": {"cve-id": ["CVE-2021-41773"]}}}) + "\n")
    assert "[critical] CVE-2021-41773" in vt.parse("nuclei.jsonl")
    with pytest.raises(ValueError):
        vt.parse("/etc/passwd")
    assert vt.save_report("Q4 scan", "# Report v1").endswith("vuln_report_Q4_scan.md")
    vt.save_report("Q4 scan", "# Report v2")
    assert (vt.folder / "vuln_report_Q4_scan.md").read_text() == "# Report v2" and len(list((vt.folder / "older").iterdir())) == 1
    assert saved[0][1] == "vuln_report"


def test_dashboard_shows_reports_and_approval_mode(tmp_path, monkeypatch):
    from test_dashboard import login, make

    dash, app = make(tmp_path, monkeypatch, {})
    with TestClient(app) as c:
        login(c)
        h = dash.harness
        st = c.get("/api/state").json()
        assert st["gated"] == "" and st["vuln_folder"] == str(h.vuln_dir)
        h.registry.tools["vuln_report_save"].handler(name="lab", content="# Lab vulnerability report")
        files = {f["name"]: f for f in c.get("/api/plans").json()["files"]}
        assert files["vuln_report_lab.md"]["kind"] == "vuln_report"
        assert c.get("/api/plans/vuln_report_lab.md").text == "# Lab vulnerability report"
        assert c.get("/api/plans/raw").status_code == 404
        h.gate_conversation("test")
        assert "every action" in c.get("/api/state").json()["gated"]


def test_check_finds_hosts_however_they_are_written(kit):
    """One-word names (dc01, localhost) and numbers the resolver reads as addresses (10.1, 167772161, 0x0a000001) are
    hosts too: each must be listed in targets and be in scope. Paths after = or stuck to an option get the path check
    (relative ones count from raw/, where the tool runs); config files and file: URLs are refused; plain option values
    (ports, counts, script names) still pass."""
    vt, _, _ = kit
    names = {"dc01": ["10.0.0.20"], "localhost": ["127.0.0.1"], "0x0a000001": ["10.0.0.1"]}
    vt.resolve = lambda h: names.get(h, [])
    for args in (["-sT", "dc01"], ["-sT", "localhost"], ["-sT", "0x0a000001"], ["-sT", "10.1"], ["167772161"]):
        assert any("not in targets" in p for p in vt.check("nmap", args, ["10.0.0.5"])), args
    assert vt.check("nmap", ["-sT", "dc01"], ["dc01"]) == []  # listed, and its address is in scope
    assert any("outside the authorized scope" in p for p in vt.check("nmap", ["localhost"], ["localhost"]))
    assert vt.check("nmap", ["-sT", "-p", "22,80", "--top-ports", "100", "--script=default", "-T4", "--max-retries", "2",
                             "10.0.0.5"], ["10.0.0.5"]) == []
    cases = {
        ("nmap", ("--script=/tmp/evil.nse", "10.0.0.5")): "path",
        ("nmap", ("-oN/etc/cron.d/x", "10.0.0.5")): "path",
        ("nmap", ("-oX", "../../../x.xml", "10.0.0.5")): "path",
        ("curl", ("-K", "cfg", "http://10.0.0.5/")): "refused option",
        ("curl", ("-sK", "cfg", "http://10.0.0.5/")): "refused option",
        ("curl", ("--config=cfg", "http://10.0.0.5/")): "refused option",
        ("curl", ("-o", "x.txt", "file:///etc/passwd")): "file: URLs",
    }
    for (tool, args), want in cases.items():
        assert any(want in p for p in vt.check(tool, list(args), ["10.0.0.5"])), (tool, args)
    assert vt.check("curl", ["-sk", "-o", "../page.html", "http://10.0.0.5/"], ["10.0.0.5"]) == []  # still the case folder
