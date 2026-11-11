"""End-to-end and unit tests. Run: .venv/bin/python -m pytest -q"""

from __future__ import annotations

import asyncio
import json
import os
import re
import sys
from pathlib import Path

import httpx
import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from compensated_anarchist import agent as agent_mod  # noqa: E402
from compensated_anarchist.audit import AuditLog, verify  # noqa: E402
from compensated_anarchist.config import ModelProfile, load_config  # noqa: E402
from compensated_anarchist.llm.base import LLMResponse, ToolCall, parse_text_tool_calls, to_text_mode, ToolSpec  # noqa: E402
from compensated_anarchist.llm.openai_compat import OpenAICompatBackend  # noqa: E402
from compensated_anarchist.memory import Memory  # noqa: E402
from compensated_anarchist.roe import RoeGate  # noqa: E402


# ---------------------------------------------------------------------------
# fixtures
# ---------------------------------------------------------------------------
def write_config(tmp: Path) -> Path:
    (tmp / "evidence").mkdir()
    (tmp / "evidence" / "sample.bin").write_bytes(b"MZ\x90\x00 http://evil.example/c2 beacon")
    roe = yaml.safe_load((ROOT / "config" / "roe.yaml").read_text())
    roe["scope"]["allowed_targets"] = ["C.1111111111111111", "10.0.0.0/8"]
    (tmp / "roe.yaml").write_text(yaml.safe_dump(roe))
    cfg = {
        "harness": {"default_model": "fake", "roe": "roe.yaml", "cases_dir": "cases", "evidence_roots": ["evidence"], "forensics_dir": "forensics",
                    "max_steps": 10, "operator": "tester"},
        "models": {"fake": {"provider": "openai_compat", "base_url": "http://fake/v1", "model": "x"}},
        "memory": {"db_path": "mem.db"},
        "mcp_servers": {"velociraptor": {"command": sys.executable, "args": [str(ROOT / "tests" / "fake_velo_server.py")]}},
        "forensics": {},
    }
    p = tmp / "harness.yaml"
    p.write_text(yaml.safe_dump(cfg))
    from compensated_anarchist.web import account
    account.save(tmp / "secrets" / "dashboard_account.json", TEST_USER, TEST_PASSWORD)  # dashboard sign-in
    return p


TEST_USER, TEST_PASSWORD = "analyst", "correct horse battery"


class ScriptedBackend:
    """Plays a fixed script per agent: list of (text, [(tool, args), ...])."""

    def __init__(self, scripts):
        self.scripts = scripts
        self.profile_name = "fake"
        self.context_tokens = 100000
        self.seen: dict[str, list] = {}
        self.delay = 0.0  # seconds between streamed words

    async def chat(self, messages, tools, on_delta=None):
        system = messages[0]["content"]
        who = "lead"
        for name in self.scripts:
            if f"# Role: {name}" in system:
                who = name
        if "retrospective" in json.dumps(messages[-1]).lower() or "after-action" in json.dumps(messages[-1]).lower():
            who = "retro"
        self.seen.setdefault(who, []).append(messages)
        step = self.scripts[who].pop(0) if self.scripts.get(who) else ("done.", [])
        text, calls = step
        if on_delta and text:  # stream it word by word, like a real provider
            for piece in re.findall(r"\S+\s*|\s+", text):
                on_delta(piece)
                await asyncio.sleep(self.delay)
        tcs = [ToolCall(f"c{i}_{len(self.seen[who])}", n, a) for i, (n, a) in enumerate(calls)]
        msg = {"role": "assistant", "content": text}
        if tcs:
            msg["tool_calls"] = [{"id": t.id, "type": "function", "function": {"name": t.name, "arguments": json.dumps(t.arguments)}} for t in tcs]
        return LLMResponse(text, tcs, msg, "stop", {"input": 1, "output": 1})

    async def aclose(self):
        pass


# ---------------------------------------------------------------------------
# end-to-end: lead delegates in parallel, expert uses local + MCP tools, ROE gates quarantine
# ---------------------------------------------------------------------------
def test_end_to_end(tmp_path, monkeypatch):
    cfg = load_config(write_config(tmp_path))
    ev = str(tmp_path / "evidence" / "sample.bin")
    scripts = {
        "lead": [
            ("Tasking experts in parallel.", [
                ("subagent_spawn", {"expert": "malware_analyst", "task": f"triage {ev}"}),
                ("subagent_spawn", {"expert": "incident_responder", "task": "isolate ws01"}),
            ]),
            ("Situation report: sample triaged; containment denied by analyst.", []),
        ],
        "Malware Analyst (static triage)": [
            ("hashing", [("case_register_evidence", {"path": ev, "description": "sample"}),
                         ("local_strings", {"path": ev, "min_len": 4}),
                         ("local_read_file", {"path": "/etc/shadow"}),            # jail must block
                         ("velociraptor__quarantine_host", {"client_id": "C.1"}),  # not in allowlist
                         ]),
            ("Found C2 URL", [("case_add_ioc", {"type": "url", "value": "http://evil.example/c2", "context": "strings"})]),
            ("Report: static triage complete.", [("submit_report", {"status": "completed", "summary": "static triage complete: C2 URL found",
                                                                    "confidence": "high", "recommended_tasks": [{"expert": "cti_analyst", "task": "enrich evil.example"}]})]),
        ],
        "Incident Responder (containment / eradication / recovery)": [
            ("find host", [("velociraptor__list_clients", {"search": "host:ws01"})]),
            ("Action brief: isolate ws01 due to C2.", [("velociraptor__quarantine_host", {"client_id": "C.1111111111111111"}),
                                                       ("velociraptor__quarantine_host", {"client_id": "C.9999999999999999"})]),
            ("Containment denied; recommending monitoring.", []),
        ],
        "retro": [("recording lessons", [("memory_record", {"kind": "lesson", "title": "Triage C2 strings first",
                                                             "content": "strings revealed C2 URL quickly"})]),
                  ("Recorded 1 lesson.", [])],
    }
    fake = ScriptedBackend(scripts)
    monkeypatch.setattr(agent_mod, "make_backend", lambda profile: fake)
    approvals = []

    async def approver(tool, args, rationale, why):
        approvals.append((tool, args, rationale))
        return False, "too disruptive during mission window"

    async def run():
        h = agent_mod.Harness(cfg, "TEST-1", interactive=True)
        h.roe.approver = approver
        await h.start()
        assert h.mcp.status["velociraptor"].startswith("connected"), h.mcp.status
        out = await h.mission("Investigate sample and contain if needed")
        retro = await h.retro()
        h.rate(5, "good")
        await h.close()
        return h, out, retro

    h, out, retro = asyncio.run(run())
    assert "Situation report" in out
    # orchestrator got structured reports back, with subagent ids it can follow up on
    lead_tool_msgs = [m["content"] for m in fake.seen["lead"][1] if m["role"] == "tool"]
    assert any("Report from SA-001" in t and "static triage complete" in t and "cti_analyst: enrich evil.example" in t for t in lead_tool_msgs)
    assert any("Report from SA-002" in t and "free text" in t for t in lead_tool_msgs)  # unstructured fallback
    case = json.loads((tmp_path / "cases" / "TEST-1" / "case.json").read_text())
    assert case["evidence"][0]["hashes"]["sha256"]
    assert case["iocs"][0]["value"] == "http://evil.example/c2"

    # ROE: in-scope quarantine asked the analyst (denied); out-of-scope target denied without asking
    assert len(approvals) == 1 and approvals[0][1]["client_id"] == "C.1111111111111111"
    assert "Action brief" in approvals[0][2]
    audit = [json.loads(l) for l in (tmp_path / "cases" / "TEST-1" / "audit.jsonl").read_text().splitlines()]
    decisions = [a["data"] for a in audit if a["event"] == "roe_decision"]
    out_of_scope = [d for d in decisions if d["arguments"].get("client_id") == "C.9999999999999999"]
    assert out_of_scope and not out_of_scope[0]["allowed"] and "outside authorized scope" in out_of_scope[0]["reason"]
    assert verify(tmp_path / "cases" / "TEST-1" / "audit.jsonl")[0]

    # tool results the expert saw: jail blocked /etc/shadow, allowlist blocked quarantine for malware analyst
    mal_msgs = fake.seen["Malware Analyst (static triage)"][1]
    tool_outs = [m["content"] for m in mal_msgs if m["role"] == "tool"]
    assert any("outside the allowed evidence roots" in t for t in tool_outs)
    assert any("not available to agent 'malware_analyst'" in t for t in tool_outs)
    assert any("evil.example" in t and 'trust="untrusted-data"' in t for t in tool_outs)

    # learning: analyst denial became approved feedback; agent lesson is a candidate
    mem = Memory(cfg.memory_db)
    stats = mem.stats()
    assert stats.get("feedback/approved") == 1 and stats.get("lesson/candidate") == 1
    assert mem.search("quarantine disruptive")  # approved feedback is retrievable
    assert not mem.search("Triage C2 strings")  # candidate is not, until promoted
    # transcripts written per agent for training export
    assert len(list((tmp_path / "cases" / "TEST-1" / "transcripts").rglob("*__*__*.json"))) >= 3
    from compensated_anarchist.memory import export_training
    assert export_training(tmp_path / "cases", tmp_path / "train.jsonl", 4) >= 3


# ---------------------------------------------------------------------------
# unit tests
# ---------------------------------------------------------------------------
def test_audit_tamper_detected(tmp_path):
    log = AuditLog(tmp_path / "a.jsonl", "op")
    for i in range(3):
        log.record("x", i=i)
    assert verify(tmp_path / "a.jsonl")[0]
    lines = (tmp_path / "a.jsonl").read_text().splitlines()
    lines[1] = lines[1].replace('"i":1', '"i":7')
    (tmp_path / "a.jsonl").write_text("\n".join(lines) + "\n")
    ok, msg = verify(tmp_path / "a.jsonl")
    assert not ok and "line 2" in msg


def test_roe_observe_posture_and_args(tmp_path):
    log = AuditLog(tmp_path / "a.jsonl", "op")

    async def yes(*a):
        return True, ""

    gate = RoeGate(ROOT / "config" / "roe.yaml", log, yes, posture="observe")
    tier, _ = gate.classify("velociraptor__collect_artifact", {"artifact": "Windows.System.Pslist"})
    assert tier == "approve"  # even triage runs on the endpoint: a human approves it
    tier, _ = gate.classify("velociraptor__collect_artifact", {"artifact": "Windows.KapeFiles.Targets"})
    assert tier == "approve"
    assert gate.classify("velociraptor_admin__download_flow_uploads", {})[0] == "approve"
    assert gate.classify("velociraptor__collect_artifact", {"artifact": "Windows.System.PowerShell"})[0] == "deny"
    d = asyncio.run(gate.authorize("velociraptor__quarantine_host", {"client_id": "C.1"}, "", "t"))
    assert not d.allowed and "OBSERVE" in d.reason
    assert gate.classify("brand_new_tool", {})[0] == "approve"


def test_human_gate_for_endpoint_actions(tmp_path):
    """Nothing touches an endpoint through Velociraptor without an analyst saying yes - and roe.yaml cannot
    lower that. Investigation (collection, downloads) may be requested in OBSERVE; containment may not."""
    asked = []

    async def analyst(tool, args, rationale, why):
        asked.append(tool)
        return True, "ok"

    async def no(tool, args, rationale, why):
        asked.append(tool)
        return False, "no"

    gate = RoeGate(ROOT / "config" / "roe.yaml", AuditLog(tmp_path / "a.jsonl", "op"), analyst, posture="observe")
    d = asyncio.run(gate.authorize("velociraptor__collect_artifact", {"client_id": "C.1", "artifact": "Linux.Sys.Pslist"}, "", "t"))
    assert d.allowed and d.tier == "approve" and asked == ["velociraptor__collect_artifact"]  # asked, then allowed
    d = asyncio.run(gate.authorize("velociraptor_admin__download_flow_uploads", {"client_id": "C.1", "flow_id": "F.1"}, "", "t"))
    assert d.allowed and asked[-1] == "velociraptor_admin__download_flow_uploads"
    gate.approver = no
    d = asyncio.run(gate.authorize("velociraptor__collect_artifact", {"client_id": "C.1", "artifact": "Generic.Collectors.File"}, "", "t"))
    assert not d.allowed and "DENIED" in d.reason  # the analyst said no: nothing runs
    for t in ("velociraptor_admin__quarantine_host", "velociraptor_admin__run_server_vql"):
        n = len(asked)
        d = asyncio.run(gate.authorize(t, {"client_id": "C.1"}, "", "t"))
        assert not d.allowed and "OBSERVE" in d.reason and len(asked) == n  # response actions: not even asked

    # a permissive roe.yaml cannot switch the gate off
    lax = tmp_path / "lax.yaml"
    lax.write_text(yaml.safe_dump({"default_tier": "auto", "rules": [
        {"match": "velociraptor*__quarantine_host", "tier": "auto"},
        {"match": "velociraptor*__collect_artifact", "tier": "notify"},
        {"match": "velociraptor*__download_flow_uploads", "tier": "auto", "observe": "ask"},
        {"match": "velociraptor*__run_server_vql", "tier": "deny"}]}))
    gate = RoeGate(lax, AuditLog(tmp_path / "b.jsonl", "op"), no, posture="respond")
    for t in ("velociraptor_admin__quarantine_host", "velociraptor__collect_artifact", "velociraptor_admin__download_flow_uploads",
              "velociraptor__create_hunt", "velociraptor__acquire_memory", "velociraptor__label_client"):
        tier, why = gate.classify(t, {})
        assert tier == "approve" and ("human gate" in why or "approve" in why), (t, tier, why)
        n = len(asked)
        assert not asyncio.run(gate.authorize(t, {"client_id": "C.1"}, "", "t")).allowed and len(asked) == n + 1
    assert gate.classify("velociraptor_admin__run_server_vql", {})[0] == "deny"  # stricter rules still win
    assert gate.classify("velociraptor__list_clients", {})[0] == "auto"      # read-only listing is untouched


def test_text_mode_tool_calls():
    text, calls = parse_text_tool_calls('Checking.\n<tool_call>{"name": "case_summary", "arguments": {}}</tool_call>')
    assert text == "Checking." and calls[0].name == "case_summary"
    msgs = [{"role": "system", "content": "s"}, {"role": "user", "content": "u"},
            {"role": "assistant", "content": "", "tool_calls": [{"id": "1", "function": {"name": "t", "arguments": "{}"}}]},
            {"role": "tool", "tool_call_id": "1", "name": "t", "content": "r"}]
    out = to_text_mode(msgs, [ToolSpec("t", "d", {"type": "object"})])
    assert "<tool_call>" in out[2]["content"] and "<tool_response" in out[3]["content"] and out[3]["role"] == "user"


def test_openai_compat_parsing():
    def handler(request: httpx.Request):
        body = json.loads(request.content)
        assert body["tools"][0]["function"]["name"] == "case_summary"
        return httpx.Response(200, json={"choices": [{"finish_reason": "tool_calls", "message": {
            "content": None, "tool_calls": [{"id": "a", "type": "function",
                                             "function": {"name": "case_summary", "arguments": "{}"}}]}}],
            "usage": {"prompt_tokens": 5, "completion_tokens": 2}})

    b = OpenAICompatBackend(ModelProfile(name="t", provider="openai_compat", model="m", base_url="http://x/v1"))
    b.client = httpx.AsyncClient(base_url="http://x/v1", transport=httpx.MockTransport(handler))
    r = asyncio.run(b.chat([{"role": "user", "content": "hi", "_private": 1}], [ToolSpec("case_summary", "d", {"type": "object"})]))
    assert r.tool_calls[0].name == "case_summary" and r.usage["input"] == 5


def test_memory_candidates_and_ranking(tmp_path):
    m = Memory(tmp_path / "m.db")
    a = m.add("query", "SPL failed logons by source", "index=wineventlog EventCode=4625 | stats count by src", source="analyst")
    m.add("query", "SPL failed logons agent", "index=wineventlog EventCode=4625 agent version", source="agent")
    assert [h["id"] for h in m.search("failed logons 4625")] == [a]
    assert len(m.search("failed logons 4625", include_candidates=True)) == 2


def test_splunk_blocks_write_commands(monkeypatch):
    monkeypatch.setenv("SPLUNK_URL", "https://splunk.invalid:8089")
    monkeypatch.setenv("SPLUNK_TOKEN", "x")
    from compensated_anarchist.servers import splunk

    with pytest.raises(ValueError):
        splunk._spl("index=main | delete")
    with pytest.raises(ValueError):
        splunk._spl("index=main | outputlookup x.csv")
    assert splunk._spl("index=main error") == "search index=main error"
    assert splunk._spl("| tstats count where index=*").startswith("| tstats")


def test_empty_reply_gets_a_nudge_not_a_silent_end(tmp_path, monkeypatch):
    """Small reasoning models sometimes return nothing at all after a tool result. The agent must ask for the
    answer instead of ending the turn with '(no final answer)'."""
    cfg = load_config(write_config(tmp_path))
    fake = ScriptedBackend({"lead": [("Checking memory.", [("memory_search", {"query": "BPFDoor false positive"})]),
                                     ("", []), ("  \n", []),
                                     ("**Verdict:** suspicious, unconfirmed (low confidence).", [])]})
    monkeypatch.setattr(agent_mod, "make_backend", lambda profile: fake)

    async def go():
        h = agent_mod.Harness(cfg, "EMPTY-1", interactive=False)
        await h.start(new=True)
        out = await h.mission("Is BPFDoor real?")
        msgs = h.lead.messages
        await h.close()
        return out, msgs

    out, msgs = asyncio.run(go())
    assert out.startswith("**Verdict:**")
    nudges = [m for m in msgs if m["role"] == "user" and m["content"].startswith("[Harness] Your last reply was empty")]
    assert len(nudges) == 2
    assert not [m for m in msgs if m["role"] == "assistant" and not (m.get("content") or "").strip() and not m.get("tool_calls")]
