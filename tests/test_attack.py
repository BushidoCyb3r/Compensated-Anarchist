"""MITRE ATT&CK hunt planning: group resolution, technique collection (direct / via software / via campaigns),
data-source coverage by connected tools, Navigator layers, the CLI, and the hunt_planner expert's toolset.
Uses a small synthetic STIX bundle shaped like the real enterprise-attack.json."""

from __future__ import annotations

import asyncio
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_harness import ROOT, ScriptedBackend, write_config  # noqa: E402

from compensated_anarchist import agent as agent_mod  # noqa: E402
from compensated_anarchist import attack  # noqa: E402
from compensated_anarchist.audit import AuditLog  # noqa: E402
from compensated_anarchist.cli import main as cli  # noqa: E402
from compensated_anarchist.config import load_config  # noqa: E402
from compensated_anarchist.roe import RoeGate  # noqa: E402


def ext(eid):
    return [{"source_name": "mitre-attack", "external_id": eid, "url": f"https://attack.mitre.org/{eid}"}]


def obj(t, sid, name, eid=None, **kw):
    o = {"type": t, "id": f"{t}--{sid}", "name": name, **kw}
    if eid:
        o["external_references"] = ext(eid)
    return o


def tech(sid, eid, name, tactic, platforms, **kw):
    return obj("attack-pattern", sid, name, eid, kill_chain_phases=[{"kill_chain_name": "mitre-attack", "phase_name": tactic}],
               x_mitre_platforms=platforms, description=f"{name} description (Citation: Ref)", **kw)


def rel(sid, rt, src, tgt, desc=""):
    return {"type": "relationship", "id": f"relationship--{sid}", "relationship_type": rt, "source_ref": src,
            "target_ref": tgt, "description": desc}


def bundle() -> dict:
    o = [
        {"type": "x-mitre-collection", "id": "x-mitre-collection--1", "name": "Enterprise ATT&CK", "x_mitre_version": "17.1"},
        obj("intrusion-set", "g1", "Test Bear", "G9001", aliases=["Test Bear", "Cozy Test", "TB-1"], description="A test group."),
        obj("intrusion-set", "g2", "Other Panda", "G9002", aliases=["Other Panda", "Panda Test"]),
        obj("intrusion-set", "g3", "Old Group", "G9003", aliases=["Old Group"], x_mitre_deprecated=True),
        tech("t1", "T1059", "Command and Scripting Interpreter", "execution", ["Windows", "Linux"],
             x_mitre_data_sources=["Command: Command Execution", "Process: Process Creation"]),
        tech("t2", "T1059.001", "PowerShell", "execution", ["Windows"], x_mitre_is_subtechnique=True,
             x_mitre_detection="Monitor for PowerShell with encoded commands."),
        tech("t3", "T1053.005", "Scheduled Task", "persistence", ["Windows"], x_mitre_is_subtechnique=True),
        tech("t4", "T1071.001", "Web Protocols", "command-and-control", ["Windows", "Linux"], x_mitre_is_subtechnique=True),
        tech("t5", "T1595", "Active Scanning", "reconnaissance", ["PRE"], x_mitre_data_sources=["Internet Scan: Response Content"]),
        tech("t6", "T1999", "Revoked Technique", "execution", ["Windows"], revoked=True),
        tech("t7", "T1003.001", "LSASS Memory", "credential-access", ["Windows"], x_mitre_is_subtechnique=True,
             x_mitre_data_sources=["Process: Process Access"]),
        obj("x-mitre-data-source", "ds1", "Scheduled Job"),
        obj("x-mitre-data-source", "ds2", "Network Traffic"),
        obj("x-mitre-data-source", "ds3", "Process"),
        obj("x-mitre-data-component", "dc1", "Scheduled Job Creation", x_mitre_data_source_ref="x-mitre-data-source--ds1"),
        obj("x-mitre-data-component", "dc2", "Network Traffic Flow", x_mitre_data_source_ref="x-mitre-data-source--ds2"),
        obj("x-mitre-data-component", "dc3", "Process Creation", x_mitre_data_source_ref="x-mitre-data-source--ds3"),
        obj("x-mitre-detection-strategy", "det1", "Detect encoded PowerShell", x_mitre_analytic_refs=["x-mitre-analytic--an1"]),
        obj("x-mitre-analytic", "an1", "Encoded PowerShell analytic", x_mitre_log_source_references=[
            {"x_mitre_data_component_ref": "x-mitre-data-component--dc3", "name": "WinEventLog:Security EventCode 4688"}]),
        obj("malware", "s1", "TestRAT", "S9001"),
        obj("campaign", "c1", "Operation Test", "C9001"),
        rel("r1", "uses", "intrusion-set--g1", "attack-pattern--t2", "Test Bear ran encoded PowerShell downloaders."),
        rel("r2", "uses", "intrusion-set--g1", "malware--s1", "Test Bear deployed TestRAT."),
        rel("r3", "uses", "malware--s1", "attack-pattern--t4", "TestRAT beacons over HTTPS."),
        rel("r4", "attributed-to", "campaign--c1", "intrusion-set--g1"),
        rel("r5", "uses", "campaign--c1", "attack-pattern--t3", "During Operation Test the actors created a scheduled task."),
        rel("r6", "uses", "intrusion-set--g1", "attack-pattern--t5", "Scanned the victim's perimeter."),
        rel("r7", "uses", "intrusion-set--g2", "attack-pattern--t2", "Other Panda used PowerShell."),
        rel("r8", "uses", "intrusion-set--g2", "attack-pattern--t4"),
        rel("r9", "uses", "intrusion-set--g1", "attack-pattern--t6", "revoked target"),
        rel("r10", "subtechnique-of", "attack-pattern--t2", "attack-pattern--t1"),
        rel("r11", "detects", "x-mitre-data-component--dc1", "attack-pattern--t3"),
        rel("r12", "detects", "x-mitre-data-component--dc2", "attack-pattern--t4"),
        rel("r13", "detects", "x-mitre-detection-strategy--det1", "attack-pattern--t2"),
        rel("r14", "uses", "intrusion-set--g1", "attack-pattern--t7", "Dumped LSASS."),
    ]
    return {"type": "bundle", "id": "bundle--1", "objects": o}


def kb_tools(tmp_path, connected=("security_onion", "velociraptor")):
    p = tmp_path / "enterprise-attack.json"
    p.write_text(json.dumps(bundle()))
    kb = attack.AttackKB([p])
    return kb, {t.name: t.handler for t in attack.tools(kb, lambda: tmp_path / "hunt_plans", lambda: list(connected))}


def test_resolution_and_group_techniques(tmp_path):
    kb, T = kb_tools(tmp_path)
    for name in ("Test Bear", "cozy test", "G9001", "tb-1"):
        g, _ = kb.resolve_group(name)
        assert g and g["name"] == "Test Bear", name
    g, cands = kb.resolve_group("test")  # substring of several -> ambiguous
    assert g is None and {c["name"] for c in cands} == {"Test Bear", "Other Panda"}
    assert kb.resolve_group("Old Group")[0] is None  # deprecated groups are not offered

    out = T["attack_group"](name="Cozy Test")
    assert out.startswith("G9001 Test Bear - ATT&CK Enterprise ATT&CK v17.1")
    assert "S9001 TestRAT" in out and "C9001 Operation Test" in out and "T1999" not in out
    order = [out.index(t) for t in ("T1595", "T1059.001", "T1053.005", "T1003.001", "T1071.001")]
    assert order == sorted(order)  # recon -> execution -> persistence -> credential access -> C2
    lines = {b.split()[0]: b for b in re.split(r"\n  (?=T\d{4})", out)[1:]}  # one block per technique
    assert "via: S9001 TestRAT" in lines["T1071.001"] and "seen by: security_onion" in lines["T1071.001"]
    assert "via: C9001 Operation Test" in lines["T1053.005"] and "seen by: velociraptor" in lines["T1053.005"]
    assert "Scheduled Job: Scheduled Job Creation" in lines["T1053.005"]
    assert "not observable with connected tools" in lines["T1595"]
    assert "WinEventLog:Security EventCode 4688" in lines["T1059.001"]  # v18-style detection strategy
    assert "Process: Process Access" in lines["T1003.001"]               # legacy x_mitre_data_sources
    assert "security_onion (if endpoint data is shipped to it)" in lines["T1003.001"]  # conditional source flagged

    linux = T["attack_group"](name="Test Bear", platforms=["Linux"])
    assert "T1071.001" in linux and "T1059.001" not in linux and "filtered from" in linux
    assert "T1053.005" not in T["attack_group"](name="Test Bear", include_campaigns=False)
    assert "T1071.001" not in T["attack_group"](name="Test Bear", include_software=False)
    assert "ambiguous" in T["attack_group"](name="test")


def test_technique_detail_search_and_layer(tmp_path):
    kb, T = kb_tools(tmp_path, connected=("security_onion", "elastic", "velociraptor"))
    d = T["attack_technique"](technique_id="t1059.001", group="TB-1")
    assert "T1059.001 PowerShell" in d and "Monitor for PowerShell" in d
    assert "Test Bear ran encoded PowerShell downloaders" in d and "(Citation" not in d
    assert "- elastic:" in d and "- velociraptor:" in d
    parent = T["attack_technique"](technique_id="T1059")
    assert "Sub-techniques: T1059.001 PowerShell" in parent
    assert "not recorded using" in T["attack_technique"](technique_id="T1003.001", group="Other Panda")
    assert "No live ATT&CK technique" in T["attack_technique"](technique_id="T1999")
    assert "G9002" in T["attack_search"](query="panda") and "T1071.001" in T["attack_search"](query="web protocols")

    msg = T["attack_navigator_layer"](name="Bear and Panda", groups=["Test Bear", "G9002"],
                                      technique_status={"t1059.001": "data_confirmed", "T1071.001": "no_data"})
    path = Path(msg.split("layer ")[1].split(" (")[0])
    layer = json.loads(path.read_text())
    assert path.parent == tmp_path / "hunt_plans" and layer["versions"]["layer"] == "4.5"  # next to the plan
    by = {t["techniqueID"]: t for t in layer["techniques"]}
    assert by["T1059.001"]["score"] == 2 and by["T1059.001"]["color"] == "#1565c0" and "status: data_confirmed" in by["T1059.001"]["comment"]
    assert by["T1071.001"]["score"] == 2 and by["T1071.001"]["color"] == "#c62828"
    assert by["T1053.005"]["score"] == 1 and "color" not in by["T1053.005"]


def test_missing_data_and_cli(tmp_path, monkeypatch, capsys):
    kb = attack.AttackKB([tmp_path / "nope.json"])
    T = {t.name: t.handler for t in attack.tools(kb, lambda: tmp_path, lambda: [])}
    assert "canarchist attack fetch" in T["attack_group"](name="APT29")
    (tmp_path / "nope.json").write_text(json.dumps(bundle()))  # data arrives later: picked up without a restart
    assert "G9001 Test Bear" in T["attack_group"](name="Test Bear")

    cfgp = write_config(tmp_path)
    src = tmp_path / "copied-enterprise-attack.json"
    src.write_text(json.dumps(bundle()))
    monkeypatch.setenv("ATTACK_STIX", str(tmp_path / "data" / "enterprise-attack.json"))
    cli(["--config", str(cfgp), "attack", "fetch", "--from", str(src)])  # air-gapped import
    assert (tmp_path / "data" / "enterprise-attack.json").is_file()
    cli(["--config", str(cfgp), "attack", "status"])
    cli(["--config", str(cfgp), "attack", "group", "Cozy Test"])
    out = capsys.readouterr().out
    assert "Enterprise ATT&CK v17.1" in out and "2 groups, 6 techniques, 1 software, 1 campaigns" in out
    assert "G9001 Test Bear" in out


def test_hunt_planner_expert_and_playbook(tmp_path, monkeypatch):
    cfg = load_config(write_config(tmp_path))
    gate = RoeGate(ROOT / "config" / "roe.yaml", AuditLog(tmp_path / "a.jsonl", "op"), None, "observe")
    assert gate.classify("attack_group", {})[0] == "auto"
    monkeypatch.setattr(agent_mod, "make_backend", lambda profile: ScriptedBackend({}))

    async def go():
        h = agent_mod.Harness(cfg, "HUNT-1", interactive=False)
        await h.start(new=True)
        try:
            a = h._build_subagent(agent_mod.SubAgent("SA-001", "hunt_planner", "planner", "t"))
            b = h._build_subagent(agent_mod.SubAgent("SA-002", "threat_hunter", "hunter", "t"))
            plans = h.hunt_plans_dir
            reg = h.registry.tools
            empty = reg["hunt_plan_list"].handler()
            reg["hunt_plan_save"].handler(name="APT29 & Volt Typhoon", content="# Hunt plan: APT29, Volt Typhoon\n...v1")
            reg["hunt_plan_save"].handler(name="APT29 & Volt Typhoon", content="# Hunt plan: APT29, Volt Typhoon\n...v2")
            listing = reg["hunt_plan_list"].handler()
            body = reg["hunt_plan_read"].handler(name="apt29_volt_typhoon")
            reg["hunt_plan_save"].handler(name="APT29 & Volt Typhoon", content="# Results\nT1059.001: clear", kind="results")
            hunted = reg["hunt_plan_list"].handler()
            outside = reg["hunt_plan_read"].handler(name="../../audit.jsonl")
            return ({t.name for t in a.tools}, h.experts["hunt_planner"], {t.name for t in b.tools}, h.lead.messages[0]["content"],
                    {t.name for t in h.lead.tools}, b.messages[0]["content"], plans, empty, listing, body, hunted, outside)
        finally:
            await h.close()

    (names, expert, hunter, lead_system, lead_tools, hunter_system, plans, empty, listing, body, hunted,
     outside) = asyncio.run(go())
    assert {"attack_group", "attack_technique", "attack_search", "attack_navigator_layer", "case_save_artifact",
            "velociraptor__list_clients", "submit_report"} <= names
    assert not {n for n in names if "quarantine" in n or "collect" in n or n.startswith("subagent_")}  # plans only
    planner_patterns = [t for t in expert.tools if "__" in t]  # it may survey what data exists, never search it
    assert not [t for t in planner_patterns if t.split("__")[1] in ("search", "esql", "eql", "pair_counts", "alerts",
                                                                     "alerts_summary", "search_dsl", "collect_artifact")]
    assert "never runs hunt queries" in expert.description and "Plans only" in expert.description
    assert {"attack_group", "attack_navigator_layer", "hunt_plan_list", "hunt_plan_read", "hunt_plan_save"} <= hunter
    assert "local_read_file" not in hunter  # it reads plans, not arbitrary files
    assert "hunt_plan_save" in names and "hunt_plan_list" in lead_tools  # planner writes; lead can see what exists

    # the hunt plans folder: every agent is told where it is; the hunter knows it must not run plans by itself
    assert plans.name == "hunt_plans" and plans.parent.name == "HUNT-1"
    assert f"Hunt plans folder (hunt_planner saves plans, threat_hunter reads them): {plans}" in hunter_system
    assert "You never execute a plan on your own" in hunter_system
    assert "No hunt plans yet" in empty
    assert "hunt_plan_APT29_Volt_Typhoon.md" in listing and "not hunted yet" in listing and "1 earlier version" in listing
    assert body.startswith("# hunt_plan_APT29_Volt_Typhoon.md") and "...v2" in body
    assert "hunted (results saved)" in hunted and "hunt_results_APT29_Volt_Typhoon.md" in hunted
    assert outside.startswith("No hunt plan named")  # cannot read outside the folder
    pb = (ROOT / "compensated_anarchist" / "playbooks" / "hunt_plan.md").read_text()
    assert "hunt_planner" in pb and "Navigator" in pb
    assert "Always check with the analyst first" in pb and "Then stop and wait for the answer" in pb
    assert "(a) from their input only" in pb and "(b) survey the connected systems" in pb and "Only on the analyst's go-ahead" in pb
    assert "Check with the analyst first" in lead_system and "never runs hunt queries" in lead_system
