"""CTE planner (network maps, plan check against ATT&CK, no exploitation, plans folder) and the report writer
(example library, mission data sources, citation verifier, drafts, analyst statements), plus their wiring into the
harness and the dashboard."""

from __future__ import annotations

import asyncio
import base64
import io
import json
import sys
import time
import urllib.parse
import zipfile
import zlib
from datetime import datetime, timezone
from pathlib import Path

from starlette.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_attack import bundle, rel, tech  # noqa: E402
from test_harness import ScriptedBackend, write_config  # noqa: E402

from compensated_anarchist import agent as agent_mod  # noqa: E402
from compensated_anarchist import cte, huntplans, reports  # noqa: E402
from compensated_anarchist.attack import AttackKB  # noqa: E402
from compensated_anarchist.case import Case  # noqa: E402
from compensated_anarchist.config import load_config  # noqa: E402
from compensated_anarchist.history import ChatStore  # noqa: E402
from compensated_anarchist.skills import SkillStore  # noqa: E402

V = "http://schemas.microsoft.com/office/visio/2012/main"
R = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
WNS = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"


def zipped(files: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, text in files.items():
            z.writestr(name, text)
    return buf.getvalue()


# ---------------------------------------------------------------------------------------------------------------
# network maps
# ---------------------------------------------------------------------------------------------------------------
def test_network_maps(tmp_path):
    csv_ = tmp_path / "assets.csv"
    csv_.write_text("Hostname,IP Address,OS,Role,Zone,Owner\nDC01,10.1.1.10,Windows Server 2019,Domain controller,Server VLAN,IT\n"
                    "WS-042,10.1.2.42,Windows 11,Workstation,User VLAN,\n")
    out = cte.read_map(csv_)
    assert "Mapped columns: host=Hostname, ip=IP Address, os=OS, role=Role, zone=Zone" in out
    assert "- DC01 | 10.1.1.10 | Windows Server 2019 | Domain controller | Server VLAN | Owner=IT" in out
    assert "By zone: Server VLAN (1), User VLAN (1)" in out and "not instructions" in out

    nmap = tmp_path / "scan.xml"
    nmap.write_text('<?xml version="1.0"?><!DOCTYPE nmaprun><nmaprun args="nmap -sV 10.1.1.0/24" startstr="Tue Nov 10">'
                    '<host><status state="up"/><address addr="10.1.1.10" addrtype="ipv4"/><hostnames><hostname name="dc01.lab.local"/>'
                    '</hostnames><ports><port protocol="tcp" portid="445"><state state="open"/><service name="microsoft-ds" '
                    'product="Windows Server 2019"/></port><port protocol="tcp" portid="23"><state state="closed"/></port></ports>'
                    '<os><osmatch name="Microsoft Windows Server 2019" accuracy="98"/></os></host>'
                    '<host><status state="down"/><address addr="10.1.1.99"/></host></nmaprun>')
    out = cte.read_map(nmap)
    assert "nmap scan: 1 host(s) up" in out and "dc01.lab.local | 10.1.1.10 | Microsoft Windows Server 2019 (98%)" in out
    assert "445/tcp microsoft-ds Windows Server 2019" in out and "23/tcp" not in out and "10.1.1.99" not in out

    model = ('<mxGraphModel><root><mxCell id="0"/><mxCell id="1" parent="0"/>'
             '<mxCell id="z" value="Server VLAN" style="swimlane" vertex="1" parent="1"/>'
             '<object id="a" label="DC01" ip="10.1.1.10"><mxCell style="shape=mxgraph.cisco.servers.fileserver" vertex="1" parent="z"/></object>'
             '<mxCell id="b" value="&lt;b&gt;FW1&lt;/b&gt;" style="shape=mxgraph.cisco.firewalls.firewall" vertex="1" parent="1"/>'
             '<mxCell id="e" edge="1" source="a" target="b" parent="1"/></root></mxGraphModel>')
    plain = tmp_path / "site.drawio"
    plain.write_text(f'<mxfile><diagram name="Site">{model}</diagram></mxfile>')
    c = zlib.compressobj(9, zlib.DEFLATED, -15)
    packed = base64.b64encode(c.compress(urllib.parse.quote(model).encode()) + c.flush()).decode()
    compressed = tmp_path / "site2.drawio"
    compressed.write_text(f'<mxfile><diagram name="Packed">{packed}</diagram></mxfile>')
    for f in (plain, compressed):
        out = cte.read_map(f)
        assert "- DC01 [fileserver] (in Server VLAN) | ip=10.1.1.10" in out, out
        assert "- FW1 [firewall]" in out and "link: DC01 -- FW1" in out

    vsdx = tmp_path / "enclave.vsdx"
    vsdx.write_bytes(zipped({
        "visio/masters/masters.xml": f'<Masters xmlns="{V}"><Master ID="2" NameU="Server"/><Master ID="3" NameU="PC"/></Masters>',
        "visio/pages/pages.xml": f'<Pages xmlns="{V}" xmlns:r="{R}"><Page ID="0" NameU="Enclave A"><Rel r:id="rId1"/></Page></Pages>',
        "visio/pages/_rels/pages.xml.rels": '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                                            '<Relationship Id="rId1" Type="page" Target="page1.xml"/></Relationships>',
        "visio/pages/page1.xml": (
            f'<PageContents xmlns="{V}"><Shapes>'
            '<Shape ID="1" Master="2"><Section N="Property"><Row N="IPAddress"><Cell N="Value" V="10.1.1.10"/></Row></Section><Text>DC01</Text></Shape>'
            '<Shape ID="2" Master="3"><Text>WS-042</Text></Shape><Shape ID="3"><Text>uplink</Text></Shape>'
            '<Shape ID="4" Type="Group"><Text>DMZ</Text><Shapes><Shape ID="5"><Text>WEB01</Text></Shape></Shapes></Shape>'
            '</Shapes><Connects><Connect FromSheet="3" FromCell="BeginX" ToSheet="1"/><Connect FromSheet="3" FromCell="EndX" ToSheet="2"/>'
            '</Connects></PageContents>')}))
    out = cte.read_map(vsdx)
    assert "Visio page 'Enclave A': 5 shape(s), 1 connection(s)" in out
    assert "- DC01 [Server] | IPAddress=10.1.1.10" in out and "- WEB01 (in DMZ)" in out
    assert "link: DC01 -- WS-042 (uplink)" in out and "- uplink" not in out

    note = tmp_path / "network.md"
    note.write_text("Flat enterprise network: 2 DCs, 300 Windows 11 workstations, a Linux web tier.")
    assert "300 Windows 11 workstations" in cte.read_map(note)
    (tmp_path / "diagram.png").write_bytes(b"\x89PNG")
    assert "can't be read as text" in cte.read_map(tmp_path / "diagram.png")
    (tmp_path / "old.vsd").write_bytes(b"\xd0\xcf\x11\xe0")
    assert "save it as .vsdx" in cte.read_map(tmp_path / "old.vsd")


# ---------------------------------------------------------------------------------------------------------------
# CTE plan check, plans folder, layer, Atomic tests
# ---------------------------------------------------------------------------------------------------------------
def kb_with_exploitation(tmp_path) -> AttackKB:
    b = bundle()
    b["objects"] += [tech("t8", "T1190", "Exploit Public-Facing Application", "initial-access", ["Windows", "Linux"]),
                     tech("t9", "T1486", "Data Encrypted for Impact", "impact", ["Windows"]),
                     tech("t10", "T1021", "Remote Services", "lateral-movement", ["Windows"]),
                     rel("r20", "uses", "intrusion-set--g1", "attack-pattern--t8", "Exploited a VPN appliance."),
                     rel("r21", "uses", "intrusion-set--g1", "attack-pattern--t9", "Encrypted file servers.")]
    p = tmp_path / "enterprise-attack.json"
    p.write_text(json.dumps(b))
    return AttackKB([p])


GOOD_PLAN = """# CTE plan: Test Bear (G9001) against enterprise Windows
| 1 | execution | T1059.001 | PowerShell | WS-042 | Atomic Red Team: tests for T1059.001 (operator selects) |
| 2 | persistence | T1053.005 | Scheduled Task | WS-042 |
| 3 | command-and-control | T1071.001 | Web Protocols | WS-042 |
| 4 | credential-access | T1003.001 | LSASS Memory | WS-042 |
| 5 | execution | T1059 | Command and Scripting Interpreter (parent of the group's T1059.001) |
| 6 | lateral-movement | T1021 | Remote Services | analyst-added |
## Not emulated
- T1190 Exploit Public-Facing Application: not emulated (exploitation). Detection: web server and VPN logs.
- T1486 Data Encrypted for Impact: not emulated (destructive). Detection: file modification bursts.
"""


def test_cte_plan_check_folder_and_layer(tmp_path):
    kb = kb_with_exploitation(tmp_path)
    ok, report = cte.check_plan(kb, GOOD_PLAN, ["Test Bear"])
    assert ok, report
    bad = (GOOD_PLAN.replace("not emulated (exploitation)", "emulate with a test exploit")
           .replace("| analyst-added |", "|").replace("T1486 Data Encrypted for Impact: not emulated", "T1486 Data Encrypted for Impact: emulate")
           + "| 7 | T9999 | made up |\n")
    ok, report = cte.check_plan(kb, bad, ["Test Bear"])
    assert not ok
    assert "(T1190): exploitation (Exploit Public-Facing Application) is never emulated" in report
    assert "(T1486): destructive or disruptive impact (Data Encrypted for Impact) is never emulated" in report
    assert "(T1021): ATT&CK does not record Test Bear using this technique" in report
    assert "(T9999): not a live ATT&CK technique" in report
    assert "T1059" not in report.split("problem(s):")[1].replace("T1059.001", "")  # a parent of the group's sub-technique is fine
    ok, report = cte.check_plan(kb, GOOD_PLAN, ["Nobody Group"])
    assert not ok and "'Nobody Group' is not an ATT&CK group" in report
    assert cte.never_emulated("T1068") and cte.never_emulated("t1499.004") and not cte.never_emulated("T1059.001")

    folder = tmp_path / "cte_plans"
    saved = []
    atomics = tmp_path / "atomics" / "T1059.001"
    atomics.mkdir(parents=True)
    (atomics / "T1059.001.yaml").write_text(
        "attack_technique: T1059.001\ndisplay_name: PowerShell\natomic_tests:\n- name: Mimic download cradle\n"
        "  auto_generated_guid: 11111111-2222\n  description: Simulates a download cradle.\n  supported_platforms: [windows]\n"
        "  executor: {name: powershell, elevation_required: false, command: SECRET-COMMAND-TEXT}\n")
    T = {t.name: t.handler for t in cte.tools(kb, lambda: folder, lambda: [folder / "maps", tmp_path / "evidence"],
                                               {"atomics_dir": str(tmp_path / "atomics")}, on_saved=lambda p, k: saved.append((p.name, k)))}
    msg = T["cte_plan_save"](name="Test Bear", content=bad, actors=["Test Bear"])
    assert msg.startswith("NOT SAVED") and not (folder / "cte_plan_Test_Bear.md").exists() and not saved
    msg = T["cte_plan_save"](name="Test Bear", content=GOOD_PLAN, actors=["Test Bear"])
    plan = folder / "cte_plan_Test_Bear.md"
    assert msg.startswith(f"saved {plan}") and plan.read_text() == GOOD_PLAN and saved == [("cte_plan_Test_Bear.md", "cte_plan")]
    assert (folder / ".agent" / plan.name).read_text() == GOOD_PLAN
    assert "Steps" not in T["cte_plan_changes"](name="Test Bear") and "unchanged" in T["cte_plan_changes"](name="Test Bear")
    plan.write_text(GOOD_PLAN + "- Analyst: always include a stop condition for the domain controllers.\n")  # the analyst edits it
    assert "[edited by the analyst]" in T["cte_plan_list"]()
    assert "+- Analyst: always include a stop condition" in T["cte_plan_changes"](name="test bear")
    assert "EDITED BY THE ANALYST" in T["cte_plan_read"](name="Test Bear")
    T["cte_plan_save"](name="Test Bear", content="## Results\n| 1 | T1059.001 | detected |", actors=["Test Bear"], kind="results")
    assert (folder / "cte_results_Test_Bear.md").exists() and saved[-1][1] == "cte_results"

    assert "Not live ATT&CK techniques" in T["cte_navigator_layer"](name="Test Bear", actors=["Test Bear"], technique_status={"T9999": "emulate"})
    T["cte_navigator_layer"](name="Test Bear", actors=["Test Bear"],
                             technique_status={"T1059.001": "emulate", "T1190": "not_emulated", "T1021": "analyst_added"})
    layer = json.loads((folder / "attack_layer_cte_Test_Bear.json").read_text())
    assert {t["techniqueID"]: t["metadata"][0]["value"] for t in layer["techniques"]} == \
        {"T1059.001": "emulate", "T1190": "not_emulated", "T1021": "analyst_added"}

    tests_ = T["cte_atomic_tests"](technique_id="t1059.001")
    assert "#1 Mimic download cradle" in tests_ and "executor: powershell" in tests_ and "SECRET-COMMAND-TEXT" not in tests_
    assert "No local Atomic Red Team checkout" in cte.atomic_tests(None, "T1059.001")
    assert "has no tests for T1003.001" in T["cte_atomic_tests"](technique_id="T1003.001")

    (folder / "maps").mkdir(parents=True, exist_ok=True)
    (folder / "maps" / "assets.csv").write_text("host,ip\nDC01,10.1.1.10\n")
    assert "assets.csv" in T["cte_network_map"]() and "- DC01 | 10.1.1.10" in T["cte_network_map"](name="ASSETS.csv")
    assert "No file named" in T["cte_network_map"](name="../../etc/passwd")

    kb_missing = AttackKB([tmp_path / "nope.json"])
    ok, report = cte.check_plan(kb_missing, GOOD_PLAN, ["Test Bear"])
    assert not ok and "No MITRE ATT&CK data" in report


# ---------------------------------------------------------------------------------------------------------------
# report writer
# ---------------------------------------------------------------------------------------------------------------
NOW = datetime(2026, 11, 11, 15, 0, tzinfo=timezone.utc)


def mission(tmp_path):
    case = Case(tmp_path / "cases", "R-1")
    case.add_finding(title="Beacon from ws01", severity="high", confidence="medium",
                     description="`ws01` (10.0.5.21) beaconed to 203.0.113.7 every 60s; 1,440 connections.",
                     attack_techniques=["T1071.001"], affected_assets=["ws01"])
    case.add_timeline_event("2026-11-10T14:22:05+00:00", "first beacon to 203.0.113.7", host="ws01", source="zeek.conn")
    store = ChatStore(tmp_path / "h.db")
    conv = store.create("R-1", "beacon")
    ev1 = store.append(conv["id"], "s", "analyst_message", {"text": "Mark it UNCLASSIFIED. It is for the SOC lead."}, time.time())
    ev2 = store.append(conv["id"], "s", "subagent_report", {"id": "SA-001", "expert": "network_analyst", "status": "completed",
                       "summary": "ws01 beacons to 203.0.113.7 over HTTPS (port 443).", "details": "zeek.ssl"}, time.time())
    hunts = tmp_path / "cases" / "R-1" / "hunt_plans"
    hunts.mkdir()
    (hunts / "hunt_results_beacon.md").write_text("# Hunt results\nHunt H1 matched 3 hosts beaconing to 203.0.113.7.\n")
    md = reports.MissionData(case, store, {"hunt plans": hunts}, now=lambda: NOW)
    ex = tmp_path / "reports" / "examples"
    (ex / "incident_report").mkdir(parents=True)
    (ex / "incident_report" / "old.md").write_text(
        "# Incident Report\n## BLUF\nOn 2024-03-01 host `HQ-FS-07` at 192.0.2.44 was compromised during Operation Silent "
        "Night, reported by Major Jane Doe. SECRET//NOFORN\n")
    (ex / "incident_report" / "old.docx").write_bytes(zipped({
        "word/header1.xml": f'<w:hdr xmlns:w="{WNS}"><w:p><w:r><w:t>SECRET//NOFORN</w:t></w:r></w:p></w:hdr>',
        "word/document.xml": (
            f'<w:document xmlns:w="{WNS}"><w:body>'
            '<w:p><w:pPr><w:pStyle w:val="Heading1"/></w:pPr><w:r><w:t>Executive Summary</w:t></w:r></w:p>'
            '<w:p><w:r><w:t>The C2 server was </w:t></w:r><w:r><w:t>198.51.100.23.</w:t></w:r></w:p>'
            '<w:tbl><w:tr><w:tc><w:p><w:r><w:t>IP</w:t></w:r></w:p></w:tc><w:tc><w:p><w:r><w:t>Role</w:t></w:r></w:p></w:tc></w:tr>'
            '<w:tr><w:tc><w:p><w:r><w:t>198.51.100.23</w:t></w:r></w:p></w:tc><w:tc><w:p><w:r><w:t>C2</w:t></w:r></w:p></w:tc></w:tr></w:tbl>'
            '</w:body></w:document>')}))
    (ex / "incident_report" / "scan.pdf").write_bytes(b"%PDF-1.4")
    return case, store, md, ex, ev1, ev2


def good_draft(ev2: int) -> str:
    return f"""# Incident report: beacon from ws01
UNCLASSIFIED

## Bottom line up front
Host `ws01` (10.0.5.21) beaconed to 203.0.113.7 [FIN-0001]. The finding is still unreviewed by the analyst [FIN-0001].
The first beacon was at 2026-11-10 14:22Z [TIM-0001]. The beacon used port 443 [EV-{ev2}].
It made 1,440 connections [FIN-0001]. The hunt matched 3 hosts [FILE:hunt_results_beacon.md].
Report date: 2026-11-11 [NOW].

## Questions / gaps
- Who owns 10.0.5.21, and is it still on the network?
"""


def test_report_verifier_drafts_and_examples(tmp_path):
    case, store, md, ex, ev1, ev2 = mission(tmp_path)
    folder = tmp_path / "cases" / "R-1" / "reports"
    saved = []
    T = {t.name: t.handler for t in reports.tools(lambda: md, lambda: folder, lambda: ex, lambda t: "",
                                                   on_saved=lambda p, k: saved.append((p.name, k)))}

    text = reports.docx_text((ex / "incident_report" / "old.docx").read_bytes())
    assert text.startswith("[page header] SECRET//NOFORN") and "# Executive Summary" in text
    assert "The C2 server was 198.51.100.23." in text and "| 198.51.100.23 | C2 |" in text
    lib = T["report_examples"]()
    assert "incident_report: 3 file(s); no approved template yet" in lib and "scan.pdf" in lib and "unsupported format" in lib
    assert "FORMAT ONLY" in T["report_example_read"](report_type="incident_report", file="old.docx")
    assert "unsupported format" in T["report_example_read"](report_type="incident_report", file="scan.pdf")

    src = T["report_sources"]()
    for want in ("CASE R-1", "NOW:", "FIN-0001 finding [high, verdict unreviewed] Beacon from ws01", f"EV-{ev1}", f"EV-{ev2}",
                 "FILE:hunt_results_beacon.md"):
        assert want in src, want
    assert "Hunt H1 matched 3 hosts" in T["report_source"](source_id="file:hunt_results_beacon.md")
    assert "No source" in T["report_source"](source_id="FIN-0099")

    # missing facts are not invented: uncited, unsupported and unknown sources are refused
    bad = ("# Report\n## Summary\nHost `ws01` beaconed to 203.0.113.7.\nThe attacker also used 198.51.100.200 [FIN-0001].\n"
           "It started on 2026-11-09 [TIM-0001]. Lateral movement reached 4 hosts [FIN-0099].\n")
    msg = T["report_save"](name="incident", content=bad)
    assert msg.startswith("NOT SAVED") and not folder.exists() or not list(folder.glob("report_*"))
    assert "[uncited]" in msg and "ip '198.51.100.200' is not in the cited source(s) FIN-0001" in msg
    assert "date '2026-11-09' is not in the cited source(s) TIM-0001" in msg and "cites FIN-0099" in msg

    # nothing from the example reports leaks in; markings only from the analyst
    leak = good_draft(ev2) + "\n## Context\nThe C2 at 192.0.2.44 matched `HQ-FS-07` [FIN-0001].\n"
    msg = T["report_verify"](content=leak)
    assert "[example_leak] '192.0.2.44' comes from an example report" in msg and "'HQ-FS-07' comes from an example report" in msg
    msg = T["report_verify"](content=good_draft(ev2).replace("UNCLASSIFIED", "SECRET//NOFORN"))
    assert "marking 'SECRET' was not given by the analyst" in msg and "marking 'NOFORN'" in msg
    msg = T["report_verify"](content=good_draft(ev2) + "\n## More\n(S) A portion marking [FIN-0001].\n")
    assert "marking 'S' was not given" in msg

    # a supported draft saves, with sources and verification appended; a phrase from an old report is a warning
    draft = good_draft(ev2) + "\nNot connected to Operation Silent Night as far as the data shows [FIN-0001].\n"
    msg = T["report_save"](name="incident", content=draft, report_type="incident_report")
    v1 = folder / "report_incident_v1.md"
    assert msg.startswith(f"saved {v1}") and saved == [("report_incident_v1.md", "report")]
    body = v1.read_text()
    assert reports.GENERATED in body and "## Sources" in body and "- FIN-0001 finding [high, verdict unreviewed]" in body
    assert "0 blocking problems" in body and "possible_leak" in body and "operation silent night" in body
    # re-saving a draft that still carries the generated tail regenerates it once, as v2
    T["report_save"](name="incident", content=body)
    v2 = folder / "report_incident_v2.md"
    assert v2.read_text().count("## Sources") == 1 and v1.exists()

    # the analyst edits the draft; the reporter can read the edits; final copy keeps them
    v2.write_text(v2.read_text().replace("Report date", "Report DTG"))
    assert "[edited by the analyst]" in T["report_list"]() and "+Report DTG: 2026-11-11 [NOW]." in T["report_changes"](name="incident")
    msg = T["report_finalize"](name="incident")
    final = folder / "report_incident_final.md"
    assert msg.startswith(f"final copy saved: {final}") and "analyst's own edits" in msg and "Report DTG" in final.read_text()
    assert saved[-1] == ("report_incident_final.md", "report_final")
    assert "Report DTG" in T["report_read"](name="incident_final.md") or "Report DTG" in T["report_read"](name="report_incident_final.md")


def test_values_and_units():
    vals = reports.values("ran `powershell -enc AAA` on WS01 at 14:22Z on port 443: 1,440 connections, 3 hosts, LAB-0001, "
                          "SHA256 and RFC1918, e.g. this, see https://x.example/a and evil.example.com")
    kinds = {(k, v) for k, v in vals}
    assert ("code", "powershell -enc AAA") in kinds and ("time", "14:22Z") in kinds and ("number", "443") in kinds
    assert ("count", "1,440") in kinds and ("count", "3") in kinds and ("ref", "LAB-0001") in kinds
    assert ("url", "https://x.example/a") in kinds and ("domain", "evil.example.com") in kinds
    assert not any(v in ("SHA256", "RFC1918", "e.g") for _, v in vals)
    units = reports._units("# T\nOne fact 10.0.0.1. [FIN-0001]\n| a | b |\n|---|---|\n```\nquery 10.0.0.2\n```\n## Questions\n- why 10.0.0.3?\n")
    assert units[0][1] == "One fact 10.0.0.1. [FIN-0001]" and units[-1][2] is True and units[2][3] is True


# ---------------------------------------------------------------------------------------------------------------
# harness wiring: experts, always-on skills, tools, ROE, analyst statements; dashboard
# ---------------------------------------------------------------------------------------------------------------
def test_harness_wiring_and_analyst_statements(tmp_path, monkeypatch):
    cfg = load_config(write_config(tmp_path))
    draft = ("# Report\nUNCLASSIFIED\n\n## BLUF\nThe analyst set the marking [STA-0001]. The case is `RPT-1` [CASE].\n")
    scripts = {
        "lead": [("Recording your answer, then tasking the reporter.", [
            ("case_analyst_statement", {"question": "Classification?", "answer": "unclassified"}),
            ("case_analyst_statement", {"question": "Classification?", "answer": "TOP SECRET"}),
            ("subagent_spawn", {"expert": "reporter", "task": "incident report", "context": "markings: STA-0001"})]),
            ("SITREP", [])],
        "Report Writer": [("Drafting.", [("report_save", {"name": "incident", "content": draft})]),
                          ("done", [("submit_report", {"status": "completed", "summary": "draft v1",
                                                       "skills_used": [{"name": "report-writing", "worked": True}]})])],
    }
    fake = ScriptedBackend(scripts)
    monkeypatch.setattr(agent_mod, "make_backend", lambda profile: fake)

    async def go():
        h = agent_mod.Harness(cfg, "RPT-1")
        await h.start()
        store = SkillStore(cfg.memory_db, cfg.skills)
        assert {"cte-plan-build", "report-writing"} <= {s["name"] for s in store.list()}
        assert store.get("cte-plan-build")["expert"] == "cte_planner" and store.get("report-writing")["active_version"] == 1
        # tool sets: the reporter has no memory and no way to add facts; the planner cannot touch a host
        rep = {t.name for t in h.registry.specs(h.experts["reporter"].tools, [])}
        assert "report_save" in rep and "case_analyst_statement" in rep and "case_summary" in rep
        assert not {n for n in rep if n.startswith(("memory_", "case_add_")) or n == "case_write_report"}
        planner = {t.name for t in h.registry.specs(h.experts["cte_planner"].tools, [])}
        assert {"cte_plan_save", "cte_network_map", "attack_group"} <= planner
        assert not {n for n in planner if n.startswith(("vuln_", "local_run", "hunt_plan_save")) or "collect" in n
                    or "quarantine" in n or n.endswith(("__search", "__esql", "__create_hunt"))}
        assert {"cte_plan_list", "report_list"} <= {t.name for t in h.lead.tools}
        assert "case_write_report" not in h.registry.tools
        assert h.roe.classify("report_finalize", {})[0] == "approve" and h.roe.classify("report_save", {})[0] == "auto"
        assert h.roe.classify("cte_plan_save", {})[0] == "auto"
        system = h.lead.messages[0]["content"]
        assert f"CTE plans folder (cte_planner; network maps in maps/): {h.cte_dir}" in system
        assert h.report_examples_dir == tmp_path / "reports" / "examples" and (h.report_examples_dir / "README.txt").exists()

        await h.mission("Write the incident report. Mark it UNCLASSIFIED.")
        sts = h.case.data["statements"]
        assert len(sts) == 1 and sts[0]["id"] == "STA-0001" and sts[0]["answer"] == "unclassified" and sts[0]["by"] == "tester"
        lead_results = [m["content"] for m in h.lead.messages if m["role"] == "tool"]
        assert any("recorded STA-0001" in r for r in lead_results) and any("NOT RECORDED" in r for r in lead_results)
        assert (h.reports_dir / "report_incident_v1.md").exists()
        brief = next(m["content"] for m in h.subagents["SA-001"].agent.messages if m["role"] == "user")
        assert "## Skill report-writing v1" in brief and "# Write a report from mission data" in brief
        assert store.get("report-writing")["successes"] == 1
        await h.close()

    asyncio.run(go())


def test_dashboard_lists_cte_plans_and_reports(tmp_path, monkeypatch):
    from test_dashboard import login, make

    dash, app = make(tmp_path, monkeypatch, {})
    with TestClient(app) as c:
        login(c)
        h = dash.harness
        st = c.get("/api/state").json()
        assert st["cte_folder"] == str(h.cte_dir) and st["reports_folder"] == str(h.reports_dir)
        assert c.get("/api/report").text == ""
        huntplans.write_versioned(h.cte_dir, "cte_plan_test_bear.md", "# CTE plan: Test Bear")
        huntplans.write_versioned(h.reports_dir, "report_incident_v1.md", "# Draft one")
        files = {f["name"]: f for f in c.get("/api/plans").json()["files"]}
        assert files["cte_plan_test_bear.md"]["kind"] == "cte_plan" and files["report_incident_v1.md"]["kind"] == "report"
        assert files["cte_plan_test_bear.md"]["edited"] is False
        assert c.get("/api/plans/cte_plan_test_bear.md").text == "# CTE plan: Test Bear"
        assert c.get("/api/plans/maps").status_code == 404
        assert c.get("/api/report").text == "# Draft one"
        huntplans.write_versioned(h.reports_dir, "report_incident_final.md", "# Final")
        assert c.get("/api/report").text == "# Final"
        assert c.get("/api/plans").json()["files"][0]["kind"] in ("report_final", "report")


def test_authored_artifacts_keep_earlier_versions(tmp_path):
    """Code and rules the agents save keep their history: the reviewer's version survives the author's fixes."""
    import os
    case = Case(tmp_path / "cases", "CODE-1")
    first = case.save_artifact("parse_logons.py", "print('v1')\n")
    authored = case.artifacts / "authored"
    os.utime(authored / "parse_logons.py", (1_700_000_000, 1_700_000_000))
    second = case.save_artifact("parse_logons.py", "print('v2')\n")
    assert "earlier version" not in first and "earlier version is kept in older/" in second
    assert (authored / "parse_logons.py").read_text() == "print('v2')\n"
    assert [p.read_text() for p in (authored / "older").iterdir()] == ["print('v1')\n"]
    assert (authored / ".agent" / "parse_logons.py").read_text() == "print('v2')\n"
