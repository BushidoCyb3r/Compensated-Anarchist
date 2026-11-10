"""Per-case forensics folders: created for every case, readable by the forensic tools, never executable, listed with
detected types by local_case_evidence, and named in every agent's session block."""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_harness import ScriptedBackend, write_config  # noqa: E402

from compensated_anarchist import agent as agent_mod  # noqa: E402
from compensated_anarchist import casefiles  # noqa: E402
from compensated_anarchist.config import load_config  # noqa: E402


async def call(tool, **kw):
    """Tool handlers may be plain functions or coroutines (the executor accepts both)."""
    res = tool.handler(**kw)
    return await res if asyncio.iscoroutine(res) else res

SAMPLES = {
    "disk/ws01.E01": b"EVF\x09\x0d\x0a\xff\x00" + b"\x00" * 64,
    "memory/ws01.lime": b"EMiL" + b"\x00" * 64,
    "memory/MEMORY.DMP": b"PAGEDU64" + b"\x00" * 64,
    "logs/Security.evtx": b"ElfFile\x00" + b"\x00" * 64,
    "logs/auth.log": b"Nov 10 12:00:01 host sshd[1]: Accepted publickey",
    "triage/NTUSER.DAT": b"regf" + b"\x00" * 64,
    "triage/C/Windows/Prefetch/EVIL.EXE-1234.pf": b"\x1e\x00\x00\x00SCCA" + b"\x00" * 64,
    "triage/kape.zip": b"PK\x03\x04" + b"\x00" * 64,
    "network/capture.pcapng": b"\x0a\x0d\x0d\x0a" + b"\x00" * 64,
    "network/old.pcap": b"\xd4\xc3\xb2\xa1" + b"\x00" * 64,
    "mobile/sms.db": b"SQLite format 3\x00" + b"\x00" * 64,
    "other/dropper.bin": b"MZ\x90\x00" + b"\x00" * 64,
    "other/implant": b"\x7fELF\x02\x01\x01" + b"\x00" * 64,
}
EXPECT = {
    "disk/ws01.E01": "disk image (EWF/E01)", "memory/ws01.lime": "memory image (LiME)",
    "memory/MEMORY.DMP": "memory image (Windows crash dump)", "logs/Security.evtx": "Windows event log (EVTX)",
    "logs/auth.log": "log file", "triage/NTUSER.DAT": "registry hive",
    "triage/C/Windows/Prefetch/EVIL.EXE-1234.pf": "Windows prefetch", "triage/kape.zip": "zip archive (triage package?)",
    "network/capture.pcapng": "packet capture (PCAPNG)", "network/old.pcap": "packet capture (PCAP)",
    "mobile/sms.db": "SQLite database (browser / mobile / app artifact)",
    "other/dropper.bin": "Windows executable (PE) - analyze statically, never run",
    "other/implant": "Linux executable (ELF) - analyze statically, never run",
}


def test_folder_layout_and_type_detection(tmp_path):
    folder = casefiles.ensure_case_folder(tmp_path / "forensics", "IR-2026-0042")
    assert folder == tmp_path / "forensics" / "IR-2026-0042"
    assert {p.name for p in folder.iterdir()} == {*casefiles.SUBFOLDERS, "README.txt"}
    for rel, data in SAMPLES.items():
        (folder / rel).parent.mkdir(parents=True, exist_ok=True)
        (folder / rel).write_bytes(data)
    disk = folder / "disk" / "usb.dd"  # raw image recognized by its MBR boot signature
    with open(disk, "wb") as fh:
        fh.write(b"\x00" * 510 + b"\x55\xaa")
        fh.truncate(2 << 20)
    for rel, kind in EXPECT.items():
        assert casefiles.detect_type(folder / rel) == kind, rel
    assert casefiles.detect_type(disk) == "raw disk image (MBR)"
    casefiles.ensure_case_folder(tmp_path / "forensics", "IR-2026-0042")  # re-run touches nothing
    assert (folder / "logs" / "Security.evtx").read_bytes() == SAMPLES["logs/Security.evtx"]


def test_harness_creates_and_exposes_the_case_folder(tmp_path, monkeypatch):
    cfg = load_config(write_config(tmp_path))
    assert cfg.forensics_dir == (tmp_path / "forensics").resolve() and cfg.forensics_dir in cfg.evidence_roots
    fake = ScriptedBackend({})
    monkeypatch.setattr(agent_mod, "make_backend", lambda profile: fake)
    marker = tmp_path / "ran"

    async def go():
        h = agent_mod.Harness(cfg, "FOR-1", interactive=False)
        await h.start(new=True)
        folder = h.case_evidence_dir
        (folder / "logs" / "Security.evtx").write_bytes(SAMPLES["logs/Security.evtx"])
        tool = folder / "other" / "fls"  # planted program named like an allowlisted tool
        tool.write_text(f"#!/bin/sh\ntouch {marker}\n")
        tool.chmod(0o755)
        reg = h.registry.tools
        try:
            before = await call(reg["local_case_evidence"])
            info = await call(reg["local_file_info"], path=str(folder / "logs" / "Security.evtx"))  # readable: in the jail
            h.case.register_evidence(str(folder / "logs" / "Security.evtx"), "Security log from ws01", "analyst")
            after = await call(reg["local_case_evidence"])
            monkeypatch.setenv("PATH", f"{folder / 'other'}:{os.environ.get('PATH', '')}")
            from compensated_anarchist.tools.forensics import Forensics
            ran = await Forensics({"allowed_binaries": ["fls"]}, h.cfg.evidence_roots, h.case).run("fls", [])
            system, lead_tools = h.lead.messages[0]["content"], {t.name for t in h.lead.tools}
        finally:
            await h.close()  # always stop the MCP servers, or the event loop never exits
        return folder, before, info, after, ran, system, lead_tools

    folder, before, info, after, ran, system, lead_tools = asyncio.run(go())
    assert folder == cfg.forensics_dir / "FOR-1" and (folder / "README.txt").exists()
    assert "Windows event log (EVTX)" in before and "NOT registered" in before and "2 not yet registered" in before
    assert "script - analyze statically, never run" in before  # the planted tool is listed as what it is
    assert "sha256" in info.lower() and "Security.evtx" in info
    assert "logs/Security.evtx" in after and "1 not yet registered" in after  # the evtx is registered now
    assert ran.startswith("ERROR: refusing to execute") and not marker.exists()
    assert f"Case evidence folder (the analyst drops artifacts here): {folder}" in system  # every agent knows where
    assert "local_case_evidence" in lead_tools
