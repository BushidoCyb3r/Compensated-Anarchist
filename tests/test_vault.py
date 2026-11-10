"""Evidence vault: files pulled from endpoints are stored read-only and never executable, executables are defanged,
and nothing in the evidence roots can be run by local_run."""

from __future__ import annotations

import asyncio
import base64
import importlib
import json
import os
import stat
import subprocess
import sys
from contextlib import contextmanager
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from compensated_anarchist import vault  # noqa: E402
from compensated_anarchist.case import Case  # noqa: E402
from compensated_anarchist.tools.forensics import Forensics  # noqa: E402

CID, FID = "C.0123456789abcdef", "F.CT9A1B2C3D"
FILES = {  # endpoint path -> content
    "C:/Users/bob/AppData/Local/Temp/update.exe": b"MZ\x90\x00\x03\x00 fake PE",
    "/tmp/.x/kworkerd": b"\x7fELF\x02\x01\x01 fake ELF, no extension",
    "/home/bob/run.sh": b"#!/bin/sh\ntouch /tmp/should-never-exist\n",
    "C:/Windows/System32/winevt/Logs/Security.evtx": b"ElfFile\x00 not an ELF - an event log",
    "/home/bob/notes.txt": b"just text",
}


def mod(monkeypatch, tmp_path):
    monkeypatch.setenv("VELO_API_CONFIG", str(tmp_path / "unused.api.yaml"))
    monkeypatch.setenv("VELO_DOWNLOAD_DIR", str(tmp_path / "evidence" / "vault" / "velociraptor"))
    v = importlib.reload(importlib.import_module("compensated_anarchist.servers.velociraptor"))
    ups = [{"client_path": p, "file_size": len(b), "vfs_path": f"/clients/{CID}/collections/{FID}/uploads/{i}",
            "cc": p.replace(":", "").split("/")} for i, (p, b) in enumerate(FILES.items())]
    by_vfs = {u["vfs_path"]: FILES[u["client_path"]] for u in ups}

    @contextmanager
    def stub():
        yield None

    def query(stub, vql, params, max_rows):
        data = by_vfs[params["CaPath"]][int(params["CaOff"]):int(params["CaOff"]) + int(params["CaLen"])]
        return [{"b": base64.b64encode(data).decode()}], []

    monkeypatch.setattr(v, "_vql", lambda vql, params=None, max_rows=1000: [dict(u) for u in ups])
    monkeypatch.setattr(v, "_stub", stub)
    monkeypatch.setattr(v, "_query", query)
    return v


def test_detection():
    assert vault.is_executable("x", b"MZ\x90\x00") and vault.is_executable("x", b"\x7fELF\x02")
    assert vault.is_executable("x", b"#!/bin/") and vault.is_executable("evil.PS1", b"Write-Host")
    assert vault.is_executable("y", b"\xcf\xfa\xed\xfe")  # Mach-O
    assert not vault.is_executable("Security.evtx", b"ElfFile\x00") and not vault.is_executable("a.txt", b"hello")


def test_downloads_land_read_only_and_never_executable(monkeypatch, tmp_path):
    v = mod(monkeypatch, tmp_path)
    out = json.loads(v.download_flow_uploads(CID, FID))
    files = {f["client_path"]: f for f in out["files"]}
    flow = Path(out["vault"])
    assert flow == (tmp_path / "evidence" / "vault" / "velociraptor" / CID / FID).resolve()

    # executables and scripts are defanged by suffix; data files keep their names
    for p in ("C:/Users/bob/AppData/Local/Temp/update.exe", "/tmp/.x/kworkerd", "/home/bob/run.sh"):
        assert files[p]["executable_quarantined"] and files[p]["local_path"].endswith(".quarantined"), p
    for p in ("C:/Windows/System32/winevt/Logs/Security.evtx", "/home/bob/notes.txt"):
        assert not files[p]["executable_quarantined"] and not files[p]["local_path"].endswith(".quarantined"), p

    # every file 0400, every folder in the flow 0500; content and hashes intact
    for f in out["files"]:
        st = Path(f["local_path"]).stat()
        assert stat.S_IMODE(st.st_mode) == 0o400 and f["size_verified"]
        assert not os.access(f["local_path"], os.X_OK)
    for dirpath, _, _ in os.walk(flow):
        assert stat.S_IMODE(Path(dirpath).stat().st_mode) == 0o500, dirpath
    script = Path(files["/home/bob/run.sh"]["local_path"])
    assert script.read_bytes() == FILES["/home/bob/run.sh"]

    # trying to run it fails, and it cannot be modified or added to
    with pytest.raises(PermissionError):
        subprocess.run([str(script)], check=False)
    assert not Path("/tmp/should-never-exist").exists()
    with pytest.raises(PermissionError):
        open(script, "ab")
    with pytest.raises(PermissionError):
        (script.parent / "dropped.exe").write_bytes(b"MZ")

    # manifest has every file with its origin and hash
    lines = [json.loads(x) for x in (flow.parents[1] / "MANIFEST.jsonl").read_text().splitlines()]
    assert {x["client_path"] for x in lines} == set(FILES) and all(len(x["sha256"]) == 64 for x in lines)

    # downloading again leaves the stored evidence untouched
    again = json.loads(v.download_flow_uploads(CID, FID))
    assert all(f.get("already_in_vault") for f in again["files"])
    assert stat.S_IMODE(flow.stat().st_mode) == 0o500


def test_local_run_never_executes_files_from_evidence_or_vault(monkeypatch, tmp_path):
    ev = tmp_path / "evidence"
    trap = vault.ensure(ev / "vault") / "planted"
    trap.mkdir(mode=0o700)
    marker = tmp_path / "ran"
    fake = trap / "fls"  # named like an allowlisted tool
    fake.write_text(f"#!/bin/sh\ntouch {marker}\n")
    fake.chmod(0o755)
    monkeypatch.setenv("PATH", f"{trap}:{os.environ.get('PATH', '')}")
    f = Forensics({"allowed_binaries": ["fls"]}, [ev], Case(tmp_path / "cases", "VAULT-1"))
    out = asyncio.run(f.run("fls", ["-h"]))
    assert out.startswith("ERROR: refusing to execute") and not marker.exists()
