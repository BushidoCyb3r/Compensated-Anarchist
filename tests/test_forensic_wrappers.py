"""Forensic wrapper tests. Real tools where installed (sigma-cli, capa); otherwise stand-ins that mimic the
real CLI's arguments and output layout (Zimmerman tools need .NET, FLOSS/MemProcFS/ALEAPP need samples)."""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import stat
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from compensated_anarchist.case import Case  # noqa: E402
from compensated_anarchist.tools.forensics import Forensics  # noqa: E402

VENV_BIN = Path(sys.executable).parent
CAPA_RULES = os.environ.get("CA_CAPA_RULES", "")

SIGMA_RULE = """title: Encoded PowerShell
id: 3b6ab547-8ec2-4991-b9d2-2b06702a48d7
status: test
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\\\\powershell.exe'
    CommandLine|contains: ' -enc '
  condition: selection
level: high
"""


def script(path: Path, body: str) -> Path:
    path.write_text("#!" + sys.executable + "\n" + body)
    path.chmod(path.stat().st_mode | stat.S_IEXEC)
    return path


@pytest.fixture
def fx(tmp_path, monkeypatch):
    ev = tmp_path / "evidence"
    ev.mkdir()
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    monkeypatch.setenv("PATH", f"{fake_bin}{os.pathsep}{VENV_BIN}{os.pathsep}{os.environ['PATH']}")
    case = Case(tmp_path / "cases", "FX-1")
    cfg = {"capa_rules_dir": CAPA_RULES}
    return Forensics(cfg, [ev], case), ev, fake_bin, tmp_path


@pytest.mark.skipif(not shutil.which("sigma", path=str(VENV_BIN)), reason="sigma-cli not installed")
def test_sigma_convert_real(fx):
    f, *_ = fx
    spl = asyncio.run(f.sigma_convert(SIGMA_RULE, "splunk", ["splunk_windows"]))
    assert "powershell.exe" in spl.lower() and "-enc" in spl.lower(), spl
    eql = asyncio.run(f.sigma_convert(SIGMA_RULE, "eql", ["ecs_windows"]))
    assert "process.command_line" in eql.lower(), eql
    esql = asyncio.run(f.sigma_convert(SIGMA_RULE, "esql", ["sysmon"]))
    assert "from " in esql.lower(), esql
    bad = asyncio.run(f.sigma_convert(SIGMA_RULE, "esql", ["ecs_windows"]))
    assert "not intended to be used with the target esql" in bad  # real error reaches the agent
    kql = asyncio.run(f.sigma_convert(SIGMA_RULE, "kusto", ["microsoft_xdr"]))
    assert "DeviceProcessEvents" in kql, kql
    check = asyncio.run(f.sigma_check(SIGMA_RULE))
    assert "error" not in check.lower() or "0 errors" in check.lower() or "no errors" in check.lower(), check
    assert asyncio.run(f.sigma_convert(SIGMA_RULE, "splunk; rm -rf /")).startswith("ERROR")


@pytest.mark.skipif(not (shutil.which("capa", path=str(VENV_BIN)) and CAPA_RULES), reason="set CA_CAPA_RULES to a capa-rules dir")
def test_capa_real_elf(fx):
    f, ev, *_ = fx
    shutil.copy("/usr/bin/true", ev / "true.elf")
    out = json.loads(asyncio.run(f.capa(str(ev / "true.elf"))))
    assert out["format"] == "elf" and out["capabilities"] and Path(out["full_json"]).exists()


def test_ez_tool_standin(fx):
    f, ev, fake_bin, _ = fx
    script(fake_bin / "PECmd", """import sys, pathlib
a = sys.argv; out = pathlib.Path(a[a.index('--csv') + 1]); out.mkdir(parents=True, exist_ok=True)
assert a[1] in ('-d', '-f')
(out / '20261109_PECmd_Output.csv').write_text('ExecutableName,RunCount,LastRun\\nEVIL.EXE,3,2026-11-08 21:13:00\\nCMD.EXE,40,2026-11-09\\n')
print('Processed 2 files')
""")
    pf = ev / "Prefetch"
    pf.mkdir()
    (pf / "EVIL.EXE-1234ABCD.pf").write_bytes(b"MAM\x04")
    out = json.loads(asyncio.run(f.ez_tool("PECmd", str(pf))))
    assert out["files"][0]["rows"] == 2 and "EVIL.EXE" in out["preview"]
    assert asyncio.run(f.ez_tool("Calc", str(pf))).startswith("ERROR")
    assert asyncio.run(f.ez_tool("PECmd", str(pf), ["$(id)"])).startswith("ERROR")
    with pytest.raises(PermissionError):
        asyncio.run(f.ez_tool("PECmd", "/etc"))


def test_floss_standin(fx):
    f, ev, fake_bin, _ = fx
    script(fake_bin / "floss", """import json
print('INFO: floss: extracting static strings')
print(json.dumps({"metadata": {}, "strings": {"decoded_strings": [{"string": "http://185.220.101.47/beacon"}],
  "stack_strings": [{"string": "cmd.exe /c whoami"}], "tight_strings": [{"string": "VirtualAlloc"}]}}))
""")
    (ev / "s.exe").write_bytes(b"MZ" + b"\0" * 64)
    out = json.loads(asyncio.run(f.floss(str(ev / "s.exe"))))
    assert out["decoded_strings"]["strings"] == ["http://185.220.101.47/beacon"]
    out = json.loads(asyncio.run(f.floss(str(ev / "s.exe"), grep="whoami")))
    assert out["stack_strings"]["count"] == 1 and out["decoded_strings"]["count"] == 0


def test_memprocfs_standin(fx, monkeypatch):
    f, ev, _, tmp = fx
    fake = tmp / "fakempfs" / "memprocfs"
    fake.mkdir(parents=True)
    (fake / "__init__.py").write_text('''
FILES = {"/sys/proc/proc.txt": b"   PID  PPID NAME\\n  4  0 System\\n 6120 712 rundll32.exe\\n",
         "/sys/net/netstat.txt": b"TCP 10.1.2.3:50122 185.220.101.47:443 ESTABLISHED rundll32.exe\\n",
         "/forensic/progress_percent.txt": b"100",
         "/forensic/findevil/findevil.txt": b"PE_INJECT rundll32.exe 6120\\n",
         "/forensic/csv/timeline_all.csv": b"time,type,desc\\n2026-11-08,PROC,rundll32\\n"}
class _Vfs:
    def read(self, path, length, offset=0):
        return FILES[path][offset:offset + length]
    def list(self, path):
        p = path.rstrip("/") + "/"
        return {k[len(p):]: {"size": len(v), "f_isdir": False} for k, v in FILES.items() if k.startswith(p) and "/" not in k[len(p):]}
class Vmm:
    def __init__(self, args):
        assert args[0] == "-device"
        self.vfs = _Vfs()
''')
    monkeypatch.setenv("PYTHONPATH", str(fake.parent))
    (ev / "mem.raw").write_bytes(b"\0" * 4096)
    s = json.loads(asyncio.run(f.memprocfs(str(ev / "mem.raw"), "summary")))
    assert "rundll32.exe" in s["processes"] and "185.220.101.47" in s["netstat"]
    fe = json.loads(asyncio.run(f.memprocfs(str(ev / "mem.raw"), "findevil")))
    assert "PE_INJECT" in fe["findevil"]
    tl = json.loads(asyncio.run(f.memprocfs(str(ev / "mem.raw"), "timeline")))
    assert Path(tl["csv"][0]["file"]).read_text().startswith("time,type")


def test_leapp_standin(fx):
    f, ev, _, tmp = fx
    aleapp = script(tmp / "aleapp.py", """import sys, pathlib
a = sys.argv; out = pathlib.Path(a[a.index('-o') + 1]) / 'ALEAPP_Reports_2026'
(out / '_TSV Exports').mkdir(parents=True)
(out / '_TSV Exports' / 'Chrome History.tsv').write_text('url\\ttime\\nhttp://evil.example\\t2026-11-08\\n')
(out / 'index.html').write_text('<html></html>')
assert a[a.index('-t') + 1] == 'fs'
""")
    f.aleapp = str(aleapp)
    (ev / "android").mkdir()
    out = json.loads(asyncio.run(f.leapp("android", str(ev / "android"))))
    assert out["artifacts"][0]["artifact"] == "Chrome History" and out["artifacts"][0]["rows"] == 1
    assert "not configured" in asyncio.run(f.leapp("ios", str(ev / "android")))


ECHO = "import os, sys, json; print(json.dumps({'argv': sys.argv[1:], 'cwd': os.getcwd()}))\n"


def test_volatility_runs_in_its_output_folder_and_keeps_its_own_options(fx):
    """Volatility runs in a new folder in the case artifacts (-o and working directory): --dump output never lands in
    the dashboard's working directory, and relative paths in plugin_args count from that folder. Its own options
    (--plugin-dirs loads Python plugins; --log and --output-dir write files; --file swaps the image), any prefix of
    them, and short options are refused. A refused call leaves no folder behind."""
    f, ev, fake_bin, tmp = fx
    script(fake_bin / "vol", ECHO)
    img = ev / "mem.raw"
    img.write_bytes(b"\0" * 16)
    (tmp / "secret.txt").write_text("not evidence")
    for bad in (["--plugin-dirs=/tmp"], ["--plug=x"], ["-p", "x"], ["--output-dir=x"], ["--log=x"], ["--file=x"],
                ["--conf"], ["--"]):
        out = asyncio.run(f.volatility(str(img), "windows.pslist", bad))
        assert out.startswith("ERROR: rejected plugin argument"), (bad, out)
    up = "../" * (len(f.case.artifacts.resolve().relative_to(tmp.resolve()).parts) + 1)  # run folder -> tmp
    with pytest.raises(PermissionError):
        asyncio.run(f.volatility(str(img), "windows.pslist", ["--yara-file=" + up + "secret.txt"]))
    text = asyncio.run(f.volatility(str(img), "windows.pslist", ["--pid=4", "--dump"]))
    ran = json.loads(text.split("\n", 1)[1])
    run_dir = Path(ran["cwd"])
    assert run_dir.parent == f.case.artifacts.resolve() and run_dir.name.startswith("vol_windows.pslist_")
    assert ran["argv"][:2] == ["-q", "-o"] and Path(ran["argv"][2]).resolve() == run_dir
    assert ran["argv"][-2:] == ["--pid=4", "--dump"] and (run_dir / "output.txt").exists()
    assert [p.name for p in f.case.artifacts.glob("vol_*")] == [run_dir.name]


def test_ez_tool_runs_in_its_output_folder(fx):
    """A Zimmerman tool runs in its output folder, so '..' in extra_args means the case artifacts, not the folder
    above the dashboard's working directory. Paths and RECmd batch files outside the jail are refused."""
    f, ev, fake_bin, tmp = fx
    script(fake_bin / "PECmd", ECHO)
    script(fake_bin / "RECmd", ECHO)
    pf = ev / "Prefetch"
    pf.mkdir()
    out = json.loads(asyncio.run(f.ez_tool("PECmd", str(pf), ["-d", ".."])))
    ran = json.loads(out["log_tail"])
    assert Path(ran["cwd"]) == Path(out["output_dir"]).resolve() and ran["argv"][-2:] == ["-d", ".."]
    with pytest.raises(PermissionError):
        asyncio.run(f.ez_tool("PECmd", str(pf), ["/etc"]))
    hive = ev / "SYSTEM"
    hive.write_bytes(b"regf")
    (tmp / "outside.reb").write_text("Description: test\n")
    assert asyncio.run(f.ez_tool("RECmd", str(hive), batch_file=str(tmp / "outside.reb"))).startswith("ERROR: batch_file")
    (ev / "inside.reb").write_text("Description: test\n")
    ok = json.loads(asyncio.run(f.ez_tool("RECmd", str(hive), batch_file=str(ev / "inside.reb"))))
    assert str((ev / "inside.reb").resolve()) in json.loads(ok["log_tail"])["argv"]


def test_plaso_date_filter_cannot_become_an_option(fx):
    """date_filter is psort's FILTER expression; one starting with - would be read as an option (-w <path> writes the
    timeline anywhere), so it is refused before anything runs. Both plaso tools run in their case output folder."""
    f, ev, fake_bin, tmp = fx
    script(fake_bin / "log2timeline.py", ECHO)
    script(fake_bin / "psort.py", ECHO)
    src = ev / "triage"
    src.mkdir()
    for bad in ("-w/tmp/x", "--write=/tmp/x"):
        assert asyncio.run(f.plaso_timeline(str(src), bad)).startswith("ERROR: date_filter")
    assert not list(f.case.artifacts.glob("plaso_*"))
    out = asyncio.run(f.plaso_timeline(str(src), "date > '2026-01-01 00:00:00'"))
    runs = [json.loads(line) for line in out.splitlines() if line.startswith("{")]
    assert len(runs) == 2 and runs[1]["argv"][-1] == "date > '2026-01-01 00:00:00'"
    assert all(Path(r["cwd"]).parent == f.case.artifacts.resolve() for r in runs)
