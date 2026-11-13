"""Local forensic tooling on the analyst workstation / forensic VM.

Safety properties:
  - no shell: every command is an argv list (no injection through file names / args)
  - reads are jailed to configured evidence_roots + the case directory
  - writes go only to the case artifacts directory; evidence is never modified
  - binaries resolved from config; generic `local_run` only allows allowlisted binaries, never one whose options
    run code (NEVER_LOCAL_RUN), and every path its arguments name - absolute, relative or after `=` - must stay in
    the jail (an argument check, not a sandbox: review what an approved call does)
  - every call is still subject to the ROE gate
"""

from __future__ import annotations

import asyncio
import fnmatch
import json
import os
import sys
import re
import shutil
import signal
import stat
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .. import casefiles
from ..case import Case, sha256_file
from .registry import Tool, schema

DEFAULT_BINARIES = {
    "file": "file", "strings": "strings", "yara": "yara", "volatility": "vol", "tshark": "tshark",
    "zeek": "zeek", "capa": "capa", "exiftool": "exiftool", "hayabusa": "hayabusa", "chainsaw": "chainsaw",
    "log2timeline": "log2timeline.py", "psort": "psort.py", "bulk_extractor": "bulk_extractor",
    "floss": "floss", "sigma": "sigma", "dotnet": "dotnet",
}
MAX_CAPTURE = 5 * 1024 * 1024
# local_run never starts these, whatever forensics.allowed_binaries says: their options run code (exiftool's -if and
# -p evaluate Perl, -config loads a Perl file) or rewrite files. The value is the tool to use instead.
NEVER_LOCAL_RUN = {"exiftool": "local_exiftool (read-only metadata, fixed arguments)"}


def _never_run(name: str) -> str:
    """The tool to use instead when local_run must refuse `name` (exiftool, exiftool.pl, ...), else ""."""
    return NEVER_LOCAL_RUN.get(Path(name).name.lower().split(".", 1)[0], "")


def _path_like(value: str) -> bool:
    return value.startswith(("/", "~")) or "/" in value or value in (".", "..")


# Volatility 3 options that are not a plugin's: they load code (--plugin-dirs loads Python plugins), write files
# (--log, --cache-path, --write-config, --save-config, --output-dir), change what is read or how (--file,
# --single-location, --single-swap-locations, --config, --extend, --symbol-dirs) or fetch from the network
# (--remote-isf-url). Volatility reads its own options wherever they appear and accepts any unambiguous prefix of
# one (argparse), so plugin_args may not carry them or a prefix of them. The harness sets -q, -o and -f itself.
VOL_GLOBAL_OPTIONS = ("plugin-dirs", "symbol-dirs", "config", "extend", "file", "single-location",
                      "single-swap-locations", "output-dir", "log", "cache-path", "clear-cache", "write-config",
                      "save-config", "remote-isf-url")


def _vol_global_option(arg: str) -> str:
    """Why `arg` (one starting with -) may not be a plugin argument, or ""."""
    if not arg.startswith("--"):
        return "plugin options are long options (--pid=4); short options set Volatility's own settings"
    name = arg[2:].split("=", 1)[0].lower()
    hit = next((g for g in VOL_GLOBAL_OPTIONS if g.startswith(name)), "")
    return f"--{hit} is Volatility's own option, set by the harness or not allowed" if hit else ""


class PathJail:
    def __init__(self, roots: list[Path]):
        self.roots = [r.resolve() for r in roots]

    def inside(self, p: Path) -> bool:
        return any(p == r or r in p.parents for r in self.roots)

    def check(self, path: str) -> Path:
        p = Path(os.path.expanduser(path)).resolve()
        if not self.inside(p):
            raise PermissionError(f"{p} is outside the allowed evidence roots {[str(r) for r in self.roots]}")
        if not p.exists():
            raise FileNotFoundError(str(p))
        return p

    def check_from(self, path: str, cwd: Path) -> Path:
        """`path` as a program running in `cwd` opens it (relative paths count from `cwd`). One that exists must be
        inside the roots; one that does not exist yet (an output) must be inside `cwd`, so nothing new is written
        into the evidence."""
        p = Path(os.path.expanduser(path))
        p = (p if p.is_absolute() else cwd / p).resolve()
        if p.exists():
            if not self.inside(p):
                raise PermissionError(f"{path} ({p}) is outside the allowed evidence roots {[str(r) for r in self.roots]}")
        else:
            base = cwd.resolve()
            if not (p == base or base in p.parents):
                raise PermissionError(f"{path} ({p}) does not exist; a new file or folder (an output) can only be "
                                      f"created inside {base}")
        return p

    def check_args(self, args: list[str], cwd: Path) -> None:
        """Every path in a command's arguments must stay in the jail: an argument that starts with / or ~, contains
        a /, or is . or ..; and the same after `=` (--out=../x, name=/tmp/x). A path attached to a short option
        (-o/tmp/x) cannot be told apart from the option's letters, so it is refused: give it as its own argument."""
        for a in args:
            head, eq, value = a.partition("=")
            if a.startswith("-"):
                if "/" in head or ".." in head:
                    raise PermissionError(f"argument {a!r}: give the path as its own argument, not attached to an option")
                candidates = [value] if eq else []
            else:
                candidates = [a, value] if eq else [a]
            for c in candidates:
                if _path_like(c):
                    self.check_from(c, cwd)


class Forensics:
    def __init__(self, cfg: dict[str, Any], evidence_roots: list[Path], case: Case,
                 case_folder: Path | None = None, vault_dir: Path | None = None):
        self.case = case
        self.case_folder = case_folder
        self.vault_dir = vault_dir
        self.jail = PathJail([*evidence_roots, case.dir])
        self.bin = {**DEFAULT_BINARIES, **(cfg.get("binaries") or {})}
        self.allowed_run = set(cfg.get("allowed_binaries") or [])
        self.timeout = int(cfg.get("default_timeout_s", 900))
        self.yara_rules_dir = cfg.get("yara_rules_dir", "")
        self.sigma_rules_dir = cfg.get("sigma_rules_dir", "")
        self.capa_rules = cfg.get("capa_rules_dir", "")
        self.ez_dir = cfg.get("ez_tools_dir", "")
        self.mpfs_python = cfg.get("memprocfs_python") or sys.executable
        self.aleapp = cfg.get("aleapp_path", "")
        self.ileapp = cfg.get("ileapp_path", "")
        self.leapp_python = cfg.get("leapp_python") or sys.executable

    # ---- helpers ------------------------------------------------------------
    def _which(self, key: str) -> str:
        exe = self.bin.get(key, key)
        found = shutil.which(exe)
        if not found:
            raise FileNotFoundError(f"'{exe}' ({key}) is not installed / not on PATH. Run local_tools_inventory.")
        return found

    def _outdir(self, prefix: str, create: bool = True) -> Path:
        """A new output folder in the case artifacts. create=False only names it, so a call refused while its
        arguments are checked leaves no empty folder behind."""
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
        d = self.case.artifacts / f"{prefix}_{stamp}_{uuid.uuid4().hex[:4]}"
        if create:
            d.mkdir(parents=True, exist_ok=True)
        return d

    async def _run(self, argv: list[str], timeout: int | None = None, cwd: Path | None = None) -> str:
        # its own process group, so a timeout or Stop also ends the workers it starts (plaso runs several)
        proc = await asyncio.create_subprocess_exec(
            *argv, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, cwd=cwd,
            stdin=asyncio.subprocess.DEVNULL, start_new_session=True)
        try:
            out, err = await asyncio.wait_for(proc.communicate(), timeout or self.timeout)
        except asyncio.TimeoutError:
            _kill_group(proc)
            await proc.wait()
            return f"ERROR: timed out after {timeout or self.timeout}s: {' '.join(argv[:4])} ..."
        except asyncio.CancelledError:  # the analyst stopped the operation or this subagent, or the dashboard stopped
            _kill_group(proc)
            raise
        text = out[:MAX_CAPTURE].decode("utf-8", "replace")
        if len(out) > MAX_CAPTURE:  # never let a partial output pass for the whole: counts made from it are partial
            text += (f"\n[OUTPUT CUT: only the first {MAX_CAPTURE:,} of {len(out):,} bytes are shown. Counts made from "
                     "this text are partial; narrow the run, or have the tool write a file and read that.]")
        if proc.returncode != 0:
            text += f"\n[exit code {proc.returncode}]\n[stderr]\n" + err[-4000:].decode("utf-8", "replace")
        return text or "(no output)"

    # ---- tools ----------------------------------------------------------------
    async def tools_inventory(self) -> str:
        rows = [f"{k:15s} {v:20s} {'OK ' + shutil.which(v) if shutil.which(v) else 'MISSING'}" for k, v in self.bin.items()]
        try:
            import yara  # noqa: F401
            rows.append("yara-python     (module)             OK")
        except ImportError:
            pass
        rows.append(f"\nlocal_run allowlist: {sorted(self.allowed_run) or 'none'}")
        rows.append(f"evidence roots: {[str(r) for r in self.jail.roots]}")
        return "\n".join(rows)

    def list_dir(self, path: str, pattern: str = "*", recursive: bool = False, max_entries: int = 500) -> str:
        root = self.jail.check(path)
        it = root.rglob("*") if recursive else root.iterdir()
        rows = []
        for p in it:
            if not fnmatch.fnmatch(p.name, pattern):
                continue
            try:
                st = p.lstat()
            except OSError:
                continue
            kind = "d" if stat.S_ISDIR(st.st_mode) else ("l" if stat.S_ISLNK(st.st_mode) else "f")
            mtime = datetime.fromtimestamp(st.st_mtime, timezone.utc).isoformat()[:19]
            rows.append(f"{kind} {st.st_size:>12} {mtime} {p}")
            if len(rows) >= max_entries:
                rows.append(f"... truncated at {max_entries} entries")
                break
        return "\n".join(rows) or "(empty)"

    async def file_info(self, path: str) -> str:
        p = self.jail.check(path)
        st = p.stat()
        magic = await self._run([self._which("file"), "-b", str(p)]) if shutil.which(self.bin["file"]) else "n/a"
        hashes = sha256_file(p) if p.is_file() else {}
        ts = {k: datetime.fromtimestamp(getattr(st, f"st_{k}"), timezone.utc).isoformat() for k in ("mtime", "atime", "ctime")}
        return "\n".join([f"path: {p}", f"size: {st.st_size}", f"mode: {oct(st.st_mode)}", f"type: {magic.strip()}",
                          *[f"{k}: {v}" for k, v in ts.items()], *[f"{k}: {v}" for k, v in hashes.items()]])

    def read_file(self, path: str, offset: int = 0, length: int = 8000, mode: str = "text") -> str:
        p = self.jail.check(path)
        length = min(max(length, 1), 64000)
        with open(p, "rb") as fh:
            fh.seek(offset)
            data = fh.read(length)
        if mode == "hex":
            lines = []
            for i in range(0, len(data), 16):
                chunk = data[i:i + 16]
                asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
                lines.append(f"{offset + i:08x}  {chunk.hex(' '):<48}  {asc}")
            return "\n".join(lines)
        return f"[bytes {offset}-{offset + len(data)} of {p.stat().st_size}]\n" + data.decode("utf-8", "replace")

    async def strings(self, path: str, min_len: int = 6, encoding: str = "ascii", grep: str = "", max_lines: int = 500) -> str:
        p = self.jail.check(path)
        enc = {"ascii": "s", "utf16le": "l", "utf16be": "b"}.get(encoding, "s")
        out = await self._run([self._which("strings"), "-a", "-t", "x", "-n", str(min_len), "-e", enc, str(p)])
        lines = out.splitlines()
        if grep:
            rx = re.compile(grep, re.I)
            lines = [ln for ln in lines if rx.search(ln)]
        more = f"\n... {len(lines) - max_lines} more lines" if len(lines) > max_lines else ""
        return "\n".join(lines[:max_lines]) + more

    async def yara_scan(self, target: str, rules: str = "", recursive: bool = True) -> str:
        t = self.jail.check(target)
        rules_path = rules or self.yara_rules_dir
        if not rules_path:
            return "ERROR: no rules given and forensics.yara_rules_dir not configured"
        rp = Path(os.path.expanduser(rules_path)).resolve()
        if rules:  # the agent's choice: rule files in the evidence roots, the case folder or the configured rules dir
            home = Path(os.path.expanduser(self.yara_rules_dir)).resolve() if self.yara_rules_dir else None
            if not (self.jail.inside(rp) or (home and (rp == home or home in rp.parents))):
                raise PermissionError(f"{rules}: YARA rules must be in forensics.yara_rules_dir"
                                      f"{f' ({home})' if home else ''}, the evidence roots or the case folder")
        if rp.is_dir():
            files = sorted([*rp.rglob("*.yar"), *rp.rglob("*.yara")])
        else:
            files = [rp]
        if shutil.which(self.bin["yara"]):
            results = []
            for rf in files[:500]:
                argv = [self._which("yara"), "-w", "-s"] + (["-r"] if recursive and t.is_dir() else []) + [str(rf), str(t)]
                res = await self._run(argv)
                if res.strip() and res.strip() != "(no output)":
                    results.append(f"## {rf.name}\n{res}")
            return "\n".join(results) or f"no matches ({len(files)} rule files)"
        try:
            import yara
        except ImportError:
            return "ERROR: neither yara binary nor yara-python installed"
        compiled = yara.compile(filepaths={f"r{i}": str(f) for i, f in enumerate(files)})
        targets = [x for x in (t.rglob("*") if t.is_dir() and recursive else [t]) if x.is_file()]
        hits = []
        for f in targets:
            for m in compiled.match(str(f), timeout=60):
                hits.append(f"{m.rule} {f} tags={m.tags}")
        return "\n".join(hits) or f"no matches across {len(targets)} files"

    async def volatility(self, image: str, plugin: str, plugin_args: list[str] | None = None) -> str:
        """Volatility 3 runs in its own output folder in the case artifacts (-o and the working directory), so files a
        plugin writes (--dump) land there, and relative paths in plugin_args count from there."""
        img = self.jail.check(image)
        if not re.fullmatch(r"(windows|linux|mac)\.[A-Za-z0-9_.]+", plugin):
            return "ERROR: plugin must look like windows.pslist / linux.bash / mac.pslist"
        args = [str(a) for a in plugin_args or []]
        for a in args:
            if not re.fullmatch(r"--?[A-Za-z0-9-]+(=[\w.:,\\/ -]+)?|[\w.:,\\/-]+", a):
                return f"ERROR: rejected plugin argument {a!r}"
            if a.startswith("-") and (why := _vol_global_option(a)):
                return f"ERROR: rejected plugin argument {a!r}: {why}"
        out = self._outdir(f"vol_{plugin}", create=False)
        self.jail.check_args(args, out)
        out.mkdir(parents=True, exist_ok=True)
        text = await self._run([self._which("volatility"), "-q", "-o", str(out), "-f", str(img), plugin, *args], cwd=out)
        dest = out / "output.txt"
        dest.write_text(text)
        return f"[saved {dest}; files the plugin writes are in {out}]\n{text}"

    async def pcap_stats(self, pcap: str) -> str:
        p = self.jail.check(pcap)
        ts = self._which("tshark")
        parts = []
        for stat_ in ("io,phs", "conv,ip", "endpoints,ip"):
            parts.append(f"## {stat_}\n" + await self._run([ts, "-n", "-r", str(p), "-q", "-z", stat_]))
        return "\n".join(parts)

    async def tshark(self, pcap: str, display_filter: str = "", fields: list[str] | None = None, max_packets: int = 500) -> str:
        p = self.jail.check(pcap)
        argv = [self._which("tshark"), "-n", "-r", str(p), "-c", str(min(max_packets, 20000))]
        if display_filter:
            argv += ["-Y", display_filter]
        if fields:
            argv += ["-T", "fields", "-E", "header=y", "-E", "separator=\t"]
            for f in fields:
                if not re.fullmatch(r"[A-Za-z0-9_.]+", f):
                    return f"ERROR: bad field {f!r}"
                argv += ["-e", f]
        return await self._run(argv)

    async def zeek(self, pcap: str) -> str:
        p = self.jail.check(pcap)
        out = self._outdir("zeek")
        res = await self._run([self._which("zeek"), "-C", "-r", str(p), "LogAscii::use_json=T"], cwd=out)
        logs = sorted(x.name for x in out.glob("*.log"))
        notice = (out / "notice.log").read_text()[:4000] if (out / "notice.log").exists() else "(no notice.log)"
        return f"zeek logs in {out}: {logs}\n{res if 'ERROR' in res else ''}\n## notice.log (head)\n{notice}"

    async def evtx_hunt(self, evtx_path: str, min_level: str = "medium") -> str:
        p = self.jail.check(evtx_path)
        out = self._outdir("evtx_hunt")
        if shutil.which(self.bin["hayabusa"]):
            csv = out / "hayabusa.csv"
            res = await self._run([self._which("hayabusa"), "csv-timeline", "-d" if p.is_dir() else "-f", str(p),
                                   "-o", str(csv), "-m", min_level, "-w", "-q", "-U"], timeout=3600)
            head = csv.read_text()[:12000] if csv.exists() else res
            return f"[hayabusa timeline saved {csv}]\n{head}"
        if shutil.which(self.bin["chainsaw"]):
            if not self.sigma_rules_dir:
                return "ERROR: chainsaw needs forensics.sigma_rules_dir (and its mapping file) configured"
            mapping = (self.bin.get("chainsaw_mapping") or "")
            argv = [self._which("chainsaw"), "hunt", str(p), "-s", self.sigma_rules_dir, "--csv", "--output", str(out)]
            if mapping:
                argv += ["--mapping", mapping]
            return await self._run(argv, timeout=3600) + f"\n[output dir {out}]"
        return "ERROR: neither hayabusa nor chainsaw installed"

    async def plaso_timeline(self, source: str, date_filter: str = "") -> str:
        """log2timeline + psort, run in their output folder in the case artifacts. date_filter is psort's FILTER
        expression (a positional argument): one starting with - would be read as an option (-w <path> would write
        the timeline anywhere), so it is refused."""
        src = self.jail.check(source)
        date_filter = str(date_filter or "")
        if date_filter.startswith("-"):
            return ("ERROR: date_filter is a psort filter expression such as \"date > '2026-01-01 00:00:00'\"; it "
                    "cannot start with -")
        out = self._outdir("plaso")
        store = out / "timeline.plaso"
        r1 = await self._run([self._which("log2timeline"), "--status_view", "none", "--unattended",
                              "--storage-file", str(store), str(src)], timeout=6 * 3600, cwd=out)
        argv = [self._which("psort"), "--status_view", "none", "-o", "l2tcsv", "-w", str(out / "timeline.csv"), str(store)]
        if date_filter:
            argv.append(date_filter)
        r2 = await self._run(argv, timeout=3600, cwd=out)
        return f"plaso storage {store}\ncsv {out / 'timeline.csv'}\n{r1[-2000:]}\n{r2[-2000:]}"

    async def capa(self, path: str, file_format: str = "auto") -> str:
        """capa JSON -> capabilities grouped with ATT&CK / MBC mappings (full JSON saved to artifacts)."""
        p = self.jail.check(path)
        if file_format not in ("auto", "pe", "dotnet", "elf", "sc32", "sc64"):
            return "ERROR: file_format must be auto|pe|dotnet|elf|sc32|sc64"
        argv = [self._which("capa"), "-q", "-j", "-f", file_format]
        if self.capa_rules:
            argv += ["-r", self.capa_rules]
        out = await self._run(argv + [str(p)], timeout=1800)
        try:
            data = json.loads(out)
        except json.JSONDecodeError:
            return out  # error text from capa (e.g. unsupported format / missing rules)
        dest = self._outdir("capa") / "capa.json"
        dest.write_text(out)
        caps, attack, mbc = [], set(), set()
        for name, m in data.get("rules", {}).items():
            meta = m.get("meta", {})
            if meta.get("lib"):
                continue
            ids = [a.get("id") for a in meta.get("attack", []) if a.get("id")]
            attack.update(f"{a.get('id')} {a.get('technique', '')}".strip() for a in meta.get("attack", []))
            mbc.update(f"{b.get('id', '')} {b.get('objective', '')}::{b.get('behavior', '')}".strip() for b in meta.get("mbc", []))
            caps.append({"capability": name, "namespace": meta.get("namespace"), "attack": ids,
                         "matches": len(m.get("matches", {}) or [])})
        a = data.get("meta", {}).get("analysis", {})
        return json.dumps({"sample": data.get("meta", {}).get("sample", {}).get("sha256"), "format": a.get("format"),
                           "arch": a.get("arch"), "os": a.get("os"), "capabilities": sorted(caps, key=lambda c: c["namespace"] or ""),
                           "attack": sorted(attack), "mbc": sorted(mbc), "full_json": str(dest)}, indent=1)

    async def floss(self, path: str, min_length: int = 6, grep: str = "", include_static: bool = False,
                    max_per_type: int = 300) -> str:
        """FLOSS: decoded, stack and tight strings (obfuscated strings plain `strings` misses)."""
        p = self.jail.check(path)
        argv = [self._which("floss"), "-j", "-n", str(int(min_length))]
        if not include_static:
            argv += ["--only", "decoded", "stack", "tight"]
        out = await self._run(argv + [str(p)], timeout=3600)
        try:
            data = json.loads(out[out.index("{"):]) if "{" in out else json.loads(out)
        except (json.JSONDecodeError, ValueError):
            return out
        dest = self._outdir("floss") / "floss.json"
        dest.write_text(json.dumps(data))
        rx = re.compile(grep, re.I) if grep else None
        result: dict[str, Any] = {"full_json": str(dest)}
        for kind, items in (data.get("strings") or {}).items():
            vals = [i.get("string", "") for i in items or []]
            if rx:
                vals = [v for v in vals if rx.search(v)]
            result[kind] = {"count": len(vals), "strings": vals[:max_per_type]}
        return json.dumps(result, indent=1)

    # ---- Eric Zimmerman tools ---------------------------------------------------------
    EZ_TOOLS = {  # tool -> (input flag for a file, input flag for a directory)
        "MFTECmd": ("-f", "-f"), "PECmd": ("-f", "-d"), "LECmd": ("-f", "-d"), "JLECmd": ("-f", "-d"),
        "AmcacheParser": ("-f", None), "AppCompatCacheParser": ("-f", None), "RECmd": ("-f", "-d"),
        "SBECmd": (None, "-d"), "SrumECmd": ("-f", "-d"), "EvtxECmd": ("-f", "-d"), "RBCmd": ("-f", "-d"),
        "WxTCmd": ("-f", None), "SQLECmd": (None, "-d"), "bstrings": ("-f", "-d"),
    }

    def _ez_command(self, tool: str) -> list[str]:
        exe = shutil.which(tool)
        if exe:
            return [exe]
        if self.ez_dir:
            for dll in Path(self.ez_dir).rglob(f"{tool}.dll"):
                return [self._which("dotnet"), str(dll)]
        raise FileNotFoundError(f"{tool} not found: put it on PATH or set forensics.ez_tools_dir (needs the .NET runtime)")

    async def ez_tool(self, tool: str, input_path: str, extra_args: list[str] | None = None, batch_file: str = "",
                      head_rows: int = 25) -> str:
        """Run an Eric Zimmerman parser to CSV and return the output files with row counts and a preview."""
        if tool not in self.EZ_TOOLS:
            return f"ERROR: tool must be one of {sorted(self.EZ_TOOLS)}"
        src = self.jail.check(input_path)
        file_flag, dir_flag = self.EZ_TOOLS[tool]
        flag = dir_flag if src.is_dir() else file_flag
        if not flag:
            return f"ERROR: {tool} needs a {'directory' if src.is_file() else 'file'} as input"
        extra = [str(a) for a in extra_args or []]
        for a in extra:  # flags, simple values, or paths inside the evidence jail
            if not a.startswith(("/", "~")) and not re.fullmatch(r"--?[A-Za-z][\w-]*|[\w.:,@ -]+", a):
                return f"ERROR: rejected argument {a!r}"
        out = self._outdir(f"ez_{tool}", create=False)  # the tool runs here, so relative paths (..) count from here
        self.jail.check_args(extra, out)
        argv = [*self._ez_command(tool), flag, str(src), "--csv", str(out)]
        if tool == "RECmd":
            if batch_file:
                bp = Path(os.path.expanduser(batch_file))
                bp = (bp if bp.is_absolute() else out / bp).resolve()
                ez = Path(self.ez_dir).resolve() if self.ez_dir else None
                if not bp.is_file() or not (self.jail.inside(bp) or (ez and ez in bp.parents)):
                    return ("ERROR: batch_file must be a .reb file in forensics.ez_tools_dir, the evidence roots or the "
                            "case folder")
            bn = str(bp) if batch_file else next(
                (str(b) for b in Path(self.ez_dir or "/nonexistent").rglob("Kroll_Batch.reb")), "")
            if not bn:
                return "ERROR: RECmd needs a batch file (batch_file=...reb or forensics.ez_tools_dir containing BatchExamples)"
            argv += ["--bn", bn]
        out.mkdir(parents=True, exist_ok=True)
        log = await self._run(argv + extra, timeout=7200, cwd=out)
        csvs = sorted(out.rglob("*.csv"))
        files = []
        for c in csvs:
            with open(c, encoding="utf-8", errors="replace") as fh:
                rows = sum(1 for _ in fh) - 1
            files.append({"csv": str(c), "rows": max(rows, 0)})
        preview = ""
        if csvs:
            biggest = max(csvs, key=lambda c: c.stat().st_size)
            with open(biggest, encoding="utf-8", errors="replace") as fh:
                preview = "".join(next(fh, "") for _ in range(head_rows + 1))
        return json.dumps({"tool": tool, "output_dir": str(out), "files": files, "preview": preview,
                           "log_tail": log[-1500:]}, indent=1)

    # ---- Sigma --------------------------------------------------------------------------------
    def _rule_file(self, rule: str) -> Path:
        if "\n" in rule or rule.lstrip().startswith(("title:", "detection:")):
            d = self._outdir("sigma")
            p = d / "rule.yml"
            p.write_text(rule, encoding="utf-8")
            return p
        return self.jail.check(rule)

    async def sigma_convert(self, rule: str, target: str, pipelines: list[str] | None = None, output_format: str = "") -> str:
        """Convert Sigma rule(s) (YAML text, a rule file or a directory) to a SIEM query with sigma-cli."""
        if not re.fullmatch(r"[a-z0-9_]+", target):
            return "ERROR: bad target"
        argv = [self._which("sigma"), "convert", "-t", target]
        for pl in pipelines or []:
            if not re.fullmatch(r"[A-Za-z0-9_.\-]+", pl):
                return f"ERROR: bad pipeline {pl!r}"
            argv += ["-p", pl]
        if not pipelines:
            argv.append("--without-pipeline")
        if output_format:
            argv += ["-f", output_format]
        return await self._run(argv + [str(self._rule_file(rule))], timeout=300)

    async def sigma_check(self, rule: str) -> str:
        """Validate Sigma rule(s): syntax, required fields and common issues (sigma check)."""
        return await self._run([self._which("sigma"), "check", str(self._rule_file(rule))], timeout=300)

    # ---- MemProcFS -----------------------------------------------------------------------------
    async def memprocfs(self, image: str, action: str = "summary", path: str = "", length: int = 60000,
                        timeout_s: int = 3600) -> str:
        """MemProcFS analysis of a memory image (isolated subprocess)."""
        img = self.jail.check(image)
        if action not in ("summary", "processes", "netstat", "findevil", "timeline", "list", "read"):
            return "ERROR: action must be summary|processes|netstat|findevil|timeline|list|read"
        req = {"image": str(img), "action": action, "path": path or "/", "length": length, "max_chars": 60000,
               "forensic_timeout_s": timeout_s}
        if action == "timeline":
            req["outdir"] = str(self._outdir("memprocfs_timeline"))
        argv = [self.mpfs_python, "-m", "compensated_anarchist.tools.memprocfs_runner", json.dumps(req)]
        return await self._run(argv, timeout=timeout_s + 300, cwd=Path(__file__).resolve().parents[2])

    # ---- ALEAPP / iLEAPP (mobile) -----------------------------------------------------------
    async def leapp(self, platform: str, input_path: str, input_type: str = "fs", max_artifacts: int = 60) -> str:
        """Parse an Android (ALEAPP) or iOS (iLEAPP) extraction; returns the artifacts found (TSV exports)."""
        script = {"android": self.aleapp, "ios": self.ileapp}.get(platform)
        if script is None:
            return "ERROR: platform must be android or ios"
        if not script or not Path(script).is_file():
            return f"ERROR: forensics.{'aleapp' if platform == 'android' else 'ileapp'}_path is not configured"
        if input_type not in ("fs", "tar", "zip", "gz", "itunes", "file"):
            return "ERROR: input_type must be fs|tar|zip|gz|itunes|file"
        src = self.jail.check(input_path)
        out = self._outdir(f"{platform}_leapp")
        log = await self._run([self.leapp_python, script, "-t", input_type, "-i", str(src), "-o", str(out)],
                              timeout=6 * 3600, cwd=Path(script).parent)
        tsvs = sorted(out.rglob("*.tsv"))
        arts = []
        for t in tsvs[:max_artifacts]:
            with open(t, encoding="utf-8", errors="replace") as fh:
                lines = fh.readlines()
            arts.append({"artifact": t.stem, "rows": max(len(lines) - 1, 0), "tsv": str(t),
                         "sample": [ln.rstrip("\n")[:300] for ln in lines[1:3]]})
        reports = [str(p) for p in out.rglob("index.html")][:1]
        return json.dumps({"platform": platform, "output_dir": str(out), "html_report": reports,
                           "artifacts": arts, "total_tsv": len(tsvs), "log_tail": log[-1500:]}, indent=1)

    async def exiftool(self, path: str) -> str:
        p = self.jail.check(path)
        return await self._run([self._which("exiftool"), "-a", "-G1", str(p)])

    async def run(self, binary: str, args: list[str], timeout_s: int = 600) -> str:
        if instead := _never_run(binary):
            return (f"ERROR: local_run never runs {binary}: its options can run code or rewrite evidence. "
                    f"Use {instead}.")
        if binary not in self.allowed_run:
            return f"ERROR: '{binary}' not in forensics.allowed_binaries {sorted(self.allowed_run)}"
        exe = shutil.which(binary)
        if not exe:
            return f"ERROR: {binary} not installed"
        real = Path(exe).resolve()
        if instead := _never_run(real.name):  # an allowlisted name that is a link to one of them
            return (f"ERROR: local_run never runs {binary} ({real}): its options can run code or rewrite evidence. "
                    f"Use {instead}.")
        for zone in [*self.jail.roots, self.case.dir.resolve()]:  # evidence (incl. the vault) and case outputs
            if real == zone or zone in real.parents:
                return (f"ERROR: refusing to execute {real}: it is inside {zone}, where files pulled from endpoints "
                        f"and tool outputs live. Only installed tools run.")
        args = [str(a) for a in args]
        self.jail.check_args(args, self.case.artifacts)  # paths count from the working directory, as the tool sees them
        return await self._run([exe, *args], timeout=min(timeout_s, 6 * 3600), cwd=self.case.artifacts)

    def case_evidence(self, include_vault: bool = True, max_entries: int = 500) -> str:
        if not self.case_folder:
            return "ERROR: no case evidence folder configured (harness.forensics_dir)"
        registered = {str(Path(e.get("path", "")).resolve()) for e in self.case.data.get("evidence", [])}
        return casefiles.inventory(self.case_folder, self.vault_dir, registered, include_vault, max_entries)

    # ---- definitions ------------------------------------------------------------
    def tools(self) -> list[Tool]:
        S, I, B = {"type": "string"}, {"type": "integer"}, {"type": "boolean"}
        L = {"type": "array", "items": {"type": "string"}}
        return [
            Tool("local_tools_inventory", "List which local forensic tools are installed and the evidence roots.", schema({}), self.tools_inventory),
            Tool("local_case_evidence", "START HERE for forensics: list every artifact available to this case - the case evidence "
                 "folder where the analyst drops artifacts (forensics/<case-id>/) and files pulled from endpoints into the "
                 "evidence vault - with each item's type detected from its content (disk image, memory image, EVTX, registry "
                 "hive, PCAP, triage package, executable...) and whether it is registered in the chain of custody.",
                 schema({"include_vault": B, "max_entries": I}), self.case_evidence),
            Tool("local_list_dir", "List files in an evidence directory (size, mtime UTC).",
                 schema({"path": S, "pattern": S, "recursive": B, "max_entries": I}, ["path"]), self.list_dir),
            Tool("local_file_info", "File metadata, magic type, MAC times and MD5/SHA1/SHA256.", schema({"path": S}, ["path"]), self.file_info),
            Tool("local_read_file", "Read part of a file as text or hex dump (max 64KB per call). Also used to page spilled tool output.",
                 schema({"path": S, "offset": I, "length": I, "mode": {"type": "string", "enum": ["text", "hex"]}}, ["path"]), self.read_file),
            Tool("local_strings", "Extract strings with offsets; optional regex grep.",
                 schema({"path": S, "min_len": I, "encoding": {"type": "string", "enum": ["ascii", "utf16le", "utf16be"]},
                         "grep": S, "max_lines": I}, ["path"]), self.strings),
            Tool("local_yara_scan", "Scan a file or directory with YARA rules (file or directory of .yar).",
                 schema({"target": S, "rules": S, "recursive": B}, ["target"]), self.yara_scan),
            Tool("local_volatility", "Run a Volatility 3 plugin against a memory image (e.g. windows.pslist, windows.netscan, windows.malfind, linux.bash). "
                 "plugin_args are the plugin's long options (--pid=4, --dump); dumped files go to the run's folder in the case "
                 "artifacts. Paths on this machine in the arguments must be in the evidence roots or the case folder.",
                 schema({"image": S, "plugin": S, "plugin_args": L}, ["image", "plugin"]), self.volatility),
            Tool("local_pcap_stats", "Protocol hierarchy, IP conversations and endpoints for a PCAP (tshark).", schema({"pcap": S}, ["pcap"]), self.pcap_stats),
            Tool("local_tshark", "Query a PCAP with a Wireshark display filter, optionally extracting fields.",
                 schema({"pcap": S, "display_filter": S, "fields": L, "max_packets": I}, ["pcap"]), self.tshark),
            Tool("local_zeek", "Process a PCAP with Zeek into JSON logs in the case artifacts dir.", schema({"pcap": S}, ["pcap"]), self.zeek),
            Tool("local_evtx_hunt", "Run Sigma-based hunting over Windows EVTX (hayabusa or chainsaw).",
                 schema({"evtx_path": S, "min_level": {"type": "string", "enum": ["informational", "low", "medium", "high", "critical"]}}, ["evtx_path"]), self.evtx_hunt),
            Tool("local_plaso_timeline", "Build a super-timeline with plaso (log2timeline + psort). Slow on large images. "
                 "date_filter: a psort filter expression, e.g. date > '2026-01-01 00:00:00' AND date < '2026-01-08 00:00:00'.",
                 schema({"source": S, "date_filter": S}, ["source"]), self.plaso_timeline),
            Tool("local_capa", "capa: identify capabilities in a PE/.NET/ELF/shellcode sample, mapped to ATT&CK and MBC.",
                 schema({"path": S, "file_format": {"type": "string", "enum": ["auto", "pe", "dotnet", "elf", "sc32", "sc64"]}}, ["path"]), self.capa),
            Tool("local_floss", "FLOSS: extract obfuscated strings (decoded, stack, tight) from a PE sample; optional regex grep.",
                 schema({"path": S, "min_length": I, "grep": S, "include_static": B, "max_per_type": I}, ["path"]), self.floss),
            Tool("local_ez_tool", "Run an Eric Zimmerman parser to CSV: MFTECmd ($MFT/$J/$LogFile), PECmd (Prefetch), LECmd (LNK), "
                 "JLECmd (Jump Lists), AmcacheParser, AppCompatCacheParser (ShimCache, SYSTEM hive), RECmd (registry via batch file), "
                 "SBECmd (ShellBags, dir of hives), SrumECmd (SRUDB.dat), EvtxECmd (EVTX), RBCmd (Recycle Bin), WxTCmd, SQLECmd, bstrings. "
                 "It runs in its output folder in the case artifacts; paths in extra_args and batch_file must be in the evidence roots "
                 "or the case folder (batch_file may also be in forensics.ez_tools_dir).",
                 schema({"tool": {"type": "string", "enum": sorted(self.EZ_TOOLS)}, "input_path": S, "extra_args": L,
                         "batch_file": S, "head_rows": I}, ["tool", "input_path"]), self.ez_tool),
            Tool("local_sigma_convert", "Convert Sigma rule(s) (YAML text, file or directory) to a SIEM query. Valid target -> pipelines: "
                 "splunk/splunk_spl2 -> splunk_windows | splunk_cim | sysmon; lucene/eql (Elastic, Security Onion) -> ecs_windows | "
                 "ecs_zeek_beats | sysmon; esql -> sysmon | windows-audit | windows-logsources; kusto (Sentinel/Defender) -> "
                 "microsoft_xdr | sentinel_asim | azure_monitor. Run local_sigma_check first.",
                 schema({"rule": S, "target": S, "pipelines": L, "output_format": S}, ["rule", "target"]), self.sigma_convert),
            Tool("local_sigma_check", "Validate Sigma rule(s) (YAML text, file or directory).", schema({"rule": S}, ["rule"]), self.sigma_check),
            Tool("local_memprocfs", "MemProcFS on a memory image: summary | processes (tree) | netstat | findevil (forensic-mode malware "
                 "indicators) | timeline (forensic CSVs to artifacts) | list/read a VFS path (e.g. /name/<proc>/...).",
                 schema({"image": S, "action": {"type": "string", "enum": ["summary", "processes", "netstat", "findevil", "timeline", "list", "read"]},
                         "path": S, "length": I, "timeout_s": I}, ["image"]), self.memprocfs),
            Tool("local_leapp", "Parse a mobile extraction: platform android (ALEAPP) or ios (iLEAPP); input_type fs|tar|zip|gz|itunes|file.",
                 schema({"platform": {"type": "string", "enum": ["android", "ios"]}, "input_path": S,
                         "input_type": {"type": "string", "enum": ["fs", "tar", "zip", "gz", "itunes", "file"]}, "max_artifacts": I},
                        ["platform", "input_path"]), self.leapp),
            Tool("local_exiftool", "Extract document/media metadata with exiftool.", schema({"path": S}, ["path"]), self.exiftool),
            Tool("local_run", "Run an allowlisted forensic binary (e.g. Sleuth Kit fls/icat/mmls, bulk_extractor) with argv list; no shell. "
                 "Working dir = case artifacts. Every path (absolute, relative, or after =) must be in the evidence roots or the "
                 "case folder, and new outputs go in the case artifacts folder; give each path as its own argument. Not for "
                 "exiftool: use local_exiftool.",
                 schema({"binary": S, "args": L, "timeout_s": I}, ["binary", "args"]), self.run),
        ]


def _kill_group(proc: Any) -> None:
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError, OSError):
        try:
            proc.kill()
        except ProcessLookupError:
            pass
