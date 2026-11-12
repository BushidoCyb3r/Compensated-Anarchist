"""Vulnerability assessment tools (vuln_*), for the vuln_assessor expert.

Every vuln_* call needs an analyst's approval: the tools are on the ROE's built-in HUMAN_GATED floor, and the
vuln_assessor runs under the gate-everything floor besides. On top of that approval, vuln_run checks each command
itself before it runs:

  - the program must be on the allowlist (assessment tools, no exploitation or password attacks) and installed;
  - the ROE must define an authorized scope (scope.allowed_targets): no scope, no scanning;
  - every host in the arguments (IPs, CIDRs, hostnames, URLs, host:port) must be listed in `targets`, and every
    target must sit inside the scope (hostnames: every address they resolve to);
  - target ranges with - or *, and "read targets from a file" options, are refused: scope is checked on what
    is written in the command;
  - options matching the program's deny patterns (exploit / brute-force / DoS script categories, uploads,
    HTTP methods that change data, ...) are refused;
  - absolute paths may only point into the case's vuln_assessment folder, or into read-only data folders for
    inputs such as wordlists;
  - argv only, never a shell; a minimal environment (no API keys); a timeout; the full output is kept in
    <case>/vuln_assessment/raw/ next to the command that produced it.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import re
import shutil
import signal
import socket
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from ..roe import _matches_target
from .registry import Tool, schema
from .. import xmlsafe

# Assessment programs: discovery, service/version and TLS checks, web and vulnerability scanners, enumeration,
# exploit-database lookups and local audits. Nothing here exploits, cracks passwords or floods.
DEFAULT_TOOLS = [
    "nmap", "nuclei", "nikto", "whatweb", "httpx", "sslscan", "testssl.sh", "testssl", "sslyze",
    "enum4linux-ng", "enum4linux", "nbtscan", "smbmap", "snmpwalk", "ldapsearch", "showmount", "rpcinfo",
    "ike-scan", "dnsrecon", "dig", "host", "whois", "curl", "gobuster", "ffuf", "feroxbuster", "dirb",
    "wpscan", "searchsploit", "trivy", "grype", "lynis", "ping", "traceroute", "arp-scan",
]
# Refused options, matched against the whole argument string. "*" applies to every program.
DEFAULT_DENY: dict[str, list[str]] = {
    "*": [r"(^|\s)--?(exec|execute|shell|upload|delete)(\s|=|$)"],
    "nmap": [r"--script[= ]\S*(exploit|brute|dos|intrusive|malware|fuzzer|flood|slowloris)",
             r"--script-args[= ]\S*unsafe", r"(^|\s)-iR(\s|$)", r"(^|\s)-iL(\s|$)", r"(^|\s)--resume(\s|$)"],
    "nuclei": [r"(^|\s)-(tags|itags|include-tags|t|templates|tc|template-condition)[= ]\S*(dos|fuzz|intrusive|brute)",
               r"(^|\s)-(l|list|resume|code|headless)(\s|=|$)"],
    "httpx": [r"(^|\s)-(l|list)(\s|=|$)"],
    "whatweb": [r"(^|\s)(-i|--input-file)(\s|=|$)"],
    "sslscan": [r"--targets[= ]"],
    "testssl.sh": [r"--file[= ]"], "testssl": [r"--file[= ]"],
    "sslyze": [r"--targets_in[= ]"],
    "curl": [r"(^|\s)(-X|--request)[= ]?(PUT|POST|DELETE|PATCH)\b",
             r"(^|\s)(-T|--upload-file|-d|--data\S*|-F|--form\S*|--json)(\s|=|$)"],
    "ffuf": [r"(^|\s)(-d|-X|-request)(\s|=|$)"],
    "wpscan": [r"(^|\s)(-P|--passwords|-U|--usernames)(\s|=|$)"],
    "smbmap": [r"(^|\s)(-x|-X|--upload|--download|--delete|--mode)(\s|=|$)"],
    "ldapsearch": [r"(^|\s)-w(\s|$)", r"(^|\s)-y(\s|$)"],  # no passwords on the command line
    "nikto": [r"(^|\s)-(evasion|mutate)(\s|=|$)"],
}
READ_DIRS = ["/usr/share", "/opt", "/var/lib/nuclei", "/root/nuclei-templates"]
FILE_EXT = {"xml", "txt", "json", "jsonl", "yaml", "yml", "csv", "html", "htm", "nmap", "gnmap", "lst", "conf", "cfg",
            "nse", "md", "log", "out", "php", "asp", "aspx", "jsp", "js", "sh", "py", "pem", "crt", "key", "db"}
_URL = re.compile(r"[a-z][a-z0-9+.-]*://(\[[^\]]+\]|[^/:?#\s]+)", re.I)
_HOSTNAME = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}\.?$", re.I)
_RANGE = re.compile(r"^\d{1,3}(-\d{1,3})?(\.(\d{1,3}(-\d{1,3})?|\*)){3}$")  # 10.0.0.1-50, 10.0.*.1 (not port ranges)
_OUTPUT_FLAG = re.compile(r"^-(o[A-Za-z]?|-?out\S*|-?output\S*|-?log\S*|-?json\S*|-?xml\S*|-?report\S*|-?export\S*)$")
MAX_TIMEOUT_S = 3600


def _ip(v: str):
    try:
        return ipaddress.ip_address(v.strip("[]"))
    except ValueError:
        return None


def _net(v: str):
    try:
        return ipaddress.ip_network(v, strict=False) if "/" in v else None
    except ValueError:
        return None


def hosts_in_args(args: list[str]) -> tuple[list[str], list[str]]:
    """(hosts named in the arguments, problems). Hosts: IPs, CIDRs, hostnames, URL hosts, host:port hosts."""
    hosts, problems = [], []
    for tok in args:
        for url_host in _URL.findall(tok):
            hosts.append(url_host.strip("[]").lower())
        rest = _URL.sub(" ", tok)
        for piece in re.split(r"[=,\s]", rest):
            piece = piece.strip().strip("'\"")
            if not piece or piece.startswith("-") and not piece[1:2].isdigit():
                continue
            if _RANGE.match(piece) and not _ip(piece) and not _net(piece):
                problems.append(f"'{piece}': write targets as single addresses or CIDRs, not ranges or wildcards")
                continue
            host = piece
            m = re.match(r"^(\[[0-9a-f:]+\]|[^:]+):\d{1,5}$", piece, re.I)  # host:port
            if m:
                host = m.group(1).strip("[]")
            if _ip(host) or _net(host):
                hosts.append(host.lower())
            elif ("/" not in host and _HOSTNAME.match(host) and host.rsplit(".", 1)[-1].lower() not in FILE_EXT
                  and not Path(host).exists()):
                hosts.append(host.lower().rstrip("."))
    return list(dict.fromkeys(hosts)), problems


class VulnTools:
    def __init__(self, cfg: dict[str, Any], folder: Path, scope: Callable[[], tuple[list[str], list[str]]],
                 on_saved: Callable[[Path, str], None] | None = None, resolve: Callable[[str], list[str]] | None = None):
        cfg = cfg or {}
        self.folder = Path(folder)
        self.raw = self.folder / "raw"
        self.allow = list(dict.fromkeys([*(cfg.get("tools") or DEFAULT_TOOLS), *(cfg.get("extra_tools") or [])]))
        self.deny = {k: list(v) for k, v in DEFAULT_DENY.items()}
        for k, pats in (cfg.get("deny_args") or {}).items():
            self.deny.setdefault(str(k), []).extend(str(p) for p in pats)
        self.read_dirs = [Path(p) for p in (cfg.get("read_dirs") or READ_DIRS)]
        self.timeout_s = int(cfg.get("timeout_s", 900))
        self.max_timeout_s = min(int(cfg.get("max_timeout_s", MAX_TIMEOUT_S)), 4 * MAX_TIMEOUT_S)
        self.scope = scope
        self.on_saved = on_saved
        self.resolve = resolve or _resolve

    # ---- checks -----------------------------------------------------------------------------------------
    def installed(self) -> dict[str, str]:
        return {t: p for t in self.allow if (p := shutil.which(t))}

    def check(self, tool: str, args: list[str], targets: list[str]) -> list[str]:
        """Everything wrong with this command (empty = it may run once the analyst approves it)."""
        problems: list[str] = []
        if tool not in self.allow:
            return [f"'{tool}' is not on the vulnerability assessment allowlist ({', '.join(self.allow)})"]
        if not shutil.which(tool):
            return [f"'{tool}' is not installed on this machine (vuln_environment lists what is)"]
        if any(not isinstance(a, str) for a in args) or any("\x00" in a for a in args):
            return ["arguments must be strings"]
        allowed, _protected = self.scope()
        if not allowed:
            return ["no authorized scope: the ROE file's scope.allowed_targets is empty. The analyst must define the "
                    "authorized ranges before anything is scanned"]
        line = " ".join(args)
        for pat in [*self.deny.get("*", []), *self.deny.get(tool, [])]:
            if re.search(pat, line, re.I):
                problems.append(f"refused option for {tool} (matches deny pattern {pat!r})")
        tgt = [str(t).strip().lower().rstrip(".") for t in targets if str(t).strip()]
        for t in tgt:
            if "://" in t or _RANGE.match(t) and not _ip(t) and not _net(t):
                problems.append(f"target '{t}': give a host, an IP or a CIDR (no URLs, ranges or wildcards)")
                continue
            names = [t] if (_ip(t) or _net(t)) else (self.resolve(t) or [])
            if not names:
                problems.append(f"target '{t}' does not resolve, so its scope cannot be checked")
            elif not (_matches_target(t, allowed) or all(_matches_target(n, allowed) for n in names)):
                problems.append(f"target '{t}' ({', '.join(names)}) is outside the authorized scope {allowed}")
        named, issues = hosts_in_args(args)
        problems += issues
        for h in named:
            if not _covered(h, tgt):
                problems.append(f"'{h}' appears in the arguments but not in targets: list every host the command touches")
        for i, a in enumerate(args):
            if not (a.startswith(("/", "~")) or ".." in Path(a).parts):
                continue
            p = Path(os.path.expanduser(a)).resolve()
            inside = p == self.folder.resolve() or self.folder.resolve() in p.parents
            readable = any(d == p or d in p.parents for d in self.read_dirs)
            writing = i > 0 and bool(_OUTPUT_FLAG.match(args[i - 1]))
            if not inside and (not readable or writing):
                problems.append(f"path '{a}': only the case's vuln_assessment folder"
                                + ("" if writing else f" or read-only data folders ({', '.join(map(str, self.read_dirs))})")
                                + " may be used")
        return problems

    # ---- tools ------------------------------------------------------------------------------------------
    def environment(self) -> str:
        osr = {}
        try:
            for line in Path("/etc/os-release").read_text().splitlines():
                k, _, v = line.partition("=")
                osr[k] = v.strip('"')
        except OSError:
            pass
        have = self.installed()
        allowed, protected = self.scope()
        lines = [f"Host: {socket.gethostname()}  OS: {osr.get('PRETTY_NAME', os.uname().sysname)}"
                 + ("  (Kali Linux)" if osr.get("ID") == "kali" else ""),
                 f"Running as: {'root' if hasattr(os, 'geteuid') and os.geteuid() == 0 else 'an unprivileged user'}"
                 + ("" if hasattr(os, "geteuid") and os.geteuid() == 0 else
                    " (nmap SYN/OS scans, arp-scan and raw-socket probes need root; use -sT and -sV)"),
                 f"Authorized scope (ROE allowed_targets): {allowed or 'NONE - scanning is refused until the analyst sets it'}",
                 f"Protected assets (extra care; tell the analyst before touching): {protected or 'none'}",
                 f"Output folder: {self.folder}  (raw command output in raw/)",
                 f"Installed assessment tools ({len(have)} of {len(self.allow)} allowed):"]
        lines += [f"  {t:15s} {p}" for t, p in have.items()]
        missing = [t for t in self.allow if t not in have]
        if missing:
            lines.append(f"Not installed: {', '.join(missing)}")
        return "\n".join(lines)

    async def run(self, tool: str, args: list[str], targets: list[str] | None = None, timeout_s: int | None = None) -> str:
        args = [str(a) for a in args or []]
        problems = self.check(tool, args, list(targets or []))
        if problems:
            return "REFUSED, nothing was run:\n- " + "\n- ".join(problems)
        self.raw.mkdir(parents=True, exist_ok=True)
        os.chmod(self.folder, 0o750)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        out_file = self.raw / f"{stamp}_{re.sub(r'[^A-Za-z0-9._-]', '_', tool)}.txt"
        timeout = max(1, min(int(timeout_s or self.timeout_s), self.max_timeout_s))
        env = {k: v for k, v in os.environ.items() if k in ("PATH", "HOME", "LANG", "LC_ALL", "USER", "LOGNAME", "TMPDIR")}
        env["TERM"] = "dumb"
        argv = [shutil.which(tool) or tool, *args]
        started = datetime.now(timezone.utc)
        proc = await asyncio.create_subprocess_exec(*argv, cwd=str(self.raw), env=env, stdin=asyncio.subprocess.DEVNULL,
                                                    stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
                                                    start_new_session=True)
        status = ""
        try:
            data, _ = await asyncio.wait_for(proc.communicate(), timeout)
        except asyncio.TimeoutError:
            _kill(proc)
            data, _ = await proc.communicate()
            status = f"TIMED OUT after {timeout}s (partial output below)"
        except asyncio.CancelledError:  # the analyst pressed Stop: take the scan down with the task
            _kill(proc)
            raise
        text = data.decode("utf-8", errors="replace")
        ended = datetime.now(timezone.utc)
        head = (f"$ {tool} {' '.join(_quote(a) for a in args)}\n"
                f"# targets: {', '.join(targets or []) or '(none)'}\n"
                f"# started {started.isoformat()[:19]}Z, ended {ended.isoformat()[:19]}Z, "
                f"exit {proc.returncode}{', ' + status if status else ''}\n"
                f"# full output: {out_file}\n")
        out_file.write_text(head + "\n" + text, encoding="utf-8")
        os.chmod(out_file, 0o640)
        return head + "\n" + (text or "(no output)")

    def parse(self, file: str) -> str:
        p = self._inside(file)
        data = p.read_text(encoding="utf-8", errors="replace")
        if "<nmaprun" in data[:4000]:
            return _nmap_summary(data)
        if data.lstrip().startswith("{") and '"template-id"' in data[:20000]:
            return _nuclei_summary(data)
        return f"{p.name}: not nmap XML or nuclei JSONL; first 6000 characters:\n{data[:6000]}"

    def save_report(self, name: str, content: str) -> str:
        slug = re.sub(r"[^A-Za-z0-9._-]+", "_", re.sub(r"\.md$", "", Path(name).name, flags=re.I)).strip("_")[:80] or "report"
        slug = re.sub(r"^vuln_report_", "", slug)
        self.folder.mkdir(parents=True, exist_ok=True)
        path = self.folder / f"vuln_report_{slug}.md"
        if path.exists():
            older = self.folder / "older"
            older.mkdir(exist_ok=True)
            stamp = datetime.fromtimestamp(path.stat().st_mtime, timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            os.replace(path, older / f"{path.stem}.{stamp}.md")
        path.write_text(content, encoding="utf-8")
        if self.on_saved:
            self.on_saved(path, "vuln_report")
        return f"saved {path}"

    def _inside(self, file: str) -> Path:
        p = Path(file)
        p = (p if p.is_absolute() else self.raw / p).resolve()
        root = self.folder.resolve()
        if root not in p.parents or not p.is_file():
            raise ValueError(f"{file}: not a file in {self.folder}")
        return p

    def tools(self) -> list[Tool]:
        S, L = {"type": "string"}, {"type": "array", "items": {"type": "string"}}
        return [
            Tool("vuln_environment", "What this machine can do for a vulnerability assessment: OS (Kali or not), "
                 "privileges, the ROE's authorized scope and protected assets, and which allowlisted assessment tools are "
                 "installed. Call it first.", schema({}), self.environment),
            Tool("vuln_run", "Run ONE allowlisted assessment program (nmap, nuclei, nikto, sslscan, testssl.sh, "
                 "enum4linux-ng, whatweb, gobuster, searchsploit, ...) with an argument list - no shell, so no pipes, "
                 "redirects or quoting. List in `targets` every host, IP or CIDR the command touches; each must be in "
                 "the authorized scope. Write outputs (e.g. nmap -oX scan.xml) as plain file names: they land in the "
                 "case's vuln_assessment/raw folder, where vuln_parse reads them. No exploitation, password attacks or "
                 "DoS options. Each call is approved by the analyst before it runs.",
                 schema({"tool": S, "args": L, "targets": L,
                         "timeout_s": {"type": "integer", "description": f"default {self.timeout_s}, max {self.max_timeout_s}"}},
                        ["tool", "args", "targets"]), self.run),
            Tool("vuln_parse", "Summarize a scan output file from the vuln_assessment folder: nmap XML -> hosts, open "
                 "ports, services, versions, CPEs and script findings; nuclei JSONL -> findings by severity. File name "
                 "relative to raw/, or a full path inside the folder.", schema({"file": S}, ["file"]), self.parse),
            Tool("vuln_report_save", "Save the vulnerability assessment report (markdown) to the case's vuln_assessment "
                 "folder as vuln_report_<name>.md; earlier versions are kept. The analyst can open it from the dashboard.",
                 schema({"name": S, "content": S}, ["name", "content"]), self.save_report),
        ]


# ---- helpers -------------------------------------------------------------------------------------------
def _covered(host: str, targets: list[str]) -> bool:
    """Is a host named in the arguments listed in targets (itself, or inside a listed CIDR)?"""
    if host in targets:
        return True
    ip, sub = _ip(host), _net(host)
    for t in targets:
        n = _net(t)
        if n is None:
            continue
        if ip is not None and ip.version == n.version and ip in n:
            return True
        if sub is not None and sub.version == n.version and sub.subnet_of(n):
            return True
    return False


def _resolve(host: str) -> list[str]:
    try:
        return sorted({ai[4][0] for ai in socket.getaddrinfo(host, None)})
    except (socket.gaierror, UnicodeError, OSError):
        return []


def _kill(proc) -> None:
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError, OSError):
        pass


def _quote(a: str) -> str:
    return a if re.fullmatch(r"[\w@%+=:,./-]+", a) else "'" + a.replace("'", "'\\''") + "'"


def _nmap_summary(xml: str) -> str:
    root = xmlsafe.fromstring(xml)
    rows = [f"nmap {root.get('version', '')}: {root.get('args', '')}"]
    for h in root.iter("host"):
        st = h.find("status")
        if st is not None and st.get("state") != "up":
            continue
        addr = ", ".join(a.get("addr", "") for a in h.findall("address") if a.get("addrtype") in ("ipv4", "ipv6"))
        names = ", ".join(n.get("name", "") for n in h.iter("hostname"))
        osm = h.find("os/osmatch")
        rows.append(f"\nHOST {addr}{f' ({names})' if names else ''}"
                    + (f"  OS: {osm.get('name')} ({osm.get('accuracy')}%)" if osm is not None else ""))
        for p in h.iter("port"):
            state = p.find("state")
            if state is None or state.get("state") not in ("open", "open|filtered"):
                continue
            sv = p.find("service")
            svc = ""
            if sv is not None:
                svc = " ".join(x for x in (sv.get("name"), sv.get("product"), sv.get("version"), sv.get("extrainfo")) if x)
                cpes = [c.text for c in sv.findall("cpe") if c.text]
                if cpes:
                    svc += f"  [{', '.join(cpes)}]"
            rows.append(f"  {p.get('portid')}/{p.get('protocol')} {state.get('state')}  {svc}")
            for sc in p.findall("script"):
                out = " ".join((sc.get("output") or "").split())
                rows.append(f"    script {sc.get('id')}: {out[:600]}")
        for sc in h.findall("hostscript/script"):
            rows.append(f"  hostscript {sc.get('id')}: {' '.join((sc.get('output') or '').split())[:600]}")
    return "\n".join(rows)


def _nuclei_summary(jsonl: str) -> str:
    order = ["critical", "high", "medium", "low", "info", "unknown"]
    found = []
    for line in jsonl.splitlines():
        try:
            r = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = r.get("info") or {}
        cls = info.get("classification") or {}
        found.append((str(info.get("severity", "unknown")).lower(), r.get("template-id", ""), info.get("name", ""),
                      r.get("matched-at") or r.get("host", ""), ", ".join(cls.get("cve-id") or []),
                      cls.get("cvss-score", "")))
    found.sort(key=lambda f: order.index(f[0]) if f[0] in order else 9)
    rows = [f"nuclei: {len(found)} findings"]
    rows += [f"  [{sev}] {tid}: {name} at {at}" + (f"  {cve}" if cve else "") + (f" CVSS {cv}" if cv else "")
             for sev, tid, name, at, cve, cv in found]
    return "\n".join(rows)
