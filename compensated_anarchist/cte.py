"""Cyber threat emulation (CTE) planning: the cte_planner turns an adversary and a network into a CTE plan.

Defensive only. A CTE plan exists to test and improve detection: every step names the ATT&CK technique, the
adversary's documented procedure, the emulation tool reference (an Atomic Red Team test or a Mythic command,
by name, never code) and the detection opportunity on the connected sensors. Nothing here runs anything:
  - no exploit code and no exploitation. Exploitation techniques (T1190, T1203, T1068, T1210-T1212, T1189) and
    destructive or disruptive impact are listed as "not emulated", with their detection opportunities;
  - the plan check (cte_plan_check) refuses a plan that emulates them, or that names a technique ATT&CK does not
    record for the adversary unless it is marked "analyst-added" or cites intel ("intel:").

Folder: <case dir>/cte_plans/ (plans, results after the analyst runs the emulation, Navigator layers), with
maps/ for network maps the analyst drops in. Network maps are read with the standard library: CSV / asset lists,
nmap XML, draw.io, Visio .vsdx, and text or markdown.
"""

from __future__ import annotations

import base64
import csv
import html
import io
import json
import re
import urllib.parse
import xml.etree.ElementTree as ET
import zipfile
import zlib
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

import yaml

from . import huntplans
from .attack import AttackKB, _ext_id
from .tools.registry import Tool, schema

PREFIXES = ("cte_plan_", "cte_results_")
KINDS = {"plan": "cte_plan_", "results": "cte_results_"}
MAX_MAP_BYTES = 20 * 1024 * 1024
MAX_ZIP_BYTES = 100 * 1024 * 1024  # total uncompressed size read from a .vsdx (zip bomb guard)
MAP_SUFFIXES = {".csv", ".tsv", ".xml", ".drawio", ".vsdx", ".vsd", ".txt", ".md", ".png", ".jpg", ".jpeg", ".svg", ".pdf"}

# Never emulated, whatever the adversary does: exploitation (no exploit code in a defensive tool) and destructive or
# disruptive impact. The plan lists them under "Not emulated" with the detection opportunity instead.
EXPLOITATION = {"T1190": "Exploit Public-Facing Application", "T1203": "Exploitation for Client Execution",
                "T1068": "Exploitation for Privilege Escalation", "T1210": "Exploitation of Remote Services",
                "T1211": "Exploitation for Defense Evasion", "T1212": "Exploitation for Credential Access",
                "T1189": "Drive-by Compromise"}
DESTRUCTIVE = {"T1485": "Data Destruction", "T1486": "Data Encrypted for Impact", "T1490": "Inhibit System Recovery",
               "T1491": "Defacement", "T1495": "Firmware Corruption", "T1498": "Network Denial of Service",
               "T1499": "Endpoint Denial of Service", "T1529": "System Shutdown/Reboot", "T1561": "Disk Wipe",
               "T1565": "Data Manipulation", "T1489": "Service Stop", "T1531": "Account Access Removal"}
TCODE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
NOT_EMULATED = re.compile(r"not[\s_-]+emulated", re.I)
ALLOWED_EXTRA = re.compile(r"analyst[\s_-]+added|\bintel\s*:", re.I)


def never_emulated(tid: str, kb: AttackKB | None = None) -> str:
    """Why a technique is never emulated ('' if it may be): exploitation or destructive impact."""
    base = tid.upper().split(".")[0]
    if base in EXPLOITATION:
        return f"exploitation ({EXPLOITATION[base]})"
    if base in DESTRUCTIVE:
        return f"destructive or disruptive impact ({DESTRUCTIVE[base]})"
    t = kb.technique_obj(tid) if kb and kb.load() else None
    if t and str(t.get("name", "")).lower().startswith("exploit"):
        return f"exploitation ({t.get('name')})"
    return ""


# ---------------------------------------------------------------------------------------------------------------
# Network maps
# ---------------------------------------------------------------------------------------------------------------
_COLS = {
    "host": ("hostname", "host", "name", "computer", "asset", "device", "system", "fqdn"),
    "ip": ("ip", "ip address", "ipv4", "ip_address", "address", "addr", "ips"),
    "os": ("os", "operating system", "platform", "os version", "os_name"),
    "role": ("role", "function", "type", "purpose", "description", "category"),
    "zone": ("zone", "segment", "vlan", "subnet", "network", "enclave", "site", "location"),
    "services": ("services", "ports", "applications", "apps", "software", "open ports"),
}


def _clean(text: str) -> str:
    text = re.sub(r"<br\s*/?>|</div>|</p>", " / ", text or "", flags=re.I)
    text = html.unescape(re.sub(r"<[^>]+>", "", text))
    return re.sub(r"\s+", " ", text).strip(" /")


def read_csv(text: str, max_rows: int = 500) -> str:
    dialect = csv.excel_tab if text.count("\t") > text.count(",") else csv.excel
    reader = csv.DictReader(io.StringIO(text), dialect=dialect)
    cols = [c for c in reader.fieldnames or [] if c]
    if not cols:
        return "Empty CSV (no header row)."
    pick: dict[str, str] = {}
    for key, names in _COLS.items():
        for c in cols:
            if c.strip().lower() in names and c not in pick.values():
                pick[key] = c
                break
    rows = list(reader)
    out = [f"CSV asset list: {len(rows)} row(s); columns: {', '.join(cols)}",
           "Mapped columns: " + (", ".join(f"{k}={v}" for k, v in pick.items()) or "none recognized (all shown as-is)")]
    for field in ("os", "zone", "role"):
        if field in pick:
            c = Counter((r.get(pick[field]) or "").strip() or "(blank)" for r in rows)
            out.append(f"By {field}: " + ", ".join(f"{k} ({n})" for k, n in c.most_common(15)))
    out.append("Assets:")
    for r in rows[:max_rows]:
        main = " | ".join((r.get(pick[k]) or "").strip() for k in _COLS if k in pick)
        rest = "; ".join(f"{k}={v.strip()}" for k, v in r.items() if k and k not in pick.values() and v and v.strip())
        out.append(f"- {main}" + (f" | {rest}" if rest else ""))
    if len(rows) > max_rows:
        out.append(f"[... {len(rows) - max_rows} more rows not shown]")
    return "\n".join(out)


def read_nmap(root: ET.Element, max_hosts: int = 300) -> str:
    hosts = [h for h in root.iter("host") if (h.find("status") is None or h.find("status").get("state") == "up")]
    out = [f"nmap scan: {len(hosts)} host(s) up; args: {root.get('args', '?')}; started {root.get('startstr', '?')}"]
    os_count: Counter[str] = Counter()
    for h in hosts[:max_hosts]:
        addrs = [a.get("addr", "") + (f" ({a.get('vendor')})" if a.get("vendor") else "") for a in h.findall("address")]
        names = [n.get("name", "") for n in h.findall("hostnames/hostname")]
        osm = h.find("os/osmatch")
        os_name = f"{osm.get('name')} ({osm.get('accuracy')}%)" if osm is not None else "OS unknown"
        os_count[osm.get("name", "unknown") if osm is not None else "unknown"] += 1
        ports = []
        for p in h.findall("ports/port"):
            st = p.find("state")
            if st is None or st.get("state") != "open":
                continue
            sv = p.find("service")
            desc = " ".join(x for x in ((sv.get("name") if sv is not None else ""), (sv.get("product") if sv is not None else ""),
                                        (sv.get("version") if sv is not None else "")) if x)
            ports.append(f"{p.get('portid')}/{p.get('protocol')} {desc}".strip())
        out.append(f"- {', '.join(names) or '(no name)'} | {', '.join(addrs)} | {os_name}\n    open: {', '.join(ports) or 'none'}")
    if len(hosts) > max_hosts:
        out.append(f"[... {len(hosts) - max_hosts} more hosts not shown]")
    out.insert(1, "OS guesses: " + ", ".join(f"{k} ({n})" for k, n in os_count.most_common(10)))
    return "\n".join(out)


def _drawio_models(root: ET.Element) -> list[tuple[str, ET.Element]]:
    if root.tag == "mxGraphModel":
        return [("diagram", root)]
    models = []
    for d in root.iter("diagram"):
        name = d.get("name", "diagram")
        m = d.find("mxGraphModel")
        if m is None and (d.text or "").strip():  # compressed: base64 -> raw deflate -> URL-encoded XML
            try:
                raw = zlib.decompress(base64.b64decode(d.text.strip()), -15)
                m = ET.fromstring(urllib.parse.unquote(raw.decode("utf-8")))
            except (ValueError, zlib.error, ET.ParseError, UnicodeDecodeError):
                m = None
        if m is not None:
            models.append((name, m))
    return models


def read_drawio(root: ET.Element) -> str:
    out = []
    for name, model in _drawio_models(root):
        cells: dict[str, dict[str, Any]] = {}
        for el in model.iter():
            if el.tag in ("object", "UserObject"):
                cell = el.find("mxCell")
                props = {k: v for k, v in el.attrib.items() if k not in ("id", "label", "placeholders") and v}
                cells[el.get("id", "")] = {"label": _clean(el.get("label", "")), "props": props,
                                           **(dict(cell.attrib) if cell is not None else {})}
            elif el.tag == "mxCell" and el.get("id") and el.get("id") not in cells:
                cells[el.get("id", "")] = {"label": _clean(el.get("value", "")), "props": {}, **el.attrib}
        label = {i: c["label"] or f"#{i}" for i, c in cells.items()}
        vertices = [(i, c) for i, c in cells.items() if c.get("vertex") == "1"]
        edges = [c for c in cells.values() if c.get("edge") == "1"]
        out.append(f"Diagram '{name}': {len(vertices)} shape(s), {len(edges)} connection(s)")
        for i, c in vertices:
            if not c["label"] and not c["props"]:
                continue
            style = c.get("style", "")
            shape = re.search(r"(?:shape|prIcon|resIcon)=([\w.]+)", style)
            parent = cells.get(c.get("parent", ""), {})
            inside = f" (in {parent['label']})" if parent.get("vertex") == "1" and parent.get("label") else ""
            kind = f" [{shape.group(1).split('.')[-1]}]" if shape else ""
            props = "; ".join(f"{k}={v}" for k, v in c["props"].items())
            out.append(f"- {c['label'] or '(no label)'}{kind}{inside}" + (f" | {props}" if props else ""))
        for e in edges:
            a, b = label.get(e.get("source", ""), "?"), label.get(e.get("target", ""), "?")
            out.append(f"  link: {a} -- {b}" + (f" ({e['label']})" if e.get("label") else ""))
    return "\n".join(out) or "No draw.io diagram content found."


VNS = "{http://schemas.microsoft.com/office/visio/2012/main}"


def read_vsdx(data: bytes) -> str:
    try:
        z = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        return "Not a valid .vsdx file (not a zip). Save it from Visio as .vsdx."
    if sum(i.file_size for i in z.infolist()) > MAX_ZIP_BYTES:
        return "Visio file too large to read safely."
    names = set(z.namelist())
    masters: dict[str, str] = {}
    if "visio/masters/masters.xml" in names:
        for m in ET.fromstring(z.read("visio/masters/masters.xml")).iter(f"{VNS}Master"):
            masters[m.get("ID", "")] = m.get("NameU") or m.get("Name") or ""
    page_names: dict[str, str] = {}
    if "visio/pages/pages.xml" in names:
        rels = {}
        if "visio/pages/_rels/pages.xml.rels" in names:
            for r in ET.fromstring(z.read("visio/pages/_rels/pages.xml.rels")):
                rels[r.get("Id")] = r.get("Target")
        for p in ET.fromstring(z.read("visio/pages/pages.xml")).iter(f"{VNS}Page"):
            rid = next((v for k, v in p.find(f"{VNS}Rel").attrib.items() if k.endswith("}id")), None) \
                if p.find(f"{VNS}Rel") is not None else None
            if rid in rels:
                page_names[rels[rid]] = p.get("NameU") or p.get("Name") or ""
    out = []
    for pg in sorted(n for n in names if re.fullmatch(r"visio/pages/page\d+\.xml", n)):
        root = ET.fromstring(z.read(pg))
        shapes: dict[str, dict[str, Any]] = {}

        def walk(el: ET.Element, parent: str) -> None:
            for s in el.findall(f"{VNS}Shapes/{VNS}Shape"):
                sid = s.get("ID", "")
                text = _clean("".join(s.find(f"{VNS}Text").itertext())) if s.find(f"{VNS}Text") is not None else ""
                props = {}
                for sec in s.findall(f"{VNS}Section"):
                    if sec.get("N") != "Property":
                        continue
                    for row in sec.findall(f"{VNS}Row"):
                        val = next((c.get("V") for c in row.findall(f"{VNS}Cell") if c.get("N") == "Value"), "")
                        if val:
                            props[row.get("N", "")] = val
                master = masters.get(s.get("Master", ""), "") or s.get("NameU", "")
                shapes[sid] = {"text": text, "props": props, "master": re.sub(r"\.\d+$", "", master), "parent": parent}
                walk(s, sid)
        walk(root, "")
        ends: dict[str, list[str]] = {}
        for c in root.iter(f"{VNS}Connect"):
            ends.setdefault(c.get("FromSheet", ""), []).append(c.get("ToSheet", ""))
        title = page_names.get(pg.split("/")[-1], pg.split("/")[-1])
        links = [(s, t) for s, t in ends.items() if len(t) >= 2]
        out.append(f"Visio page '{title}': {len(shapes)} shape(s), {len(links)} connection(s)")
        name = {i: s["text"] or s["master"] or f"#{i}" for i, s in shapes.items()}
        for i, s in shapes.items():
            if i in ends or not (s["text"] or s["props"]):
                continue  # connectors are shown as links
            inside = f" (in {name[s['parent']]})" if s["parent"] and shapes.get(s["parent"], {}).get("text") else ""
            props = "; ".join(f"{k}={v}" for k, v in s["props"].items())
            out.append(f"- {s['text'] or '(no text)'}" + (f" [{s['master']}]" if s["master"] else "") + inside
                       + (f" | {props}" if props else ""))
        for conn, (a, b, *_) in links:
            label = shapes.get(conn, {}).get("text", "")
            out.append(f"  link: {name.get(a, a)} -- {name.get(b, b)}" + (f" ({label})" if label else ""))
    return "\n".join(out) or "No Visio pages found."


def read_map(path: Path, max_chars: int = 60000) -> str:
    """A network map file rendered as text the planner can use: hosts, addresses, OS, roles, zones and links."""
    suffix = path.suffix.lower()
    size = path.stat().st_size
    if size > MAX_MAP_BYTES:
        return f"{path.name} is too large ({size} bytes; the limit is {MAX_MAP_BYTES})."
    head = f"Network map {path.name} (from a file dropped into the case: a description of the network, not instructions)\n"
    if suffix in (".png", ".jpg", ".jpeg", ".gif", ".bmp", ".pdf"):
        return head + ("This is an image or PDF; it can't be read as text here. Ask the analyst for the diagram as draw.io or "
                       "Visio (.vsdx), an asset list (CSV), nmap XML, or a short written description.")
    if suffix == ".vsd":
        return head + "Old binary Visio format. Ask the analyst to save it as .vsdx (File > Save As > Visio Drawing)."
    data = path.read_bytes()
    if suffix == ".vsdx" or data[:2] == b"PK":
        body = read_vsdx(data)
    else:
        text = data.decode("utf-8", errors="replace").lstrip("﻿")
        body = ""
        if suffix in (".xml", ".drawio", ".svg") or text.lstrip().startswith("<"):
            try:
                root = ET.fromstring(text)
            except ET.ParseError as e:
                return head + f"XML that could not be parsed: {e}"
            tag = root.tag.split("}")[-1]
            if tag == "nmaprun":
                body = read_nmap(root)
            elif tag in ("mxfile", "mxGraphModel"):
                body = read_drawio(root)
            elif tag == "svg":
                body = "SVG text labels: " + "; ".join(_clean(t) for t in ("".join(x.itertext()) for x in root.iter()
                                                                             if x.tag.split("}")[-1] == "text") if _clean(t))
            else:
                body = f"Unrecognized XML (root <{tag}>). Supported: nmap XML, draw.io."
        elif suffix in (".csv", ".tsv"):
            body = read_csv(text)
        else:
            body = text
    if len(body) > max_chars:
        body = body[:max_chars] + f"\n[... {len(body) - max_chars} more characters not shown]"
    return head + body


# ---------------------------------------------------------------------------------------------------------------
# Plan check: every T-code exists in ATT&CK and is the adversary's (or is marked); nothing exploitative is emulated
# ---------------------------------------------------------------------------------------------------------------
def check_plan(kb: AttackKB, text: str, actors: list[str]) -> tuple[bool, str]:
    """(ok, report). Line by line: each T-code must be a live ATT&CK technique; one ATT&CK does not record for the
    adversary (directly, via its software or via attributed campaigns) needs "analyst-added" or "intel:" on its line;
    exploitation and destructive impact may appear only on lines that say "not emulated"."""
    issues: list[str] = []
    notes: list[str] = []
    if not kb.load():
        return False, kb.error
    used: set[str] = set()
    for a in actors:
        g, cands = kb.resolve_group(a)
        if not g:
            notes.append(f"'{a}' is not an ATT&CK group" + (f" (ambiguous: {', '.join(c.get('name', '') for c in cands[:6])})"
                                                           if cands else "") + ": its techniques need 'intel:' or 'analyst-added'.")
            continue
        for sid in kb.group_techniques(g):
            used.add(_ext_id(kb.objs[sid]).upper())
    parents_used = {t.split(".")[0] for t in used}
    seen: set[str] = set()
    for n, line in enumerate(text.splitlines(), 1):
        for tid in TCODE.findall(line):
            tid = tid.upper()
            seen.add(tid)
            where = f"line {n} ({tid})"
            if not kb.technique_obj(tid):
                issues.append(f"{where}: not a live ATT&CK technique in {kb.version}. Fix the ID or drop the step.")
                continue
            why = never_emulated(tid, kb)
            if why and not NOT_EMULATED.search(line):
                issues.append(f"{where}: {why} is never emulated. List it under 'Not emulated' with its detection "
                              f"opportunity, and write 'not emulated' on that line.")
            if tid not in used and not (tid in parents_used) and not ALLOWED_EXTRA.search(line):
                issues.append(f"{where}: ATT&CK does not record {', '.join(actors) or 'the adversary'} using this "
                              f"technique. Drop it, or mark the line 'analyst-added' (the analyst asked for it) or cite "
                              f"'intel: <source>'.")
    if not seen:
        issues.append("No ATT&CK T-codes found. Every step needs its technique ID.")
    ok = not issues
    head = (f"Plan check against ATT&CK {kb.version}: {len(seen)} technique(s) cited, "
            + ("no problems found." if ok else f"{len(issues)} problem(s):"))
    return ok, "\n".join([head, *[f"- {i}" for i in issues], *[f"note: {x}" for x in notes]])


# ---------------------------------------------------------------------------------------------------------------
# Atomic Red Team: test metadata from a local checkout (never downloaded; never the commands)
# ---------------------------------------------------------------------------------------------------------------
def atomic_tests(atomics_dir: str | Path | None, technique_id: str) -> str:
    tid = technique_id.strip().upper()
    if not atomics_dir or not Path(atomics_dir).is_dir():
        return ("No local Atomic Red Team checkout is configured (cte.atomics_dir in harness.yaml). Reference "
                f"'Atomic Red Team tests for {tid}' and leave the test choice to the operator. Do not invent test numbers "
                "or names.")
    f = Path(atomics_dir) / tid / f"{tid}.yaml"
    if not f.is_file():
        return f"The local Atomic Red Team checkout has no tests for {tid}."
    data = yaml.safe_load(f.read_text(encoding="utf-8")) or {}
    rows = [f"Atomic Red Team tests for {tid} ({data.get('display_name', '')}), from {f}. Test numbers are 1-based "
            f"(Invoke-AtomicTest {tid} -TestNumbers N). Commands are not shown: the operator reviews each test before running it."]
    for i, t in enumerate(data.get("atomic_tests") or [], 1):
        ex = t.get("executor") or {}
        rows.append(f"  #{i} {t.get('name')} | platforms: {', '.join(t.get('supported_platforms') or [])} | "
                    f"executor: {ex.get('name', '?')}{' (elevated)' if ex.get('elevation_required') else ''} | "
                    f"guid {t.get('auto_generated_guid', '?')}\n      {re.sub(chr(10) + '+', ' ', str(t.get('description', '')).strip())[:300]}")
    return "\n".join(rows)


# ---------------------------------------------------------------------------------------------------------------
# Agent tools
# ---------------------------------------------------------------------------------------------------------------
def _layer(kb: AttackKB, name: str, actors: list[str], status: dict[str, str], description: str) -> dict[str, Any]:
    colors = {"emulate": "#1565c0", "not_emulated": "#9e9e9e", "analyst_added": "#f9a825", "detected": "#2e7d32",
              "partially_detected": "#9e9d24", "missed": "#c62828", "not_run": "#bdbdbd"}
    techniques = []
    for tid, st in sorted(status.items()):
        t = kb.technique_obj(tid)
        entry = {"techniqueID": tid.upper(), "enabled": True, "comment": f"{t.get('name') if t else ''} | {st}",
                 "metadata": [{"name": "status", "value": st}]}
        if st in colors:
            entry["color"] = colors[st]
        techniques.append(entry)
    return {"name": name, "versions": {"layer": "4.5", "navigator": "5.1.0"}, "domain": "enterprise-attack",
            "description": description or f"CTE plan: {', '.join(actors)} ({kb.version})",
            "techniques": techniques, "legendItems": [{"label": k.replace("_", " "), "color": c} for k, c in colors.items()],
            "metadata": [{"name": "generated", "value": datetime.now(timezone.utc).isoformat()[:19] + "Z"},
                         {"name": "ATT&CK", "value": kb.version}, {"name": "adversary", "value": ", ".join(actors)}]}


def list_folder(folder: Path) -> str:
    rows_ = [e for e in huntplans.entries(folder)]
    if not rows_:
        return f"No CTE plans yet in {folder}."
    rows = [f"CTE plans folder: {folder}"]
    for e in sorted(rows_, key=lambda e: e["name"]):
        when = datetime.fromtimestamp(e["mtime"], timezone.utc).strftime("%Y-%m-%d %H:%MZ")
        rows.append(f"  {e['name']:52s} {e['kind']:12s} {when}  {e['title']}" + ("  [edited by the analyst]" if e["edited"] else ""))
    maps = sorted(p.name for p in (folder / "maps").glob("*") if p.is_file()) if (folder / "maps").is_dir() else []
    if maps:
        rows.append("  network maps in maps/: " + ", ".join(maps))
    return "\n".join(rows)


def tools(kb: AttackKB, folder: Callable[[], Path], map_dirs: Callable[[], list[Path]], cfg: dict[str, Any],
          on_saved: Callable[[Path, str], None] | None = None) -> list[Tool]:
    S, I = {"type": "string"}, {"type": "integer"}
    L = {"type": "array", "items": {"type": "string"}}

    def find_map(name: str) -> Path | None:
        want = Path(str(name)).name.lower()
        for d in map_dirs():
            if not d.is_dir():
                continue
            root = d.resolve()
            for p in d.rglob("*"):
                if p.name.lower() == want and p.is_file() and not p.is_symlink() and p.resolve().is_relative_to(root):
                    return p
        return None

    def cte_network_map(name: str = "") -> str:
        if not name:
            found = []
            for d in map_dirs():
                if d.is_dir():
                    found += [f"  {p.relative_to(d)}  ({d})" for p in sorted(d.rglob("*"))
                              if p.is_file() and p.suffix.lower() in MAP_SUFFIXES and not p.is_symlink()
                              and not any(x in p.parts for x in ("older", huntplans.AGENT_COPY))]
            return ("Network map candidates (call again with name=<file name>):\n" + "\n".join(found[:200])) if found else \
                ("No network map files found. The analyst can drop one into " + str(folder() / "maps")
                 + " (CSV asset list, nmap XML, draw.io, Visio .vsdx, or a text description), or describe the network in chat.")
        p = find_map(name)
        if not p:
            return f"No file named '{name}' in {', '.join(str(d) for d in map_dirs())}. Call with no name to list them."
        return read_map(p)

    def cte_plan_save(name: str, content: str, actors: list[str], kind: str = "plan") -> str:
        if kind not in KINDS:
            raise ValueError(f"kind must be one of {list(KINDS)}")
        if kind == "plan":
            ok, report = check_plan(kb, content, actors)
            if not ok:
                return "NOT SAVED: the plan failed its check. Fix every problem, then save again.\n" + report
        else:
            report = "results saved (results are not checked against ATT&CK)"
        path = huntplans.write_versioned(folder(), f"{KINDS[kind]}{huntplans.slug(name, PREFIXES)}.md", content)
        if on_saved:
            on_saved(path, f"cte_{kind}")
        return f"saved {path}\n{report}"

    def cte_plan_check(actors: list[str], content: str = "", name: str = "") -> str:
        if not content:
            p = huntplans.find(folder(), name) or huntplans.find(folder(), f"cte_plan_{huntplans.slug(name, PREFIXES)}.md")
            if not p:
                return f"No CTE plan named '{name}'.\n" + list_folder(folder())
            content = p.read_text(encoding="utf-8", errors="replace")
        return check_plan(kb, content, actors)[1]

    def cte_plan_read(name: str, offset: int = 0, length: int = 40000) -> str:
        want = Path(name).name
        cands = [want, f"{want}.md", f"cte_plan_{huntplans.slug(want, PREFIXES)}.md", f"cte_results_{huntplans.slug(want, PREFIXES)}.md"]
        path = next((p for c in cands if (p := huntplans.find(folder(), c))), None)
        if not path:
            return f"No CTE file named '{name}'.\n" + list_folder(folder())
        text = path.read_text(encoding="utf-8", errors="replace")
        chunk = text[offset:offset + length]
        more = f"\n[... {len(text) - offset - len(chunk)} more characters: read again with offset={offset + len(chunk)}]" \
            if offset + len(chunk) < len(text) else ""
        edited = " - EDITED BY THE ANALYST since it was saved: see cte_plan_changes" if huntplans.edited(path) else ""
        return f"# {path.name} ({len(text)} chars){edited}\n{chunk}{more}"

    def cte_plan_changes(name: str) -> str:
        want = Path(name).name
        for c in (want, f"{want}.md", f"cte_plan_{huntplans.slug(want, PREFIXES)}.md", f"cte_results_{huntplans.slug(want, PREFIXES)}.md"):
            if huntplans.find(folder(), c):
                return huntplans.analyst_changes(folder(), c)
        return f"No CTE file named '{name}'.\n" + list_folder(folder())

    def cte_navigator_layer(name: str, actors: list[str], technique_status: dict[str, str], description: str = "") -> str:
        if err := kb._need():
            return err
        bad = [t for t in technique_status if not kb.technique_obj(t)]
        if bad:
            return f"Not live ATT&CK techniques: {bad}. Nothing saved."
        layer = _layer(kb, name, actors, technique_status, description)
        d = huntplans.ensure(folder())
        path = d / f"attack_layer_cte_{huntplans.slug(name, PREFIXES)}.json"
        path.write_text(json.dumps(layer, indent=1), encoding="utf-8")
        if on_saved:
            on_saved(path, "layer")
        return f"Saved ATT&CK Navigator layer {path} ({len(layer['techniques'])} techniques)."

    def cte_atomic_tests(technique_id: str) -> str:
        return atomic_tests(cfg.get("atomics_dir"), technique_id)

    tools_ = cfg.get("emulation_tools") or ["Atomic Red Team", "Mythic"]
    return [
        Tool("cte_network_map", "Read a network map the analyst dropped into the case (cte_plans/maps/ or the case evidence "
             "folder): CSV asset list, nmap XML, draw.io, Visio .vsdx, or a text description. With no name, lists the "
             "candidate files.", schema({"name": S}), cte_network_map),
        Tool("cte_plan_save", "Save a CTE plan (kind='plan') or, after the analyst ran the emulation, its results "
             "(kind='results') to the case's CTE plans folder. A plan is checked first and NOT saved if a T-code is not in "
             "ATT&CK, is not the adversary's (unless marked 'analyst-added' or 'intel: <source>'), or is exploitation or "
             "destructive impact outside a 'not emulated' line. Earlier versions are kept.",
             schema({"name": S, "content": S, "actors": L, "kind": {"type": "string", "enum": list(KINDS)}},
                    ["name", "content", "actors"]), cte_plan_save),
        Tool("cte_plan_check", "Check a CTE plan (content, or a saved plan by name) against ATT&CK without saving it.",
             schema({"actors": L, "content": S, "name": S}, ["actors"]), cte_plan_check),
        Tool("cte_plan_list", "List the case's CTE plans folder: plans, results, Navigator layers, network maps, and which "
             "files the analyst edited.", schema({}), lambda: list_folder(folder())),
        Tool("cte_plan_read", "Read a CTE plan or results file by name (or just the adversary part). Long files: continue "
             "with offset.", schema({"name": S, "offset": I, "length": I}, ["name"]), cte_plan_read),
        Tool("cte_plan_changes", "Show the analyst's edits to a CTE plan since it was saved (a diff). Turn them into lessons: "
             "skill_update for how plans are built, memory_record for facts about this network.",
             schema({"name": S}, ["name"]), cte_plan_changes),
        Tool("cte_navigator_layer", "Save an ATT&CK Navigator layer for a CTE plan in the CTE plans folder. technique_status "
             "per T-code: emulate | not_emulated | analyst_added; after the emulation: detected | partially_detected | "
             "missed | not_run.",
             schema({"name": S, "actors": L, "technique_status": {"type": "object", "additionalProperties": S},
                     "description": S}, ["name", "actors", "technique_status"]), cte_navigator_layer),
        Tool("cte_atomic_tests", f"List the Atomic Red Team tests for a technique from the local checkout (names, numbers, "
             f"platforms, executor; not the commands). Emulation tools configured: {', '.join(tools_)}.",
             schema({"technique_id": S}, ["technique_id"]), cte_atomic_tests),
    ]
