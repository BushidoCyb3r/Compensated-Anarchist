"""MITRE ATT&CK knowledge for hunt planning, from the official ATT&CK STIX 2.1 bundles (read from local files, so it
works air-gapped; `canarchist attack fetch` downloads them when the analyst chooses to).

What it answers:
  - which group is "Cozy Bear" (names, aliases, G-ids), and which techniques it uses - directly, through its software
    (S-ids) and through campaigns attributed to it (C-ids), with the procedure text ATT&CK records for each
  - what a technique is (T-id, tactics, platforms, sub-techniques), what data would show it, and which of the
    CONNECTED tools can see that data (Security Onion, Elastic, Splunk, Velociraptor)
  - an ATT&CK Navigator layer for a plan (scores = how many of the selected actors use a technique)

Data sources are read three ways, whichever the bundle has: `detects` relationships from data components (ATT&CK
<= v17), detection strategies / analytics (v18+), and the legacy `x_mitre_data_sources` field on techniques.
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from .tools.registry import Tool, schema

TACTIC_ORDER = ["reconnaissance", "resource-development", "initial-access", "execution", "persistence",
                "privilege-escalation", "defense-evasion", "credential-access", "discovery", "lateral-movement",
                "collection", "command-and-control", "exfiltration", "impact"]

# Which connected tool can observe which kind of data, with a hint for writing the query. Matched by keyword
# against data source / data component / log source names.
COVERAGE: list[tuple[tuple[str, ...], dict[str, str]]] = [
    (("network traffic", "network connection", "network share", "domain name", "dns", "nsm", "zeek", "netflow"), {
        "security_onion": "Zeek (event.dataset:zeek.conn / zeek.dns / zeek.http / zeek.ssl / zeek.smb_files / zeek.kerberos) and Suricata alerts; pair_counts for who talked to whom",
        "elastic": "network events (event.category:network, dns.question.name) if shipped",
        "splunk": "network / DNS / proxy data (CIM Network_Traffic, Network_Resolution, Web)"}),
    (("process", "command", "script", "module", "os api", "named pipe", "driver", "wmi", "sysmon", "4688"), {
        "velociraptor": "endpoint artifacts (Windows.System.Pslist, Windows.EventLogs.EvtxHunter, Windows.Persistence.PermanentWMIEvents, Linux.Sys.Pslist); collection needs analyst approval",
        "elastic": "endpoint / Sysmon / Windows logs (event.category:process, process.command_line, process.parent.name; EQL sequences)",
        "splunk": "Sysmon EventCode 1/7/17/19-21 and Security 4688 (CIM Endpoint.Processes)",
        "security_onion": "only if endpoint data is shipped to the grid (Elastic Agent / winlogbeat: logs-endpoint.*, logs-windows.*)"}),
    (("file",), {
        "velociraptor": "Windows.Search.FileFinder, Windows.NTFS.MFT, Linux file search artifacts; collection needs analyst approval",
        "elastic": "file events (Sysmon 11/23, Elastic Defend: event.category:file, file.path)",
        "splunk": "Sysmon 11/23, FIM sourcetypes (CIM Endpoint.Filesystem)",
        "security_onion": "files carried over the network (event.dataset:zeek.files, Strelka scans)"}),
    (("registry",), {
        "velociraptor": "Windows.Registry.* and Windows.Sys.StartupItems artifacts; collection needs analyst approval",
        "elastic": "registry events (Sysmon 12-14: registry.path, registry.value)",
        "splunk": "Sysmon EventCode 12-14 (CIM Endpoint.Registry)"}),
    (("logon session", "user account", "active directory", "credential", "authentication", "group", "4624", "kerberos"), {
        "elastic": "Windows Security events (event.code 4624/4625/4672/4768/4769/4776) and auth logs",
        "splunk": "WinEventLog:Security 4624/4625/4768/4769/4776 (CIM Authentication)",
        "velociraptor": "Windows.EventLogs.* and Windows.Sys.Users on the endpoint; collection needs analyst approval",
        "security_onion": "network view of authentication (event.dataset:zeek.kerberos / zeek.ntlm / zeek.smb_mapping)"}),
    (("scheduled job", "service", "startup", "cron", "systemd"), {
        "velociraptor": "Windows.System.TaskScheduler, Windows.System.Services, Linux.Sys.Crontab artifacts; collection needs analyst approval",
        "elastic": "Security 4698/4702, System 7045, 4697 (event.code)",
        "splunk": "Security 4698/4702, System 7045 (CIM Endpoint.Services)"}),
    (("application log", "firewall", "web credential", "certificate", "proxy"), {
        "elastic": "application / firewall / proxy logs if shipped",
        "splunk": "application / firewall / proxy sourcetypes",
        "security_onion": "Suricata (event.dataset:suricata.alert), zeek.x509 / zeek.ssl for certificates"}),
    (("firmware", "drive", "kernel", "sensor health", "boot"), {
        "velociraptor": "endpoint artifacts for drivers, boot configuration and drives; collection needs analyst approval"}),
]
NOT_OBSERVABLE = ("cloud", "container", "pod", "instance", "snapshot", "volume", "image", "cluster", "internet scan",
                  "malware repository", "persona", "domain registration", "passive dns", "social media")


def _ext_id(obj: dict[str, Any]) -> str:
    for r in obj.get("external_references") or []:
        if r.get("source_name") in ("mitre-attack", "mitre-ics-attack", "mitre-mobile-attack") and r.get("external_id"):
            return r["external_id"]
    return ""


def _live(obj: dict[str, Any]) -> bool:
    return not obj.get("revoked") and not obj.get("x_mitre_deprecated")


def _clip(text: str, n: int) -> str:
    text = re.sub(r"\(Citation:[^)]*\)", "", text or "")
    text = re.sub(r"\s+", " ", text).strip()
    return text if len(text) <= n else text[: n - 1].rstrip() + "…"


def coverage_for(data_names: list[str], connected: list[str]) -> dict[str, str]:
    """Connected tools that can observe any of these data sources, with a query hint each."""
    out: dict[str, str] = {}
    for name in data_names:
        low = name.lower()
        for keys, hints in COVERAGE:
            if any(k in low for k in keys):
                for tool, hint in hints.items():
                    if tool in connected and tool not in out:
                        out[tool] = hint
    return out


class AttackKB:
    def __init__(self, paths: list[Path]):
        self.paths = [Path(p) for p in paths]
        self._loaded = False
        self.error = ""
        self.version = ""
        self.objs: dict[str, dict[str, Any]] = {}
        self.by_ext: dict[str, str] = {}
        self.uses: dict[str, list[tuple[str, str]]] = defaultdict(list)       # source stix id -> [(target, procedure)]
        self.attributed: dict[str, list[str]] = defaultdict(list)            # group id -> campaign ids
        self.detected_by: dict[str, set[str]] = defaultdict(set)             # technique id -> data names
        self.subs: dict[str, list[str]] = defaultdict(list)                  # parent technique stix id -> subs

    # ---- loading -------------------------------------------------------------------------------
    def load(self) -> bool:
        if self._loaded:
            return not self.error
        found = [p for p in self.paths if p.is_file()]
        if found:
            self._loaded = True
            self.error = ""
        else:  # not cached: data fetched later is picked up on the next call, without a restart
            self.error = ("No MITRE ATT&CK data. Expected the ATT&CK STIX bundle at: "
                          + ", ".join(str(p) for p in self.paths)
                          + ". The analyst can run `canarchist attack fetch` (downloads enterprise-attack.json from MITRE's "
                            "attack-stix-data repository) or copy the file there on air-gapped networks.")
            return False
        objects: list[dict[str, Any]] = []
        versions = []
        for p in found:
            data = json.loads(p.read_text(encoding="utf-8"))
            objects.extend(data.get("objects") or [])
            versions += [f'{o.get("name", "ATT&CK")} v{o.get("x_mitre_version", "?")}' for o in data.get("objects") or []
                         if o.get("type") == "x-mitre-collection"]
        self.version = ", ".join(versions) or "unknown version"
        for o in objects:
            self.objs[o["id"]] = o
            ext = _ext_id(o)
            if ext and _live(o):
                self.by_ext[ext.upper()] = o["id"]
        components = {i: o for i, o in self.objs.items() if o.get("type") == "x-mitre-data-component"}
        sources = {i: o.get("name", "") for i, o in self.objs.items() if o.get("type") == "x-mitre-data-source"}
        for o in objects:
            t = o.get("type")
            if t == "relationship" and _live(o):
                rt, src, tgt = o.get("relationship_type"), o.get("source_ref", ""), o.get("target_ref", "")
                if rt == "uses":
                    self.uses[src].append((tgt, o.get("description", "")))
                elif rt == "attributed-to":
                    self.attributed[tgt].append(src)
                elif rt == "subtechnique-of":
                    self.subs[tgt].append(src)
                elif rt == "detects":
                    s = self.objs.get(src, {})
                    if s.get("type") == "x-mitre-data-component":
                        parent = sources.get(s.get("x_mitre_data_source_ref", ""), "")
                        self.detected_by[tgt].add(f"{parent}: {s.get('name')}" if parent else s.get("name", ""))
                    elif s.get("type") == "x-mitre-detection-strategy":  # ATT&CK v18+
                        for aref in s.get("x_mitre_analytic_refs") or []:
                            a = self.objs.get(aref, {})
                            for ls in a.get("x_mitre_log_source_references") or []:
                                comp = components.get(ls.get("x_mitre_data_component_ref", ""), {})
                                name = comp.get("name") or ls.get("name") or ""
                                if name:
                                    self.detected_by[tgt].add(f"{name} ({ls.get('name')})" if ls.get("name") and comp else name)
            elif t == "attack-pattern" and _live(o):
                for ds in o.get("x_mitre_data_sources") or []:
                    self.detected_by[o["id"]].add(ds)
        return True

    def _need(self) -> str | None:
        return None if self.load() else self.error

    # ---- lookups -------------------------------------------------------------------------------------
    def resolve_group(self, name: str) -> tuple[dict[str, Any] | None, list[dict[str, Any]]]:
        """Exact match on G-id, name or alias (case-insensitive); otherwise substring candidates."""
        if not self.load():
            return None, []
        q = name.strip().lower()
        if q.upper() in self.by_ext and self.objs[self.by_ext[q.upper()]].get("type") == "intrusion-set":
            return self.objs[self.by_ext[q.upper()]], []
        groups = [o for o in self.objs.values() if o.get("type") == "intrusion-set" and _live(o)]
        for g in groups:
            if q == g.get("name", "").lower() or q in [a.lower() for a in g.get("aliases") or []]:
                return g, []
        cands = [g for g in groups if q in g.get("name", "").lower() or any(q in a.lower() for a in g.get("aliases") or [])]
        return (cands[0], []) if len(cands) == 1 else (None, cands)

    def technique_obj(self, tid: str) -> dict[str, Any] | None:
        if not self.load():
            return None
        sid = self.by_ext.get(tid.strip().upper())
        o = self.objs.get(sid or "")
        return o if o and o.get("type") == "attack-pattern" else None

    def counts(self) -> dict[str, int]:
        live = [o.get("type") for o in self.objs.values() if _live(o)]
        return {"groups": live.count("intrusion-set"), "techniques": live.count("attack-pattern"),
                "software": live.count("malware") + live.count("tool"), "campaigns": live.count("campaign")}

    def tactics(self, t: dict[str, Any]) -> list[str]:
        return [p["phase_name"] for p in t.get("kill_chain_phases") or [] if p.get("kill_chain_name", "").startswith("mitre")]

    def group_techniques(self, g: dict[str, Any], include_software: bool = True, include_campaigns: bool = True
                         ) -> dict[str, dict[str, Any]]:
        """technique stix id -> {"via": [...], "procedures": [...]} for a group."""
        out: dict[str, dict[str, Any]] = defaultdict(lambda: {"via": [], "procedures": []})

        def add(src_label: str, tgt: str, proc: str) -> None:
            t = self.objs.get(tgt)
            if t and t.get("type") == "attack-pattern" and _live(t):
                e = out[tgt]
                if src_label not in e["via"]:
                    e["via"].append(src_label)
                if proc:
                    e["procedures"].append((src_label, proc))

        for tgt, proc in self.uses.get(g["id"], []):
            o = self.objs.get(tgt, {})
            if o.get("type") == "attack-pattern":
                add("group", tgt, proc)
            elif include_software and o.get("type") in ("malware", "tool") and _live(o):
                label = f"{_ext_id(o)} {o.get('name')}"
                for t2, p2 in self.uses.get(tgt, []):
                    add(label, t2, p2)
        if include_campaigns:
            for cid in self.attributed.get(g["id"], []):
                c = self.objs.get(cid, {})
                if not _live(c):
                    continue
                label = f"{_ext_id(c)} {c.get('name')}"
                for t2, p2 in self.uses.get(cid, []):
                    add(label, t2, p2)
        return dict(out)

    def data_for(self, tech: dict[str, Any]) -> list[str]:
        names = set(self.detected_by.get(tech["id"], set()))
        if not names and tech.get("x_mitre_is_subtechnique"):  # fall back to the parent technique's data
            parent = self.technique_obj(_ext_id(tech).split(".")[0])
            if parent:
                names |= self.detected_by.get(parent["id"], set())
        return sorted(n for n in names if n)


# ---------------------------------------------------------------------------------------------------------------
# Agent tools
# ---------------------------------------------------------------------------------------------------------------
def tools(kb: AttackKB, plans_dir: Callable[[], Path], connected: Callable[[], list[str]],
          on_saved: Callable[[Path, str], None] | None = None) -> list[Tool]:
    S, I, B = {"type": "string"}, {"type": "integer"}, {"type": "boolean"}
    L = {"type": "array", "items": {"type": "string"}}

    def short_cov(names: list[str]) -> str:
        cov = coverage_for(names, connected())
        if cov:  # conditional sources ("only if endpoint data is shipped") are marked so the plan does not rely on them
            return ", ".join(f"{k} (if endpoint data is shipped to it)" if v.startswith("only if") else k
                             for k, v in sorted(cov.items()))
        if names and all(any(k in n.lower() for k in NOT_OBSERVABLE) for n in names):
            return "not observable with connected tools"
        return "no connected source" if names else "unknown"

    def attack_search(query: str, kind: str = "any", limit: int = 20) -> str:
        """Search ATT&CK groups, software, campaigns and techniques by name, alias, ID or keyword."""
        if err := kb._need():
            return err
        q = query.lower().strip()
        types = {"group": ["intrusion-set"], "software": ["malware", "tool"], "campaign": ["campaign"],
                 "technique": ["attack-pattern"]}.get(kind, ["intrusion-set", "malware", "tool", "campaign", "attack-pattern"])
        hits = []
        for o in kb.objs.values():
            if o.get("type") not in types or not _live(o):
                continue
            names = [o.get("name", ""), *(o.get("aliases") or []), *(o.get("x_mitre_aliases") or []), _ext_id(o)]
            score = 3 if any(q == n.lower() for n in names) else 2 if any(q in n.lower() for n in names) else \
                1 if q in (o.get("description") or "").lower() else 0
            if score:
                hits.append((score, o))
        hits.sort(key=lambda x: (-x[0], x[1].get("name", "")))
        if not hits:
            return f"No ATT&CK object matches '{query}' ({kb.version})."
        rows = [f"{_ext_id(o):10s} {o['type']:13s} {o.get('name')}" + (f"  (aliases: {', '.join((o.get('aliases') or [])[1:6])})"
                if o.get("aliases") and len(o["aliases"]) > 1 else "") for _, o in hits[:limit]]
        return f"ATT&CK {kb.version} - {len(hits)} match(es)\n" + "\n".join(rows)

    def attack_group(name: str, platforms: list[str] | None = None, tactics: list[str] | None = None,
                     include_software: bool = True, include_campaigns: bool = True) -> str:
        """A threat group's profile and its techniques, grouped by tactic, with the data that would show each one
        and which connected tools can see it."""
        if err := kb._need():
            return err
        g, cands = kb.resolve_group(name)
        if not g:
            if cands:
                return f"'{name}' is ambiguous - candidates:\n" + "\n".join(
                    f"  {_ext_id(c)} {c.get('name')} (aliases: {', '.join(c.get('aliases') or [])})" for c in cands[:15])
            return f"No ATT&CK group named '{name}'. Try attack_search."
        techs = kb.group_techniques(g, include_software, include_campaigns)
        plats = {p.lower() for p in platforms or []}
        tacs = {t.lower() for t in tactics or []}
        rows: list[tuple[int, str, str]] = []
        for sid, info in techs.items():
            t = kb.objs[sid]
            tt = kb.tactics(t)
            if plats and not plats & {p.lower() for p in t.get("x_mitre_platforms") or []}:
                continue
            if tacs and not tacs & set(tt):
                continue
            order = min((TACTIC_ORDER.index(x) for x in tt if x in TACTIC_ORDER), default=99)
            data = kb.data_for(t)
            via = ", ".join(v for v in info["via"] if v != "group") or ""
            rows.append((order, _ext_id(t),
                         f"  {_ext_id(t):10s} {_clip(t.get('name', ''), 46):46s} [{', '.join(tt)}] "
                         f"{'/'.join(t.get('x_mitre_platforms') or [])}\n"
                         f"             data: {_clip('; '.join(data) or 'not listed', 140)}\n"
                         f"             seen by: {short_cov(data)}" + (f" | via: {_clip(via, 80)}" if via else "")))
        rows.sort(key=lambda r: (r[0], r[1]))
        sw = sorted({f"{_ext_id(kb.objs[t])} {kb.objs[t].get('name')}" for t, _ in kb.uses.get(g["id"], [])
                     if kb.objs.get(t, {}).get("type") in ("malware", "tool") and _live(kb.objs[t])})
        camps = [f"{_ext_id(kb.objs[c])} {kb.objs[c].get('name')}" for c in kb.attributed.get(g["id"], []) if c in kb.objs]
        head = [f"{_ext_id(g)} {g.get('name')} - ATT&CK {kb.version}",
                f"Aliases: {', '.join(g.get('aliases') or []) or 'none'}",
                f"About: {_clip(g.get('description', ''), 500)}",
                f"Software ({len(sw)}): {_clip(', '.join(sw), 600) or 'none recorded'}",
                f"Campaigns: {', '.join(camps) or 'none recorded'}",
                f"Connected tools: {', '.join(connected()) or 'none'}",
                f"Techniques: {len(rows)} shown" + (f" (filtered from {len(techs)})" if len(rows) != len(techs) else "")
                + " - use attack_technique(<T-id>, group) for the procedure and detection detail."]
        return "\n".join(head) + "\n" + "\n".join(r[2] for r in rows)

    def attack_technique(technique_id: str, group: str = "") -> str:
        """A technique's detail: tactics, platforms, description, detection guidance, the data that would show it,
        which connected tools can see that data (with query hints) and - with `group` - how that group did it."""
        if err := kb._need():
            return err
        t = kb.technique_obj(technique_id)
        if not t:
            return f"No live ATT&CK technique '{technique_id}' ({kb.version})."
        data = kb.data_for(t)
        cov = coverage_for(data, connected())
        out = [f"{_ext_id(t)} {t.get('name')} - tactics: {', '.join(kb.tactics(t))} - platforms: {', '.join(t.get('x_mitre_platforms') or [])}",
               f"Description: {_clip(t.get('description', ''), 900)}"]
        if t.get("x_mitre_detection"):
            out.append(f"ATT&CK detection notes: {_clip(t['x_mitre_detection'], 700)}")
        out.append("Data that would show it: " + ("; ".join(data) or "not listed in this ATT&CK version"))
        if cov:
            out.append("Connected tools that can see it:")
            out += [f"  - {k}: {v}" for k, v in sorted(cov.items())]
        else:
            out.append("Connected tools that can see it: none (a telemetry gap - say so in the plan)")
        subs = sorted(_ext_id(kb.objs[s]) + " " + kb.objs[s].get("name", "") for s in kb.subs.get(t["id"], [])
                      if _live(kb.objs.get(s, {})))
        if subs:
            out.append(f"Sub-techniques: {_clip(', '.join(subs), 700)}")
        if group:
            g, cands = kb.resolve_group(group)
            if not g:
                out.append(f"(group '{group}' not resolved)")
            else:
                info = kb.group_techniques(g).get(t["id"])
                if not info:
                    out.append(f"{g.get('name')} is not recorded using {_ext_id(t)} in ATT&CK.")
                else:
                    out.append(f"How {g.get('name')} used it (ATT&CK procedure examples, via {', '.join(info['via'])}):")
                    out += [f"  - [{src}] {_clip(p, 400)}" for src, p in info["procedures"][:8]]
        return "\n".join(out)

    def attack_navigator_layer(name: str, groups: list[str], technique_status: dict[str, str] | None = None,
                               description: str = "") -> str:
        """Save an ATT&CK Navigator layer (JSON) for a hunt plan into the hunt plans folder. Score = number of the selected
        groups that use each technique; technique_status colors and annotates each technique. The planner sets data
        status (planned | data_confirmed | data_unconfirmed | no_data); the threat_hunter sets hunt outcomes
        (hits | clear | query_error | inconclusive) by saving a layer with the same name."""
        if err := kb._need():
            return err
        resolved, missing = [], []
        for n in groups:
            g, _ = kb.resolve_group(n)
            (resolved.append(g) if g else missing.append(n))
        if not resolved:
            return f"No groups resolved from {groups}"
        users: dict[str, list[str]] = defaultdict(list)
        for g in resolved:
            for sid in kb.group_techniques(g):
                users[_ext_id(kb.objs[sid])].append(g.get("name", ""))
        colors = {"planned": "#f9a825", "data_confirmed": "#1565c0", "data_unconfirmed": "#9e9e9e", "no_data": "#c62828",
                  "hits": "#e65100", "clear": "#2e7d32", "query_error": "#6a1b9a", "inconclusive": "#9e9d24"}
        status = {k.upper(): v for k, v in (technique_status or {}).items()}
        techniques = []
        for tid, names in sorted(users.items()):
            entry = {"techniqueID": tid, "score": len(names), "enabled": True, "comment": "Used by: " + ", ".join(names)}
            st = status.get(tid)
            if st:
                entry["comment"] += f" | status: {st}"
                entry["metadata"] = [{"name": "status", "value": st}]
                if st in colors:
                    entry["color"] = colors[st]
            techniques.append(entry)
        layer = {
            "name": name, "versions": {"layer": "4.5", "navigator": "5.1.0"}, "domain": "enterprise-attack",
            "description": description or f"Hunt plan for {', '.join(g.get('name', '') for g in resolved)} ({kb.version}). "
                                          f"Score = number of selected groups using the technique.",
            "techniques": techniques,
            "gradient": {"colors": ["#ffffff", "#ff6666"], "minValue": 0, "maxValue": max(1, len(resolved))},
            "legendItems": [{"label": k.replace("_", " "), "color": c} for k, c in colors.items()],
            "metadata": [{"name": "generated", "value": datetime.now(timezone.utc).isoformat()[:19] + "Z"},
                         {"name": "ATT&CK", "value": kb.version}],
        }
        d = plans_dir()  # saved next to the plan in the hunt plans folder
        d.mkdir(parents=True, exist_ok=True)
        slug = re.sub(r"[^A-Za-z0-9._-]+", "_", name).strip("_")[:60] or "hunt_plan"
        path = d / f"attack_layer_{slug}.json"
        path.write_text(json.dumps(layer, indent=1), encoding="utf-8")
        if on_saved:
            on_saved(path, "layer")
        return (f"Saved ATT&CK Navigator layer {path} ({len(techniques)} techniques, {len(status)} with hunt status). "
                f"Open it in ATT&CK Navigator (Open Existing Layer -> Upload from local)."
                + (f" Unresolved groups: {missing}" if missing else ""))

    return [
        Tool("attack_search", "Search MITRE ATT&CK (local copy) for groups, software, campaigns or techniques by name, alias, "
             "ID or keyword. kind: any | group | software | campaign | technique.",
             schema({"query": S, "kind": S, "limit": I}, ["query"]), attack_search),
        Tool("attack_group", "A MITRE ATT&CK threat group (name, alias or G-id, e.g. 'APT29', 'Cozy Bear', 'G0016'): profile, "
             "software, campaigns and every technique it uses (directly, via its software, via attributed campaigns), "
             "ordered by tactic, each with the data that would show it and which CONNECTED tools can see that data. "
             "Filter with platforms (e.g. ['Windows','Linux']) and tactics.",
             schema({"name": S, "platforms": L, "tactics": L, "include_software": B, "include_campaigns": B}, ["name"]),
             attack_group),
        Tool("attack_technique", "A MITRE ATT&CK technique (T-id, e.g. 'T1059.001'): tactics, platforms, description, detection "
             "notes, data sources, which connected tools can see it (with query hints), sub-techniques, and - given "
             "`group` - that group's recorded procedures.",
             schema({"technique_id": S, "group": S}, ["technique_id"]), attack_technique),
        Tool("attack_navigator_layer", "Save an ATT&CK Navigator layer (JSON) for a hunt plan into the hunt plans folder: techniques "
             "used by the selected groups, scored by how many use each, colored by status. Planner: planned | "
             "data_confirmed | data_unconfirmed | no_data. Threat hunter (same layer name, after hunting): hits | clear | "
             "query_error | inconclusive.",
             schema({"name": S, "groups": L, "technique_status": {"type": "object", "additionalProperties": S},
                     "description": S}, ["name", "groups"]), attack_navigator_layer),
    ]
