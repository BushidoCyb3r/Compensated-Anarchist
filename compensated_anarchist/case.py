"""Case workspace shared by the lead agent and all experts.

cases/<CASE_ID>/
  case.json        structured state: notes, IOCs, timeline, findings, evidence register
  audit.jsonl      hash-chained audit log
  transcripts/     full agent conversations (training data for local models)
  artifacts/       spilled tool output, tool-generated files (timelines, carved files...)
  report.md        generated report
"""

from __future__ import annotations

import hashlib
import json
import re
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .tools.registry import Tool, schema

SEVERITIES = ["informational", "low", "medium", "high", "critical"]
IOC_TYPES = ["ipv4", "ipv6", "domain", "url", "md5", "sha1", "sha256", "filename", "filepath", "registry",
             "email", "user", "process", "mutex", "ja3", "ja4", "useragent", "certificate", "other"]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256_file(path: Path) -> dict[str, str]:
    h = {"md5": hashlib.md5(), "sha1": hashlib.sha1(), "sha256": hashlib.sha256()}
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            for x in h.values():
                x.update(chunk)
    return {k: v.hexdigest() for k, v in h.items()}


class Case:
    def __init__(self, cases_dir: Path, case_id: str):
        self.id = case_id
        self.dir = cases_dir / case_id
        for sub in ("transcripts", "artifacts"):
            (self.dir / sub).mkdir(parents=True, exist_ok=True)
        self.path = self.dir / "case.json"
        self._lock = threading.Lock()
        if self.path.exists():
            self.data = json.loads(self.path.read_text())
        else:
            self.data = {"id": case_id, "opened": _now(), "status": "open", "mission": "", "notes": [], "iocs": [],
                         "timeline": [], "findings": [], "evidence": []}
            self._save()

    @property
    def artifacts(self) -> Path:
        return self.dir / "artifacts"

    def _save(self) -> None:
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.data, indent=2, default=str))
        tmp.replace(self.path)

    def _append(self, key: str, item: dict[str, Any]) -> str:
        with self._lock:
            item = {"id": f"{key[:3].upper()}-{len(self.data[key]) + 1:04d}", "ts": _now(), **item}
            self.data[key].append(item)
            self._save()
            return item["id"]

    # ---- tool handlers ----------------------------------------------------
    def add_note(self, text: str, author: str = "agent") -> str:
        return f"recorded {self._append('notes', {'author': author, 'text': text})}"

    def add_ioc(self, type: str, value: str, context: str, confidence: str = "medium",
                attack_techniques: list[str] | None = None) -> str:
        for i in self.data["iocs"]:
            if i["type"] == type and i["value"] == value:
                return f"IOC already recorded as {i['id']}"
        iid = self._append("iocs", {"type": type, "value": value, "context": context, "confidence": confidence,
                                    "attack_techniques": attack_techniques or []})
        return f"recorded {iid}"

    def add_timeline_event(self, timestamp: str, description: str, host: str = "", source: str = "",
                           attack_technique: str = "") -> str:
        eid = self._append("timeline", {"event_time": timestamp, "host": host, "description": description,
                                        "source": source, "attack_technique": attack_technique})
        with self._lock:
            self.data["timeline"].sort(key=lambda e: e.get("event_time", ""))
            self._save()
        return f"recorded {eid}"

    def add_finding(self, title: str, severity: str, description: str, attack_techniques: list[str] | None = None,
                    affected_assets: list[str] | None = None, evidence: list[str] | None = None,
                    recommended_actions: list[str] | None = None, confidence: str = "medium") -> str:
        fid = self._append("findings", {
            "title": title, "severity": severity, "description": description, "confidence": confidence,
            "attack_techniques": attack_techniques or [], "affected_assets": affected_assets or [],
            "evidence": evidence or [], "recommended_actions": recommended_actions or [], "verdict": "unreviewed"})
        return f"recorded {fid}"

    def register_evidence(self, path: str, description: str, acquired_by: str = "") -> str:
        p = Path(path).resolve()
        if not p.is_file():
            return f"ERROR: {p} is not a file"
        hashes = sha256_file(p)
        eid = self._append("evidence", {"path": str(p), "size": p.stat().st_size, "description": description,
                                        "acquired_by": acquired_by, "hashes": hashes, "custody": [
                                            {"ts": _now(), "action": "registered", "by": acquired_by or "harness"}]})
        return f"registered {eid} sha256={hashes['sha256']}"

    def save_artifact(self, filename: str, content: str) -> str:
        name = re.sub(r"[^A-Za-z0-9_.-]", "_", filename).lstrip(".") or "artifact.txt"
        out = self.artifacts / "authored" / name
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(content, encoding="utf-8")
        return f"saved {out} ({len(content)} chars)"

    def set_verdict(self, finding_id: str, verdict: str, note: str = "") -> bool:
        with self._lock:
            for f in self.data["findings"]:
                if f["id"] == finding_id:
                    f["verdict"], f["verdict_note"] = verdict, note
                    self._save()
                    return True
        return False

    def summary(self, max_items: int = 25) -> str:
        d = self.data
        lines = [f"CASE {d['id']} status={d['status']} opened={d['opened']}", f"Mission: {d.get('mission', '')}"]
        lines.append(f"\nFindings ({len(d['findings'])}):")
        lines += [f"  {f['id']} [{f['severity']}/{f['verdict']}] {f['title']} ATT&CK={','.join(f['attack_techniques'])}"
                  for f in d["findings"][-max_items:]]
        lines.append(f"\nIOCs ({len(d['iocs'])}):")
        lines += [f"  {i['id']} {i['type']}={i['value']} ({i['confidence']}) {i['context'][:80]}" for i in d["iocs"][-max_items:]]
        lines.append(f"\nTimeline ({len(d['timeline'])} events, latest {max_items}):")
        lines += [f"  {e['event_time']} {e['host']} {e['description'][:100]}" for e in d["timeline"][-max_items:]]
        lines.append(f"\nEvidence ({len(d['evidence'])}):")
        lines += [f"  {e['id']} {e['path']} sha256={e['hashes']['sha256'][:16]}..." for e in d["evidence"]]
        lines.append(f"\nNotes ({len(d['notes'])}, latest 10):")
        lines += [f"  {n['ts'][:19]} {n['author']}: {n['text'][:160]}" for n in d["notes"][-10:]]
        return "\n".join(lines)

    def write_report(self, executive_summary: str, analysis: str = "", recommendations: str = "") -> str:
        d = self.data
        sev_rank = {s: i for i, s in enumerate(SEVERITIES)}
        findings = sorted(d["findings"], key=lambda f: -sev_rank.get(f["severity"], 0))
        md = [f"# Incident / Operation Report - {d['id']}", "",
              f"*Generated {_now()} by Compensated Anarchist. Case opened {d['opened']}.*", "",
              "## Executive summary", executive_summary, ""]
        if analysis:
            md += ["## Analysis", analysis, ""]
        md += ["## Findings", ""]
        for f in findings:
            md += [f"### {f['id']} - {f['title']}",
                   f"- **Severity:** {f['severity']}  **Confidence:** {f['confidence']}  **Analyst verdict:** {f['verdict']}",
                   f"- **ATT&CK:** {', '.join(f['attack_techniques']) or 'n/a'}",
                   f"- **Affected assets:** {', '.join(f['affected_assets']) or 'n/a'}", "", f["description"], ""]
            if f["recommended_actions"]:
                md += ["**Recommended actions:**"] + [f"- {a}" for a in f["recommended_actions"]] + [""]
        md += ["## Indicators of compromise", "", "| ID | Type | Value | Confidence | Context |", "|---|---|---|---|---|"]
        md += [f"| {i['id']} | {i['type']} | `{i['value']}` | {i['confidence']} | {i['context'][:120]} |" for i in d["iocs"]]
        md += ["", "## Timeline", "", "| Time (UTC) | Host | Event | Source | ATT&CK |", "|---|---|---|---|---|"]
        md += [f"| {e['event_time']} | {e['host']} | {e['description'][:200]} | {e['source']} | {e['attack_technique']} |"
               for e in d["timeline"]]
        md += ["", "## Evidence register (chain of custody)", "", "| ID | Path | SHA-256 | Description |", "|---|---|---|---|"]
        md += [f"| {e['id']} | {e['path']} | `{e['hashes']['sha256']}` | {e['description']} |" for e in d["evidence"]]
        if recommendations:
            md += ["", "## Recommendations", recommendations]
        out = self.dir / "report.md"
        out.write_text("\n".join(md))
        return f"report written to {out}"

    # ---- tool definitions ---------------------------------------------------
    def tools(self) -> list[Tool]:
        S = {"type": "string"}
        L = {"type": "array", "items": {"type": "string"}}
        return [
            Tool("case_add_note", "Record an analyst-grade note (hypothesis, observation, decision) in the case file.",
                 schema({"text": S, "author": S}, ["text"]), self.add_note),
            Tool("case_add_ioc", "Record an indicator of compromise with context and confidence.",
                 schema({"type": {"type": "string", "enum": IOC_TYPES}, "value": S, "context": S,
                         "confidence": {"type": "string", "enum": ["low", "medium", "high"]},
                         "attack_techniques": L}, ["type", "value", "context"]), self.add_ioc),
            Tool("case_add_timeline_event", "Add an event to the incident timeline (ISO-8601 UTC timestamp).",
                 schema({"timestamp": S, "description": S, "host": S, "source": S, "attack_technique": S},
                        ["timestamp", "description"]), self.add_timeline_event),
            Tool("case_add_finding", "Record a finding: what happened, how bad, ATT&CK mapping, evidence, recommended actions.",
                 schema({"title": S, "severity": {"type": "string", "enum": SEVERITIES}, "description": S,
                         "attack_techniques": L, "affected_assets": L, "evidence": L, "recommended_actions": L,
                         "confidence": {"type": "string", "enum": ["low", "medium", "high"]}},
                        ["title", "severity", "description"]), self.add_finding),
            Tool("case_register_evidence", "Hash (MD5/SHA1/SHA256) and register an evidence file in the chain-of-custody register.",
                 schema({"path": S, "description": S, "acquired_by": S}, ["path", "description"]), self.register_evidence),
            Tool("case_save_artifact", "Save an authored text artifact into the case (detection rule, Sigma/YARA/Suricata rule, script, brief, IOC export).",
                 schema({"filename": S, "content": S}, ["filename", "content"]), self.save_artifact),
            Tool("case_summary", "Show the current case state: findings, IOCs, timeline, evidence, notes.",
                 schema({}), lambda: self.summary()),
            Tool("case_write_report", "Generate report.md from the case data plus your narrative sections (markdown).",
                 schema({"executive_summary": S, "analysis": S, "recommendations": S}, ["executive_summary"]),
                 self.write_report),
        ]
