"""Rules of Engagement (ROE) policy engine + analyst approval gate.

Every tool call - local, MCP, or delegated - passes through `RoeGate.authorize()` in code.
The model cannot bypass it: a call that is not authorized is never executed, and the
model is told why.

Tiers (least to most restrictive):
  auto     - run without asking (read-only hunting, case notes)
  notify   - run, but announce to the analyst and audit prominently
  approve  - stop and require an analyst decision
  deny     - never run

Resolution order for a call:
  0. built-in floors: HUMAN_GATED tools are never below `approve`; under the gate-everything floor
     (GATE_ALL_EXPERTS / GATE_ALL_PLAYBOOKS) every call by the gated agent or in the gated conversation is `approve`.
  1. posture: in "observe" posture anything above `notify` is denied (except rules with `observe: ask`, and
     read-only calls that only need approval because of the gate-everything floor).
  2. first matching rule in roe.yaml (tool glob + optional argument globs).
  3. MCP tool annotations, only for servers listed in trust_annotations_from.
  4. default_tier.
  Then for active tiers (notify/approve) the scope check runs:
  - a target argument outside the authorized scope -> deny
  - a target argument that is a protected asset   -> escalate to approve
"""

from __future__ import annotations

import asyncio
import fnmatch
import ipaddress
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Awaitable, Callable

from .audit import AuditLog
from .config import load_yaml

TIERS = ["auto", "notify", "approve", "deny"]

# Built-in human-in-the-loop floor. Anything that changes an endpoint, runs on one, or pulls files from it through
# Velociraptor needs an analyst's approval no matter what roe.yaml says: a rule can make these `deny`, but never
# `auto` or `notify`. Quarantine, collection, hunts, memory images and evidence downloads all land here.
HUMAN_GATED = (
    "velociraptor*__collect_artifact", "velociraptor*__create_hunt", "velociraptor*__acquire_memory",
    "velociraptor*__download_flow_uploads", "velociraptor*__label_client",
    "velociraptor*__quarantine_host", "velociraptor*__unquarantine_host", "velociraptor*__run_server_vql",
    "vuln_*",  # vulnerability assessment: scanners and command-line tools, listing them and saving the report
)

# Built-in "gate everything" floor. Every action - reads, case notes, memory, skills, the final report - taken by
# one of these experts, or by any agent in a conversation that ran one of these playbooks or used one of these
# experts, needs an analyst's approval. roe.yaml (gate_everything:) can add experts and playbooks, never remove these.
GATE_ALL_EXPERTS = ("vuln_assessor",)
GATE_ALL_PLAYBOOKS = ("vulnerability_assessment",)
# (agent, tool, arguments) -> why this call must be approved under the gate-everything floor, or "" if not
GateHook = Callable[[str, str, dict[str, Any]], str]


def missing_shipped_rules(site: Path, shipped: Path) -> list[dict[str, Any]]:
    """Rules of the shipped roe.yaml that a site ROE file has no rule for (same tool glob and argument globs). A site
    file is a copy made at install time, so rules that later updates add are missing from it, and the tools they
    cover fall to its default tier (usually approve, which OBSERVE denies). A site rule of its own for the same
    match, at any tier, is the site's choice and is not reported."""
    try:
        if not site.exists() or not shipped.exists() or site.resolve() == shipped.resolve():
            return []

        def key(r: dict[str, Any]) -> tuple[str, str]:
            return str(r.get("match")), json.dumps(r.get("args") or {}, sort_keys=True)
        have = {key(r) for r in load_yaml(site).get("rules") or [] if isinstance(r, dict)}
        return [r for r in load_yaml(shipped).get("rules") or [] if isinstance(r, dict) and key(r) not in have]
    except (OSError, ValueError, AttributeError):
        return []


def drift_note(site: Path, shipped: Path) -> str:
    """One warning for doctor and start when the site ROE file lacks shipped rules, or "" when it has them all."""
    missing = missing_shipped_rules(site, shipped)
    if not missing:
        return ""
    default = (load_yaml(site) or {}).get("default_tier", "approve")
    names = ", ".join(f"{r['match']} ({r.get('tier')})" for r in missing)
    return (f"your ROE file {site.name} has no rule for {len(missing)} rule(s) that {shipped.name} now ships: {names}. "
            f"The calls they cover get a later rule or the default tier ({default}) instead. Copy them from "
            f"{shipped.name} into {site.name}, in the same place (the first matching rule wins), or add your own rule "
            "for each to keep a different choice.")


def roe_drift_note(cfg: Any) -> str:
    """drift_note for an installation: its ROE file (harness.roe) against the roe.yaml shipped next to it."""
    return drift_note(Path(cfg.roe_path), Path(cfg.root) / "roe.yaml")


def human_gated(tool: str) -> bool:
    return any(fnmatch.fnmatchcase(tool, p) for p in HUMAN_GATED)


@dataclass
class Decision:
    tier: str
    allowed: bool
    reason: str
    rule: str = ""
    approved_by: str = ""


@dataclass
class Rule:
    match: str
    tier: str
    args: dict[str, list[str]] = field(default_factory=dict)
    note: str = ""
    observe: str = ""  # "ask": an approve-tier action that may still be requested in OBSERVE posture (collection)

    def matches(self, tool: str, arguments: dict[str, Any]) -> bool:
        if not fnmatch.fnmatchcase(tool, self.match):
            return False
        for key, patterns in self.args.items():
            val = arguments.get(key)
            vals = val if isinstance(val, list) else [val]
            if val is None or not all(
                any(fnmatch.fnmatchcase(str(v), p) for p in patterns) for v in vals
            ):
                return False
        return True


def _matches_target(value: str, patterns: list[str]) -> bool:
    for p in patterns:
        try:
            net = ipaddress.ip_network(p, strict=False)
            try:
                if ipaddress.ip_address(value) in net:
                    return True
            except ValueError:
                try:  # a range target (10.0.5.0/24) is in scope only if all of it is
                    sub = ipaddress.ip_network(value, strict=False)
                    if sub.version == net.version and sub.subnet_of(net):
                        return True
                except ValueError:
                    pass
            continue
        except ValueError:
            pass
        if fnmatch.fnmatchcase(value.lower(), p.lower()):
            return True
    return False


Approver = Callable[[str, dict[str, Any], str, str], Awaitable[tuple[bool, str]]]
# (tool, target value) -> aliases of that target (e.g. a Velociraptor client id -> hostname, fqdn, last IP)
TargetResolver = Callable[[str, str], Awaitable[list[str]]]


class RoeGate:
    def __init__(self, path: Path, audit: AuditLog, approver: Approver, posture: str | None = None):
        cfg = load_yaml(path)
        self.path = path
        self.audit = audit
        self.approver = approver
        self.posture = posture or cfg.get("posture", "respond")
        if self.posture not in ("observe", "respond"):
            raise ValueError("posture must be 'observe' or 'respond'")
        self.default_tier = cfg.get("default_tier", "approve")
        self.trust_annotations_from = set(cfg.get("trust_annotations_from", []))
        scope = cfg.get("scope") or {}
        self.scope_enforce = bool(scope.get("enforce", True))
        # "targets" is always a target key: the vulnerability tools put every host they touch there
        self.target_keys = list(dict.fromkeys([*scope.get("target_arg_keys", ["host", "hostname", "ip", "client_id", "target"]),
                                               "targets"]))
        self.allowed_targets = [str(x) for x in scope.get("allowed_targets", [])]
        self.protected_assets = [str(x) for x in scope.get("protected_assets", [])]
        self.rules = [
            Rule(match=r["match"], tier=r["tier"], args=r.get("args") or {}, note=r.get("note", ""),
                 observe=str(r.get("observe", "")))
            for r in cfg.get("rules", [])
        ]
        for r in self.rules:
            if r.tier not in TIERS:
                raise ValueError(f"ROE rule {r.match}: bad tier {r.tier}")
        self._approval_lock = asyncio.Lock()  # one approval prompt at a time across parallel experts
        self.target_resolver: TargetResolver | None = None
        gate = cfg.get("gate_everything") or {}
        self.gate_all_experts = set(GATE_ALL_EXPERTS) | {str(x) for x in gate.get("experts") or []}
        self.gate_all_playbooks = set(GATE_ALL_PLAYBOOKS) | {str(x) for x in gate.get("playbooks") or []}
        self.gate_hook: GateHook | None = None  # set by the harness (it knows conversations and subagents)

    # ---- classification -------------------------------------------------
    def classify(
        self, tool: str, arguments: dict[str, Any], annotations: dict[str, Any] | None = None, server: str = ""
    ) -> tuple[str, str]:
        tier, why = self._classify(tool, arguments, annotations, server)
        if tier in ("auto", "notify") and human_gated(tool):
            return "approve", f"{why}; raised to approve by the built-in human gate (touches an endpoint)"
        return tier, why

    def _rule(self, tool: str, arguments: dict[str, Any]) -> Rule | None:
        return next((r for r in self.rules if r.matches(tool, arguments)), None)

    def _classify(
        self, tool: str, arguments: dict[str, Any], annotations: dict[str, Any] | None = None, server: str = ""
    ) -> tuple[str, str]:
        for r in self.rules:
            if r.matches(tool, arguments):
                return r.tier, f"rule '{r.match}'" + (f" ({r.note})" if r.note else "")
        if annotations and server in self.trust_annotations_from:
            if annotations.get("destructive_hint"):
                return "approve", f"annotation destructive_hint from trusted server {server}"
            if annotations.get("read_only_hint"):
                return "auto", f"annotation read_only_hint from trusted server {server}"
        return self.default_tier, "default_tier"

    def _targets(self, arguments: dict[str, Any]) -> list[str]:
        out: list[str] = []
        for k in self.target_keys:
            v = arguments.get(k)
            if isinstance(v, list):
                out.extend(str(x) for x in v)
            elif v not in (None, ""):
                out.append(str(v))
        return out

    # ---- authorization ---------------------------------------------------
    async def authorize(
        self,
        tool: str,
        arguments: dict[str, Any],
        rationale: str,
        agent: str,
        annotations: dict[str, Any] | None = None,
        server: str = "",
    ) -> Decision:
        tier, why = self.classify(tool, arguments, annotations, server)
        gated = self.gate_hook(agent, tool, arguments) if self.gate_hook else ""
        raised = bool(gated) and tier in ("auto", "notify")
        if gated and tier != "deny":
            tier, why = "approve", f"{why}; {gated}"
        decision = await self._decide(tool, arguments, rationale, agent, tier, why, ask_in_observe=raised)
        self.audit.record(
            "roe_decision",
            agent=agent,
            tool=tool,
            arguments=arguments,
            tier=decision.tier,
            allowed=decision.allowed,
            reason=decision.reason,
            approved_by=decision.approved_by,
            rationale=rationale[:2000],
        )
        return decision

    async def _decide(self, tool, arguments, rationale, agent, tier, why, ask_in_observe: bool = False) -> Decision:
        if tier == "deny":
            return Decision("deny", False, f"denied by ROE: {why}", why)
        if self.posture == "observe" and tier == "approve" and not ask_in_observe:  # gate-raised reads may still ask
            rule = self._rule(tool, arguments)
            if not (rule and rule.observe == "ask" and rule.tier == "approve"):
                return Decision("deny", False, "denied: harness is in OBSERVE posture (no response actions)", why)
            why = f"{why}; OBSERVE posture allows asking for this collection"

        if tier in ("notify", "approve"):
            targets = self._targets(arguments)
            names: dict[str, list[str]] = {t: [t] for t in targets}
            if targets and self.target_resolver and (self.allowed_targets or self.protected_assets):
                for t in targets:  # e.g. client id -> hostname/fqdn/IP so CIDR/hostname scope rules apply
                    names[t] += [a for a in await self.target_resolver(tool, t) if a]
            if self.scope_enforce and self.allowed_targets:
                outside = [t for t, ns in names.items() if not any(_matches_target(n, self.allowed_targets) for n in ns)]
                if outside:
                    detail = "; ".join(f"{t} = {names[t][1:] or 'unresolvable'}" for t in outside)
                    return Decision("deny", False, f"denied: target(s) outside authorized scope ({detail})", why)
                if any(len(ns) > 1 for ns in names.values()):
                    why = f"{why}; in scope as {[ns for ns in names.values()]}"
            protected = [t for t, ns in names.items() if any(_matches_target(n, self.protected_assets) for n in ns)]
            if protected:
                tier, why = "approve", f"{why}; PROTECTED ASSET {protected}"

        if tier == "auto":
            return Decision("auto", True, why, why)
        if tier == "notify":
            return Decision("notify", True, why, why)

        async with self._approval_lock:
            ok, note = await self.approver(tool, arguments, rationale, f"[{agent}] {why}")
        if ok:
            return Decision("approve", True, f"approved by analyst: {note}".strip(), why, self.audit.operator)
        return Decision("approve", False, f"analyst DENIED: {note or 'no reason given'}", why)


# ---- approvers --------------------------------------------------------------
async def cli_approver(tool: str, arguments: dict[str, Any], rationale: str, why: str) -> tuple[bool, str]:
    def ask() -> tuple[bool, str]:
        bar = "=" * 78
        print(f"\n{bar}\n  APPROVAL REQUIRED  {why}\n{bar}")
        print(f"  tool : {tool}")
        print("  args : " + json.dumps(arguments, indent=2, default=str).replace("\n", "\n         "))
        if rationale:
            print(f"  why  : {rationale.strip()[:1500]}")
        print(bar)
        while True:
            ans = input("  Approve? [y]es / [n]o : ").strip().lower()
            if ans in ("y", "yes", "n", "no"):
                break
        note = input("  Note / reason (feeds the agent's learning): ").strip()
        return ans.startswith("y"), note

    return await asyncio.to_thread(ask)


async def deny_all_approver(tool, arguments, rationale, why) -> tuple[bool, str]:
    return False, "non-interactive run: approvals auto-denied"
