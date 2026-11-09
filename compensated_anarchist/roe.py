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
  1. posture: in "observe" posture anything above `notify` is denied.
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
        self.target_keys = scope.get("target_arg_keys", ["host", "hostname", "ip", "client_id", "target"])
        self.allowed_targets = [str(x) for x in scope.get("allowed_targets", [])]
        self.protected_assets = [str(x) for x in scope.get("protected_assets", [])]
        self.rules = [
            Rule(match=r["match"], tier=r["tier"], args=r.get("args") or {}, note=r.get("note", ""))
            for r in cfg.get("rules", [])
        ]
        for r in self.rules:
            if r.tier not in TIERS:
                raise ValueError(f"ROE rule {r.match}: bad tier {r.tier}")
        self._approval_lock = asyncio.Lock()  # one approval prompt at a time across parallel experts
        self.target_resolver: TargetResolver | None = None

    # ---- classification -------------------------------------------------
    def classify(
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
        decision = await self._decide(tool, arguments, rationale, agent, tier, why)
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

    async def _decide(self, tool, arguments, rationale, agent, tier, why) -> Decision:
        if tier == "deny":
            return Decision("deny", False, f"denied by ROE: {why}", why)
        if self.posture == "observe" and tier == "approve":
            return Decision("deny", False, "denied: harness is in OBSERVE posture (no response actions)", why)

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
