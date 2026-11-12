"""Unified tool registry + executor (local tools, MCP tools, agent tools).

Execution pipeline for every call, from every agent:
   allowlist check (expert's tool globs) -> ROE gate -> run -> truncate/spill -> audit
Tool output is wrapped as UNTRUSTED data: logs, alerts, files and packets are attacker-
influenced and may contain prompt-injection text.
"""

from __future__ import annotations

import contextvars
import fnmatch
import hashlib
import inspect
import json
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Awaitable, Callable

from ..audit import AuditLog
from ..llm.base import ToolCall, ToolSpec
from ..roe import RoeGate

Handler = Callable[..., Awaitable[str] | str]


@dataclass(frozen=True)
class CallRef:
    """The tool call being executed: which agent made it, its id, and a digest of its name and arguments. `resumed`
    is set when an interrupted operation runs a call that had no result yet when it stopped."""
    agent_id: str
    call_id: str
    digest: str
    resumed: bool = False

    @property
    def key(self) -> str:
        return f"{self.agent_id}:{self.call_id}:{self.digest}"


# Set while a tool runs, so the approver and the orchestration tools know which call they serve (contextvars
# follow each asyncio task, so parallel calls never see each other's).
CURRENT_CALL: contextvars.ContextVar[CallRef | None] = contextvars.ContextVar("ca_current_call", default=None)


def call_digest(name: str, arguments: Any) -> str:
    return hashlib.sha256(json.dumps([name, arguments], sort_keys=True, default=str).encode()).hexdigest()[:12]


@dataclass
class Tool:
    name: str
    description: str
    parameters: dict[str, Any]
    handler: Handler
    server: str = ""  # MCP server name, "" for local
    annotations: dict[str, Any] = field(default_factory=dict)
    quarantined: bool = False  # from an MCP server in quarantine: listed for onboarding, never offered or called

    @property
    def spec(self) -> ToolSpec:
        return ToolSpec(self.name, self.description, self.parameters)


def schema(properties: dict[str, Any], required: list[str] | None = None) -> dict[str, Any]:
    return {"type": "object", "properties": properties, "required": required or [], "additionalProperties": False}


class ToolRegistry:
    def __init__(self) -> None:
        self.tools: dict[str, Tool] = {}

    def add(self, tool: Tool) -> None:
        if tool.name in self.tools:
            raise ValueError(f"duplicate tool {tool.name}")
        self.tools[tool.name] = tool

    def specs(self, allow: list[str] | None = None, deny: list[str] | None = None) -> list[ToolSpec]:
        return [t.spec for t in self.select(allow, deny)]

    def select(self, allow: list[str] | None = None, deny: list[str] | None = None) -> list[Tool]:
        out = []
        for t in self.tools.values():
            if t.quarantined:
                continue
            if allow is not None and not any(fnmatch.fnmatchcase(t.name, p) for p in allow):
                continue
            if deny and any(fnmatch.fnmatchcase(t.name, p) for p in deny):
                continue
            out.append(t)
        return out


class ToolExecutor:
    def __init__(self, registry: ToolRegistry, roe: RoeGate, audit: AuditLog, spill_dir: Path, max_chars: int,
                 on_event: Callable[[str, dict[str, Any]], None] | None = None):
        self.registry = registry
        self.roe = roe
        self.audit = audit
        self.budget_of: Callable[[], Any] = lambda: None  # the running operation's budget (set by the harness)
        self.spill_dir = spill_dir
        self.max_chars = max_chars
        self.on_event = on_event or (lambda kind, data: None)
        self.denials: list[dict[str, Any]] = []  # analyst denials -> learning signal

    async def execute(self, call: ToolCall, agent: str, rationale: str, allowed: list[ToolSpec],
                      local: dict[str, Tool] | None = None, agent_id: str = "", resumed: bool = False) -> tuple[str, bool]:
        """Returns (content_for_model, is_error). `local` holds tools bound to this agent (skills, report
        submission); they go through the same ROE gate and audit as registry tools. `resumed`: the call is run by
        an operation resumed after an interruption (the ROE decides it again)."""
        if call.parse_error:
            return f"ERROR: {call.parse_error}. Re-issue the call with valid JSON arguments.", True
        if call.name not in {s.name for s in allowed}:
            return f"ERROR: tool '{call.name}' is not available to agent '{agent}'.", True
        tool = (local or {}).get(call.name) or self.registry.tools[call.name]
        aid = agent_id or agent
        token = CURRENT_CALL.set(CallRef(aid, call.id, call_digest(call.name, call.arguments), resumed))
        try:
            return await self._execute(call, agent, aid, tool, rationale)
        finally:
            CURRENT_CALL.reset(token)

    async def _execute(self, call: ToolCall, agent: str, aid: str, tool: Tool, rationale: str) -> tuple[str, bool]:
        budget = self.budget_of()
        if budget and (why := budget.add_tool_call()):  # the run is over its budget: nothing more runs
            return (f"NOT EXECUTED - this run reached its budget ({why}). Stop here and report what you have."), True
        if tool.quarantined:  # before the ROE: a quarantined server's annotations and tools are not trusted at all
            self.audit.record("tool_quarantined_call", agent=agent, agent_id=aid, tool=call.name)
            return (f"NOT EXECUTED - {call.name} is from an MCP server in quarantine. It becomes usable only after "
                    "the analyst approves an onboarding proposal for it."), True
        decision = await self.roe.authorize(call.name, call.arguments, rationale, agent, tool.annotations, tool.server)
        self.on_event("decision", {"agent": agent, "agent_id": aid, "tool": call.name, "args": call.arguments,
                                   "tier": decision.tier, "allowed": decision.allowed, "reason": decision.reason})
        if not decision.allowed:
            if "analyst DENIED" in decision.reason:
                self.denials.append({"agent": agent, "tool": call.name, "args": call.arguments, "reason": decision.reason})
            return (f"NOT EXECUTED - {decision.reason}. Do not retry the same action; adjust your approach "
                    f"or ask the analyst."), True

        t0 = time.monotonic()
        is_error = False
        try:
            res = tool.handler(**call.arguments)
            if inspect.isawaitable(res):
                res = await res
            out = res if isinstance(res, str) else json.dumps(res, indent=1, default=str)
        except TypeError as e:
            out, is_error = f"ERROR: bad arguments for {call.name}: {e}", True
        except Exception as e:  # tool failures are returned to the model, not raised
            out, is_error = f"ERROR: {type(e).__name__}: {e}", True
        elapsed = round(time.monotonic() - t0, 2)

        digest = hashlib.sha256(out.encode("utf-8", "replace")).hexdigest()
        self.audit.record("tool_result", agent=agent, agent_id=aid, tool=call.name, sha256=digest, chars=len(out),
                          error=is_error, seconds=elapsed)
        self.on_event("result", {"agent": agent, "agent_id": aid, "tool": call.name, "chars": len(out), "error": is_error,
                                 "seconds": elapsed, "preview": out[:800]})
        return self._wrap(call.name, tool.server, out), is_error

    def _wrap(self, name: str, server: str, out: str) -> str:
        if len(out) > self.max_chars:
            self.spill_dir.mkdir(parents=True, exist_ok=True)
            spill = self.spill_dir / f"{name}_{uuid.uuid4().hex[:8]}.txt"
            spill.write_text(out, encoding="utf-8")
            head = out[: self.max_chars]
            out = (f"{head}\n...[TRUNCATED {len(out) - self.max_chars} chars; full output saved to {spill} - "
                   f"use local_read_file with offset to page through it, or narrow your query]")
        src = server or "local"
        return f'<tool_output tool="{name}" source="{src}" trust="untrusted-data">\n{out}\n</tool_output>'
