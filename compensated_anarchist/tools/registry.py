"""Unified tool registry + executor (local tools, MCP tools, agent tools).

Execution pipeline for every call, from every agent:
   allowlist check (expert's tool globs) -> ROE gate -> run -> truncate/spill -> audit
Tool output is wrapped as UNTRUSTED data: logs, alerts, files and packets are attacker-
influenced and may contain prompt-injection text. The data cannot end its own wrapper: every
`<tool_output` / `</tool_output` inside it is escaped, so the block ends only where the harness ends it.
"""

from __future__ import annotations

import contextvars
import fnmatch
import hashlib
import inspect
import json
import re
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Awaitable, Callable

from ..audit import AuditLog
from ..llm.base import ToolCall, ToolSpec
from ..redact import HARNESS_NOTE, Redactor
from ..roe import RoeGate

Handler = Callable[..., Awaitable[str] | str]

# The wrapper's tag inside the data (any case, any spacing: "</tool_output>", "< / TOOL_OUTPUT"), whose "<" is
# escaped so it can neither close the block early nor open a fake one that looks like the harness's.
_WRAPPER_TAG = re.compile(r"<(?=\s*/?\s*tool_output)", re.I)


def defang_wrapper(text: str) -> str:
    return _WRAPPER_TAG.sub("&lt;", text)


def _attr(value: str) -> str:
    """A tool or server name for the wrapper's attributes: a connector picks its own tool names."""
    return re.sub(r"[^A-Za-z0-9_.:-]", "_", value)


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
                 on_event: Callable[[str, dict[str, Any]], None] | None = None, redactor: Redactor | None = None):
        self.registry = registry
        # credentials in tool output are replaced before the model, the feed, spill files or the audit hash see it
        self.redactor = redactor or Redactor()
        self.roe = roe
        self.audit = audit
        self.budget_of: Callable[[], Any] = lambda: None  # the running operation's budget (set by the harness)
        self.spill_dir = spill_dir  # a folder directly in the case's artifacts folder (case_read_artifact: spill/<file>)
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
        names = {s.name for s in allowed}
        pager = next((p for p in PAGERS if p in names), "")  # how this agent can read a spilled result
        token = CURRENT_CALL.set(CallRef(aid, call.id, call_digest(call.name, call.arguments), resumed))
        try:
            return await self._execute(call, agent, aid, tool, rationale, pager)
        finally:
            CURRENT_CALL.reset(token)

    async def _execute(self, call: ToolCall, agent: str, aid: str, tool: Tool, rationale: str,
                       pager: str = "") -> tuple[str, bool]:
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
        out, redacted = self.redactor.redact(out)

        digest = hashlib.sha256(out.encode("utf-8", "replace")).hexdigest()
        self.audit.record("tool_result", agent=agent, agent_id=aid, tool=call.name, sha256=digest, chars=len(out),
                          error=is_error, seconds=elapsed, **({"credentials_redacted": redacted} if redacted else {}))
        self.on_event("result", {"agent": agent, "agent_id": aid, "tool": call.name, "chars": len(out), "error": is_error,
                                 "seconds": elapsed, "preview": out[:800]})
        wrapped = self._wrap(call.name, tool.server, out, pager)
        if redacted:  # the harness's own note, outside the untrusted data
            wrapped += "\n" + HARNESS_NOTE.format(n=redacted)
        return wrapped, is_error

    def _wrap(self, name: str, server: str, out: str, pager: str = "") -> str:
        if len(out) > self.max_chars:
            self.spill_dir.mkdir(parents=True, exist_ok=True)
            spill = self.spill_dir / f"{_attr(name)}_{uuid.uuid4().hex[:8]}.txt"
            spill.write_text(out, encoding="utf-8")
            head = out[: self.max_chars]
            nxt = len(head.encode("utf-8"))  # the byte offset the rest starts at
            where = f"{spill.parent.name}/{spill.name}"  # in the case's artifacts folder
            if pager == "case_read_artifact":
                how = (f'read on with case_read_artifact(path="{where}", offset={nxt}), search it with its find '
                       "argument, or narrow your query")
            elif pager == "local_read_file":
                how = f'page through it with local_read_file(path="{spill}", offset={nxt}), or narrow your query'
            else:
                how = "narrow your query to see the rest"
            out = (f"{head}\n...[TRUNCATED {len(out) - self.max_chars} chars; the full output is saved in the case "
                   f"artifacts as {where} - {how}]")
        return wrap_output(name, server, out)


# Tools that page a spilled result, best first: the case tool reads only the case's artifacts folder.
PAGERS = ("case_read_artifact", "local_read_file")


def wrap_output(name: str, server: str, out: str) -> str:
    """Tool output as the model sees it: untrusted data in a block it cannot end early."""
    src = _attr(server or "local")
    return (f'<tool_output tool="{_attr(name)}" source="{src}" trust="untrusted-data">\n{defang_wrapper(out)}\n'
            f'</tool_output>')
