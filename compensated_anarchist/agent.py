"""Agent loop, the orchestrator / subagent model, and the Harness that wires everything together.

Orchestrator - subagent relationship
  - The lead is the one orchestrator. It answers to the analyst, plans, and spawns expert subagents
    (subagent_spawn). Each subagent gets an id (SA-001...), a scoped brief and its own context window.
  - A subagent persists for the whole conversation: the orchestrator follows up with the same subagent
    (subagent_message) and it still has everything it learned. Subagent state survives restarts.
  - Subagents never spawn agents. They finish every task with a structured report (submit_report: status,
    bottom line, evidence, confidence, open questions, recommended tasks, skills used). Recommended tasks go UP
    to the orchestrator, which decides what runs next.
  - Independent subagents run in parallel, bounded by orchestration.max_parallel.

Chat history: every conversation (feed + orchestrator/subagent context) is persisted in the ChatStore and kept
until the analyst deletes it. Skills: see skills.py.
"""

from __future__ import annotations

import asyncio
import inspect
import json
import os
import re
import shutil
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from importlib import resources
from pathlib import Path
from typing import Any, Callable

import yaml

from .audit import AuditLog
from .case import Case
from .config import HarnessConfig
from .history import ChatStore
from .llm import LLMBackend, ToolSpec, make_backend
from .llm.base import LoopDetector, RepetitionLoop, ToolCall, estimate_tokens
from .mcp_manager import McpManager
from .memory import Memory
from .roe import RoeGate, cli_approver, deny_all_approver
from .skills import BUILTIN_DIR, LEAD, SkillStore, skill_tools
from . import attack, casefiles, cte, huntplans, reports, toolspecs, vault
from .tools import vulnscan
from .tools.forensics import Forensics
from .tools.registry import CURRENT_CALL, Tool, ToolExecutor, ToolRegistry, schema

EventFn = Callable[[str, dict[str, Any]], None]

# events that make up the conversation feed (persisted and replayed); everything else is UI-only
PERSIST_KINDS = {"analyst_message", "text", "subagent_spawn", "subagent_message", "subagent_report", "subagent_steer",
                 "decision", "result", "approval_request", "approval_resolved", "run_end", "compact", "skill_used",
                 "skill_proposed", "retro_start", "loop_guard", "plan_saved", "gate_on", "operation_resumed",
                 "subagent_resumed"}
RESUMABLE_KINDS = {"mission", "resume"}  # an after-action review cut off by a restart is ended, not resumed
REPORT_STATUSES = ["completed", "blocked", "needs_input", "failed"]
# The lead orchestrates, so it only holds overview tools; detailed connector, forensic and intel tools belong to
# the experts. This keeps the lead's prompt small (tool schemas are most of it), which matters on local models.
# Override with orchestration.lead_tools in harness.yaml (["*"] = every tool, the old behavior).
DEFAULT_LEAD_TOOLS = ["subagent_*", "case_*", "memory_*", "*__alerts_summary", "*__notable_events", "*__list_clients",
                      "local_case_evidence", "hunt_plan_list", "cte_plan_list", "report_list"]


def _prompt(name: str) -> str:
    return resources.files("compensated_anarchist").joinpath(f"prompts/{name}.md").read_text(encoding="utf-8")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Expert definitions (markdown + YAML frontmatter)
# ---------------------------------------------------------------------------
@dataclass
class ExpertDef:
    name: str
    title: str
    description: str
    prompt: str
    tools: list[str]
    deny_tools: list[str] = field(default_factory=list)
    model: str | None = None
    max_steps: int = 30
    skills: list[str] = field(default_factory=list)  # always on: loaded in full into every brief


def _parse_expert(text: str) -> ExpertDef:
    m = re.match(r"^---\n(.*?)\n---\n(.*)$", text, re.S)
    if not m:
        raise ValueError("expert file needs YAML frontmatter")
    meta = yaml.safe_load(m.group(1))
    return ExpertDef(prompt=m.group(2).strip(), **meta)


def load_experts(cfg: HarnessConfig) -> dict[str, ExpertDef]:
    experts: dict[str, ExpertDef] = {}
    for f in resources.files("compensated_anarchist").joinpath("experts").iterdir():
        if f.name.endswith(".md"):
            e = _parse_expert(f.read_text(encoding="utf-8"))
            experts[e.name] = e
    extra_dir = cfg.experts.get("extra_dir")
    if extra_dir:
        p = Path(extra_dir) if Path(extra_dir).is_absolute() else cfg.root / extra_dir
        for f in sorted(p.glob("*.md")):
            e = _parse_expert(f.read_text(encoding="utf-8"))
            experts[e.name] = e
    for name, over in (cfg.experts.get("overrides") or {}).items():  # per-expert model / step overrides
        if name in experts:
            for k, v in over.items():
                setattr(experts[name], k, v)
    for name in cfg.experts.get("disabled") or []:
        experts.pop(name, None)
    return experts


# ---------------------------------------------------------------------------
# Agent loop
# ---------------------------------------------------------------------------
DELTA_INTERVAL_S = 0.05  # streamed text is batched into one "delta" event per ~50 ms per agent
MAX_EMPTY_REPLIES = 2    # small local models sometimes stop with an empty reply; ask them to answer instead
MAX_LOOP_RETRIES = 2     # a reply stuck repeating itself is cut off and re-asked at most this many times per turn
LOOP_NUDGE = ("[Harness] Your last reply was cut off because it kept repeating the same text: {snippet}. "
              "Do not repeat yourself or list items over and over. Continue the task: answer briefly from the tool "
              "results above, or call the next tool. Subagents finish with submit_report.")
EMPTY_REPLY_NUDGE = ("[Harness] Your last reply was empty. Continue the task: if you have what you need, write your "
                     "answer now in plain text from the tool results above; if not, call the next tool. "
                     "Subagents finish with submit_report.")


def _accepts_on_delta(backend: Any) -> bool:
    try:
        return "on_delta" in inspect.signature(backend.chat).parameters
    except (TypeError, ValueError):
        return False


class _DeltaSink:
    """Collects streamed text and emits it as ephemeral "delta" events.

    Each event carries the text added since the last one and its offset in the reply being generated, so a client
    that reconnects can stitch the live text without gaps or duplicates. {"reset": True} discards the reply so far
    (the provider restarted the response, or the call failed).
    """

    def __init__(self, agent: "Agent"):
        self.agent = agent
        self.buf: list[str] = []
        self.offset = 0
        self.first: float | None = None
        self.handle: asyncio.TimerHandle | None = None
        self.loop = asyncio.get_running_loop()
        self.guard = LoopDetector()     # visible text
        self.r_guard = LoopDetector()   # hidden reasoning (servers that stream it separately)

    def _emit(self, **data: Any) -> None:
        self.agent.on_event("delta", {"agent": self.agent.name, "agent_id": self.agent.agent_id, **data})

    def __call__(self, chunk: str | None) -> None:
        if chunk is None:
            self.discard()
            return
        if self.first is None:
            self.first = time.monotonic()
        unit = self.guard.feed(chunk)
        if unit is not None:
            raise RepetitionLoop(unit, "text")
        self.buf.append(chunk)
        if self.handle is None:
            self.handle = self.loop.call_later(DELTA_INTERVAL_S, self.flush)

    def reasoning(self, chunk: str) -> None:
        """Hidden reasoning tokens: never displayed, only watched for loops."""
        if self.first is None:
            self.first = time.monotonic()
        unit = self.r_guard.feed(chunk)
        if unit is not None:
            raise RepetitionLoop(unit, "reasoning")

    def flush(self) -> None:
        if self.handle:
            self.handle.cancel()
            self.handle = None
        if self.buf:
            text = "".join(self.buf)
            self.buf.clear()
            self._emit(text=text, offset=self.offset)
            self.offset += len(text)

    def discard(self) -> None:
        if self.handle:
            self.handle.cancel()
            self.handle = None
        had = bool(self.offset or self.buf)  # evaluate before clearing: buf is the same list object
        self.buf.clear()
        self.offset = 0
        if had:
            self._emit(reset=True)


def _tool_call(tc: dict[str, Any]) -> ToolCall:
    """A tool call as the model made it, rebuilt from the saved assistant message."""
    fn = tc.get("function") or {}
    raw = fn.get("arguments")
    try:
        args = json.loads(raw) if isinstance(raw, str) else (raw or {})
    except json.JSONDecodeError as e:
        return ToolCall(str(tc.get("id", "")), str(fn.get("name", "")), {}, f"invalid JSON arguments: {e}")
    return ToolCall(str(tc.get("id", "")), str(fn.get("name", "")), args if isinstance(args, dict) else {})


TERMINAL_TOOLS = {"submit_report"}  # a call to one of these ends the agent's turn


class BudgetExceeded(Exception):
    """The operation reached a limit under budgets: in harness.yaml. It stops cleanly, like the analyst's Stop."""


class Budget:
    """One operation's limits (a mission, a review, a resume), counted over every agent together: tokens, tool calls
    and wall time. 0 means no limit. A warning at 80 %. Tokens count as they are billed: input and output in full,
    prompt tokens read from the provider's cache at cached_weight (default 0.1; Anthropic bills cache reads at about a
    tenth), so a long run on a cached hosted model is not stopped for tokens it barely paid for."""

    def __init__(self, limits: dict[str, Any], emit: EventFn):
        self.max_tokens = int(limits.get("max_tokens", 0) or 0)
        self.max_tool_calls = int(limits.get("max_tool_calls", 0) or 0)
        self.max_seconds = float(limits.get("max_minutes", 0) or 0) * 60
        self.cached_weight = float(limits.get("cached_weight", 0.1))
        self.tokens: float = 0
        self.tool_calls = 0
        self.t0 = time.monotonic()
        self.emit = emit
        self.warned: set[str] = set()
        self.reason = ""

    def used(self) -> dict[str, Any]:
        return {"tokens": int(self.tokens), "tool_calls": self.tool_calls, "minutes": round((time.monotonic() - self.t0) / 60, 1),
                "max_tokens": self.max_tokens, "max_tool_calls": self.max_tool_calls, "max_minutes": self.max_seconds / 60}

    def _over(self) -> str:
        secs = time.monotonic() - self.t0
        if self.max_tokens and self.tokens >= self.max_tokens:
            return f"{int(self.tokens):,} tokens used of its {self.max_tokens:,}"
        if self.max_tool_calls and self.tool_calls >= self.max_tool_calls:
            return f"{self.tool_calls} tool calls of its {self.max_tool_calls}"
        if self.max_seconds and secs >= self.max_seconds:
            return f"{secs / 60:.0f} minutes of its {self.max_seconds / 60:.0f}"
        return ""

    def _warn(self) -> None:
        for what, used, top in (("tokens", self.tokens, self.max_tokens), ("tool calls", self.tool_calls, self.max_tool_calls),
                                ("minutes", (time.monotonic() - self.t0) / 60, self.max_seconds / 60)):
            if top and used >= 0.8 * top and what not in self.warned:
                self.warned.add(what)
                self.emit("budget_warning", {"what": what, "used": round(used, 1), "limit": top})

    def check(self) -> None:
        """Before a model call: raises BudgetExceeded once any limit is reached."""
        if why := self._over():
            self.reason = why
            raise BudgetExceeded(why)
        self._warn()

    def add_tokens(self, usage: dict[str, int]) -> None:
        cached = int(usage.get("cached", 0) or 0)  # part of input: prompt tokens read from the provider's cache
        self.tokens += int(usage.get("input", 0) or 0) - cached + cached * self.cached_weight + int(usage.get("output", 0) or 0)
        self._warn()

    def add_tool_call(self) -> str:
        """Before a tool runs: the reason it may not, or ""."""
        if why := self._over():
            self.reason = why
            return why
        self.tool_calls += 1
        self._warn()
        return ""


class Agent:
    def __init__(self, name: str, system: str, backend: LLMBackend, executor: ToolExecutor, tools: list[ToolSpec],
                 max_steps: int, on_event: EventFn, agent_id: str = "",
                 on_save: Callable[["Agent", bool], None] | None = None, transcript_name: str = ""):
        self.name = name                      # expert name (ROE / allowlists / audit)
        self.agent_id = agent_id or name      # instance id: "lead" or SA-###
        self.backend = backend
        self.executor = executor
        self.tools = list(tools)
        self.local: dict[str, Tool] = {}      # tools bound to this agent (skills, submit_report)
        self.max_steps = max_steps
        self.on_event = on_event
        self.on_save = on_save
        self.transcript_name = transcript_name or f"{self.agent_id}.json"
        self.messages: list[dict[str, Any]] = [{"role": "system", "content": system}]
        self.usage = {"input": 0, "output": 0, "cached": 0}  # cached: prompt tokens read from the provider's cache
        self.budget_of: Callable[[], Budget | None] = lambda: None  # the running operation's budget (set by the harness)
        self.terminal: dict[str, Any] | None = None  # set by a terminal tool (submit_report) to end the turn
        self.inbox: list[str] = []  # analyst guidance ("steer"), delivered before the next model call
        # results of the current step's tool calls that have finished (call id -> [content, is_error]); saved with
        # each checkpoint, so a resumed operation never runs a finished call twice
        self.partial: dict[str, list[Any]] = {}

    def add_local(self, tools: list[Tool]) -> None:
        for t in tools:
            self.local[t.name] = t
            self.tools.append(t.spec)

    # ---- turns: start, resume, run ----------------------------------------------------------
    # The context is checkpointed after every change (the new message, each reply, each finished tool call), so an
    # operation cut off by a restart or a crash can carry on from where it stopped (resume).
    def add_user(self, text: str) -> None:
        """Start a turn: close any tool calls an interrupted earlier turn left open, add the message, checkpoint."""
        self._close_open_calls("NOT EXECUTED - the operation was interrupted before this ran")
        self.messages.append({"role": "user", "content": text})
        self.terminal = None
        self.checkpoint()

    async def turn(self, user_text: str) -> str:
        self.add_user(user_text)
        return await self.resume()

    def open_calls(self) -> list[ToolCall]:
        """Tool calls in the last reply that have no result yet (the step was interrupted)."""
        i = len(self.messages) - 1
        while i > 0 and self.messages[i]["role"] == "tool":
            i -= 1
        m = self.messages[i]
        if i == 0 or m["role"] != "assistant" or not m.get("tool_calls"):
            return []
        answered = {x.get("tool_call_id") for x in self.messages[i + 1:]}
        return [_tool_call(tc) for tc in m["tool_calls"] if tc.get("id") not in answered]

    def _ended_by_terminal(self) -> bool:
        """The last step ended the turn with a terminal tool (submit_report), and it has its result."""
        i = len(self.messages) - 1
        if self.messages[i]["role"] != "tool":
            return False
        while i > 0 and self.messages[i]["role"] == "tool":
            i -= 1
        m = self.messages[i]
        return m["role"] == "assistant" and any((tc.get("function") or {}).get("name") in TERMINAL_TOOLS
                                                for tc in m.get("tool_calls") or [])

    def unfinished(self) -> bool:
        """True when the last turn stopped part-way (a restart or a crash): resume() carries it on."""
        if len(self.messages) <= 1:
            return False
        last = self.messages[-1]
        if last["role"] == "user":
            return True
        if last["role"] == "assistant":
            return bool(last.get("tool_calls"))
        return not self._ended_by_terminal()

    async def resume(self) -> str:
        """Carry on with the current turn from where it stopped: run the tool calls that have no result yet (each is
        decided by the ROE again), then continue. A turn that already finished returns its answer."""
        calls = self.open_calls()
        if not calls and self._ended_by_terminal() and self.terminal is not None:
            return self.terminal.get("summary", "") or "(no final answer)"
        if not calls and self.messages[-1]["role"] == "assistant":
            return str(self.messages[-1].get("content") or "") or "(no final answer)"
        self.terminal = None
        if calls:
            reply = next(m for m in reversed(self.messages) if m["role"] == "assistant")
            await self._run_calls(calls, str(reply.get("content") or ""), resumed=True)
            if self.terminal is not None:
                self.save()
                return self.terminal.get("summary", "") or "(no final answer)"
        return await self._loop()

    async def _run_calls(self, calls: list[ToolCall], rationale: str, resumed: bool = False) -> None:
        """Run one step's tool calls in parallel and add their results. Each result is checkpointed as it arrives."""
        async def one(c: ToolCall) -> tuple[str, bool]:
            done = self.partial.get(c.id)
            if done is not None:  # finished before an interruption
                return str(done[0]), bool(done[1])
            content, is_err = await self.executor.execute(c, self.name, rationale, self.tools, self.local,
                                                          self.agent_id, resumed)
            self.partial[c.id] = [content, is_err]
            self.checkpoint()
            return content, is_err

        results = await asyncio.gather(*[one(c) for c in calls])
        for call, (content, is_err) in zip(calls, results):
            self.messages.append({"role": "tool", "tool_call_id": call.id, "name": call.name,
                                  "content": content, "_is_error": is_err})
        self.partial = {}
        self.checkpoint()

    async def _loop(self) -> str:
        final = ""
        empty = loops = 0
        for _ in range(self.max_steps):
            if self.inbox:
                notes, self.inbox = self.inbox, []
                self.messages.append({"role": "user", "content": "[Guidance from the analyst - adjust your work accordingly]\n"
                                      + "\n".join(f"- {n}" for n in notes)})
            await self._maybe_compact()
            try:
                resp = await self._step(self.tools)
            except RepetitionLoop as e:
                loops += 1
                if self._loop_guard(e, loops):
                    final = self.LOOP_GIVE_UP
                    break
                continue
            if not resp.tool_calls:
                if not resp.text.strip() and empty < MAX_EMPTY_REPLIES:
                    empty += 1
                    self.messages.pop()  # an empty assistant turn is noise (and some servers reject it on replay)
                    self.messages.append({"role": "user", "content": EMPTY_REPLY_NUDGE})
                    continue
                final = resp.text
                break
            await self._run_calls(resp.tool_calls, resp.text)
            if self.terminal is not None:
                final = self.terminal.get("summary", "")
                break
        else:
            self.messages.append({"role": "user", "content": (
                "Step budget exhausted. Do not call tools. Give your final report now: what you did, what you "
                "found (with evidence), what remains open, and recommended next steps.")})
            try:
                final = (await self._step([])).text
            except RepetitionLoop as e:
                self._loop_guard(e, MAX_LOOP_RETRIES + 1)
                final = self.LOOP_GIVE_UP
        self.save()
        return final or "(no final answer)"

    LOOP_GIVE_UP = ("(stopped: the model kept repeating itself and was cut off each time. Try a larger model "
                    "for this agent, or narrow the task.)")

    def _loop_guard(self, e: RepetitionLoop, attempt: int) -> bool:
        """Record a cut-off loop and queue a nudge. Returns True when it is time to give up."""
        give_up = attempt > MAX_LOOP_RETRIES
        snippet = " ".join(e.unit.split())[:80] or repr(e.unit[:20])
        self.on_event("loop_guard", {"agent": self.name, "agent_id": self.agent_id, "unit": snippet, "where": e.where,
                                     "attempt": attempt, "gave_up": give_up})
        if not give_up:
            self.messages.append({"role": "user", "content": LOOP_NUDGE.format(snippet=f'"{snippet}"')})
        return give_up

    async def _step(self, tools: list[ToolSpec]) -> Any:
        """One model call: stream its text, record usage, append the reply, then emit text and telemetry.

        The text event comes before telemetry so a client can swap the streamed draft for the final text in one go.
        """
        budget = self.budget_of()
        if budget:
            budget.check()  # a run over its budget stops here, before another model call
        sink = _DeltaSink(self) if _accepts_on_delta(self.backend) else None  # the backend can be switched mid-session
        t0 = time.monotonic()
        try:
            if sink:
                resp = await self.backend.chat(self.messages, tools, on_delta=sink)
                sink.flush()
            else:
                resp = await self.backend.chat(self.messages, tools)
        except BaseException:
            if sink:
                sink.discard()  # the partial reply will never complete
            raise
        t1 = time.monotonic()
        for k in self.usage:
            self.usage[k] += resp.usage.get(k, 0)
        if budget:
            budget.add_tokens(resp.usage)
        unit = LoopDetector().check(resp.text or "")  # non-streamed replies (or a loop that began near the end)
        if unit is not None:
            if sink:
                sink.discard()
            raise RepetitionLoop(unit, "text")
        self.messages.append(resp.assistant_message)
        self.checkpoint()
        if resp.text.strip():
            self.on_event("text", {"agent": self.name, "agent_id": self.agent_id, "text": resp.text.strip(),
                                   "final": not resp.tool_calls})
        out_tokens = resp.usage.get("output", 0)
        first = sink.first if sink else None
        gen = t1 - first if first and t1 - first > 0.2 else t1 - t0  # generation speed, excluding time to first token
        self.on_event("telemetry", {
            "agent_id": self.agent_id, "seconds": round(t1 - t0, 2),
            "ttft": round(first - t0, 2) if first else None,
            "tok_s": round(out_tokens / gen, 1) if out_tokens and gen > 0.05 else None,
            "context_pct": round(100 * estimate_tokens(self.messages) / max(1, self.backend.context_tokens)),
            "input": self.usage["input"], "output": self.usage["output"]})
        return resp

    def _close_open_calls(self, reason: str) -> bool:
        """Give every open tool call a result, so the history stays valid: the real one when the call finished before
        the interruption, else `reason`."""
        calls = self.open_calls()
        for c in calls:
            done = self.partial.get(c.id)
            content, err = (str(done[0]), bool(done[1])) if done is not None else (reason, True)
            self.messages.append({"role": "tool", "tool_call_id": c.id, "name": c.name, "content": content, "_is_error": err})
        self.partial = {}
        return bool(calls)

    def repair(self, reason: str = "cancelled by analyst") -> None:
        """After an interrupted turn, close any tool calls left without results so the history stays valid."""
        self._close_open_calls(f"NOT EXECUTED - {reason}")
        self.save()

    async def _maybe_compact(self) -> None:
        budget = self.backend.context_tokens
        if estimate_tokens(self.messages) < 0.75 * budget:
            return
        # keep a tail that fits in ~40% of the budget, starting at a user/assistant boundary
        cut = None
        for i in range(2, len(self.messages)):
            if self.messages[i]["role"] in ("user", "assistant") and estimate_tokens(self.messages[i:]) <= 0.4 * budget:
                cut = i
                break
        if cut is None:
            cut = max(2, len(self.messages) - 4)
            while cut < len(self.messages) - 1 and self.messages[cut]["role"] == "tool":
                cut += 1
        old = self.messages[1:cut]
        rendered = "\n".join(f"{m['role']}: {str(m.get('content') or '')[:1500]}"
                             + (f" [tool_calls: {[t['function']['name'] for t in m.get('tool_calls', [])]}]" if m.get("tool_calls") else "")
                             for m in old)
        req = [{"role": "system", "content": "You compress DCO agent working memory. Preserve: the original tasking verbatim, "
                                             "hypotheses, every IOC/host/user/timestamp found, queries that worked or failed, "
                                             "actions taken and their ROE outcome, open leads. Be dense; no prose filler."},
               {"role": "user", "content": rendered[-400000:]}]
        summary = (await self.backend.chat(req, [])).text
        tail = self.messages[cut:]
        for m in tail:  # replayed provider-private blocks (e.g. thinking) are bound to the old prefix
            m.pop("_anthropic", None)
        self.messages = [self.messages[0], {"role": "user", "content": f"[Compacted history of this operation]\n{summary}"}] + tail
        self.on_event("compact", {"agent": self.name, "agent_id": self.agent_id, "dropped": len(old)})

    def export_state(self) -> dict[str, Any]:
        return {"name": self.name, "agent_id": self.agent_id, "model": self.backend.profile_name, "usage": self.usage,
                "messages": self.messages[1:], "partial": self.partial, "terminal": self.terminal}

    def restore(self, state: dict[str, Any]) -> None:
        """Resume from a saved state under a fresh system prompt (session details change between runs)."""
        msgs = state.get("messages") or []
        for m in msgs:  # provider-private blocks are bound to the old prompt prefix
            m.pop("_anthropic", None)
        self.messages = [self.messages[0], *msgs]
        self.usage = {**self.usage, **(state.get("usage") or {})}
        self.partial = {str(k): list(v) for k, v in (state.get("partial") or {}).items()}
        self.terminal = state.get("terminal")

    def checkpoint(self) -> None:
        """Save the context mid-turn (no transcript file), so an interrupted operation can resume from here."""
        if self.on_save:
            self.on_save(self, False)

    def save(self) -> None:
        if self.on_save:
            self.on_save(self, True)


# ---------------------------------------------------------------------------
# Subagents
# ---------------------------------------------------------------------------
SUB_META = ("id", "expert", "title", "task", "context", "expected", "status", "turns", "created", "updated", "last_report",
            "started", "call", "answered")


@dataclass
class SubAgent:
    id: str
    expert: str
    title: str
    task: str
    context: str = ""
    expected: str = ""
    status: str = "idle"  # queued | running | completed | blocked | needs_input | failed | stopped | interrupted
    turns: int = 0
    created: str = ""
    updated: str = ""
    last_report: dict[str, Any] | None = None
    started: float = 0.0  # epoch seconds of the current / last run
    agent: Agent | None = None
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    job: asyncio.Task | None = None  # the running agent turn, so the analyst can stop this subagent alone
    stop_requested: bool = False
    call: str = ""      # the orchestrator's tool call that gave it its current task (CallRef.key)
    answered: str = ""  # the call its last report answered

    def meta(self) -> dict[str, Any]:
        return {k: getattr(self, k) for k in SUB_META}


# ---------------------------------------------------------------------------
# Harness: case + memory + skills + history + ROE + tools + MCP + orchestrator + subagents
# ---------------------------------------------------------------------------
class Harness:
    def __init__(self, cfg: HarnessConfig, case_id: str, model: str | None = None, posture: str | None = None,
                 interactive: bool = True, on_event: EventFn | None = None):
        self.cfg = cfg
        self.model_name = model or cfg.default_model
        self.on_event = on_event or (lambda k, d: None)
        self.session = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        self.case = Case(cfg.cases_dir, case_id)
        self.audit = AuditLog(self.case.dir / "audit.jsonl", cfg.operator)
        self.memory = Memory(cfg.memory_db, cfg.memory, self.audit)
        self.memory.case_id = case_id
        self.budget: Budget | None = None  # the running operation's limits (budgets: in harness.yaml)
        self.retro_ran_auto = False  # the CLI's --retro is not run twice
        self.memory.conversation_of = lambda: self.conversation["id"] if self.conversation else ""
        self.skills = SkillStore(cfg.memory_db, cfg.skills, self.audit)
        self.skills.import_dir(BUILTIN_DIR, "built-in", only_new=True)  # shipped skills, e.g. ponytail for code_writer
        self.history = ChatStore(cfg.history_db)
        self.conversation: dict[str, Any] | None = None
        self.roe = RoeGate(cfg.roe_path, self.audit, cli_approver if interactive else deny_all_approver, posture)
        self.registry = ToolRegistry()
        self.executor = ToolExecutor(self.registry, self.roe, self.audit, self.case.artifacts / "spill",
                                     cfg.max_tool_result_chars, self.emit)
        self.executor.budget_of = lambda: self.budget
        self.vault_dir = vault.ensure(Path(cfg.forensics.get("vault_dir") or cfg.evidence_roots[0] / "vault"))
        self.case_evidence_dir = casefiles.ensure_case_folder(cfg.forensics_dir, case_id)  # analyst drop folder
        self.hunt_plans_dir = huntplans.ensure(self.case.dir / "hunt_plans")  # hunt_planner writes, threat_hunter reads
        self.vuln_dir = huntplans.ensure(self.case.dir / "vuln_assessment")  # vuln_assessor's reports and raw scans
        self.cte_dir = huntplans.ensure(self.case.dir / "cte_plans")  # cte_planner's plans; network maps go in maps/
        huntplans.ensure(self.cte_dir / "maps")
        self.reports_dir = huntplans.ensure(self.case.dir / "reports")  # reporter's versioned drafts and finals
        rcfg = cfg.raw.get("reports") or {}
        ex = Path(str(rcfg["examples_dir"])) if rcfg.get("examples_dir") else cfg.cases_dir.parent / "reports" / "examples"
        self.report_examples_dir = ex if ex.is_absolute() else (cfg.root / ex).resolve()  # the analyst's old reports
        self.gate_reason = ""  # set when this conversation is under the gate-everything floor (every action approved)
        for spec in cfg.mcp_servers.values():  # Velociraptor evidence lands in the vault, inside the forensic jail
            if str(spec.get("module", "")).endswith(".velociraptor"):
                env = spec.setdefault("env", {})
                # files pulled from endpoints always land in the vault (read-only, never executable)
                want = Path(env.get("VELO_DOWNLOAD_DIR") or self.vault_dir / "velociraptor").resolve()
                if not want.is_relative_to(self.vault_dir.resolve()):
                    want = (self.vault_dir / "velociraptor").resolve()
                env["VELO_DOWNLOAD_DIR"] = str(want)
        self.mcp = McpManager(cfg.mcp_servers, self.case.dir / "logs")
        self.experts = load_experts(cfg)
        self.backends: dict[str, LLMBackend] = {}
        self.retired_backends: list[LLMBackend] = []  # replaced after a profile edit; closed with the harness
        self.lead: Agent | None = None
        self.subagents: dict[str, SubAgent] = {}
        self._sub_states: dict[str, dict[str, Any]] = {}
        self.max_parallel = max(1, int(cfg.orchestration.get("max_parallel", 4)))
        self._sem: asyncio.Semaphore | None = None
        self._alias_cache: dict[str, tuple[float, list[str]]] = {}
        self.roe.target_resolver = self._resolve_target
        self.roe.gate_hook = self._gate_hook
        self._agent_seq = 0
        self.op: dict[str, Any] | None = None  # the operation running now (history.operations row)

    # ---- events / conversation -------------------------------------------------------
    def emit(self, kind: str, data: dict[str, Any]) -> None:
        """Every harness event goes through here: feed events are persisted to the conversation first."""
        if kind in PERSIST_KINDS:
            self.history.append(self._conv()["id"], self.session, kind, data, time.time())
        self.on_event(kind, data)

    # ---- gate everything (vulnerability assessment) ------------------------------------------
    def _gate_hook(self, agent: str, tool: str, arguments: dict[str, Any]) -> str:
        """Why this call needs an analyst's approval under the gate-everything floor ('' = it does not)."""
        gated = self.roe.gate_all_experts
        if agent in gated:
            return f"the {agent} needs analyst approval for every action"
        if self.gate_reason:
            return self.gate_reason
        if tool == "subagent_spawn" and str(arguments.get("expert", "")) in gated:
            return f"starting the {arguments.get('expert')} needs analyst approval"
        if tool == "subagent_message":
            sa = self.subagents.get(str(arguments.get("subagent_id", "")).strip().upper())
            if sa and sa.expert in gated:
                return f"tasking the {sa.expert} needs analyst approval"
        return ""

    def gate_conversation(self, why: str) -> None:
        """From now on every action in this conversation, by any agent, needs the analyst's approval. Sticky: it
        is recorded in the conversation and restored when it is reopened. A new conversation starts ungated."""
        if self.gate_reason:
            return
        self.gate_reason = f"{why}: every action in this conversation needs analyst approval"
        self.audit.record("gate_everything_on", conversation=self._conv()["id"], reason=self.gate_reason)
        self.emit("gate_on", {"reason": self.gate_reason})

    @property
    def plan_dirs(self) -> list[Path]:
        """Folders whose files the dashboard lists under Plans & reports (and can open)."""
        return [self.hunt_plans_dir, self.vuln_dir, self.cte_dir, self.reports_dir]

    def _plan_saved(self, path: Path, kind: str) -> None:
        """A plan, results, report draft or Navigator layer was saved: the dashboard shows it with links to open it."""
        self.emit("plan_saved", {"name": path.name, "kind": kind, "path": str(path),
                                 "title": huntplans.title(path) if path.suffix == ".md" else ""})

    def _conv(self) -> dict[str, Any]:
        if self.conversation is None:  # created on first use, so `doctor` etc. leave no empty conversations
            self.conversation = self.history.create(self.case.id)
            self.audit.record("conversation_start", conversation=self.conversation["id"])
        return self.conversation

    def _skill_ctx(self) -> dict[str, str]:
        return {"conversation_id": self._conv()["id"], "case_id": self.case.id}

    def open_conversation(self, conv_id: str) -> dict[str, Any]:
        c = self.history.get(conv_id)
        if not c or c["case_id"] != self.case.id:
            raise ValueError(f"no conversation {conv_id} in case {self.case.id}")
        self.conversation = c
        gate = self.history.first_event(conv_id, "gate_on")
        self.gate_reason = str(gate["data"].get("reason", "")) if gate else ""
        self.lead = self._new_lead()
        self.subagents, self._sub_states = {}, {}
        states = self.history.load_agents(conv_id)
        if "lead" in states:
            self.lead.restore(states["lead"])
        for key, st in sorted(states.items()):
            meta = st.get("meta") or {}
            if key == "lead" or not meta.get("id"):
                continue
            sa = SubAgent(**{k: meta[k] for k in SUB_META if k in meta})
            if sa.status in ("running", "queued"):
                sa.status = "interrupted"
            self.subagents[sa.id] = sa
            self._sub_states[sa.id] = st  # the agent itself is rebuilt on first follow-up
        self.audit.record("conversation_open", conversation=conv_id, subagents=len(self.subagents))
        return c

    def new_conversation(self) -> None:
        if self.lead:
            self.lead.save()
        self.conversation = None
        self.gate_reason = ""
        self.lead = self._new_lead()
        self.subagents, self._sub_states = {}, {}

    def delete_conversation(self, conv_id: str) -> bool:
        c = self.history.get(conv_id)
        if not c or c["case_id"] != self.case.id:
            return False
        if self.conversation and self.conversation["id"] == conv_id:
            self.conversation = None
            self.gate_reason = ""
            self.lead = self._new_lead()
            self.subagents, self._sub_states = {}, {}
        _purge(self.history, self.case.dir, c, self.audit)
        return True

    # ---- setup ----------------------------------------------------------------------------
    def backend(self, name: str | None) -> LLMBackend:
        key = name or self.model_name
        prof = self.cfg.model(key)
        if key not in self.backends or getattr(self.backends[key], "profile", prof) is not prof:
            if key in self.backends:  # its profile was edited (models.yaml or config/.env): rebuild it
                self.retired_backends.append(self.backends[key])
            self.backends[key] = make_backend(prof)
        return self.backends[key]

    async def start(self, conversation_id: str | None = None, new: bool = False) -> None:
        for t in self.case.tools():
            self.registry.add(t)
        for t in self.memory.tools():
            self.registry.add(t)
        for t in Forensics(self.cfg.forensics, self.cfg.evidence_roots, self.case,
                           case_folder=self.case_evidence_dir, vault_dir=self.vault_dir).tools():
            self.registry.add(t)
        await self.mcp.start(self.registry)
        self.onboarding = toolspecs.Onboarding(self)
        for t in self.onboarding.tools():
            self.registry.add(t)
        self.attack = attack.AttackKB(self.cfg.attack_paths)  # loaded on first use
        for t in attack.tools(self.attack, lambda: self.hunt_plans_dir,
                              lambda: [k for k, v in self.mcp.status.items() if str(v).startswith("connected")],
                              on_saved=self._plan_saved):
            self.registry.add(t)
        for t in huntplans.tools(lambda: self.hunt_plans_dir, on_saved=self._plan_saved):
            self.registry.add(t)
        for t in cte.tools(self.attack, lambda: self.cte_dir, lambda: [self.cte_dir / "maps", self.case_evidence_dir],
                           self.cfg.raw.get("cte") or {}, on_saved=self._plan_saved):
            self.registry.add(t)
        try:
            reports.ensure_examples(self.report_examples_dir)
        except OSError:
            pass  # read-only location: the library is simply empty
        for t in reports.tools(self.mission_data, lambda: self.reports_dir, lambda: self.report_examples_dir,
                               self._report_template, on_saved=self._plan_saved):
            self.registry.add(t)
        self.registry.add(self._statement_tool())
        vt = vulnscan.VulnTools(self.cfg.raw.get("vuln_assessment") or {}, self.vuln_dir,
                                scope=lambda: (self.roe.allowed_targets, self.roe.protected_assets), on_saved=self._plan_saved)
        for t in vt.tools():
            self.registry.add(t)
        self._register_orchestration()
        self.onboarding.activate_all()  # approved tools and MCP servers, after every other tool is registered
        self.audit.record("session_start", session=self.session, model=self.model_name, posture=self.roe.posture,
                          mcp=self.mcp.status, experts=list(self.experts))
        self.lead = self._new_lead()
        if conversation_id:
            self.open_conversation(conversation_id)
        elif not new and (latest := self.history.latest(self.case.id)):
            self.open_conversation(latest["id"])

    def mission_data(self) -> reports.MissionData:
        """Everything a report may cite: the case record, conversation events and the case's files."""
        return reports.MissionData(self.case, self.history, {
            "hunt plans": self.hunt_plans_dir, "vulnerability assessment": self.vuln_dir, "CTE plans": self.cte_dir,
            "authored artifacts": self.case.artifacts / "authored"})

    def _report_template(self, report_type: str) -> str:
        """The approved template skill for a report type ('' if there is none)."""
        if not report_type:
            return ""
        s = self.skills.get(f"report-template-{re.sub(r'[^a-z0-9]+', '-', report_type.lower()).strip('-')}")
        return s["body"] if s and s["status"] == "active" else ""

    def _statement_tool(self) -> Tool:
        """Record the analyst's answer to an agent's question as a citable statement. The answer must be quoted from
        one of the analyst's own messages in this case, so an agent cannot put words in the analyst's mouth."""
        def case_analyst_statement(question: str, answer: str, topic: str = "") -> str:
            want = " ".join(answer.split()).lower()
            if len(want) < 1:
                raise ValueError("empty answer")
            for conv in self.history.list(self.case.id, 1000):
                for e in reversed(self.history.events(conv["id"])):
                    if e["kind"] == "analyst_message" and want in " ".join(str(e["data"].get("text", "")).split()).lower():
                        when = datetime.fromtimestamp(e["ts"], timezone.utc).isoformat()
                        sid = self.case.add_statement(question.strip(), answer.strip(), self.cfg.operator, when,
                                                      f"EV-{e['id']}", topic.strip())
                        self.audit.record("analyst_statement", id=sid, question=question[:300], answer=answer[:300],
                                          analyst_message=f"EV-{e['id']}")
                        return f"recorded {sid}: the analyst's answer from EV-{e['id']} ({when[:16]}). Cite it as [{sid}]."
            return ("NOT RECORDED: that answer is not in any of the analyst's messages in this case. Quote the analyst's "
                    "own words exactly; if they have not answered yet, ask them.")
        S = {"type": "string"}
        return Tool("case_analyst_statement", "Record an analyst's answer to a question (classification markings, a missing "
                    "fact, a decision) as a citable statement STA-nnnn. The answer must be quoted exactly from the analyst's "
                    "own message in this case.", schema({"question": S, "answer": S, "topic": S}, ["question", "answer"]),
                    case_analyst_statement)

    def _register_orchestration(self) -> None:
        S = {"type": "string"}
        roster = "; ".join(f"{n}: {e.description}" for n, e in self.experts.items())
        self.registry.add(Tool(
            "subagent_spawn",
            "Spawn an expert subagent for a scoped task; returns its structured report. The subagent keeps its "
            "context for this whole conversation - follow up with subagent_message instead of spawning a duplicate. "
            "Call several in one turn to run independent tasks in parallel. Experts: " + roster,
            schema({"expert": {"type": "string", "enum": list(self.experts)},
                    "task": {"type": "string", "description": "Specific objective, scope (hosts, subnets, indices), time window."},
                    "context": {"type": "string", "description": "Facts, IOCs, hosts, users and findings already known."},
                    "expected_output": {"type": "string", "description": "What the report must contain for you to decide the next step."}},
                   ["expert", "task"]),
            self._spawn))
        self.registry.add(Tool(
            "subagent_message",
            "Send a follow-up question, a correction or a related new task to a subagent you spawned earlier in this "
            "conversation. It remembers its earlier work and answers with a new report.",
            schema({"subagent_id": {"type": "string", "description": "e.g. SA-003"}, "message": S}, ["subagent_id", "message"]),
            self._message))
        self.registry.add(Tool("subagent_list", "List your subagents in this conversation: id, expert, task, status, last bottom line.",
                               schema({}), self._list_subagents))

    async def _resolve_target(self, tool: str, value: str) -> list[str]:
        """Resolve a Velociraptor client id to hostname / fqdn / last IP for ROE scope checks (cached 10 min).
        Returns [] when it cannot be resolved -> the gate fails closed for scoped actions."""
        if not re.fullmatch(r"C\.[0-9a-f]{16}", value):
            return []
        hit = self._alias_cache.get(value)
        if hit and time.monotonic() - hit[0] < 600:
            return hit[1]
        aliases: list[str] = []
        for name in ("velociraptor__client_info", "velociraptor_admin__client_info"):
            t = self.registry.tools.get(name)
            if not t:
                continue
            try:
                rows = json.loads(await t.handler(client_id=value))
                info = rows[0] if isinstance(rows, list) and rows else {}
                os_info = info.get("os_info") or {}
                ip = str(info.get("last_ip") or "")
                ip = ip.rsplit(":", 1)[0].strip("[]") if ip.count(":") == 1 or ip.startswith("[") else ip
                aliases = [x for x in (os_info.get("hostname"), os_info.get("fqdn"), ip) if x]
            except (json.JSONDecodeError, TypeError, AttributeError, IndexError):
                aliases = []
            if aliases:
                break
        self._alias_cache[value] = (time.monotonic(), aliases)
        return aliases

    def _system(self, role_prompt: str) -> str:
        env = (f"\n\n# Session\nCase: {self.case.id} | Posture: {self.roe.posture.upper()} | Operator: {self.cfg.operator} | "
               f"UTC now: {datetime.now(timezone.utc).isoformat()[:19]}\nConnectors: "
               + ", ".join(f"{k}={v}" for k, v in self.mcp.status.items())
               + f"\nCase evidence folder (the analyst drops artifacts here): {self.case_evidence_dir}"
               + f"\nFiles pulled from endpoints (evidence vault): {self.vault_dir / 'velociraptor'}"
               + f"\nHunt plans folder (hunt_planner saves plans, threat_hunter reads them): {self.hunt_plans_dir}"
               + f"\nCTE plans folder (cte_planner; network maps in maps/): {self.cte_dir}"
               + f"\nReports folder (reporter drafts): {self.reports_dir} | example reports: {self.report_examples_dir}"
               + f"\nEvidence roots: {[str(p) for p in self.cfg.evidence_roots]}")
        return _prompt("core") + "\n\n" + role_prompt + env

    def _make_agent(self, name: str, agent_id: str, role_prompt: str, model: str | None, allow: list[str],
                    deny: list[str], max_steps: int) -> Agent:
        self._agent_seq += 1
        agent = Agent(name, self._system(role_prompt), self.backend(model), self.executor, self.registry.specs(allow, deny),
                      max_steps, self.emit, agent_id=agent_id, on_save=self._on_save,
                      transcript_name=f"{self.session}__{agent_id}__{self._agent_seq:03d}.json")
        agent.budget_of = lambda: self.budget
        return agent

    def _new_lead(self) -> Agent:
        allow = list(self.cfg.orchestration.get("lead_tools") or DEFAULT_LEAD_TOOLS)
        lead = self._make_agent("lead", "lead", _prompt("lead"), None, allow, [], self.cfg.max_steps)
        lead.add_local(skill_tools(self.skills, LEAD, "lead", self._skill_ctx, list(self.experts), self.emit))
        lead.add_local([Tool(
            "learning_recommend",
            "At the end of an after-action review: say which of this conversation's unreviewed memories and skill "
            "versions you recommend the analyst approve for every case (checked against the evidence), and which to "
            "reject (wrong or superseded), each with a short reason. The analyst can then approve your recommendations "
            "in one step on the Learning page.",
            schema({"approve_memories": {"type": "array", "items": {"type": "integer"}},
                    "approve_skill_versions": {"type": "array", "items": {"type": "integer"}},
                    "reject_memories": {"type": "array", "items": {"type": "integer"}},
                    "reasons": {"type": "string"}}),
            self._learning_recommend)])
        return lead

    def _learning_recommend(self, approve_memories: list[int] | None = None, approve_skill_versions: list[int] | None = None,
                            reject_memories: list[int] | None = None, reasons: str = "") -> str:
        """Record the review's recommendations; only items written in this conversation and still unreviewed count."""
        conv = self._conv()["id"]
        mems = {m["id"] for m in self.memory.pending(conversation_id=conv)}
        vers = {v["id"] for v in self.skills.pending() if v.get("conversation_id") == conv}
        rec = {"approve_memories": sorted({int(i) for i in approve_memories or []} & mems),
               "approve_skill_versions": sorted({int(i) for i in approve_skill_versions or []} & vers),
               "reject_memories": sorted({int(i) for i in reject_memories or []} & mems), "reasons": reasons[:3000]}
        ignored = sorted(({int(i) for i in approve_memories or []} | {int(i) for i in reject_memories or []}) - mems) + \
            sorted({int(i) for i in approve_skill_versions or []} - vers)
        self.history.append(conv, self.session, "learning_recommendation", rec, time.time())
        self.audit.record("learning_recommendation", conversation=conv, **{k: v for k, v in rec.items() if k != "reasons"})
        self.emit("learning_recommendation", rec)
        return (f"Recorded: approve {len(rec['approve_memories'])} memories and {len(rec['approve_skill_versions'])} skill "
                f"versions, reject {len(rec['reject_memories'])} memories."
                + (f" Ignored (not unreviewed items of this conversation): {ignored}" if ignored else ""))

    def learning_recommendation(self) -> dict[str, Any] | None:
        """The latest review recommendation in this conversation, reduced to items still waiting for review."""
        if not self.conversation:
            return None
        recs = [e for e in self.history.events(self.conversation["id"]) if e["kind"] == "learning_recommendation"]
        if not recs:
            return None
        rec = recs[-1]["data"]
        mems = {m["id"] for m in self.memory.pending(conversation_id=self.conversation["id"])}
        vers = {v["id"] for v in self.skills.pending()}
        return {"approve_memories": [i for i in rec.get("approve_memories", []) if i in mems],
                "approve_skill_versions": [i for i in rec.get("approve_skill_versions", []) if i in vers],
                "reject_memories": [i for i in rec.get("reject_memories", []) if i in mems], "reasons": rec.get("reasons", "")}

    def what_we_learned(self, conv_id: str) -> str:
        """The review's closing section, from the records rather than the model's memory of them."""
        mems = [m for m in self.memory.list(limit=1000) if m.get("conversation_id") == conv_id]
        vers = self.skills.versions_in(conv_id)
        lines = ["## What we learned in this mission (from the records)"]
        if mems:
            lines.append("Memories:")
            lines += [f"- M{m['id']} ({m['kind']}, {m['status']}): {m['title']}" for m in mems]
        if vers:
            lines.append("Skills:")
            lines += [f"- {v['name']} v{v['version']} for {v['expert']} ({v['status']}): {((v.get('change_note') or '').splitlines() or [''])[0][:120]}" for v in vers]
        if not mems and not vers:
            lines.append("Nothing new was recorded.")
        rec = self.learning_recommendation()
        waiting = len(self.memory.pending(conversation_id=conv_id)) + sum(1 for v in vers if v["status"] == "candidate")
        if waiting:
            lines.append(f"\n{waiting} item(s) wait for your review on the Learning page"
                         + (f"; the review recommends approving {len(rec['approve_memories']) + len(rec['approve_skill_versions'])} "
                            "of them (one step there)." if rec and (rec['approve_memories'] or rec['approve_skill_versions']) else "."))
        return "\n".join(lines)


    def _on_save(self, agent: Agent, transcript: bool = True) -> None:
        """Persist an agent's context to the conversation: at every checkpoint, and with its transcript (for training
        export) at the end of each turn."""
        if self.conversation is None and len(agent.messages) <= 1:
            return
        conv = self._conv()
        if transcript:
            d = self.case.dir / "transcripts" / conv["id"]
            d.mkdir(parents=True, exist_ok=True)
            (d / agent.transcript_name).write_text(json.dumps({
                "agent": agent.name, "agent_id": agent.agent_id, "model": agent.backend.profile_name, "usage": agent.usage,
                "tools": [{"name": t.name, "description": t.description, "parameters": t.parameters} for t in agent.tools],
                "messages": agent.messages}, indent=1, default=str))
        state = agent.export_state()
        if agent.agent_id in self.subagents:
            state["meta"] = self.subagents[agent.agent_id].meta()
        self.history.save_agent(conv["id"], agent.agent_id, state)

    # ---- orchestrator tools -------------------------------------------------------------------
    def _semaphore(self) -> asyncio.Semaphore:
        if self._sem is None:
            self._sem = asyncio.Semaphore(self.max_parallel)
        return self._sem

    def _next_sid(self) -> str:
        nums = [int(k[3:]) for k in self.subagents if k[3:].isdigit()]
        return f"SA-{max(nums, default=0) + 1:03d}"

    def _build_subagent(self, sa: SubAgent) -> Agent:
        e = self.experts.get(sa.expert)
        if not e:
            raise ValueError(f"expert {sa.expert} is no longer configured")
        agent = self._make_agent(e.name, sa.id, f"# Role: {e.title}\n{e.prompt}\n\n{_prompt('subagent')}", e.model, e.tools,
                                 ["subagent_*", *e.deny_tools], e.max_steps)
        agent.add_local(skill_tools(self.skills, e.name, sa.id, self._skill_ctx, list(self.experts), self.emit))
        agent.add_local([self._report_tool(agent, sa)])
        if sa.id in self._sub_states:
            agent.restore(self._sub_states.pop(sa.id))
        return agent

    def _report_tool(self, agent: Agent, sa: SubAgent) -> Tool:
        def submit_report(status: str, summary: str, details: str = "", confidence: str = "medium",
                          open_questions: list[str] | None = None, recommended_tasks: list[dict[str, Any]] | None = None,
                          skills_used: list[dict[str, Any]] | None = None) -> str:
            if status not in REPORT_STATUSES:
                raise ValueError(f"status must be one of {REPORT_STATUSES}")
            rec = [{"expert": str(r.get("expert", "")), "task": str(r["task"])[:1500]}
                   for r in recommended_tasks or [] if isinstance(r, dict) and r.get("task")]
            used = []
            for u in skills_used or []:
                if not (isinstance(u, dict) and u.get("name")):
                    continue
                worked, note = bool(u.get("worked", True)), str(u.get("note", ""))[:500]
                try:
                    self.skills.feedback(str(u["name"]), worked, note, sa.id, self._conv()["id"])
                    used.append({"name": str(u["name"]), "worked": worked, "note": note})
                except KeyError:
                    pass
            agent.terminal = {"status": status, "summary": summary.strip(), "details": details.strip(),
                              "confidence": confidence, "open_questions": [str(q) for q in open_questions or []],
                              "recommended_tasks": rec, "skills_used": used}
            return "report submitted to the orchestrator"

        S = {"type": "string"}
        return Tool(
            "submit_report",
            "Finish your task: deliver your report to the orchestrator. Call it once, last. Put follow-on work you "
            "recommend in recommended_tasks (the orchestrator decides); list every skill you loaded in skills_used.",
            schema({"status": {"type": "string", "enum": REPORT_STATUSES},
                    "summary": {"type": "string", "description": "Bottom line in 1-5 sentences: the answer to the tasking."},
                    "details": {"type": "string", "description": "Evidence (queries, artifacts, hashes, times), assessment, actions taken."},
                    "confidence": {"type": "string", "enum": ["low", "medium", "high"]},
                    "open_questions": {"type": "array", "items": S},
                    "recommended_tasks": {"type": "array", "items": {"type": "object", "properties": {
                        "expert": S, "task": S}, "required": ["task"]}},
                    "skills_used": {"type": "array", "items": {"type": "object", "properties": {
                        "name": S, "worked": {"type": "boolean"}, "note": S}, "required": ["name", "worked"]}}},
                   ["status", "summary"]),
            submit_report)

    @staticmethod
    def _call_key() -> str:
        ref = CURRENT_CALL.get()
        return ref.key if ref else ""

    def _resumed_sub(self) -> SubAgent | None:
        """When an interrupted operation is resumed: the subagent the call being resumed had already tasked."""
        ref = CURRENT_CALL.get()
        if not (ref and ref.resumed):
            return None
        return next((sa for sa in reversed(list(self.subagents.values())) if sa.call == ref.key), None)

    async def _spawn(self, expert: str, task: str, context: str = "", expected_output: str = "") -> str:
        if sa := self._resumed_sub():
            return await self._resume_sub(sa)
        e = self.experts.get(expert)
        if not e:
            return f"ERROR: unknown expert {expert}. Experts: {', '.join(self.experts)}"
        self._conv()
        if e.name in self.roe.gate_all_experts:  # the analyst approved starting it; everything after is gated too
            self.gate_conversation(f"the {e.name} is working in this conversation")
        sa = SubAgent(self._next_sid(), e.name, e.title, task, context, expected_output, created=_now(), updated=_now(),
                      call=self._call_key())
        self.subagents[sa.id] = sa
        sa.agent = self._build_subagent(sa)
        mem = self.memory.context_block(f"{e.name} {task} {context}")
        skills = self._default_skills(e, sa.id) + self.skills.index_block(e.name, f"{task} {context}")
        brief = (f"# Tasking from the orchestrator (you are subagent {sa.id})\n{task}\n\n"
                 f"# Known context\n{context or '(none)'}\n\n"
                 f"# Expected output\n{expected_output or 'Answer the tasking with evidence for every claim.'}\n\n"
                 f"{skills}\n\n{mem}").rstrip()
        self.emit("subagent_spawn", {"id": sa.id, "expert": e.name, "title": e.title, "task": task, "context": context[:2000]})
        return await self._run_sub(sa, brief)

    def _default_skills(self, e: ExpertDef, agent_id: str) -> str:
        """The expert's always-on skills, in full and at their current approved version (revisions apply; a
        retired skill drops out). Each counts as a use, so it is scored like any skill the agent loads."""
        c, parts = self._skill_ctx(), []
        for name in e.skills:
            try:
                s = self.skills.record_use(name, e.name, agent_id, c["conversation_id"], c["case_id"])
            except KeyError:
                continue
            self.emit("skill_used", {"agent": e.name, "agent_id": agent_id, "skill": name, "version": s["active_version"]})
            parts.append(f"## Skill {name} v{s['active_version']}\n{s['body']}")
        if not parts:
            return ""
        return ("# Skills always on for your role (already loaded: follow them, and list them in skills_used)\n"
                + "\n\n".join(parts) + "\n\n")

    async def _message(self, subagent_id: str, message: str) -> str:
        if sa := self._resumed_sub():
            return await self._resume_sub(sa)
        sa = self.subagents.get(subagent_id.strip().upper())
        if not sa:
            return f"ERROR: no subagent {subagent_id} in this conversation (subagent_list shows them)"
        if sa.lock.locked():
            return f"ERROR: {sa.id} is still working on an earlier task; wait for that report"
        if sa.agent is None:
            sa.agent = self._build_subagent(sa)
        sa.call = self._call_key()
        self.emit("subagent_message", {"id": sa.id, "expert": sa.expert, "title": sa.title, "message": message})
        return await self._run_sub(sa, f"# Follow-up from the orchestrator\n{message}\n\nFinish with submit_report.")

    async def _resume_sub(self, sa: SubAgent) -> str:
        """A resumed operation reached a call that had tasked `sa` before the interruption: hand back the report it
        already gave, or let it finish its task from where it stopped."""
        if sa.answered and sa.answered == sa.call and sa.last_report:
            return self._format_report(sa, sa.last_report)
        if sa.lock.locked():
            return f"ERROR: {sa.id} is still working on an earlier task; wait for that report"
        if sa.agent is None:
            sa.agent = self._build_subagent(sa)
        sa.stop_requested = False
        self.emit("subagent_resumed", {"id": sa.id, "expert": sa.expert, "title": sa.title, "task": sa.task})
        return await self._drive_sub(sa, sa.agent.resume)

    async def _run_sub(self, sa: SubAgent, text: str) -> str:
        if sa.lock.locked():
            return f"ERROR: {sa.id} is still working on an earlier task; wait for that report"
        assert sa.agent
        sa.status, sa.stop_requested = "queued", False
        sa.agent.add_user(text)  # the task is saved before it waits for a slot, so a restart cannot lose it
        return await self._drive_sub(sa, sa.agent.resume)

    async def _drive_sub(self, sa: SubAgent, work: Callable[[], Any]) -> str:
        """Run a subagent's turn (`work`) in a parallel slot and turn its outcome into a report for the orchestrator.
        A subagent stopped while it waits for a slot never starts."""
        assert sa.agent
        stopped = False
        sa.status, sa.updated = "queued", _now()
        async with sa.lock, self._semaphore():
            sa.status, sa.updated, sa.started = "running", _now(), time.time()
            if sa.stop_requested:
                sa.agent.repair("stopped by the analyst")
                stopped, final = True, ""
            else:
                sa.job = asyncio.ensure_future(work())
                try:
                    final = await sa.job
                except asyncio.CancelledError:
                    me = asyncio.current_task()
                    if not sa.stop_requested or (me is not None and me.cancelling()):
                        raise  # the whole operation was cancelled, not just this subagent
                    sa.agent.repair("stopped by the analyst")
                    stopped, final = True, ""
                except Exception as ex:
                    sa.status, sa.updated = "failed", _now()
                    sa.agent.repair(f"subagent failed: {type(ex).__name__}")
                    self.emit("subagent_report", {"id": sa.id, "expert": sa.expert, "title": sa.title, "status": "failed",
                                                  "summary": f"{type(ex).__name__}: {ex}", "details": "", "confidence": "",
                                                  "open_questions": [], "recommended_tasks": [], "skills_used": []})
                    raise
                finally:
                    sa.job = None
        if stopped:
            report = {"status": "stopped", "summary": "Stopped by the analyst before finishing.", "details": "",
                      "confidence": "", "open_questions": [], "recommended_tasks": [], "skills_used": []}
        else:
            report = sa.agent.terminal or {"status": "completed", "summary": final, "details": "", "confidence": "unstated",
                                           "open_questions": [], "recommended_tasks": [], "skills_used": [], "unstructured": True}
        sa.turns += 1
        sa.status, sa.last_report, sa.updated, sa.answered = report["status"], report, _now(), sa.call
        sa.agent.save()
        self.audit.record("subagent_report", id=sa.id, expert=sa.expert, status=sa.status, task=sa.task[:500],
                          chars=len(report["summary"]) + len(report["details"]))
        self.emit("subagent_report", {"id": sa.id, "expert": sa.expert, "title": sa.title, **report, "usage": sa.agent.usage,
                                      "seconds": round(time.time() - sa.started, 1)})
        return self._format_report(sa, report)

    def steer_subagent(self, subagent_id: str, message: str, by: str) -> None:
        """Queue analyst guidance for a running subagent; it is delivered before its next model call."""
        sa = self.subagents.get(subagent_id)
        if not sa:
            raise KeyError(f"no subagent {subagent_id}")
        if sa.status not in ("running", "queued") or not sa.agent:
            raise ValueError(f"{subagent_id} is not running; ask the lead to follow up with it instead")
        msg = message.strip()[:2000]
        if not msg:
            raise ValueError("empty guidance")
        sa.agent.inbox.append(msg)
        self.audit.record("subagent_steer", id=sa.id, expert=sa.expert, message=msg[:500], by=by)
        self.emit("subagent_steer", {"id": sa.id, "expert": sa.expert, "title": sa.title, "message": msg})

    def stop_subagent(self, subagent_id: str, by: str) -> None:
        """Cancel one running subagent. The orchestrator gets a 'stopped' report and carries on."""
        sa = self.subagents.get(subagent_id)
        if not sa:
            raise KeyError(f"no subagent {subagent_id}")
        if sa.status == "queued" and not sa.stop_requested:  # waiting for a slot: it will not start
            sa.stop_requested = True
        elif not sa.job or sa.job.done():
            raise ValueError(f"{subagent_id} is not running")
        else:
            sa.stop_requested = True
            sa.job.cancel()
        self.audit.record("subagent_stopped", id=sa.id, expert=sa.expert, by=by)

    @staticmethod
    def _format_report(sa: SubAgent, r: dict[str, Any]) -> str:
        out = [f"# Report from {sa.id} - {sa.title} ({sa.expert})", f"status: {r['status']} | confidence: {r['confidence']}"]
        if r.get("unstructured"):
            out.append("(the subagent answered in free text instead of submit_report)")
        out += ["## Bottom line", r["summary"] or "(empty)"]
        if r["details"]:
            out += ["## Details", r["details"]]
        if r["open_questions"]:
            out += ["## Open questions", *[f"- {q}" for q in r["open_questions"]]]
        if r["recommended_tasks"]:
            out += ["## Recommended tasks (your decision)", *[f"- {t['expert'] or 'any'}: {t['task']}" for t in r["recommended_tasks"]]]
        if r["skills_used"]:
            out += ["## Skills used", *[f"- {u['name']}: {'worked' if u['worked'] else 'DID NOT WORK'} {u['note']}" for u in r["skills_used"]]]
        out.append(f'(Follow up with subagent_message(subagent_id="{sa.id}", ...) - it keeps its context.)')
        return "\n".join(out)

    def _list_subagents(self) -> str:
        if not self.subagents:
            return "no subagents yet in this conversation"
        return "\n".join(f"{s.id} {s.expert} [{s.status}, {s.turns} report(s)] task: {s.task[:200]}"
                         + (f"\n   last: {s.last_report['summary'][:300]}" if s.last_report else "")
                         for s in self.subagents.values())

    # ---- entry points -----------------------------------------------------------------
    def refresh_models(self) -> None:
        """Pick up edits to config/.env and the model files before a run: an agent whose profile changed (say, a
        rotated API key) gets a new backend for it. Profiles that were removed keep their current backend."""
        if not self.cfg.reload_models():
            return
        agents = [self.lead] + [sa.agent for sa in self.subagents.values() if sa.agent]
        for ag in agents:
            prof = getattr(ag.backend, "profile", None) if ag else None
            new = self.cfg.models.get(prof.name) if prof else None
            if new is not None and new is not prof:
                ag.backend = self.backend(prof.name)

    async def mission(self, text: str, display: str | None = None, playbook: str = "") -> str:
        assert self.lead
        self.refresh_models()
        conv = self._conv()
        shown = text if display is None else display
        if not conv.get("title"):
            src = (shown or playbook or text).strip()
            title = src.splitlines()[0][:120] if src else "operation"
            self.history.rename(conv["id"], title)
            conv["title"] = title
        self.emit("analyst_message", {"text": shown, "playbook": playbook})
        if playbook in self.roe.gate_all_playbooks:  # before the lead takes any step
            self.gate_conversation(f"{playbook.replace('_', ' ')} playbook")
        if not self.case.data.get("mission"):
            self.case.data["mission"] = text
            self.case._save()
        parts = [text]
        if mem := self.memory.context_block(text):
            parts.append(mem)
        if self.skills.relevant(LEAD, text, 1):
            parts.append(self.skills.index_block(LEAD, text))
        if mem or self.case.data["findings"]:
            parts.append(f"# Current case state\n{self.case.summary(10)}")
        return await self.lead.turn("\n\n".join(parts))

    async def retro(self) -> str:
        """After-action review. Each subagent reflects on its own work and revises its skills, then the
        orchestrator turns the whole operation into memories and skills."""
        assert self.lead
        self.refresh_models()
        self.emit("retro_start", {})
        self._learn_denials()
        verdicts = "\n".join(f"{f['id']} {f['title']}: {f['verdict']} {f.get('verdict_note', '')}"
                             for f in self.case.data["findings"] if f["verdict"] != "unreviewed") or "(none yet)"
        conv_id = self._conv()["id"]
        usage = self.skills.conversation_usage(conv_id)

        reflections: list[str] = []
        subs = [s for s in self.subagents.values() if s.status not in ("failed",)]
        if subs and self.cfg.orchestration.get("reflect_on_retro", True):
            async def reflect(sa: SubAgent) -> str:
                mine = [u for u in usage if u["agent_id"] == sa.id]
                block = "\n".join(f"- {u['name']} v{u['version']}: {u['outcome'] or 'not reported'} {u['note'] or ''}" for u in mine)
                return await self._message(sa.id, _prompt("reflect") + f"\n\n# Analyst verdicts on findings\n{verdicts}\n\n"
                                           f"# Skills you used in this operation\n{block or '(none)'}\n\n"
                                           f"# Did your procedure work?\n{self._worked(sa, mine)}")
            for sa, res in zip(subs, await asyncio.gather(*[reflect(s) for s in subs], return_exceptions=True)):
                summary = (sa.last_report or {}).get("summary", "") if not isinstance(res, BaseException) else f"failed: {res}"
                reflections.append(f"- {sa.id} {sa.expert}: {summary[:600]}")

        usage = self.skills.conversation_usage(conv_id)
        used = "\n".join(f"- {u['agent_id']} used {u['name']} v{u['version']}: {u['outcome'] or 'not reported'} {u['note'] or ''}"
                         for u in usage) or "(no skills were used)"
        weak = "\n".join(f"- {s['name']} ({s['expert']}): {s['successes']} worked / {s['failures']} failed"
                         for s in self.skills.struggling()) or "(none)"
        prompt = (_prompt("retro") + f"\n\n# Analyst verdicts on findings\n{verdicts}\n\n# Skill use in this operation\n{used}"
                  f"\n\n# Skills with a poor track record (revise or replace)\n{weak}"
                  f"\n\n# Subagent reflections\n" + ("\n".join(reflections) or "(no subagents reflected)")
                  + f"\n\n# Plans and reports the analyst edited after an agent saved them\n{self._analyst_edits()}"
                  + f"\n\n# Unreviewed memories written in this conversation\n{self._unreviewed_block(conv_id)}")
        text = await self.lead.turn(prompt)
        summary = self.what_we_learned(conv_id)
        self.emit("learning_summary", {"text": summary})
        return f"{text}\n\n{summary}"

    def _worked(self, sa: SubAgent, uses: list[dict[str, Any]]) -> str:
        """The signals that a subagent's procedure worked: its report, the analyst's confirmation, how many steps."""
        steps = sum(len(m.get("tool_calls") or []) for m in (sa.agent.messages if sa.agent else []) if m.get("role") == "assistant")
        conv = self.conversation["id"] if self.conversation else ""
        ratings = [r["rating"] for r in self.case.data.get("ratings", []) if r.get("conversation") == conv]
        tp = [f["id"] for f in self.case.data["findings"] if f["verdict"] == "tp"]
        confirmed = bool(tp) or (ratings and ratings[-1] >= 4)
        signals = [f"- your report: {sa.status}", f"- tool calls you made: {steps}",
                   f"- analyst confirmation: {'true-positive verdicts on ' + ', '.join(tp) if tp else 'none on findings'}"
                   f"; operation rating: {ratings[-1] if ratings else 'not rated'}"]
        if sa.status == "completed" and confirmed and steps >= 5 and not any(u["outcome"] == "good" for u in uses):
            signals.append("Your multi-step procedure worked and the analyst confirmed it, and no skill you used covers "
                           "it: write it as a skill now (skill_create), the exact steps and queries that worked, unless "
                           "an existing skill already says it.")
        return "\n".join(signals)

    def _analyst_edits(self, budget: int = 12000) -> str:
        """The analyst's changes to files agents saved (hunt plans, results, CTE plans, reports), as diffs."""
        out: list[str] = []
        for folder in self.plan_dirs:
            for path in sorted(folder.glob("*.md")) if folder.is_dir() else []:
                if huntplans.edited(path) and budget > 0:
                    diff = huntplans.analyst_changes(folder, path.name, min(4000, budget))
                    out.append(diff)
                    budget -= len(diff)
        return "\n\n".join(out) or "(none)"

    def _unreviewed_block(self, conv_id: str) -> str:
        rows = self.memory.pending(conversation_id=conv_id)[:40]
        return "\n".join(f"- M{m['id']} ({m['kind']}) {m['title']}: {m['content'][:300]}" for m in rows) or "(none)"

    # ---- operations: recorded, so one cut off by a restart or a crash can be resumed or ended ------------
    def op_begin(self, kind: str, label: str, playbook: str = "") -> dict[str, Any]:
        """Record a new operation (mission, after-action review). An interrupted one in this conversation is ended
        first: the analyst chose to do something else."""
        if self.interrupted_operation():
            self.end_interrupted("a new request was started instead")
        self.op = self.history.op_create(self._conv()["id"], kind, label, playbook, os.getpid(), time.time())
        self.budget = Budget(self.cfg.budgets, self.emit)
        return self.op

    def _learn_denials(self) -> None:
        """The analyst's denials are corrections: trusted at once, as approved feedback memories."""
        for d in self.executor.denials:
            self.memory.add("feedback", f"Analyst denied {d['tool']}",
                            f"Agent {d['agent']} requested {d['tool']} with {json.dumps(d['args'])[:400]}. {d['reason']}",
                            tags=[d["tool"]], source="analyst")
        self.executor.denials.clear()

    def budget_stop(self, why: str) -> str:
        """End the operation at its budget, cleanly: every agent's open tool calls get a result, so the conversation
        can carry on with a new message."""
        if self.lead:
            self.lead.repair("the run reached its budget")
        for sa in self.subagents.values():
            if sa.agent and sa.status in ("running", "queued"):
                sa.status = "interrupted"
                sa.agent.repair("the run reached its budget")
        used = self.budget.used() if self.budget else {}
        self.audit.record("budget_stop", reason=why, **used)
        self.op_end("stopped", f"budget: {why}")
        return (f"Stopped: this run reached its budget ({why}). Nothing more ran. Send a new message to carry on, "
                "or raise the limits under budgets: in harness.yaml.")

    def auto_retro_due(self, playbook: str = "") -> str:
        """Why an after-action review should now run by itself (learning.auto_retro), or "". Never in a conversation
        where every action needs the analyst's approval: there the analyst runs it, and approves each step."""
        cfg = self.cfg.learning
        if not cfg.get("auto_retro", False) or self.gate_reason or not self.conversation:
            return ""
        if playbook:
            return f"the {playbook.replace('_', ' ')} playbook completed"
        n = int(cfg.get("every_n_missions", 0) or 0)
        done = [o for o in self.history.ops_since(self.conversation["id"], "retro")
                if o["kind"] in ("mission", "resume") and o["status"] == "done"]
        return f"{len(done)} missions completed since the last review" if n > 0 and len(done) >= n else ""

    def op_end(self, status: str, note: str = "") -> None:
        """done | stopped | failed; interrupted (a shutdown or crash cut it off: it can be resumed)."""
        if status != "interrupted":
            self._learn_denials()
        if not self.op:
            return
        self.history.op_update(self.op["id"], status=status, note=note[:500],
                               ended=None if status == "interrupted" else time.time())
        self.op = None

    def interrupted_operation(self) -> dict[str, Any] | None:
        """The operation in this conversation that a restart or a crash cut off, with whether it can be resumed and
        the approvals it was waiting for. None when there is none (or it is running now, here or in another process)."""
        if not self.conversation:
            return None
        op = self.history.op_latest(self.conversation["id"])
        if not op or op["status"] not in ("running", "interrupted") or (self.op and self.op["id"] == op["id"]):
            return None
        if op["status"] == "running":
            if op["pid"] != os.getpid() and _pid_alive(int(op["pid"] or 0)):
                return None  # another process (the CLI) is running it
            self.history.op_update(op["id"], status="interrupted")
            op["status"] = "interrupted"
        waiting = self.history.approvals(op["conversation_id"], ("pending", "approved_later", "denied_later"), op["id"])
        resumable = op["kind"] in RESUMABLE_KINDS and bool(self.lead and self.lead.unfinished())
        if op["kind"] in RESUMABLE_KINDS and not resumable and not waiting:
            self.history.op_update(op["id"], status="done", ended=time.time(), note="had finished before the interruption")
            return None
        return {**op, "resumable": resumable, "approvals": waiting}

    async def resume(self) -> str:
        """Carry on with the operation a restart cut off: every agent continues from its last checkpoint. Tool calls
        that had no result are decided by the ROE again; a finished subagent hands back its report."""
        op = self.interrupted_operation()
        if not op or not op["resumable"]:
            raise ValueError("there is no interrupted operation to resume in this conversation")
        assert self.lead
        self.refresh_models()
        self.history.op_update(op["id"], status="running", pid=os.getpid(), kind="resume" if op["kind"] == "mission" else op["kind"])
        self.op = {**op, "status": "running"}
        self.budget = Budget(self.cfg.budgets, self.emit)  # a resumed operation gets a fresh budget
        self.audit.record("operation_resumed", operation=op["id"], label=op["label"])
        self.emit("operation_resumed", {"id": op["id"], "label": op["label"], "playbook": op["playbook"]})
        return await self.lead.resume()

    def end_interrupted(self, reason: str) -> dict[str, Any] | None:
        """End an interrupted operation without resuming it: open tool calls get a 'not executed' result, the
        approvals it was waiting for expire. The conversation carries on from there."""
        op = self.interrupted_operation()
        if not op:
            return None
        why = f"the operation was interrupted and then ended ({reason})"
        if self.lead and self.lead.unfinished():
            self.lead.repair(why)
        for sa in self.subagents.values():
            if sa.agent is None and sa.id in self._sub_states:
                try:
                    sa.agent = self._build_subagent(sa)
                except ValueError:
                    continue
            if sa.agent and sa.agent.unfinished():
                sa.status = "interrupted"
                sa.agent.repair(why)
        self.history.op_update(op["id"], status="ended", ended=time.time(), note=reason[:500])
        for r in op["approvals"]:
            self.history.approval_update(r["id"], status="expired", note=why[:500])
        self.audit.record("operation_ended", operation=op["id"], label=op["label"], reason=reason)
        self.emit("run_end", {"label": op["label"], "ok": False, "stopped": True, "ended": True,
                              "text": f"The interrupted operation was ended: {reason}."})
        return op

    async def operation(self, kind: str, work: Callable[[], Any], label: str = "", playbook: str = "") -> str:
        """Run a mission, a resume or an after-action review as a recorded operation (the CLI; the dashboard records
        its own runs). Interrupted (Ctrl+C, a crash) it stays resumable."""
        if kind != "resume":
            self.op_begin(kind, label or kind, playbook)
        try:
            out = await work()
        except (asyncio.CancelledError, KeyboardInterrupt):
            self.op_end("interrupted")
            raise
        except BudgetExceeded as e:
            return self.budget_stop(str(e))
        except BaseException as e:
            self.op_end("failed", f"{type(e).__name__}: {e}")
            raise
        self.op_end("done")
        if kind in ("mission", "resume") and (why := self.auto_retro_due(playbook)):
            self.emit("retro_auto", {"why": why})
            self.retro_ran_auto = True
            out = f"{out}\n\n# After-action review (automatic: {why})\n\n" + \
                await self.operation("retro", self.retro, "after-action review (automatic)")
        return out

    def set_verdict(self, finding_id: str, verdict: str, note: str = "") -> bool:
        """Analyst adjudication of a finding. Benign/false-positive verdicts become approved memory."""
        if verdict not in ("tp", "fp", "benign", "inconclusive"):
            raise ValueError("verdict must be tp, fp, benign or inconclusive")
        if not self.case.set_verdict(finding_id, verdict, note):
            return False
        self.audit.record("finding_verdict", finding=finding_id, verdict=verdict, note=note)
        f = next(x for x in self.case.data["findings"] if x["id"] == finding_id)
        if verdict in ("fp", "benign"):
            self.memory.add("false_positive", f"Benign: {f['title']}", f"{f['description'][:800]}\nAnalyst: {note}",
                            tags=f["attack_techniques"], source="analyst")
        elif verdict == "tp":  # tradecraft confirmed in this network
            self.memory.add("ttp", f"Confirmed: {f['title']}", f"{f['description'][:800]}\nAnalyst: {note}",
                            tags=f["attack_techniques"], attack_techniques=f["attack_techniques"], source="analyst")
        return True

    def remember(self, kind: str, title: str, content: str) -> int:
        return self.memory.add(kind, title.strip(), content.strip(), source="analyst")

    def rate(self, rating: int, note: str = "") -> None:
        self.case.data.setdefault("ratings", []).append({"run": self.session, "rating": rating, "note": note,
                                                         "by": self.cfg.operator,
                                                         "conversation": self.conversation["id"] if self.conversation else ""})
        self.case._save()
        settled = self.skills.settle_conversation(self.conversation["id"], rating) if self.conversation else 0
        self.audit.record("session_rating", session=self.session, rating=rating, note=note, skill_uses_settled=settled)
        if len(note.split()) >= 5:  # a comment on how it went (not just "good") is guidance for the next operation
            mission = str(self.case.data.get("mission") or "")[:200]
            self.memory.add("feedback", f"Analyst rated an operation {rating}/5: {note.strip().splitlines()[0][:80]}",
                            f"Rating {rating}/5 for the operation \"{mission}\". The analyst said: {note.strip()}",
                            source="analyst")

    def switch_model(self, name: str) -> None:
        self.cfg.reload_models()
        if why := self.cfg.model(name).problem():  # unknown names raise here too
            raise ValueError(f"model profile '{name}' is not usable yet: {why}")
        assert self.lead
        self.model_name = name
        self.lead.backend = self.backend(name)
        for m in self.lead.messages:
            m.pop("_anthropic", None)  # provider-private blocks don't transfer across models
        self.audit.record("model_switch", model=name)

    async def close(self) -> None:
        if self.lead:
            self.lead.save()
        self.audit.record("session_end", session=self.session)
        await self.mcp.aclose()
        for b in [*self.backends.values(), *self.retired_backends]:
            await b.aclose()


def _pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _purge(store: ChatStore, case_dir: Path, conv: dict[str, Any], audit: AuditLog) -> None:
    store.delete(conv["id"])
    shutil.rmtree(case_dir / "transcripts" / conv["id"], ignore_errors=True)
    audit.record("conversation_deleted", conversation=conv["id"], title=conv["title"], events=conv["events"])


def delete_conversation(cfg: HarnessConfig, conv_id: str, operator: str) -> dict[str, Any] | None:
    """Delete a conversation from outside a running harness (CLI). Returns the deleted conversation's row."""
    store = ChatStore(cfg.history_db)
    c = store.get(conv_id)
    if not c:
        return None
    case_dir = cfg.cases_dir / c["case_id"]
    _purge(store, case_dir, c, AuditLog(case_dir / "audit.jsonl", operator))
    return c
