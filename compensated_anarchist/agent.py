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
from .llm.base import LoopDetector, RepetitionLoop, estimate_tokens
from .mcp_manager import McpManager
from .memory import Memory
from .roe import RoeGate, cli_approver, deny_all_approver
from .skills import BUILTIN_DIR, LEAD, SkillStore, skill_tools
from . import attack, casefiles, huntplans, vault
from .tools import vulnscan
from .tools.forensics import Forensics
from .tools.registry import Tool, ToolExecutor, ToolRegistry, schema

EventFn = Callable[[str, dict[str, Any]], None]

# events that make up the conversation feed (persisted and replayed); everything else is UI-only
PERSIST_KINDS = {"analyst_message", "text", "subagent_spawn", "subagent_message", "subagent_report", "subagent_steer",
                 "decision", "result", "approval_request", "approval_resolved", "run_end", "compact", "skill_used",
                 "skill_proposed", "retro_start", "loop_guard", "plan_saved", "gate_on"}
REPORT_STATUSES = ["completed", "blocked", "needs_input", "failed"]
# The lead orchestrates, so it only holds overview tools; detailed connector, forensic and intel tools belong to
# the experts. This keeps the lead's prompt small (tool schemas are most of it), which matters on local models.
# Override with orchestration.lead_tools in harness.yaml (["*"] = every tool, the old behavior).
DEFAULT_LEAD_TOOLS = ["subagent_*", "case_*", "memory_*", "*__alerts_summary", "*__notable_events", "*__list_clients",
                      "local_case_evidence", "hunt_plan_list"]


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


class Agent:
    def __init__(self, name: str, system: str, backend: LLMBackend, executor: ToolExecutor, tools: list[ToolSpec],
                 max_steps: int, on_event: EventFn, agent_id: str = "", on_save: Callable[["Agent"], None] | None = None,
                 transcript_name: str = ""):
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
        self.usage = {"input": 0, "output": 0}
        self.terminal: dict[str, Any] | None = None  # set by a terminal tool (submit_report) to end the turn
        self.inbox: list[str] = []  # analyst guidance ("steer"), delivered before the next model call

    def add_local(self, tools: list[Tool]) -> None:
        for t in tools:
            self.local[t.name] = t
            self.tools.append(t.spec)

    async def turn(self, user_text: str) -> str:
        self.messages.append({"role": "user", "content": user_text})
        self.terminal = None
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
            results = await asyncio.gather(*[
                self.executor.execute(c, self.name, resp.text, self.tools, self.local, self.agent_id) for c in resp.tool_calls])
            for call, (content, is_err) in zip(resp.tool_calls, results):
                self.messages.append({"role": "tool", "tool_call_id": call.id, "name": call.name,
                                      "content": content, "_is_error": is_err})
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
        unit = LoopDetector().check(resp.text or "")  # non-streamed replies (or a loop that began near the end)
        if unit is not None:
            if sink:
                sink.discard()
            raise RepetitionLoop(unit, "text")
        self.messages.append(resp.assistant_message)
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

    def repair(self, reason: str = "cancelled by analyst") -> None:
        """After an interrupted turn, close any tool calls left without results so the history stays valid."""
        for i in range(len(self.messages) - 1, -1, -1):
            m = self.messages[i]
            if m["role"] == "assistant" and m.get("tool_calls"):
                answered = {x.get("tool_call_id") for x in self.messages[i + 1:] if x["role"] == "tool"}
                for tc in m["tool_calls"]:
                    if tc["id"] not in answered:
                        self.messages.append({"role": "tool", "tool_call_id": tc["id"], "name": tc["function"]["name"],
                                              "content": f"NOT EXECUTED - {reason}", "_is_error": True})
                break
            if m["role"] in ("user",):
                break
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
                "messages": self.messages[1:]}

    def restore(self, state: dict[str, Any]) -> None:
        """Resume from a saved state under a fresh system prompt (session details change between runs)."""
        msgs = state.get("messages") or []
        for m in msgs:  # provider-private blocks are bound to the old prompt prefix
            m.pop("_anthropic", None)
        self.messages = [self.messages[0], *msgs]
        self.usage = dict(state.get("usage") or self.usage)

    def save(self) -> None:
        if self.on_save:
            self.on_save(self)


# ---------------------------------------------------------------------------
# Subagents
# ---------------------------------------------------------------------------
SUB_META = ("id", "expert", "title", "task", "context", "expected", "status", "turns", "created", "updated", "last_report",
            "started")


@dataclass
class SubAgent:
    id: str
    expert: str
    title: str
    task: str
    context: str = ""
    expected: str = ""
    status: str = "idle"  # running | completed | blocked | needs_input | failed | interrupted
    turns: int = 0
    created: str = ""
    updated: str = ""
    last_report: dict[str, Any] | None = None
    started: float = 0.0  # epoch seconds of the current / last run
    agent: Agent | None = None
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    job: asyncio.Task | None = None  # the running agent turn, so the analyst can stop this subagent alone
    stop_requested: bool = False

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
        self.skills = SkillStore(cfg.memory_db, cfg.skills, self.audit)
        self.skills.import_dir(BUILTIN_DIR, "built-in", only_new=True)  # shipped skills, e.g. ponytail for code_writer
        self.history = ChatStore(cfg.history_db)
        self.conversation: dict[str, Any] | None = None
        self.roe = RoeGate(cfg.roe_path, self.audit, cli_approver if interactive else deny_all_approver, posture)
        self.registry = ToolRegistry()
        self.executor = ToolExecutor(self.registry, self.roe, self.audit, self.case.artifacts / "spill",
                                     cfg.max_tool_result_chars, self.emit)
        self.vault_dir = vault.ensure(Path(cfg.forensics.get("vault_dir") or cfg.evidence_roots[0] / "vault"))
        self.case_evidence_dir = casefiles.ensure_case_folder(cfg.forensics_dir, case_id)  # analyst drop folder
        self.hunt_plans_dir = huntplans.ensure(self.case.dir / "hunt_plans")  # hunt_planner writes, threat_hunter reads
        self.vuln_dir = huntplans.ensure(self.case.dir / "vuln_assessment")  # vuln_assessor's reports and raw scans
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

    def _plan_saved(self, path: Path, kind: str) -> None:
        """A hunt plan, hunt results or Navigator layer was saved: the dashboard shows it with links to open it."""
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
            if sa.status == "running":
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
        self.attack = attack.AttackKB(self.cfg.attack_paths)  # loaded on first use
        for t in attack.tools(self.attack, lambda: self.hunt_plans_dir,
                              lambda: [k for k, v in self.mcp.status.items() if str(v).startswith("connected")],
                              on_saved=self._plan_saved):
            self.registry.add(t)
        for t in huntplans.tools(lambda: self.hunt_plans_dir, on_saved=self._plan_saved):
            self.registry.add(t)
        vt = vulnscan.VulnTools(self.cfg.raw.get("vuln_assessment") or {}, self.vuln_dir,
                                scope=lambda: (self.roe.allowed_targets, self.roe.protected_assets), on_saved=self._plan_saved)
        for t in vt.tools():
            self.registry.add(t)
        self._register_orchestration()
        self.audit.record("session_start", session=self.session, model=self.model_name, posture=self.roe.posture,
                          mcp=self.mcp.status, experts=list(self.experts))
        self.lead = self._new_lead()
        if conversation_id:
            self.open_conversation(conversation_id)
        elif not new and (latest := self.history.latest(self.case.id)):
            self.open_conversation(latest["id"])

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
               + f"\nEvidence roots: {[str(p) for p in self.cfg.evidence_roots]}")
        return _prompt("core") + "\n\n" + role_prompt + env

    def _make_agent(self, name: str, agent_id: str, role_prompt: str, model: str | None, allow: list[str],
                    deny: list[str], max_steps: int) -> Agent:
        self._agent_seq += 1
        return Agent(name, self._system(role_prompt), self.backend(model), self.executor, self.registry.specs(allow, deny),
                     max_steps, self.emit, agent_id=agent_id, on_save=self._on_save,
                     transcript_name=f"{self.session}__{agent_id}__{self._agent_seq:03d}.json")

    def _new_lead(self) -> Agent:
        allow = list(self.cfg.orchestration.get("lead_tools") or DEFAULT_LEAD_TOOLS)
        lead = self._make_agent("lead", "lead", _prompt("lead"), None, allow, [], self.cfg.max_steps)
        lead.add_local(skill_tools(self.skills, LEAD, "lead", self._skill_ctx, list(self.experts), self.emit))
        return lead

    def _on_save(self, agent: Agent) -> None:
        """Persist an agent's context to the conversation (and its transcript for training export)."""
        if self.conversation is None and len(agent.messages) <= 1:
            return
        conv = self._conv()
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

    async def _spawn(self, expert: str, task: str, context: str = "", expected_output: str = "") -> str:
        e = self.experts.get(expert)
        if not e:
            return f"ERROR: unknown expert {expert}. Experts: {', '.join(self.experts)}"
        self._conv()
        if e.name in self.roe.gate_all_experts:  # the analyst approved starting it; everything after is gated too
            self.gate_conversation(f"the {e.name} is working in this conversation")
        sa = SubAgent(self._next_sid(), e.name, e.title, task, context, expected_output, created=_now(), updated=_now())
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
        sa = self.subagents.get(subagent_id.strip().upper())
        if not sa:
            return f"ERROR: no subagent {subagent_id} in this conversation (subagent_list shows them)"
        if sa.agent is None:
            sa.agent = self._build_subagent(sa)
        self.emit("subagent_message", {"id": sa.id, "expert": sa.expert, "title": sa.title, "message": message})
        return await self._run_sub(sa, f"# Follow-up from the orchestrator\n{message}\n\nFinish with submit_report.")

    async def _run_sub(self, sa: SubAgent, text: str) -> str:
        if sa.lock.locked():
            return f"ERROR: {sa.id} is still working on an earlier task; wait for that report"
        assert sa.agent
        stopped = False
        async with sa.lock, self._semaphore():
            sa.status, sa.updated, sa.started, sa.stop_requested = "running", _now(), time.time(), False
            sa.job = asyncio.ensure_future(sa.agent.turn(text))
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
        sa.status, sa.last_report, sa.updated = report["status"], report, _now()
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
        if sa.status != "running" or not sa.agent:
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
        if not sa.job or sa.job.done():
            raise ValueError(f"{subagent_id} is not running")
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
        for d in self.executor.denials:  # analyst-authored corrections are trusted immediately
            self.memory.add("feedback", f"Analyst denied {d['tool']}",
                            f"Agent {d['agent']} requested {d['tool']} with {json.dumps(d['args'])[:400]}. {d['reason']}",
                            tags=[d["tool"]], source="analyst")
        self.executor.denials.clear()
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
                                           f"# Skills you used in this operation\n{block or '(none)'}")
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
                  f"\n\n# Subagent reflections\n" + ("\n".join(reflections) or "(no subagents reflected)"))
        return await self.lead.turn(prompt)

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
