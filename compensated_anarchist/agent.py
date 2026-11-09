"""Agent loop, expert delegation and the Harness that wires everything together."""

from __future__ import annotations

import asyncio
import json
import re
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
from .llm import LLMBackend, ToolSpec, make_backend
from .llm.base import estimate_tokens
from .mcp_manager import McpManager
from .memory import Memory
from .roe import RoeGate, cli_approver, deny_all_approver
from .tools.forensics import Forensics
from .tools.registry import Tool, ToolExecutor, ToolRegistry, schema

EventFn = Callable[[str, dict[str, Any]], None]


def _prompt(name: str) -> str:
    return resources.files("compensated_anarchist").joinpath(f"prompts/{name}.md").read_text(encoding="utf-8")


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
class Agent:
    def __init__(self, name: str, system: str, backend: LLMBackend, executor: ToolExecutor, tools: list[ToolSpec],
                 max_steps: int, transcript_path: Path, on_event: EventFn):
        self.name = name
        self.backend = backend
        self.executor = executor
        self.tools = tools
        self.max_steps = max_steps
        self.transcript_path = transcript_path
        self.on_event = on_event
        self.messages: list[dict[str, Any]] = [{"role": "system", "content": system}]
        self.usage = {"input": 0, "output": 0}

    async def turn(self, user_text: str) -> str:
        self.messages.append({"role": "user", "content": user_text})
        final = ""
        for step in range(self.max_steps):
            await self._maybe_compact()
            resp = await self.backend.chat(self.messages, self.tools)
            for k in self.usage:
                self.usage[k] += resp.usage.get(k, 0)
            self.messages.append(resp.assistant_message)
            if resp.text:
                self.on_event("text", {"agent": self.name, "text": resp.text, "final": not resp.tool_calls})
            if not resp.tool_calls:
                final = resp.text
                break
            results = await asyncio.gather(*[
                self.executor.execute(c, self.name, resp.text, self.tools) for c in resp.tool_calls])
            for call, (content, is_err) in zip(resp.tool_calls, results):
                self.messages.append({"role": "tool", "tool_call_id": call.id, "name": call.name,
                                      "content": content, "_is_error": is_err})
        else:
            self.messages.append({"role": "user", "content": (
                "Step budget exhausted. Do not call tools. Give your final report now: what you did, what you "
                "found (with evidence), what remains open, and recommended next steps.")})
            resp = await self.backend.chat(self.messages, [])
            self.messages.append(resp.assistant_message)
            final = resp.text
        self.save()
        return final or "(no final answer)"

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
        self.on_event("compact", {"agent": self.name, "dropped": len(old)})

    def save(self) -> None:
        self.transcript_path.parent.mkdir(parents=True, exist_ok=True)
        self.transcript_path.write_text(json.dumps({
            "agent": self.name, "model": self.backend.profile_name, "usage": self.usage,
            "tools": [{"name": t.name, "description": t.description, "parameters": t.parameters} for t in self.tools],
            "messages": self.messages}, indent=1, default=str))


# ---------------------------------------------------------------------------
# Harness: case + memory + ROE + tools + MCP + lead agent + experts
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
        self.roe = RoeGate(cfg.roe_path, self.audit, cli_approver if interactive else deny_all_approver, posture)
        self.registry = ToolRegistry()
        self.executor = ToolExecutor(self.registry, self.roe, self.audit, self.case.artifacts / "spill",
                                     cfg.max_tool_result_chars, self.on_event)
        for spec in cfg.mcp_servers.values():  # Velociraptor evidence lands inside the forensic jail
            if str(spec.get("module", "")).endswith(".velociraptor"):
                env = spec.setdefault("env", {})
                if not env.get("VELO_DOWNLOAD_DIR"):
                    env["VELO_DOWNLOAD_DIR"] = str(cfg.evidence_roots[0] / "velociraptor")
        self.mcp = McpManager(cfg.mcp_servers, self.case.dir / "logs")
        self.experts = load_experts(cfg)
        self.backends: dict[str, LLMBackend] = {}
        self.lead: Agent | None = None
        self._alias_cache: dict[str, tuple[float, list[str]]] = {}
        self.roe.target_resolver = self._resolve_target
        self._expert_runs = 0

    def backend(self, name: str | None) -> LLMBackend:
        key = name or self.model_name
        if key not in self.backends:
            self.backends[key] = make_backend(self.cfg.model(key))
        return self.backends[key]

    async def start(self) -> None:
        for t in self.case.tools():
            self.registry.add(t)
        for t in self.memory.tools():
            self.registry.add(t)
        for t in Forensics(self.cfg.forensics, self.cfg.evidence_roots, self.case).tools():
            self.registry.add(t)
        await self.mcp.start(self.registry)
        roster = {n: e.description for n, e in self.experts.items()}
        self.registry.add(Tool(
            "delegate",
            "Hand a scoped task to an expert agent and get its report back. Call several in one turn to run experts "
            "in parallel. Experts: " + "; ".join(f"{n}: {d}" for n, d in roster.items()),
            schema({"expert": {"type": "string", "enum": list(roster)},
                    "task": {"type": "string", "description": "Specific objective, scope, time window, what to return."},
                    "context": {"type": "string", "description": "Relevant facts/IOCs/hosts already known."}},
                   ["expert", "task"]),
            self._delegate))
        self.audit.record("session_start", session=self.session, model=self.model_name, posture=self.roe.posture,
                          mcp=self.mcp.status, experts=list(self.experts))
        self.lead = self._make_agent("lead", _prompt("lead"), None, ["*"], [], self.cfg.max_steps)

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
               + f"\nEvidence roots: {[str(p) for p in self.cfg.evidence_roots]}")
        return _prompt("core") + "\n\n" + role_prompt + env

    def _make_agent(self, name: str, role_prompt: str, model: str | None, allow: list[str], deny: list[str],
                    max_steps: int) -> Agent:
        specs = self.registry.specs(allow, deny)
        n = self._expert_runs = self._expert_runs + 1
        path = self.case.dir / "transcripts" / f"{self.session}__{name}__{n:03d}.json"
        return Agent(name, self._system(role_prompt), self.backend(model), self.executor, specs, max_steps, path,
                     self.on_event)

    async def _delegate(self, expert: str, task: str, context: str = "") -> str:
        e = self.experts.get(expert)
        if not e:
            return f"ERROR: unknown expert {expert}"
        agent = self._make_agent(e.name, f"# Role: {e.title}\n{e.prompt}", e.model, e.tools,
                                 ["delegate", *e.deny_tools], e.max_steps)
        mem = self.memory.context_block(f"{e.name} {task} {context}")
        brief = f"# Tasking from DCO lead\n{task}\n\n# Known context\n{context or '(none)'}\n\n{mem}"
        self.on_event("delegate", {"expert": expert, "title": e.title, "task": task})
        try:
            report = await agent.turn(brief)
        except Exception as ex:
            self.on_event("expert_done", {"expert": expert, "ok": False, "error": f"{type(ex).__name__}: {ex}"})
            raise
        self.audit.record("expert_report", expert=expert, task=task[:500], chars=len(report))
        self.on_event("expert_done", {"expert": expert, "ok": True, "report": report[:4000],
                                      "usage": agent.usage})
        return f"# Report from {e.title}\n{report}"

    # ---- entry points -----------------------------------------------------------
    async def mission(self, text: str) -> str:
        assert self.lead
        if not self.case.data.get("mission"):
            self.case.data["mission"] = text
            self.case._save()
        mem = self.memory.context_block(text)
        intro = f"{text}\n\n{mem}\n\n# Current case state\n{self.case.summary(10)}" if mem or self.case.data["findings"] else text
        return await self.lead.turn(intro)

    async def retro(self) -> str:
        """After-action review: the lead turns this operation into durable lessons."""
        assert self.lead
        for d in self.executor.denials:  # analyst-authored corrections are trusted immediately
            self.memory.add("feedback", f"Analyst denied {d['tool']}",
                            f"Agent {d['agent']} requested {d['tool']} with {json.dumps(d['args'])[:400]}. {d['reason']}",
                            tags=[d["tool"]], source="analyst")
        self.executor.denials.clear()
        verdicts = [f"{f['id']} {f['title']}: {f['verdict']} {f.get('verdict_note', '')}"
                    for f in self.case.data["findings"] if f["verdict"] != "unreviewed"]
        prompt = _prompt("retro") + "\n\n# Analyst verdicts on findings\n" + ("\n".join(verdicts) or "(none yet)")
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
                                                         "by": self.cfg.operator})
        self.case._save()
        self.audit.record("session_rating", session=self.session, rating=rating, note=note)

    def switch_model(self, name: str) -> None:
        self.cfg.model(name)  # validate
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
        for b in self.backends.values():
            await b.aclose()
