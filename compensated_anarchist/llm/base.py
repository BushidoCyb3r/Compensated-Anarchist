"""Provider-neutral LLM interface.

Internal conversation format is OpenAI chat-completions style dicts:
  {"role": "system"|"user"|"assistant"|"tool", "content": str, "tool_calls": [...], "tool_call_id": str}
Keys starting with "_" are backend-private (e.g. raw Anthropic content blocks that must be
replayed verbatim) and are stripped by backends that don't understand them.
"""

from __future__ import annotations

import json
import re
import uuid
from dataclasses import dataclass, field
from typing import Any, Protocol


@dataclass
class ToolCall:
    id: str
    name: str
    arguments: dict[str, Any]
    parse_error: str = ""


@dataclass
class LLMResponse:
    text: str
    tool_calls: list[ToolCall]
    assistant_message: dict[str, Any]  # append this to history verbatim
    stop_reason: str = ""
    usage: dict[str, int] = field(default_factory=dict)


@dataclass
class ToolSpec:
    name: str
    description: str
    parameters: dict[str, Any]


class LLMBackend(Protocol):
    profile_name: str
    context_tokens: int

    async def chat(self, messages: list[dict[str, Any]], tools: list[ToolSpec]) -> LLMResponse: ...

    async def aclose(self) -> None: ...


# ---------------------------------------------------------------------------
# Text-mode tool calling (for local models without native function calling).
# Uses the Hermes-style <tool_call>{json}</tool_call> convention that most open
# models are trained on.
# ---------------------------------------------------------------------------
_TOOL_CALL_RE = re.compile(r"<tool_call>\s*(\{.*?\})\s*</tool_call>", re.S)


def text_tools_prompt(tools: list[ToolSpec]) -> str:
    lines = [
        "# Tools",
        "You may call tools. To call one, output exactly:",
        '<tool_call>{"name": "<tool name>", "arguments": {<json args>}}</tool_call>',
        "You may emit several <tool_call> blocks in one reply. After calling tools, STOP and wait;",
        "results arrive in <tool_response> blocks. Available tools (JSON schema):",
    ]
    for t in tools:
        lines.append(json.dumps({"name": t.name, "description": t.description, "parameters": t.parameters}))
    return "\n".join(lines)


def parse_text_tool_calls(text: str) -> tuple[str, list[ToolCall]]:
    calls: list[ToolCall] = []
    for m in _TOOL_CALL_RE.finditer(text or ""):
        cid = "call_" + uuid.uuid4().hex[:12]
        try:
            obj = json.loads(m.group(1))
            calls.append(ToolCall(cid, str(obj.get("name", "")), obj.get("arguments") or {}))
        except json.JSONDecodeError as e:
            calls.append(ToolCall(cid, "invalid", {}, parse_error=f"invalid tool call JSON: {e}"))
    clean = _TOOL_CALL_RE.sub("", text or "").strip()
    return clean, calls


def to_text_mode(messages: list[dict[str, Any]], tools: list[ToolSpec]) -> list[dict[str, Any]]:
    """Rewrite a native-tool conversation into plain user/assistant turns."""
    out: list[dict[str, Any]] = []
    for m in messages:
        role = m["role"]
        if role == "system":
            content = m["content"]
            if not out:  # first system message gets the tool catalogue
                content = content + "\n\n" + text_tools_prompt(tools)
            out.append({"role": "system", "content": content})
        elif role == "assistant":
            content = m.get("content") or ""
            for tc in m.get("tool_calls") or []:
                fn = tc["function"]
                content += f'\n<tool_call>{{"name": "{fn["name"]}", "arguments": {fn["arguments"]}}}</tool_call>'
            out.append({"role": "assistant", "content": content.strip()})
        elif role == "tool":
            block = f'<tool_response name="{m.get("name", "")}">\n{m["content"]}\n</tool_response>'
            if out and out[-1]["role"] == "user" and out[-1].get("_tool_resp"):
                out[-1]["content"] += "\n" + block
            else:
                out.append({"role": "user", "content": block, "_tool_resp": True})
        else:
            out.append({"role": role, "content": m.get("content") or ""})
    return [{k: v for k, v in m.items() if not k.startswith("_")} for m in out]


def estimate_tokens(messages: list[dict[str, Any]]) -> int:
    return sum(len(json.dumps(m, default=str)) for m in messages) // 4
