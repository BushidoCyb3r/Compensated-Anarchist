"""Native Anthropic (Claude) backend using the official SDK.

- adaptive thinking + effort from the profile
- server-side refusal fallbacks enabled by default on models that support it
- assistant content blocks (incl. thinking blocks) are replayed verbatim via the
  private "_anthropic" key so multi-turn tool use stays valid.
- every request streams (timeout protection); with an on_delta sink, text deltas are forwarded as they arrive.
  After a mid-stream server-side fallback the partial text is kept and the fallback model continues it, so the
  streamed text never has to be retracted.
"""

from __future__ import annotations

import json
from typing import Any

from ..config import ModelProfile
from .base import DeltaFn, LLMResponse, ToolCall, ToolSpec

_FALLBACK_MODELS = {"claude-fable-5-2", "claude-fable-5-1", "claude-opus-5-5", "claude-opus-5", "claude-sonnet-5-5"}
_FALLBACK_BETA = "server-side-fallback-2026-07-01"


class AnthropicBackend:
    def __init__(self, profile: ModelProfile):
        try:
            import anthropic
        except ImportError as e:  # pragma: no cover
            raise RuntimeError("pip install 'compensated-anarchist[anthropic]' to use provider: anthropic") from e
        kwargs: dict[str, Any] = {}
        if profile.api_key:
            kwargs["api_key"] = profile.api_key
        if profile.base_url:
            kwargs["base_url"] = profile.base_url
        if profile.extra_headers:
            kwargs["default_headers"] = profile.extra_headers
        self.client = anthropic.AsyncAnthropic(timeout=profile.timeout_s, **kwargs)
        self.profile = profile
        self.profile_name = profile.name
        self.context_tokens = profile.context_tokens

    async def aclose(self) -> None:
        await self.client.close()

    @staticmethod
    def _convert(messages: list[dict[str, Any]]) -> tuple[str, list[dict[str, Any]]]:
        system_parts: list[str] = []
        out: list[dict[str, Any]] = []
        for m in messages:
            role = m["role"]
            if role == "system":
                system_parts.append(m["content"])
            elif role == "user":
                out.append({"role": "user", "content": m["content"]})
            elif role == "assistant":
                if "_anthropic" in m:
                    out.append({"role": "assistant", "content": m["_anthropic"]})
                    continue
                blocks: list[dict[str, Any]] = []
                if m.get("content"):
                    blocks.append({"type": "text", "text": m["content"]})
                for tc in m.get("tool_calls") or []:
                    blocks.append({
                        "type": "tool_use",
                        "id": tc["id"],
                        "name": tc["function"]["name"],
                        "input": json.loads(tc["function"]["arguments"] or "{}"),
                    })
                out.append({"role": "assistant", "content": blocks or [{"type": "text", "text": "(no content)"}]})
            elif role == "tool":
                block = {
                    "type": "tool_result",
                    "tool_use_id": m["tool_call_id"],
                    "content": m["content"],
                    **({"is_error": True} if m.get("_is_error") else {}),
                }
                # all tool results for one assistant turn go in a single user message
                if out and out[-1]["role"] == "user" and isinstance(out[-1]["content"], list) and out[-1].get("_results"):
                    out[-1]["content"].append(block)
                else:
                    out.append({"role": "user", "content": [block], "_results": True})
        clean = [{k: v for k, v in m.items() if not k.startswith("_")} for m in out]
        return "\n\n".join(system_parts), clean

    @staticmethod
    async def _consume(stream: Any, on_delta: DeltaFn | None) -> Any:
        if on_delta:
            async for event in stream:
                if event.type == "text" and event.text:
                    on_delta(event.text)
        return await stream.get_final_message()

    async def chat(self, messages: list[dict[str, Any]], tools: list[ToolSpec], on_delta: DeltaFn | None = None) -> LLMResponse:
        system, wire = self._convert(messages)
        p = self.profile
        params: dict[str, Any] = {
            "model": p.model,
            "max_tokens": max(p.max_output_tokens, 16000),
            "system": system,
            "messages": wire,
            "thinking": {"type": "adaptive"},
            "output_config": {"effort": p.effort},
            **p.extra_body,
        }
        if tools:
            params["tools"] = [
                {"name": t.name, "description": t.description, "input_schema": t.parameters, "eager_input_streaming": True}
                for t in tools
            ]
        sink = on_delta if p.stream else None
        api = self.client.messages
        if p.model in _FALLBACK_MODELS:
            params["betas"] = [_FALLBACK_BETA]
            params["fallbacks"] = "default"
            api = self.client.beta.messages
        for attempt in range(3):
            try:
                async with api.stream(**params) as stream:
                    msg = await self._consume(stream, sink)
                break
            except ValueError:
                # eager input streaming: tool-input JSON the SDK could not parse at all. No tool_use id exists to
                # answer, so re-issue the turn (bounded) and discard the text streamed so far.
                if attempt == 2:
                    raise
                if sink:
                    sink(None)

        raw_blocks = [b.model_dump(exclude_none=True) for b in msg.content]
        text = "".join(b.text for b in msg.content if b.type == "text")
        calls: list[ToolCall] = []
        if msg.stop_reason == "refusal":
            text = (text + "\n[model refused this request]").strip()
        elif msg.stop_reason == "max_tokens":
            # tool inputs may be truncated - don't execute them
            text = (text + "\n[output truncated at max_tokens; tool calls dropped]").strip()
        else:
            for b in msg.content:
                if b.type == "tool_use":
                    args = b.input if isinstance(b.input, dict) else {}
                    err = "" if isinstance(b.input, dict) else "tool input was not a JSON object"
                    calls.append(ToolCall(b.id, b.name, args, err))

        assistant: dict[str, Any] = {"role": "assistant", "content": text or None, "_anthropic": raw_blocks}
        if calls:
            assistant["tool_calls"] = [
                {"id": c.id, "type": "function", "function": {"name": c.name, "arguments": json.dumps(c.arguments)}}
                for c in calls
            ]
        return LLMResponse(
            text=text,
            tool_calls=calls,
            assistant_message=assistant,
            stop_reason=msg.stop_reason or "",
            usage={"input": msg.usage.input_tokens, "output": msg.usage.output_tokens},
        )
