"""OpenAI-compatible chat-completions backend.

Covers anything that speaks /v1/chat/completions: vLLM, Ollama, llama.cpp server,
LM Studio, TGI, LiteLLM proxies, enterprise / government AI gateways, OpenAI, Gemini's
OpenAI endpoint, etc. Supports DoD PKI: custom CA bundle and mTLS client certificates.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

import httpx

from ..config import ModelProfile
from .base import LLMResponse, ToolCall, ToolSpec, parse_text_tool_calls, to_text_mode


class OpenAICompatBackend:
    def __init__(self, profile: ModelProfile):
        if not profile.base_url:
            raise ValueError(f"model profile '{profile.name}' needs base_url")
        self.profile = profile
        self.profile_name = profile.name
        self.context_tokens = profile.context_tokens
        headers = {"Content-Type": "application/json", **profile.extra_headers}
        if profile.api_key:
            if profile.api_key_header.lower() == "authorization":
                headers["Authorization"] = f"Bearer {profile.api_key}"
            else:
                headers[profile.api_key_header] = profile.api_key
        verify: Any = profile.ca_bundle or profile.verify_tls
        cert = (profile.client_cert, profile.client_key) if profile.client_cert else None
        self.client = httpx.AsyncClient(
            base_url=profile.base_url.rstrip("/"),
            headers=headers,
            verify=verify,
            cert=cert,
            timeout=httpx.Timeout(profile.timeout_s, connect=30.0),
        )

    async def aclose(self) -> None:
        await self.client.aclose()

    async def _post(self, body: dict[str, Any]) -> dict[str, Any]:
        delay = 2.0
        for attempt in range(5):
            try:
                r = await self.client.post("/chat/completions", json=body)
            except (httpx.ConnectError, httpx.ReadTimeout, httpx.RemoteProtocolError):
                if attempt == 4:
                    raise
                await asyncio.sleep(delay)
                delay *= 2
                continue
            if r.status_code in (408, 429) or r.status_code >= 500:
                if attempt == 4:
                    r.raise_for_status()
                await asyncio.sleep(float(r.headers.get("retry-after", delay)))
                delay *= 2
                continue
            if r.status_code >= 400:
                raise RuntimeError(f"{self.profile.name}: HTTP {r.status_code}: {r.text[:1000]}")
            return r.json()
        raise RuntimeError("unreachable")

    async def chat(self, messages: list[dict[str, Any]], tools: list[ToolSpec]) -> LLMResponse:
        text_mode = self.profile.tool_mode == "text"
        if text_mode:
            wire = to_text_mode(messages, tools)
        else:
            wire = [{k: v for k, v in m.items() if not k.startswith("_")} for m in messages]
        body: dict[str, Any] = {
            "model": self.profile.model,
            "messages": wire,
            "max_tokens": self.profile.max_output_tokens,
            **self.profile.extra_body,
        }
        if tools and not text_mode:
            body["tools"] = [
                {"type": "function", "function": {"name": t.name, "description": t.description, "parameters": t.parameters}}
                for t in tools
            ]
            body["tool_choice"] = "auto"

        data = await self._post(body)
        choice = data["choices"][0]
        msg = choice.get("message") or {}
        text = msg.get("content") or ""
        calls: list[ToolCall] = []
        for tc in msg.get("tool_calls") or []:
            fn = tc.get("function") or {}
            raw = fn.get("arguments") or "{}"
            try:
                args = json.loads(raw) if isinstance(raw, str) else raw
                calls.append(ToolCall(tc.get("id") or f"call_{len(calls)}", fn.get("name", ""), args or {}))
            except json.JSONDecodeError as e:
                calls.append(ToolCall(tc.get("id") or f"call_{len(calls)}", fn.get("name", ""), {}, f"invalid JSON arguments: {e}"))

        # Fallback: many local models emit Hermes-style <tool_call> text even in native mode.
        if not calls and "<tool_call>" in text:
            text, calls = parse_text_tool_calls(text)

        assistant: dict[str, Any] = {"role": "assistant", "content": text or None}
        if calls:
            assistant["tool_calls"] = [
                {"id": c.id, "type": "function", "function": {"name": c.name, "arguments": json.dumps(c.arguments)}}
                for c in calls
            ]
        usage = data.get("usage") or {}
        return LLMResponse(
            text=text,
            tool_calls=calls,
            assistant_message=assistant,
            stop_reason=choice.get("finish_reason") or "",
            usage={"input": usage.get("prompt_tokens", 0), "output": usage.get("completion_tokens", 0)},
        )
