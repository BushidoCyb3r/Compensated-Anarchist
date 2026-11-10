"""OpenAI-compatible chat-completions backend.

Covers anything that speaks /v1/chat/completions: vLLM, Ollama, llama.cpp server,
LM Studio, TGI, LiteLLM proxies, enterprise / government AI gateways, OpenAI, Gemini's
OpenAI endpoint, etc. Supports DoD PKI: custom CA bundle and mTLS client certificates.

Streaming: with an on_delta sink (and profile.stream), the request uses "stream": true and server-sent events.
Text and tool-call fragments are reassembled into the same response a non-streaming call returns. If the
server rejects a streaming request (HTTP 400/404/415/422), the backend switches to non-streaming for the rest of
the session, so gateways without SSE support keep working.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

import httpx

from ..config import ModelProfile
from .base import DeltaFn, LLMResponse, ToolCall, ToolCallTextFilter, ToolSpec, parse_text_tool_calls, to_text_mode

_RETRY_ERRORS = (httpx.ConnectError, httpx.ReadTimeout, httpx.RemoteProtocolError, httpx.ReadError)


class _StreamRefused(Exception):
    """The server does not accept streaming requests (or the stream_options extension)."""


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
        self.stream_ok = profile.stream

    async def aclose(self) -> None:
        await self.client.aclose()

    async def _post(self, body: dict[str, Any]) -> dict[str, Any]:
        delay = 2.0
        for attempt in range(5):
            try:
                r = await self.client.post("/chat/completions", json=body)
            except _RETRY_ERRORS:
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

    async def _post_stream(self, body: dict[str, Any], on_delta: DeltaFn) -> dict[str, Any]:
        """Streaming request; returns the same shape as a non-streaming chat completion."""
        body = {**body, "stream": True, "stream_options": {"include_usage": True}}
        filt = ToolCallTextFilter(on_delta)
        delay = 2.0
        for attempt in range(5):
            text: list[str] = []
            calls: dict[int, dict[str, Any]] = {}
            finish, usage, emitted = "", {}, False
            try:
                async with self.client.stream("POST", "/chat/completions", json=body) as r:
                    if r.status_code in (400, 404, 415, 422):
                        raise _StreamRefused(f"HTTP {r.status_code}: {(await r.aread())[:500]!r}")
                    if r.status_code in (408, 429) or r.status_code >= 500:
                        await r.aread()
                        if attempt == 4:
                            r.raise_for_status()
                        await asyncio.sleep(float(r.headers.get("retry-after", delay)))
                        delay *= 2
                        continue
                    if r.status_code >= 400:
                        raise RuntimeError(f"{self.profile.name}: HTTP {r.status_code}: {(await r.aread()).decode(errors='replace')[:1000]}")
                    if "text/event-stream" not in r.headers.get("content-type", "text/event-stream"):
                        return self._unstreamed(await r.aread(), filt)
                    raw: list[str] = []
                    saw_data = False
                    async for line in r.aiter_lines():
                        if not line.startswith("data:"):
                            if not saw_data and len(raw) < 20000:
                                raw.append(line)
                            continue
                        saw_data = True
                        payload = line[5:].strip()
                        if payload == "[DONE]":
                            break
                        try:
                            chunk = json.loads(payload)
                        except json.JSONDecodeError:
                            continue
                        if chunk.get("error"):
                            raise RuntimeError(f"{self.profile.name}: stream error: {json.dumps(chunk['error'])[:1000]}")
                        if chunk.get("usage"):
                            usage = chunk["usage"]
                        for ch in chunk.get("choices") or []:
                            if ch.get("index", 0) != 0:
                                continue
                            delta = ch.get("delta") or {}
                            piece = delta.get("content")
                            if piece:
                                text.append(piece)
                                filt.feed(piece)
                                emitted = True
                            for tc in delta.get("tool_calls") or []:
                                _merge_tool_delta(calls, tc)
                            if ch.get("finish_reason"):
                                finish = ch["finish_reason"]
            except _RETRY_ERRORS:
                if attempt == 4:
                    raise
                if emitted:  # the response restarts from scratch
                    filt.reset()
                await asyncio.sleep(delay)
                delay *= 2
                continue
            if not saw_data:  # the server ignored "stream" and sent a whole response
                return self._unstreamed("\n".join(raw).encode(), filt)
            filt.flush()
            message: dict[str, Any] = {"content": "".join(text) or None}
            if calls:
                message["tool_calls"] = [calls[i] for i in sorted(calls)]
            return {"choices": [{"message": message, "finish_reason": finish}], "usage": usage}
        raise RuntimeError("unreachable")

    def _unstreamed(self, body: bytes, filt: ToolCallTextFilter) -> dict[str, Any]:
        """A server that answered a streaming request with one plain completion: use it, and stop asking."""
        try:
            data = json.loads(body)
        except json.JSONDecodeError as e:
            raise RuntimeError(f"{self.profile.name}: unreadable response to a streaming request: {body[:300]!r}") from e
        if not isinstance(data, dict) or not data.get("choices"):
            raise RuntimeError(f"{self.profile.name}: unexpected response: {json.dumps(data)[:500]}")
        self.stream_ok = False
        text = (data["choices"][0].get("message") or {}).get("content") or ""
        if text:
            filt.feed(text)
            filt.flush()
        return data

    async def chat(self, messages: list[dict[str, Any]], tools: list[ToolSpec], on_delta: DeltaFn | None = None) -> LLMResponse:
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

        data = None
        if on_delta and self.stream_ok:
            try:
                data = await self._post_stream(body, on_delta)
            except _StreamRefused:
                data = await self._post(body)  # a bad request fails here too, with the server's real error
                self.stream_ok = False  # the plain request worked, so streaming is what this server refuses
        if data is None:
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


def _merge_tool_delta(calls: dict[int, dict[str, Any]], tc: dict[str, Any]) -> None:
    """Accumulate one streamed tool-call fragment (OpenAI streams the name once and the arguments in pieces)."""
    i = tc.get("index")
    if not isinstance(i, int):
        i = len(calls)
    slot = calls.setdefault(i, {"id": "", "type": "function", "function": {"name": "", "arguments": ""}})
    if tc.get("id"):
        slot["id"] = tc["id"]
    fn = tc.get("function") or {}
    name = fn.get("name")
    if name:  # some servers repeat the full name on every fragment, others split it
        cur = slot["function"]["name"]
        slot["function"]["name"] = name if not cur or name.startswith(cur) else cur + name
    args = fn.get("arguments")
    if isinstance(args, dict):  # a few servers send the parsed object in one piece
        slot["function"]["arguments"] = json.dumps(args)
    elif args:
        slot["function"]["arguments"] += args
