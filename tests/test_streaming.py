"""Token streaming: provider parsing (OpenAI-compatible SSE, Anthropic SDK stream), the agent's delta events,
the dashboard's live-text catch-up, and fallbacks when a gateway will not stream."""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

import httpx
import pytest
from starlette.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_dashboard import login, make  # noqa: E402
from test_harness import ScriptedBackend, write_config  # noqa: E402

from compensated_anarchist import agent as agent_mod  # noqa: E402
from compensated_anarchist.config import ModelProfile, load_config  # noqa: E402
from compensated_anarchist.history import ChatStore  # noqa: E402
from compensated_anarchist.llm import openai_compat  # noqa: E402
from compensated_anarchist.llm.base import ToolCallTextFilter, ToolSpec  # noqa: E402
from compensated_anarchist.llm.openai_compat import OpenAICompatBackend  # noqa: E402

TOOLS = [ToolSpec("case_add_ioc", "Record an IOC", {"type": "object", "properties": {"type": {"type": "string"}, "value": {"type": "string"}}})]
MSGS = [{"role": "system", "content": "sys"}, {"role": "user", "content": "go"}]


def sse_lines(chunks: list) -> bytes:
    out = []
    for c in chunks:
        out.append("data: " + (c if isinstance(c, str) else json.dumps(c)) + "\n\n")
    return "".join(out).encode()


def oa_backend(handler, **profile) -> OpenAICompatBackend:
    b = OpenAICompatBackend(ModelProfile(name="t", provider="openai_compat", model="m", base_url="http://llm.test/v1", **profile))
    b.client = httpx.AsyncClient(base_url="http://llm.test/v1", transport=httpx.MockTransport(handler))
    return b


def delta(content=None, tool_calls=None, finish=None):
    d = {}
    if content is not None:
        d["content"] = content
    if tool_calls is not None:
        d["tool_calls"] = tool_calls
    return {"choices": [{"index": 0, "delta": d, "finish_reason": finish}]}


STREAM = [
    delta("Pivoting "), delta("on the flow."),
    delta(tool_calls=[{"index": 0, "id": "call_1", "type": "function", "function": {"name": "case_add_ioc", "arguments": ""}}]),
    delta(tool_calls=[{"index": 0, "function": {"arguments": "{\"type\": \"ipv4\", "}}]),
    delta(tool_calls=[{"index": 0, "function": {"arguments": "\"value\": \"203.0.113.7\"}"}}]),
    # a second call whose name arrives split, and a server that repeats it in full
    delta(tool_calls=[{"index": 1, "id": "call_2", "function": {"name": "case_add", "arguments": "{\"type\": "}}]),
    delta(tool_calls=[{"index": 1, "function": {"name": "_ioc", "arguments": "\"domain\", \"value\": \"cdn-static.example\"}"}}]),
    delta(tool_calls=[{"index": 1, "function": {"name": "case_add_ioc"}}]),
    delta(finish="tool_calls"),
    {"choices": [], "usage": {"prompt_tokens": 50, "completion_tokens": 12}},
    "[DONE]",
]


def test_openai_stream_reassembles_text_and_tool_calls():
    seen = []

    def handler(req: httpx.Request) -> httpx.Response:
        body = json.loads(req.content)
        seen.append(body)
        assert body["stream"] is True and body["stream_options"] == {"include_usage": True}
        return httpx.Response(200, headers={"content-type": "text/event-stream"}, content=sse_lines(STREAM))

    b = oa_backend(handler)
    pieces = []
    r = asyncio.run(b.chat(MSGS, TOOLS, on_delta=pieces.append))
    assert "".join(pieces) == r.text == "Pivoting on the flow."
    assert [(c.id, c.name, c.arguments) for c in r.tool_calls] == [
        ("call_1", "case_add_ioc", {"type": "ipv4", "value": "203.0.113.7"}),
        ("call_2", "case_add_ioc", {"type": "domain", "value": "cdn-static.example"})]
    assert r.stop_reason == "tool_calls" and r.usage == {"input": 50, "output": 12}
    assert r.assistant_message["tool_calls"][0]["function"]["name"] == "case_add_ioc"

    # without a sink the request is not streamed
    def plain(req):
        assert "stream" not in json.loads(req.content)
        return httpx.Response(200, json={"choices": [{"message": {"content": "ok"}, "finish_reason": "stop"}]})
    assert asyncio.run(oa_backend(plain).chat(MSGS, TOOLS)).text == "ok"
    # profile.stream = false turns it off even with a sink
    out = []
    assert asyncio.run(oa_backend(plain, stream=False).chat(MSGS, TOOLS, on_delta=out.append)).text == "ok" and out == []


def test_text_mode_tool_calls_are_not_streamed():
    chunks = [delta("Checking the "), delta("host.<tool"), delta('_call>{"name": "case_add_ioc", "arguments": {"type": "ipv4", '),
              delta('"value": "10.1.2.3"}}</tool_call>'), delta(finish="stop"), "[DONE]"]

    def handler(req):
        return httpx.Response(200, content=sse_lines(chunks))

    pieces = []
    r = asyncio.run(oa_backend(handler, tool_mode="text").chat(MSGS, TOOLS, on_delta=pieces.append))
    assert "".join(pieces) == "Checking the host."  # the <tool_call> block never reaches the screen
    assert r.text == "Checking the host." and r.tool_calls[0].arguments == {"type": "ipv4", "value": "10.1.2.3"}

    # a held partial tag that turns out to be text is released at the end
    f_out = []
    f = ToolCallTextFilter(f_out.append)
    f.feed("a <to")
    assert "".join(f_out) == "a "
    f.feed("p> b")
    f.flush()
    assert "".join(f_out) == "a <top> b"


def test_gateway_that_refuses_streaming_falls_back():
    calls = []

    def handler(req):
        body = json.loads(req.content)
        calls.append(bool(body.get("stream")))
        if body.get("stream"):
            return httpx.Response(400, json={"error": {"message": "stream not supported"}})
        return httpx.Response(200, json={"choices": [{"message": {"content": "plain answer"}, "finish_reason": "stop"}],
                                         "usage": {"prompt_tokens": 3, "completion_tokens": 2}})

    b = oa_backend(handler)
    out = []
    assert asyncio.run(b.chat(MSGS, TOOLS, on_delta=out.append)).text == "plain answer"
    assert asyncio.run(b.chat(MSGS, TOOLS, on_delta=out.append)).text == "plain answer"
    assert calls == [True, False, False] and b.stream_ok is False  # asked once, then stopped asking

    # a request that is bad either way surfaces the server's error and keeps streaming enabled
    def bad(req):
        return httpx.Response(400, json={"error": {"message": "context length exceeded"}})
    b2 = oa_backend(bad)
    with pytest.raises(RuntimeError, match="context length exceeded"):
        asyncio.run(b2.chat(MSGS, TOOLS, on_delta=out.append))
    assert b2.stream_ok is True


@pytest.mark.parametrize("ctype", ["application/json", ""])  # labelled JSON, or unlabelled
def test_gateway_that_ignores_stream_flag(ctype):
    body = json.dumps({"choices": [{"message": {"content": "whole reply", "tool_calls": [
        {"id": "c1", "type": "function", "function": {"name": "case_add_ioc", "arguments": "{\"type\": \"ipv4\", \"value\": \"10.1.2.3\"}"}}]},
        "finish_reason": "tool_calls"}], "usage": {"prompt_tokens": 9, "completion_tokens": 4}}).encode()

    def handler(req):
        return httpx.Response(200, headers={"content-type": ctype} if ctype else {}, content=body)

    b = oa_backend(handler)
    out = []
    r = asyncio.run(b.chat(MSGS, TOOLS, on_delta=out.append))
    assert r.text == "whole reply" and "".join(out) == "whole reply" and r.tool_calls[0].arguments["value"] == "10.1.2.3"
    assert r.usage == {"input": 9, "output": 4} and b.stream_ok is False


def test_dropped_stream_retries_and_resets_partial_text(monkeypatch):
    async def no_sleep(_s):
        return None
    monkeypatch.setattr(openai_compat.asyncio, "sleep", no_sleep)

    class Broken(httpx.AsyncByteStream):
        async def __aiter__(self):
            yield sse_lines([delta("Half a sen")])
            raise httpx.RemoteProtocolError("peer closed connection without sending complete message body")

    attempts = []

    def handler(req):
        attempts.append(1)
        if len(attempts) == 1:
            return httpx.Response(200, stream=Broken())
        return httpx.Response(200, content=sse_lines([delta("Whole sentence."), delta(finish="stop"), "[DONE]"]))

    events = []
    r = asyncio.run(oa_backend(handler).chat(MSGS, TOOLS, on_delta=events.append))
    assert r.text == "Whole sentence." and len(attempts) == 2
    assert events == ["Half a sen", None, "Whole sentence."]  # None = discard what was shown


# ---------------------------------------------------------------------------
# Anthropic: the SDK's stream helper over a mocked transport
# ---------------------------------------------------------------------------
def anthropic_sse(model: str) -> bytes:
    evs = [
        ("message_start", {"type": "message_start", "message": {"id": "msg_1", "type": "message", "role": "assistant", "model": model,
                                                                  "content": [], "stop_reason": None, "stop_sequence": None,
                                                                  "usage": {"input_tokens": 40, "output_tokens": 1}}}),
        ("content_block_start", {"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}}),
        ("content_block_delta", {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": "Recording "}}),
        ("content_block_delta", {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": "the C2 address."}}),
        ("content_block_stop", {"type": "content_block_stop", "index": 0}),
        ("content_block_start", {"type": "content_block_start", "index": 1,
                                 "content_block": {"type": "tool_use", "id": "toolu_1", "name": "case_add_ioc", "input": {}}}),
        ("content_block_delta", {"type": "content_block_delta", "index": 1, "delta": {"type": "input_json_delta", "partial_json": "{\"type\": \"ipv4\", "}}),
        ("content_block_delta", {"type": "content_block_delta", "index": 1, "delta": {"type": "input_json_delta", "partial_json": "\"value\": \"203.0.113.7\"}"}}),
        ("content_block_stop", {"type": "content_block_stop", "index": 1}),
        ("message_delta", {"type": "message_delta", "delta": {"stop_reason": "tool_use", "stop_sequence": None}, "usage": {"output_tokens": 30}}),
        ("message_stop", {"type": "message_stop"}),
    ]
    return "".join(f"event: {k}\ndata: {json.dumps(v)}\n\n" for k, v in evs).encode()


@pytest.mark.parametrize("model", ["claude-test-model", "claude-opus-5-5"])  # plain and server-side-fallback (beta) paths
def test_anthropic_stream_forwards_text(model):
    anthropic = pytest.importorskip("anthropic")
    hx = pytest.importorskip("httpx2")  # the SDK's HTTP client package
    from compensated_anarchist.llm.anthropic_backend import AnthropicBackend

    reqs = []

    def handler(req):
        reqs.append(req)
        return hx.Response(200, headers={"content-type": "text/event-stream"}, content=anthropic_sse(model))

    b = AnthropicBackend(ModelProfile(name="c", provider="anthropic", model=model, api_key="test-key"))
    b.client = anthropic.AsyncAnthropic(api_key="test-key", base_url="http://anthropic.test", max_retries=0,
                                        http_client=hx.AsyncClient(transport=hx.MockTransport(handler)))
    pieces = []
    r = asyncio.run(b.chat(MSGS, TOOLS, on_delta=pieces.append))
    assert "".join(pieces) == r.text == "Recording the C2 address."
    assert [(c.name, c.arguments) for c in r.tool_calls] == [("case_add_ioc", {"type": "ipv4", "value": "203.0.113.7"})]
    assert r.usage == {"input": 40, "output": 30} and r.stop_reason == "tool_use"
    body = json.loads(reqs[0].content)
    assert body["stream"] is True
    if model == "claude-opus-5-5":
        assert "server-side-fallback" in reqs[0].headers.get("anthropic-beta", "")


# ---------------------------------------------------------------------------
# Agent and dashboard
# ---------------------------------------------------------------------------
def test_agent_emits_ordered_deltas_that_are_never_persisted(tmp_path, monkeypatch):
    cfg = load_config(write_config(tmp_path))
    answer = "## Situation report\n- **ws01** beacons to `203.0.113.7` every 60 s\n- Containment pending"
    fake = ScriptedBackend({"lead": [("Recording the IOC first.", [("case_add_ioc", {"type": "ipv4", "value": "203.0.113.7",
                                                                                         "context": "C2"})]),
                                     (answer, [])]})
    monkeypatch.setattr(agent_mod, "make_backend", lambda profile: fake)
    events = []

    async def go():
        h = agent_mod.Harness(cfg, "STREAM-1", interactive=False, on_event=lambda k, d: events.append((k, d)))
        await h.start(new=True)
        out = await h.mission("Scope the beacon")
        conv = h.conversation["id"]
        await h.close()
        return out, conv

    out, conv = asyncio.run(go())
    assert out == answer
    lead = [(k, d) for k, d in events if d.get("agent_id") == "lead" and k in ("delta", "text", "telemetry")]
    # per model call: deltas, then the text event, then telemetry
    calls, cur = [], []
    for k, d in lead:
        cur.append((k, d))
        if k == "telemetry":
            calls.append(cur)
            cur = []
    assert len(calls) == 2
    for call, expected in zip(calls, ["Recording the IOC first.", answer]):
        kinds = [k for k, _ in call]
        assert kinds[-2:] == ["text", "telemetry"] and set(kinds[:-2]) == {"delta"}
        deltas = [d for k, d in call if k == "delta"]
        pos = 0
        for d in deltas:  # contiguous offsets
            assert d["offset"] == pos
            pos += len(d["text"])
        assert "".join(d["text"] for d in deltas) == expected == call[-2][1]["text"]
        assert call[-1][1]["ttft"] is not None
    kinds = {e["kind"] for e in ChatStore(cfg.history_db).events(conv)}
    assert "text" in kinds and "delta" not in kinds and "telemetry" not in kinds


def test_delta_sink_coalesces_and_discards(tmp_path):
    events = []

    class A:
        name, agent_id = "lead", "lead"

        def on_event(self, k, d):
            events.append(d)

    async def go():
        sink = agent_mod._DeltaSink(A())
        for w in ["a", "b", "c"]:
            sink(w)
        await asyncio.sleep(agent_mod.DELTA_INTERVAL_S * 3)  # one timer flush for all three pieces
        sink("d")
        sink.flush()
        sink("e")
        sink(None)  # provider restarted: drop what was shown
        sink("f")
        sink.flush()
    asyncio.run(go())
    assert events == [{"agent": "lead", "agent_id": "lead", "text": "abc", "offset": 0},
                      {"agent": "lead", "agent_id": "lead", "text": "d", "offset": 3},
                      {"agent": "lead", "agent_id": "lead", "reset": True},
                      {"agent": "lead", "agent_id": "lead", "text": "f", "offset": 0}]


def test_dashboard_keeps_live_text_for_late_joiners(tmp_path, monkeypatch):
    dash, app = make(tmp_path, monkeypatch, {})
    with TestClient(app) as c:
        login(c)
        dash.emit("delta", {"agent": "network_analyst", "agent_id": "SA-001", "text": "Beacon to ", "offset": 0})
        dash.emit("delta", {"agent": "network_analyst", "agent_id": "SA-001", "text": "203.0.113.7", "offset": 10})
        dash.emit("delta", {"agent": "lead", "agent_id": "lead", "text": "Plan: ", "offset": 0})
        st = c.get("/api/state").json()
        assert st["live"]["SA-001"]["text"] == "Beacon to 203.0.113.7" and st["live"]["lead"]["text"] == "Plan: "
        assert st["live"]["SA-001"]["seq"] <= st["last_seq"]
        assert not [e for e in c.get("/api/events/poll?after=0").json() if e["kind"] == "delta"]  # never replayed
        dash.emit("delta", {"agent": "lead", "agent_id": "lead", "reset": True})
        dash.emit("text", {"agent": "network_analyst", "agent_id": "SA-001", "text": "Beacon to 203.0.113.7", "final": False})
        assert c.get("/api/state").json()["live"] == {}
