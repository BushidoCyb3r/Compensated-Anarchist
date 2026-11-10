"""Loop guard: small local models sometimes fall into a degenerate repetition loop ("2 low, 2 low, ...") and
run to max_tokens. The harness must spot it while streaming, cut the reply off, nudge, and give up cleanly."""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_harness import ScriptedBackend, write_config  # noqa: E402

from compensated_anarchist import agent as agent_mod  # noqa: E402
from compensated_anarchist.config import ModelProfile, load_config  # noqa: E402
from compensated_anarchist.history import ChatStore  # noqa: E402
from compensated_anarchist.llm.base import LLMResponse, LoopDetector, RepetitionLoop  # noqa: E402
from compensated_anarchist.llm.openai_compat import OpenAICompatBackend  # noqa: E402

REPORT = """## Bottom line
Security Onion raised 131 alerts in the last 24 hours. The top rule is ET MALWARE BPFDoor ICMP Echo Reply (40).

| Rule | Count | Severity | Top pairs |
|---|---|---|---|
| ET MALWARE BPFDoor ICMP Echo Reply | 40 | high | 10.99.1.1 -> 10.99.1.47: 24 |
| ET FILE_SHARING File Hosting Service Domain | 16 | low | 10.98.0.16 -> 10.98.0.1: 16 |
| ET INFO Observed DNS Query to VSCode Hosting Domain | 16 | low | 10.98.0.16 -> 10.98.0.1: 10 |
| ET SCAN Potential SSH Scan OUTBOUND | 9 | medium | 10.99.1.3 -> 10.98.0.16: 3 |

- 10.99.1.1 -> 10.99.1.47: 24
- 172.31.5.1 -> 172.31.5.17: 10
- 10.99.1.1 -> 10.99.1.6: 6

```
FROM logs-*.alerts-so | STATS c = COUNT(*) BY rule.name | SORT c DESC | LIMIT 10
```
Confidence: medium. Benign explanation not yet checked: both sources are .1 addresses (likely gateways).
"""


def stream(det: LoopDetector, text: str, step: int = 7) -> str | None:
    for i in range(0, len(text), step):
        if (u := det.feed(text[i:i + step])) is not None:
            return u
    return det.check(det.buf)


def test_detector_catches_loops_and_leaves_real_output_alone():
    assert stream(LoopDetector(), "Top rules by count: 40 high, 16 low, " + "2 low, " * 120) in ("2 low, ", " low, 2", "low, 2 ", "ow, 2 l", "w, 2 lo", ", 2 low", " 2 low,")
    assert stream(LoopDetector(), "Destinations: " + "10.98.0.16, " * 80) is not None
    assert stream(LoopDetector(), "x" * 30 + "\n" * 500) is not None  # whitespace loops count too
    long_unit = "The beacon interval is sixty seconds and the destination is the same. " * 8  # 71-char sentence x8
    assert stream(LoopDetector(), long_unit) is not None
    for ok in (REPORT, REPORT * 2, "\n".join(f"10.98.0.{i} -> 10.98.0.1: {i}" for i in range(200)),
               "|" + "---|" * 30 + "\n", "a" * 300):
        assert stream(LoopDetector(), ok) is None, ok[:60]


def run(cfg, monkeypatch, backend, mission="Summarize alerts"):
    monkeypatch.setattr(agent_mod, "make_backend", lambda profile: backend)
    events = []

    async def go():
        h = agent_mod.Harness(cfg, "LOOP-1", interactive=False, on_event=lambda k, d: events.append((k, d)))
        await h.start(new=True)
        out = await h.mission(mission)
        conv, msgs = h.conversation["id"], h.lead.messages
        await h.close()
        return out, conv, msgs
    out, conv, msgs = asyncio.run(go())
    return out, conv, msgs, events


def test_streamed_loop_is_cut_off_and_retried(tmp_path, monkeypatch):
    cfg = load_config(write_config(tmp_path))
    looping = "Top rules by count: 40 high, 16 low, " + "2 low, " * 400
    fake = ScriptedBackend({"lead": [(looping, []), ("**Bottom line:** 131 alerts; BPFDoor (40) is top.", [])]})
    out, conv, msgs, events = run(cfg, monkeypatch, fake)
    assert out.startswith("**Bottom line:**")
    guard = [d for k, d in events if k == "loop_guard"]
    assert len(guard) == 1 and guard[0]["where"] == "text" and not guard[0]["gave_up"] and "low" in guard[0]["unit"]
    deltas = "".join(d.get("text", "") for k, d in events if k == "delta" and d.get("agent_id") == "lead")
    assert len(deltas) < 1200  # cut off early, not streamed to the end
    assert any(k == "delta" and d.get("reset") for k, d in events)  # the dashboard drops the partial reply
    assert not any("2 low, 2 low, 2 low" in str(m.get("content")) for m in msgs if m["role"] == "assistant")
    assert any(m["role"] == "user" and "kept repeating" in m["content"] for m in msgs)
    assert "loop_guard" in {e["kind"] for e in ChatStore(cfg.history_db).events(conv)}  # kept in the record


def test_model_that_keeps_looping_is_stopped(tmp_path, monkeypatch):
    cfg = load_config(write_config(tmp_path))
    fake = ScriptedBackend({"lead": [("ok " + "10.98.0.16, " * 300, [])] * 5})
    out, _, _, events = run(cfg, monkeypatch, fake)
    assert out.startswith("(stopped: the model kept repeating itself")
    guard = [d for k, d in events if k == "loop_guard"]
    assert [g["gave_up"] for g in guard] == [False, False, True]


def test_non_streaming_backend_is_checked_after_the_fact(tmp_path, monkeypatch):
    cfg = load_config(write_config(tmp_path))

    class Plain:  # no on_delta: cannot stream
        profile_name, context_tokens = "plain", 100000

        def __init__(self):
            self.replies = ["Summary: " + "2 low, " * 200, "Done: 131 alerts."]

        async def chat(self, messages, tools):
            t = self.replies.pop(0)
            return LLMResponse(t, [], {"role": "assistant", "content": t}, "stop", {"input": 1, "output": 1})

        async def aclose(self):
            pass

    out, _, msgs, events = run(cfg, monkeypatch, Plain())
    assert out == "Done: 131 alerts." and [k for k, _ in events].count("loop_guard") == 1


def test_reasoning_loop_on_an_openai_compatible_server():
    """omlx / vLLM stream hidden reasoning as reasoning_content: a loop there is caught too."""
    chunks = [{"choices": [{"index": 0, "delta": {"reasoning_content": "I should count the pairs again. "}}]}] * 60
    body = "".join("data: " + json.dumps(c) + "\n\n" for c in chunks).encode()
    b = OpenAICompatBackend(ModelProfile(name="t", provider="openai_compat", model="m", base_url="http://llm.test/v1"))
    b.client = httpx.AsyncClient(base_url="http://llm.test/v1", transport=httpx.MockTransport(
        lambda req: httpx.Response(200, headers={"content-type": "text/event-stream"}, content=body)))

    class Sink:
        def __init__(self):
            self.det = LoopDetector()

        def __call__(self, chunk):
            pass

        def reasoning(self, chunk):
            if (u := self.det.feed(chunk)) is not None:
                raise RepetitionLoop(u, "reasoning")

    with pytest.raises(RepetitionLoop) as e:
        asyncio.run(b.chat([{"role": "user", "content": "go"}], [], on_delta=Sink()))
    assert e.value.where == "reasoning"
