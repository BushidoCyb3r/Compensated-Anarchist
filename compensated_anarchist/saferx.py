"""Regular expressions from agents, matched with a time limit.

Python's `re` backtracks: a pattern such as (a+)+$ takes exponential time on a long line of a's, and nothing can stop
it in the thread that runs it - a connector would hang, or the whole harness when it runs in the harness's own event
loop. A pattern an agent writes may come from text an attacker planted in the data the agent read, so it is matched
in a child process that is killed after a few seconds. Plain text (no regex syntax) is matched here directly.
"""

from __future__ import annotations

import asyncio
import json
import re
import subprocess
import sys

TIMEOUT_S = 15.0
MAX_PATTERN = 500
_SYNTAX = set(".^$*+?{}[]\\|()")
_CHILD = (
    "import json, re, sys\n"
    "d = json.load(sys.stdin)\n"
    "rx = re.compile(d['pattern'], re.I if d['ignore_case'] else 0)\n"
    "test = rx.fullmatch if d['full'] else rx.search\n"
    "json.dump([i for i, s in enumerate(d['items']) if test(s)], sys.stdout)\n"
)


def _prepare(pattern: str, ignore_case: bool) -> str | None:
    """Checks the pattern; returns it lower-cased when it is plain text to match here, or None for a real regex."""
    p = str(pattern)
    if len(p) > MAX_PATTERN:
        raise ValueError(f"the pattern is longer than {MAX_PATTERN} characters; use a shorter one")
    try:
        re.compile(p, re.I if ignore_case else 0)  # compiling is quick; a bad pattern fails here, with its reason
    except re.error as e:
        raise ValueError(f"invalid regular expression {p[:80]!r}: {e}") from None
    if any(c in _SYNTAX for c in p):
        return None
    return p.lower() if ignore_case else p


def _plain(text: str, items: list[str], ignore_case: bool, full: bool) -> list[int]:
    fold = (lambda s: s.lower()) if ignore_case else (lambda s: s)  # noqa: E731
    return [i for i, s in enumerate(items) if (fold(s) == text if full else text in fold(s))]


def _too_slow(pattern: str, timeout: float) -> ValueError:
    return ValueError(f"the pattern {pattern[:80]!r} took more than {timeout:g} s to match (it backtracks too much); "
                      "use a simpler one, such as plain text or a pattern without nested repeats like (a+)+")


def _payload(pattern: str, items: list[str], ignore_case: bool, full: bool) -> bytes:
    return json.dumps({"pattern": pattern, "items": [str(s) for s in items], "ignore_case": ignore_case,
                       "full": full}).encode()


def _child_argv() -> list[str]:
    return [sys.executable, "-I", "-S", "-c", _CHILD]  # isolated: no site packages, environment or working directory


def _result(out: bytes, err: bytes, code: int | None) -> list[int]:
    if code != 0:
        lines = err.decode(errors="replace").strip().splitlines()
        raise ValueError(f"the pattern could not be matched: {lines[-1] if lines else f'exit {code}'}")
    return [int(i) for i in json.loads(out or b"[]")]


def matching(pattern: str, items: list[str], ignore_case: bool = True, full: bool = False,
             timeout: float = TIMEOUT_S) -> list[int]:
    """Indexes of the items the pattern matches (search, or fullmatch with full=True). Raises ValueError for a bad
    pattern or one that runs longer than `timeout` seconds."""
    if not items:
        return []
    plain = _prepare(pattern, ignore_case)
    if plain is not None:
        return _plain(plain, items, ignore_case, full)
    try:
        r = subprocess.run(_child_argv(), input=_payload(pattern, items, ignore_case, full), capture_output=True,
                           timeout=timeout)
    except subprocess.TimeoutExpired:
        raise _too_slow(pattern, timeout) from None
    return _result(r.stdout, r.stderr, r.returncode)


async def amatching(pattern: str, items: list[str], ignore_case: bool = True, full: bool = False,
                    timeout: float = TIMEOUT_S) -> list[int]:
    """matching() for code on the event loop: the loop keeps running while the child matches."""
    if not items:
        return []
    plain = _prepare(pattern, ignore_case)
    if plain is not None:
        return _plain(plain, items, ignore_case, full)
    proc = await asyncio.create_subprocess_exec(*_child_argv(), stdin=asyncio.subprocess.PIPE,
                                                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    try:
        out, err = await asyncio.wait_for(proc.communicate(_payload(pattern, items, ignore_case, full)), timeout)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        raise _too_slow(pattern, timeout) from None
    except BaseException:
        if proc.returncode is None:
            proc.kill()
            await proc.wait()
        raise
    return _result(out, err, proc.returncode)
