"""Onboarded tools report complete counts. An output file is counted to its end however large it is: a 4.8 MB
Hayabusa CSV was once read only up to 4 MB, and the agent was told 6,061 detections where there were 7,123. Output
that does have to be cut (stdout past MAX_CAPTURE, a huge JSON file, long text) says so with `truncated`, so a
partial count is never passed off as the total. Runs without the sandbox (mode none), so it needs no bubblewrap."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

from compensated_anarchist import toolspecs
from compensated_anarchist.tools.forensics import PathJail

TOOL = r'''#!/usr/bin/env python3
import sys
a = sys.argv[1:]
n = int(a[a.index("-n") + 1])
if "-o" in a:  # a Hayabusa-like CSV: one quoted field spans two lines, so lines and records differ
    with open(a[a.index("-o") + 1], "w", newline="") as fh:
        fh.write("Timestamp,Level,RuleTitle,Details\n")
        for i in range(n):
            fh.write(f'2016-09-19T16:50:{i % 60:02d}Z,high,Metasploit SMB Authentication,"first line\nsecond line {i} {"x" * 300}"\n')
else:
    for i in range(n):
        print(f"hit {i} " + "y" * 300)
'''


def make_tool(tmp_path: Path) -> Path:
    tool = tmp_path / "opt" / "bigout" / "bigout"
    tool.parent.mkdir(parents=True)
    tool.write_text(TOOL)
    tool.chmod(0o755)
    return tool


def spec(tool: Path, **over) -> dict:
    s = {"name": "bigout", "binary": str(tool), "output": "csv", "output_from": "hits", "timeout_s": 60,
         "params": [{"name": "n", "type": "int", "required": True}, {"name": "hits", "type": "output_file", "ext": "csv"}],
         "argv": ["-n", "{n}", "-o", "{hits}"]}
    s.update(over)
    return s


def run(tool_spec: dict, args: dict, tmp_path: Path, name: str) -> dict:
    return asyncio.run(toolspecs.execute(tool_spec, args, PathJail([tmp_path]), tmp_path / "runs" / name,
                                         toolspecs.Sandbox("none")))


def test_an_output_file_is_counted_to_its_end(tmp_path, monkeypatch):
    monkeypatch.setattr(toolspecs, "MAX_CAPTURE", 20_000)  # far smaller than the file: the count must not depend on it
    out = run(spec(make_tool(tmp_path)), {"n": 400}, tmp_path, "csv")
    res = out["result"]
    f = Path(next(o["path"] for o in out["outputs"] if o["path"].endswith("hits.csv")))
    assert f.stat().st_size > 100_000
    assert res["rows"] == 400 and not res.get("truncated")
    assert res["columns"] == ["Timestamp", "Level", "RuleTitle", "Details"] and len(res["first"]) == toolspecs.ROWS
    assert res["first"][1]["Details"].startswith("first line\nsecond line 1 ")


def test_ndjson_and_lines_files_are_counted_to_their_end(tmp_path):
    f = tmp_path / "out.ndjson"
    f.write_text("".join(json.dumps({"i": i}) + "\n" for i in range(3000)) + "not json\n\n")
    res = toolspecs.parse_file("ndjson", f)
    assert res["rows"] == 3000 and res["unparsed_lines"] == 1 and res["first"][0] == {"i": 0}
    res = toolspecs.parse_file("lines", f)
    assert res["rows"] == 3001 and len(res["first"]) == toolspecs.ROWS


def test_cut_output_says_it_was_cut(tmp_path, monkeypatch):
    monkeypatch.setattr(toolspecs, "MAX_CAPTURE", 20_000)
    tool = make_tool(tmp_path)
    out = run(spec(tool, output="lines", output_from="stdout", params=[{"name": "n", "type": "int", "required": True}],
                   argv=["-n", "{n}"]), {"n": 400}, tmp_path, "stdout")
    res = out["result"]
    assert res["truncated"] is True and "cut at 20,000 bytes" in res["note"] and res["rows"] < 400
    small = run(spec(tool, output="lines", output_from="stdout", params=[{"name": "n", "type": "int", "required": True}],
                     argv=["-n", "{n}"]), {"n": 10}, tmp_path, "small")
    assert small["result"]["rows"] == 10 and "truncated" not in small["result"]
    big_json = tmp_path / "big.json"
    big_json.write_text("[" + ",".join("1" for _ in range(50)) + "]")
    monkeypatch.setattr(toolspecs, "MAX_JSON_FILE", 10)
    assert toolspecs.parse_file("json", big_json)["truncated"] is True
    monkeypatch.setattr(toolspecs, "MAX_JSON_FILE", 64_000_000)
    assert toolspecs.parse_file("json", big_json)["rows"] == 50
    text = tmp_path / "out.txt"
    text.write_text("z" * (toolspecs.TEXT + 5))
    assert toolspecs.parse_file("text", text)["truncated"] is True


def test_a_local_forensic_tool_says_when_its_output_was_cut(tmp_path, monkeypatch):
    import sys

    from compensated_anarchist.case import Case
    from compensated_anarchist.tools import forensics
    monkeypatch.setattr(forensics, "MAX_CAPTURE", 1000)
    fx = forensics.Forensics({}, [tmp_path], Case(tmp_path / "cases", "OUT-1"))
    cut = asyncio.run(fx._run([sys.executable, "-c", "print('a' * 5000)"]))
    assert cut.startswith("a" * 1000) and "[OUTPUT CUT: only the first 1,000 of 5,001 bytes" in cut
    whole = asyncio.run(fx._run([sys.executable, "-c", "print('b' * 10)"]))
    assert whole == "b" * 10 + "\n"
