"""ROE scope hardening: Velociraptor client ids resolve to hostname/IP so CIDR/hostname scope rules apply;
unresolvable targets fail closed; protected-asset aliases escalate to approval."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from compensated_anarchist.audit import AuditLog  # noqa: E402
from compensated_anarchist.roe import RoeGate  # noqa: E402

ALIASES = {"C.1111111111111111": ["ws01", "ws01.corp.example", "10.1.2.3"],
           "C.2222222222222222": ["dc01", "dc01.corp.example", "10.1.1.5"],
           "C.3333333333333333": ["kiosk", "kiosk.guest", "192.168.50.9"]}


def gate(tmp_path, asked):
    roe = yaml.safe_load((ROOT / "config" / "roe.yaml").read_text())
    roe["scope"]["allowed_targets"] = ["10.0.0.0/8", "*.corp.example"]
    roe["scope"]["protected_assets"] = ["dc01*"]
    (tmp_path / "roe.yaml").write_text(yaml.safe_dump(roe))

    async def approver(tool, args, rationale, why):
        asked.append(why)
        return True, "ok"

    g = RoeGate(tmp_path / "roe.yaml", AuditLog(tmp_path / "a.jsonl", "t"), approver)

    async def resolver(tool, value):
        return ALIASES.get(value, [])

    g.target_resolver = resolver
    return g


def test_scope_resolution(tmp_path):
    asked: list[str] = []
    g = gate(tmp_path, asked)
    run = lambda tool, cid: asyncio.run(g.authorize(tool, {"client_id": cid}, "brief", "incident_responder"))  # noqa: E731

    d = run("velociraptor_admin__quarantine_host", "C.1111111111111111")
    assert d.allowed and "in scope as" in asked[-1]
    d = run("velociraptor_admin__quarantine_host", "C.3333333333333333")  # guest network, outside CIDR + domain
    assert not d.allowed and "outside authorized scope" in d.reason and "192.168.50.9" in d.reason
    d = run("velociraptor_admin__quarantine_host", "C.9999999999999999")  # unknown client -> fail closed
    assert not d.allowed and "unresolvable" in d.reason
    n = len(asked)
    d = run("velociraptor__collect_artifact", "C.2222222222222222")  # protected DC escalates even a notify-tier call
    assert d.allowed and len(asked) == n + 1 and "PROTECTED ASSET" in asked[-1]
    # read-only tools are never blocked by scope (querying about anything is fine)
    d = run("velociraptor__client_info", "C.9999999999999999")
    assert d.allowed and d.tier == "auto"


def test_local_run_tiers_for_static_parsers(tmp_path):
    """olevba and pescan only read and print: notify. Tools that can load plugin, decoder or signature scripts, or
    write files, stay at approve, and the approval note tells the analyst what to look for."""
    g = gate(tmp_path, [])
    tier = lambda binary: g.classify("local_run", {"binary": binary, "args": ["/x/sample.doc"]})  # noqa: E731
    assert tier("olevba")[0] == "notify" and tier("pescan")[0] == "notify" and tier("fls")[0] == "notify"
    for b in ("oledump.py", "pdfid.py", "pdf-parser.py", "diec", "densityscout"):
        t, why = tier(b)
        assert t == "approve" and "--plugins" in why, b


def test_pytest_never_collects_agent_written_code():
    """Agents write code into case folders (the code writer's test files); collecting a test file imports it and runs
    its top-level code, so pytest looks only in tests/ and never descends into case, evidence or data folders."""
    import tomllib
    from pathlib import Path

    cfg = tomllib.loads((Path(__file__).resolve().parents[1] / "pyproject.toml").read_text())["tool"]["pytest"]["ini_options"]
    assert cfg["testpaths"] == ["tests"]
    assert {"cases", "forensics", "evidence", "data", "tool_specs"} <= set(cfg["norecursedirs"])


def test_evidence_hashing_works_in_fips_mode(tmp_path, monkeypatch):
    """On a FIPS-mode host hashlib.md5()/sha1() raise unless usedforsecurity=False: evidence hashing must not."""
    import hashlib

    from compensated_anarchist import case

    real_md5, real_sha1 = hashlib.md5, hashlib.sha1

    def fips(real):
        def h(*a, usedforsecurity=True, **k):
            if usedforsecurity:
                raise ValueError("[digital envelope routines] unsupported (FIPS mode)")
            return real(*a, usedforsecurity=False, **k)
        return h
    monkeypatch.setattr(hashlib, "md5", fips(real_md5))
    monkeypatch.setattr(hashlib, "sha1", fips(real_sha1))
    f = tmp_path / "e.bin"
    f.write_bytes(b"evidence")
    h = case.sha256_file(f)
    assert h["md5"] == real_md5(b"evidence").hexdigest() and len(h["sha256"]) == 64


def test_source_has_no_invisible_or_bidi_characters():
    """Trojan Source: invisible and bidi control characters make code read differently from how it runs."""
    import re
    import subprocess
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    ranges = [(0x200B, 0x200F), (0x202A, 0x202E), (0x2060, 0x2064), (0x2066, 0x2069), (0xFEFF, 0xFEFF), (0xAD, 0xAD)]
    bad = re.compile("[" + "".join(f"{chr(a)}-{chr(b)}" for a, b in ranges) + "]")  # from numbers: no such character here
    hits = []
    for f in subprocess.run(["git", "ls-files"], capture_output=True, text=True, cwd=root).stdout.split():
        try:
            text = (root / f).read_text(encoding="utf-8")
        except (UnicodeDecodeError, IsADirectoryError, FileNotFoundError):
            continue
        hits += [f"{f}:{i}" for i, line in enumerate(text.splitlines(), 1) if bad.search(line)]
    assert hits == []


def test_untrusted_xml_with_entities_is_refused():
    import pytest

    from compensated_anarchist import xmlsafe

    laughs = b'<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;">]><x>&lol2;</x>'
    xxe = '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>'
    for doc in (laughs, xxe, xxe.encode("utf-16"), xxe.encode("utf-16-le")):
        with pytest.raises(ValueError, match="declares entities"):
            xmlsafe.fromstring(doc)
    nmap = b'<?xml version="1.0"?><!DOCTYPE nmaprun><nmaprun scanner="nmap"><host><address addr="10.0.0.5"/></host></nmaprun>'
    assert xmlsafe.fromstring(nmap).find("host/address").get("addr") == "10.0.0.5"  # a plain DOCTYPE is fine


def test_index_names_cannot_become_other_elasticsearch_apis(monkeypatch):
    """An agent's index argument goes into the request path: '/', '?', '#' or an API name (_security, _delete_by_query)
    must never reach Elasticsearch, where it could turn a search into a delete with the search's own query."""
    import importlib

    import httpx
    import pytest
    from mcp.server.mcpserver.exceptions import ToolError

    from compensated_anarchist.servers.common import check_index

    for ok in ("logs-*", "logs-zeek-so", ".ds-logs-x-000001", "remote:logs-*", "logs-*,-logs-old", "*"):
        assert check_index(ok) == ok
    for bad in ("logs-*/_delete_by_query?x=", "../_cluster/settings#", "_security", "logs-*,_all/_doc",
                "logs zeek", "a?b", "a#b", "%2e%2e", "", "-_cat"):
        with pytest.raises(ValueError):
            check_index(bad)
    monkeypatch.setenv("ES_URL", "https://es.invalid")
    monkeypatch.setenv("ES_API_KEY", "k")
    el = importlib.reload(importlib.import_module("compensated_anarchist.servers.elastic"))
    sent = []
    el.es.http = httpx.Client(base_url="https://es.invalid", transport=httpx.MockTransport(lambda r: sent.append(r) or httpx.Response(200, json={})))
    with pytest.raises(ToolError, match="index"):
        el.search("*", index="logs-*/_delete_by_query?x=")
    assert sent == []  # refused before anything was sent


def test_splunk_blocks_write_commands_and_index_injection(monkeypatch):
    import importlib

    import pytest
    from mcp.server.mcpserver.exceptions import ToolError

    monkeypatch.setenv("SPLUNK_URL", "https://splunk.invalid:8089")
    monkeypatch.setenv("SPLUNK_TOKEN", "t")
    sp = importlib.reload(importlib.import_module("compensated_anarchist.servers.splunk"))
    for spl in ("index=main | summaryindex index=evil", "| dbxquery query=\"DROP TABLE x\"", "index=main | collect index=x"):
        with pytest.raises(ValueError, match="not permitted"):
            sp._spl(spl)
    with pytest.raises(ToolError, match="index"):
        sp.data_inventory(index="* | outputlookup x.csv")


def test_roe_drift_is_reported(tmp_path):
    """A site ROE file is a copy made at install time: rules a later update ships are missing from it, so doctor and
    start say which. A site rule of its own for the same match, at any tier, is the site's choice."""
    from compensated_anarchist.roe import drift_note, missing_shipped_rules
    shipped, site = tmp_path / "roe.yaml", tmp_path / "roe.local.yaml"
    shipped.write_text(yaml.safe_dump({"rules": [{"match": "cte_*", "tier": "auto"},
                                                 {"match": "local_run", "tier": "notify", "args": {"binary": ["olevba"]}},
                                                 {"match": "local_run", "tier": "approve"}]}))
    site.write_text(yaml.safe_dump({"default_tier": "approve", "rules": [{"match": "local_run", "tier": "approve"}]}))
    assert [(r["match"], r.get("args")) for r in missing_shipped_rules(site, shipped)] == [
        ("cte_*", None), ("local_run", {"binary": ["olevba"]})]
    note = drift_note(site, shipped)
    assert "2 rule(s)" in note and "cte_* (auto)" in note and "default tier (approve)" in note
    site.write_text(yaml.safe_dump({"rules": [{"match": "cte_*", "tier": "deny"},  # the site's own choice
                                              {"match": "local_run", "tier": "deny", "args": {"binary": ["olevba"]}},
                                              {"match": "local_run", "tier": "approve"}]}))
    assert missing_shipped_rules(site, shipped) == [] and drift_note(site, shipped) == ""
    assert missing_shipped_rules(shipped, shipped) == []  # running on the shipped file itself
