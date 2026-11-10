"""Security Onion and Elastic connector tests against a mock Elasticsearch. Request and response shapes follow
what a live Security Onion 3.4.0 grid returned (synthetic values): Zeek datasets are zeek.<log>, alerts live in
logs-*.alerts-so, and read-only API keys get 403 from the metadata APIs."""

from __future__ import annotations

import importlib
import json
import sys
from pathlib import Path

import httpx
import pytest
from mcp.server.mcpserver.exceptions import ToolError

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

FORBIDDEN = {"error": {"type": "security_exception", "reason": "action [indices:admin/data_stream/get] is unauthorized for API key"}, "status": 403}
INVENTORY = {"hits": {"total": {"value": 10000, "relation": "gte"}, "hits": []}, "aggregations": {"i": {"buckets": [
    {"key": ".ds-logs-zeek-so-2026.10.25-000016", "doc_count": 900, "last": {"value_as_string": "2026-11-09T23:59:00.000Z"}},
    {"key": ".ds-logs-zeek-so-2026.09.25-000014", "doc_count": 600, "last": {"value_as_string": "2026-10-25T17:00:00.000Z"}},
    {"key": ".ds-logs-suricata.alerts-so-2026.11.09-000443", "doc_count": 40, "last": {"value_as_string": "2026-11-09T22:00:00.000Z"}},
    {"key": "elastalert_status", "doc_count": 7, "last": {}}]}}}


def load(monkeypatch, module, env):
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    mod = importlib.import_module(f"compensated_anarchist.servers.{module}")
    return importlib.reload(mod)


def mock(m, base, handler, seen):
    def wrapped(req: httpx.Request):
        body = json.loads(req.content) if req.content else None
        seen.append((req.method, req.url.path, dict(req.url.params), body))
        assert req.headers["authorization"] == "ApiKey k3y"
        return handler(req.method, req.url.path, body)
    m.es.http = httpx.Client(base_url=base, headers={"Authorization": "ApiKey k3y"}, transport=httpx.MockTransport(wrapped))


def test_security_onion(monkeypatch):
    so = load(monkeypatch, "security_onion", {"SO_URL": "https://so.invalid:9200", "SO_API_KEY": "k3y"})
    seen: list = []

    def handler(method, path, body):
        if path == "/logs-*.alerts-so/_search" and "aggs" in body:
            return httpx.Response(200, json={"hits": {"total": {"value": 43}, "hits": []}, "aggregations": {"rule": {"buckets": [
                {"key": "ET MALWARE Example Beacon", "doc_count": 27, "sev": {"buckets": [{"key": "high"}]},
                 "module": {"buckets": [{"key": "suricata"}]}, "src": {"value": 1}, "dst": {"value": 2},
                 "last": {"value_as_string": "2026-11-09T19:34:59.343Z"}},
                {"key": "Security Onion - Grid Node Login Failure (SSH)", "doc_count": 16, "sev": {"buckets": [{"key": "high"}]},
                 "module": {"buckets": [{"key": "sigma"}]}, "src": {"value": 0}, "dst": {"value": 0}, "last": {}}]}}})
        if path == "/logs-*.alerts-so/_search":
            return httpx.Response(200, json={"hits": {"total": {"value": 1}, "hits": [{"_index": ".ds-logs-suricata.alerts-so-2026.11.09-000443", "_id": "a1",
                "_source": {"@timestamp": "2026-11-09T19:34:59Z", "event": {"dataset": "suricata.alert", "module": "suricata", "severity_label": "high"},
                            "rule": {"name": "ET MALWARE Example Beacon", "uuid": "2069174"}, "source": {"ip": "10.0.0.1"}, "destination": {"ip": "10.0.0.47"},
                            "network": {"community_id": "1:abc="}}}]}})
        if path == "/logs-zeek-so/_search":
            return httpx.Response(200, json={"hits": {"total": {"value": 5000}, "hits": []}, "aggregations": {"pair": {"buckets": [
                {"key": ["10.0.0.5", "10.0.0.1", 53], "doc_count": 12000, "hours": {"buckets": [{}] * 7}, "avg_bytes": {"value": 40.0}},
                {"key": ["10.0.0.9", "203.0.113.7", 443], "doc_count": 1400, "hours": {"buckets": [{}] * 24}, "avg_bytes": {"value": 3100.0}}]}}})
        if path == "/_data_stream/logs-*":
            return httpx.Response(403, json=FORBIDDEN)
        if path == "/logs-*/_search" and "i" in (body.get("aggs") or {}):
            return httpx.Response(200, json=INVENTORY)
        if path == "/_query":
            return httpx.Response(200, json={"columns": [{"name": "c", "type": "long"}, {"name": "destination.port", "type": "long"}],
                                             "values": [[4000, 443], [900, 53]]})
        return httpx.Response(404, json={"error": f"unexpected {method} {path}"})

    mock(so, "https://so.invalid:9200", handler, seen)

    summary = json.loads(so.alerts_summary())
    assert summary[0]["rule"] == "ET MALWARE Example Beacon" and summary[0]["severity"] == ["high"] and summary[0]["source"] == ["suricata"]
    assert summary[1]["source"] == ["sigma"]  # SO Detections alerts come from the same alert streams
    _, path, params, body = seen[-1]
    assert path == "/logs-*.alerts-so/_search" and params.get("ignore_unavailable") == "true"
    assert "must" not in body["query"]["bool"]  # no stale event.dataset:alert filter: everything in the alert streams is an alert
    assert body["aggs"]["rule"]["aggs"]["sev"]["terms"]["field"] == "event.severity_label"

    hits = json.loads(so.alerts('source.ip:"10.0.0.1"'))
    assert hits["hits"][0]["rule"]["uuid"] == "2069174"
    q = seen[-1][3]["query"]["bool"]["must"][0]["query_string"]["query"]
    assert q == '(source.ip:"10.0.0.1")' and "event_data.message" in seen[-1][3]["_source"]

    beacons = json.loads(so.beacon_candidates(min_connections=50))
    assert beacons[0]["dst"] == "203.0.113.7" and beacons[0]["hours_active"] == 24  # most persistent pair ranks first
    _, path, _, body = seen[-1]
    assert path == "/logs-zeek-so/_search"  # zeek stream only: multi_terms breaks on streams that lack the fields
    assert {"term": {"event.dataset": "zeek.conn"}} in body["query"]["bool"]["filter"]

    streams = json.loads(so.list_data_streams())
    assert "read-only" in streams["source"]
    zeek = streams["streams"][0]
    assert zeek == {"name": "logs-zeek-so", "docs": 1500, "backing_indices": 2, "last_event": "2026-11-09T23:59:00.000Z"}
    assert {s["name"] for s in streams["streams"]} == {"logs-zeek-so", "logs-suricata.alerts-so", "elastalert_status"}

    rows = json.loads(so.esql('FROM logs-zeek-so | WHERE event.dataset == "zeek.conn" | STATS c = COUNT(*) BY destination.port'))
    assert rows["columns"] == ["c", "destination.port"] and rows["rows"][0] == [4000, 443]
    assert seen[-1][2] == {"format": "json", "drop_null_columns": "true"}

    # the field layout reaches the model through the tool descriptions
    assert "event.dataset:zeek.dns" in so.search.__doc__ and "event.dataset:conn" not in so.search.__doc__


def test_security_onion_errors(monkeypatch):
    so = load(monkeypatch, "security_onion", {"SO_URL": "https://so.invalid:9200", "SO_API_KEY": "k3y"})

    def handler(method, path, body):
        if path.startswith("/_data_stream"):
            return httpx.Response(500, json={"error": "boom"})
        return httpx.Response(401, json={"error": {"type": "security_exception", "reason": "unable to authenticate with provided credentials"}})

    mock(so, "https://so.invalid:9200", handler, [])
    with pytest.raises(ToolError, match="HTTP 401.*unable to authenticate"):
        so.alerts()
    with pytest.raises(ToolError, match="HTTP 500"):  # only 403 falls back; other failures surface
        so.list_data_streams()
    with pytest.raises(ToolError, match="JSONDecodeError"):
        so.search_dsl("{not json")


def test_elastic(monkeypatch):
    el = load(monkeypatch, "elastic", {"ES_URL": "https://es.invalid:9200", "ES_API_KEY": "k3y"})
    seen: list = []
    cat_status = {"code": 403}

    def handler(method, path, body):
        if path.startswith("/_cat/indices"):
            if cat_status["code"] == 200:
                return httpx.Response(200, json=[{"index": "logs-x", "docs.count": "5", "store.size": "1kb", "health": "green"}])
            return httpx.Response(403, json=FORBIDDEN)
        if path == "/logs-*/_search" and "i" in (body.get("aggs") or {}):
            return httpx.Response(200, json=INVENTORY)
        if path.endswith("/_eql/search"):
            return httpx.Response(200, json={"hits": {"total": {"value": 1, "relation": "eq"}, "sequences": [{"events": [
                {"_source": {"process": {"name": "winword.exe"}}}, {"_source": {"process": {"name": "powershell.exe"}}}]}]}})
        if path == "/_query":
            return httpx.Response(200, json={"columns": [{"name": "c"}, {"name": "unused.field"}, {"name": "host.name"}],
                                             "values": [[3, None, "ws01"]]})  # older ES ignores drop_null_columns
        if path.startswith("/.alerts-security.alerts-*"):
            return httpx.Response(200, json={"hits": {"hits": []}, "aggregations": {"rule": {"buckets": [
                {"key": "Suspicious PowerShell", "doc_count": 3, "hosts": {"value": 2}, "sev": {"buckets": [{"key": "high"}]}}]}}})
        if path.endswith("/_search") and "ioc" in (body.get("aggs") or {}):
            return httpx.Response(200, json={"hits": {"hits": []}, "aggregations": {"ioc": {"buckets": {
                "evil.example": {"doc_count": 2, "first": {"value_as_string": "2026-11-01T00:00:00Z"}, "last": {"value_as_string": "2026-11-02T00:00:00Z"},
                                 "where": {"buckets": [{"key": "ws01", "doc_count": 2}]}, "idx": {"buckets": [{"key": ".ds-logs-x"}]}},
                "absent.example": {"doc_count": 0}}}}})
        return httpx.Response(404, json={"error": f"unexpected {method} {path}"})

    mock(el, "https://es.invalid:9200", handler, seen)

    inv = json.loads(el.list_indices("logs-*"))  # read-only key: _cat is forbidden -> aggregation fallback
    assert inv["streams"][0]["name"] == "logs-zeek-so" and seen[-1][1] == "/logs-*/_search"
    cat_status["code"] = 200
    assert json.loads(el.list_indices("logs-*"))[0]["index"] == "logs-x"  # privileged key: _cat passthrough

    seq = json.loads(el.eql('sequence by host.name [process where process.name == "winword.exe"] [process where process.name == "powershell.exe"]'))
    assert [e["process"]["name"] for e in seq["sequences"][0]] == ["winword.exe", "powershell.exe"]
    assert seen[-1][3]["filter"]["range"]["@timestamp"]["gte"] == "now-24h"

    out = json.loads(el.esql("FROM logs-* | STATS c = COUNT(*) BY host.name"))
    assert out["columns"] == ["c", "host.name"] and out["rows"] == [[3, "ws01"]]  # all-null column dropped client-side

    sweep = json.loads(el.ioc_sweep(["evil.example", "absent.example"]))
    assert sweep["evil.example"]["top_hosts"] == [["ws01", 2]] and sweep["absent.example"] == {"hits": 0}
    assert seen[-1][3]["aggs"]["ioc"]["aggs"]["where"]["terms"]["field"] == "host.name"

    summary = json.loads(el.alerts_summary())
    assert summary == [{"rule": "Suspicious PowerShell", "count": 3, "hosts": 2, "severity": ["high"]}]
    assert {"term": {"kibana.alert.workflow_status": "open"}} in seen[-1][3]["query"]["bool"]["filter"]
