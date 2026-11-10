"""MCP server: Elastic (Elasticsearch / Elastic Security). Read-only.

Env: ES_URL, ES_API_KEY | ES_USER+ES_PASS, ES_VERIFY (true|false|/path/ca.pem), ES_DEFAULT_INDEX,
     ES_ALERTS_INDEX (default .alerts-security.alerts-*), ES_TIME_FIELD, ES_MAX_HITS, ES_HOST_FIELD
"""

from __future__ import annotations

import json

from mcp.server.mcpserver import MCPServer

from .common import tool_factory, READ, ESClient, dumps, env

mcp = MCPServer("elastic", instructions="Read-only Elasticsearch / Elastic Security queries for DCO.")
tool = tool_factory(mcp)
es = ESClient("ES")
DEFAULT_INDEX = env("ES_DEFAULT_INDEX", "logs-*")
ALERTS = env("ES_ALERTS_INDEX", ".alerts-security.alerts-*")
HOST_FIELD = env("ES_HOST_FIELD", "host.name")


@tool(READ)
def search(query: str = "*", index: str = "", start: str = "now-24h", end: str = "now", size: int = 50,
           fields: list[str] | None = None) -> str:
    """Lucene/query_string search over a time window. start/end accept ES date math (now-7d) or ISO-8601.
    Use `fields` to return only the fields you need."""
    return es.search(index or DEFAULT_INDEX, query, start, end, size, fields)


@tool(READ)
def search_dsl(body_json: str, index: str = "") -> str:
    """Raw Elasticsearch query DSL (JSON string) for aggregations and complex bool logic. Read-only _search."""
    return es.search_dsl(index or DEFAULT_INDEX, json.loads(body_json))


@tool(READ)
def esql(query: str) -> str:
    """Run an ES|QL query, e.g. 'FROM logs-* | WHERE @timestamp > NOW() - 1 day | STATS c=COUNT(*) BY host.name | SORT c DESC'.
    For raw rows always KEEP the columns you need (| KEEP @timestamp, host.name, process.command_line) - log
    indices have thousands of fields."""
    return es.esql(query)


@tool(READ)
def eql(query: str, index: str = "", start: str = "now-24h", end: str = "now", size: int = 50) -> str:
    """Run an EQL query (event or sequence), e.g. 'sequence by host.name [process where process.name=="winword.exe"] [process where process.name=="powershell.exe"]'."""
    return es.eql(index or DEFAULT_INDEX, query, start, end, size)


@tool(READ)
def list_indices(pattern: str = "*") -> str:
    """List indices / data streams with doc counts - use to discover where data lives. With a read-only API key
    this falls back to a per-data-stream inventory (docs, newest event) built from a read-only aggregation."""
    return es.indices(pattern)


@tool(READ)
def field_values(field: str, index: str = "", query: str = "*", start: str = "now-24h", end: str = "now",
                 size: int = 25, rarest: bool = False) -> str:
    """Stack a field: top (or rarest, for long-tail hunting) values with counts."""
    return es.field_values(index or DEFAULT_INDEX, field, query, start, end, size, rarest)


@tool(READ)
def ioc_sweep(values: list[str], index: str = "", start: str = "now-30d", end: str = "now") -> str:
    """Sweep IOCs (IPs, domains, hashes, filenames...) across all fields: per-IOC hits, first/last seen, top hosts."""
    return es.ioc_sweep(index or DEFAULT_INDEX, values, start, end, HOST_FIELD)


@tool(READ)
def alerts(query: str = "*", start: str = "now-24h", end: str = "now", size: int = 50, open_only: bool = True) -> str:
    """Elastic Security detection alerts (rule name, severity, risk, host, user, reason)."""
    q = query if not open_only else f"({query}) AND kibana.alert.workflow_status:open"
    return es.search(ALERTS, q, start, end, size, ["@timestamp", "kibana.alert.rule.name", "kibana.alert.severity",
                                                   "kibana.alert.risk_score", "kibana.alert.reason", "host.name",
                                                   "user.name", "process.command_line", "kibana.alert.workflow_status",
                                                   "threat.technique.id"])


@tool(READ)
def alerts_summary(start: str = "now-24h", end: str = "now") -> str:
    """Count open alerts by rule and severity - start triage here."""
    body = {"size": 0, "query": {"bool": {"filter": [es.time_filter(start, end), {"term": {"kibana.alert.workflow_status": "open"}}]}},
            "aggs": {"rule": {"terms": {"field": "kibana.alert.rule.name", "size": 50},
                              "aggs": {"sev": {"terms": {"field": "kibana.alert.severity"}},
                                       "hosts": {"cardinality": {"field": HOST_FIELD}}}}}}
    res = es.req("POST", f"/{ALERTS}/_search", body)
    return dumps([{"rule": b["key"], "count": b["doc_count"], "hosts": b["hosts"]["value"],
                   "severity": [s["key"] for s in b["sev"]["buckets"]]} for b in res["aggregations"]["rule"]["buckets"]])


if __name__ == "__main__":
    mcp.run()
