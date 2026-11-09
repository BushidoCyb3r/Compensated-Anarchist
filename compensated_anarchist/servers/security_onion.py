"""MCP server: Security Onion 3 (read-only, via its Elasticsearch backend).

SO3 stores events in Elasticsearch data streams (e.g. logs-zeek-so); Zeek records carry event.module:zeek
with event.dataset:conn|dns|http|ssl|files|notice..., Suricata alerts carry event.dataset:alert, and alert
severity is rule.severity.

Access: authenticate with a SOC account (SO3 accepts the same username/password for Elasticsearch).
Port 9200 on the manager is not open to analysts by default: add a custom port group for 9200 and a host
group containing the harness host (Administration -> Configuration -> firewall), not raw iptables.
TLS: the grid CA is /etc/pki/ca.crt on the manager.
Security Onion Pro also ships an official MCP server (Connect API / OQL) - it can be added to harness.yaml
alongside this connector.

Env: SO_URL (https://<manager>:9200), SO_USER + SO_PASS | SO_API_KEY, SO_VERIFY (path to ca.crt | true | false),
     SO_INDEX (default "logs-*-so"), SO_ALERT_QUERY (default "event.dataset:alert"),
     SO_SEVERITY_FIELD (default "rule.severity"), SO_MAX_HITS
"""

from __future__ import annotations

import json

from mcp.server.mcpserver import MCPServer

from .common import tool_factory, READ, ESClient, dumps, env

mcp = MCPServer("security_onion", instructions="Read-only Security Onion NSM/alert data: Suricata, Zeek, Strelka, endpoint logs.")
tool = tool_factory(mcp)
es = ESClient("SO")
INDEX = env("SO_INDEX", "logs-*-so")
ALERT_Q = env("SO_ALERT_QUERY", "event.dataset:alert")
SEV = env("SO_SEVERITY_FIELD", "rule.severity")


@tool(READ)
def alerts_summary(start: str = "now-24h", end: str = "now") -> str:
    """Alerts grouped by rule/signature with severity, counts and distinct source/destination hosts."""
    body = {"size": 0, "query": {"bool": {"filter": [es.time_filter(start, end)], "must": [{"query_string": {"query": ALERT_Q}}]}},
            "aggs": {"rule": {"terms": {"field": "rule.name", "size": 75},
                              "aggs": {"sev": {"terms": {"field": SEV, "size": 3}},
                                       "src": {"cardinality": {"field": "source.ip"}},
                                       "dst": {"cardinality": {"field": "destination.ip"}},
                                       "last": {"max": {"field": "@timestamp"}}}}}}
    res = es.req("POST", f"/{INDEX}/_search", body)
    return dumps([{"rule": b["key"], "count": b["doc_count"], "severity": [s["key"] for s in b["sev"]["buckets"]],
                   "distinct_src": b["src"]["value"], "distinct_dst": b["dst"]["value"], "last_seen": b["last"].get("value_as_string")}
                  for b in res["aggregations"]["rule"]["buckets"]])


@tool(READ)
def alerts(query: str = "*", start: str = "now-24h", end: str = "now", size: int = 50) -> str:
    """Individual alerts (Suricata / Sigma / YARA) matching an optional extra query, newest first."""
    q = ALERT_Q if query.strip() in ("", "*") else f"({ALERT_Q}) AND ({query})"
    return es.search(INDEX, q, start, end, size, ["@timestamp", "rule.name", "rule.uuid", SEV, "event.module", "event.dataset",
                                                 "source.ip", "source.port", "destination.ip", "destination.port",
                                                 "network.community_id", "observer.name", "message"])


@tool(READ)
def search(query: str, start: str = "now-24h", end: str = "now", size: int = 50, fields: list[str] | None = None,
           index: str = "") -> str:
    """Search any Security Onion data with Lucene/query_string, e.g.
    'event.module:zeek AND event.dataset:dns AND dns.query.name:*.xyz'. Zeek datasets: conn, dns, http, ssl,
    files, notice, x509, smb_files, kerberos...; alerts: event.dataset:alert. Use list_data_streams to see sources."""
    return es.search(index or INDEX, query, start, end, size, fields)


@tool(READ)
def search_dsl(body_json: str, index: str = "") -> str:
    """Raw Elasticsearch DSL (JSON string) against Security Onion indices, for aggregations."""
    return es.search_dsl(index or INDEX, json.loads(body_json))


@tool(READ)
def esql(query: str) -> str:
    """ES|QL against Security Onion data (Elasticsearch 9.x), e.g. 'FROM logs-*-so | WHERE event.module=="zeek" AND event.dataset=="conn" | STATS c=COUNT(*) BY destination.ip | SORT c DESC | LIMIT 20'."""
    return es.esql(query)


@tool(READ)
def community_id_pivot(community_id: str, start: str = "now-7d", end: str = "now") -> str:
    """Pull every record (alerts, Zeek conn/dns/http/ssl/files, Strelka) sharing a network.community_id - full flow context."""
    return es.search(INDEX, f'network.community_id:"{community_id}"', start, end, 100, None, sort_desc=False)


@tool(READ)
def field_values(field: str, query: str = "*", start: str = "now-24h", end: str = "now", size: int = 25,
                 rarest: bool = False) -> str:
    """Stack a field (top or rarest values), e.g. field=dns.query.name query='event.module:zeek AND event.dataset:dns' rarest=true."""
    return es.field_values(INDEX, field, query, start, end, size, rarest)


@tool(READ)
def ioc_sweep(values: list[str], start: str = "now-30d", end: str = "now") -> str:
    """Sweep IOCs across all Security Onion data: hits, first/last seen, top source IPs."""
    return es.ioc_sweep(INDEX, values, start, end, "source.ip")


@tool(READ)
def beacon_candidates(start: str = "now-24h", end: str = "now", min_connections: int = 50, size: int = 25) -> str:
    """Find beaconing candidates in Zeek conn logs: src->dst:port pairs with many connections; returns count, distinct
    hours active and average bytes so the analyst/agent can examine interval regularity next."""
    body = {"size": 0, "query": {"bool": {"filter": [es.time_filter(start, end), {"query_string": {"query": "event.module:zeek AND event.dataset:conn"}}]}},
            "aggs": {"pair": {"multi_terms": {"terms": [{"field": "source.ip"}, {"field": "destination.ip"}, {"field": "destination.port"}],
                                              "size": 500, "min_doc_count": max(min_connections, 2)},
                              "aggs": {"hours": {"date_histogram": {"field": "@timestamp", "fixed_interval": "1h", "min_doc_count": 1}},
                                       "avg_bytes": {"avg": {"field": "client.bytes"}}}}}}
    res = es.req("POST", f"/{INDEX}/_search", body)
    rows = [{"src": b["key"][0], "dst": b["key"][1], "dport": b["key"][2], "connections": b["doc_count"],
             "hours_active": len(b["hours"]["buckets"]), "avg_client_bytes": b["avg_bytes"]["value"]}
            for b in res["aggregations"]["pair"]["buckets"]]
    rows.sort(key=lambda r: (-r["hours_active"], -r["connections"]))
    return dumps(rows[:size])


@tool(READ)
def list_data_streams(pattern: str = "logs-*") -> str:
    """List Elasticsearch data streams (where SO3 stores each log source) - verify sources before hunting."""
    res = es.req("GET", f"/_data_stream/{pattern or '*'}")
    return dumps([{"name": d["name"], "indices": len(d.get("indices", [])), "status": d.get("status")}
                  for d in res.get("data_streams", [])][:500])


if __name__ == "__main__":
    mcp.run()
