"""MCP server: Security Onion 3 (read-only, via its Elasticsearch backend).

Field layout verified against a live Security Onion 3.4.0 grid:
  - Zeek: data stream logs-zeek-so, event.module:zeek, event.dataset:zeek.<log> (zeek.conn, zeek.dns, zeek.http,
    zeek.ssl, zeek.file, zeek.x509, zeek.notice, zeek.weird...), plus client.bytes/server.bytes, log.id.uid.
  - Alerts: logs-suricata.alerts-so (event.dataset:suricata.alert, rule.name, rule.uuid = SID, rule.severity 1-3)
    and logs-detections.alerts-so (SO Detections: event.dataset:sigma.alert..., the matched event under event_data.*).
    Both carry event.severity_label (low|medium|high|critical).
  - network.community_id joins Suricata alerts with Zeek records.

Access: authenticate with a read-only API key (or a SOC account). Port 9200 on the manager is not open to analysts
by default: add a port group for 9200 and a host group containing the harness host (Administration ->
Configuration -> firewall), not raw iptables. TLS: the grid CA is /etc/pki/ca.crt on the manager.
A read-only key without view_index_metadata works: list_data_streams falls back to a read-only aggregation.
Security Onion Pro also ships an official MCP server (Connect API / OQL) - it can be added to harness.yaml
alongside this connector.

Env: SO_URL (https://<manager>:9200), SO_API_KEY | SO_USER + SO_PASS, SO_VERIFY (path to ca.crt | true | false),
     SO_INDEX (default "logs-*-so"), SO_ALERT_INDEX (default "logs-*.alerts-so"), SO_ZEEK_INDEX (default
     "logs-zeek-so"), SO_ALERT_QUERY (extra filter on alerts, default none), SO_SEVERITY_FIELD (default
     "event.severity_label"), SO_MAX_HITS
"""

from __future__ import annotations

import json

from mcp.server.mcpserver import MCPServer

from .common import tool_factory, READ, ESClient, ESHTTPError, dumps, env, check_index

mcp = MCPServer("security_onion", instructions="Read-only Security Onion NSM/alert data: Suricata, Zeek, Strelka, endpoint logs.")
tool = tool_factory(mcp)
es = ESClient("SO")
INDEX = env("SO_INDEX", "logs-*-so")
ALERT_INDEX = env("SO_ALERT_INDEX", "logs-*.alerts-so")
ZEEK_INDEX = env("SO_ZEEK_INDEX", "logs-zeek-so")
ALERT_Q = env("SO_ALERT_QUERY", "")
SEV = env("SO_SEVERITY_FIELD", "event.severity_label")
ALERT_FIELDS = ["@timestamp", "event.module", "event.dataset", "rule.name", "rule.uuid", "rule.category", SEV, "rule.severity",
                "source.ip", "source.port", "destination.ip", "destination.port", "network.community_id", "observer.name",
                "event_data.host.name", "event_data.user.name", "event_data.source.ip", "event_data.process.command_line",
                "event_data.message"]


def _alert_query(extra: str) -> str:
    parts = [p for p in (ALERT_Q, "" if extra.strip() in ("", "*") else extra) if p]
    return " AND ".join(f"({p})" for p in parts) or "*"


def _rule_row(b: dict) -> dict:
    pairs = sorted(((x["key"], y["key"], y["doc_count"]) for x in b.get("pairs", {}).get("buckets", [])
                    for y in x.get("dst", {}).get("buckets", [])), key=lambda t: -t[2])
    row = {"rule": b["key"], "count": b["doc_count"], "severity": [s["key"] for s in b["sev"]["buckets"]],
           "source": [m["key"] for m in b["module"]["buckets"]],
           "distinct_src": b["src"]["value"], "distinct_dst": b["dst"]["value"],
           "top_pairs": [f"{x} -> {y}: {c}" for x, y, c in pairs[:5]], "last_seen": b["last"].get("value_as_string")}
    covered = sum(c for _, _, c in pairs[:5])
    if pairs and covered < b["doc_count"]:
        row["pairs_cover"] = f"{covered} of {b['doc_count']} (use pair_counts for the rest)"
    return row


@tool(READ)
def alerts_summary(start: str = "now-24h", end: str = "now") -> str:
    """Alerts (Suricata + SO Detections/Sigma) grouped by rule over the WHOLE window: severity, source module,
    count, distinct source/destination IPs, the top source -> destination pairs with counts, and last seen.
    Start triage here; it answers "which hosts" without sampling."""
    body: dict = {"size": 0, "query": {"bool": {"filter": [es.time_filter(start, end)]}},
                  "aggs": {"rule": {"terms": {"field": "rule.name", "size": 75},
                                    "aggs": {"sev": {"terms": {"field": SEV, "size": 3}},
                                             "module": {"terms": {"field": "event.module", "size": 3}},
                                             "src": {"cardinality": {"field": "source.ip"}},
                                             "dst": {"cardinality": {"field": "destination.ip"}},
                                             "pairs": {"terms": {"field": "source.ip", "size": 5},
                                                       "aggs": {"dst": {"terms": {"field": "destination.ip", "size": 5}}}},
                                             "last": {"max": {"field": "@timestamp"}}}}}}
    if (q := _alert_query("")) != "*":
        body["query"]["bool"]["must"] = [{"query_string": {"query": q}}]
    res = es.req("POST", f"/{ALERT_INDEX}/_search", body, params={"ignore_unavailable": "true"})
    return dumps([_rule_row(b) for b in res["aggregations"]["rule"]["buckets"]])


@tool(READ)
def alerts(query: str = "*", start: str = "now-24h", end: str = "now", size: int = 50) -> str:
    """Individual alerts (Suricata, SO Detections Sigma/YARA) newest first, optionally narrowed by a query such as
    'rule.name:"ET HUNTING*"', 'event.severity_label:high', 'source.ip:10.1.2.3' or 'event.module:sigma'.
    Sigma alerts hold the matched log under event_data.* (event_data.host.name, event_data.message...).
    Returns a SAMPLE when more alerts match than `size` - good for reading; verify any conclusion about hosts or
    counts with alerts_summary or pair_counts, which count the whole window."""
    return es.search(ALERT_INDEX, _alert_query(query), start, end, size, ALERT_FIELDS)


@tool(READ)
def pair_counts(query: str = "*", start: str = "now-24h", end: str = "now", source_field: str = "source.ip",
                destination_field: str = "destination.ip", alerts_only: bool = False, size: int = 20) -> str:
    """Who talked to whom over the WHOLE window: event counts per source -> destination pair for any query, e.g.
    query='rule.name:"ET MALWARE BPFDoor*"' alerts_only=true, or query='event.dataset:zeek.conn AND destination.port:22'.
    Use it to verify what you concluded from a sample of events. Also works for other field pairs
    (e.g. source_field=source.ip destination_field=dns.query.name)."""
    return es.pair_counts(ALERT_INDEX if alerts_only else INDEX, _alert_query(query) if alerts_only else query,
                          start, end, source_field, destination_field, size)


@tool(READ)
def search(query: str, start: str = "now-24h", end: str = "now", size: int = 50, fields: list[str] | None = None,
           index: str = "") -> str:
    """Search any Security Onion data with Lucene/query_string. Zeek logs are event.dataset:zeek.<log>, e.g.
    'event.dataset:zeek.dns AND dns.query.name:*.xyz', 'event.dataset:zeek.conn AND destination.port:3389',
    'event.dataset:zeek.ssl AND NOT ssl.established:true'. Zeek datasets: zeek.conn, zeek.dns, zeek.http, zeek.ssl,
    zeek.file, zeek.x509, zeek.notice, zeek.weird, zeek.smb_files, zeek.kerberos... Alerts: event.dataset:suricata.alert
    (or use the alerts tool). Common fields: source.ip/port, destination.ip/port, network.community_id, log.id.uid,
    client.bytes, server.bytes, observer.name. `index` defaults to all SO data (logs-*-so); logs-zeek-so is faster
    for Zeek-only searches. Use list_data_streams to see which sources exist."""
    return es.search(index or INDEX, query, start, end, size, fields)


@tool(READ)
def search_dsl(body_json: str, index: str = "") -> str:
    """Raw Elasticsearch DSL (JSON string) against Security Onion indices, for aggregations."""
    return es.search_dsl(index or INDEX, json.loads(body_json))


@tool(READ)
def esql(query: str) -> str:
    """ES|QL against Security Onion data (Elasticsearch 9.x), e.g. 'FROM logs-zeek-so | WHERE event.dataset == "zeek.conn"
    AND @timestamp > NOW() - 1 day | STATS c = COUNT(*) BY destination.ip | SORT c DESC | LIMIT 20'.
    For raw rows always KEEP the columns you need (e.g. | KEEP @timestamp, source.ip, destination.ip) - SO data has
    thousands of fields."""
    return es.esql(query)


@tool(READ)
def community_id_pivot(community_id: str, start: str = "now-7d", end: str = "now") -> str:
    """Pull every record (alerts, Zeek conn/dns/http/ssl/files, Strelka) sharing a network.community_id - full flow context."""
    return es.search(INDEX, f'network.community_id:"{community_id}"', start, end, 100, None, sort_desc=False)


@tool(READ)
def field_values(field: str, query: str = "*", start: str = "now-24h", end: str = "now", size: int = 25,
                 rarest: bool = False) -> str:
    """Stack a field (top or rarest values), e.g. field=dns.query.name query='event.dataset:zeek.dns' rarest=true,
    or field=rule.name query='event.dataset:suricata.alert'."""
    return es.field_values(INDEX, field, query, start, end, size, rarest)


@tool(READ)
def ioc_sweep(values: list[str], start: str = "now-30d", end: str = "now") -> str:
    """Sweep IOCs across all Security Onion data: hits, first/last seen, top source IPs."""
    return es.ioc_sweep(INDEX, values, start, end, "source.ip")


@tool(READ)
def beacon_candidates(start: str = "now-24h", end: str = "now", min_connections: int = 50, size: int = 25) -> str:
    """Find beaconing candidates in Zeek conn logs: src->dst:port pairs with many connections; returns count, distinct
    hours active and average bytes so the analyst/agent can examine interval regularity next (expect DNS to the
    local resolver and other infrastructure chatter near the top - judge, don't assume)."""
    body = {"size": 0, "query": {"bool": {"filter": [es.time_filter(start, end), {"term": {"event.dataset": "zeek.conn"}}]}},
            "aggs": {"pair": {"multi_terms": {"terms": [{"field": "source.ip"}, {"field": "destination.ip"}, {"field": "destination.port"}],
                                              "size": 500, "min_doc_count": max(min_connections, 2)},
                              "aggs": {"hours": {"date_histogram": {"field": "@timestamp", "fixed_interval": "1h", "min_doc_count": 1}},
                                       "avg_bytes": {"avg": {"field": "client.bytes"}}}}}}
    # Zeek stream only: multi_terms fails at reduce when some indices in the pattern lack a field (SOC/Kratos streams)
    res = es.req("POST", f"/{ZEEK_INDEX}/_search", body)
    rows = [{"src": b["key"][0], "dst": b["key"][1], "dport": b["key"][2], "connections": b["doc_count"],
             "hours_active": len(b["hours"]["buckets"]), "avg_client_bytes": b["avg_bytes"]["value"]}
            for b in res["aggregations"]["pair"]["buckets"]]
    rows.sort(key=lambda r: (-r["hours_active"], -r["connections"]))
    return dumps(rows[:size])


@tool(READ)
def list_data_streams(pattern: str = "logs-*") -> str:
    """List the data streams that hold data (where SO3 stores each log source), with doc counts and newest event -
    verify a source exists before hunting in it."""
    try:
        res = es.req("GET", f"/_data_stream/{check_index(pattern or '*')}")
        return dumps([{"name": d["name"], "indices": len(d.get("indices", [])), "status": d.get("status")}
                      for d in res.get("data_streams", [])][:500])
    except ESHTTPError as e:
        if e.status != 403:
            raise
    return dumps({"source": "aggregation on _index (API key lacks view_index_metadata - expected for read-only keys)",
                  "streams": es.inventory(pattern)[:500]})


if __name__ == "__main__":
    mcp.run()
