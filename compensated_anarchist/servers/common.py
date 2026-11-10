"""Shared helpers for the Compensated Anarchist MCP connector servers."""

from __future__ import annotations

import functools
import json
import os
import re
import sys
from typing import Any, Callable

import httpx
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations

READ = ToolAnnotations(read_only_hint=True, destructive_hint=False, open_world_hint=False)
ACTION = ToolAnnotations(read_only_hint=False, destructive_hint=True, open_world_hint=False)


def tool_factory(mcp: Any) -> Callable[[ToolAnnotations], Callable]:
    """`@tool(READ)` - registers an MCP tool whose failures reach the agent with the real reason
    (HTTP status, auth error, DNS failure...) instead of a generic error, so it can adapt."""

    def tool(annotations: ToolAnnotations) -> Callable:
        def deco(fn: Callable) -> Callable:
            @functools.wraps(fn)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                try:
                    return fn(*args, **kwargs)
                except ToolError:
                    raise
                except Exception as e:
                    raise ToolError(f"{type(e).__name__}: {str(e)[:2000]}") from e

            return mcp.tool(annotations=annotations)(wrapper)

        return deco

    return tool


def env(name: str, default: str = "", required: bool = False) -> str:
    v = os.environ.get(name, default)
    if required and not v:
        print(f"missing required environment variable {name}", file=sys.stderr)
        raise SystemExit(2)
    return v


def tls_verify(value: str) -> Any:
    """'true'/'false' or a CA bundle path (e.g. DoD root CAs)."""
    if value.lower() in ("", "1", "true", "yes"):
        return True
    if value.lower() in ("0", "false", "no"):
        return False
    return value


def dumps(obj: Any, limit: int = 60000) -> str:
    s = json.dumps(obj, indent=1, default=str, ensure_ascii=False)
    return s if len(s) <= limit else s[:limit] + f"\n...[truncated {len(s) - limit} chars - narrow the query]"


class ESHTTPError(RuntimeError):
    def __init__(self, status: int, text: str):
        super().__init__(f"HTTP {status}: {text[:2000]}")
        self.status = status


def _stream_name(index: str) -> str:
    """'.ds-logs-zeek-so-2026.10.25-000016' -> 'logs-zeek-so' (backing index -> data stream)."""
    return re.sub(r"-\d{4}\.\d{2}\.\d{2}-\d+$", "", index.removeprefix(".ds-"))


class ESClient:
    """Minimal Elasticsearch / OpenSearch client (used by the Elastic and Security Onion servers)."""

    def __init__(self, prefix: str):
        url = env(f"{prefix}_URL", required=True)
        headers = {"Content-Type": "application/json"}
        auth = None
        if env(f"{prefix}_API_KEY"):
            headers["Authorization"] = f"ApiKey {env(f'{prefix}_API_KEY')}"
        elif env(f"{prefix}_USER"):
            auth = (env(f"{prefix}_USER"), env(f"{prefix}_PASS"))
        self.time_field = env(f"{prefix}_TIME_FIELD", "@timestamp")
        self.max_hits = int(env(f"{prefix}_MAX_HITS", "200"))
        self.http = httpx.Client(base_url=url.rstrip("/"), headers=headers, auth=auth,
                                 verify=tls_verify(env(f"{prefix}_VERIFY", "true")), timeout=float(env(f"{prefix}_TIMEOUT", "120")))

    def req(self, method: str, path: str, body: Any = None, params: dict[str, Any] | None = None) -> Any:
        r = self.http.request(method, path, json=body, params=params)
        if r.status_code >= 400:
            raise ESHTTPError(r.status_code, r.text)
        return r.json()

    def inventory(self, pattern: str) -> list[dict[str, Any]]:
        """Data streams/indices with doc counts and newest event, using only the `read` privilege (a terms
        aggregation on _index) - works with a least-privilege read-only API key, unlike _cat/_data_stream."""
        body = {"size": 0, "aggs": {"i": {"terms": {"field": "_index", "size": 2000},
                                          "aggs": {"last": {"max": {"field": self.time_field}}}}}}
        res = self.req("POST", f"/{pattern or '*'}/_search", body, params={"ignore_unavailable": "true"})
        out: dict[str, dict[str, Any]] = {}
        for b in res["aggregations"]["i"]["buckets"]:
            s = out.setdefault(_stream_name(b["key"]), {"name": _stream_name(b["key"]), "docs": 0, "backing_indices": 0, "last_event": None})
            s["docs"] += b["doc_count"]
            s["backing_indices"] += 1
            last = b["last"].get("value_as_string")
            if last and (s["last_event"] is None or last > s["last_event"]):
                s["last_event"] = last
        return sorted(out.values(), key=lambda s: -s["docs"])

    def time_filter(self, start: str, end: str) -> dict[str, Any]:
        return {"range": {self.time_field: {"gte": start or "now-24h", "lte": end or "now"}}}

    def search(self, index: str, query: str, start: str, end: str, size: int, fields: list[str] | None,
               sort_desc: bool = True) -> str:
        body: dict[str, Any] = {
            "size": min(size or 50, self.max_hits),
            "query": {"bool": {"filter": [self.time_filter(start, end)]}},
            "sort": [{self.time_field: {"order": "desc" if sort_desc else "asc"}}],
            "track_total_hits": True,
        }
        if query and query.strip() not in ("*", ""):
            body["query"]["bool"]["must"] = [{"query_string": {"query": query, "analyze_wildcard": True}}]
        if fields:
            body["_source"] = fields
        res = self.req("POST", f"/{index}/_search", body)
        hits = res.get("hits", {})
        total = hits.get("total", {}).get("value", 0)
        docs = [{"_index": h["_index"], "_id": h["_id"], **h.get("_source", {})} for h in hits.get("hits", [])]
        out: dict[str, Any] = {"total": total, "returned": len(docs)}
        if len(docs) < total:  # say so in the data itself: small models generalize from whatever rows they see
            out["sample"] = (f"SAMPLE: {len(docs)} of {total} matching events, newest first. Fine to read; before you "
                             f"decide anything from it (hosts, src->dst pairs, counts, a pattern, a verdict), go back and "
                             f"verify over the full window with pair_counts or field_values.")
        out["hits"] = docs
        return dumps(out)

    def pair_counts(self, index: str, query: str, start: str, end: str, a: str, b: str, size: int) -> str:
        """Count events per (a, b) value pair over the WHOLE window - e.g. who talked to whom."""
        n = max(1, min(size or 20, 100))
        body: dict[str, Any] = {
            "size": 0, "track_total_hits": True,
            "query": {"bool": {"filter": [self.time_filter(start, end)]}},
            "aggs": {"a": {"terms": {"field": a, "size": n}, "aggs": {"b": {"terms": {"field": b, "size": n}}}},
                     "a_n": {"cardinality": {"field": a}}, "b_n": {"cardinality": {"field": b}}},
        }
        if query and query.strip() not in ("*", ""):
            body["query"]["bool"]["must"] = [{"query_string": {"query": query, "analyze_wildcard": True}}]
        res = self.req("POST", f"/{index}/_search", body, params={"ignore_unavailable": "true"})
        total = res.get("hits", {}).get("total", {}).get("value", 0)
        aggs = res.get("aggregations") or {}
        pairs = sorted(((x["key"], y["key"], y["doc_count"]) for x in aggs.get("a", {}).get("buckets", [])
                        for y in x.get("b", {}).get("buckets", [])), key=lambda t: -t[2])[:n]
        covered = sum(c for _, _, c in pairs)
        out: dict[str, Any] = {"query": query or "*", "total_events": total, f"distinct_{a}": aggs.get("a_n", {}).get("value"),
                               f"distinct_{b}": aggs.get("b_n", {}).get("value"),
                               "pairs": [f"{x} -> {y}: {c}" for x, y, c in pairs]}
        if covered < total:
            out["not_in_pairs"] = (f"{total - covered} of {total} events are not in these pairs (more pairs than size={n}, "
                                   f"or events without {a}/{b}). Raise size or narrow the query before saying 'all'.")
        return dumps(out)

    def search_dsl(self, index: str, body: dict[str, Any]) -> str:
        body = dict(body)
        body["size"] = min(int(body.get("size", 50)), self.max_hits)
        res = self.req("POST", f"/{index}/_search", body)
        return dumps({"total": res.get("hits", {}).get("total"), "hits": [h.get("_source") for h in res.get("hits", {}).get("hits", [])],
                      "aggregations": res.get("aggregations")})

    def esql(self, query: str) -> str:
        # without KEEP, ES|QL returns every mapped field (thousands on a SIEM) - drop all-null columns server-side
        # (drop_null_columns, ES 8.13+) and again client-side for older clusters
        res = self.req("POST", "/_query", {"query": query}, params={"format": "json", "drop_null_columns": "true"})
        cols = [c["name"] for c in res.get("columns", [])]
        rows = res.get("values", [])[: self.max_hits]
        keep = [i for i in range(len(cols)) if any(i < len(r) and r[i] is not None for r in rows)] if rows else list(range(len(cols)))
        if len(keep) < len(cols):
            cols, rows = [cols[i] for i in keep], [[r[i] for i in keep] for r in rows]
        return dumps({"columns": cols, "rows": rows, "returned": len(rows)})

    def eql(self, index: str, query: str, start: str, end: str, size: int) -> str:
        body = {"query": query, "size": min(size or 50, self.max_hits), "filter": self.time_filter(start, end)}
        res = self.req("POST", f"/{index}/_eql/search", body)
        h = res.get("hits", {})
        out = {"total": h.get("total"), "events": [e.get("_source") for e in h.get("events", [])],
               "sequences": [[e.get("_source") for e in s.get("events", [])] for s in h.get("sequences", [])]}
        return dumps(out)

    def indices(self, pattern: str) -> str:
        try:
            res = self.req("GET", f"/_cat/indices/{pattern or '*'}", params={"format": "json", "h": "index,docs.count,store.size,health",
                                                                            "s": "index", "expand_wildcards": "open"})
            return dumps(res[:500])
        except ESHTTPError as e:
            if e.status != 403:
                raise
        return dumps({"source": "aggregation on _index (API key lacks monitor/view_index_metadata - expected for read-only keys)",
                      "streams": self.inventory(pattern)[:500]})

    def field_values(self, index: str, field: str, query: str, start: str, end: str, size: int, rare: bool) -> str:
        body: dict[str, Any] = {
            "size": 0,
            "query": {"bool": {"filter": [self.time_filter(start, end)]}},
            "aggs": {"v": {"terms": {"field": field, "size": min(size or 25, 500),
                                     "order": {"_count": "asc" if rare else "desc"}}}},
        }
        if query and query.strip() not in ("*", ""):
            body["query"]["bool"]["must"] = [{"query_string": {"query": query}}]
        res = self.req("POST", f"/{index}/_search", body)
        return dumps({"field": field, "mode": "rarest" if rare else "top",
                      "buckets": [(b["key"], b["doc_count"]) for b in res["aggregations"]["v"]["buckets"]]})

    def ioc_sweep(self, index: str, values: list[str], start: str, end: str, group_field: str) -> str:
        filters = {v: {"query_string": {"query": '"' + v.replace('"', "") + '"'}} for v in values[:100]}
        body = {
            "size": 0,
            "query": {"bool": {"filter": [self.time_filter(start or "now-30d", end)]}},
            "aggs": {"ioc": {"filters": {"filters": filters}, "aggs": {
                "first": {"min": {"field": self.time_field}}, "last": {"max": {"field": self.time_field}},
                "where": {"terms": {"field": group_field, "size": 10}},
                "idx": {"terms": {"field": "_index", "size": 5}}}}},
        }
        res = self.req("POST", f"/{index}/_search", body)
        out = {}
        for v, b in res["aggregations"]["ioc"]["buckets"].items():
            out[v] = {"hits": b["doc_count"]}
            if b["doc_count"]:
                out[v].update(first_seen=b["first"].get("value_as_string"), last_seen=b["last"].get("value_as_string"),
                              top_hosts=[(x["key"], x["doc_count"]) for x in b["where"]["buckets"]],
                              indices=[x["key"] for x in b["idx"]["buckets"]])
        return dumps(out)
