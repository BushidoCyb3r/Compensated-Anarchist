"""MCP server: Splunk (Enterprise / Enterprise Security) via the REST API on :8089. Read-only.

Env: SPLUNK_URL (https://splunk:8089), SPLUNK_TOKEN (bearer auth token) | SPLUNK_USER+SPLUNK_PASS,
     SPLUNK_VERIFY (true|false|/path/ca.pem), SPLUNK_MAX_RESULTS (default 200), SPLUNK_TIMEOUT
SPL that writes or executes (delete, collect, outputlookup, sendemail, script, run, map, ...) is refused here;
search is read-only by construction, independent of the harness ROE.
"""

from __future__ import annotations

import re

import httpx
from mcp.server.mcpserver import MCPServer

from .common import tool_factory, READ, dumps, env, tls_verify

mcp = MCPServer("splunk", instructions="Read-only Splunk searches for DCO (SPL).")
tool = tool_factory(mcp)

_headers = {}
_auth = None
if env("SPLUNK_TOKEN"):
    _headers["Authorization"] = f"Bearer {env('SPLUNK_TOKEN')}"
else:
    _auth = (env("SPLUNK_USER", required=True), env("SPLUNK_PASS"))
http = httpx.Client(base_url=env("SPLUNK_URL", required=True).rstrip("/"), headers=_headers, auth=_auth,
                    verify=tls_verify(env("SPLUNK_VERIFY", "true")), timeout=float(env("SPLUNK_TIMEOUT", "300")))
MAX = int(env("SPLUNK_MAX_RESULTS", "200"))

_BLOCKED = ("delete", "collect", "mcollect", "meventcollect", "tscollect", "outputlookup", "outputcsv", "outputtext",
            "sendemail", "sendalert", "script", "run", "runshellscript", "map", "dump", "rest", "sendtocyberark")
_BLOCK_RE = re.compile(r"\|\s*(" + "|".join(_BLOCKED) + r")\b", re.I)


def _spl(spl: str) -> str:
    spl = spl.strip()
    if _BLOCK_RE.search(spl):
        raise ValueError(f"SPL command not permitted by the read-only connector: {_BLOCK_RE.search(spl).group(1)}")
    if not (spl.startswith("|") or spl.lower().startswith("search ")):
        spl = "search " + spl
    return spl


def _oneshot(spl: str, earliest: str, latest: str, count: int) -> list[dict]:
    r = http.post("/services/search/jobs", data={
        "search": _spl(spl), "exec_mode": "oneshot", "output_mode": "json", "count": min(count, MAX),
        "earliest_time": earliest, "latest_time": latest})
    if r.status_code >= 400:
        raise RuntimeError(f"HTTP {r.status_code}: {r.text[:2000]}")
    data = r.json()
    msgs = [m.get("text") for m in data.get("messages", []) if m.get("type") in ("ERROR", "FATAL")]
    if msgs:
        raise RuntimeError("; ".join(msgs))
    return data.get("results", [])


@tool(READ)
def search(spl: str, earliest: str = "-24h", latest: str = "now", max_results: int = 100) -> str:
    """Run an SPL search (blocking oneshot). Always set index= and a time window; prefer stats/tstats.
    e.g. 'index=wineventlog EventCode=4625 | stats count by src_ip, user | sort -count'."""
    rows = _oneshot(spl, earliest, latest, max_results)
    return dumps({"returned": len(rows), "results": rows})


@tool(READ)
def list_indexes() -> str:
    """List indexes the account can search, with event counts and time range."""
    rows = _oneshot("| eventcount summarize=false index=* index=_* | stats sum(count) as events by index", "0", "now", 1000)
    return dumps(rows)


@tool(READ)
def data_inventory(index: str = "*", earliest: str = "-7d") -> str:
    """Which sourcetypes/hosts feed an index (tstats) - verify data exists and learn field sources before hunting."""
    rows = _oneshot(f"| tstats count max(_time) as last where index={index} by index, sourcetype "
                    f"| eval last=strftime(last, \"%Y-%m-%dT%H:%M:%SZ\") | sort -count", earliest, "now", 500)
    return dumps(rows)


@tool(READ)
def field_summary(spl: str, earliest: str = "-24h", latest: str = "now") -> str:
    """Field names, coverage and distinct counts for events matching a base search (fieldsummary)."""
    rows = _oneshot(f"{_spl(spl)} | head 5000 | fieldsummary maxvals=5 | table field count distinct_count values",
                    earliest, latest, 300)
    return dumps(rows)


@tool(READ)
def ioc_sweep(values: list[str], index: str = "*", earliest: str = "-30d", latest: str = "now") -> str:
    """Sweep IOCs across indexes; per IOC: hit count, first/last seen, indexes, sourcetypes, hosts."""
    out = {}
    for v in values[:50]:
        v = v.replace('"', "")
        if re.fullmatch(r"[\w.\-:@]+", v):
            spl = (f"| tstats count min(_time) as first max(_time) as last values(sourcetype) as sourcetypes "
                   f"values(host) as hosts where index={index} TERM({v}) by index")
        else:
            spl = (f'search index={index} "{v}" | stats count min(_time) as first max(_time) as last '
                   f"values(sourcetype) as sourcetypes values(host) as hosts by index")
        spl += ' | eval first=strftime(first,"%Y-%m-%dT%H:%M:%SZ"), last=strftime(last,"%Y-%m-%dT%H:%M:%SZ")'
        try:
            out[v] = _oneshot(spl, earliest, latest, 50)
        except Exception as e:
            out[v] = f"error: {e}"
    return dumps(out)


@tool(READ)
def notable_events(earliest: str = "-24h", latest: str = "now", status: str = "new", max_results: int = 100) -> str:
    """Splunk Enterprise Security notable events (requires ES). status: new|in progress|pending|resolved|closed|*."""
    flt = "" if status == "*" else f'| where status_label="{status}"'
    spl = (f"`notable` {flt} | table _time, rule_name, urgency, status_label, owner, src, dest, user, "
           f"security_domain, annotations.mitre_attack | sort -_time")
    return dumps(_oneshot(spl, earliest, latest, max_results))


if __name__ == "__main__":
    mcp.run()
