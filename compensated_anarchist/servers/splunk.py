"""MCP server: Splunk (Enterprise / Enterprise Security) via the REST API on :8089. Read-only.

Env: SPLUNK_URL (https://splunk:8089), SPLUNK_TOKEN (bearer auth token) | SPLUNK_USER+SPLUNK_PASS,
     SPLUNK_VERIFY (true|false|/path/ca.pem), SPLUNK_MAX_RESULTS (default 200), SPLUNK_TIMEOUT,
     SPLUNK_EXTRA_COMMANDS (comma list of more read-only commands to allow), SPLUNK_ALLOW_MACROS (comma list, or *)
Every command in a search - the first, each one after a pipe, each one opening a subsearch - must be on the list of
read-only search and reporting commands (_ALLOWED, plus SPLUNK_EXTRA_COMMANDS); commands that write or execute
(_BLOCKED: delete, collect, outputlookup, sendemail, script, run, map, ...) are refused even when listed. A command an
installed app adds is refused until the site lists it. Macros can expand to any command, which this check cannot
see, so only the macros this connector uses (`notable`) and SPLUNK_ALLOW_MACROS run. The Splunk account's role is
still the real limit: give it no write capabilities (SETUP.md).
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
            "sendemail", "sendalert", "script", "run", "runshellscript", "map", "dump", "rest", "sendtocyberark",
            "summaryindex", "dbxquery", "dbxoutput", "dbxlookup", "outputtelemetry", "sendresults")
# Search and reporting commands that only read. Anything else, including commands installed apps add, is refused
# unless the site lists it in SPLUNK_EXTRA_COMMANDS.
_ALLOWED = frozenset("""
    search where eval stats eventstats streamstats tstats mstats mcatalog chart timechart top rare table fields rename
    sort dedup head tail reverse rex regex erex spath xmlkv xpath kvform extract kv multikv mvexpand makemv mvcombine
    nomv fillnull filldown bin bucket convert lookup inputlookup inputcsv join append appendcols appendpipe union
    multisearch transaction iplocation geostats fieldsummary metadata eventcount dbinspect makeresults gentimes
    datamodel from pivot addinfo addtotals addcoltotals accum autoregress delta trendline predict anomalydetection
    anomalies cluster kmeans contingency correlate associate xyseries untable transpose uniq return format set typer
    highlight iconify localize rangemap replace strcat makecontinuous timewrap foreach selfjoin tags concurrency
    reltime outlier abstract noop tojson fromjson
""".split())
_EXTRA = frozenset(c.strip().lower() for c in env("SPLUNK_EXTRA_COMMANDS", "").split(",") if c.strip())
_MACROS = frozenset({"notable"} | {m.strip().lower() for m in env("SPLUNK_ALLOW_MACROS", "").split(",") if m.strip()})
_INDEX_RE = re.compile(r"^[A-Za-z0-9_*:.-]{1,200}$")


def _index(index: str) -> str:
    if not _INDEX_RE.match(index or ""):
        raise ValueError(f"index: an index name or pattern such as main or wineventlog*; got {index!r}")
    return index


def _commands(spl: str, single_quotes: bool) -> list[str]:
    """The command names in a search: the first word of the search, of every pipe segment and of every subsearch
    ([...]). Quoted strings are skipped (backslash escapes); single quotes count as quotes only when asked. A first
    word followed by = or a comparison (index=main) is an implicit search, not a command."""
    quotes = "\"'" if single_quotes else '"'
    cmds, expect, i, n = [], True, 0, len(spl)
    while i < n:
        c = spl[i]
        if c in quotes:
            i += 1
            while i < n and spl[i] != c:
                i += 2 if spl[i] == "\\" else 1
            i, expect = i + 1, False
        elif c in "|[":
            i, expect = i + 1, True
        elif c.isspace() or not expect:
            i += 1
        else:
            m = re.match(r"[A-Za-z_][A-Za-z0-9_]*", spl[i:])
            if m and not re.match(r"\s*(=|!=|<|>)", spl[i + m.end():]):
                cmds.append(m.group(0).lower())
            i, expect = i + (m.end() if m else 1), False
    return cmds


def _check_spl(spl: str) -> None:
    """Raise unless every command is a read-only one and every macro is allowed. The commands are read twice, with
    and without single quotes as quotes, so a quote Splunk reads differently cannot hide a pipe."""
    for cmd in dict.fromkeys(_commands(spl, False) + _commands(spl, True)):
        if cmd in _BLOCKED:
            raise ValueError(f"SPL command not permitted by the read-only connector: {cmd}")
        if cmd not in _ALLOWED and cmd not in _EXTRA:
            raise ValueError(f"SPL command not permitted by the read-only connector: {cmd} (not on its list of "
                             "read-only commands; a site can add one with SPLUNK_EXTRA_COMMANDS)")
    if "*" not in _MACROS:
        for body in re.findall(r"`([^`]*)`", spl):
            name = body.split("(", 1)[0].strip().lower()
            if name not in _MACROS:
                raise ValueError(f"SPL macro not permitted by the read-only connector: `{body[:60]}` (a macro can hide "
                                 "any command; a site can allow one with SPLUNK_ALLOW_MACROS)")


def _spl(spl: str) -> str:
    spl = spl.strip()
    if not (spl.startswith("|") or spl.lower().startswith("search ")):
        spl = "search " + spl
    _check_spl(spl)
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
    rows = _oneshot(f"| tstats count max(_time) as last where index={_index(index)} by index, sourcetype "
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
    index = _index(index)
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
