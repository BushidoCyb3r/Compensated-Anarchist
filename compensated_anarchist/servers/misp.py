"""MCP server: MISP threat intelligence platform (your organisation's instance).

Env: MISP_URL (https://misp.example), MISP_KEY (auth key), MISP_VERIFY (true|false|/path/ca.pem),
     MISP_MAX_RESULTS (default 100)
Read tools run freely; writes are deliberately narrow:
  - add_sighting: record that an indicator was seen in your network
  - create_event: always created UNPUBLISHED with distribution "your organisation only" - an analyst publishes
"""

from __future__ import annotations

import re
from typing import Any

import httpx
from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations

from .common import ACTION, READ, dumps, env, tls_verify, tool_factory

mcp = MCPServer("misp", instructions="MISP threat intel: IOC lookups, events, warninglists (known-benign), sightings.")
tool = tool_factory(mcp)
CHANGE = ToolAnnotations(read_only_hint=False, destructive_hint=False, open_world_hint=False)
http = httpx.Client(base_url=env("MISP_URL", required=True).rstrip("/"),
                    headers={"Authorization": env("MISP_KEY", required=True), "Accept": "application/json",
                             "Content-Type": "application/json"},
                    verify=tls_verify(env("MISP_VERIFY", "true")), timeout=float(env("MISP_TIMEOUT", "120")))
MAX = int(env("MISP_MAX_RESULTS", "100"))
THREAT = {"high": 1, "medium": 2, "low": 3, "undefined": 4}
_EVENT_ID = re.compile(r"[0-9]{1,12}|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")


def _req(method: str, path: str, body: Any = None) -> Any:
    r = http.request(method, path, json=body)
    if r.status_code >= 400:
        raise RuntimeError(f"MISP HTTP {r.status_code}: {r.text[:1500]}")
    return r.json()


def _attr(a: dict[str, Any]) -> dict[str, Any]:
    ev = a.get("Event") or {}
    return {"value": a.get("value"), "type": a.get("type"), "category": a.get("category"), "to_ids": a.get("to_ids"),
            "comment": a.get("comment"), "first_seen": a.get("first_seen"), "last_seen": a.get("last_seen"),
            "event_id": a.get("event_id"), "event_info": ev.get("info"), "event_date": ev.get("date"),
            "threat_level_id": ev.get("threat_level_id"), "org": (ev.get("Orgc") or {}).get("name"),
            "tags": sorted({t.get("name") for t in (a.get("Tag") or []) + (ev.get("Tag") or []) if t.get("name")})}


@tool(READ)
def search_ioc(values: list[str], to_ids_only: bool = False, limit_per_value: int = 20) -> str:
    """Look up indicators (IP, domain, URL, hash, filename, email...) in MISP: matching attributes with their
    events, threat level, tags (incl. ATT&CK/galaxy tags) and IDS flag. Use to enrich every IOC you find."""
    out: dict[str, Any] = {}
    for v in values[:50]:
        body: dict[str, Any] = {"returnFormat": "json", "value": v, "limit": min(limit_per_value, MAX), "page": 1,
                                "includeEventTags": True, "includeContext": True}
        if to_ids_only:
            body["to_ids"] = True
        res = _req("POST", "/attributes/restSearch", body)
        attrs = (res.get("response") or {}).get("Attribute", [])
        out[v] = {"hits": len(attrs), "attributes": [_attr(a) for a in attrs]}
    return dumps(out)


@tool(READ)
def warninglist_check(values: list[str]) -> str:
    """Check values against MISP warninglists (known-benign: public DNS resolvers, CDNs, cloud ranges, top domains...).
    A hit is strong false-positive evidence - check before escalating or blocking an indicator."""
    res = _req("POST", "/warninglists/checkValue", values[:100])
    return dumps(res)


@tool(READ)
def search_events(query: str = "", tags: list[str] | None = None, since: str = "", limit: int = 25) -> str:
    """Search MISP events by text in the event info, tags (e.g. 'misp-galaxy:threat-actor="APT28"', 'tlp:amber'),
    and a since-date (e.g. '30d' or '2026-10-01')."""
    body: dict[str, Any] = {"returnFormat": "json", "limit": min(limit, MAX), "page": 1, "metadata": True}
    if query:
        body["eventinfo"] = f"%{query}%"
    if tags:
        body["tags"] = tags
    if since:
        body["date"] = since
    res = _req("POST", "/events/restSearch", body)
    events = res.get("response", []) if isinstance(res, dict) else res
    return dumps([{"id": e["Event"].get("id"), "info": e["Event"].get("info"), "date": e["Event"].get("date"),
                   "threat_level_id": e["Event"].get("threat_level_id"), "published": e["Event"].get("published"),
                   "org": (e["Event"].get("Orgc") or {}).get("name"), "attribute_count": e["Event"].get("attribute_count"),
                   "tags": [t.get("name") for t in e["Event"].get("Tag") or []]} for e in events])


@tool(READ)
def get_event(event_id: str, max_attributes: int = 200) -> str:
    """Full MISP event: description, tags/galaxies (actors, ATT&CK), objects and attributes (indicators)."""
    eid = str(event_id).strip()
    if not _EVENT_ID.fullmatch(eid):  # it goes into the request path: nothing else may reach it (../admin/...)
        raise ValueError("event_id must be a numeric id or a UUID")
    ev = _req("GET", f"/events/view/{eid}").get("Event", {})
    galaxies = [{"galaxy": g.get("name"), "clusters": [c.get("value") for c in g.get("GalaxyCluster") or []]}
                for g in ev.get("Galaxy") or []]
    attrs = [_attr({**a, "Event": {}}) for a in (ev.get("Attribute") or [])]
    for o in ev.get("Object") or []:
        attrs += [{**_attr({**a, "Event": {}}), "object": o.get("name")} for a in o.get("Attribute") or []]
    return dumps({"id": ev.get("id"), "uuid": ev.get("uuid"), "info": ev.get("info"), "date": ev.get("date"),
                  "threat_level_id": ev.get("threat_level_id"), "analysis": ev.get("analysis"),
                  "org": (ev.get("Orgc") or {}).get("name"), "tags": [t.get("name") for t in ev.get("Tag") or []],
                  "galaxies": galaxies, "attribute_count": len(attrs), "attributes": attrs[:max_attributes]})


@tool(CHANGE)
def add_sighting(value: str, source: str = "Compensated Anarchist", sighting_type: str = "sighting") -> str:
    """Record that an indicator was observed in the defended network (type: sighting | false_positive)."""
    t = {"sighting": "0", "false_positive": "1"}.get(sighting_type)
    if t is None:
        raise ValueError("sighting_type must be sighting or false_positive")
    return dumps(_req("POST", "/sightings/add", {"value": value, "source": source, "type": t}))


@tool(ACTION)
def create_event(info: str, attributes: list[dict[str, Any]], threat_level: str = "medium", tags: list[str] | None = None) -> str:
    """Create a MISP event for this incident, UNPUBLISHED and restricted to your organisation (an analyst reviews
    and publishes it in MISP). attributes: [{type: ip-dst|domain|url|sha256|filename|..., value, category?, to_ids?, comment?}]"""
    if threat_level not in THREAT:
        raise ValueError(f"threat_level must be one of {list(THREAT)}")
    event = {"info": info[:500], "distribution": 0, "threat_level_id": THREAT[threat_level], "analysis": 1,
             "published": False,
             "Attribute": [{"type": a["type"], "value": a["value"], "category": a.get("category", "Network activity"),
                            "to_ids": bool(a.get("to_ids", True)), "comment": str(a.get("comment", ""))[:500],
                            "distribution": 5} for a in attributes[:500]],
             "Tag": [{"name": t} for t in (tags or [])]}
    res = _req("POST", "/events/add", {"Event": event})
    ev = res.get("Event", res)
    return dumps({"id": ev.get("id"), "uuid": ev.get("uuid"), "published": ev.get("published"),
                  "distribution": ev.get("distribution"), "attributes": len(event["Attribute"])})


if __name__ == "__main__":
    mcp.run()
