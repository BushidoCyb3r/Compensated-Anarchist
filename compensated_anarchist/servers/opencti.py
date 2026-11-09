"""MCP server: OpenCTI (read-only) - your organisation's cyber threat intelligence platform.

GraphQL shapes follow the official pycti client (OpenCTI 6.x).
Env: OPENCTI_URL (https://opencti.example), OPENCTI_TOKEN (API token of a read-only user),
     OPENCTI_VERIFY (true|false|/path/ca.pem)
"""

from __future__ import annotations

import re
from typing import Any

import httpx
from mcp.server.mcpserver import MCPServer

from .common import READ, dumps, env, tls_verify, tool_factory

mcp = MCPServer("opencti", instructions="OpenCTI threat intel: observables, indicators, actors/malware/campaigns, relationships.")
tool = tool_factory(mcp)
http = httpx.Client(base_url=env("OPENCTI_URL", required=True).rstrip("/"),
                    headers={"Authorization": f"Bearer {env('OPENCTI_TOKEN', required=True)}",
                             "Content-Type": "application/json"},
                    verify=tls_verify(env("OPENCTI_VERIFY", "true")), timeout=float(env("OPENCTI_TIMEOUT", "120")))
SDO_TYPES = ["Intrusion-Set", "Threat-Actor-Group", "Threat-Actor-Individual", "Malware", "Campaign", "Attack-Pattern",
             "Tool", "Vulnerability", "Report", "Infrastructure"]


def gql(query: str, variables: dict[str, Any] | None = None) -> dict[str, Any]:
    r = http.post("/graphql", json={"query": query, "variables": variables or {}})
    if r.status_code >= 400:
        raise RuntimeError(f"OpenCTI HTTP {r.status_code}: {r.text[:1500]}")
    data = r.json()
    if data.get("errors"):
        raise RuntimeError("OpenCTI GraphQL: " + "; ".join(e.get("message", "") for e in data["errors"])[:1500])
    return data.get("data") or {}


def _edges(conn: dict[str, Any] | None) -> list[dict[str, Any]]:
    return [e["node"] for e in (conn or {}).get("edges", [])]


_OBSERVABLES = """
query Obs($search: String, $first: Int) {
  stixCyberObservables(search: $search, first: $first) {
    edges { node {
      id entity_type observable_value x_opencti_score created_at updated_at
      objectLabel { value }
      indicators { edges { node { id pattern pattern_type } } }
    } }
  }
}"""

_INDICATORS = """
query Ind($search: String, $first: Int) {
  indicators(search: $search, first: $first) {
    edges { node {
      id name pattern pattern_type x_opencti_score valid_from valid_until x_opencti_main_observable_type
      killChainPhases { kill_chain_name phase_name }
      objectLabel { value }
    } }
  }
}"""

_REL_ENTITY = """
  ... on BasicObject { id entity_type }
  ... on AttackPattern { name x_mitre_id }
  ... on Campaign { name }
  ... on IntrusionSet { name }
  ... on Malware { name }
  ... on ThreatActor { name }
  ... on Tool { name }
  ... on Vulnerability { name }
  ... on Infrastructure { name }
  ... on Indicator { name }
  ... on StixCyberObservable { observable_value }
"""

_RELATIONSHIPS = """
query Rels($ids: [String], $first: Int) {
  stixCoreRelationships(fromOrToId: $ids, first: $first) {
    edges { node {
      id relationship_type description start_time stop_time confidence
      from { %s }
      to { %s }
    } }
  }
}""" % (_REL_ENTITY, _REL_ENTITY)

_SDOS = """
query Sdo($search: String, $types: [String], $first: Int) {
  stixDomainObjects(search: $search, types: $types, first: $first) {
    edges { node {
      id entity_type created_at
      ... on IntrusionSet { name description aliases first_seen last_seen primary_motivation }
      ... on ThreatActor { name description aliases first_seen last_seen sophistication primary_motivation }
      ... on Malware { name description aliases malware_types is_family first_seen last_seen }
      ... on Campaign { name description aliases first_seen last_seen objective }
      ... on AttackPattern { name description x_mitre_id x_mitre_platforms }
      ... on Tool { name description aliases }
      ... on Vulnerability { name description }
      ... on Infrastructure { name description }
      ... on Report { name description published report_types }
    } }
  }
}"""


def _short(n: dict[str, Any] | None) -> dict[str, Any] | None:
    if not n:
        return None
    return {"id": n.get("id"), "type": n.get("entity_type"),
            "name": n.get("name") or n.get("observable_value"), "mitre_id": n.get("x_mitre_id")}


@tool(READ)
def lookup_ioc(values: list[str], with_context: bool = True) -> str:
    """Look up indicators in OpenCTI: matching observables (score, labels), indicators (pattern, validity,
    kill chain) and - with_context - what they relate to (intrusion sets, malware, campaigns, ATT&CK)."""
    out: dict[str, Any] = {}
    for v in values[:30]:
        obs = _edges(gql(_OBSERVABLES, {"search": v, "first": 10}).get("stixCyberObservables"))
        obs = [o for o in obs if str(o.get("observable_value", "")).lower() == v.lower()] or obs[:3]
        inds = _edges(gql(_INDICATORS, {"search": v, "first": 10}).get("indicators"))
        entry: dict[str, Any] = {
            "observables": [{"id": o["id"], "type": o["entity_type"], "value": o["observable_value"],
                             "score": o.get("x_opencti_score"), "labels": [l["value"] for l in o.get("objectLabel") or []],
                             "indicator_patterns": [i["pattern"] for i in _edges(o.get("indicators"))]} for o in obs],
            "indicators": [{"id": i["id"], "name": i["name"], "pattern": i["pattern"], "type": i["pattern_type"],
                            "score": i.get("x_opencti_score"), "valid_from": i.get("valid_from"),
                            "valid_until": i.get("valid_until"),
                            "kill_chain": [f"{k['kill_chain_name']}:{k['phase_name']}" for k in i.get("killChainPhases") or []],
                            "labels": [l["value"] for l in i.get("objectLabel") or []]} for i in inds],
        }
        ids = [o["id"] for o in obs] + [i["id"] for i in inds]
        if with_context and ids:
            rels = _edges(gql(_RELATIONSHIPS, {"ids": ids[:20], "first": 50}).get("stixCoreRelationships"))
            entry["related"] = [{"relationship": r["relationship_type"], "from": _short(r.get("from")),
                                 "to": _short(r.get("to")), "confidence": r.get("confidence")} for r in rels]
        out[v] = entry
    return dumps(out)


@tool(READ)
def search_entities(query: str, types: list[str] | None = None, limit: int = 15) -> str:
    """Search threat entities by name/alias/keyword: intrusion sets, threat actors, malware, campaigns,
    ATT&CK attack patterns, tools, vulnerabilities, infrastructure, reports. types use OpenCTI names
    (e.g. Intrusion-Set, Malware, Attack-Pattern, Report)."""
    bad = [t for t in types or [] if not re.fullmatch(r"[A-Za-z-]{2,40}", t)]
    if bad:
        raise ValueError(f"invalid types {bad}")
    nodes = _edges(gql(_SDOS, {"search": query, "types": types or SDO_TYPES, "first": min(limit, 100)}).get("stixDomainObjects"))
    for n in nodes:
        if n.get("description"):
            n["description"] = n["description"][:600]
    return dumps(nodes)


@tool(READ)
def entity_relationships(entity_id: str, limit: int = 50) -> str:
    """Relationships of an OpenCTI entity (e.g. what an intrusion set uses / targets / is attributed to,
    which indicators indicate a malware family)."""
    if not re.fullmatch(r"[A-Za-z0-9-]{8,80}", entity_id or ""):
        raise ValueError("invalid entity id")
    rels = _edges(gql(_RELATIONSHIPS, {"ids": [entity_id], "first": min(limit, 200)}).get("stixCoreRelationships"))
    return dumps([{"relationship": r["relationship_type"], "from": _short(r.get("from")), "to": _short(r.get("to")),
                   "confidence": r.get("confidence"), "start": r.get("start_time"), "stop": r.get("stop_time"),
                   "description": (r.get("description") or "")[:300]} for r in rels])


@tool(READ)
def graphql_query(query: str, variables: dict[str, Any] | None = None) -> str:
    """Escape hatch: run a read-only GraphQL QUERY against OpenCTI when the specific tools don't cover it.
    Mutations and subscriptions are refused."""
    stripped = re.sub(r"#.*", "", query)
    if re.search(r"\b(mutation|subscription)\b", stripped, re.I):
        raise ValueError("only read-only GraphQL queries are allowed")
    return dumps(gql(query, variables))


if __name__ == "__main__":
    mcp.run()
