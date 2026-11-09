"""MISP and OpenCTI connector tests against mock HTTP servers (request shapes per the MISP REST API and
the official pycti GraphQL queries)."""

from __future__ import annotations

import importlib
import json
import sys
from pathlib import Path

from mcp.server.mcpserver.exceptions import ToolError

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def load(monkeypatch, module, env):
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    mod = importlib.import_module(f"compensated_anarchist.servers.{module}")
    return importlib.reload(mod)


def test_misp(monkeypatch):
    m = load(monkeypatch, "misp", {"MISP_URL": "https://misp.invalid", "MISP_KEY": "k123"})
    seen = []

    def handler(req: httpx.Request):
        seen.append(req)
        assert req.headers["authorization"] == "k123"
        body = json.loads(req.content or b"null")
        if req.url.path == "/attributes/restSearch":
            assert body["value"] == "185.220.101.47" and body["returnFormat"] == "json"
            return httpx.Response(200, json={"response": {"Attribute": [{
                "value": "185.220.101.47", "type": "ip-dst", "category": "Network activity", "to_ids": True, "event_id": "42",
                "Event": {"info": "CS beacon infra", "threat_level_id": "1", "Orgc": {"name": "CERT"}},
                "Tag": [{"name": 'misp-galaxy:mitre-attack-pattern="Application Layer Protocol - T1071"'}]}]}})
        if req.url.path == "/warninglists/checkValue":
            assert body == ["8.8.8.8"]
            return httpx.Response(200, json={"8.8.8.8": [{"id": 1, "name": "List of known IPv4 public DNS resolvers"}]})
        if req.url.path == "/events/add":
            ev = body["Event"]
            assert ev["distribution"] == 0 and ev["published"] is False  # org-only, never auto-published
            return httpx.Response(200, json={"Event": {"id": "77", "uuid": "u", "published": False, "distribution": "0"}})
        if req.url.path == "/sightings/add":
            assert body["type"] == "0"
            return httpx.Response(200, json={"Sighting": {"id": "9"}})
        return httpx.Response(404, text="nope")

    m.http = httpx.Client(base_url="https://misp.invalid", headers={"Authorization": "k123"},
                          transport=httpx.MockTransport(handler))
    hits = json.loads(m.search_ioc(["185.220.101.47"]))
    a = hits["185.220.101.47"]["attributes"][0]
    assert a["event_info"] == "CS beacon infra" and "T1071" in a["tags"][0]
    assert "public DNS" in m.warninglist_check(["8.8.8.8"])
    assert json.loads(m.create_event("IR-0042 C2", [{"type": "ip-dst", "value": "185.220.101.47"}]))["published"] is False
    assert "9" in m.add_sighting("185.220.101.47")
    with pytest.raises(ToolError, match="Error"):
        m.add_sighting("x", sighting_type="delete")
    with pytest.raises(ToolError, match="Error"):
        m.get_event("../../users")


def test_opencti(monkeypatch):
    m = load(monkeypatch, "opencti", {"OPENCTI_URL": "https://octi.invalid", "OPENCTI_TOKEN": "t0k"})

    def handler(req: httpx.Request):
        assert req.url.path == "/graphql" and req.headers["authorization"] == "Bearer t0k"
        q = json.loads(req.content)
        query, var = q["query"], q["variables"]
        if "stixCyberObservables(" in query:
            assert var["search"] == "185.220.101.47"
            return httpx.Response(200, json={"data": {"stixCyberObservables": {"edges": [{"node": {
                "id": "obs-1", "entity_type": "IPv4-Addr", "observable_value": "185.220.101.47", "x_opencti_score": 80,
                "objectLabel": [{"value": "c2"}], "indicators": {"edges": [{"node": {"id": "ind-1", "pattern": "[ipv4-addr:value = '185.220.101.47']", "pattern_type": "stix"}}]}}}]}}})
        if "indicators(" in query:
            return httpx.Response(200, json={"data": {"indicators": {"edges": [{"node": {
                "id": "ind-1", "name": "185.220.101.47", "pattern": "[ipv4-addr:value = '185.220.101.47']", "pattern_type": "stix",
                "x_opencti_score": 80, "valid_from": "2026-10-01", "valid_until": None,
                "killChainPhases": [{"kill_chain_name": "mitre-attack", "phase_name": "command-and-control"}], "objectLabel": []}}]}}})
        if "stixCoreRelationships(" in query:
            assert "fromOrToId" in query
            return httpx.Response(200, json={"data": {"stixCoreRelationships": {"edges": [{"node": {
                "id": "rel-1", "relationship_type": "indicates", "confidence": 75,
                "from": {"id": "ind-1", "entity_type": "Indicator", "name": "185.220.101.47"},
                "to": {"id": "is-1", "entity_type": "Intrusion-Set", "name": "APT-EXAMPLE"}}}]}}})
        if "stixDomainObjects(" in query:
            return httpx.Response(200, json={"data": {"stixDomainObjects": {"edges": [{"node": {
                "id": "is-1", "entity_type": "Intrusion-Set", "name": "APT-EXAMPLE", "aliases": ["EX"], "description": "d"}}]}}})
        return httpx.Response(200, json={"errors": [{"message": "unknown"}]})

    m.http = httpx.Client(base_url="https://octi.invalid", headers={"Authorization": "Bearer t0k"},
                          transport=httpx.MockTransport(handler))
    r = json.loads(m.lookup_ioc(["185.220.101.47"]))["185.220.101.47"]
    assert r["observables"][0]["score"] == 80 and r["indicators"][0]["kill_chain"] == ["mitre-attack:command-and-control"]
    assert r["related"][0]["to"]["name"] == "APT-EXAMPLE"
    assert "APT-EXAMPLE" in m.search_entities("APT", ["Intrusion-Set"])
    with pytest.raises(ToolError, match="Error"):
        m.graphql_query("mutation { stixDomainObjectEdit(id: \"x\") { delete } }")
    with pytest.raises(ToolError, match="Error"):
        m.search_entities("x", ["Intrusion-Set; drop"])
    with pytest.raises(ToolError, match="RuntimeError"):
        m.graphql_query("query { nothing }")
