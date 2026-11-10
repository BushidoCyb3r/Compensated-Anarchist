"""Live, read-only checks of the Security Onion and Elastic connectors against a real grid.
Skipped unless CA_LIVE_ES_URL and CA_LIVE_ES_API_KEY are set (CA_LIVE_ES_VERIFY: true | false | /path/ca.crt).
CA_LIVE_SO=1 also runs the Security Onion checks (the cluster must be an SO3 grid).
Use a read-only API key: these tests only search."""

from __future__ import annotations

import importlib
import json
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

URL, KEY = os.environ.get("CA_LIVE_ES_URL", ""), os.environ.get("CA_LIVE_ES_API_KEY", "")
VERIFY = os.environ.get("CA_LIVE_ES_VERIFY", "true")
pytestmark = pytest.mark.skipif(not (URL and KEY), reason="set CA_LIVE_ES_URL and CA_LIVE_ES_API_KEY")


def load(monkeypatch, module, prefix):
    monkeypatch.setenv(f"{prefix}_URL", URL)
    monkeypatch.setenv(f"{prefix}_API_KEY", KEY)
    monkeypatch.setenv(f"{prefix}_VERIFY", VERIFY)
    return importlib.reload(importlib.import_module(f"compensated_anarchist.servers.{module}"))


@pytest.mark.skipif(os.environ.get("CA_LIVE_SO") != "1", reason="set CA_LIVE_SO=1 for a Security Onion 3 grid")
def test_security_onion_live(monkeypatch):
    so = load(monkeypatch, "security_onion", "SO")
    streams = {s["name"] for s in (lambda r: r["streams"] if isinstance(r, dict) else r)(json.loads(so.list_data_streams("logs-*-so")))}
    assert "logs-zeek-so" in streams, streams
    assert json.loads(so.search("event.dataset:zeek.conn", start="now-24h", size=1))["total"] > 0, "no zeek.conn in 24h"
    assert json.loads(so.field_values("event.dataset", "event.module:zeek", start="now-1h"))["buckets"]
    json.loads(so.alerts_summary(start="now-7d"))
    json.loads(so.alerts(start="now-7d", size=1))
    json.loads(so.beacon_candidates(start="now-1h", min_connections=10, size=3))
    assert "columns" in json.loads(so.esql('FROM logs-zeek-so | WHERE event.dataset == "zeek.conn" | LIMIT 1'))
    json.loads(so.ioc_sweep(["192.0.2.255"], start="now-1h"))


def test_elastic_live(monkeypatch):
    el = load(monkeypatch, "elastic", "ES")
    inv = json.loads(el.list_indices("logs-*"))
    assert inv, "no logs-* data"
    json.loads(el.search("*", start="now-1h", size=1))
    json.loads(el.field_values("event.dataset", start="now-1h", size=5))
    assert "columns" in json.loads(el.esql("FROM logs-* | LIMIT 1"))
    json.loads(el.eql("any where true", start="now-15m", size=1))
    json.loads(el.alerts_summary())
