"""Live integration test for the Velociraptor MCP connector.

Skipped unless pointed at a real (test) server:
  CA_VELO_API_CONFIG        api client config with investigator,api role
  CA_VELO_ADMIN_API_CONFIG  (optional) api client config with administrator,api role - enables download test
  CA_VELO_CLIENT_SEARCH     (optional) client search, default 'all' (first Linux client is used)

Safe by design: collects Linux.Sys.Pslist, uploads one temp file it creates, runs a Generic.Client.Info hunt
that expires in 1 hour, toggles a test label. It never quarantines, acquires memory or runs shells.
Quick lab server:  velociraptor gui --datastore /tmp/velo --nobrowser
  then: velociraptor --config /tmp/velo/server.config.yaml config api_client --name t --role investigator,api api.yaml
  (restart the gui so the server loads the new API user)
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import sys
import tempfile
from pathlib import Path

import pytest

API = os.environ.get("CA_VELO_API_CONFIG")
ADMIN = os.environ.get("CA_VELO_ADMIN_API_CONFIG")
pytestmark = pytest.mark.skipif(not API, reason="set CA_VELO_API_CONFIG to run live Velociraptor tests")
ROOT = Path(__file__).resolve().parents[1]


async def _session(api: str, download_dir: str, fn):
    from mcp import Client, StdioServerParameters, stdio_client

    p = StdioServerParameters(command=sys.executable, args=["-m", "compensated_anarchist.servers.velociraptor"],
                              env={"VELO_API_CONFIG": api, "VELO_DOWNLOAD_DIR": download_dir, "PYTHONPATH": str(ROOT)})
    with open(os.devnull, "w") as err:
        async with Client(stdio_client(p, errlog=err), read_timeout_seconds=600) as c:
            return await fn(c)


async def _call(c, name, args):
    r = await c.call_tool(name, args)
    return r.is_error, (r.content[0].text if r.content else "")


def test_velociraptor_connector_live(tmp_path):
    evidence = Path(tempfile.mkdtemp(prefix="ca_velo_")) / "evidence.bin"
    evidence.write_bytes(os.urandom(6 * 1024 * 1024 + 123))  # > 1 download chunk
    want = hashlib.sha256(evidence.read_bytes()).hexdigest()

    async def investigator(c):
        names = {t.name for t in (await c.list_tools()).tools}
        assert {"collect_artifact", "download_flow_uploads", "quarantine_host", "acquire_memory"} <= names
        err, out = await _call(c, "list_clients", {"search": os.environ.get("CA_VELO_CLIENT_SEARCH", "all")})
        assert not err, out
        linux = [r for r in json.loads(out) if r.get("os") == "linux"]
        assert linux, "need a Linux client for the live test"
        cid = linux[0]["client_id"]

        err, out = await _call(c, "artifact_info", {"artifact": "Linux.Search.FileFinder"})
        assert not err and "SearchFilesGlob" in out
        err, out = await _call(c, "collect_artifact", {"client_id": cid, "artifact": "Linux.Sys.Pslist", "max_rows": 1})
        assert not err and json.loads(out)["state"] == "FINISHED", out
        err, out = await _call(c, "collect_artifact", {
            "client_id": cid, "artifact": "Linux.Search.FileFinder", "timeout_s": 300, "max_rows": 1,
            "parameters": {"SearchFilesGlob": str(evidence), "Upload_File": "Y", "LocalFilesystemOnly": "N"}})
        flow = json.loads(out)
        assert not err and flow["state"] == "FINISHED" and flow["uploads"] == 1, out
        err, out = await _call(c, "flow_uploads", {"client_id": cid, "flow_id": flow["flow_id"]})
        assert not err and str(evidence) in out

        err, out = await _call(c, "label_client", {"client_id": cid, "labels": ["ca-live-test"], "op": "set"})
        assert not err and "ca-live-test" in out
        err, out = await _call(c, "label_client", {"client_id": cid, "labels": ["ca-live-test"], "op": "remove"})
        assert not err and "ca-live-test" not in out

        err, out = await _call(c, "create_hunt", {"artifact": "Generic.Client.Info", "description": "ca live test",
                                                  "os": "linux", "expires_hours": 1})
        assert not err and json.loads(out)["hunt_id"].startswith("H."), out

        err, out = await _call(c, "collect_artifact", {"client_id": cid, "artifact": "No.Such.Artifact", "wait": False})
        assert err and "unknown artifact" in out.lower()
        err, out = await _call(c, "client_info", {"client_id": "C.bad'; DROP"})
        assert err and "invalid client_id" in out
        return cid, flow["flow_id"]

    cid, fid = asyncio.run(_session(API, str(tmp_path), investigator))

    if ADMIN:
        async def admin(c):
            err, out = await _call(c, "download_flow_uploads", {"client_id": cid, "flow_id": fid})
            assert not err, out
            f = json.loads(out)["files"][0]
            assert f["size_verified"] and f["sha256"] == want
            assert hashlib.sha256(Path(f["local_path"]).read_bytes()).hexdigest() == want

        asyncio.run(_session(ADMIN, str(tmp_path), admin))
