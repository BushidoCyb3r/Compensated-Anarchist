"""MCP server: Velociraptor - endpoint visibility, collection, hunting, evidence retrieval and response.

Verified live against Velociraptor 0.77.3 over the gRPC API.

Server-side setup (on the Velociraptor server):
  # least privilege for hunting/collection:
  velociraptor --config server.config.yaml config api_client --name canarchist --role investigator,api api.config.yaml
  # evidence download (reads the filestore), server VQL and quarantine also need:  --role administrator,api
  Restart the frontend (or create the user through the GUI) so the running server loads the new API user.
Env:
  VELO_API_CONFIG     path to the api client config (required)
  VELO_ORG_ID         org to operate in (optional, multi-tenant servers)
  VELO_TIMEOUT        per-query timeout seconds (default 600)
  VELO_DOWNLOAD_DIR   the evidence vault folder download_flow_uploads writes to (the harness sets it to
                      <evidence root>/vault/velociraptor). Files there are read-only and never executable;
                      executables and scripts are stored with a .quarantined suffix (see compensated_anarchist/vault.py).

Injection safety: every tool argument reaches VQL as a query *parameter* (VQLEnv), never by string
formatting. Parameters use a `Ca` prefix because plain names collide with VQL builtins and keywords
(e.g. `Artifact` is the artifact namespace and `Desc` parses as DESC).
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

import yaml
from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations

from .. import saferx, vault
from .common import ACTION, READ, dumps, env, tool_factory

mcp = MCPServer("velociraptor", instructions=(
    "Velociraptor endpoint visibility and response. Prefer: existing results -> targeted artifact on one host -> "
    "hunts. Use artifact_info to get exact parameter names before collect_artifact."))
tool = tool_factory(mcp)
CHANGE = ToolAnnotations(read_only_hint=False, destructive_hint=False, open_world_hint=False)  # low-impact state change

CONFIG = env("VELO_API_CONFIG", required=True)
ORG = env("VELO_ORG_ID", "")
TIMEOUT = int(env("VELO_TIMEOUT", "600"))
DOWNLOAD_DIR = env("VELO_DOWNLOAD_DIR", "")
CHUNK = 4 * 1024 * 1024
_CLIENT_RE = re.compile(r"^C\.[0-9a-f]{16}$")
_FLOW_RE = re.compile(r"^F\.[A-Z0-9]+$")
_HUNT_RE = re.compile(r"^H\.[A-Z0-9]+$")
_ART_RE = re.compile(r"^[A-Za-z0-9_.]+(/[A-Za-z0-9_ ]+)?$")
_NOISE = ("Starting query execution", "Sending response part", "Query Stats")
_ERRORISH = ("PermissionDenied", "VQL Error", "Unknown artifact", "unknown artifact", "NotFound", "Invalid",
             "error", "Error", "denied")
QUARANTINE = {"windows": "Windows.Remediation.Quarantine", "linux": "Linux.Remediation.Quarantine",
              "darwin": "MacOS.Remediation.Quarantine"}


# ---------------------------------------------------------------------------
# gRPC plumbing
# ---------------------------------------------------------------------------
@contextmanager
def _stub() -> Iterator[Any]:
    import grpc
    from pyvelociraptor import api_pb2_grpc

    with open(CONFIG, encoding="utf-8") as fh:
        cfg = yaml.safe_load(fh)
    creds = grpc.ssl_channel_credentials(root_certificates=cfg["ca_certificate"].encode(),
                                         private_key=cfg["client_private_key"].encode(),
                                         certificate_chain=cfg["client_cert"].encode())
    opts = (("grpc.ssl_target_name_override", "VelociraptorServer"),
            ("grpc.max_receive_message_length", 64 * 1024 * 1024))
    try:
        with grpc.secure_channel(cfg["api_connection_string"], creds, opts) as channel:
            yield api_pb2_grpc.APIStub(channel)
    except grpc.RpcError as e:  # surface the server's reason (auth, ACL, unknown user) cleanly
        raise RuntimeError(f"Velociraptor API {e.code().name}: {e.details()}") from None


def _query(stub: Any, vql: str, params: dict[str, Any] | None, max_rows: int) -> tuple[list[dict[str, Any]], list[str]]:
    import grpc
    from pyvelociraptor import api_pb2

    envs = [api_pb2.VQLEnv(key=k, value=v if isinstance(v, str) else json.dumps(v)) for k, v in (params or {}).items()]
    req = api_pb2.VQLCollectorArgs(max_wait=1, max_row=max_rows, timeout=TIMEOUT, org_id=ORG,
                                   Query=[api_pb2.VQLRequest(Name="canarchist", VQL=vql)], env=envs)
    rows: list[dict[str, Any]] = []
    logs: list[str] = []
    try:
        for resp in stub.Query(req, timeout=TIMEOUT + 30):
            if resp.Response:
                rows.extend(json.loads(resp.Response))
            elif resp.log and not any(n in resp.log for n in _NOISE):
                logs.append(resp.log.strip())
            if len(rows) >= max_rows:
                break
    except grpc.RpcError as e:
        raise RuntimeError(f"Velociraptor API {e.code().name}: {e.details()}") from None
    return rows[:max_rows], logs


def _vql(vql: str, params: dict[str, Any] | None = None, max_rows: int = 1000) -> list[dict[str, Any]]:
    """Run VQL. If nothing useful comes back and the server logged problems, raise them (permissions,
    VQL errors, unknown artifacts) so the agent learns WHY instead of seeing an empty result."""
    with _stub() as stub:
        rows, logs = _query(stub, vql, params, max_rows)
    meaningful = [r for r in rows if any(v not in (None, "", [], {}) for v in r.values())]
    errs = [m for m in logs if any(e in m for e in _ERRORISH)]
    if errs and not meaningful:
        raise RuntimeError("; ".join(errs[-5:]))
    return rows


def _check(pattern: re.Pattern, value: str, what: str) -> str:
    if not isinstance(value, str) or not pattern.match(value):
        raise ValueError(f"invalid {what}: {value!r}")
    return value


def _collectable(artifact: str) -> str:
    """An artifact to collect or hunt: its plain name. Name/Source only selects results when reading them; refusing it
    here also keeps the ROE's artifact rules (which name artifacts) from being sidestepped with a source suffix."""
    _check(_ART_RE, artifact, "artifact")
    if "/" in artifact:
        raise ValueError(f"collect an artifact by its name ({artifact.split('/')[0]}): a source (Name/Source) "
                         "applies only when reading results")
    return artifact


def _filtered(rows: list[dict[str, Any]], where_regex: str) -> list[dict[str, Any]]:
    """The rows whose JSON text the agent's regex matches (case-insensitive), matched with a time limit (saferx)."""
    return [rows[i] for i in saferx.matching(where_regex, [json.dumps(r, default=str) for r in rows])]


def _flow_logs(client_id: str, flow_id: str, limit: int = 20) -> list[str]:
    rows = _vql("SELECT level, message FROM flow_logs(client_id=CaClient, flow_id=CaFlow)",
                {"CaClient": client_id, "CaFlow": flow_id}, 2000)
    msgs = [f"{r.get('level', '')}: {str(r.get('message', '')).strip()}" for r in rows]
    return [m for m in msgs if not any(n in m for n in _NOISE)][-limit:]


def _client_os(client_id: str) -> str:
    rows = _vql("SELECT os_info.system AS os FROM clients(client_id=CaClient)", {"CaClient": client_id})
    if not rows:
        raise ValueError(f"unknown client {client_id}")
    return (rows[0].get("os") or "").lower()


def _schedule(client_id: str, artifact: str, parameters: dict[str, Any] | None, timeout_s: int) -> str:
    rows = _vql("SELECT collect_client(client_id=CaClient, artifacts=[CaArt], spec=parse_json(data=CaSpec), "
                "timeout=int(int=CaTimeout)).flow_id AS flow_id FROM scope()",
                {"CaClient": client_id, "CaArt": artifact, "CaTimeout": str(int(timeout_s)),
                 "CaSpec": json.dumps({artifact.split("/")[0]: {k: str(v) for k, v in (parameters or {}).items()}})})
    flow_id = rows[0].get("flow_id") if rows else None
    if not flow_id:
        raise RuntimeError(f"collection of {artifact} was not scheduled (check artifact name and parameters with artifact_info)")
    return flow_id


def _wait(client_id: str, flow_id: str, timeout_s: int) -> dict[str, Any]:
    deadline = time.time() + timeout_s
    st: dict[str, Any] = {}
    while time.time() < deadline:
        rows = _vql("SELECT state, status, total_collected_rows AS rows, total_uploaded_files AS uploads "
                    "FROM flows(client_id=CaClient, flow_id=CaFlow)", {"CaClient": client_id, "CaFlow": flow_id})
        st = rows[0] if rows else {"state": "UNKNOWN"}
        if st.get("state") in ("FINISHED", "ERROR"):
            return st
        time.sleep(3)
    st["state"] = st.get("state", "RUNNING") + " (still running - poll flow_status)"
    return st


# ---------------------------------------------------------------------------
# Visibility
# ---------------------------------------------------------------------------
@tool(READ)
def list_clients(search: str = "all", limit: int = 50) -> str:
    """Find endpoints. search uses Velociraptor syntax: 'all', 'host:ws01', 'label:servers', or a client id."""
    return dumps(_vql("SELECT client_id, os_info.hostname AS hostname, os_info.fqdn AS fqdn, os_info.system AS os, "
                      "os_info.release AS release, timestamp(epoch=last_seen_at / 1000000) AS last_seen, labels, "
                      "last_ip FROM clients(search=CaSearch) LIMIT " + str(min(int(limit), 500)), {"CaSearch": search}))


@tool(READ)
def client_info(client_id: str) -> str:
    """Full client record: OS, hostname, MACs, labels, last IP, agent version, last seen, in-flight flows."""
    return dumps(_vql("SELECT * FROM clients(client_id=CaClient)", {"CaClient": _check(_CLIENT_RE, client_id, "client_id")}))


@tool(READ)
def client_flows(client_id: str, limit: int = 20) -> str:
    """Recent collections on an endpoint (what has already been collected - reuse results before re-collecting)."""
    rows = _vql("SELECT session_id AS flow_id, request.artifacts AS artifacts, state, total_collected_rows AS rows, "
                "total_uploaded_files AS uploads, request.creator AS creator, create_time, "
                "timestamp(epoch=create_time/1000000) AS created FROM flows(client_id=CaClient) "
                "ORDER BY create_time DESC LIMIT " + str(min(int(limit), 200)),
                {"CaClient": _check(_CLIENT_RE, client_id, "client_id")})
    for r in rows:
        r.pop("create_time", None)
    return dumps(rows)


@tool(READ)
def list_artifacts(name_regex: str = ".", type: str = "client", limit: int = 100) -> str:
    """Search available artifacts (name, short description, parameter names). type: client|server|client_event."""
    rows = _vql("SELECT name, type, description, parameters.name AS parameters FROM artifact_definitions() "
                "WHERE name =~ CaRegex AND type =~ CaType LIMIT " + str(min(int(limit), 300)),
                {"CaRegex": name_regex, "CaType": f"^{re.escape(type)}$" if type else "."})
    for r in rows:
        r["description"] = (r.get("description") or "").strip().split("\n\n")[0][:300]
    return dumps(rows)


@tool(READ)
def artifact_info(artifact: str) -> str:
    """Full artifact definition summary: description, sources, and every parameter with its type, default and
    description. Call this before collect_artifact to get parameter names exactly right."""
    rows = _vql("SELECT name, type, description, parameters, sources.name AS sources, required_permissions "
                "FROM artifact_definitions(names=CaArt)", {"CaArt": _check(_ART_RE, artifact, "artifact")})
    if not rows:
        return f"artifact {artifact} not found on this server (it may need importing, e.g. via Server.Import.Extras)"
    r = rows[0]
    r["parameters"] = [{k: p.get(k) for k in ("name", "type", "default", "description") if p.get(k) not in (None, "")}
                       for p in (r.get("parameters") or [])]
    return dumps(r)


# ---------------------------------------------------------------------------
# Collection
# ---------------------------------------------------------------------------
@tool(ACTION)
def collect_artifact(client_id: str, artifact: str, parameters: dict[str, Any] | None = None, timeout_s: int = 600,
                     wait: bool = True, max_rows: int = 200) -> str:
    """Collect an artifact from ONE endpoint, e.g. Windows.System.Pslist, Windows.Network.Netstat,
    Windows.Sys.StartupItems, Linux.Sys.Pslist, Windows.Search.FileFinder (Upload_File=Y to retrieve files).
    parameters = {name: value} using the artifact's exact parameter names (see artifact_info).
    wait=true polls until finished (up to timeout_s) and returns results; use wait=false for long collections."""
    cid = _check(_CLIENT_RE, client_id, "client_id")
    _collectable(artifact)
    flow_id = _schedule(cid, artifact, parameters, timeout_s)
    if not wait:
        return dumps({"client_id": cid, "flow_id": flow_id, "status": "scheduled"})
    st = _wait(cid, flow_id, min(timeout_s, TIMEOUT))
    out: dict[str, Any] = {"client_id": cid, "flow_id": flow_id, **st}
    if st.get("state") == "FINISHED":
        out["results"] = _vql("SELECT * FROM source(client_id=CaClient, flow_id=CaFlow, artifact=CaArt) LIMIT "
                              + str(min(int(max_rows), 2000)),
                              {"CaClient": cid, "CaFlow": flow_id, "CaArt": artifact}, min(int(max_rows), 2000))
        if st.get("uploads"):
            out["note"] = f"{st['uploads']} file(s) uploaded - use flow_uploads / download_flow_uploads"
    else:
        out["logs"] = _flow_logs(cid, flow_id)
    return dumps(out)


@tool(READ)
def flow_status(client_id: str, flow_id: str) -> str:
    """State of a collection (RUNNING / FINISHED / ERROR), row and upload counts, plus the latest client logs."""
    cid, fid = _check(_CLIENT_RE, client_id, "client_id"), _check(_FLOW_RE, flow_id, "flow_id")
    rows = _vql("SELECT session_id AS flow_id, state, status, total_collected_rows AS rows, total_uploaded_files AS uploads, "
                "total_uploaded_bytes AS uploaded_bytes, request.artifacts AS artifacts, "
                "timestamp(epoch=create_time/1000000) AS created FROM flows(client_id=CaClient, flow_id=CaFlow)",
                {"CaClient": cid, "CaFlow": fid})
    return dumps({"flow": rows[0] if rows else None, "logs": _flow_logs(cid, fid)})


@tool(READ)
def flow_results(client_id: str, flow_id: str, artifact: str, limit: int = 200, where_regex: str = "") -> str:
    """Rows collected by a flow for an artifact (or artifact/source). Optional case-insensitive regex filter."""
    q = "SELECT * FROM source(client_id=CaClient, flow_id=CaFlow, artifact=CaArt)"
    params = {"CaClient": _check(_CLIENT_RE, client_id, "client_id"), "CaFlow": _check(_FLOW_RE, flow_id, "flow_id"),
              "CaArt": _check(_ART_RE, artifact, "artifact")}
    if not where_regex:
        return dumps(_vql(q + f" LIMIT {min(int(limit), 2000)}", params, min(int(limit), 2000)))
    rows = _filtered(_vql(q, params, 20000), where_regex)
    return dumps({"matched": len(rows), "rows": rows[: min(int(limit), 2000)]})


@tool(READ)
def flow_uploads(client_id: str, flow_id: str) -> str:
    """Files uploaded by a collection (client path, size, server vfs_path)."""
    return dumps(_vql("SELECT Upload.Path AS client_path, file_size, uploaded_size, vfs_path, _accessor AS accessor "
                      "FROM uploads(client_id=CaClient, flow_id=CaFlow)",
                      {"CaClient": _check(_CLIENT_RE, client_id, "client_id"), "CaFlow": _check(_FLOW_RE, flow_id, "flow_id")}))


@tool(READ)
def download_flow_uploads(client_id: str, flow_id: str, path_regex: str = "", max_total_mb: int = 65536) -> str:
    """Download files a collection uploaded (memory images, triage files, binaries) into the evidence VAULT on the
    analyst workstation, verifying size and computing SHA-256 for chain of custody. Every file is stored read-only
    and non-executable; executables and scripts get a .quarantined suffix. Analyze them with local tools (they read,
    never run, files), then register them with case_register_evidence. Needs the analyst's approval and an API
    client with the administrator role."""
    cid, fid = _check(_CLIENT_RE, client_id, "client_id"), _check(_FLOW_RE, flow_id, "flow_id")
    if not DOWNLOAD_DIR:
        raise RuntimeError("VELO_DOWNLOAD_DIR is not configured for the velociraptor connector")
    ups = _vql("SELECT Upload.Path AS client_path, file_size, vfs_path, _client_components AS cc "
               "FROM uploads(client_id=CaClient, flow_id=CaFlow)", {"CaClient": cid, "CaFlow": fid})
    if path_regex:
        ups = [ups[i] for i in saferx.matching(path_regex, [str(u.get("client_path") or "") for u in ups])]
    if not ups:
        return "no uploaded files matched"
    total = sum(int(u.get("file_size") or 0) for u in ups)
    if total > max_total_mb * 1024 * 1024:
        return f"refusing: {total} bytes exceeds max_total_mb={max_total_mb}; narrow with path_regex"
    out = []
    root = vault.ensure(Path(DOWNLOAD_DIR).resolve())
    flow_dir = root / cid / fid
    os.chmod(vault.ensure(root / cid), 0o700)
    with _stub() as stub, vault.writable(flow_dir):
        for u in ups:
            parts = [re.sub(r"[^A-Za-z0-9._ -]", "_", c) for c in (u.get("cc") or [Path(u["client_path"]).name])
                     if c not in ("", ".", "..")]
            dest = flow_dir / Path(*parts)
            if (existing := vault.stored_copy(dest)) is not None:
                out.append({"client_path": u["client_path"], "local_path": str(existing), "already_in_vault": True})
                continue
            sha, md5, off = hashlib.sha256(), hashlib.md5(usedforsecurity=False), 0  # md5: Velociraptor's id; FIPS-safe
            with vault.open_new(dest) as fh:
                while True:
                    rows, logs = _query(stub, "SELECT base64encode(string=read_file(accessor='fs', filename=CaPath, "
                                              "offset=int(int=CaOff), length=int(int=CaLen))) AS b FROM scope()",
                                        {"CaPath": u["vfs_path"], "CaOff": str(off), "CaLen": str(CHUNK)}, 1)
                    errs = [m for m in logs if any(e in m for e in _ERRORISH)]
                    if errs:
                        raise RuntimeError("; ".join(errs[-3:]))
                    data = base64.b64decode(rows[0]["b"]) if rows and rows[0].get("b") else b""
                    if not data:
                        break
                    fh.write(data)
                    sha.update(data)
                    md5.update(data)
                    off += len(data)
                    if len(data) < CHUNK:
                        break
            expected = int(u.get("file_size") or 0)
            stored = vault.seal_file(dest)
            entry = {"client_path": u["client_path"], "local_path": str(stored), "bytes": off,
                     "size_verified": off == expected, "expected_bytes": expected,
                     "sha256": sha.hexdigest(), "md5": md5.hexdigest(),
                     "executable_quarantined": stored.name.endswith(vault.QUARANTINE_SUFFIX)}
            vault.record(root, {"client_id": cid, "flow_id": fid, **entry})
            out.append(entry)
    return dumps({"client_id": cid, "flow_id": fid, "vault": str(flow_dir), "files": out,
                  "note": "stored read-only and non-executable; analyze with local tools, never run these files"})


@tool(CHANGE)
def cancel_flow(client_id: str, flow_id: str) -> str:
    """Cancel a running collection (e.g. one that is too heavy for the endpoint)."""
    return dumps(_vql("SELECT cancel_flow(client_id=CaClient, flow_id=CaFlow) AS result FROM scope()",
                      {"CaClient": _check(_CLIENT_RE, client_id, "client_id"), "CaFlow": _check(_FLOW_RE, flow_id, "flow_id")}))


@tool(CHANGE)
def label_client(client_id: str, labels: list[str], op: str = "set") -> str:
    """Add (op=set) or remove (op=remove) labels on an endpoint - used to track investigation state and to
    target hunts (include_labels)."""
    if op not in ("set", "remove"):
        raise ValueError("op must be set or remove")
    for lab in labels:
        if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,64}", lab):
            raise ValueError(f"invalid label {lab!r}")
    cid = _check(_CLIENT_RE, client_id, "client_id")
    _vql("SELECT label(client_id=CaClient, labels=parse_json_array(data=CaLabels), op=CaOp) AS r FROM scope()",
         {"CaClient": cid, "CaLabels": json.dumps(labels), "CaOp": op})
    return dumps(_vql("SELECT client_id, labels FROM clients(client_id=CaClient)", {"CaClient": cid}))


# ---------------------------------------------------------------------------
# Hunting (fleet-wide)
# ---------------------------------------------------------------------------
@tool(ACTION)
def create_hunt(artifact: str, description: str, parameters: dict[str, Any] | None = None,
                include_labels: list[str] | None = None, exclude_labels: list[str] | None = None, os: str = "",
                expires_hours: int = 168) -> str:
    """Launch a FLEET-WIDE hunt across all matching endpoints. Strong justification required; scope it with
    include_labels / exclude_labels / os (windows|linux|darwin)."""
    _collectable(artifact)
    args = ["description=CaDescription", "artifacts=[CaArt]", "spec=parse_json(data=CaSpec)",
            "expires=now() + int(int=CaExpires)"]
    params: dict[str, Any] = {"CaDescription": f"[canarchist] {description}"[:500], "CaArt": artifact,
                              "CaSpec": json.dumps({artifact.split("/")[0]: {k: str(v) for k, v in (parameters or {}).items()}}),
                              "CaExpires": str(int(expires_hours) * 3600)}
    if include_labels:
        args.append("include_labels=parse_json_array(data=CaInc)")
        params["CaInc"] = json.dumps(include_labels)
    if exclude_labels:
        args.append("exclude_labels=parse_json_array(data=CaExc)")
        params["CaExc"] = json.dumps(exclude_labels)
    if os:
        if os not in ("windows", "linux", "darwin"):
            raise ValueError("os must be windows, linux or darwin")
        args.append("os=CaOS")
        params["CaOS"] = os
    rows = _vql("SELECT hunt(" + ", ".join(args) + ").HuntId AS hunt_id FROM scope()", params)
    if not rows or not rows[0].get("hunt_id"):
        raise RuntimeError(f"hunt was not created: {rows}")
    return dumps({"hunt_id": rows[0]["hunt_id"], "artifact": artifact, "status": "running"})


@tool(READ)
def list_hunts(limit: int = 20, state: str = "") -> str:
    """Recent hunts with state and progress counts."""
    rows = _vql("SELECT hunt_id, hunt_description AS description, state, start_request.artifacts AS artifacts, "
                "stats.total_clients_scheduled AS scheduled, stats.total_clients_with_results AS with_results, "
                "create_time, timestamp(epoch=create_time/1000000) AS created FROM hunts() "
                "ORDER BY create_time DESC LIMIT " + str(min(int(limit), 200)))
    rows = [r for r in rows if not state or r.get("state") == state.upper()]
    for r in rows:
        r.pop("create_time", None)
    return dumps(rows)


@tool(READ)
def hunt_results(hunt_id: str, artifact: str, limit: int = 500, where_regex: str = "") -> str:
    """Results of a hunt across all endpoints for an artifact (or artifact/source); optional regex filter."""
    params = {"CaHunt": _check(_HUNT_RE, hunt_id, "hunt_id"), "CaArt": _check(_ART_RE, artifact, "artifact")}
    q = "SELECT * FROM hunt_results(hunt_id=CaHunt, artifact=CaArt)"
    if not where_regex:
        return dumps(_vql(q + " LIMIT " + str(min(int(limit), 5000)), params, min(int(limit), 5000)))
    rows = _filtered(_vql(q, params, 50000), where_regex)
    return dumps({"matched": len(rows), "rows": rows[: min(int(limit), 5000)]})


# ---------------------------------------------------------------------------
# Response
# ---------------------------------------------------------------------------
@tool(ACTION)
def acquire_memory(client_id: str, timeout_s: int = 7200) -> str:
    """Acquire a full physical memory image (Windows: Windows.Memory.Acquisition / WinPmem). Large transfer;
    returns the flow id immediately - poll flow_status, then download_flow_uploads and run Volatility locally.
    Linux/macOS have no built-in full-memory artifact: use Linux.Triage.ProcessMemory for specific processes."""
    cid = _check(_CLIENT_RE, client_id, "client_id")
    system = _client_os(cid)
    if system != "windows":
        return (f"ERROR: no built-in full memory acquisition artifact for '{system}'. Options: "
                "collect Linux.Triage.ProcessMemory (processPid) for suspect processes, or import an AVML-based artifact.")
    flow_id = _schedule(cid, "Windows.Memory.Acquisition", {}, timeout_s)
    return dumps({"client_id": cid, "flow_id": flow_id, "status": "scheduled",
                  "next": "poll flow_status; when FINISHED use download_flow_uploads"})


def _quarantine(client_id: str, remove: bool, message: str) -> str:
    cid = _check(_CLIENT_RE, client_id, "client_id")
    system = _client_os(cid)
    artifact = QUARANTINE.get(system)
    if not artifact:
        raise RuntimeError(f"no quarantine artifact for OS '{system}'")
    params = {"RemovePolicy": "Y"} if remove else ({"MessageBox": message[:200]} if message else {})
    return collect_artifact(cid, artifact, params, timeout_s=300, wait=True)


@tool(ACTION)
def quarantine_host(client_id: str, message: str = "") -> str:
    """NETWORK-ISOLATE an endpoint (Windows firewall / Linux nftables / macOS pf) so it can only reach the
    Velociraptor server. Disruptive containment. Optional message is shown to the logged-on user."""
    return _quarantine(client_id, False, message)


@tool(ACTION)
def unquarantine_host(client_id: str) -> str:
    """Remove network isolation from a previously quarantined endpoint."""
    return _quarantine(client_id, True, "")


@tool(ACTION)
def run_server_vql(query: str, max_rows: int = 500) -> str:
    """Run arbitrary VQL on the Velociraptor SERVER. Very powerful (can collect from clients, read server files).
    Prefer the specific tools; requires analyst approval."""
    return dumps(_vql(query, None, min(int(max_rows), 5000)))


if __name__ == "__main__":
    mcp.run()
