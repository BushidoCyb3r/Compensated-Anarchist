"""Spins up / connects to MCP servers and exposes their tools to the agents.

Each entry under `mcp_servers:` in harness.yaml is one of:
  module: compensated_anarchist.servers.splunk   # launched as `python -m <module>` over stdio
  command: /path/to/server  + args: [...]        # any stdio MCP server (third-party ones too)
  url: https://host/mcp  + headers: {...}        # remote streamable-HTTP MCP server
Tools are registered as "<server>__<tool>" so ROE rules can target them by glob.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from contextlib import AsyncExitStack
from typing import Any

from pathlib import Path

from mcp import Client, StdioServerParameters, stdio_client

from .tools.registry import Tool, ToolRegistry

log = logging.getLogger("canarchist.mcp")


def _format_result(res: Any) -> str:
    parts: list[str] = []
    for c in res.content or []:
        if getattr(c, "type", "") == "text":
            parts.append(c.text)
        else:
            parts.append(f"[{getattr(c, 'type', 'content')} content omitted]")
    if not parts and res.structured_content is not None:
        parts.append(json.dumps(res.structured_content, indent=1, default=str))
    text = "\n".join(parts) or "(empty result)"
    return f"ERROR: {text}" if res.is_error else text


class McpManager:
    def __init__(self, servers: dict[str, dict[str, Any]], log_dir: Path | None = None):
        def on(v: Any) -> bool:  # env-expanded YAML gives strings like "false"
            return v if isinstance(v, bool) else str(v).strip().lower() not in ("false", "0", "no", "off", "")

        self.servers = {k: v for k, v in servers.items() if on(v.get("enabled", True))}
        self.clients: dict[str, Client] = {}
        self.status: dict[str, str] = {}
        self._stack = AsyncExitStack()
        self.log_dir = log_dir

    def _target(self, name: str, spec: dict[str, Any]) -> Any:
        if "url" in spec:
            import httpx2
            from mcp.client.streamable_http import streamable_http_client

            http = httpx2.AsyncClient(headers=spec.get("headers") or {}, verify=spec.get("ca_bundle") or spec.get("verify_tls", True),
                                      timeout=spec.get("timeout_s", 120))
            return streamable_http_client(spec["url"], http_client=http)
        env = {k: str(v) for k, v in (spec.get("env") or {}).items()}
        if "module" in spec:
            # make sure the child can import this package even when not pip-installed
            pkg_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            env["PYTHONPATH"] = os.pathsep.join(filter(None, [pkg_root, os.environ.get("PYTHONPATH", "")]))
            return StdioServerParameters(command=sys.executable, args=["-m", spec["module"]], env=env)
        if "command" in spec:
            return StdioServerParameters(command=spec["command"], args=spec.get("args", []), env=env, cwd=spec.get("cwd"))
        raise ValueError(f"mcp server '{name}': need module, command or url")

    async def start(self, registry: ToolRegistry) -> None:
        for name, spec in self.servers.items():
            try:
                target = self._target(name, spec)
                if isinstance(target, StdioServerParameters) and self.log_dir:
                    # connector stderr (tracebacks, warnings) goes to a per-server log, not the analyst console
                    self.log_dir.mkdir(parents=True, exist_ok=True)
                    errlog = self._stack.enter_context(open(self.log_dir / f"mcp_{name}.log", "a", encoding="utf-8"))
                    target = stdio_client(target, errlog=errlog)
                client = Client(target, read_timeout_seconds=float(spec.get("timeout_s", 300)))
                await self._stack.enter_async_context(client)
                listing = await client.list_tools()
                include = set(spec.get("include_tools") or [])
                exclude = set(spec.get("exclude_tools") or [])
                tools = [t for t in listing.tools if (not include or t.name in include) and t.name not in exclude]
                for t in tools:
                    tool = self._wrap(name, client, t)
                    tool.quarantined = bool(spec.get("quarantine"))  # listed for onboarding, not callable
                    registry.add(tool)
                self.clients[name] = client
                self.status[name] = f"connected ({len(tools)} tools)" + (", in quarantine" if spec.get("quarantine") else "")
            except Exception as e:  # one broken connector must not take down the harness
                self.status[name] = f"FAILED: {type(e).__name__}: {e}"
                log.warning("MCP server %s failed to start: %s", name, e)

    def _wrap(self, server: str, client: Client, t: Any) -> Tool:
        async def handler(**kwargs: Any) -> str:
            return _format_result(await client.call_tool(t.name, kwargs))

        ann = t.annotations.model_dump(exclude_none=True) if t.annotations else {}
        return Tool(
            name=f"{server}__{t.name}"[:64],
            description=f"[{server}] {t.description or ''}",
            parameters=t.input_schema or {"type": "object", "properties": {}},
            handler=handler,
            server=server,
            annotations=ann,
        )

    async def aclose(self) -> None:
        try:
            await self._stack.aclose()
        except Exception as e:  # pragma: no cover - shutdown noise from child processes
            log.debug("mcp shutdown: %s", e)
