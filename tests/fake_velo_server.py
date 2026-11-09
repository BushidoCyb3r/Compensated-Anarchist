"""Stand-in Velociraptor MCP server for tests (same tool names/annotations, canned data)."""

from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations

READ = ToolAnnotations(read_only_hint=True, destructive_hint=False)
ACTION = ToolAnnotations(read_only_hint=False, destructive_hint=True)
mcp = MCPServer("velociraptor")


@mcp.tool(annotations=READ)
def list_clients(search: str = "all", limit: int = 50) -> str:
    """Find endpoints."""
    return '[{"client_id": "C.1111111111111111", "hostname": "ws01", "last_ip": "10.1.2.3"}]'


@mcp.tool(annotations=ACTION)
def quarantine_host(client_id: str, message: str = "") -> str:
    """Network-isolate an endpoint."""
    return f"quarantined {client_id}"


if __name__ == "__main__":
    mcp.run()
