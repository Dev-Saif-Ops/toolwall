"""ToolWall for MCP servers built with the official Python SDK.

    from mcp.server.mcpserver import MCPServer        # mcp 2.x (FastMCP in 1.x)
    from toolwall.integrations.mcp import guard

    server = MCPServer("shop")

    @server.tool()
    @guard(wall)
    async def issue_refund(order_id: str, amount: int | float) -> str: ...

guard(wall) is wall.protect with the SDK's ToolError as the exception, so a
blocked or held call becomes an MCP tool error whose text is the model-safe
reason, and the tool keeps its signature for the server to read. Works with
mcp 1.x (FastMCP) and 2.x (MCPServer).

To gate calls you forward to another MCP server, use toolwall.MCPGuard.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # pragma: no cover
    from toolwall.wall import ToolWall


def _tool_error() -> type[BaseException]:
    try:
        from mcp.server.mcpserver.exceptions import ToolError  # mcp 2.x
    except ImportError:
        from mcp.server.fastmcp.exceptions import ToolError  # mcp 1.x
    return ToolError


def guard(wall: "ToolWall", fn: Any = None, *, name: str | None = None) -> Any:
    """@guard(wall): the wall's checks on every call, ToolError on a block."""
    return wall.protect(fn, name=name, error=_tool_error())
