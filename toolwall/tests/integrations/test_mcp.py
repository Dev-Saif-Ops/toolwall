"""MCP adapter: @guard(wall) under the official SDK's server, called in process.

Skipped unless mcp is installed.
"""

import asyncio

import pytest

pytest.importorskip("mcp")

from toolwall import ToolWall  # noqa: E402
from toolwall import rules as r  # noqa: E402
from toolwall.integrations.mcp import _tool_error, guard  # noqa: E402

try:  # mcp 2.x
    from mcp.server.mcpserver import MCPServer as Server
except ImportError:  # mcp 1.x
    from mcp.server.fastmcp import FastMCP as Server

OWNERS = {"o_9": "c_42", "o_77": "c_7"}


def make(ran):
    wall = ToolWall()
    server = Server("shop")

    @server.tool()
    @guard(wall)
    async def issue_refund(order_id: str, amount: int | float) -> str:
        """Refund an order."""
        ran.append((order_id, amount))
        return f"refunded {amount} on {order_id}"

    wall.rule("issue_refund",
              amount=r.positive() & r.at_most(500),
              order_id=r.owned_by("customer_id", lookup=OWNERS.get),
              ask_if=r.over("amount", 200))
    return wall, server


def call(server, args):
    return asyncio.run(server.call_tool("issue_refund", args))


def test_the_server_still_sees_the_tool_signature():
    _, server = make([])
    tools = asyncio.run(server.list_tools())
    schema = getattr(tools[0], "input_schema", None) or tools[0].inputSchema  # 2.x / 1.x
    assert set(schema["properties"]) == {"order_id", "amount"}


def test_allowed_call_runs():
    ran = []
    wall, server = make(ran)
    with wall.context(customer_id="c_42"):
        call(server, {"order_id": "o_9", "amount": 40})
    assert ran == [("o_9", 40)]


def test_denied_and_held_calls_become_tool_errors_with_safe_reasons():
    ran = []
    wall, server = make(ran)
    with wall.context(customer_id="c_42"):
        with pytest.raises(_tool_error()) as denied:
            call(server, {"order_id": "o_77", "amount": 40})
        with pytest.raises(_tool_error()):
            call(server, {"order_id": "o_9", "amount": 300})
    assert ran == []
    assert "c_7" not in str(denied.value) and "owned_by" not in str(denied.value)


def test_no_context_means_no_refund():
    ran = []
    _, server = make(ran)
    with pytest.raises(_tool_error()):
        call(server, {"order_id": "o_9", "amount": 40})
    assert ran == []


def test_a_held_call_can_be_approved_and_then_runs_once():
    ran = []
    wall, server = make(ran)
    with wall.context(customer_id="c_42"):
        with pytest.raises(_tool_error()):
            call(server, {"order_id": "o_9", "amount": 300})
        ticket = wall.approvals.pending()[0].id
        wall.approvals.approve(ticket, by="ops")
        call(server, {"order_id": "o_9", "amount": 300})
        with pytest.raises(_tool_error()):
            call(server, {"order_id": "o_9", "amount": 300})
    assert ran == [("o_9", 300)]
