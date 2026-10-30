"""Async tools, handlers and rules (0.4.3).

Found in the 2026-10-30 adoption audit: `wall.call()` on an `async def` tool
returned ALLOW, executed=True and an un-awaited coroutine. The tool body never
ran, the audit said it did, and when the caller awaited the coroutine the output
shield never saw the result: a secret the sync path withholds came straight
back. Most agent frameworks are async, so this was the first thing a real user
would hit.

Reading the code for that fix turned up two more places where an awaitable was
read as truthy: an async approval handler (granted without ever being asked)
and an async policy rule (passed without ever being evaluated).
"""

import asyncio
import gc
import warnings

import pytest

from toolwall import Gate, Policy, Shield, ToolSchema, ToolWall, Verdict
from toolwall.mcp_guard import MCPGuard

AWS_KEY = "AKIA" + "IOSFODNN7EXAMPLE"


def run(coro):
    return asyncio.run(coro)


def no_unawaited_coroutines(fn):
    """Fail if anything left a coroutine un-awaited (RuntimeWarning)."""
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        out = fn()
        gc.collect()
    leaked = [w for w in caught if "was never awaited" in str(w.message)]
    assert not leaked, [str(w.message) for w in leaked]
    return out


# --- sync entry points must not pretend an async tool ran ----------------------


def test_sync_call_on_async_tool_is_refused_not_reported_as_executed():
    ran = []

    async def tool():
        ran.append(1)
        return {"k": AWS_KEY}

    wall = ToolWall()
    wall.register("t", tool, schema=ToolSchema())
    result = no_unawaited_coroutines(lambda: wall.call("t"))
    assert result.verdict is Verdict.BLOCK
    assert not result.executed
    assert result.return_value is None
    assert "acall" in result.reason
    assert ran == []


def test_sync_tool_returning_an_awaitable_is_withheld():
    async def inner():
        return {"k": AWS_KEY}

    wall = ToolWall()
    wall.register("t", lambda: inner(), schema=ToolSchema())
    result = no_unawaited_coroutines(lambda: wall.call("t"))
    assert result.return_value is None
    assert not result.executed
    assert "acall" in result.error


def test_awaitable_nested_in_output_is_withheld():
    async def inner():
        return AWS_KEY

    gate = Gate(default="allow", shield=Shield(mode="block"))
    gate.register("t", lambda: {"later": inner()})
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")  # the withheld coroutine is dropped un-awaited by design
        result = gate.run({"name": "t", "args": {}})
    assert result.return_value is None
    assert "withheld" in result.error


def test_audit_never_records_an_unrun_async_tool_as_executed():
    async def tool():
        return "x"

    wall = ToolWall()
    wall.register("t", tool, schema=ToolSchema())
    no_unawaited_coroutines(lambda: wall.call("t"))
    assert wall.report()["executed"] == 0
    tool_events = [e for e in wall.meter.report.events if e.kind == "tool"]
    assert not any(e.ok for e in tool_events)


# --- the async path ----------------------------------------------------------------


def test_acall_awaits_the_tool_and_scans_its_output():
    async def tool():
        await asyncio.sleep(0)
        return {"k": AWS_KEY}

    wall = ToolWall()
    wall.register("t", tool, schema=ToolSchema())
    result = run(wall.acall("t"))
    assert result.executed
    assert result.return_value is None
    assert "tool output withheld" in result.error


def test_acall_returns_clean_async_output():
    async def tool(q: str):
        await asyncio.sleep(0)
        return {"rows": [(1, q)]}

    wall = ToolWall()
    wall.register("t", tool, schema=ToolSchema(required=["q"]))
    result = run(wall.acall("t", {"q": "hi"}))
    assert result.executed and result.error is None
    assert result.return_value == {"rows": [(1, "hi")]}


def test_acall_runs_sync_tools_too():
    wall = ToolWall()
    wall.register("t", lambda q: q.upper(), schema=ToolSchema(required=["q"]))
    result = run(wall.acall("t", {"q": "hi"}))
    assert result.executed and result.return_value == "HI"


def test_acall_keeps_every_check():
    ran = []

    async def tool(limit: int):
        ran.append(limit)

    from toolwall import in_range

    wall = ToolWall()
    wall.register("t", tool, schema=ToolSchema(required=["limit"], types={"limit": int}),
                  policy=Policy(constraints={"limit": in_range(1, 10)}))
    wall.budget(max_calls=1)
    assert run(wall.acall("t", {"limit": 99})).verdict is Verdict.BLOCK      # policy
    assert run(wall.acall("nope", {})).verdict is Verdict.BLOCK               # unknown tool
    assert run(wall.acall("t", {"limit": 5})).executed                         # allowed
    assert run(wall.acall("t", {"limit": 5})).verdict is Verdict.BLOCK       # budget
    assert ran == [5]


def test_async_tool_exception_text_is_scanned():
    async def tool():
        raise RuntimeError(f"auth failed with {AWS_KEY}")

    wall = ToolWall()
    wall.register("t", tool, schema=ToolSchema())
    result = run(wall.acall("t"))
    assert not result.executed
    assert AWS_KEY not in result.error


def test_async_budget_holds_under_concurrency():
    ran = []

    async def tool():
        await asyncio.sleep(0)
        ran.append(1)

    gate = Gate(default="deny")
    gate.register("t", tool, schema=ToolSchema())
    gate.budget(max_calls=2)

    async def main():
        return await asyncio.gather(*(gate.arun({"name": "t", "args": {}}) for _ in range(20)))

    results = run(main())
    assert len(ran) == 2
    assert sum(r.executed for r in results) == 2


def test_aguard_handles_provider_payloads():
    async def tool(q: str):
        return q

    wall = ToolWall()
    wall.register("search", tool, schema=ToolSchema(required=["q"]))
    payload = {"choices": [{"message": {"tool_calls": [
        {"id": "1", "function": {"name": "search", "arguments": '{"q": "a"}'}},
        {"id": "2", "function": {"name": "drop_db", "arguments": "{}"}},
    ]}}]}
    results = run(wall.aguard(payload))
    assert [r.verdict for r in results] == [Verdict.ALLOW, Verdict.BLOCK]
    assert results[0].return_value == "a"


# --- approval handlers -------------------------------------------------------------


def test_async_approval_handler_is_never_read_as_granted_on_the_sync_path():
    ran = []

    async def handler(result):
        return False  # a human said no

    wall = ToolWall(approval=handler)
    wall.register("wipe", lambda id: ran.append(id), schema=ToolSchema(required=["id"]),
                  policy=Policy(require_approval=True))
    result = no_unawaited_coroutines(lambda: wall.call("wipe", {"id": 1}))
    assert ran == []
    assert result.verdict is Verdict.BLOCK


def test_async_approval_handler_is_awaited_on_the_async_path():
    ran = []
    decisions = {1: True, 2: False}

    async def handler(result):
        await asyncio.sleep(0)
        return decisions[result.call.args["id"]]

    wall = ToolWall(approval=handler)
    wall.register("wipe", lambda id: ran.append(id), schema=ToolSchema(required=["id"]),
                  policy=Policy(require_approval=True))
    assert run(wall.acall("wipe", {"id": 1})).executed
    assert run(wall.acall("wipe", {"id": 2})).verdict is Verdict.BLOCK
    assert ran == [1]


# --- policy rules ------------------------------------------------------------------


def test_async_policy_rule_fails_closed():
    async def rule(value):
        return False

    ran = []
    wall = ToolWall()
    wall.register("t", lambda x: ran.append(x), schema=ToolSchema(required=["x"]),
                  policy=Policy(constraints={"x": rule}))
    result = no_unawaited_coroutines(lambda: wall.call("t", {"x": 1}))
    assert ran == []
    assert result.verdict is Verdict.BLOCK


def test_async_cross_rule_fails_closed():
    async def cross(args):
        return None

    ran = []
    wall = ToolWall()
    wall.register("t", lambda x: ran.append(x), schema=ToolSchema(required=["x"]),
                  policy=Policy(cross=cross))
    result = no_unawaited_coroutines(lambda: wall.call("t", {"x": 1}))
    assert ran == []
    assert result.verdict is Verdict.BLOCK


# --- MCP ---------------------------------------------------------------------------


def test_mcp_guard_ahandle_awaits_an_async_forward_and_scans_it():
    async def forward(name, args):
        await asyncio.sleep(0)
        return {"note": f"stored {AWS_KEY}"}

    gate = Gate(default="deny", shield=Shield(mode="block"))
    gate.register("read_note", lambda note_id: None, schema=ToolSchema(required=["note_id"]))
    out = run(MCPGuard(gate, forward).ahandle("read_note", {"note_id": "1"}))
    assert out.forwarded
    assert out.result["isError"] is True
    assert AWS_KEY not in repr(out.result)


def test_mcp_guard_sync_handle_refuses_an_async_forward():
    async def forward(name, args):
        return "ok"

    gate = Gate(default="deny")
    gate.register("t", lambda: None, schema=ToolSchema())
    out = no_unawaited_coroutines(lambda: MCPGuard(gate, forward).handle("t", {}))
    assert out.result["isError"] is True
    assert "ahandle" in out.reason or "acall" in (out.reason or "")


def test_partial_of_an_async_tool_is_still_refused_on_the_sync_path():
    import functools

    ran = []

    async def tool(prefix, q):
        ran.append(q)

    wall = ToolWall()
    wall.register("t", functools.partial(tool, "x"), schema=ToolSchema(required=["q"]))
    result = no_unawaited_coroutines(lambda: wall.call("t", {"q": "a"}))
    assert result.verdict is Verdict.BLOCK and ran == []


def test_mcp_guard_ahandle_awaits_an_async_approval_handler():
    forwarded = []

    async def approve(result):
        await asyncio.sleep(0)
        return result.call.args["id"] == 1

    gate = Gate(default="deny", approval=approve)
    gate.register("wipe", lambda id: None, schema=ToolSchema(required=["id"]),
                  policy=Policy(require_approval=True))
    guard = MCPGuard(gate, lambda n, a: forwarded.append(a["id"]) or "ok")
    assert run(guard.ahandle("wipe", {"id": 1})).forwarded
    assert not run(guard.ahandle("wipe", {"id": 2})).forwarded
    assert forwarded == [1]
