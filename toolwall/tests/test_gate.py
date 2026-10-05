"""Gate verdict paths — every path fail-closed."""

import pytest

from toolwall import Gate, Meter, ToolSchema, Verdict


def db_query(q: str, limit: int = 10) -> dict:
    return {"q": q, "limit": limit}


def boom(**kwargs) -> None:
    raise RuntimeError("tool exploded")


def make_gate(**kwargs) -> Gate:
    gate = Gate(**kwargs)
    gate.register("db_query", db_query, schema=ToolSchema(required=["q"], types={"q": str, "limit": int}))
    return gate


CALL = {"name": "db_query", "args": {"q": "x", "limit": 5}}


def test_allow_and_execute():
    result = make_gate().run(CALL)
    assert result.verdict is Verdict.ALLOW
    assert result.executed
    assert result.return_value == {"q": "x", "limit": 5}


def test_unknown_tool_blocks():
    result = make_gate().run({"name": "drop_database", "args": {}})
    assert result.verdict is Verdict.BLOCK
    assert not result.executed
    assert "unknown tool" in result.reasons[0]


def test_schema_violation_blocks():
    result = make_gate().run({"name": "db_query", "args": {"limit": 5}})  # missing q
    assert result.verdict is Verdict.BLOCK
    assert not result.executed


def test_type_violation_blocks():
    result = make_gate().run({"name": "db_query", "args": {"q": "x", "limit": "many"}})
    assert result.verdict is Verdict.BLOCK


def test_default_deny_blocks_schemaless_tool():
    gate = Gate(default="deny")
    gate.register("no_schema_tool", lambda **kw: "ran")
    result = gate.run({"name": "no_schema_tool", "args": {}})
    assert result.verdict is Verdict.BLOCK
    assert not result.executed


def test_default_allow_permits_schemaless_tool():
    gate = Gate(default="allow")
    gate.register("no_schema_tool", lambda: "ran")
    result = gate.run({"name": "no_schema_tool"})
    assert result.verdict is Verdict.ALLOW
    assert result.executed


def test_intake_failure_blocks():
    results = make_gate().check_all({"unrecognizable": True})
    assert len(results) == 1
    assert results[0].verdict is Verdict.BLOCK
    assert results[0].reasons[0].startswith("intake:")


def test_empty_payload_blocks():
    results = make_gate().check_all({"choices": [{"message": {"content": "no tools"}}]})
    assert results[0].verdict is Verdict.BLOCK


def test_check_never_executes():
    executed = []
    gate = Gate(default="allow")
    gate.register("t", lambda: executed.append(1))
    result = gate.check({"name": "t"})
    assert result.verdict is Verdict.ALLOW
    assert executed == []


def test_execute_refuses_blocked_result():
    gate = make_gate()
    blocked = gate.check({"name": "nope", "args": {}})
    with pytest.raises(PermissionError):
        gate.execute(blocked)


def test_tool_exception_is_captured_not_raised():
    gate = Gate(default="allow")
    gate.register("boom", boom)
    result = gate.run({"name": "boom", "args": {}})
    assert result.verdict is Verdict.ALLOW
    assert not result.executed
    assert "RuntimeError" in result.error


def test_run_all_mixed_verdicts():
    gate = make_gate()
    payload = {
        "content": [
            {"type": "tool_use", "id": "1", "name": "db_query", "input": {"q": "ok"}},
            {"type": "tool_use", "id": "2", "name": "rm_rf", "input": {}},
        ]
    }
    results = gate.run_all(payload)
    assert results[0].executed
    assert results[1].verdict is Verdict.BLOCK


def test_meter_records_verdicts():
    meter = Meter(model="test")
    gate = make_gate(meter=meter)
    gate.run(CALL)
    gate.run({"name": "nope", "args": {}})
    intercepts = [e for e in meter.report.events if e.kind == "intercept"]
    tools = [e for e in meter.report.events if e.kind == "tool"]
    assert len(intercepts) == 2
    assert intercepts[0].ok and not intercepts[1].ok
    assert len(tools) == 1 and tools[0].ok


def test_openai_shape_end_to_end():
    payload = {
        "choices": [
            {
                "message": {
                    "tool_calls": [
                        {"id": "c1", "function": {"name": "db_query", "arguments": '{"q": "cve", "limit": 3}'}}
                    ]
                }
            }
        ]
    }
    result = make_gate().run(payload)
    assert result.executed
    assert result.return_value == {"q": "cve", "limit": 3}


def test_deny_is_the_default_when_nothing_is_passed():
    # Every other test passes default= explicitly, so flipping the default
    # value itself went unnoticed (mutation run, 2026-10-05). Pin it.
    from toolwall import ToolWall
    gate = Gate()
    gate.register("t", lambda: None)
    assert gate.default == "deny"
    assert gate.run({"name": "t", "args": {}}).verdict is Verdict.BLOCK

    wall = ToolWall()
    wall.register("t", lambda: None)
    assert wall.gate.default == "deny"
    assert wall.call("t").verdict is Verdict.BLOCK
