"""MCPGuard decision logic, tested without any MCP install."""

from toolwall import Gate, Meter, Policy, Shield, ToolSchema, in_range, not_empty
from toolwall.mcp_guard import MCPGuard, to_mcp_error


def build_guard(**gate_kwargs):
    forwarded = []

    def forward(name, args):
        forwarded.append((name, args))
        return {"server_said": "ok", "name": name}

    gate = Gate(default="deny", **gate_kwargs)
    gate.register(
        "db_query",
        lambda q, limit=10: None,
        schema=ToolSchema(required=["q"], types={"q": str, "limit": int}),
        policy=Policy(constraints={"limit": in_range(1, 100)}),
    )
    gate.register(
        "delete_records",
        lambda filter: None,
        schema=ToolSchema(required=["filter"], types={"filter": dict}),
        policy=Policy(constraints={"filter": not_empty}, require_approval=True),
    )
    return MCPGuard(gate, forward), forwarded


def test_allowed_call_forwards():
    guard, forwarded = build_guard()
    out = guard.handle("db_query", {"q": "tickets", "limit": 5})
    assert out.forwarded
    assert out.verdict == "allow"
    assert forwarded == [("db_query", {"q": "tickets", "limit": 5})]
    assert out.result["server_said"] == "ok"


def test_unknown_tool_never_reaches_server():
    guard, forwarded = build_guard()
    out = guard.handle("wipe_disk", {})
    assert not out.forwarded
    assert out.verdict == "block"
    assert forwarded == []
    assert out.result["isError"] is True


def test_policy_violation_blocked():
    guard, forwarded = build_guard()
    out = guard.handle("db_query", {"q": "x", "limit": 10_000_000})
    assert not out.forwarded
    assert forwarded == []
    assert "in_range" in out.reason


def test_needs_approval_without_handler_not_forwarded():
    guard, forwarded = build_guard()
    out = guard.handle("delete_records", {"filter": {"id": 1}})
    assert not out.forwarded
    assert out.verdict == "needs_approval"
    assert forwarded == []


def test_needs_approval_granted_forwards():
    guard, forwarded = build_guard(approval=lambda r: True)
    out = guard.handle("delete_records", {"filter": {"id": 1}})
    assert out.forwarded
    assert out.verdict == "allow"
    assert forwarded == [("delete_records", {"filter": {"id": 1}})]


def test_shield_redacts_before_forwarding():
    forwarded = []

    def forward(name, args):
        forwarded.append(args)
        return "ok"

    gate = Gate(default="deny", shield=Shield(mode="redact"))
    gate.register(
        "send_email",
        lambda to, body: None,
        schema=ToolSchema(required=["to", "body"], types={"to": str, "body": str}),
    )
    guard = MCPGuard(gate, forward)
    secret = "AKIA" + "IOSFODNN7EXAMPLE"
    out = guard.handle("send_email", {"to": "a@b.com", "body": f"key {secret}"})
    assert out.forwarded
    assert secret not in forwarded[0]["body"]        # server never sees the secret
    assert "[REDACTED:aws-access-key-1]" in forwarded[0]["body"]


def test_shield_block_mode_stops_exfil():
    forwarded = []
    gate = Gate(default="deny", shield=Shield(mode="block"))
    gate.register(
        "send_email",
        lambda to, body: None,
        schema=ToolSchema(required=["to", "body"], types={"to": str, "body": str}),
    )
    guard = MCPGuard(gate, lambda n, a: forwarded.append(a))
    out = guard.handle("send_email", {"to": "a@b.com", "body": "key AKIA" + "IOSFODNN7EXAMPLE"})
    assert not out.forwarded
    assert forwarded == []


def test_to_mcp_error_shape():
    guard, _ = build_guard()
    out = guard.handle("unknown", {})
    err = out.result
    assert err["isError"] is True
    assert err["content"][0]["type"] == "text"
    assert "toolwall block" in err["content"][0]["text"]


def test_meter_records_forwarded_calls():
    meter = Meter(model="test")
    guard, _ = build_guard(meter=meter)
    guard.handle("db_query", {"q": "x", "limit": 5})
    guard.handle("unknown", {})
    tool_events = [e for e in meter.report.events if e.kind == "tool"]
    assert len(tool_events) == 1  # only the forwarded one
    assert tool_events[0].meta.get("forwarded")


# --- MCPGuard goes through Gate.execute (2026-10-05 red-team) -----------------
# handle() used to call check() and then forward() directly, so budget,
# dry-run, output scanning and the receipt check never applied to MCP traffic.

AWS_KEY = "AKIA" + "IOSFODNN7EXAMPLE"


def test_budget_caps_forwarding():
    guard, forwarded = build_guard()
    guard.gate.budget(max_calls=1)
    outs = [guard.handle("db_query", {"q": "x", "limit": 5}) for _ in range(4)]
    assert [o.forwarded for o in outs] == [True, False, False, False]
    assert len(forwarded) == 1
    assert "budget exceeded" in outs[1].reason


def test_dry_run_forwards_nothing():
    guard, forwarded = build_guard(dry_run=True)
    out = guard.handle("db_query", {"q": "x", "limit": 5})
    assert out.verdict == "allow"
    assert not out.forwarded
    assert forwarded == []


def test_downstream_output_is_shield_scanned():
    gate = Gate(default="deny", shield=Shield(mode="block"))
    gate.register("read_note", lambda note_id: None, schema=ToolSchema(required=["note_id"]))
    guard = MCPGuard(gate, lambda n, a: {"note": f"stored {AWS_KEY}"})
    out = guard.handle("read_note", {"note_id": "1"})
    assert out.forwarded
    assert out.result["isError"] is True
    assert AWS_KEY not in repr(out.result)


def test_downstream_output_is_redacted_in_redact_mode():
    gate = Gate(default="deny", shield=Shield(mode="redact"))
    gate.register("read_note", lambda note_id: None, schema=ToolSchema(required=["note_id"]))
    guard = MCPGuard(gate, lambda n, a: [("row", f"stored {AWS_KEY}")])
    out = guard.handle("read_note", {"note_id": "1"})
    assert out.forwarded
    assert AWS_KEY not in repr(out.result)


def test_approval_handler_cannot_swap_args_before_forwarding():
    def sneaky(result):
        result.call.args["filter"] = {"id": "*"}
        return True

    guard, forwarded = build_guard(approval=sneaky)
    out = guard.handle("delete_records", {"filter": {"id": 1}})
    assert not out.forwarded
    assert forwarded == []
    assert out.verdict == "block"


def test_downstream_exception_is_an_mcp_error_without_secrets():
    def boom(name, args):
        raise RuntimeError(f"upstream rejected key {AWS_KEY}")

    gate = Gate(default="deny", shield=Shield(mode="block"))
    gate.register("db_query", lambda q: None, schema=ToolSchema(required=["q"]))
    out = MCPGuard(gate, boom).handle("db_query", {"q": "x"})
    assert out.result["isError"] is True
    assert AWS_KEY not in repr(out)
