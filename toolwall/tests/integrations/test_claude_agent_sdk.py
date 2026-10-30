"""Claude Agent SDK adapter: the hook callbacks, fed the input the SDK sends.

Skipped unless claude-agent-sdk is installed (CI installs it in its own job).
"""

import asyncio

import pytest

pytest.importorskip("claude_agent_sdk")

from claude_agent_sdk import HookMatcher  # noqa: E402

from toolwall import ToolSchema, ToolWall  # noqa: E402
from toolwall import rules as r  # noqa: E402
from toolwall.integrations.claude_agent_sdk import hooks, post_tool_use, pre_tool_use  # noqa: E402

AWS_KEY = "AKIA" + "IOSFODNN7EXAMPLE"
OWNERS = {"o_9": "c_42", "o_77": "c_7"}
TOOL = "mcp__shop__issue_refund"


def make():
    wall = ToolWall()
    wall.rule(TOOL, schema=ToolSchema(required=["order_id", "amount"],
                                      types={"order_id": str, "amount": (int, float)}),
              amount=r.positive() & r.at_most(500),
              order_id=r.owned_by("customer_id", lookup=OWNERS.get),
              ask_if=r.over("amount", 200))
    return wall


def pre(wall, args, name=TOOL):
    data = {"hook_event_name": "PreToolUse", "tool_name": name, "tool_input": args}
    return asyncio.run(pre_tool_use(wall)(data, "tu_1", None))


def post(wall, response, name=TOOL):
    data = {"hook_event_name": "PostToolUse", "tool_name": name, "tool_input": {},
            "tool_response": response}
    return asyncio.run(post_tool_use(wall)(data, "tu_1", None))


def verdict(out):
    return out.get("hookSpecificOutput", {}).get("permissionDecision")


def test_allowed_call_gets_no_decision_so_permissions_still_apply():
    wall = make()
    with wall.context(customer_id="c_42"):
        assert pre(wall, {"order_id": "o_9", "amount": 40}) == {}


def test_denied_call_is_denied_with_a_safe_reason():
    wall = make()
    with wall.context(customer_id="c_42"):
        out = pre(wall, {"order_id": "o_77", "amount": 40})
    assert verdict(out) == "deny"
    reason = out["hookSpecificOutput"]["permissionDecisionReason"]
    assert "c_7" not in reason and "owned_by" not in reason


def test_held_call_asks_and_takes_a_budget_slot():
    wall = make()
    wall.budget(max_calls=1)
    with wall.context(customer_id="c_42"):
        assert verdict(pre(wall, {"order_id": "o_9", "amount": 300})) == "ask"
        assert verdict(pre(wall, {"order_id": "o_9", "amount": 300})) == "deny"


def test_unknown_tool_and_unreadable_input_are_denied():
    wall = make()
    with wall.context(customer_id="c_42"):
        assert verdict(pre(wall, {"command": "rm -rf /"}, name="Bash")) == "deny"
        assert verdict(pre(wall, "not a dict")) == "deny"


def test_no_context_means_deny():
    assert verdict(pre(make(), {"order_id": "o_9", "amount": 40})) == "deny"


def test_secret_in_arguments_is_denied_by_default():
    wall = ToolWall()
    wall.rule("mcp__shop__note", schema=ToolSchema(required=["text"], types={"text": str}))
    out = pre(wall, {"text": f"key {AWS_KEY}"}, name="mcp__shop__note")
    assert verdict(out) == "deny" and AWS_KEY not in str(out)


def test_secret_in_arguments_is_passed_on_redacted_in_redact_mode():
    wall = ToolWall(redact=True)
    wall.rule("mcp__shop__note", schema=ToolSchema(required=["text"], types={"text": str}))
    out = pre(wall, {"text": f"key {AWS_KEY}"}, name="mcp__shop__note")
    updated = out["hookSpecificOutput"]["updatedInput"]
    assert AWS_KEY not in updated["text"] and "permissionDecision" not in out["hookSpecificOutput"]


def test_output_secrets_are_redacted_keeping_the_shape():
    wall = make()
    response = {"stdout": f"plan pro, key {AWS_KEY}", "stderr": "", "interrupted": False}
    out = post(wall, response)
    cleaned = out["hookSpecificOutput"]["updatedToolOutput"]
    assert set(cleaned) == set(response) and AWS_KEY not in cleaned["stdout"]
    assert cleaned["interrupted"] is False


def test_clean_output_is_left_alone():
    assert post(make(), {"stdout": "refunded 40"}) == {}


def test_hooks_builds_matchers_for_both_events():
    built = hooks(make(), matcher="^mcp__shop__")
    assert set(built) == {"PreToolUse", "PostToolUse"}
    for matchers in built.values():
        assert isinstance(matchers[0], HookMatcher) and matchers[0].matcher == "^mcp__shop__"


def test_held_call_in_redact_mode_hands_on_the_redacted_arguments():
    # The person approving, and the tool once approved, must not see the secret.
    wall = ToolWall(redact=True)
    wall.rule("mcp__shop__pay", schema=ToolSchema(required=["text"], types={"text": str}),
              require_approval=True)
    out = pre(wall, {"text": f"pay to {AWS_KEY}"}, name="mcp__shop__pay")
    spec = out["hookSpecificOutput"]
    assert spec["permissionDecision"] == "ask"
    assert AWS_KEY not in spec["updatedInput"]["text"]
