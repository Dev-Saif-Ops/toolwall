"""@wall.protect, take_slot() and the 0.6 adapter building blocks."""

import asyncio
import inspect

import pytest

from toolwall import ToolBlocked, ToolSchema, ToolWall
from toolwall import rules as r

OWNERS = {"o_9": "c_42", "o_77": "c_7"}


def refund_wall():
    wall = ToolWall()
    ran = []

    @wall.protect
    def issue_refund(order_id: str, amount: int | float = 10) -> str:
        ran.append((order_id, amount))
        return f"refunded {amount}"

    wall.rule("issue_refund",
              amount=r.positive() & r.at_most(500),
              order_id=r.owned_by("customer_id", lookup=OWNERS.get),
              ask_if=r.over("amount", 200))
    return wall, issue_refund, ran


def test_protect_runs_allowed_calls_and_keeps_the_signature():
    wall, issue_refund, ran = refund_wall()
    assert list(inspect.signature(issue_refund).parameters) == ["order_id", "amount"]
    with wall.context(customer_id="c_42"):
        assert issue_refund("o_9", amount=40) == "refunded 40"
        assert issue_refund("o_9") == "refunded 10"  # defaults are checked too
    assert ran == [("o_9", 40), ("o_9", 10)]


def test_protect_raises_with_the_model_safe_reason_on_deny_and_ask():
    wall, issue_refund, ran = refund_wall()
    with wall.context(customer_id="c_42"):
        with pytest.raises(ToolBlocked) as denied:
            issue_refund("o_77", 40)
        with pytest.raises(ToolBlocked):
            issue_refund("o_9", 300)  # held for a person: does not run
    assert ran == []
    assert "c_7" not in str(denied.value) and "owned_by" not in str(denied.value)


def test_protect_custom_error_and_async():
    wall = ToolWall()
    ran = []

    class Refused(Exception):
        pass

    @wall.protect(error=Refused)
    async def delete_user(user_id: str) -> str:
        ran.append(user_id)
        return "gone"

    wall.rule("delete_user", user_id=r.one_of("u_test"))
    assert asyncio.run(delete_user("u_test")) == "gone"
    with pytest.raises(Refused):
        asyncio.run(delete_user("u_admin"))
    assert ran == ["u_test"]


def test_protect_keeps_an_existing_registration():
    wall = ToolWall()
    wall.rule("lookup", schema=ToolSchema(required=["q"], types={"q": str}))

    @wall.protect(name="lookup")
    def lookup(q):  # untyped: the declared schema still applies
        return q

    assert lookup("x") == "x"
    with pytest.raises(ToolBlocked):
        lookup(5)


def test_wall_guard_still_gates_a_raw_response():
    # 0.4 API: wall.guard(response) must not be shadowed by the decorator.
    wall, _, _ = refund_wall()
    params = list(inspect.signature(wall.guard).parameters)
    assert params == ["response"]


def test_take_slot_only_turns_ask_into_allow():
    wall, _, _ = refund_wall()
    wall.budget(max_calls=1)
    with wall.context(customer_id="c_42"):
        denied = wall.decide("issue_refund", {"order_id": "o_77", "amount": 40})
        assert wall.take_slot(denied).verdict == "deny"
        held = wall.decide("issue_refund", {"order_id": "o_9", "amount": 300})
        assert held.verdict == "ask"
        assert wall.take_slot(held).verdict == "allow"
        assert wall.take_slot(held).verdict == "deny"  # budget spent


def test_protect_refuses_a_name_registered_to_another_function():
    wall = ToolWall()
    wall.register("lookup", lambda q: q, schema=ToolSchema(required=["q"]))
    with pytest.raises(ValueError):
        @wall.protect(name="lookup")
        def lookup(q: str) -> str:
            return q


def test_protect_withholds_output_carrying_a_secret():
    wall = ToolWall()
    key = "AKIA" + "IOSFODNN7EXAMPLE"

    @wall.protect
    def leak(x: str) -> str:
        return f"key {key}"

    with pytest.raises(ToolBlocked) as e:
        leak("a")
    assert key not in str(e.value)
