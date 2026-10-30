"""decide(), check_output(), context and model-safe reasons (0.5).

decide() is the verdict-only path for frameworks that run the tool themselves
(OpenAI Agents SDK guardrails, Claude Agent SDK hooks, LangChain middleware).
"""

import asyncio
import threading

import pytest

from toolwall import Shield, ToolSchema, ToolWall, Verdict
from toolwall import rules as r

AWS_KEY = "AKIA" + "IOSFODNN7EXAMPLE"
OWNERS = {"o_9": "c_42", "o_77": "c_7"}


def wall_for_framework():
    """Tools the framework runs: declared by schema, never by function."""
    wall = ToolWall()
    wall.rule("issue_refund",
              schema=ToolSchema(required=["order_id", "amount"],
                                types={"order_id": str, "amount": (int, float)}),
              amount=r.positive() & r.at_most(500),
              order_id=r.owned_by("customer_id", lookup=OWNERS.get),
              ask_if=r.over("amount", 200))
    wall.rule("send_email",
              schema=ToolSchema(required=["to", "body"], types={"to": str, "body": str}),
              to=r.email_domain("ourco.com") | r.equals_context("customer_email"))
    return wall


def test_decide_allow_deny_ask():
    wall = wall_for_framework()
    with wall.context(customer_id="c_42", customer_email="amal@example.com"):
        ok = wall.decide("issue_refund", {"order_id": "o_9", "amount": 40})
        assert ok.verdict == "allow" and ok.allowed and ok.reason is None
        too_big = wall.decide("issue_refund", {"order_id": "o_9", "amount": 5000})
        assert too_big.verdict == "deny" and too_big.denied
        held = wall.decide("issue_refund", {"order_id": "o_9", "amount": 300})
        assert held.verdict == "ask" and held.needs_approval
        assert wall.decide("send_email", {"to": "amal@example.com", "body": "hi"}).allowed
        assert wall.decide("send_email", {"to": "x@evil.com", "body": "hi"}).denied
        assert wall.decide("drop_db", {}).denied


def test_model_reason_does_not_reveal_the_policy():
    wall = wall_for_framework()
    with wall.context(customer_id="c_42", customer_email="amal@example.com"):
        d = wall.decide("send_email", {"to": "x@evil.com", "body": "hi"})
    assert "ourco.com" not in d.reason and "email_domain" not in d.reason
    assert "'to'" in d.reason
    assert "email_domain" in d.detail  # the full reason is kept for the audit log


def test_model_reasons_by_kind():
    wall = wall_for_framework()
    with wall.context(customer_id="c_42"):
        assert "not available" in wall.decide("drop_db", {}).reason
        assert "arguments" in wall.decide("issue_refund", {"order_id": 9}).reason
        secret = wall.decide("send_email", {"to": "ops@ourco.com", "body": f"key {AWS_KEY}"})
        assert secret.denied and "secret" in secret.reason and AWS_KEY not in secret.reason
        assert "approval" in wall.decide("issue_refund", {"order_id": "o_9", "amount": 300}).reason


def test_gate_results_carry_model_reasons_too():
    wall = ToolWall()
    wall.register("t", lambda q: q, schema=ToolSchema(required=["q"]))
    wall.rule("t", q=r.one_of("a"))
    res = wall.call("t", {"q": "b"})
    assert res.blocked and res.model_reason and "one_of" not in res.model_reason
    assert wall.call("t", {"q": "a"}).model_reason is None


def test_decide_counts_toward_budgets():
    wall = wall_for_framework()
    wall.budget(max_calls=2)
    with wall.context(customer_id="c_42"):
        verdicts = [wall.decide("issue_refund", {"order_id": "o_9", "amount": 1}).verdict for _ in range(4)]
    assert verdicts == ["allow", "allow", "deny", "deny"]


def test_decide_budget_holds_under_threads():
    wall = wall_for_framework()
    wall.budget(max_calls=3)
    out = []

    def worker():
        with wall.context(customer_id="c_42"):
            out.append(wall.decide("issue_refund", {"order_id": "o_9", "amount": 1}).verdict)

    threads = [threading.Thread(target=worker) for _ in range(30)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert out.count("allow") == 3


def test_decided_only_tool_cannot_be_run_through_call():
    wall = wall_for_framework()
    with wall.context(customer_id="c_42"):
        res = wall.call("issue_refund", {"order_id": "o_9", "amount": 1})
    assert res.verdict is Verdict.BLOCK and not res.executed
    assert "framework" in res.reason


def test_decide_returns_the_checked_arguments_and_a_receipt():
    wall = ToolWall(redact=True)
    wall.rule("send_email", schema=ToolSchema(required=["to", "body"]))
    d = wall.decide("send_email", {"to": "ops@ourco.com", "body": f"key {AWS_KEY}"})
    assert d.allowed and AWS_KEY not in str(d.args)  # redact mode: run these args
    assert d.receipt


def test_adecide():
    wall = wall_for_framework()

    async def main():
        with wall.context(customer_id="c_42"):
            return await wall.adecide("issue_refund", {"order_id": "o_9", "amount": 40})

    assert asyncio.run(main()).allowed


# --- context isolation --------------------------------------------------------------


def test_context_is_isolated_between_concurrent_tasks():
    wall = wall_for_framework()

    async def as_customer(cid, order):
        with wall.context(customer_id=cid):
            await asyncio.sleep(0)  # interleave with the other task
            return wall.decide("issue_refund", {"order_id": order, "amount": 1}).verdict

    async def main():
        return await asyncio.gather(
            *(as_customer("c_42", "o_77") for _ in range(20)),   # not theirs
            *(as_customer("c_7", "o_77") for _ in range(20)),    # theirs
        )

    results = asyncio.run(main())
    assert results[:20] == ["deny"] * 20 and results[20:] == ["allow"] * 20


def test_context_is_isolated_between_threads():
    wall = wall_for_framework()
    results = {}
    barrier = threading.Barrier(2)

    def worker(cid):
        with wall.context(customer_id=cid):
            barrier.wait()
            results[cid] = wall.decide("issue_refund", {"order_id": "o_77", "amount": 1}).verdict

    a = threading.Thread(target=worker, args=("c_42",))
    b = threading.Thread(target=worker, args=("c_7",))
    a.start(); b.start(); a.join(); b.join()
    assert results == {"c_42": "deny", "c_7": "allow"}


def test_nested_contexts_merge_and_restore():
    wall = ToolWall()
    from toolwall.context import current
    with wall.context(customer_id="c_42", tenant="t1"):
        with wall.context(customer_id="c_7"):
            assert dict(current()) == {"customer_id": "c_7", "tenant": "t1"}
        assert dict(current()) == {"customer_id": "c_42", "tenant": "t1"}
    assert dict(current()) == {}


def test_context_values_are_not_written_to_the_audit_log(tmp_path):
    wall = wall_for_framework()
    with wall.context(customer_id="c_42", customer_email="amal@example.com"):
        wall.decide("send_email", {"to": "x@evil.com", "body": "hi"})
    paths = wall.export(str(tmp_path / "a.json"), str(tmp_path / "a.csv"))
    text = "".join(p.read_text(encoding="utf-8") for p in paths.values())
    assert "amal@example.com" not in text
    assert "customer_email" in text  # the key is recorded, the value is not


# --- check_output -------------------------------------------------------------------


def test_check_output_withholds_and_redacts():
    wall = ToolWall()
    out = wall.check_output("lookup", {"key": AWS_KEY})
    assert out.withheld and out.value is None and "secret" in out.reason
    clean = wall.check_output("lookup", {"plan": "pro"})
    assert not clean.withheld and clean.value == {"plan": "pro"}
    red = ToolWall(redact=True).check_output("lookup", {"key": AWS_KEY})
    assert not red.withheld and AWS_KEY not in str(red.value)


def test_check_output_withholds_lazy_values():
    async def stream():
        yield 1

    assert ToolWall().check_output("t", stream()).withheld
