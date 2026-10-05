"""Property-based fuzzing of the one invariant everything else rests on:

    if the verdict is not ALLOW, the underlying callable must never run.

Generated with stdlib `random` under a fixed seed so failures are reproducible
without adding a test dependency. Every tool counts its own invocations, so a
single leaked execution anywhere fails the run.
"""

from __future__ import annotations

import math
import random
import string
from decimal import Decimal

import pytest

from toolwall import (
    Gate,
    Policy,
    Shield,
    ToolSchema,
    Verdict,
    email_domain,
    in_range,
    not_empty,
)

SEED = 20260829
CASES = 2000

CALLS: dict[str, int] = {}


def counted(name):
    """A tool that records every real invocation."""

    def tool(**kwargs):
        CALLS[name] = CALLS.get(name, 0) + 1
        return {"ran": name}

    return tool


REGISTERED = ["db_query", "send_email", "delete_records", "read_file"]
UNREGISTERED = ["run_shell", "purge", "", "db_query ", "DB_QUERY", "../db_query", "𝚍𝚋_𝚚𝚞𝚎𝚛𝚢"]


def build_gate(shield_mode="block"):
    CALLS.clear()
    gate = Gate(default="deny", shield=Shield(mode=shield_mode))
    gate.register("db_query", counted("db_query"),
                  schema=ToolSchema(required=["q"], types={"q": str, "limit": int}),
                  policy=Policy(constraints={"limit": in_range(1, 100)}))
    gate.register("send_email", counted("send_email"),
                  schema=ToolSchema(required=["to", "body"], types={"to": str, "body": str}),
                  policy=Policy(constraints={"to": email_domain("ourco.com")}))
    gate.register("delete_records", counted("delete_records"),
                  schema=ToolSchema(required=["filter"], types={"filter": dict}),
                  policy=Policy(constraints={"filter": not_empty}, require_approval=True))
    gate.register("read_file", counted("read_file"),
                  schema=ToolSchema(required=["path"], types={"path": str}),
                  policy=Policy(cross=lambda a: "traversal" if ".." in str(a.get("path", "")) else None))
    return gate


# --- generators --------------------------------------------------------------

def rand_scalar(rng, depth=0):
    kind = rng.randrange(14)
    if kind == 0:
        return rng.randint(-(2**70), 2**70)          # huge ints
    if kind == 1:
        return rng.choice([float("nan"), float("inf"), float("-inf"), -0.0])
    if kind == 2:
        return rng.choice(["", " ", "\x00", "\n\r\t"])
    if kind == 3:
        return rng.choice([None, True, False])
    if kind == 4:
        return "".join(rng.choice(string.printable) for _ in range(rng.randrange(0, 40)))
    if kind == 5:
        return rng.choice(["🔥", "𝚡" * 8, "café", "‮", "ＡＢＣ", "０１２"])
    if kind == 6:
        return rng.choice(["AKIA" + "IOSFODNN7EXAMPLE", "sk-" + "a" * 24, "-----BEGIN RSA PRIVATE KEY-----"])
    if kind == 7 and depth < 3:
        return [rand_scalar(rng, depth + 1) for _ in range(rng.randrange(0, 4))]
    if kind == 8 and depth < 3:
        return {rand_key(rng): rand_scalar(rng, depth + 1) for _ in range(rng.randrange(0, 4))}
    if kind == 9:
        return rng.choice([[], {}, (), set()])
    if kind == 10:
        return rng.choice(["a@ourco.com", "a@evil.com", "/app/x", "/app/../etc/x"])
    if kind == 11:
        return rng.randrange(-5, 1000)
    if kind == 12:
        return "x" * rng.choice([0, 1, 10_000])
    return rng.choice([object(), Exception("boom"), lambda: 1])   # unserializable junk


def rand_key(rng):
    return rng.choice(["q", "limit", "to", "body", "filter", "path", "", "__init__",
                       "q ", "Q", "🔥", "a" * 200, "self", "kwargs"])


def rand_args(rng):
    shape = rng.randrange(6)
    if shape == 0:
        return {}
    if shape == 1:
        return {rand_key(rng): rand_scalar(rng) for _ in range(rng.randrange(1, 5))}
    if shape == 2:
        return rng.choice([None, [], "notadict", 42, True])       # not an args object at all
    if shape == 3:
        return {"q": rand_scalar(rng), "limit": rand_scalar(rng)}
    if shape == 4:
        return {"to": rand_scalar(rng), "body": rand_scalar(rng)}
    return {"filter": rand_scalar(rng), "path": rand_scalar(rng)}


def rand_payload(rng):
    name = rng.choice(REGISTERED + UNREGISTERED + [rand_scalar(rng)])
    args = rand_args(rng)
    style = rng.randrange(4)
    if style == 0:
        return {"name": name, "args": args}
    if style == 1:
        return {"content": [{"type": "tool_use", "id": "1", "name": name, "input": args}]}
    if style == 2:
        return {"candidates": [{"content": {"parts": [{"functionCall": {"name": name, "args": args}}]}}]}
    return {"choices": [{"message": {"tool_calls": [
        {"id": "1", "function": {"name": name, "arguments": args}}]}}]}


# --- the invariant -----------------------------------------------------------

@pytest.mark.parametrize("shield_mode", ["block", "redact", "warn"])
def test_non_allow_never_executes(shield_mode):
    """No verdict other than ALLOW may result in the tool running."""
    rng = random.Random(SEED)
    gate = build_gate(shield_mode)
    checked = 0

    for _ in range(CASES):
        payload = rand_payload(rng)
        before = dict(CALLS)
        try:
            results = gate.run_all(payload)
        except Exception as exc:                     # a crash is itself fail-open risk
            pytest.fail(f"gate raised on payload {payload!r}: {type(exc).__name__}: {exc}")
        checked += len(results)

        executed_names = {k for k in CALLS if CALLS[k] != before.get(k, 0)}
        allowed_names = {r.call.name for r in results if r.allowed and r.call}
        leaked = executed_names - allowed_names
        assert not leaked, f"tool ran without an ALLOW verdict: {leaked} on {payload!r}"

        for r in results:
            if not r.allowed:
                assert not r.executed, f"{r.verdict} result marked executed: {payload!r}"

    assert checked >= CASES, "generator produced no results"


def test_blocked_calls_never_reach_the_tool_even_when_shield_disabled():
    """Same invariant with no shield attached at all."""
    rng = random.Random(SEED + 1)
    CALLS.clear()
    gate = Gate(default="deny")
    gate.register("db_query", counted("db_query"),
                  schema=ToolSchema(required=["q"], types={"q": str, "limit": int}),
                  policy=Policy(constraints={"limit": in_range(1, 100)}))

    for _ in range(CASES):
        payload = rand_payload(rng)
        results = gate.run_all(payload)
        for r in results:
            if not r.allowed:
                assert not r.executed


def test_budget_is_never_exceeded_under_fuzz():
    """However calls arrive, an executed-call cap must hold."""
    rng = random.Random(SEED + 2)
    CALLS.clear()
    gate = build_gate("warn")
    gate.approval = lambda r: True          # worst case: approvals always granted
    gate.budget(max_calls=25)

    for _ in range(CASES):
        gate.run_all(rand_payload(rng))

    assert sum(CALLS.values()) <= 25, f"budget exceeded: {sum(CALLS.values())} executions"


def test_dry_run_never_executes_anything():
    rng = random.Random(SEED + 3)
    CALLS.clear()
    gate = build_gate("warn")
    gate.dry_run = True
    gate.approval = lambda r: True

    for _ in range(CASES):
        gate.run_all(rand_payload(rng))

    assert CALLS == {}, f"dry run executed tools: {CALLS}"


def test_nan_and_inf_do_not_slip_past_range_policy():
    """NaN comparisons are always False; make sure that can't read as 'in range'.

    The argument is deliberately untyped. An earlier version of this test used
    db_query, whose schema types limit as int, so the schema rejected the float
    before in_range ever saw it and the test passed with in_range broken.
    """
    CALLS.clear()
    gate = Gate(default="deny", shield=Shield(mode="warn"))
    gate.register("transfer", counted("transfer"),
                  schema=ToolSchema(required=["amount"]),
                  policy=Policy(constraints={"amount": in_range(0, 1000)}))
    for bad in (float("nan"), float("inf"), float("-inf"), "nan", "NaN", "inf", Decimal("NaN")):
        result = gate.run({"name": "transfer", "args": {"amount": bad}})
        assert not result.executed, f"amount={bad!r} executed"
    assert CALLS == {}
