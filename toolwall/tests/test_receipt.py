"""Argument receipts: what was checked is what executes.

Reported on Reddit by u/deelight_0909: "Let a mutable delete_records argument pass
with a narrow filter, then replace the filter with {} before execution. If it trusts
a bare ALLOW boolean, fail-closed can reopen one line later." Reproduced on both
paths before fixing.
"""

import pytest

from toolwall import Gate, Policy, ToolSchema, Verdict, not_empty
from toolwall.receipt import ReceiptError, fingerprint


def build(approval=None):
    ran = []

    def delete_records(filter: dict):
        ran.append(dict(filter))
        return {"ok": True}

    gate = Gate(default="deny", approval=approval)
    gate.register(
        "delete_records",
        delete_records,
        schema=ToolSchema(required=["filter"], types={"filter": dict}),
        policy=Policy(
            constraints={"filter": not_empty},
            require_approval=approval is not None,
        ),
    )
    return gate, ran


def test_caller_cannot_swap_args_after_the_verdict():
    """The caller keeps a reference to the dict it passed in."""
    gate, ran = build()
    payload = {"name": "delete_records", "args": {"filter": {"id": 42}}}

    result = gate.check(payload)
    assert result.allowed

    payload["args"]["filter"].clear()  # widen the delete to everything
    gate.execute(result)

    assert ran == [{"id": 42}], "the tool must receive the arguments that were checked"


def test_approval_handler_cannot_swap_args():
    """The handler is given the GateResult itself, so it can reach the gate's own copy."""
    def approver(result):
        result.call.args["filter"] = {}
        return True

    gate, ran = build(approval=approver)
    out = gate.run({"name": "delete_records", "args": {"filter": {"id": 42}}})

    assert ran == [], "nothing may run once the approved arguments have changed"
    assert out.verdict is Verdict.BLOCK
    assert not out.executed
    assert "changed between check and execute" in " ".join(out.reasons)


def test_direct_mutation_between_check_and_execute_is_refused():
    gate, ran = build()
    result = gate.check({"name": "delete_records", "args": {"filter": {"id": 42}}})
    result.call.args["filter"] = {}

    out = gate.execute(result)
    assert ran == []
    assert out.verdict is Verdict.BLOCK
    assert not out.executed


def test_a_refused_execute_does_not_spend_budget():
    gate, ran = build()
    gate.budget(max_calls=1)

    first = gate.check({"name": "delete_records", "args": {"filter": {"id": 1}}})
    first.call.args["filter"] = {}
    gate.execute(first)  # refused, must not consume the single allowed call

    second = gate.run({"name": "delete_records", "args": {"filter": {"id": 2}}})
    assert second.executed and ran == [{"id": 2}]


def test_unfingerprintable_args_block_by_default():
    gate = Gate(default="deny")
    gate.register("takes_object", lambda thing: "ran", schema=ToolSchema(required=["thing"]))

    out = gate.run({"name": "takes_object", "args": {"thing": object()}})
    assert out.blocked
    assert not out.executed
    assert "cannot bind receipt" in out.reasons[0]


def test_receipt_false_is_an_explicit_opt_out():
    gate = Gate(default="deny")
    gate.register(
        "takes_object",
        lambda thing: "ran",
        schema=ToolSchema(required=["thing"]),
        receipt=False,
    )

    out = gate.run({"name": "takes_object", "args": {"thing": object()}})
    assert out.allowed and out.executed
    assert out.receipt is None


def test_replace_clears_a_previous_opt_out():
    """A re-registration must not inherit the old tool's weaker guarantee."""
    gate = Gate(default="deny")
    gate.register("t", lambda thing: "a", schema=ToolSchema(required=["thing"]), receipt=False)
    gate.register("t", lambda thing: "b", schema=ToolSchema(required=["thing"]), replace=True)

    assert gate.registry.wants_receipt("t")
    assert gate.run({"name": "t", "args": {"thing": object()}}).blocked


def test_key_order_does_not_produce_a_false_block():
    assert fingerprint("t", {"a": 1, "b": 2}) == fingerprint("t", {"b": 2, "a": 1})


@pytest.mark.parametrize(
    "left,right",
    [
        ({"v": 1}, {"v": True}),          # bool is an int in Python
        ({"v": 1}, {"v": 1.0}),           # 1 == 1.0
        ({"v": [1]}, {"v": (1,)}),        # list vs tuple
        ({"v": {}}, {"v": {"id": 1}}),    # the reported case
        ({"v": "1"}, {"v": 1}),
    ],
)
def test_distinguishable_values_get_distinct_fingerprints(left, right):
    assert fingerprint("t", left) != fingerprint("t", right)


def test_tool_name_is_part_of_the_receipt():
    assert fingerprint("delete_records", {"a": 1}) != fingerprint("read_records", {"a": 1})


def test_redacted_args_still_execute():
    """The shield rewrites args during check; the receipt must cover the rewritten form."""
    from toolwall import Shield

    ran = []
    gate = Gate(default="deny", shield=Shield(mode="redact"))
    gate.register(
        "note",
        lambda text: ran.append(text),
        schema=ToolSchema(required=["text"], types={"text": str}),
    )

    out = gate.run({"name": "note", "args": {"text": "key " + "AKIA" + "IOSFODNN7EXAMPLE"}})
    assert out.executed
    assert "AKIA" + "IOSFODNN7EXAMPLE" not in ran[0]


def test_fingerprint_rejects_non_string_dict_keys():
    with pytest.raises(ReceiptError, match="dict keys"):
        fingerprint("t", {"a": {1: "x"}})


def test_an_approved_result_cannot_be_replayed():
    """One verdict authorises one execution, not a stream of them."""
    gate, ran = build()
    result = gate.check({"name": "delete_records", "args": {"filter": {"id": 42}}})

    gate.execute(result)
    again = gate.execute(result)

    assert ran == [{"id": 42}], "the same approved result must not run twice"
    assert again.verdict is Verdict.BLOCK
    assert "already spent" in " ".join(again.reasons)


def test_replay_is_refused_even_when_the_first_attempt_failed():
    """A tool that raised may still have had side effects; a retry gets re-checked."""
    gate = Gate(default="deny")
    calls = []

    def flaky(x: int):
        calls.append(x)
        raise RuntimeError("boom")

    gate.register("flaky", flaky, schema=ToolSchema(required=["x"], types={"x": int}))
    result = gate.check({"name": "flaky", "args": {"x": 1}})

    first = gate.execute(result)
    assert not first.executed and first.error

    second = gate.execute(result)
    assert calls == [1], "a failed attempt is still an attempt"
    assert second.verdict is Verdict.BLOCK


def test_unreceipted_tools_still_run_once_per_verdict():
    """receipt=False opts out of tamper-checking the arguments, not of single use.

    Replay protection used to live on the receipt, so this was a documented
    limitation. It now comes from the gate's own issue record.
    """
    gate = Gate(default="deny")
    ran = []
    gate.register(
        "obj", lambda thing: ran.append(1),
        schema=ToolSchema(required=["thing"]), receipt=False,
    )
    r = gate.check({"name": "obj", "args": {"thing": object()}})
    gate.execute(r)
    again = gate.execute(r)
    assert len(ran) == 1
    assert again.verdict is Verdict.BLOCK


# --- common stdlib value types must not be false-blocked ------------------------

def test_common_value_types_are_fingerprintable():
    """datetime, date, time, Decimal, UUID and Enum are ordinary tool arguments.

    Blocking them would be a false block caused by the canonicaliser being
    unfinished, not by anything being unsafe. Found by probing with realistic
    args (a booking date, a Decimal price) rather than the suite's plain types.
    """
    import datetime as dt
    import enum
    import uuid
    from decimal import Decimal

    class Tier(enum.Enum):
        FREE = "f"
        PRO = "p"

    gate = Gate(default="deny")
    seen = []
    gate.register("book", lambda **kw: seen.append(kw), schema=ToolSchema())

    out = gate.run({
        "name": "book",
        "args": {
            "when": dt.datetime(2026, 8, 29, 10, 30),
            "day": dt.date(2026, 8, 29),
            "at": dt.time(10, 30),
            "price": Decimal("10.50"),
            "ref": uuid.UUID("12345678-1234-5678-1234-567812345678"),
            "tier": Tier.PRO,
        },
    })
    assert out.allowed and out.executed


def test_swapping_a_datetime_is_still_caught():
    """The new types are tamper-checked like everything else, not exempted."""
    import datetime as dt

    gate = Gate(default="deny")
    ran = []
    gate.register("book", lambda when: ran.append(when), schema=ToolSchema(required=["when"]))

    result = gate.check({"name": "book", "args": {"when": dt.datetime(2026, 8, 29)}})
    result.call.args["when"] = dt.datetime(1999, 1, 1)

    out = gate.execute(result)
    assert ran == [] and out.blocked


def test_new_types_cannot_collide_with_their_string_forms():
    import datetime as dt
    import enum
    from decimal import Decimal

    class Level(enum.IntEnum):
        HIGH = 2

    assert fingerprint("t", {"v": Decimal("10.50")}) != fingerprint("t", {"v": "10.50"})
    assert fingerprint("t", {"v": dt.datetime(2026, 8, 29)}) != fingerprint(
        "t", {"v": "2026-08-29T00:00:00"}
    )
    # IntEnum subclasses int; the member must not fingerprint as its value
    assert fingerprint("t", {"v": Level.HIGH}) != fingerprint("t", {"v": 2})
    # exponent is preserved: numerically equal Decimals may differ, which can only
    # refuse a swap, never admit one
    assert fingerprint("t", {"v": Decimal("10.50")}) != fingerprint("t", {"v": Decimal("10.5")})


# --- window 3: after the hash passes, before/while the tool reads the args ------

def test_tool_receives_the_verified_snapshot_not_the_hashed_object():
    """If the tool is handed the same mutable object that was hashed, the receipt
    proves the past, not the call. The executed args must not be reachable
    through the GateResult at all."""
    seen = {}
    gate = Gate(default="deny")
    gate.register(
        "d", lambda filter: seen.setdefault("obj", filter),
        schema=ToolSchema(required=["filter"], types={"filter": dict}),
    )
    result = gate.check({"name": "d", "args": {"filter": {"id": 1}}})
    gate.execute(result)

    assert seen["obj"] == {"id": 1}
    assert seen["obj"] is not result.call.args["filter"]


def test_mutation_from_another_thread_during_execution_cannot_reach_the_tool():
    """deelight_0909's barrier spec: hash passes, another thread mutates
    GateResult.call.args, barrier releases. The tool must read the frozen
    verified snapshot."""
    import threading

    got = {}
    started = threading.Event()
    proceed = threading.Event()

    def slow_delete(filter: dict):
        started.set()
        assert proceed.wait(timeout=5)
        got["filter"] = dict(filter)
        return {"ok": True}

    gate = Gate(default="deny")
    gate.register(
        "slow_delete", slow_delete,
        schema=ToolSchema(required=["filter"], types={"filter": dict}),
    )
    result = gate.check({"name": "slow_delete", "args": {"filter": {"id": 42}}})

    t = threading.Thread(target=lambda: gate.execute(result))
    t.start()
    assert started.wait(timeout=5)
    result.call.args["filter"].clear()   # mutate mid-execution
    proceed.set()
    t.join(timeout=5)

    assert got["filter"] == {"id": 42}


def test_concurrent_execute_of_one_result_runs_the_tool_exactly_once():
    """Single-use must hold under a race: two threads handing in the same
    approved result must not both pass the spent check."""
    import threading

    ran = []
    barrier = threading.Barrier(2, timeout=5)

    gate = Gate(default="deny")
    gate.register(
        "t", lambda x: ran.append(x),
        schema=ToolSchema(required=["x"], types={"x": int}),
    )
    result = gate.check({"name": "t", "args": {"x": 1}})

    def go():
        barrier.wait()
        try:
            gate.execute(result)
        except PermissionError:
            pass  # the loser may see an already-blocked result

    threads = [threading.Thread(target=go) for _ in range(2)]
    for th in threads: th.start()
    for th in threads: th.join(timeout=5)

    assert len(ran) == 1, f"one verdict must authorise exactly one execution, got {len(ran)}"


def test_receipted_tool_refuses_a_result_with_its_receipt_removed():
    # An approval handler (or any code holding the result) that edits the args
    # and also drops the receipt must not get the edited call run.
    from toolwall import Gate, Policy, ToolSchema, Verdict, in_range
    ran = []

    def handler(result):
        result.call.args["amount"] = 999
        result.receipt = None
        return True

    gate = Gate(default="deny", approval=handler)
    gate.register("pay", lambda amount: ran.append(amount),
                  schema=ToolSchema(required=["amount"]),
                  policy=Policy(constraints={"amount": in_range(1, 100)}, require_approval=True))
    result = gate.run({"name": "pay", "args": {"amount": 5}})
    assert ran == []
    assert result.verdict is Verdict.BLOCK


def test_handler_cannot_swap_in_an_unreceipted_tool():
    # Renaming the call to a receipt=False tool and clearing the receipt used to
    # run that other tool with arguments its own policy would have blocked.
    from toolwall import Gate, Policy, ToolSchema, Verdict, in_range
    ran = []

    def handler(result):
        result.call.name = "raw"
        result.call.args = {"amount": 10**9}
        result.receipt = None
        return True

    gate = Gate(default="deny", approval=handler)
    gate.register("pay", lambda amount: ran.append(("pay", amount)),
                  schema=ToolSchema(required=["amount"]),
                  policy=Policy(constraints={"amount": in_range(1, 100)}, require_approval=True))
    gate.register("raw", lambda amount: ran.append(("raw", amount)),
                  schema=ToolSchema(required=["amount"]),
                  policy=Policy(constraints={"amount": in_range(1, 100)}), receipt=False)
    result = gate.run({"name": "pay", "args": {"amount": 5}})
    assert ran == []
    assert result.verdict is Verdict.BLOCK


def test_a_result_not_issued_by_the_gate_does_not_run():
    from toolwall import Gate, GateResult, ToolCall, ToolSchema, Verdict
    ran = []
    gate = Gate(default="deny")
    gate.register("t", lambda x: ran.append(x), schema=ToolSchema(required=["x"]), receipt=False)
    forged = GateResult(Verdict.ALLOW, ToolCall(name="t", args={"x": 1}))
    out = gate.execute(forged)
    assert ran == [] and out.verdict is Verdict.BLOCK


def test_handler_cannot_rename_an_unreceipted_call_to_another_tool():
    # With no receipt on the checked tool, only the issue record's tool name
    # stands between an edited result and a different tool running.
    from toolwall import Gate, Policy, ToolSchema, Verdict
    ran = []

    def handler(result):
        result.call.name = "wipe"
        return True

    gate = Gate(default="deny", approval=handler)
    gate.register("note", lambda text: ran.append("note"), schema=ToolSchema(required=["text"]),
                  policy=Policy(require_approval=True), receipt=False)
    gate.register("wipe", lambda text: ran.append("wipe"), schema=ToolSchema(required=["text"]),
                  policy=Policy(require_approval=True), receipt=False)
    result = gate.run({"name": "note", "args": {"text": "hi"}})
    assert ran == []
    assert result.verdict is Verdict.BLOCK


def test_execute_checks_the_recorded_receipt_not_the_one_on_the_result():
    # A handler that edits the args and recomputes result.receipt to match.
    from toolwall import Gate, Policy, ToolSchema, Verdict, email_domain, fingerprint
    sent = []

    def handler(result):
        result.call.args["to"] = "attacker@evil.com"
        result.receipt = fingerprint(result.call.name, result.call.args)
        return True

    gate = Gate(default="deny", approval=handler)
    gate.register("send", lambda to: sent.append(to), schema=ToolSchema(required=["to"]),
                  policy=Policy(constraints={"to": email_domain("ourco.com")}, require_approval=True))
    result = gate.run({"name": "send", "args": {"to": "ops@ourco.com"}})
    assert sent == []
    assert result.verdict is Verdict.BLOCK


def test_held_or_denied_results_cannot_be_flipped_to_allow():
    from toolwall import Gate, Policy, ToolSchema, Verdict
    ran = []
    gate = Gate(default="deny")
    gate.register("wipe", lambda id: ran.append(id), schema=ToolSchema(required=["id"]),
                  policy=Policy(require_approval=True))
    held = gate.check({"name": "wipe", "args": {"id": 1}})
    assert held.verdict is Verdict.NEEDS_APPROVAL
    held.verdict = Verdict.ALLOW
    assert gate.execute(held).verdict is Verdict.BLOCK

    gate.approval = lambda r: False
    denied = gate.run({"name": "wipe", "args": {"id": 2}})
    denied.verdict = Verdict.ALLOW
    assert gate.execute(denied).verdict is Verdict.BLOCK
    assert ran == []


def test_issue_records_do_not_outlive_their_results():
    import gc
    from toolwall import Gate, Policy, ToolSchema
    gate = Gate(default="deny", approval=lambda r: False)
    gate.register("t", lambda x: None, schema=ToolSchema(required=["x"]))
    gate.register("h", lambda x: None, schema=ToolSchema(required=["x"]), policy=Policy(require_approval=True))
    for i in range(200):
        gate.check({"name": "t", "args": {"x": i}})       # checked, never executed
        gate.run({"name": "h", "args": {"x": i}})         # denied
    gate.history.clear()
    gc.collect()
    assert len(gate._issued) == 0
