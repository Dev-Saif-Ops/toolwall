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


# -- issue #4: the verdict is bound to the tool's registration -------------------

def _registered_gate():
    from toolwall import Gate, ToolSchema

    ran = []
    gate = Gate()
    gate.register("pay", lambda amount: ran.append(("old", amount)) or "old",
                  ToolSchema(required=["amount"], types={"amount": int}))
    return gate, ran


def test_a_tool_replaced_between_check_and_execute_does_not_run():
    from toolwall import ToolSchema

    gate, ran = _registered_gate()
    result = gate.check({"name": "pay", "args": {"amount": 5}})
    assert result.allowed
    gate.register("pay", lambda amount: ran.append(("new", amount)) or "new",
                  ToolSchema(required=["amount"], types={"amount": int}), replace=True)
    out = gate.execute(result)
    assert not out.executed and ran == []
    assert "re-registered" in out.reasons[-1]


def test_rules_changed_between_check_and_execute_refuse_the_old_verdict():
    from toolwall import Policy, ToolSchema, in_range

    gate, ran = _registered_gate()
    result = gate.check({"name": "pay", "args": {"amount": 5}})
    gate.registry.set_policy("pay", Policy(constraints={"amount": in_range(0, 1)}))
    assert not gate.execute(result).executed
    gate.registry.set_policy("pay", None)
    result = gate.check({"name": "pay", "args": {"amount": 5}})
    assert result.allowed
    gate.registry.set_schema("pay", ToolSchema(required=["amount"], types={"amount": int}))
    assert not gate.execute(result).executed
    assert ran == []


def test_an_unchanged_registration_still_runs_and_a_fresh_check_after_replace_runs_the_new_tool():
    from toolwall import ToolSchema

    gate, ran = _registered_gate()
    assert gate.execute(gate.check({"name": "pay", "args": {"amount": 1}})).executed
    gate.register("pay", lambda amount: ran.append(("new", amount)) or "new",
                  ToolSchema(required=["amount"], types={"amount": int}), replace=True)
    assert gate.execute(gate.check({"name": "pay", "args": {"amount": 2}})).executed
    assert ran == [("old", 1), ("new", 2)]


def test_a_replace_during_an_approval_is_refused():
    from toolwall import Gate, Policy, ToolSchema

    ran = []
    schema = ToolSchema(required=["amount"], types={"amount": int})

    def approve(result):
        # Someone swaps the tool while a person is looking at the call.
        gate.register("pay", lambda amount: ran.append("new"), schema,
                      policy=Policy(require_approval=True), replace=True)
        return True

    gate = Gate(approval=approve)
    gate.register("pay", lambda amount: ran.append("old"), schema, policy=Policy(require_approval=True))
    out = gate.run({"name": "pay", "args": {"amount": 5}})
    assert not out.executed and ran == []


def test_a_tool_swapped_under_live_traffic_never_runs_on_the_old_verdict():
    import sys
    import threading

    from toolwall import ToolWall
    from toolwall import rules as r

    evil_runs = []

    def good(x: int) -> str:
        return "g"

    def evil(x: int) -> str:
        evil_runs.append(x)
        return "e"

    wall = ToolWall(approvals=False, audit=False)
    wall.register("t", good)
    stop = threading.Event()

    def swapper():
        while not stop.is_set():
            wall.gate.registry.register("t", evil, replace=True, infer_schema=True,
                                        policy=Policy(constraints={"x": r.at_most(0)}))
            wall.gate.registry.register("t", good, replace=True, infer_schema=True)

    old = sys.getswitchinterval()
    sys.setswitchinterval(1e-6)
    th = threading.Thread(target=swapper)
    th.start()
    try:
        for _ in range(20000):
            wall.call("t", {"x": 1})
            wall.gate.history.clear()
    finally:
        stop.set()
        th.join()
        sys.setswitchinterval(old)
    assert evil_runs == []   # evil's own policy forbids x=1


def _swap_under_load(wall, swappers, calls):
    import sys
    import threading

    stop = threading.Event()
    threads = [threading.Thread(target=lambda f=f: [f() for _ in iter(stop.is_set, True)]) for f in swappers]
    old = sys.getswitchinterval()
    sys.setswitchinterval(1e-6)
    for t in threads:
        t.start()
    try:
        return [calls() for _ in range(20000)]
    finally:
        stop.set()
        for t in threads:
            t.join()
        sys.setswitchinterval(old)


def test_two_overlapping_replaces_never_run_a_half_registered_tool():
    from toolwall import ToolWall
    from toolwall import rules as r

    evil_runs = []

    def good(x: int) -> str:
        return "g"

    def evil(x: int) -> str:
        evil_runs.append(x)
        return "e"

    wall = ToolWall(approvals=False, audit=False)
    wall.register("t", good)
    reg = wall.gate.registry

    def run():
        wall.call("t", {"x": 1})
        wall.gate.history.clear()

    _swap_under_load(wall, [
        lambda: reg.register("t", evil, replace=True, infer_schema=True,
                             policy=Policy(constraints={"x": r.at_most(0)})),
        lambda: reg.register("t", good, replace=True, infer_schema=True),
    ], run)
    assert evil_runs == []


def test_decide_never_allows_from_a_half_registered_tool():
    from toolwall import ToolWall
    from toolwall import rules as r

    wall = ToolWall(approvals=False, audit=False)
    schema = ToolSchema(required=["x"], types={"x": int})
    wall.rule("t", schema=schema, x=r.at_most(0))
    policy = wall.gate.registry.get_policy("t")
    fn = wall.gate.registry.get("t")
    verdicts = _swap_under_load(
        wall, [lambda: wall.gate.registry.register("t", fn, schema, policy=policy, replace=True)],
        lambda: wall.decide("t", {"x": 1}).verdict)
    assert "allow" not in verdicts   # every registered state forbids x=1


def test_a_check_overlapping_a_change_is_blocked_with_a_plain_reason():
    gate, ran = _registered_gate()
    gate.registry._changing("pay")   # a change in progress (or one that failed half-way)
    result = gate.check({"name": "pay", "args": {"amount": 1}})
    assert result.blocked and result.kind == "registration"
    assert result.model_reason == "This tool changed while the call was being checked. Try again."


# The exact interleavings, forced: a change that finishes during the check, and
# one that starts during it. Each must block, in decide() as in call().

def _wall_with_t():
    from toolwall import ToolWall
    from toolwall import rules as r

    wall = ToolWall(approvals=False, audit=False)
    wall.rule("t", schema=ToolSchema(required=["x"], types={"x": int}), x=r.at_most(0))
    return wall


def _during_check(wall, action):
    gate = wall.gate
    inner = gate._check_one_unguarded

    def patched(call):
        action()
        return inner(call)

    gate._check_one_unguarded = patched


def test_a_change_that_finishes_during_the_check_blocks():
    wall = _wall_with_t()
    reg = wall.gate.registry
    reg._changing("t")                      # replace #1 in progress when the check starts
    _during_check(wall, lambda: (reg._policies.pop("t", None), reg._bump("t")))   # it finishes, policy-less
    decision = wall.decide("t", {"x": 1})
    assert decision.denied and "registration" in (decision.detail or "")


def test_a_change_that_starts_during_the_check_blocks():
    wall = _wall_with_t()
    reg = wall.gate.registry
    _during_check(wall, lambda: (reg._changing("t"), reg._policies.pop("t", None)))  # replace #2 starts
    decision = wall.decide("t", {"x": 1})
    assert decision.denied and "registration" in (decision.detail or "")


def test_an_unknown_tool_is_unknown_not_a_registration_change():
    wall = _wall_with_t()
    result = wall.gate.check({"name": "nope", "args": {}})
    assert result.blocked and result.kind == "unknown_tool"


def test_a_change_ending_and_another_starting_around_the_start_read_blocks():
    # Replace #1 is in progress at the first read; it finishes right after, and
    # replace #2 starts during the check. Start and end both read "changing":
    # equal, but never a stable registration.
    wall = _wall_with_t()
    reg = wall.gate.registry
    reg._changing("t")
    real_changing = reg.changing

    def finish_then_report(name):
        reg._bump(name)                     # replace #1 finishes between two reads
        return real_changing(name)

    reg.changing = finish_then_report
    _during_check(wall, lambda: (reg._changing("t"), reg._policies.pop("t", None)))
    decision = wall.decide("t", {"x": 1})
    assert decision.denied and "registration" in (decision.detail or "")
