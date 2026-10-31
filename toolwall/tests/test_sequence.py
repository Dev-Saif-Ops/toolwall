"""Sequence rules (0.8): what may run after what, within one session."""

import pytest

from toolwall import ToolSchema, ToolWall
from toolwall import rules as r
from toolwall.sequence import Sequences


def shop(**kwargs):
    wall = ToolWall(**kwargs)
    ran = []

    @wall.protect
    def lookup_customer(customer_id: str) -> str:
        ran.append(("lookup", customer_id))
        return "ok"

    @wall.protect
    def send_email(to: str) -> str:
        ran.append(("email", to))
        return "sent"

    @wall.protect
    def search_docs(q: str) -> str:
        ran.append(("search", q))
        return "found"

    wall.after("lookup_customer", block="send_email")
    return wall, ran


def call(wall, name, args, session="s1"):
    with wall.context(session_id=session):
        return wall.call(name, args)


def test_after_the_trigger_runs_the_target_is_blocked_in_that_session_only():
    wall, ran = shop()
    assert call(wall, "send_email", {"to": "a@b.c"}).executed          # before: fine
    assert call(wall, "lookup_customer", {"customer_id": "c_42"}).executed
    blocked = call(wall, "send_email", {"to": "a@b.c"})
    assert blocked.blocked and blocked.kind == "sequence"
    assert blocked.model_reason == "This call isn't allowed after an earlier step in this conversation."
    assert call(wall, "send_email", {"to": "a@b.c"}, session="s2").executed   # another session
    assert call(wall, "search_docs", {"q": "x"}).executed                    # an unrelated tool
    assert ran.count(("email", "a@b.c")) == 2


def test_a_blocked_or_held_trigger_arms_nothing():
    wall, _ = shop()
    wall.rule("lookup_customer", customer_id=r.one_of("c_42"))
    assert call(wall, "lookup_customer", {"customer_id": "c_7"}).blocked
    assert call(wall, "send_email", {"to": "a@b.c"}).executed
    wall2, _ = shop()
    wall2.rule("lookup_customer", require_approval=True)
    assert call(wall2, "lookup_customer", {"customer_id": "c_42"}).needs_approval
    assert call(wall2, "send_email", {"to": "a@b.c"}).executed


def test_a_trigger_that_raised_still_counts():
    wall = ToolWall()

    @wall.protect
    def read_file(path: str) -> str:
        raise OSError("disk")

    @wall.protect
    def http_post(url: str) -> str:
        return "posted"

    wall.after("read_file", block="http_post")
    with wall.context(session_id="s1"):
        wall.call("read_file", {"path": "/x"})
        assert wall.call("http_post", {"url": "https://x"}).blocked


def test_ask_holds_the_target_on_a_ticket_that_runs_once_when_approved():
    wall = ToolWall()
    ran = []

    @wall.protect
    def read_file(path: str) -> str:
        return "data"

    @wall.protect
    def http_post(url: str) -> str:
        ran.append(url)
        return "posted"

    wall.after("read_file", ask="http_post")
    with wall.context(session_id="s1"):
        wall.call("read_file", {"path": "/x"})
        held = wall.call("http_post", {"url": "https://x"})
    assert held.needs_approval and held.ticket and ran == []
    wall.approvals.approve(held.ticket, by="ops")
    assert wall.run_approved(held.ticket).executed and ran == ["https://x"]


def test_no_session_blocks_targets_but_not_unrelated_calls():
    wall, ran = shop()
    assert wall.call("send_email", {"to": "a@b.c"}).blocked           # a rule applies, no session
    assert wall.call("search_docs", {"q": "x"}).executed               # no rule applies
    assert wall.call("lookup_customer", {"customer_id": "c_42"}).executed


def test_a_custom_session_key():
    wall, _ = shop(session_key="conversation")
    with wall.context(conversation="k1"):
        wall.call("lookup_customer", {"customer_id": "c_42"})
        assert wall.call("send_email", {"to": "a@b.c"}).blocked


def test_decide_counts_an_allow_but_a_probe_does_not():
    wall = ToolWall()
    wall.rule("lookup_customer", schema=ToolSchema(required=["customer_id"]))
    wall.rule("send_email", schema=ToolSchema(required=["to"]))
    wall.after("lookup_customer", block="send_email")
    with wall.context(session_id="s1"):
        wall._decide("lookup_customer", {"customer_id": "c_42"}, reserve=False)   # a probe
        assert wall.decide("send_email", {"to": "a@b.c"}).allowed
        assert wall.decide("lookup_customer", {"customer_id": "c_42"}).allowed
        assert wall.decide("send_email", {"to": "a@b.c"}).denied


def test_a_trigger_that_runs_between_check_and_execute_stops_the_target():
    wall, ran = shop()
    with wall.context(session_id="s1"):
        checked = wall.gate.check({"name": "send_email", "args": {"to": "a@b.c"}})
        assert checked.allowed
        wall.call("lookup_customer", {"customer_id": "c_42"})
        out = wall.gate.execute(checked)
    assert not out.executed and out.kind == "sequence"
    assert ("email", "a@b.c") not in ran


def test_forget_and_session_eviction():
    seq = Sequences(max_sessions=2)
    seq.add("a", block="b")
    for s in ("s1", "s2", "s3"):
        seq.ran("a", {"session_id": s})
    assert seq.check("b", {"session_id": "s1"}) is None        # evicted (oldest)
    assert seq.check("b", {"session_id": "s3"})[0] == "block"
    seq.forget("s3")
    assert seq.check("b", {"session_id": "s3"}) is None


@pytest.mark.parametrize("kwargs", [{}, {"block": ""}, {"block": [1]}, {"ask": None, "block": None}])
def test_a_rule_needs_a_target(kwargs):
    with pytest.raises((TypeError, ValueError)):
        ToolWall().after("a", **kwargs)


def test_an_unhashable_session_is_no_session():
    wall, _ = shop()
    with wall.context(session_id=["not", "hashable"]):
        assert wall.call("send_email", {"to": "a@b.c"}).blocked
