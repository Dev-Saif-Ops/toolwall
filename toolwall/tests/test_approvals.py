"""Approval tickets (0.7): hold a call, approve it later, run exactly it, once."""

import asyncio
import datetime
import decimal
import sqlite3
import threading

import pytest

import toolwall.approvals as approvals_mod
from toolwall import Approvals, SQLiteStore, ToolBlocked, ToolWall, TicketError
from toolwall import rules as r

OWNERS = {"o_9": "c_42", "o_77": "c_7"}


def refund_wall(**kwargs):
    wall = ToolWall(**kwargs)
    ran = []

    @wall.protect
    def issue_refund(order_id: str, amount: int | float) -> str:
        ran.append((order_id, amount))
        return f"refunded {amount}"

    wall.rule("issue_refund",
              amount=r.positive() & r.at_most(500),
              order_id=r.owned_by("customer_id", lookup=OWNERS.get),
              ask_if=r.over("amount", 200))
    return wall, issue_refund, ran


def held(wall, args):
    with wall.context(customer_id="c_42"):
        result = wall.call("issue_refund", args)
    assert result.needs_approval and result.ticket
    return result.ticket


def test_a_held_call_opens_a_ticket_that_runs_once_after_approval():
    wall, _, ran = refund_wall()
    ticket = held(wall, {"order_id": "o_9", "amount": 300})
    assert [t.id for t in wall.approvals.pending()] == [ticket]
    assert ran == []
    approved = wall.approvals.approve(ticket, by="ops@ourco.com", note="checked")
    assert approved.status == "approved" and approved.decided_by == "ops@ourco.com"
    result = wall.run_approved(ticket)
    assert result.allowed and result.executed and ran == [("o_9", 300)]
    assert wall.approvals.get(ticket).status == "used"
    with pytest.raises(TicketError):
        wall.run_approved(ticket)
    assert ran == [("o_9", 300)]


def test_the_same_call_held_twice_shares_one_ticket():
    wall, _, _ = refund_wall()
    assert held(wall, {"order_id": "o_9", "amount": 300}) == held(wall, {"order_id": "o_9", "amount": 300})
    assert len(wall.approvals.pending()) == 1


def test_an_approved_ticket_lets_the_same_call_through_once():
    wall, issue_refund, ran = refund_wall()
    ticket = held(wall, {"order_id": "o_9", "amount": 300})
    wall.approvals.approve(ticket, by="ops")
    with wall.context(customer_id="c_42"):
        assert issue_refund("o_9", 300) == "refunded 300"
        with pytest.raises(ToolBlocked) as again:
            issue_refund("o_9", 300)  # used up: held again, on a new ticket
    assert ran == [("o_9", 300)]
    assert again.value.ticket and again.value.ticket != ticket


@pytest.mark.parametrize("args, ctx", [
    ({"order_id": "o_9", "amount": 301}, {"customer_id": "c_42"}),     # amount changed
    ({"order_id": "o_9", "amount": 300.0}, {"customer_id": "c_42"}),   # 300 vs 300.0
    ({"order_id": "o_9", "amount": 300}, {"customer_id": "c_42", "x": 1}),  # context changed
])
def test_an_approval_does_not_cover_a_different_call(args, ctx):
    wall, _, ran = refund_wall()
    ticket = held(wall, {"order_id": "o_9", "amount": 300})
    wall.approvals.approve(ticket, by="ops")
    with wall.context(**ctx):
        result = wall.call("issue_refund", args)
    assert result.needs_approval and result.ticket != ticket and ran == []
    assert wall.approvals.get(ticket).status == "approved"


def test_run_approved_uses_the_tickets_context_not_the_callers():
    wall, _, ran = refund_wall()
    ticket = held(wall, {"order_id": "o_9", "amount": 300})
    wall.approvals.approve(ticket, by="ops")
    with wall.context(customer_id="c_7", extra="y"):
        result = wall.run_approved(ticket)
    assert result.allowed and ran == [("o_9", 300)]


def test_a_denied_ticket_declines_the_call():
    wall, _, ran = refund_wall()
    ticket = held(wall, {"order_id": "o_9", "amount": 300})
    wall.approvals.deny(ticket, by="ops", note="too much")
    with wall.context(customer_id="c_42"):
        result = wall.call("issue_refund", {"order_id": "o_9", "amount": 300})
        decision = wall.decide("issue_refund", {"order_id": "o_9", "amount": 300})
    assert result.blocked and result.model_reason == "A person declined this call."
    assert decision.denied and decision.ticket == ticket
    with pytest.raises(TicketError):
        wall.run_approved(ticket)
    assert ran == []


def test_expired_tickets_never_run(monkeypatch):
    clock = [1000.0]
    monkeypatch.setattr(approvals_mod.time, "time", lambda: clock[0])
    wall, _, ran = refund_wall(approvals=Approvals(ttl=60))
    late = held(wall, {"order_id": "o_9", "amount": 300})
    clock[0] += 61
    with pytest.raises(TicketError):
        wall.approvals.approve(late, by="ops")
    assert wall.approvals.get(late).status == "expired"

    approved = held(wall, {"order_id": "o_9", "amount": 300})
    wall.approvals.approve(approved, by="ops")
    clock[0] += 61
    with pytest.raises(TicketError):
        wall.run_approved(approved)
    with wall.context(customer_id="c_42"):
        assert wall.call("issue_refund", {"order_id": "o_9", "amount": 300}).needs_approval
    assert ran == []


def test_rules_are_checked_again_when_the_ticket_runs():
    wall, _, ran = refund_wall()
    ticket = held(wall, {"order_id": "o_9", "amount": 300})
    wall.approvals.approve(ticket, by="ops")
    OWNERS["o_9"] = "c_99"  # the order changed hands after approval
    try:
        result = wall.run_approved(ticket)
    finally:
        OWNERS["o_9"] = "c_42"
    assert result.blocked and ran == []


def test_approve_needs_a_name_and_a_pending_ticket():
    wall, _, _ = refund_wall()
    ticket = held(wall, {"order_id": "o_9", "amount": 300})
    with pytest.raises(TicketError):
        wall.approvals.approve(ticket, by="  ")
    with pytest.raises(TicketError):
        wall.approvals.approve("tkt_nope", by="ops")
    wall.approvals.deny(ticket, by="ops")
    with pytest.raises(TicketError):
        wall.approvals.approve(ticket, by="ops")


def test_an_approved_ticket_runs_once_under_concurrency():
    wall, _, ran = refund_wall()
    ticket = held(wall, {"order_id": "o_9", "amount": 300})
    wall.approvals.approve(ticket, by="ops")
    start = threading.Barrier(16)

    def go():
        start.wait()
        try:
            wall.run_approved(ticket)
        except TicketError:
            pass

    threads = [threading.Thread(target=go) for _ in range(16)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert ran == [("o_9", 300)]


def test_decide_opens_redeems_and_peeks_without_using_up():
    wall, _, _ = refund_wall()
    with wall.context(customer_id="c_42"):
        first = wall.decide("issue_refund", {"order_id": "o_9", "amount": 300})
        assert first.needs_approval and first.ticket
        wall.approvals.approve(first.ticket, by="ops")
        probe = wall._decide("issue_refund", {"order_id": "o_9", "amount": 300}, reserve=False)
        assert probe.allowed and wall.approvals.get(first.ticket).status == "approved"
        second = wall.decide("issue_refund", {"order_id": "o_9", "amount": 300})
        assert second.allowed and second.ticket == first.ticket
        assert wall.approvals.get(first.ticket).status == "used"
        third = wall.decide("issue_refund", {"order_id": "o_9", "amount": 300})
        assert third.needs_approval and third.ticket != first.ticket


def test_a_ticket_allow_takes_a_budget_slot_and_survives_an_empty_budget():
    wall, _, _ = refund_wall()
    wall.budget(max_calls=1)
    with wall.context(customer_id="c_42"):
        first = wall.decide("issue_refund", {"order_id": "o_9", "amount": 300})
        wall.approvals.approve(first.ticket, by="ops")
        assert wall.decide("issue_refund", {"order_id": "o_9", "amount": 40}).allowed  # spends it
        second = wall.decide("issue_refund", {"order_id": "o_9", "amount": 300})
    assert second.denied and "limit" in second.reason
    assert wall.approvals.get(first.ticket).status == "approved"


@pytest.mark.parametrize("value", [("a", "b"), decimal.Decimal("1.50"),
                                   datetime.date(2026, 10, 30), float("nan")])
def test_a_call_that_cannot_be_stored_stays_held_without_a_ticket(value):
    wall = ToolWall()
    wall.rule("note", schema=__import__("toolwall").ToolSchema(required=["v"]), require_approval=True)
    decision = wall.decide("note", {"v": value})
    assert decision.needs_approval and decision.ticket is None
    assert wall.approvals.pending() == []


def test_tickets_can_be_turned_off():
    wall, _, _ = refund_wall(approvals=False)
    with wall.context(customer_id="c_42"):
        result = wall.call("issue_refund", {"order_id": "o_9", "amount": 300})
    assert result.needs_approval and result.ticket is None and wall.approvals is None
    with pytest.raises(TicketError):
        wall.run_approved("tkt_x")


def test_an_approval_handler_still_decides_when_given():
    wall, _, ran = refund_wall(approval=lambda result: True)
    with wall.context(customer_id="c_42"):
        assert wall.call("issue_refund", {"order_id": "o_9", "amount": 300}).allowed
    assert ran == [("o_9", 300)] and wall.approvals.pending() == []


def test_sqlite_tickets_survive_a_restart_and_cross_processes(tmp_path):
    db = str(tmp_path / "approvals.db")
    store = SQLiteStore(db)
    wall, _, ran = refund_wall(approvals=Approvals(store))
    ticket = held(wall, {"order_id": "o_9", "amount": 300})
    store.close()

    approver = Approvals(SQLiteStore(db))  # another process, after a restart
    assert [t.id for t in approver.pending()] == [ticket]
    approver.approve(ticket, by="ops")
    approver.store.close()

    wall2, _, ran2 = refund_wall(approvals=Approvals(SQLiteStore(db)))
    result = wall2.run_approved(ticket)
    assert result.allowed and ran2 == [("o_9", 300)]
    with pytest.raises(TicketError):
        wall2.run_approved(ticket)
    wall2.approvals.store.close()


def test_an_edited_ticket_never_runs(tmp_path):
    db = str(tmp_path / "approvals.db")
    wall, _, ran = refund_wall(approvals=Approvals(SQLiteStore(db)))
    ticket = held(wall, {"order_id": "o_9", "amount": 300})
    wall.approvals.approve(ticket, by="ops")
    con = sqlite3.connect(db)
    try:
        con.execute("UPDATE toolwall_tickets SET args = ? WHERE id = ?",
                    ('{"amount": 450, "order_id": "o_9"}', ticket))
        con.commit()
    finally:
        con.close()
    with pytest.raises(TicketError):
        wall.run_approved(ticket)
    assert ran == [] and wall.approvals.pending() == []  # no stray ticket for the edit
    wall.approvals.store.close()


def test_arun_approved_awaits_an_async_tool():
    wall = ToolWall()
    ran = []

    @wall.protect
    async def wire(amount: int) -> str:
        ran.append(amount)
        return "sent"

    wall.rule("wire", require_approval=True)
    decision = wall.decide("wire", {"amount": 5})
    wall.approvals.approve(decision.ticket, by="ops")
    result = asyncio.run(wall.arun_approved(decision.ticket))
    assert result.allowed and result.return_value == "sent" and ran == [5]


@pytest.fixture(params=["memory", "sqlite"])
def store(request, tmp_path):
    if request.param == "memory":
        yield approvals_mod.MemoryStore()
        return
    s = SQLiteStore(str(tmp_path / "t.db"))
    yield s
    s.close()


def test_expiry_is_enforced_by_every_store(store, monkeypatch):
    clock = [1000.0]
    monkeypatch.setattr(approvals_mod.time, "time", lambda: clock[0])
    wall, _, ran = refund_wall(approvals=Approvals(store, ttl=60))
    late = held(wall, {"order_id": "o_9", "amount": 300})
    clock[0] += 60  # exactly at expiry
    with pytest.raises(TicketError):
        wall.approvals.approve(late, by="ops")
    with wall.context(customer_id="c_42"):
        fresh = wall.call("issue_refund", {"order_id": "o_9", "amount": 300}).ticket
    assert fresh != late  # an expired ticket isn't found again
    wall.approvals.approve(fresh, by="ops")
    clock[0] += 60
    assert not wall.approvals.redeem(wall.approvals.store.get(fresh))
    with pytest.raises(TicketError):
        wall.run_approved(fresh)
    assert ran == []


def test_the_newest_live_ticket_is_the_one_found(store, monkeypatch):
    clock = [1000.0]
    monkeypatch.setattr(approvals_mod.time, "time", lambda: clock[0])
    approvals = Approvals(store, ttl=60)
    first = approvals.open("t", {"a": 1}, {}, None)
    approvals.deny(first.id, by="ops")
    clock[0] += 61
    second = approvals.open("t", {"a": 1}, {}, None)
    clock[0] += 1
    assert approvals.lookup("t", {"a": 1}, {}).id == second.id


def test_redeem_is_atomic_in_every_store(store):
    approvals = Approvals(store)
    ticket = approvals.open("t", {"a": 1}, {}, None)
    approvals.approve(ticket.id, by="ops")
    approved = store.get(ticket.id)
    start = threading.Barrier(16)
    wins = []

    def go():
        start.wait()
        wins.append(approvals.redeem(approved))

    threads = [threading.Thread(target=go) for _ in range(16)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert wins.count(True) == 1


def test_sqlite_drops_tickets_a_day_past_expiry(tmp_path, monkeypatch):
    clock = [1000.0]
    monkeypatch.setattr(approvals_mod.time, "time", lambda: clock[0])
    store = SQLiteStore(str(tmp_path / "t.db"))
    approvals = Approvals(store, ttl=60)
    old = approvals.open("t", {"a": 1}, {}, None)
    clock[0] += 60 + 86400 + 1
    approvals.open("t", {"a": 2}, {}, None)
    assert store.get(old.id) is None
    store.close()


def test_an_approved_ticket_that_cannot_be_redeemed_does_not_run():
    wall, _, ran = refund_wall()
    ticket = held(wall, {"order_id": "o_9", "amount": 300})
    wall.approvals.approve(ticket, by="ops")
    wall.approvals.redeem = lambda t: False  # used up by someone else meanwhile
    with wall.context(customer_id="c_42"):
        result = wall.call("issue_refund", {"order_id": "o_9", "amount": 300})
    assert result.blocked and ran == []


def test_a_ticket_allow_through_decide_counts_against_the_budget():
    wall, _, _ = refund_wall()
    wall.budget(max_calls=1)
    with wall.context(customer_id="c_42"):
        first = wall.decide("issue_refund", {"order_id": "o_9", "amount": 300})
        wall.approvals.approve(first.ticket, by="ops")
        assert wall.decide("issue_refund", {"order_id": "o_9", "amount": 300}).allowed
        assert wall.decide("issue_refund", {"order_id": "o_9", "amount": 40}).denied


def test_a_context_that_cannot_be_fingerprinted_still_reaches_the_handler():
    asked = []
    wall, _, ran = refund_wall(approval=lambda result: asked.append(1) or True)
    with wall.context(customer_id="c_42", user=object()):
        result = wall.call("issue_refund", {"order_id": "o_9", "amount": 300})
    assert result.allowed and asked == [1] and ran == [("o_9", 300)]


def test_a_framework_approval_settles_the_ticket():
    wall, _, ran = refund_wall()
    with wall.context(customer_id="c_42"):
        held_call = wall.decide("issue_refund", {"order_id": "o_9", "amount": 300})
        assert wall.take_slot(held_call).allowed
    assert wall.approvals.get(held_call.ticket).status == "used"
    assert wall.approvals.pending() == []
    with pytest.raises(TicketError):
        wall.approvals.approve(held_call.ticket, by="ops")
    # a second framework approval of the same, already settled, decision
    assert wall.take_slot(held_call).denied


def test_a_framework_decline_denies_the_ticket():
    wall, _, _ = refund_wall()
    with wall.context(customer_id="c_42"):
        held_call = wall.decide("issue_refund", {"order_id": "o_9", "amount": 300})
    wall.decline(held_call)
    assert wall.approvals.get(held_call.ticket).status == "denied"


def test_run_approved_refuses_before_using_up_the_ticket():
    wall = ToolWall()

    @wall.protect
    async def wire(amount: int) -> str:
        return "sent"

    wall.rule("wire", require_approval=True)
    ticket = wall.decide("wire", {"amount": 5}).ticket
    wall.approvals.approve(ticket, by="ops")
    with pytest.raises(TicketError):
        wall.run_approved(ticket)  # async tool, sync run
    wall.dry_run = True
    with pytest.raises(TicketError):
        asyncio.run(wall.arun_approved(ticket))
    assert wall.approvals.get(ticket).status == "approved"
