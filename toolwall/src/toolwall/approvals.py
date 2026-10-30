"""Approval tickets: hold a call for a person, then run exactly that call, once.

When the wall holds a call ("ask") and nobody can approve it on the spot, it
opens a ticket. The ticket is bound to the tool, the arguments and the request
context (who the agent was serving) through a fingerprint. A person approves
or denies it later, from a CLI, an admin page or a chat message:

    wall.approvals.approve("tkt_7f3a...", by="ops@ourco.com")
    result = wall.run_approved("tkt_7f3a...")      # runs those arguments, once

The same ticket is also redeemed when the same call comes back with the same
context (an agent retrying it, or a framework resuming a paused run): it runs
once, and the ticket is used up. A changed argument, another customer's
context, an expired, denied or already used ticket never runs.

Stores: MemoryStore (the default, for one process) and SQLiteStore (stdlib,
survives restarts, shared by processes on one machine). A store holds plain
JSON, so arguments and context values must be JSON values (str, int, float,
bool, None, lists, dicts with string keys); anything else can't be held for
later, and the call stays held without a ticket. The store is trusted: anyone
who can write to it can approve a ticket, as with any approvals table.
"""

from __future__ import annotations

import json
import secrets
import sqlite3
import threading
import time
from dataclasses import dataclass, replace
from typing import Any, Iterable, Literal, Protocol

from toolwall.receipt import ReceiptError, fingerprint

Status = Literal["pending", "approved", "denied", "used", "expired"]

DEFAULT_TTL = 3600.0


class TicketError(Exception):
    """The ticket doesn't exist, isn't in a state that allows this, or the call
    can't be held as a ticket."""


@dataclass(frozen=True)
class Ticket:
    id: str
    tool: str
    args: dict[str, Any]
    context: dict[str, Any]
    digest: str
    reason: str | None
    status: Status
    created_at: float
    expires_at: float
    decided_by: str | None = None
    decided_at: float | None = None
    note: str | None = None

    def expired(self, now: float | None = None) -> bool:
        return (time.time() if now is None else now) >= self.expires_at


def digest(tool: str, args: dict[str, Any], context: dict[str, Any]) -> str:
    """What a ticket is bound to: the tool, the arguments and the context."""
    try:
        return fingerprint(tool, {"args": args, "context": context})
    except ReceiptError as exc:
        raise TicketError(f"can't bind a ticket: {exc}") from exc


def _plain(value: Any, what: str) -> Any:
    """A JSON round-trip that must not change the value (so the digest holds)."""
    try:
        text = json.dumps(value, allow_nan=False, sort_keys=True)
    except (TypeError, ValueError) as exc:
        raise TicketError(f"{what} can't be stored for later: {exc}") from exc
    return json.loads(text)


class ApprovalStore(Protocol):
    def add(self, ticket: Ticket) -> None: ...
    def get(self, ticket_id: str) -> Ticket | None: ...
    def find(self, digest: str, now: float) -> Ticket | None: ...
    def transition(self, ticket_id: str, from_status: Iterable[Status], to_status: Status,
                   now: float, by: str | None = None, note: str | None = None) -> bool: ...
    def list(self, status: Status | None = None) -> list[Ticket]: ...


class MemoryStore:
    """Tickets in this process's memory. Lost on restart."""

    def __init__(self) -> None:
        self._tickets: dict[str, Ticket] = {}
        self._lock = threading.Lock()

    def add(self, ticket: Ticket) -> None:
        with self._lock:
            self._prune(time.time())
            self._tickets[ticket.id] = ticket

    def get(self, ticket_id: str) -> Ticket | None:
        with self._lock:
            return self._tickets.get(ticket_id)

    def find(self, digest: str, now: float) -> Ticket | None:
        with self._lock:
            live = [t for t in self._tickets.values()
                    if t.digest == digest and t.status in ("pending", "approved", "denied")
                    and now < t.expires_at]
        return max(live, key=lambda t: t.created_at) if live else None

    def transition(self, ticket_id: str, from_status: Iterable[Status], to_status: Status,
                   now: float, by: str | None = None, note: str | None = None) -> bool:
        with self._lock:
            ticket = self._tickets.get(ticket_id)
            if ticket is None or ticket.status not in tuple(from_status) or now >= ticket.expires_at:
                return False
            changes: dict[str, Any] = {"status": to_status}
            if by is not None:
                changes.update(decided_by=by, decided_at=now, note=note)
            self._tickets[ticket_id] = replace(ticket, **changes)
            return True

    def list(self, status: Status | None = None) -> list[Ticket]:
        now = time.time()
        with self._lock:
            tickets = [self._shown(t, now) for t in self._tickets.values()]
        return sorted((t for t in tickets if status is None or t.status == status),
                      key=lambda t: t.created_at)

    @staticmethod
    def _shown(ticket: Ticket, now: float) -> Ticket:
        if ticket.status in ("pending", "approved") and now >= ticket.expires_at:
            return replace(ticket, status="expired")
        return ticket

    def _prune(self, now: float) -> None:
        # Keep memory bounded: drop tickets a day past their expiry.
        for tid in [tid for tid, t in self._tickets.items() if now >= t.expires_at + 86400]:
            del self._tickets[tid]


class SQLiteStore:
    """Tickets in a SQLite file (stdlib). Survives restarts; processes on one
    machine can share it. Approve from one process, run from another."""

    def __init__(self, path: str) -> None:
        self._db = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self._lock = threading.Lock()
        with self._lock:
            self._db.execute(
                "CREATE TABLE IF NOT EXISTS toolwall_tickets ("
                " id TEXT PRIMARY KEY, tool TEXT NOT NULL, args TEXT NOT NULL,"
                " context TEXT NOT NULL, digest TEXT NOT NULL, reason TEXT,"
                " status TEXT NOT NULL, created_at REAL NOT NULL, expires_at REAL NOT NULL,"
                " decided_by TEXT, decided_at REAL, note TEXT)"
            )
            self._db.execute(
                "CREATE INDEX IF NOT EXISTS toolwall_tickets_digest ON toolwall_tickets (digest)"
            )

    def close(self) -> None:
        with self._lock:
            self._db.close()

    def add(self, ticket: Ticket) -> None:
        with self._lock:
            # Keep the table bounded: drop tickets a day past their expiry.
            self._db.execute("DELETE FROM toolwall_tickets WHERE expires_at < ?",
                             (ticket.created_at - 86400,))
            self._db.execute(
                "INSERT INTO toolwall_tickets VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (ticket.id, ticket.tool, json.dumps(ticket.args, sort_keys=True),
                 json.dumps(ticket.context, sort_keys=True), ticket.digest, ticket.reason,
                 ticket.status, ticket.created_at, ticket.expires_at, ticket.decided_by,
                 ticket.decided_at, ticket.note),
            )

    def get(self, ticket_id: str) -> Ticket | None:
        with self._lock:
            row = self._db.execute(
                "SELECT * FROM toolwall_tickets WHERE id = ?", (ticket_id,)).fetchone()
        return self._ticket(row) if row else None

    def find(self, digest: str, now: float) -> Ticket | None:
        with self._lock:
            row = self._db.execute(
                "SELECT * FROM toolwall_tickets WHERE digest = ? AND expires_at > ?"
                " AND status IN ('pending', 'approved', 'denied')"
                " ORDER BY created_at DESC LIMIT 1", (digest, now)).fetchone()
        return self._ticket(row) if row else None

    def transition(self, ticket_id: str, from_status: Iterable[Status], to_status: Status,
                   now: float, by: str | None = None, note: str | None = None) -> bool:
        allowed = tuple(from_status)
        marks = ",".join("?" * len(allowed))
        if by is not None:
            sql = (f"UPDATE toolwall_tickets SET status = ?, decided_by = ?, decided_at = ?,"
                   f" note = ? WHERE id = ? AND status IN ({marks}) AND expires_at > ?")
            params: tuple[Any, ...] = (to_status, by, now, note, ticket_id, *allowed, now)
        else:
            sql = (f"UPDATE toolwall_tickets SET status = ? WHERE id = ?"
                   f" AND status IN ({marks}) AND expires_at > ?")
            params = (to_status, ticket_id, *allowed, now)
        with self._lock:
            return self._db.execute(sql, params).rowcount == 1

    def list(self, status: Status | None = None) -> list[Ticket]:
        with self._lock:
            rows = self._db.execute(
                "SELECT * FROM toolwall_tickets ORDER BY created_at").fetchall()
        now = time.time()
        tickets = [MemoryStore._shown(self._ticket(r), now) for r in rows]
        return [t for t in tickets if status is None or t.status == status]

    @staticmethod
    def _ticket(row: tuple[Any, ...]) -> Ticket:
        return Ticket(id=row[0], tool=row[1], args=json.loads(row[2]), context=json.loads(row[3]),
                      digest=row[4], reason=row[5], status=row[6], created_at=row[7],
                      expires_at=row[8], decided_by=row[9], decided_at=row[10], note=row[11])


class Approvals:
    """wall.approvals: the tickets the wall opened, and approving or denying them."""

    def __init__(self, store: ApprovalStore | None = None, *, ttl: float = DEFAULT_TTL) -> None:
        if not ttl > 0:
            raise ValueError("ttl must be a positive number of seconds")
        self.store: ApprovalStore = store if store is not None else MemoryStore()
        self.ttl = float(ttl)

    # -- for people -------------------------------------------------------------

    def get(self, ticket_id: str) -> Ticket | None:
        ticket = self.store.get(ticket_id)
        return MemoryStore._shown(ticket, time.time()) if ticket else None

    def pending(self) -> list[Ticket]:
        return self.store.list("pending")

    def approve(self, ticket_id: str, *, by: str, note: str | None = None) -> Ticket:
        """Approve a pending, unexpired ticket. `by` names the person (for the audit)."""
        return self._decide(ticket_id, "approved", by, note)

    def deny(self, ticket_id: str, *, by: str, note: str | None = None) -> Ticket:
        return self._decide(ticket_id, "denied", by, note)

    def _decide(self, ticket_id: str, to: Status, by: str, note: str | None) -> Ticket:
        if not isinstance(by, str) or not by.strip():
            raise TicketError("say who decided: by='name or email'")
        if not self.store.transition(ticket_id, ("pending",), to, time.time(), by=by, note=note):
            ticket = self.get(ticket_id)
            state = ticket.status if ticket else "unknown"
            raise TicketError(f"ticket {ticket_id!r} can't be {to}: it is {state}")
        ticket = self.store.get(ticket_id)
        assert ticket is not None
        return ticket

    # -- for the wall -----------------------------------------------------------

    def _bind(self, tool: str, args: dict[str, Any], ctx: dict[str, Any]) -> str:
        return digest(tool, args, ctx)

    def lookup(self, tool: str, args: dict[str, Any], ctx: dict[str, Any]) -> Ticket | None:
        """The live ticket for exactly this call and context, if any (no change)."""
        bound = self._bind(tool, args, ctx)
        ticket = self.store.find(bound, time.time())
        if ticket is None or not self._intact(ticket, bound):
            return None
        return ticket

    def open(self, tool: str, args: dict[str, Any], ctx: dict[str, Any],
             reason: str | None) -> Ticket:
        """The live ticket for this call (pending, approved or denied), or a new
        pending one. Raises TicketError when the call can't be stored."""
        existing = self.lookup(tool, args, ctx)
        if existing is not None:
            return existing
        stored_args = _plain(args, "the arguments")
        stored_ctx = _plain(dict(ctx), "the context")
        bound = self._bind(tool, args, ctx)
        if self._bind(tool, stored_args, stored_ctx) != bound:
            # e.g. a tuple that would come back as a list: not the same call.
            raise TicketError("the call would change on the way into the store")
        now = time.time()
        ticket = Ticket(id="tkt_" + secrets.token_hex(12), tool=tool, args=stored_args,
                        context=stored_ctx, digest=bound, reason=reason, status="pending",
                        created_at=now, expires_at=now + self.ttl)
        self.store.add(ticket)
        return ticket

    def close(self, ticket_id: str, to: Status, *, by: str | None = None) -> bool:
        """Settle a pending or approved ticket that a framework's own approval
        handled ("used" when a person approved there, "denied" when they
        declined). False when it was already settled or has expired."""
        if to not in ("used", "denied"):
            raise ValueError('close() settles a ticket as "used" or "denied"')
        return self.store.transition(ticket_id, ("pending", "approved"), to, time.time(), by=by)

    def redeem(self, ticket: Ticket) -> bool:
        """Use an approved ticket up. True once; False if it was already used,
        expired or changed state in the meantime."""
        if ticket.status != "approved" or not self._intact(ticket, ticket.digest):
            return False
        return self.store.transition(ticket.id, ("approved",), "used", time.time())

    def _intact(self, ticket: Ticket, bound: str) -> bool:
        """The stored ticket still describes the call it was opened for."""
        try:
            return ticket.digest == bound and digest(ticket.tool, ticket.args, ticket.context) == bound
        except TicketError:
            return False
