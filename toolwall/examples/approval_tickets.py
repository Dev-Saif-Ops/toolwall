"""Approval tickets: hold a refund for a person, run exactly it, once.

    python examples/approval_tickets.py

No API key. Tickets go in a SQLite file, so a person can approve from another
terminal with the CLI while your app keeps running:

    python -m toolwall approvals list --db approvals.db
    python -m toolwall approvals approve tkt_... --db approvals.db --by you@ourco.com
"""

import os
import sqlite3
import tempfile

from toolwall import Approvals, SQLiteStore, TicketError, ToolWall
from toolwall import rules as r

OWNERS = {"o_9": "c_42"}
db = os.path.join(tempfile.mkdtemp(), "approvals.db")
wall = ToolWall(approvals=Approvals(SQLiteStore(db), ttl=3600))


@wall.protect
def issue_refund(order_id: str, amount: int | float) -> str:
    return f"refunded {amount} on {order_id}"


wall.rule("issue_refund",
          amount=r.positive() & r.at_most(500),
          order_id=r.owned_by("customer_id", lookup=OWNERS.get),
          ask_if=r.over("amount", 200))

# 1. The agent asks for a big refund: held, and a ticket is opened.
with wall.context(customer_id="c_42"):
    held = wall.call("issue_refund", {"order_id": "o_9", "amount": 350})
print(f"1. held:      {held.model_reason}  ticket={held.ticket}")

# 2. A person sees exactly what would run, and approves it.
ticket = wall.approvals.get(held.ticket)
print(f"2. waiting:   {ticket.tool}({ticket.args}) for {ticket.context}")
wall.approvals.approve(held.ticket, by="ops@ourco.com", note="customer called in")
print("   approved by ops@ourco.com")

# 3. The approved call runs: those arguments, that customer, once.
result = wall.run_approved(held.ticket)
print(f"3. ran:       {result.return_value}")

# 4. Replaying the same approval does nothing.
try:
    wall.run_approved(held.ticket)
except TicketError as exc:
    print(f"4. replay:    refused ({exc})")

# 5. An approval doesn't stretch to a bigger refund...
with wall.context(customer_id="c_42"):
    second = wall.call("issue_refund", {"order_id": "o_9", "amount": 400})
wall.approvals.approve(second.ticket, by="ops@ourco.com")
with wall.context(customer_id="c_42"):
    bigger = wall.call("issue_refund", {"order_id": "o_9", "amount": 450})
print(f"5. 450 after approving 400: {'ran' if bigger.executed else 'held, new ticket ' + str(bigger.ticket)}")

# 6. ...and editing the stored ticket doesn't change what runs.
con = sqlite3.connect(db)
con.execute("UPDATE toolwall_tickets SET args = ? WHERE id = ?",
            ('{"amount": 499, "order_id": "o_9"}', second.ticket))
con.commit()
con.close()
try:
    wall.run_approved(second.ticket)
    print("6. edited ticket: ran")
except TicketError as exc:
    print(f"6. edited ticket: refused ({exc})")
wall.approvals.store.close()
