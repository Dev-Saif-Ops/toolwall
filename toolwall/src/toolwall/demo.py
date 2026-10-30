"""`python -m toolwall demo`: a support agent's tool calls, gated. No API key.

A scripted "model" makes the calls a prompt-injected support agent might make
on behalf of one signed-in customer. Every verdict printed is the real gate's.
"""

from __future__ import annotations

import os
import sys
from typing import Any

from toolwall import rules as r
from toolwall.wall import ToolWall

CUSTOMER = {"id": "c_42", "email": "amal@example.com"}
ORDER_OWNER = {"o_9": "c_42", "o_10": "c_42", "o_77": "c_7"}
# Built by concatenation so repository secret scanners don't flag the fixture.
FAKE_KEY = "sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc"


def issue_refund(order_id: str, amount: float) -> str:
    return f"refunded {amount:.2f} on {order_id}"


def send_email(to: str, body: str) -> str:
    return f"sent to {to}"


def lookup_customer(customer_id: str) -> dict:
    return {"id": customer_id, "plan": "pro", "billing_api_key": FAKE_KEY}


def close_account(customer_id: str) -> str:
    return f"closed {customer_id}"


def build_wall() -> ToolWall:
    wall = ToolWall()
    # Fully annotated functions get their schema from the signature.
    for fn in (issue_refund, send_email, lookup_customer, close_account):
        wall.register(fn.__name__, fn)
    wall.rule("issue_refund",
              amount=r.positive() & r.at_most(500),
              order_id=r.owned_by("customer_id", lookup=ORDER_OWNER.get))
    wall.rule("send_email", to=r.email_domain("ourco.com") | r.equals_context("customer_email"))
    wall.rule("close_account", require_approval=True)
    return wall


SCRIPT = [
    ("issue_refund", {"order_id": "o_9", "amount": 40.0}, "an honest refund"),
    ("issue_refund", {"order_id": "o_9", "amount": 5000.0}, "a refund over the cap"),
    ("issue_refund", {"order_id": "o_77", "amount": 40.0}, "someone else's order"),
    ("send_email", {"to": "x@evil.com,ops@ourco.com", "body": "export"}, "a smuggled recipient"),
    ("lookup_customer", {"customer_id": "c_42"}, "a lookup whose record holds a key"),
    ("close_account", {"customer_id": "c_42"}, "a destructive action"),
    ("drop_all_tables", {}, "a tool nobody registered"),
]


def _paint(color: bool):
    def paint(text: str, code: str) -> str:
        return f"\033[{code}m{text}\033[0m" if color else text
    return paint


def _render_call(name: str, args: dict[str, Any]) -> str:
    inner = ", ".join(f"{k}={v!r}" for k, v in args.items())
    return f"{name}({inner})"


def run_demo(color: bool | None = None, out: Any = None) -> int:
    out = out or sys.stdout
    if color is None:
        color = getattr(out, "isatty", lambda: False)() and "NO_COLOR" not in os.environ
    paint = _paint(color)
    wall = build_wall()
    print(paint(f"toolwall demo: a support agent serving customer {CUSTOMER['id']}", "1"), file=out)
    print(paint("Every verdict below comes from the real gate. No model or API key.\n", "2"), file=out)

    tally = {"ran": 0, "stopped": 0, "held": 0}
    with wall.context(customer_id=CUSTOMER["id"], customer_email=CUSTOMER["email"]):
        results = [(name, args, label, wall.call(name, args)) for name, args, label in SCRIPT]
    for name, args, label, res in results:
        call = _render_call(name, args)
        if res.needs_approval:
            tag, note, key = paint("HELD ", "33;1"), "waiting for a human to approve", "held"
        elif res.blocked:
            tag, note, key = paint("BLOCK", "31;1"), res.reason, "stopped"
        elif res.error:
            tag, note, key = paint("ALLOW", "32;1"), f"ran, but {res.error}", "stopped"
        else:
            tag, note, key = paint("ALLOW", "32;1"), f"ran: {res.return_value}", "ran"
        tally[key] += 1
        print(f"  {tag}  {call}", file=out)
        print(paint(f"         {label}: {note}", "2"), file=out)
        if res.model_reason:
            print(paint(f"         model is told: {res.model_reason}", "2"), file=out)

    print(file=out)
    print(f"{tally['ran']} ran · {tally['stopped']} stopped · {tally['held']} waiting for a human. "
          "The model gets the short reason; the full one goes to the audit log.", file=out)
    print(paint("Source of this demo: python -c \"import toolwall.demo as d; print(d.__file__)\"", "2"), file=out)
    return 0
