# Approval tickets

Some calls should wait for a person: a refund over 200, deleting an account,
emailing a list. ToolWall holds them (`ask_if=...`, `require_approval=True`).
Tickets let a person approve them later, and make sure the call that runs is
exactly the one they approved.

```python
from toolwall import ToolWall, Approvals, SQLiteStore, rules as r

wall = ToolWall(approvals=Approvals(SQLiteStore("approvals.db"), ttl=3600))
wall.rule("issue_refund", amount=r.at_most(500), ask_if=r.over("amount", 200))

with wall.context(customer_id="c_42"):
    result = wall.call("issue_refund", {"order_id": "o_9", "amount": 350})
result.verdict        # needs_approval
result.ticket         # "tkt_6f72..."
```

A person approves it from a CLI, an admin page or a chat message:

```python
wall.approvals.pending()                                   # what's waiting
wall.approvals.approve("tkt_6f72...", by="ops@ourco.com", note="customer called")
wall.approvals.deny("tkt_6f72...", by="ops@ourco.com")
```

```bash
python -m toolwall approvals list --db approvals.db
python -m toolwall approvals approve tkt_6f72... --db approvals.db --by ops@ourco.com
```

Then the call runs, once:

```python
result = wall.run_approved("tkt_6f72...")        # or: await wall.arun_approved(...)
```

## What a ticket guarantees

A ticket is bound to the tool, the arguments and the request context (the
customer the agent was serving) by a fingerprint. Then:

- **Exactly that call.** A different amount (`300` vs `301`, or `300` vs
  `300.0`), another order, or another customer's context doesn't match. That
  call is held on its own ticket.
- **Once.** Running it uses the ticket up, even with many threads or processes
  racing for it. A replay is refused.
- **In its own context.** `run_approved` runs with the ticket's context, not
  whatever context the caller is in.
- **Still checked.** Every other check runs again when the ticket runs: if the
  order changed hands or the budget is already spent, it is blocked and the
  ticket stays approved. (If the budget runs out in a race between the check
  and the run, the ticket is used up and nothing runs.)
- **Refused early.** `run_approved` refuses, without using the ticket, a tool
  the wall doesn't run (declared with `wall.rule(schema=...)` for a framework),
  an async tool run with the sync method, and a wall in dry-run mode.
- **Expiry.** A ticket expires after `ttl` seconds (one hour by default). An
  expired ticket can't be approved or run. A denial also lasts until the ticket
  expires: the identical call is declined until then, and gets a fresh ticket
  after.
- **Edits are refused.** A stored ticket whose content no longer matches its
  fingerprint never runs.

The store is trusted, like any approvals table: anyone who can write to it can
approve a ticket, or rewrite one consistently. Keep it where your application
data lives, with the same access control.

## Approve later, inside a framework

The same ticket is also used when the same call comes back in the same
context. This is how a framework run picks up an approval made later:

| Framework | Hold now | Approve later |
|---|---|---|
| OpenAI Agents SDK | the run pauses (`needs_approval`) | approve the ticket, run the agent again: the same call runs without pausing |
| Claude Agent SDK | `hooks(wall, on_hold="ask")` asks the user | `hooks(wall, on_hold="defer")` ends the run (`ResultMessage.deferred_tool_use`); approve the ticket, resume the session |
| LangChain / LangGraph | interrupt with `{"ticket": ...}`, resume with `Command(resume=True)` | approve the ticket, run again |
| MCP / `wall.protect` | the call raises with the reason; `ToolBlocked.ticket` | approve the ticket, the client calls again |

Find the ticket with `wall.approvals.pending()`, or from `decision.ticket`,
`result.ticket`, the LangChain interrupt or `ToolBlocked.ticket`.

When a person answers through the framework instead, the ticket is settled so
the queue can't approve and run the same call again: approving in the OpenAI
SDK or resuming LangGraph with `True` marks it used, resuming with `False`
denies it, and the Claude SDK's "ask" marks it used when it asks. The OpenAI
SDK doesn't tell the wall about a rejection, so that ticket stays pending until
it expires; approving it from the queue later is a fresh, explicit approval.

The OpenAI adapter treats a held call as approved only when the SDK says a
person approved that exact call. If the approved ticket the SDK's check saw is
used up before the call runs (another worker got there first), the call is
refused rather than run twice.

## Stores

- `MemoryStore` (the default): this process only, lost on restart.
- `SQLiteStore(path)`: survives restarts; processes on one machine can share it.
- Your own: anything with `add`, `get`, `find`, `transition` and `list` (see
  `toolwall.approvals.ApprovalStore`). `transition` must be atomic.

Every distinct held call opens a ticket. Memory keeps tickets until a day past
their expiry; SQLite deletes them then. A very busy wall holding many distinct
calls should keep `ttl` short and watch the size of `pending()`.

Arguments and context values must be plain JSON values (str, int, float, bool,
None, lists, dicts with string keys) to be held as a ticket. A call that can't
be stored (a tuple, a Decimal, a date, NaN) stays held, with no ticket.

`ToolWall(approvals=False)` turns tickets off. An approval handler
(`ToolWall(approval=...)`) still decides on the spot when you give one; an
already approved or denied ticket is honoured first.
