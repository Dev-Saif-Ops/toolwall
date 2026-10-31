# toolwall

[![PyPI version](https://img.shields.io/pypi/v/toolwall.svg?cacheSeconds=300)](https://pypi.org/project/toolwall/)
[![Python versions](https://img.shields.io/pypi/pyversions/toolwall.svg)](https://pypi.org/project/toolwall/)
[![License: MIT](https://img.shields.io/pypi/l/toolwall.svg)](https://github.com/Dev-Saif-Ops/toolwall/blob/main/toolwall/LICENSE)
[![Zero dependencies](https://img.shields.io/badge/dependencies-zero-brightgreen.svg)](https://github.com/Dev-Saif-Ops/toolwall)

**Business rules for your AI agent's tool calls.**

Your support agent can call `issue_refund()`. toolwall decides how much, for which
customer, and when a person has to approve, before the call runs. Zero dependencies,
deterministic, sync and async.

```bash
pip install toolwall
```

```python
from toolwall import ToolWall, rules as r

wall = ToolWall()                               # default-deny, secret detection + audit on
wall.register("issue_refund", issue_refund)     # schema from the type hints
wall.rule("issue_refund",
    amount=r.positive() & r.at_most(500),
    order_id=r.owned_by("customer_id", lookup=orders.owner_of),
    ask_if=r.over("amount", 200))               # above this, a person approves

with wall.context(customer_id="c_42"):          # who the agent is acting for
    wall.call("issue_refund", {"order_id": "o_9",  "amount": 40})    # runs
    wall.call("issue_refund", {"order_id": "o_77", "amount": 40})    # blocked: not their order
    wall.call("issue_refund", {"order_id": "o_9",  "amount": 300})   # held for a person
```

**Your framework runs the tools?** Ask for a verdict from its "before tool" hook:
`d = wall.decide(name, args)` gives `d.verdict` ("allow", "deny" or "ask"), `d.reason`
(safe to send to the model) and `d.detail` (the full reason, for your logs).
`wall.check_output(name, value)` scans what the tool returned.

**See it in 30 seconds, no API key:**

```bash
python -m toolwall demo
```

```text
toolwall demo: a support agent serving customer c_42
Every verdict below comes from the real gate. No model or API key.

  ALLOW  issue_refund(order_id='o_9', amount=40.0)
         an honest refund: ran: refunded 40.00 on o_9
  BLOCK  issue_refund(order_id='o_9', amount=5000.0)
         a refund over the cap: policy violation: arg 'amount' rejected by (positive() & at_most(500))
         model is told: The value for 'amount' isn't allowed for this call.
  BLOCK  issue_refund(order_id='o_77', amount=40.0)
         someone else's order: policy violation: arg 'order_id' rejected by owned_by('customer_id')
         model is told: The value for 'order_id' isn't allowed for this call.
  BLOCK  send_email(to='x@evil.com,ops@ourco.com', body='export')
         a smuggled recipient: policy violation: arg 'to' rejected by (email_domain('ourco.com',) | equals_context('customer_email'))
         model is told: The value for 'to' isn't allowed for this call.
  ALLOW  lookup_customer(customer_id='c_42')
         a lookup whose record holds a key: ran, but tool output withheld: secret detected (stripe-key) in 'return.billing_api_key'
         model is told: The tool ran, but its output can't be shown.
  HELD   close_account(customer_id='c_42')
         a destructive action: waiting for a human to approve
         model is told: This call needs approval from a person before it can run.
  BLOCK  drop_all_tables()
         a tool nobody registered: unknown tool: 'drop_all_tables'
         model is told: This tool is not available.

2 ran (1 with its output withheld) · 4 stopped · 1 waiting for a human. The model gets the short reason; the full one goes to the audit log.
```

It also blocks the generic valid-but-wrong calls an LLM produces:

```python
delete_records(filter={})            # perfectly valid JSON. whole table gone.
send_email(to="attacker@evil.com")   # recipient injected via a poisoned web page
db_query(limit=10_000_000)           # production melts.
```

Works with OpenAI, Anthropic and Gemini native tool calling, plain dicts, and MCP.
Python 3.10+.

## Quickstart

```python
from toolwall import ToolWall, Policy, ToolSchema, in_range, not_empty

wall = ToolWall()   # default-deny, secret detection + audit on

wall.register("db_query", db_query,
              schema=ToolSchema(required=["q"], types={"q": str, "limit": int}),
              policy=Policy(constraints={"limit": in_range(1, 100)}))
wall.register("delete_records", delete_records,
              schema=ToolSchema(required=["filter"], types={"filter": dict}),
              policy=Policy(constraints={"filter": not_empty}, require_approval=True))
wall.budget(max_calls=20)

result = wall.call("delete_records", {"filter": {}})
# result.blocked -> True
# result.reason  -> "policy violation: arg 'filter' rejected by not_empty"

results = wall.guard(openai_response)   # or gate a raw OpenAI/Anthropic/Gemini response
```

Only an `ALLOW` verdict runs the tool. `Gate` is the lower-level primitive underneath.

**Async tools.** Agent frameworks are mostly async. Use `acall` and `aguard`: they
await the tool, then scan what it returned, with every check `call` makes.

```python
async def lookup_customer(customer_id: str) -> dict: ...

wall.register("lookup_customer", lookup_customer)   # schema from the annotations
r = await wall.acall("lookup_customer", {"customer_id": "c_42"})
results = await wall.aguard(openai_response)
```

The sync `call` refuses an async tool instead of reporting a coroutine as a run.
A tool that streams (an async generator) has its output withheld on both paths:
return a materialised list instead.

A function whose parameters and return value are all annotated gets its schema
from its signature: classes, `X | None`, `Optional`, `Union`, generic containers
(`list[str]` checks for a list), `Any` and `Annotated[...]`; `float` also accepts an
integer. Anything else (`Literal`, `TypedDict`, a non-runtime `Protocol`, a lambda,
a partly annotated function) still needs `schema=`, for example
`types={"filters": dict}`. A parameter annotated with a class JSON can't produce (a
dataclass, an Enum, a pydantic model) is inferred but blocks every call; give it an
explicit `schema=` with `dict` or `str`.


## What it stops

```python
wall.call("delete_records", {"filter": {}})
# BLOCKED: policy violation: arg 'filter' rejected by not_empty

wall.call("send_email", {"to": "ops@ourco.com", "body": "aws key AKIA..."})
# BLOCKED: secret detected (aws-access-key) in arg 'body'

wall.call("db_query", {"q": "everything", "limit": 10_000_000})
# BLOCKED: policy violation: arg 'limit' rejected by in_range(1, 100)

wall.call("run_shell", {"cmd": "..."})
# BLOCKED: unknown tool: 'run_shell'
```

Everything not explicitly allowed is blocked. That is the whole idea.

## What it does

- **Fail-closed gate**: unknown tool, schema violation, policy violation, budget hit,
  or unparseable payload all block *before* the tool runs. Registration is the allowlist.
- **Business rules** (`toolwall.rules`): `at_most`, `between`, `positive`, `one_of`,
  `owned_by`, `equals_context`, `email_domain`, `sql_readonly`, `path_under`,
  `url_host`, composed with `&`, `|` and `~`. Strict: `"40"` is not a number and `True`
  is not `1`. A rule that needs request context blocks when it isn't set, even
  negated.
- **Request context**: `wall.context(customer_id=...)`, visible to rules in this thread
  or asyncio task only. The audit records the keys, never the values.
- **Approvals** with `ask_if=r.over("amount", 200)`, bound to the exact call checked.
- **Verdicts for any framework**: `decide()` and `check_output()`, with model-facing
  reasons that name the argument, never the rule.
- **Policy engine underneath**: cross-argument rules and budget caps (calls / per-tool
  / USD). For recipients use `email_domain("ourco.com")`, not `ends_with`: a
  comma-separated list ends with your domain too.
- **Shield, both directions**: detects secrets (AWS, OpenAI, GitHub, Stripe, Slack,
  JWT, PEM, and high-entropy strings) in tool arguments *and in tool return values*,
  then blocks or redacts them, including in dict keys, tuples (database rows), sets,
  bytes and dataclasses. Output that cannot be scanned (generators, cursors, file
  objects, XML elements, models, arrays) is withheld, so return plain data;
  redaction never modifies the tool's own objects. Reasons, reports
  and the audit log are scrubbed of detected secrets.
- **Dry-run**: run your whole agent with `dry_run=True`: nothing executes, and
  `gate.report()` tells you what it *would* have done. `suggest_policies(gate)` drafts
  a starter policy from the calls it observed.
- **MCP guard**: `MCPGuard` runs the same check and execute path (budget, dry-run,
  receipts, output scanning) in front of a function that forwards to your MCP server.
- **Audit trail**: every verdict exported to JSON/CSV.

## Why not just the guardrails in my agent framework?

Use those too. Two things make `toolwall` different from security bundled into one
workspace or framework:

- **It's an allowlist, not a blocklist.** Bundled protections usually ship a list of
  dangerous patterns to deny, so anything the authors did not anticipate gets through.
  Here, registration *is* the allowlist: everything not explicitly allowed is blocked.
- **It runs inside your agent, not instead of it.** A workspace's built-in security
  protects that workspace. `toolwall` is a zero-dependency library that drops into the
  agent you already have, on any framework, and speaks OpenAI, Anthropic, Gemini, and MCP.

It is **not** a sandbox. A sandbox isolates the process; `toolwall` authorizes the call.
Production setups want both.

toolwall sees a call only when it goes through a tool it guards. An agent that also
has a shell or code-execution tool could reach the same API directly, so don't give a
customer-facing agent one. Default-deny covers calls that reach the wall, not tools
added to a framework without its adapter; the Claude Agent SDK ships a built-in Bash
tool, so list only the tools the agent needs with `ClaudeAgentOptions(tools=[...])`. Keep
credentials inside the tool rather than in the agent's environment. What it covers and what it doesn't:
[docs/threat-model.md](https://github.com/Dev-Saif-Ops/toolwall/blob/main/docs/threat-model.md).

## Dry-run first

```python
from toolwall import Gate, Meter, suggest_policies

gate = Gate(default="deny", dry_run=True, meter=Meter())
# ... run your agent; ALLOW calls are simulated, never executed ...
print(gate.report())            # verdict counts, blocked reasons, secrets caught
print(suggest_policies(gate))   # a draft policy from observed calls, for you to review
```

## Plug into your agent framework

```python
# OpenAI Agents SDK
from toolwall.integrations.openai_agents import guard_tool
@guard_tool(wall)
def issue_refund(order_id: str, amount: int | float) -> str: ...

# Claude Agent SDK
from toolwall.integrations.claude_agent_sdk import hooks
options = ClaudeAgentOptions(hooks=hooks(wall, matcher="^mcp__shop__"))

# LangChain / LangGraph
from toolwall.integrations.langchain import ToolWallMiddleware
agent = create_agent(model, tools, middleware=[ToolWallMiddleware(wall)], checkpointer=saver)

# MCP server (official Python SDK)
from toolwall.integrations.mcp import guard
@server.tool()
@guard(wall)
async def issue_refund(order_id: str, amount: int | float) -> str: ...
```

Denied calls never run and the model gets a short, safe reason. Calls that need
a person pause through the framework's own approval flow. Tool output is
checked for secrets before the model sees it (with the Claude Agent SDK, only
when the tool succeeds: wrap your own tools with `wall.protect` so error text is
scrubbed too; see the guide). Install with
`pip install "toolwall[openai-agents]"` (or `claude-agent-sdk`, `langchain`,
`mcp`, `integrations` for all).
Full guide: [docs/frameworks.md](https://github.com/Dev-Saif-Ops/toolwall/blob/main/docs/frameworks.md).

## Approvals that bind the exact call

```python
from toolwall import Approvals, SQLiteStore

wall = ToolWall(approvals=Approvals(SQLiteStore("approvals.db")))
with wall.context(customer_id="c_42"):
    held = wall.call("issue_refund", {"order_id": "o_9", "amount": 350})
held.ticket                                           # "tkt_6f72..."

wall.approvals.approve(held.ticket, by="ops@ourco.com")   # or: python -m toolwall approvals ...
wall.run_approved(held.ticket)                        # those arguments, that customer, once
```

The ticket is bound to the exact arguments and the customer the agent was
serving. A changed amount, another customer, a replay, an expired or edited
ticket never runs. Inside a framework, the same call coming back after approval
runs once without pausing again (Claude Agent SDK: `hooks(wall, on_hold="defer")`).
Full guide: [docs/approvals.md](https://github.com/Dev-Saif-Ops/toolwall/blob/main/docs/approvals.md).

## Guard an MCP server

```python
from toolwall import Gate, MCPGuard

guard = MCPGuard(gate, forward=call_downstream_mcp_server)
decision = guard.handle(tool_name, args)   # only ALLOW is forwarded
```

`forward` is your own function that calls the downstream server; toolwall ships no
MCP transport. To guard tools on your own MCP server, use `@guard(wall)` from
`toolwall.integrations.mcp` (above).

## Examples

Runnable scripts live in the [repo `examples/` folder](https://github.com/Dev-Saif-Ops/toolwall/tree/main/toolwall/examples):

- **quickstart.py**: six gated scenarios (allow, unknown tool, out-of-range, empty-filter delete, approval hold, secret block). No API key.
- **dangerous_agent_demo.py**: an off-the-rails agent replayed with vs without the gate. No API key.
- **mcp_guard_demo.py**: the gate in front of an MCP-style server. No API key.
- **live_gemini_agent.py**: a real Gemini agent using native function calling, gated by toolwall. Needs `GEMINI_API_KEY`.

```bash
git clone https://github.com/Dev-Saif-Ops/toolwall && cd toolwall/toolwall
python examples/quickstart.py
python examples/live_gemini_agent.py     # set GEMINI_API_KEY first
```

## Honest status

`toolwall` is alpha. The published failure suite blocks **35 of 35 attack cases across
11 classes with 0 false blocks on its 14 clean cases**, at sub-millisecond per-call
overhead for small arguments (about 2 ms at 50 KB). It is a regression suite for one
reference config, not a coverage measure, and it lists ordinary text the shield is
known to flag. Secret
detection is pattern + entropy based and is **never 100%**. Structureless passwords are
out of scope, and the suite report states exactly what is and is not proven. Every claim
about toolwall cites that report, nothing broader.

**The verdict covers the call, not the state of the world.** An approved
`delete_records(id=42)` deletes whatever 42 points to at execution time; if the resource
was swapped after the check, the receipt still matches because the argument never
changed. Argument integrity is not resource integrity. For resources that can change
owner or meaning, re-verify inside the tool's own transaction (for example
compare-and-swap on a version column); the gate cannot see your datastore.

## Security

Found a way past the gate? Please report it privately through
[GitHub's vulnerability reporting](https://github.com/Dev-Saif-Ops/toolwall/security/advisories/new),
not as a public issue. Details in [SECURITY.md](https://github.com/Dev-Saif-Ops/toolwall/blob/main/SECURITY.md).

## Links

- **Source, full docs, and the failure suite:** https://github.com/Dev-Saif-Ops/toolwall
- **What happened to TOAP** (this project's predecessor, an honest postmortem):
  the [`toap-v0.1-archive`](https://github.com/Dev-Saif-Ops/toolwall/tree/toap-v0.1-archive) branch

## License

MIT © Mohammad Safwan Athar
