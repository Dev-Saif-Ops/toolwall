# toolwall

[![PyPI version](https://img.shields.io/pypi/v/toolwall.svg?cacheSeconds=300)](https://pypi.org/project/toolwall/)
[![Python versions](https://img.shields.io/pypi/pyversions/toolwall.svg)](https://pypi.org/project/toolwall/)
[![License: MIT](https://img.shields.io/pypi/l/toolwall.svg)](https://github.com/Dev-Saif-Ops/toolwall/blob/main/toolwall/LICENSE)
[![Zero dependencies](https://img.shields.io/badge/dependencies-zero-brightgreen.svg)](https://github.com/Dev-Saif-Ops/toolwall)

**The security gateway for AI agent tool calls.**

Your LLM can generate a *valid* tool call. That doesn't mean it's *safe* to execute.

```python
delete_records(filter={})            # perfectly valid JSON. whole table gone.
send_email(to="attacker@evil.com")   # recipient injected via a poisoned web page
transfer_money(amount=999999999)     # schema-valid. every field the right type.
db_query(limit=10_000_000)           # production melts.
```

Every one of these passes JSON schema validation. Structured outputs, schemas, and
content moderation all wave them through. `toolwall` is the fail-closed checkpoint
between the LLM's tool call and execution that blocks them.

---

## Install

```bash
pip install toolwall
```

Zero required dependencies. Works with OpenAI, Anthropic, and Gemini native tool
calling (and plain dicts). Python 3.10+, sync and async tools.

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
         a refund over the cap: policy violation: arg 'amount' rejected by in_range(0.01, 500)
  BLOCK  issue_refund(order_id='o_77', amount=40.0)
         someone else's order: order does not belong to the signed-in customer
  BLOCK  send_email(to='x@evil.com,ops@ourco.com', body='export')
         a smuggled recipient: policy violation: arg 'to' rejected by customer_or_ourco
  ALLOW  lookup_customer(customer_id='c_42')
         a lookup whose record holds a key: ran, but tool output withheld: secret detected (stripe-key) in 'return.billing_api_key'
  HELD   close_account(customer_id='c_42')
         a destructive action: waiting for a human to approve
  BLOCK  drop_all_tables()
         a tool nobody registered: unknown tool: 'drop_all_tables'

1 ran · 5 stopped · 1 waiting for a human. Every decision is in the audit log (wall.export).
```


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
- **Policy engine**: value constraints (`in_range`, `one_of`, `matches`, `email_domain`…),
  cross-argument rules, human-approval flags, and budget caps (calls / per-tool / USD).
  For recipients use `email_domain("ourco.com")`, not `ends_with`: a comma-separated
  list ends with your domain too.
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

## Dry-run first

```python
from toolwall import Gate, Meter, suggest_policies

gate = Gate(default="deny", dry_run=True, meter=Meter())
# ... run your agent; ALLOW calls are simulated, never executed ...
print(gate.report())            # verdict counts, blocked reasons, secrets caught
print(suggest_policies(gate))   # a draft policy from observed calls, for you to review
```

## Guard an MCP server

```python
from toolwall import Gate, MCPGuard

guard = MCPGuard(gate, forward=call_downstream_mcp_server)
decision = guard.handle(tool_name, args)   # only ALLOW is forwarded
```

`forward` is your own function that calls the downstream server; no MCP transport
ships yet. `pip install "toolwall[mcp]"` only installs the `mcp` package.

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
