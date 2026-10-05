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
calling (and plain dicts). Python 3.10+.

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
  objects) is withheld, so return plain data; redaction never modifies the tool's
  own objects. Reasons, reports
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

## Links

- **Source, full docs, and the failure suite:** https://github.com/Dev-Saif-Ops/toolwall
- **What happened to TOAP** (this project's predecessor, an honest postmortem):
  the [`toap-v0.1-archive`](https://github.com/Dev-Saif-Ops/toolwall/tree/toap-v0.1-archive) branch

## License

MIT © Mohammad Safwan Athar
