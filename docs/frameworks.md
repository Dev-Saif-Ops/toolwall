# ToolWall in your agent framework

Your framework runs the tools. ToolWall decides whether each call may run, and
checks what comes back before the model sees it. The same `ToolWall` and the
same rules work with every adapter below.

```python
from toolwall import ToolWall, rules as r

wall = ToolWall()
wall.rule("issue_refund",
          amount=r.positive() & r.at_most(500),
          order_id=r.owned_by("customer_id", lookup=orders.owner_of),
          ask_if=r.over("amount", 200))      # over 200 waits for a person
```

Set who the agent is acting for around each run:

```python
with wall.context(customer_id=session.customer_id):
    ...run the agent...
```

Every verdict is one of three:

| Verdict | What happens |
|---|---|
| allow | the tool runs; its output is scanned for secrets first |
| deny | the tool does not run; the model gets a short reason that names no rule internals or customer data |
| ask | the run pauses for a person, using the framework's own approval flow |

Install the adapter you need:

```bash
pip install "toolwall[openai-agents]"     # or claude-agent-sdk, langchain, mcp, integrations (all)
```

## OpenAI Agents SDK

```python
from agents import Agent, Runner
from toolwall.integrations.openai_agents import guard_tool

@guard_tool(wall)
def issue_refund(order_id: str, amount: int | float) -> str:
    """Refund an order."""
    ...

agent = Agent(name="support", tools=[issue_refund])
with wall.context(customer_id="c_42"):
    result = await Runner.run(agent, "refund order o_9")
```

`guard_tool` is `function_tool` with three things attached: `needs_approval`
(true when the wall says ask), a tool input guardrail (the wall's verdict right
before the tool runs) and a tool output guardrail (secret scan). Approve held
calls the SDK's way:

```python
if result.interruptions:
    state = result.to_state()
    state.approve(result.interruptions[0])     # or state.reject(...)
    result = await Runner.run(agent, state)
```

Notes:
- The SDK holds a call for approval without asking the wall whenever it can't
  compare the arguments it will run with to the ones the model sent: its own
  type coercion changed one (annotate numbers `int | float`, not `float`), an
  optional parameter was left out, a parameter isn't plain data (Enum, datetime,
  a nested model, a `str` with a pattern), or validation fails. Safe, but every
  such call waits for a person. After approval the wall still decides.
- "Always approve" in the SDK is sticky: once a person picks it, later calls to
  that tool skip approval, even ones the wall would hold. Approve per call.
- The SDK can't swap the arguments a tool receives, so a call whose arguments
  carry a secret is rejected, not redacted.
- Already using `function_tool`? Pass `**guardrails(wall, "issue_refund")` to it.

## Claude Agent SDK

```python
from claude_agent_sdk import ClaudeAgentOptions, ClaudeSDKClient
from toolwall.integrations.claude_agent_sdk import hooks

wall.rule("mcp__shop__issue_refund", schema=refund_schema, amount=r.at_most(500))

options = ClaudeAgentOptions(hooks=hooks(wall, matcher="^mcp__shop__"))
with wall.context(customer_id="c_42"):
    async with ClaudeSDKClient(options=options) as client:
        ...
```

A `PreToolUse` hook asks the wall. A deny becomes `permissionDecision: "deny"`
with the reason. An ask becomes `"ask"`, so the SDK asks the user through your
`can_use_tool` callback; without one the CLI refuses the call. An allow returns
no decision, so your permission mode and rules still apply. When the wall
redacted a secret in the arguments (`ToolWall(redact=True)`), the clean
arguments go to the tool and to the person approving.
A `PostToolUse` hook replaces secrets in the output with placeholders and keeps
the output's shape. The SDK ignores a replacement that doesn't match a
built-in tool's output shape, so withholding would leak.

Limits:
- When a tool fails (an MCP tool error or exception, Bash exiting non-zero) the
  SDK fires a failure hook that can't replace what the model sees, so a failing
  tool's error text reaches the model unscanned. Wrap your own SDK MCP tools
  with `wall.protect`, which scrubs exception text.
- The hooks read `wall.context` when the client connects, not per query. Open
  one client per customer inside `with wall.context(...)`.
- A held call takes its budget slot when the SDK asks, even if the person then
  declines.

Every tool the hooks see must be declared to the wall: `wall.rule(name, schema=...)`.
Use `matcher` to choose which tools are gated. Built-in tools are named `Bash`,
`Read`, `Write` and so on; MCP tools are named `mcp__<server>__<tool>`.

## LangChain and LangGraph (langchain >= 1.0)

```python
from langchain.agents import create_agent
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.types import Command
from toolwall.integrations.langchain import ToolWallMiddleware

agent = create_agent(model, [issue_refund], middleware=[ToolWallMiddleware(wall)],
                     checkpointer=InMemorySaver())
config = {"configurable": {"thread_id": "t1"}}
with wall.context(customer_id="c_42"):
    state = agent.invoke({"messages": [("user", "refund order o_9")]}, config)
    if "__interrupt__" in state:          # {"toolwall": "approval", "tool", "args", "reason"}
        state = agent.invoke(Command(resume=True), config)   # False declines
```

A denied call becomes a `ToolMessage` with `status="error"`. A held call raises a
LangGraph interrupt, which needs a checkpointer. Only `True` approves. With
several held calls pending, resume each by id:
`Command(resume={i.id: True for i in state["__interrupt__"]})`. Without one, pass
`ToolWallMiddleware(wall, approvals=False)` and held calls are refused. Both
`invoke` and `ainvoke` go through the wall.

## MCP servers (official Python SDK, 1.x and 2.x)

```python
from mcp.server.mcpserver import MCPServer        # FastMCP in mcp 1.x
from toolwall.integrations.mcp import guard

server = MCPServer("shop")

@server.tool()
@guard(wall)
async def issue_refund(order_id: str, amount: int | float) -> str: ...
```

`guard(wall)` checks every call and turns a deny or a hold into an MCP
`ToolError` carrying the safe reason. The server still reads the tool's
signature. MCP has no standard approval flow yet, so a held call is refused
with a message saying it needs approval, unless you gave the wall an approval
handler. Set `wall.context(...)` around the server's (or in-process client's)
lifetime, one server per customer. Keep MCP `Context` parameters out of guarded
tools.

To gate calls you forward to another MCP server, use `toolwall.MCPGuard`.

## Plain Python

```python
from toolwall import ToolBlocked

@wall.protect
def issue_refund(order_id: str, amount: int | float) -> str: ...

try:
    issue_refund("o_9", 40)
except ToolBlocked as e:
    print(e)          # the model-safe reason
```

Or ask for a verdict and run the tool yourself:

```python
decision = wall.decide("issue_refund", {"order_id": "o_9", "amount": 300})
decision.verdict        # "allow", "deny" or "ask"
if decision.needs_approval and person_says_yes():
    decision = wall.take_slot(decision)       # counts it against the budget
```

`wall.check_output(name, value)` scans what a tool returned.

## Known limits

- Rules and lookups are synchronous. An async lookup is refused, so the call is
  blocked.
- `wall.context(...)` is a contextvar. LangGraph and the SDKs above carry it into
  their tool threads. Your own thread pools need `contextvars.copy_context()`.
- Approvals happen in memory, inside one run. Approval tickets that survive a
  restart are planned for 0.7.
