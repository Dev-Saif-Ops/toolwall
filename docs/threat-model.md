# What ToolWall covers, and what it doesn't

ToolWall authorizes tool calls. It sees a call when the call goes through a
tool it guards (for example `wall.call` / `acall`, `wall.guard()` on a raw LLM
response, `@wall.protect`, `decide()` in a framework adapter, `@guard` on an MCP
server tool, `MCPGuard`, `run_approved`), and it decides whether that call may
run. It does not isolate processes, filter network traffic or
read the model's intent. This page says where that boundary is, so you can put
the other layers next to it.

## It assumes

1. **The agent's only way to do the action is a guarded tool.** If the agent
   can reach the same API another way, the wall never sees that path.
2. **Credentials for the action live with the tool, not with the agent.** The
   refund tool holds (or fetches) the key it needs to call the payments API.
   The process, container or sandbox the agent's own code runs in doesn't have
   that key.
3. **Your rules and lookups are trusted code.** `owned_by` asks your
   `lookup` who owns an order; a lookup that lies, ToolWall believes.
4. **The approval store is trusted.** Anyone who can write to it can approve a
   ticket, as with any approvals table.

## It doesn't cover

- **Shell and code execution tools.** An agent with a shell can call the API
  directly (`curl`) and never touch the guarded `issue_refund`. Default-deny
  covers calls that reach the wall: a tool name the wall doesn't know is
  blocked. It doesn't cover tools the wall never sees. In a framework, a tool
  added without the wall's adapter (a plain `function_tool`, the SDK's hosted
  shell or code-interpreter tools) runs outside it, and the **Claude Agent SDK
  ships built-in tools, Bash included**: list only the tools the agent needs
  with `ClaudeAgentOptions(tools=[...])` (`disallowed_tools=["Bash"]` removes
  Bash but leaves Write, WebFetch and the rest), or use a hook matcher that
  covers them (then the wall denies Bash, since it isn't a
  registered tool). A customer-facing agent shouldn't have a shell at all. If
  you do give one a shell or code-execution tool through the wall, the wall sees
  the command as a string: a rule like `r.one_of(...)` can allow a short list of
  exact commands, but it can't understand what an arbitrary command does. Put
  such tools in a sandbox with no credentials and no network access to the
  systems that matter.
- **Network access from the agent's runtime.** If the agent's code can open
  connections, egress rules belong in the network layer, not in ToolWall.
- **Prompt injection itself.** ToolWall doesn't detect or stop an injected
  instruction; it limits what an injected agent can do through its tools.
- **What a tool's code does beyond its return value.** A tool that writes to
  the agent's state, a file or a database directly is outside what an output
  check can see.
- **MCP tool poisoning.** ToolWall doesn't read MCP tool descriptions, so a
  malicious description in a server's tool list isn't detected.
- **Sequences of calls.** Each call is checked on its own, plus budgets.
  "Read then exfiltrate" across calls isn't a rule type yet.
- **Calls checked together.** When a framework runs a turn's tool calls
  concurrently (the OpenAI Agents SDK does by default), their checks can all
  happen before any of them runs, so two calls in one turn can each pass a rule
  that only one of them should (for example two refunds under "what's left on
  the order"). `wall.guard()` on a raw response checks and runs one call at a
  time and doesn't have this race. Enforce money limits where the money moves
  too (a database constraint or the payments service), or cap calls with
  `wall.budget(max_calls_per_tool=...)`, which counts over the wall's whole
  lifetime, not per turn or per order.
- **Secrets it can't recognise.** Detection is pattern and entropy based: it
  catches API keys, tokens and private keys, but not reliably plain passwords,
  hex-encoded secrets, or a key split into small pieces across fields.
- **Claude Agent SDK, failing tools.** When a tool fails, the SDK's failure
  hook can't replace the error text, so it reaches the model unscanned. Wrap
  your own tools with `wall.protect`, which scrubs exception text.

## Where it fits

| Layer | Stops |
|---|---|
| Sandbox / container | the agent's code touching the host |
| Least-privilege credentials | anything holding the agent's credentials doing more than intended |
| Network egress policy | the agent's runtime reaching systems directly |
| Database constraints, payments limits | money and data rules being broken by any caller |
| **ToolWall** | an allowed tool being used for the wrong customer, amount, recipient or record; secrets in tool arguments and output; risky calls running without a person |

A serious production setup wants several of these. ToolWall is the one that
knows your business rules and who the agent is serving.

## A pattern that keeps the wall in the path

```python
from toolwall.integrations.openai_agents import guard_tool   # or @wall.protect, or MCP @guard

# The agent's process has no payments key. The tool does, server side.
@guard_tool(wall)
def issue_refund(order_id: str, amount: int | float) -> str:
    return payments.refund(order_id, amount)   # client built from a key the agent never sees

# The agent gets no shell or code-execution tool, guarded or not.
```

Found a way around the wall that isn't listed here? Please report it:
[SECURITY.md](../SECURITY.md).
