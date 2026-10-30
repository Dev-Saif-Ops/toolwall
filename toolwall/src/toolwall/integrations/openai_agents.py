"""ToolWall for the OpenAI Agents SDK.

    from agents import function_tool
    from toolwall.integrations.openai_agents import guard_tool

    @guard_tool(wall)                     # or: @function_tool(**guardrails(wall, "issue_refund"))
    def issue_refund(order_id: str, amount: int | float) -> str: ...

    with wall.context(customer_id="c_42"):
        result = await Runner.run(agent, "...")

guardrails(wall, name) returns three function_tool keyword arguments that work
as one (guard_tool(wall) does the same and binds the name for you):

- needs_approval: True when the wall says "ask", so the SDK pauses the run for a
  person (see the SDK's human-in-the-loop docs for approving and resuming).
- tool_input_guardrails: the wall's verdict right before the tool runs. "deny"
  replaces the call with a model-safe reason. "ask" reaching this point means the
  SDK's approval said yes: the call takes its budget slot and runs.
- tool_output_guardrails: what the tool returned, scanned for secrets. Withheld
  output, or a redacted copy, replaces it.

Use all three together. The input guardrail treats "ask" as approved because
needs_approval is what asks; on its own it would let a held call run. The SDK
runs input guardrails after approval by default; don't enable its
pre-approval guardrail option with these.

The tool's name in the SDK (the function name, or name_override) is the name
the wall's rules use.

Annotate numbers as `int | float`, not `float`. When the SDK's own type
coercion changes an argument (a model's 40 becoming 40.0), the SDK holds the
call for approval without asking the wall, so every whole-number call would
wait for a person.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # pragma: no cover
    from toolwall.wall import ToolWall

_MALFORMED = "The arguments for this call could not be read."


def _args(raw: Any) -> dict[str, Any] | None:
    if isinstance(raw, dict):
        return raw
    if not isinstance(raw, str):
        return None
    try:
        parsed = json.loads(raw or "{}", parse_constant=_reject)
    except (ValueError, RecursionError):
        return None
    return parsed if isinstance(parsed, dict) else None


def _reject(name: str) -> Any:
    raise ValueError(name)


def guardrails(wall: "ToolWall", tool_name: str | None = None) -> dict[str, Any]:
    """function_tool(**guardrails(wall, "issue_refund")): input and output
    guardrails, plus needs_approval when the tool's name is given.

    Without tool_name there is no approval step (the SDK's needs_approval isn't
    told which tool it is asking about), so a call the wall would hold for a
    person is rejected instead.
    """
    from agents import ToolGuardrailFunctionOutput, tool_input_guardrail, tool_output_guardrail

    approvals = tool_name is not None

    @tool_input_guardrail(name="toolwall")
    def check_input(data: Any) -> Any:
        ctx = data.context
        args = _args(ctx.tool_arguments)
        if args is None:
            return ToolGuardrailFunctionOutput.reject_content(_MALFORMED)
        decision = wall.decide(ctx.tool_name, args)
        if decision.needs_approval and approvals:
            # Input guardrails run after the SDK's approval: a person said yes.
            decision = wall.take_slot(decision)
        if not decision.allowed:
            return ToolGuardrailFunctionOutput.reject_content(decision.reason or "This call isn't allowed.")
        if decision.args != args:
            # The wall redacted a secret, but the SDK can't swap the arguments a
            # tool receives, so the original (secret-bearing) call must not run.
            return ToolGuardrailFunctionOutput.reject_content(
                "The arguments contain what looks like a secret. Remove it and try again."
            )
        return ToolGuardrailFunctionOutput.allow()

    @tool_output_guardrail(name="toolwall")
    def check_output(data: Any) -> Any:
        checked = wall.check_output(data.context.tool_name, data.output)
        if checked.withheld:
            return ToolGuardrailFunctionOutput.reject_content(checked.reason or "Output withheld.")
        if checked.value is not data.output:
            # Redacted copy: the SDK only lets a guardrail replace output with text.
            value = checked.value
            text = value if isinstance(value, str) else json.dumps(value, default=str)
            return ToolGuardrailFunctionOutput.reject_content(text)
        return ToolGuardrailFunctionOutput.allow()

    kwargs: dict[str, Any] = {
        "tool_input_guardrails": [check_input],
        "tool_output_guardrails": [check_output],
    }
    if approvals:
        async def needs_approval(run_context: Any, args: dict[str, Any], call_id: str) -> bool:
            return wall._decide(tool_name, args, reserve=False).needs_approval

        kwargs["needs_approval"] = needs_approval
    return kwargs


def guard_tool(wall: "ToolWall", fn: Any = None, **function_tool_kwargs: Any) -> Any:
    """function_tool with the wall's guardrails and approvals attached.

        @guard_tool(wall)
        def issue_refund(order_id: str, amount: int | float) -> str: ...
    """
    from agents import function_tool

    def wrap(f: Any) -> Any:
        name = function_tool_kwargs.get("name_override") or f.__name__
        if wall.gate.registry.get(name) is None:
            wall.register(name, f)  # schema from the annotations; the SDK runs it
        return function_tool(f, **guardrails(wall, name), **function_tool_kwargs)

    return wrap(fn) if fn is not None else wrap
