"""ToolWall for the Claude Agent SDK.

    from claude_agent_sdk import ClaudeAgentOptions, ClaudeSDKClient
    from toolwall.integrations.claude_agent_sdk import hooks

    options = ClaudeAgentOptions(hooks=hooks(wall, matcher="^mcp__shop__"))
    with wall.context(customer_id="c_42"):
        async with ClaudeSDKClient(options=options) as client: ...

PreToolUse asks the wall:
- "deny": permissionDecision "deny" with the model-safe reason.
- "ask": permissionDecision "ask", so the SDK asks the user through its own
  permission flow. The budget slot is taken now (counting a call a person may
  still decline errs on the safe side).
- "allow": no decision is returned, so your permission mode and rules still
  apply on top of the wall. When the wall redacted a secret in the arguments,
  the redacted arguments are passed as updatedInput.

PostToolUse scans what the tool returned. The SDK keeps the original output
when a replacement doesn't match a built-in tool's output shape, so secrets are
replaced in place with placeholders (the shape is kept) rather than withheld.

Registration is the allowlist: every tool the hook sees must be known to the
wall (wall.rule(name, schema=...) for tools the SDK runs). Use `matcher` to
scope the hooks to the tools you want gated; built-in tools are named Bash,
Read, Write..., MCP tools mcp__<server>__<tool>.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # pragma: no cover
    from toolwall.wall import ToolWall


def pre_tool_use(wall: "ToolWall"):
    """The PreToolUse callback on its own (async, SDK hook signature)."""

    async def hook(input_data: dict[str, Any], tool_use_id: str | None, context: Any) -> dict[str, Any]:
        name = input_data.get("tool_name")
        args = input_data.get("tool_input")
        if not isinstance(name, str) or not isinstance(args, dict):
            return _decision(input_data, "deny", "The arguments for this call could not be read.")
        decision = wall.decide(name, args)
        if decision.needs_approval:
            decision_slot = wall.take_slot(decision)
            if decision_slot.denied:
                return _decision(input_data, "deny", decision_slot.reason)
            return _decision(input_data, "ask", decision.reason)
        if decision.denied:
            return _decision(input_data, "deny", decision.reason)
        if decision.args != args:
            # Redacted by the wall: hand the SDK the clean arguments. No decision,
            # so the SDK's own permission evaluation still runs on them.
            return {"hookSpecificOutput": {
                "hookEventName": input_data.get("hook_event_name", "PreToolUse"),
                "updatedInput": dict(decision.args),
            }}
        return {}

    return hook


def post_tool_use(wall: "ToolWall"):
    """The PostToolUse callback on its own (async, SDK hook signature)."""
    from toolwall.shield import Shield, UnscannableError

    async def hook(input_data: dict[str, Any], tool_use_id: str | None, context: Any) -> dict[str, Any]:
        shield = wall.gate.shield
        if shield is None:
            return {}
        redactor = Shield(mode="redact", patterns=shield.patterns, entropy=shield.entropy,
                          entropy_threshold=shield.entropy_threshold, allowlist=shield.allowlist)
        response = input_data.get("tool_response")
        try:
            cleaned, findings = redactor.redact_args({"v": response})
        except (UnscannableError, Exception):
            # SDK tool responses are JSON, so this shouldn't happen; if it does,
            # replace the output with a notice rather than pass it through.
            return _output(input_data, "[toolwall: output withheld, it could not be scanned]")
        if not findings:
            return {}
        return _output(input_data, cleaned["v"])

    return hook


def hooks(wall: "ToolWall", matcher: str | None = None) -> dict[str, list[Any]]:
    """ClaudeAgentOptions(hooks=hooks(wall)): PreToolUse and PostToolUse."""
    from claude_agent_sdk import HookMatcher

    return {
        "PreToolUse": [HookMatcher(matcher=matcher, hooks=[pre_tool_use(wall)])],
        "PostToolUse": [HookMatcher(matcher=matcher, hooks=[post_tool_use(wall)])],
    }


def _decision(input_data: dict[str, Any], verdict: str, reason: str | None) -> dict[str, Any]:
    return {"hookSpecificOutput": {
        "hookEventName": input_data.get("hook_event_name", "PreToolUse"),
        "permissionDecision": verdict,
        "permissionDecisionReason": reason or "This call isn't allowed.",
    }}


def _output(input_data: dict[str, Any], value: Any) -> dict[str, Any]:
    return {"hookSpecificOutput": {
        "hookEventName": input_data.get("hook_event_name", "PostToolUse"),
        "updatedToolOutput": value,
    }}
