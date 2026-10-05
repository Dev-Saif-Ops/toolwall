"""toolwall-mcp: put a fail-closed gate in front of any MCP server.

MCP (Model Context Protocol) lets a host expose tools to an agent. This guard
sits between the agent's tool call and the underlying server: the same Gate
checks name + schema + policy + shield + budget, and only ALLOW calls are
forwarded. Blocked calls return a structured MCP tool error instead.

The `mcp` package is an optional extra (`pip install toolwall[mcp]`); this
module imports it lazily so toolwall core stays stdlib-only. The logic below
(map_result) is framework-free and unit-tested without any MCP install.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from toolwall.gate import Gate, GateResult, Verdict


@dataclass
class GuardedCall:
    """What the guard decided for one forwarded MCP tool call."""

    verdict: str
    forwarded: bool
    reason: str | None = None
    result: Any = None


def to_mcp_error(result: GateResult) -> dict[str, Any]:
    """Render a blocked/held GateResult as an MCP-style tool error payload."""
    reason = "; ".join(result.reasons) if result.reasons else result.verdict.value
    return {
        "isError": True,
        "content": [
            {
                "type": "text",
                "text": f"toolwall {result.verdict.value}: {reason}",
            }
        ],
    }


class MCPGuard:
    """Wraps a callable that forwards a tool call to a downstream MCP server.

    `forward(name, args) -> Any` is whatever actually calls the real server.
    Registration on `gate` is the allowlist: a tool the gate does not know is
    blocked before it ever reaches the server.
    """

    def __init__(self, gate: Gate, forward: Callable[[str, dict[str, Any]], Any]):
        self.gate = gate
        self.forward = forward

    def handle(self, name: str, args: dict[str, Any]) -> GuardedCall:
        result = self.gate.check({"name": name, "args": args})

        if result.verdict is Verdict.NEEDS_APPROVAL:
            result = self.gate._resolve_approval(result)

        if not result.allowed:
            return _refused(result)

        # Forward through Gate.execute, not around it: the receipt check, budget,
        # dry-run and output scanning apply to MCP traffic exactly as to local tools.
        # The shield may have rewritten args (redact mode); execute hands over the
        # verified copy.
        reached: list[bool] = []

        def invoke(verified_args: dict[str, Any]) -> Any:
            reached.append(True)
            return self.forward(name, verified_args)

        result = self.gate.execute(result, invoke=invoke)

        if not result.allowed:  # refused at execute time (receipt mismatch, budget)
            return _refused(result)
        if result.dry_run:
            return GuardedCall(verdict="allow", forwarded=False, reason="dry run: not forwarded")
        if result.error is not None:  # downstream raised, or its output was withheld
            return GuardedCall(
                verdict="allow",
                forwarded=bool(reached),
                reason=result.error,
                result={
                    "isError": True,
                    "content": [{"type": "text", "text": f"toolwall: {result.error}"}],
                },
            )
        return GuardedCall(verdict="allow", forwarded=True, result=result.return_value)


def _refused(result: GateResult) -> GuardedCall:
    return GuardedCall(
        verdict=result.verdict.value,
        forwarded=False,
        reason="; ".join(result.reasons) or None,
        result=to_mcp_error(result),
    )


def build_stdio_guard(gate: Gate, upstream_command: list[str]):  # pragma: no cover
    """Construct an MCP stdio proxy in front of `upstream_command`.

    Lazy-imports `mcp`. Returns a server object the caller runs. Kept thin and
    excluded from unit coverage; the decision logic lives in MCPGuard.handle,
    which is fully tested without an MCP install.
    """
    try:
        import mcp  # noqa: F401
    except ImportError as exc:
        raise SystemExit(
            "toolwall-mcp needs the MCP extra: pip install 'toolwall[mcp]'"
        ) from exc
    raise NotImplementedError(
        "stdio transport wiring lands with the first real MCP pilot; "
        "MCPGuard.handle is the tested core and is usable now with any forward()."
    )
