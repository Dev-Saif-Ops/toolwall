"""ToolWall: the one-line entry point.

`Gate` is the low-level primitive (verdicts, execution split, meter wiring).
`ToolWall` is the ergonomic facade most users want: it wires a Gate with a
Shield and a Meter already attached, and gives you `register` + `call`.

    from toolwall import ToolWall, Policy, ToolSchema, not_empty

    wall = ToolWall()                      # default-deny, secret detection + audit on
    wall.register("get_user", get_user, schema=ToolSchema(required=["id"]))
    wall.register("delete_user", delete_user, schema=ToolSchema(required=["id"]),
                  policy=Policy(require_approval=True))

    result = wall.call("get_user", {"id": "123"})       # ALLOW -> runs
    result = wall.call("delete_user", {"id": "123"})    # held for approval
    if result.blocked:
        print(result.reason)
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from toolwall.gate import ApprovalHandler, DefaultMode, Gate, GateResult
from toolwall.meter import Meter
from toolwall.policy import Policy
from toolwall.schema import ToolSchema, fully_annotated
from toolwall.shield import Shield

ToolFn = Callable[..., Any]


class ToolWall:
    """Fail-closed security gateway for AI agent tool calls.

    Args:
        default: "deny" (registered tools still need a schema) or "allow".
        detect_secrets: attach a Shield. True blocks secrets in tool args;
            pass redact=True to replace them with placeholders instead.
        redact: if detecting secrets, redact instead of block.
        audit: attach a Meter so every verdict is recorded and exportable.
        approval: handler called when a tool needs approval; return True to run.
    """

    def __init__(
        self,
        *,
        default: DefaultMode = "deny",
        detect_secrets: bool = True,
        redact: bool = False,
        audit: bool = True,
        approval: ApprovalHandler | None = None,
    ):
        shield = Shield(mode="redact" if redact else "block") if detect_secrets else None
        meter = Meter() if audit else None
        self.gate = Gate(default=default, meter=meter, shield=shield, approval=approval)

    # -- setup (chainable) ---------------------------------------------------

    def register(
        self,
        name: str,
        fn: ToolFn,
        *,
        schema: ToolSchema | None = None,
        policy: Policy | None = None,
        infer_schema: bool | None = None,
        replace: bool = False,
    ) -> "ToolWall":
        """Register a tool. Registration is the allowlist.

        With no schema, a function whose every parameter and return value are
        annotated gets its schema from its signature (required args, types, no
        unknown args). Anything less (a lambda, a partly annotated function) still
        needs a schema: under default deny it is blocked until it has one.
        infer_schema=False opts out.
        """
        if infer_schema is None:
            infer_schema = schema is None and fully_annotated(fn)
        self.gate.register(
            name, fn, schema, policy=policy, infer_schema=infer_schema, replace=replace
        )
        return self

    def budget(
        self,
        *,
        max_calls: int | None = None,
        max_calls_per_tool: int | None = None,
        max_usd: float | None = None,
    ) -> "ToolWall":
        self.gate.budget(
            max_calls=max_calls, max_calls_per_tool=max_calls_per_tool, max_usd=max_usd
        )
        return self

    def approve_with(self, handler: ApprovalHandler) -> "ToolWall":
        self.gate.approval = handler
        return self

    # -- use -----------------------------------------------------------------

    def call(self, name: str, args: dict[str, Any] | None = None) -> GateResult:
        """Check the call and execute it only if allowed."""
        return self.gate.run({"name": name, "args": args or {}})

    async def acall(self, name: str, args: dict[str, Any] | None = None) -> GateResult:
        """call() for async tools: awaits the tool, then scans what it returned.

        Works for sync tools too. Async approval handlers are awaited here.
        """
        return await self.gate.arun({"name": name, "args": args or {}})

    def check(self, name: str, args: dict[str, Any] | None = None) -> GateResult:
        """Return the verdict without executing anything."""
        return self.gate.check({"name": name, "args": args or {}})

    def guard(self, response: Any) -> list[GateResult]:
        """Gate a raw LLM response (OpenAI/Anthropic/Gemini), possibly many calls."""
        return self.gate.run_all(response)

    async def aguard(self, response: Any) -> list[GateResult]:
        """guard() for async tools. Calls run one at a time, in order."""
        return await self.gate.arun_all(response)

    # -- dry-run + reporting -------------------------------------------------

    @property
    def dry_run(self) -> bool:
        return self.gate.dry_run

    @dry_run.setter
    def dry_run(self, value: bool) -> None:
        self.gate.dry_run = value

    def report(self) -> dict[str, Any]:
        return self.gate.report()

    def export(self, json_path: str, csv_path: str | None = None) -> dict[str, Any]:
        if self.gate.meter is None:
            raise ValueError("no audit meter attached (ToolWall was built with audit=False)")
        return self.gate.meter.export(json_path, csv_path)

    @property
    def meter(self) -> Meter | None:
        return self.gate.meter
