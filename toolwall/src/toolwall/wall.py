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
from dataclasses import dataclass
from typing import Any, Literal

from toolwall import context as _context
from toolwall.approvals import Approvals, TicketError
from toolwall.gate import ApprovalHandler, DefaultMode, Gate, GateResult, Verdict
from toolwall._aio import is_async_callable
from toolwall.intake import ToolCall
from toolwall.meter import Meter
from toolwall.policy import Policy
from toolwall.schema import ToolSchema, infer_schema_if_annotated
from toolwall.shield import Shield

ToolFn = Callable[..., Any]


@dataclass(frozen=True)
class Decision:
    """decide()'s answer for a tool call your framework will run itself.

    verdict: "allow" (run it, with `args`), "deny" (don't), or "ask" (a person
    must approve first). `reason` is safe to show the model; `detail` is the full
    reason for your logs (secrets scrubbed). `args` are the arguments as checked,
    redacted if the wall redacts secrets: run these, not the originals. `ticket`
    is the approval ticket for an "ask" (approve it with wall.approvals), or the
    ticket an "allow" used up.
    """

    verdict: Literal["allow", "deny", "ask"]
    tool: str
    args: dict[str, Any]
    reason: str | None = None
    detail: str | None = None
    receipt: str | None = None
    ticket: str | None = None

    @property
    def allowed(self) -> bool:
        return self.verdict == "allow"

    @property
    def denied(self) -> bool:
        return self.verdict == "deny"

    @property
    def needs_approval(self) -> bool:
        return self.verdict == "ask"


@dataclass(frozen=True)
class OutputCheck:
    """check_output()'s answer for what a tool returned.

    `value` is what may go back to the model: the original, a redacted copy, or
    None when it was withheld. `reason` is safe to show the model.
    """

    value: Any
    withheld: bool
    reason: str | None = None
    detail: str | None = None


class ToolBlocked(Exception):
    """Raised by @wall.protect when the wall blocks or holds a call. Its message is
    the model-safe reason; `ticket` is the approval ticket for a held call."""

    ticket: str | None = None


def _bind(fn: ToolFn, args: tuple, kwargs: dict[str, Any]) -> dict[str, Any]:
    import inspect

    bound = inspect.signature(fn).bind(*args, **kwargs)
    bound.apply_defaults()
    return dict(bound.arguments)


def _decide_only(name: str) -> ToolFn:
    # execute() refuses these unless a forwarder is given (MCPGuard forwards to the
    # server that really runs the tool, after the full check), so this never runs.
    def run(**_: Any) -> Any:
        raise RuntimeError(f"{name!r} is declared for decide() only")

    run.__toolwall_decide_only__ = True  # type: ignore[attr-defined]
    return run


class ToolWall:
    """Fail-closed security gateway for AI agent tool calls.

    Args:
        default: "deny" (a registered tool needs a schema, given or inferred from a
            fully annotated signature) or "allow".
        detect_secrets: attach a Shield. True blocks secrets in tool args;
            pass redact=True to replace them with placeholders instead.
        redact: if detecting secrets, redact instead of block.
        audit: attach a Meter so every verdict is recorded and exportable.
        approval: handler called when a tool needs approval; return True to run.
        approvals: where approval tickets are kept (toolwall.approvals.Approvals);
            a ticket per held call, in memory, by default. approvals=False turns
            tickets off.
    """

    def __init__(
        self,
        *,
        default: DefaultMode = "deny",
        detect_secrets: bool = True,
        redact: bool = False,
        audit: bool = True,
        approval: ApprovalHandler | None = None,
        approvals: Approvals | Literal[False] | None = None,
    ):
        shield = Shield(mode="redact" if redact else "block") if detect_secrets else None
        meter = Meter() if audit else None
        self.gate = Gate(default=default, meter=meter, shield=shield, approval=approval)
        self.approvals: Approvals | None = (
            None if approvals is False else approvals if approvals is not None else Approvals()
        )
        self.gate.tickets = self.approvals

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
        annotated gets its schema from its signature: required args, types, no
        unknown args. Supported annotations are classes, X | None, Optional and
        Union of classes, generic containers (list[str] checks for a list), Any and
        Annotated[...]; float also accepts int. Anything less (a lambda, a partly
        annotated function, Literal) still needs a schema: under default deny it is
        blocked until it has one. infer_schema=False opts out.
        """
        if infer_schema is None:
            infer_schema = False
            if schema is None:
                schema = infer_schema_if_annotated(fn)  # None unless fully annotated
        self.gate.register(
            name, fn, schema, policy=policy, infer_schema=infer_schema, replace=replace
        )
        return self

    def rule(
        self,
        name: str,
        *,
        schema: ToolSchema | None = None,
        ask_if: Callable[[dict[str, Any]], bool] | None = None,
        cross: Any = None,
        require_approval: bool = False,
        **constraints: Callable[[Any], bool],
    ) -> "ToolWall":
        """Set the policy for a tool in one line: argument rules as keywords.

            wall.rule("issue_refund", amount=r.at_most(500), ask_if=r.over("amount", 200))

        Replaces any earlier policy for the tool; a registered tool keeps its
        function and schema (pass schema= to replace it). For a tool your framework
        runs, there is no function to register: give schema= and the tool is
        declared for decide() only.
        """
        policy = Policy(
            constraints=dict(constraints), cross=cross,
            require_approval=require_approval, ask_if=ask_if,
        )
        registry = self.gate.registry
        if registry.get(name) is None:
            if schema is None:
                raise ValueError(
                    f"{name!r} is not registered. Register its function first, or pass "
                    "schema= to declare a tool your framework runs (decide() only)."
                )
            self.gate.register(name, _decide_only(name), schema, policy=policy)
        else:
            registry.set_policy(name, policy)
            if schema is not None:
                registry.set_schema(name, schema)
        return self

    def context(self, **values: Any) -> _context.context:
        """`with wall.context(customer_id="c_42"):` makes values visible to rules
        evaluated in this thread or task only (async-safe, nestable)."""
        return _context.context(**values)

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

    def run_approved(self, ticket_id: str) -> GateResult:
        """Run the call an approved ticket holds: its arguments, in its context,
        once. Every other check runs again first (rules see the ticket's context;
        a rule that now fails still blocks). Raises TicketError when the ticket
        isn't approved, has expired or was already used."""
        ticket = self._approved_ticket(ticket_id, sync=True)
        with _context.exactly(**ticket.context):
            return self.call(ticket.tool, ticket.args)

    async def arun_approved(self, ticket_id: str) -> GateResult:
        """run_approved() for async tools."""
        ticket = self._approved_ticket(ticket_id, sync=False)
        with _context.exactly(**ticket.context):
            return await self.acall(ticket.tool, ticket.args)

    def _approved_ticket(self, ticket_id: str, *, sync: bool) -> Any:
        if self.approvals is None:
            raise TicketError("approval tickets are off for this wall")
        ticket = self.approvals.get(ticket_id)
        if ticket is None:
            raise TicketError(f"no ticket {ticket_id!r}")
        if ticket.status != "approved":
            raise TicketError(f"ticket {ticket_id!r} is {ticket.status}, not approved")
        if not self.approvals._intact(ticket, ticket.digest):
            raise TicketError(f"ticket {ticket_id!r} was changed after it was opened")
        # Refuse here what execute would refuse after the ticket is used up.
        tool = self.gate.registry.get(ticket.tool)
        if tool is None or getattr(tool, "__toolwall_decide_only__", False):
            raise TicketError(f"{ticket.tool!r} isn't run by this wall: approve it, and let "
                              "the framework retry the call")
        if sync and is_async_callable(tool):
            raise TicketError(f"{ticket.tool!r} is async: use arun_approved()")
        if self.gate.dry_run:
            raise TicketError("the wall is in dry-run mode: nothing runs")
        return ticket

    def decide(self, name: str, args: dict[str, Any] | None = None) -> Decision:
        """Verdict for a call your framework will run itself: allow, deny or ask.

        Every check call() makes applies (allowlist, schema, rules with the current
        context, secrets, budget, approval). An "allow" takes a budget slot, since
        the framework is about to run it. Nothing is executed here.
        """
        return self._decide(name, args, reserve=True)

    def take_slot(self, decision: Decision) -> Decision:
        """Take the budget slot for a call a person approved after decide() said
        "ask". Returns the same decision as "allow", or "deny" when the budget is
        spent. Adapters call this once the framework's approval says yes.
        Any other decision comes back unchanged: a "deny" stays denied."""
        if decision.verdict != "ask":
            return decision
        if decision.ticket is not None and self.approvals is not None:
            # The person approved through the framework: close the ticket so the
            # queue can't approve and run the same call a second time.
            if not self.approvals.close(decision.ticket, "used"):
                ticket = self.approvals.get(decision.ticket)
                if ticket is not None and ticket.status in ("used", "denied"):
                    reason = f"approval ticket is already {ticket.status}"
                    return Decision("deny", decision.tool, decision.args,
                                    "This call was already handled.", reason,
                                    decision.receipt, decision.ticket)
        call = ToolCall(name=decision.tool, args=dict(decision.args))
        reason = self.gate._reserve_budget(call)
        if reason is None:
            return Decision("allow", decision.tool, decision.args, None, decision.detail,
                            decision.receipt, decision.ticket)
        probe = GateResult(Verdict.BLOCK, call, [reason], kind="budget")
        self.gate._record(probe)
        return Decision("deny", decision.tool, decision.args, probe.model_reason, reason,
                        decision.receipt, decision.ticket)

    def decline(self, decision: Decision, *, by: str = "framework") -> None:
        """A person declined a held call through the framework: deny its ticket,
        so it can't be approved and run later from the queue."""
        if decision.ticket is not None and self.approvals is not None:
            self.approvals.close(decision.ticket, "denied", by=by)

    def _decide(self, name: str, args: dict[str, Any] | None, *, reserve: bool) -> Decision:
        result = self.gate.check({"name": name, "args": args or {}})
        # The gate isn't going to run this result, so it must not hold an issue record.
        self.gate._issued.pop(id(result), None)
        ticket_id: str | None = None
        if result.needs_approval and self.approvals is not None and result.call is not None:
            result, ticket_id = self._decide_ticket(result, reserve=reserve)
        elif result.allowed and reserve:
            budget_reason = self.gate._reserve_budget(result.call)
            if budget_reason is not None:
                result = self.gate._refuse(result, budget_reason, kind="budget")
        verdict: Literal["allow", "deny", "ask"] = (
            "allow" if result.allowed else "ask" if result.needs_approval else "deny"
        )
        return Decision(
            verdict=verdict,
            tool=name,
            args=dict(result.call.args) if result.call is not None else dict(args or {}),
            reason=result.model_reason,
            detail="; ".join(result.reasons) or None,
            receipt=result.receipt,
            ticket=ticket_id,
        )

    def _decide_ticket(self, result: GateResult, *, reserve: bool) -> tuple[GateResult, str | None]:
        """A held call and its ticket: an approved ticket for exactly this call and
        context lets it run (used up only when reserve=True; a probe just looks), a
        denied one declines it, and otherwise the call waits on a pending ticket."""
        assert self.approvals is not None and result.call is not None
        ctx = dict(_context.current())
        try:
            ticket = self.approvals.lookup(result.call.name, result.call.args, ctx)
        except TicketError:
            return result, None  # can't be bound to a ticket: held, no ticket
        if ticket is not None and ticket.status == "approved":
            if not reserve:
                return self._granted(result), ticket.id
            budget_reason = self.gate._reserve_budget(result.call)
            if budget_reason is not None:
                return self.gate._refuse(result, budget_reason, kind="budget"), ticket.id
            if self.approvals.redeem(ticket):
                granted = self._granted(result)
                self.gate._record_transition(granted, "approval-granted")
                return granted, ticket.id
            ticket = None  # used up meanwhile: this call needs a new approval
        if ticket is not None and ticket.status == "denied":
            declined = self.gate._refuse(result, "approval denied", kind="approval_denied")
            return declined, ticket.id
        if ticket is None:
            try:
                ticket = self.approvals.open(result.call.name, result.call.args, ctx,
                                             "; ".join(result.reasons) or None)
            except TicketError:
                return result, None
        return result, ticket.id

    @staticmethod
    def _granted(result: GateResult) -> GateResult:
        import copy

        granted = copy.copy(result)
        granted.verdict = Verdict.ALLOW
        granted.reasons = []
        return granted

    async def adecide(self, name: str, args: dict[str, Any] | None = None) -> Decision:
        """decide() for async code. Rules are synchronous, so this does not await them."""
        return self.decide(name, args)

    def check_output(self, name: str, value: Any) -> OutputCheck:
        """Scan what a tool your framework ran returned, before the model sees it."""
        probe = GateResult(Verdict.ALLOW, ToolCall(name=name, args={}))
        self.gate._accept_output(probe, value)
        withheld = probe.return_value is None and value is not None and probe.error is not None
        if self.gate.meter is not None:
            from toolwall.meter import RunEvent

            self.gate.meter.record(RunEvent(
                lane=self.gate.lane, kind="output", ok=not withheld,
                namespace=self.gate._scrub(name), error=self.gate._scrub(probe.error),
                meta={"findings": [f.kind for f in probe.findings]},
            ))
        return OutputCheck(
            value=probe.return_value,
            withheld=withheld,
            reason=("The tool's output was withheld because it contained what looks "
                    "like a secret or couldn't be checked.") if withheld else None,
            detail=probe.error,
        )

    def protect(self, fn: ToolFn | None = None, *, name: str | None = None,
                error: Callable[[str], BaseException] | None = None) -> Any:
        """Decorator: every call to the function goes through the wall.

            @wall.protect
            async def issue_refund(order_id: str, amount: float) -> str: ...

        Registers the function (schema inferred from its annotations unless the
        tool is already registered) and replaces it with a wrapper of the same
        signature, so frameworks that read the signature (MCP servers, function
        tools) still can. A blocked or held call raises ToolBlocked, or the
        exception `error(model_reason)` returns.
        """
        import functools

        def wrap(f: ToolFn) -> ToolFn:
            tool = name or f.__name__
            registry = self.gate.registry
            existing = registry.get(tool)
            if existing is None:
                self.register(tool, f)
            elif existing is not f and not getattr(existing, "__toolwall_decide_only__", False):
                raise ValueError(
                    f"{tool!r} is already registered with another function; "
                    "protect would run that one, not this"
                )
            elif getattr(existing, "__toolwall_decide_only__", False):
                # Declared with wall.rule(schema=...): attach the function, keep
                # the declared schema and rules.
                self.gate.register(tool, f, registry.get_schema(tool),
                                   policy=registry.get_policy(tool), replace=True)
            make_error = error or ToolBlocked

            def outcome(result: GateResult) -> Any:
                if not result.allowed or result.error is not None:
                    exc = make_error(result.model_reason or "This call can't be run.")
                    try:
                        exc.ticket = result.ticket  # type: ignore[attr-defined]
                    except AttributeError:
                        pass
                    raise exc
                return result.return_value

            if is_async_callable(f):
                @functools.wraps(f)
                async def guarded_async(*args: Any, **kwargs: Any) -> Any:
                    bound = _bind(f, args, kwargs)
                    return outcome(await self.acall(tool, bound))
                return guarded_async

            @functools.wraps(f)
            def guarded(*args: Any, **kwargs: Any) -> Any:
                bound = _bind(f, args, kwargs)
                return outcome(self.call(tool, bound))
            return guarded

        return wrap(fn) if fn is not None else wrap

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
