"""toolwall: fail-closed checkpoint between LLM tool calls and execution.

    gate = Gate(default="deny", meter=meter, shield=Shield(mode="block"))
    gate.register("db_query", db_query,
                  schema=ToolSchema(required=["q"]),
                  policy=Policy(constraints={"limit": in_range(1, 100)}))
    gate.budget(max_calls=20)
    result = gate.run(openai_response)   # check + execute only if allowed

Check order (first failure blocks, fail-closed):
  intake -> known tool -> budget -> schema -> policy -> shield -> approval
"""

from __future__ import annotations

import copy
import inspect
import re
import threading
import weakref
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Literal

from toolwall._aio import discard_awaitable, is_async_callable
from toolwall.context import current as current_context
from toolwall.intake import IntakeError, ToolCall, parse_tool_calls
from toolwall.meter import Meter, RunEvent
from toolwall.policy import Policy
from toolwall.receipt import ReceiptError, fingerprint
from toolwall.schema import ToolSchema, schema_from_signature
from toolwall.shield import Finding, Shield, UnscannableError, scrub_text

ToolFn = Callable[..., Any]
DefaultMode = Literal["deny", "allow"]
ApprovalHandler = Callable[["GateResult"], bool]


_SAFE_ARG = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,39}")


class Verdict(str, Enum):
    ALLOW = "allow"
    BLOCK = "block"
    NEEDS_APPROVAL = "needs_approval"


@dataclass
class ToolRegistry:
    """Maps tool names to callables (+ optional schema and policy).

    Registration is the allowlist: unregistered tools always block.
    """

    _tools: dict[str, ToolFn] = field(default_factory=dict)
    _schemas: dict[str, ToolSchema] = field(default_factory=dict)
    _policies: dict[str, Policy] = field(default_factory=dict)
    _unreceipted: set[str] = field(default_factory=set)

    def register(
        self,
        name: str,
        fn: ToolFn,
        schema: ToolSchema | None = None,
        *,
        policy: Policy | None = None,
        infer_schema: bool = False,
        replace: bool = False,
        receipt: bool = True,
    ) -> None:
        """Register a tool. This registry IS the allowlist.

        Re-registering an existing name raises unless replace=True, so a stray
        second registration cannot silently swap out a tool (or drop its policy)
        behind an already-audited allowlist.
        """
        if name in self._tools and not replace:
            raise ValueError(
                f"tool {name!r} is already registered; pass replace=True to override it "
                "(re-registering silently would change what the allowlist permits)"
            )
        # A replace is a full re-registration: drop the old schema/policy so a
        # new tool can never inherit constraints written for the previous one.
        self._schemas.pop(name, None)
        self._policies.pop(name, None)
        self._unreceipted.discard(name)
        self._tools[name] = fn
        if not receipt:
            self._unreceipted.add(name)
        if schema is not None:
            self._schemas[name] = schema
        elif infer_schema:
            self._schemas[name] = schema_from_signature(fn)
        if policy is not None:
            self._policies[name] = policy

    def set_policy(self, name: str, policy: Policy | None) -> None:
        if name not in self._tools:
            raise KeyError(name)
        if policy is None:
            self._policies.pop(name, None)
        else:
            self._policies[name] = policy

    def set_schema(self, name: str, schema: ToolSchema) -> None:
        if name not in self._tools:
            raise KeyError(name)
        self._schemas[name] = schema

    def get(self, name: str) -> ToolFn | None:
        return self._tools.get(name)

    def get_schema(self, name: str) -> ToolSchema | None:
        return self._schemas.get(name)

    def get_policy(self, name: str) -> Policy | None:
        return self._policies.get(name)

    def wants_receipt(self, name: str) -> bool:
        return name not in self._unreceipted

    def names(self) -> list[str]:
        return list(self._tools.keys())


@dataclass
class GateResult:
    verdict: Verdict
    call: ToolCall | None = None
    reasons: list[str] = field(default_factory=list)
    executed: bool = False
    return_value: Any = None
    error: str | None = None
    findings: list[Finding] = field(default_factory=list)  # shield hits (value-free)
    dry_run: bool = False  # True when the gate simulated execution
    receipt: str | None = None  # fingerprint of (tool name, args) bound at check time
    receipt_spent: bool = False  # one verdict authorises one execution, not a stream
    kind: str | None = None  # why it was blocked or held; drives model_reason
    arg: str | None = None  # the argument a schema/policy block was about, if one
    ticket: str | None = None  # approval ticket for a held call, when one was opened

    @property
    def model_reason(self) -> str | None:
        """A short reason that is safe to send back to the model.

        It says what kind of thing went wrong and, for argument problems, which
        argument, but never the rule, the allowlist or the value: a model that
        is being steered by injected text should not learn how to get past the
        policy. The full reason stays in `reasons` and the audit log.
        """
        if self.verdict is Verdict.ALLOW and self.error is None:
            return None
        if self.verdict is Verdict.NEEDS_APPROVAL:
            return "This call needs approval from a person before it can run."
        # Echo the argument's name only when it looks like a plain identifier: the
        # model chose it, and a long, multi-line or control-character name would
        # carry injected text back into the conversation.
        if self.arg and _SAFE_ARG.fullmatch(self.arg):
            where = f" '{self.arg}'"
        elif self.arg:
            where = " an argument"
        else:
            where = ""
        messages = {
            "unknown_tool": "This tool is not available.",
            "schema": f"The arguments don't match what this tool accepts{(' (check' + where + ')') if where else ''}.",
            "policy": (f"The value for{where} isn't allowed for this call." if where
                       else "This call isn't allowed by policy."),
            "secret": "The arguments contain what looks like a secret. Remove it and try again.",  # nosec B105
            "budget": "The limit for calls to this tool has been reached.",
            "approval_denied": "A person declined this call.",
            "decide_only": "This call can't be run here.",
        }
        if self.verdict is Verdict.ALLOW:  # ran, but its output was withheld or it failed
            return "The tool ran, but its output can't be shown."
        return messages.get(self.kind or "", "This call can't be run.")

    @property
    def allowed(self) -> bool:
        return self.verdict is Verdict.ALLOW

    @property
    def blocked(self) -> bool:
        return self.verdict is Verdict.BLOCK

    @property
    def needs_approval(self) -> bool:
        return self.verdict is Verdict.NEEDS_APPROVAL

    @property
    def reason(self) -> str | None:
        """First human-readable reason for a block/hold, or None when allowed."""
        return self.reasons[0] if self.reasons else None


class Gate:
    """Fail-closed gate.

    default="deny"  -> a registered tool with NO schema is still blocked
    default="allow" -> schema optional; registered tool without schema passes

    approval: optional handler called by run()/run_all() when a policy demands
    approval. Returns True to execute. Without a handler, NEEDS_APPROVAL calls
    are never executed (fail closed).
    """

    def __init__(
        self,
        registry: ToolRegistry | None = None,
        *,
        default: DefaultMode = "deny",
        meter: Meter | None = None,
        shield: Shield | None = None,
        approval: ApprovalHandler | None = None,
        dry_run: bool = False,
        lane: str = "gate",
    ):
        if default not in ("deny", "allow"):
            raise ValueError(f"default must be 'deny' or 'allow', got {default!r}")
        self.registry = registry or ToolRegistry()
        self.default = default
        self.meter = meter
        self.shield = shield
        self.approval = approval
        # Approval tickets (toolwall.approvals), set by ToolWall: an approved
        # ticket for exactly this call grants it; a held call nobody can approve
        # now gets a pending ticket.
        self.tickets: Any = None
        self.dry_run = dry_run
        self.lane = lane
        self.history: list[GateResult] = []  # every checked result, for reports/suggest
        self._lock = threading.Lock()
        self._budget: dict[str, Any] = {}
        self._executed_calls = 0
        self._executed_per_tool: dict[str, int] = {}
        # Results this gate issued and has not run yet: id -> [weakref to result,
        # tool name, receipt, runnable]. execute() trusts this, not the mutable
        # fields on the result. An entry is spent when used, dropped when an approval
        # is denied, and freed with its result (weak reference), so clearing history
        # releases it.
        self._issued: dict[int, list[Any]] = {}

    def register(
        self,
        name: str,
        fn: ToolFn,
        schema: ToolSchema | None = None,
        *,
        policy: Policy | None = None,
        infer_schema: bool = False,
        replace: bool = False,
        receipt: bool = True,
    ) -> None:
        self.registry.register(
            name, fn, schema, policy=policy, infer_schema=infer_schema,
            replace=replace, receipt=receipt,
        )

    # -- budget ---------------------------------------------------------------

    def budget(
        self,
        *,
        max_calls: int | None = None,
        max_calls_per_tool: int | None = None,
        max_usd: float | None = None,
    ) -> None:
        if max_usd is not None and self.meter is None:
            raise ValueError("max_usd budget requires a meter (cost is meter-derived)")
        # Validate here, not at check time. A wrong type used to survive this call and
        # surface later as a TypeError raised out of check(), and an exception escaping
        # the gate is not a verdict: the caller's error handling decides what happens.
        for field_name, value, kinds, label in (
            ("max_calls", max_calls, (int,), "an int"),
            ("max_calls_per_tool", max_calls_per_tool, (int,), "an int"),
            ("max_usd", max_usd, (int, float), "a number"),
        ):
            if value is None:
                continue
            if isinstance(value, bool) or not isinstance(value, kinds):
                raise TypeError(
                    f"budget: {field_name} must be {label} or None, "
                    f"got {type(value).__name__}. Budgets apply to every tool; "
                    f"for per-tool limits use a separate Gate."
                )
            if value < 0:
                raise ValueError(f"budget: {field_name} must not be negative, got {value!r}")
        self._budget = {
            "max_calls": max_calls,
            "max_calls_per_tool": max_calls_per_tool,
            "max_usd": max_usd,
        }

    def _budget_violation(self, call: ToolCall) -> str | None:
        """Read budget counters under the lock.

        This is the early, advisory check. execute() re-checks and reserves the
        slot atomically, so a Gate shared across threads still never exceeds a
        budget; calls that lose the race are refused at execute time.
        """
        if not self._budget:
            return None
        with self._lock:
            return self._budget_violation_locked(call)

    def _budget_violation_locked(self, call: ToolCall) -> str | None:
        max_calls = self._budget.get("max_calls")
        if max_calls is not None and self._executed_calls >= max_calls:
            return f"budget exceeded: max_calls={max_calls} already executed"
        per_tool = self._budget.get("max_calls_per_tool")
        if per_tool is not None and self._executed_per_tool.get(call.name, 0) >= per_tool:
            return f"budget exceeded: max_calls_per_tool={per_tool} for {call.name!r}"
        max_usd = self._budget.get("max_usd")
        if max_usd is not None and self.meter is not None:
            spent = self.meter.report.estimate_cost_usd(self.lane)
            if spent >= max_usd:
                return f"budget exceeded: estimated ${spent:.4f} >= max_usd={max_usd}"
        return None

    # -- checking ---------------------------------------------------------------

    def check_all(self, payload: Any) -> list[GateResult]:
        """Check every tool call in a payload without executing anything.

        Budget caution: all calls are checked against the *current* counters, so
        with N parallel calls every one of them sees the same budget state. If
        you then execute them yourself, you can exceed a budget. Use run_all(),
        which checks and executes one call at a time so counters advance.
        """
        try:
            calls = parse_tool_calls(payload)
        except IntakeError as exc:
            return [self._record(GateResult(Verdict.BLOCK, reasons=[f"intake: {exc}"]))]
        if not calls:
            return [self._record(GateResult(Verdict.BLOCK, reasons=["intake: no tool calls in payload"]))]
        return [self._check_one(call) for call in calls]

    def check(self, payload: Any) -> GateResult:
        results = self.check_all(payload)
        if len(results) != 1:
            raise ValueError(f"expected exactly 1 tool call, got {len(results)}; use check_all()")
        return results[0]

    def _check_one(self, call: ToolCall) -> GateResult:
        # Anything that raises while deciding is a BLOCK, not an exception for the
        # caller's error handling to interpret (deep nesting, hostile objects).
        try:
            return self._check_one_unguarded(call)
        except Exception as exc:
            return self._record(
                GateResult(Verdict.BLOCK, call, [f"gate could not check the call ({type(exc).__name__}): fails closed"])
            )

    def _check_one_unguarded(self, call: ToolCall) -> GateResult:
        # Take our own copy before anything is validated. The caller still holds a
        # reference to the dict it handed in, and without this it could edit the
        # arguments after the verdict and before execution.
        try:
            call.args = copy.deepcopy(call.args)
        except Exception:  # nosec B110
            # Uncopyable arguments are left as-is; the receipt below is then the
            # only thing standing between check and execute, and it is required.
            pass

        if self.registry.get(call.name) is None:
            return self._record(GateResult(Verdict.BLOCK, call, [f"unknown tool: {call.name!r}"], kind="unknown_tool"))

        budget_reason = self._budget_violation(call)
        if budget_reason is not None:
            return self._record(GateResult(Verdict.BLOCK, call, [budget_reason], kind="budget"))

        schema = self.registry.get_schema(call.name)
        if schema is None:
            if self.default == "deny":
                return self._record(
                    GateResult(
                        Verdict.BLOCK,
                        call,
                        [f"no schema registered for {call.name!r} and gate default is deny"],
                        kind="unknown_tool",
                    )
                )
        else:
            errors = schema.validate(call.args)
            if errors:
                bad = _first_arg_named(errors, call.args, schema)
                return self._record(GateResult(Verdict.BLOCK, call, errors, kind="schema", arg=bad))

        policy = self.registry.get_policy(call.name)
        if policy is not None:
            violations = policy.violations(call.args)
            if violations:
                return self._record(GateResult(
                    Verdict.BLOCK, call, [message for _, message in violations],
                    kind="policy", arg=violations[0][0],
                ))

        findings: list[Finding] = []
        if self.shield is not None:
            if self.shield.mode == "redact":
                call.args, findings = self.shield.redact_args(call.args)
            else:
                findings = self.shield.scan_args(call.args)
                if findings and self.shield.mode == "block":
                    reasons = [
                        f"secret detected ({f.kind}) in arg {f.arg!r}" for f in findings
                    ]
                    return self._record(
                        GateResult(Verdict.BLOCK, call, reasons, findings=findings, kind="secret")
                    )

        # Bind the receipt last, over the arguments as they will be executed
        # (the shield may have redacted them above).
        try:
            receipt = fingerprint(call.name, call.args)
        except ReceiptError as exc:
            if self.registry.wants_receipt(call.name):
                return self._record(
                    GateResult(Verdict.BLOCK, call, [f"cannot bind receipt: {exc}"], kind="receipt")
                )
            receipt = None

        wants_approval = policy.wants_approval(call.args) if policy is not None else False
        if isinstance(wants_approval, str):  # ask_if couldn't be evaluated: fail closed
            return self._record(GateResult(Verdict.BLOCK, call, [wants_approval], kind="policy"))
        if wants_approval:
            return self._record(
                GateResult(
                    Verdict.NEEDS_APPROVAL,
                    call,
                    [f"approval required for {call.name!r}"],
                    findings=findings,
                    receipt=receipt,
                    kind="approval",
                )
            )

        return self._record(
            GateResult(Verdict.ALLOW, call, findings=findings, receipt=receipt)
        )

    # -- execution ----------------------------------------------------------------

    def execute(
        self, result: GateResult, invoke: Callable[[dict[str, Any]], Any] | None = None
    ) -> GateResult:
        """Run an ALLOW result: receipt check, budget, dry-run, tool, output scan.

        invoke: optional callable that receives the verified arguments instead of
        the registered tool being called with them (MCPGuard forwards to a
        downstream server this way). Everything else applies unchanged; the tool
        must still be registered, because registration is the allowlist.

        Synchronous. An async tool is refused here, before any budget is spent, and
        an awaitable returned by a sync callable is withheld: neither has run, and
        neither has an output the shield could scan. Use aexecute()/arun() for them.
        """
        admitted = self._admit(result, invoke, sync=True)
        if isinstance(admitted, GateResult):
            return admitted
        target, args = admitted
        try:
            value = target(args)
        except Exception as exc:
            result.error = self._scan_error_text(f"{type(exc).__name__}: {exc}", type(exc).__name__)
        except BaseException as exc:  # KeyboardInterrupt and friends: audit, then re-raise
            result.error = f"cancelled ({type(exc).__name__}) after the tool started"
            self._record_tool(result, invoke)
            raise
        else:
            if inspect.isawaitable(value):
                discard_awaitable(value)
                result.error = (
                    "tool returned an awaitable that was not awaited, so it did not run; "
                    "call it with acall() / arun()"
                )
            else:
                self._accept_output(result, value)
        return self._record_tool(result, invoke)

    async def aexecute(
        self, result: GateResult, invoke: Callable[[dict[str, Any]], Any] | None = None
    ) -> GateResult:
        """execute() for async tools and forwards: awaits, then scans the output.

        Every check is shared with execute(); only the call itself differs. Sync
        tools run inline (not in a thread), exactly as they do in execute().
        """
        admitted = self._admit(result, invoke, sync=False)
        if isinstance(admitted, GateResult):
            return admitted
        target, args = admitted
        try:
            value = target(args)
            if inspect.isawaitable(value):
                value = await value
        except Exception as exc:
            result.error = self._scan_error_text(f"{type(exc).__name__}: {exc}", type(exc).__name__)
        except BaseException as exc:
            # Cancelled (or interrupted) after the tool started: its side effects may
            # have happened. Record that in the audit, keep the spent budget, re-raise.
            result.error = f"cancelled ({type(exc).__name__}) after the tool started"
            self._record_tool(result, invoke)
            raise
        else:
            if inspect.isawaitable(value):  # an awaitable that resolved to another one
                discard_awaitable(value)
                result.error = "tool output withheld: output could not be scanned (awaitable)"
            else:
                self._accept_output(result, value)
        return self._record_tool(result, invoke)

    def _admit(
        self, result: GateResult, invoke: Callable[[dict[str, Any]], Any] | None, *, sync: bool
    ) -> GateResult | tuple[Callable[[dict[str, Any]], Any], dict[str, Any]]:
        """Every check between an ALLOW and the call. Returns the call to make, or
        the final result when the call must not happen (refused, dry run)."""
        if not result.allowed or result.call is None:
            joined = "; ".join(result.reasons) or "no call"
            raise PermissionError(f"refusing to execute a {result.verdict.value} result: {joined}")

        # One verdict authorises one execution of the call it was issued for. The
        # issue record is taken (and so spent) under the lock: two threads handing in
        # the same result cannot both get it. A result the gate never issued, or one
        # already used, does not run.
        with self._lock:
            issued = self._issued.pop(id(result), None)
        if issued is None or issued[0]() is not result or not issued[3]:
            return self._refuse(
                result,
                "receipt already spent, or this result was not issued by this gate as "
                "runnable (a held call needs a granted approval); re-check the call "
                "instead of replaying an approved result",
            )
        _, checked_name, receipt, _ = issued

        # Code holding the result (an approval handler included) can edit it. The
        # tool, and for receipted tools the arguments, must be what was checked.
        if result.call.name != checked_name:
            return self._refuse(
                result, "tool changed between check and execute; refusing to run it"
            )

        execute_args = result.call.args  # unreceipted opt-out runs the live args
        if receipt is None and self.registry.wants_receipt(checked_name):
            return self._refuse(
                result, "no receipt bound to this result; re-check the call before running it"
            )

        # The verdict was about specific arguments. If they are not the arguments we
        # are about to run, the verdict does not apply to this call. Refuse, and do
        # not spend budget on it.
        if receipt is not None:
            # Freeze first, then hash the frozen copy, then run the tool on that same
            # frozen copy. Hashing the live object and then passing the live object
            # would leave a window after the hash passes in which another thread can
            # still mutate what the tool reads: the receipt would prove the past, not
            # the call. The tool must only ever see the snapshot that was verified.
            try:
                frozen_args = copy.deepcopy(result.call.args)
                current = fingerprint(checked_name, frozen_args)
            except Exception as exc:  # ReceiptError or a failed copy: refuse either way
                current = f"unverifiable: {exc}"
            if current != receipt:
                return self._refuse(
                    result,
                    "arguments changed between check and execute; refusing to run "
                    "a call the gate did not approve",
                )
            result.receipt_spent = True
            # The snapshot must never be reachable through the result object, or a
            # thread holding the result could mutate what the tool is reading. The
            # result keeps the checked args; the hash just proved the two identical.
            execute_args = frozen_args

        tool = self.registry.get(result.call.name)
        if getattr(tool, "__toolwall_decide_only__", False) and invoke is None:
            return self._refuse(
                result,
                f"{result.call.name!r} is declared for decide() only: your framework runs "
                "it, so the gate has nothing to call",
                kind="decide_only",
            )
        # Calling an async tool synchronously only creates a coroutine: the tool would
        # not run and its output could not be scanned. Refuse before spending budget.
        if sync and invoke is None and tool is not None and is_async_callable(tool):
            return self._refuse(
                result,
                f"{result.call.name!r} is an async tool; call it with acall() / arun() "
                "so it is awaited and its output scanned",
            )

        # Re-check the budget and reserve the slot in one critical section. The check
        # in check() is advisory: between it and here other threads sharing this Gate
        # may have executed, and without this a burst of parallel calls all pass a
        # max_calls=1 read at counter 0.
        budget_reason = self._reserve_budget(result.call)
        if budget_reason is not None:
            return self._refuse(result, budget_reason, kind="budget")
        if self.dry_run:
            result.dry_run = True
            if self.meter is not None:
                self.meter.record(
                    RunEvent(
                        lane=self.lane,
                        kind="tool",
                        ok=True,
                        namespace=result.call.name,
                        meta={"dry_run": True, "would_execute": True},
                    )
                )
            return result
        if tool is None:  # registry mutated between check and execute
            result.error = f"unknown tool at execute time: {result.call.name!r}"
            return self._record_tool(result, invoke)
        if invoke is not None:
            return invoke, execute_args
        return (lambda args: tool(**args)), execute_args

    def _reserve_budget(self, call: ToolCall) -> str | None:
        """Re-check the budget and take one slot in one critical section."""
        with self._lock:
            reason = self._budget_violation_locked(call) if self._budget else None
            if reason is None:
                self._executed_calls += 1
                self._executed_per_tool[call.name] = self._executed_per_tool.get(call.name, 0) + 1
        return reason

    def _accept_output(self, result: GateResult, value: Any) -> None:
        result.return_value = value
        result.executed = True
        try:
            self._scan_output(result)
        except Exception as exc:
            # Output we could not scan is output we cannot vouch for.
            result.return_value = None
            detail = str(exc) if isinstance(exc, UnscannableError) else type(exc).__name__
            result.error = self._scrub(
                f"tool output withheld: output could not be scanned ({detail})"
            )

    def _record_tool(
        self, result: GateResult, invoke: Callable[[dict[str, Any]], Any] | None
    ) -> GateResult:
        if self.meter is not None:
            self.meter.record(
                RunEvent(
                    lane=self.lane,
                    kind="tool",
                    ok=result.executed,
                    namespace=self._scrub(result.call.name),
                    error=self._scrub(result.error),
                    meta={"forwarded": True} if invoke is not None else {},
                )
            )
        return result

    def _refuse(self, result: GateResult, reason: str, kind: str = "refused") -> GateResult:
        """A refusal at execute time is a new BLOCK result, recorded like any other.

        The ALLOW it refuses stays as it was: rewriting it in place would make the
        history say a call that already ran was blocked.
        """
        refused = copy.copy(result)
        refused.verdict = Verdict.BLOCK
        refused.kind = kind
        refused.reasons = [*result.reasons, reason]
        refused.findings = list(result.findings)
        refused.executed = False
        refused.return_value = None
        return self._record(refused)

    def _scan_output(self, result: GateResult) -> None:
        """Scan what a tool returned before it travels back to the model.

        A tool can read a secret out of a database, a file, or an API response.
        Blocking it on the way in does nothing for that path, so the return value
        gets the same shield treatment: redact substitutes placeholders, block
        drops the value and marks the result, warn only records findings.
        """
        if self.shield is None or not getattr(self.shield, "scan_output", False):
            return
        value = result.return_value
        if value is None:
            return
        # A plain dict is scanned as-is so finding paths read return.<key>; anything
        # else (a dict subclass included) is wrapped so redaction can rebuild its type.
        plain = type(value) is dict
        payload = value if plain else {"return_value": value}
        if self.shield.mode == "redact":
            cleaned, findings = self.shield.redact_args(payload)
            if findings:
                result.return_value = cleaned if plain else cleaned["return_value"]
        else:
            findings = self.shield.scan_args(payload)
            if findings and self.shield.mode == "block":
                result.return_value = None
                where = self._scrub(f"return.{findings[0].arg}" if findings[0].arg else "return")
                result.error = (
                    f"tool output withheld: secret detected ({findings[0].kind}) in {where!r}"
                )
        for f in findings:
            # Paths are built from the output's own keys, which can be the secret.
            f.arg = self._scrub(f"return.{f.arg}" if f.arg else "return")
        result.findings.extend(findings)

    def _scan_error_text(self, message: str, exc_name: str) -> str:
        """A tool's exception text goes back to the model and into the audit log."""
        if self.shield is None or self.shield.mode == "warn":
            return message
        try:
            if self.shield.mode == "redact":
                cleaned, _ = self.shield.redact_text(message)
                return cleaned
            findings = self.shield.scan(message)
        except Exception:
            return f"{exc_name}: [message withheld: could not be scanned]"
        if findings:
            return f"{exc_name}: [message withheld: secret detected ({findings[0].kind})]"
        return message

    def _resolve_approval(self, result: GateResult) -> GateResult:
        """Called by run/run_all on NEEDS_APPROVAL. Fail closed without a handler.

        An async handler cannot be asked from here: its coroutine is truthy, and
        reading it as "granted" would approve every call. It is refused, closed.
        """
        ticketed = self._resolve_ticket(result)
        if ticketed is not None:
            return ticketed
        if self.approval is None:
            return self._approval_unavailable(result)
        try:
            granted = self.approval(result)
        except Exception as exc:
            return self._approval_failed(result, f"approval handler raised {type(exc).__name__}: fails closed")
        if inspect.isawaitable(granted):
            discard_awaitable(granted)
            return self._approval_failed(
                result, "approval handler is async; use acall() / arun() so it is awaited: fails closed"
            )
        return self._approval_decided(result, bool(granted))

    async def _aresolve_approval(self, result: GateResult) -> GateResult:
        """_resolve_approval() for the async path: an async handler is awaited."""
        ticketed = self._resolve_ticket(result)
        if ticketed is not None:
            return ticketed
        if self.approval is None:
            return self._approval_unavailable(result)
        try:
            granted = self.approval(result)
            if inspect.isawaitable(granted):
                granted = await granted
        except Exception as exc:
            return self._approval_failed(result, f"approval handler raised {type(exc).__name__}: fails closed")
        except BaseException:
            self._issued.pop(id(result), None)  # cancelled mid-approval: never runnable
            raise
        if inspect.isawaitable(granted):
            discard_awaitable(granted)
            return self._approval_failed(result, "approval handler returned an awaitable: fails closed")
        return self._approval_decided(result, bool(granted))

    def _resolve_ticket(self, result: GateResult) -> GateResult | None:
        """A held call with an approved ticket for exactly this call and context
        runs (once); one with a denied ticket is declined. None: no ticket says."""
        if self.tickets is None or result.call is None:
            return None
        from toolwall import context as _context
        from toolwall.approvals import TicketError

        try:
            ticket = self.tickets.lookup(result.call.name, result.call.args, dict(_context.current()))
        except TicketError:
            return None  # this call can't be bound to a ticket, so none can exist for it
        except Exception as exc:
            return self._approval_failed(result, f"approval ticket check raised {type(exc).__name__}: fails closed")
        if ticket is None:
            return None
        result.ticket = ticket.id
        if ticket.status == "denied":
            return self._approval_decided(result, False)
        if ticket.status == "approved":
            if self.tickets.redeem(ticket):
                return self._approval_decided(result, True)
            return self._approval_failed(result, "approval ticket was already used or expired")
        return None  # pending: ask the handler, or stay held

    def _approval_unavailable(self, result: GateResult) -> GateResult:
        # Nothing may run it now. With tickets, a person can approve it later:
        # the same call then runs once, through the ticket.
        self._issued.pop(id(result), None)
        if self.tickets is not None and result.call is not None and result.ticket is None:
            try:
                from toolwall import context as _context

                ticket = self.tickets.open(result.call.name, result.call.args,
                                           dict(_context.current()), "; ".join(result.reasons) or None)
                result.ticket = ticket.id
            except Exception:  # nosec B110
                pass  # can't be held for later: it stays held, with no ticket
        return result

    def _approval_failed(self, result: GateResult, reason: str) -> GateResult:
        self._issued.pop(id(result), None)
        result.verdict = Verdict.BLOCK
        result.reasons.append(reason)
        return self._record_transition(result, "approval-error")

    def _approval_decided(self, result: GateResult, granted: bool) -> GateResult:
        if granted:
            with self._lock:
                entry = self._issued.get(id(result))
                if entry is not None and entry[0]() is result:
                    entry[3] = True  # the only way a held call becomes runnable
            result.verdict = Verdict.ALLOW
            result.reasons = []
            return self._record_transition(result, "approval-granted")
        self._issued.pop(id(result), None)
        result.verdict = Verdict.BLOCK
        result.kind = "approval_denied"
        result.reasons.append("approval denied")
        return self._record_transition(result, "approval-denied")

    def run(self, payload: Any) -> GateResult:
        result = self.check(payload)
        if result.verdict is Verdict.NEEDS_APPROVAL:
            result = self._resolve_approval(result)
        if result.allowed:
            return self.execute(result)
        return result

    def run_all(self, payload: Any) -> list[GateResult]:
        # Check and execute each call in sequence, not check-all-then-execute-all.
        # Executing one call increments budget counters, so the next call's check
        # sees the updated state. Otherwise N parallel calls all pass a budget of
        # max_calls=1 (checked at counter 0) and then all execute.
        try:
            calls = parse_tool_calls(payload)
        except IntakeError as exc:
            return [self._record(GateResult(Verdict.BLOCK, reasons=[f"intake: {exc}"]))]
        if not calls:
            return [self._record(GateResult(Verdict.BLOCK, reasons=["intake: no tool calls in payload"]))]
        out: list[GateResult] = []
        for call in calls:
            result = self._check_one(call)
            if result.verdict is Verdict.NEEDS_APPROVAL:
                result = self._resolve_approval(result)
            out.append(self.execute(result) if result.allowed else result)
        return out

    async def arun(self, payload: Any) -> GateResult:
        """run() for async tools and async approval handlers."""
        result = self.check(payload)
        if result.verdict is Verdict.NEEDS_APPROVAL:
            result = await self._aresolve_approval(result)
        if result.allowed:
            return await self.aexecute(result)
        return result

    async def arun_all(self, payload: Any) -> list[GateResult]:
        """run_all() for async tools: calls run one after another, never at once,
        so each check sees the budget the previous call spent."""
        try:
            calls = parse_tool_calls(payload)
        except IntakeError as exc:
            return [self._record(GateResult(Verdict.BLOCK, reasons=[f"intake: {exc}"]))]
        if not calls:
            return [self._record(GateResult(Verdict.BLOCK, reasons=["intake: no tool calls in payload"]))]
        out: list[GateResult] = []
        for call in calls:
            result = self._check_one(call)
            if result.verdict is Verdict.NEEDS_APPROVAL:
                result = await self._aresolve_approval(result)
            out.append(await self.aexecute(result) if result.allowed else result)
        return out

    # -- reporting ----------------------------------------------------------------

    def report(self) -> dict[str, Any]:
        """Summary of everything this gate has seen. Useful after a dry run."""
        by_verdict: dict[str, int] = {}
        by_tool: dict[str, dict[str, int]] = {}
        blocked_reasons: list[str] = []
        finding_kinds: dict[str, int] = {}
        for r in self.history:
            by_verdict[r.verdict.value] = by_verdict.get(r.verdict.value, 0) + 1
            name = self._scrub(r.call.name) if r.call else "(unparsed)"
            tool_row = by_tool.setdefault(name, {"allow": 0, "block": 0, "needs_approval": 0})
            tool_row[r.verdict.value] = tool_row.get(r.verdict.value, 0) + 1
            if r.verdict is Verdict.BLOCK and r.reasons:
                blocked_reasons.append(f"{name}: {r.reasons[0]}")
            for f in r.findings:
                finding_kinds[f.kind] = finding_kinds.get(f.kind, 0) + 1
        return {
            "dry_run": self.dry_run,
            "calls_checked": len(self.history),
            "verdicts": by_verdict,
            "would_execute" if self.dry_run else "executed": self._executed_calls,
            "by_tool": by_tool,
            "blocked_reasons": blocked_reasons,
            "secret_findings_by_kind": finding_kinds,
        }

    # -- internals -------------------------------------------------------------------

    def _scrub(self, text: Any) -> Any:
        return scrub_text(text, self.shield)

    def _issue(self, result: GateResult) -> None:
        key = id(result)

        def forget(ref: "weakref.ref[GateResult]", key: int = key) -> None:
            # No lock: this can run from the garbage collector at any point, and
            # dict operations are atomic. Only drop the entry if it is still ours.
            entry = self._issued.get(key)
            if entry is not None and entry[0] is ref:
                self._issued.pop(key, None)

        runnable = result.verdict is Verdict.ALLOW  # held calls need a granted approval
        with self._lock:
            self._issued[key] = [weakref.ref(result, forget), result.call.name, result.receipt, runnable]

    def _record(self, result: GateResult) -> GateResult:
        if result.call is not None and result.verdict in (Verdict.ALLOW, Verdict.NEEDS_APPROVAL):
            self._issue(result)
        # Reasons echo model-chosen tool names, arg keys and cross-rule text. They go
        # back to the model, into reports and into the audit log: scrub them once here.
        result.reasons = [self._scrub(r) for r in result.reasons]
        result.arg = self._scrub(result.arg)
        for f in result.findings:
            f.arg = self._scrub(f.arg)
        self.history.append(result)
        if self.meter is not None:
            self.meter.record_intercept(
                lane=self.lane,
                ok=result.verdict is Verdict.ALLOW,
                namespace=self._scrub(result.call.name) if result.call else None,
                error="; ".join(result.reasons) or None,
                meta={
                    "verdict": result.verdict.value,
                    "default": self.default,
                    "findings": [f.kind for f in result.findings],
                    # Which context keys were set, never their values (often personal data).
                    "context": sorted(current_context().keys()),
                },
            )
        return result

    def _record_transition(self, result: GateResult, event: str) -> GateResult:
        if self.meter is not None:
            self.meter.record(
                RunEvent(
                    lane=self.lane,
                    kind="note",
                    ok=result.verdict is Verdict.ALLOW,
                    namespace=self._scrub(result.call.name) if result.call else None,
                    meta={"approval": event},
                )
            )
        return result


def _first_arg_named(errors: list[str], args: dict[str, Any], schema: ToolSchema) -> str | None:
    """The argument a schema error is about, when it is one the call or schema names.

    Only names already in the model's own call or in the tool's schema are
    returned, so the model-facing reason never echoes anything else.
    """
    known = set(args) | set(schema.required) | set(schema.types)
    for message in errors:
        for name in known:
            if isinstance(name, str) and (f"'{name}'" in message or message.endswith(f": {name}")):
                return name
    return None

