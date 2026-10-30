"""Value-level policy rules, evaluated after schema and before execution.

Schema answers "is the shape right". Policy answers "is this value allowed".
Rules are plain callables returning truthy/falsy. A raising rule fails closed.
"""

from __future__ import annotations

import inspect
import math
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from toolwall._aio import discard_awaitable

Rule = Callable[[Any], bool]
CrossRule = Callable[[dict[str, Any]], "str | list[str] | None"]


def _named(name: str, fn: Rule) -> Rule:
    fn.__name__ = name
    return fn


def in_range(lo: float | None = None, hi: float | None = None) -> Rule:
    def rule(value: Any) -> bool:
        # bool is an int subclass: True would read as 1. Not a quantity.
        if isinstance(value, bool):
            return False
        number = float(value)
        # NaN compares False against everything, so both bound checks below would
        # pass it. Infinity is outside any finite range anyway; reject it here too
        # so a one-sided range (hi=None) cannot admit it.
        if not math.isfinite(number):
            return False
        if lo is not None and number < lo:
            return False
        if hi is not None and number > hi:
            return False
        return True

    return _named(f"in_range({lo}, {hi})", rule)


def one_of(*allowed: Any) -> Rule:
    def rule(value: Any) -> bool:
        return value in allowed

    return _named(f"one_of{allowed!r}", rule)


def matches(pattern: str) -> Rule:
    compiled = re.compile(pattern)

    def rule(value: Any) -> bool:
        return isinstance(value, str) and compiled.fullmatch(value) is not None

    return _named(f"matches({pattern!r})", rule)


def max_len(limit: int) -> Rule:
    def rule(value: Any) -> bool:
        return len(value) <= limit

    return _named(f"max_len({limit})", rule)


def ends_with(*suffixes: str) -> Rule:
    """String suffix check. Not a recipient allowlist: "x@evil.com,y@ourco.com"
    ends with "@ourco.com". Use email_domain() for email addresses."""

    def rule(value: Any) -> bool:
        return isinstance(value, str) and value.endswith(suffixes)

    return _named(f"ends_with{suffixes!r}", rule)


# RFC 5322 atext minus "%" and "!": both are legacy source-routing characters
# (user%host@relay, host!user@relay) that some MTAs still rewrite to another domain.
_EMAIL_LOCAL = re.compile(r"[A-Za-z0-9.#$&'*+/=?^_`{|}~-]+")


def email_domain(*domains: str) -> Rule:
    """Exactly one bare email address whose domain is one of `domains`.

    Rejects anything a mail API could read as more than one recipient or as an
    extra header: commas, semicolons, angle brackets, whitespace, CR/LF, a second
    "@", and "%"/"!" source routing. Domains match exactly, case-insensitively; subdomains are not included
    (list them explicitly). Non-ASCII lookalikes never equal an ASCII domain.
    """
    allowed = {d.strip().lstrip("@").lower() for d in domains}
    if not allowed or "" in allowed:
        raise ValueError("email_domain needs at least one non-empty domain")

    def rule(value: Any) -> bool:
        if not isinstance(value, str) or value.count("@") != 1:
            return False
        local, domain = value.split("@")
        return (
            _EMAIL_LOCAL.fullmatch(local) is not None
            and domain.isascii()
            and domain.lower() in allowed
        )

    return _named(f"email_domain{tuple(sorted(allowed))!r}", rule)


def starts_with(*prefixes: str) -> Rule:
    def rule(value: Any) -> bool:
        return isinstance(value, str) and value.startswith(prefixes)

    return _named(f"starts_with{prefixes!r}", rule)


def not_empty(value: Any) -> bool:
    return bool(value)


@dataclass
class Policy:
    """Per-tool policy: arg constraints, an optional cross-arg rule, approval.

    constraints: {arg_name: rule}. Absent args are skipped (schema owns presence).
    cross: receives the full args dict; returns an error string, a list of error
           strings, or None. Raising fails closed.
    require_approval: passing calls become NEEDS_APPROVAL instead of ALLOW.
    ask_if: receives the full args dict; True makes a passing call NEEDS_APPROVAL
           (for example "refunds over 200 need a human"). Raising or returning an
           awaitable fails closed.
    """

    constraints: dict[str, Rule] = field(default_factory=dict)
    cross: CrossRule | None = None
    require_approval: bool = False
    ask_if: Callable[[dict[str, Any]], bool] | None = None

    def validate(self, args: dict[str, Any]) -> list[str]:
        return [message for _, message in self.violations(args)]

    def violations(self, args: dict[str, Any]) -> list[tuple[str | None, str]]:
        """(argument name or None for a cross-rule, message) for each failure."""
        errors: list[tuple[str | None, str]] = []
        for key, rule in self.constraints.items():
            if key not in args:
                continue
            name = getattr(rule, "__name__", "rule")
            try:
                verdict = rule(args[key])
                if inspect.isawaitable(verdict):
                    # A coroutine is truthy: reading it would pass every value.
                    discard_awaitable(verdict)
                    errors.append((key, f"policy rule {name} for arg {key!r} is async; rules must be synchronous: fails closed"))
                    continue
                ok = bool(verdict)
            except Exception as exc:
                errors.append((key,
                    f"policy rule {name} for arg {key!r} raised {type(exc).__name__}: fails closed"
                ))
                continue
            if not ok:
                errors.append((key, f"policy violation: arg {key!r} rejected by {name}"))
        if self.cross is not None:
            try:
                verdict = self.cross(dict(args))
            except Exception as exc:
                errors.append((None, f"policy cross-rule raised {type(exc).__name__}: fails closed"))
            else:
                if inspect.isawaitable(verdict):
                    discard_awaitable(verdict)
                    errors.append((None, "policy cross-rule is async; rules must be synchronous: fails closed"))
                    return errors
                if isinstance(verdict, str):
                    errors.append((None, verdict))
                elif verdict:
                    for item in verdict:
                        if inspect.isawaitable(item):
                            discard_awaitable(item)
                            errors.append((None, "policy cross-rule returned an awaitable: fails closed"))
                        else:
                            errors.append((None, item))
        return errors

    def wants_approval(self, args: dict[str, Any]) -> bool | str:
        """True/False, or an error message when ask_if can't be evaluated (fail closed)."""
        if self.require_approval:
            return True
        if self.ask_if is None:
            return False
        try:
            verdict = self.ask_if(dict(args))
        except Exception as exc:
            return f"policy ask_if raised {type(exc).__name__}: fails closed"
        if inspect.isawaitable(verdict):
            discard_awaitable(verdict)
            return "policy ask_if is async; it must be synchronous: fails closed"
        return bool(verdict)
