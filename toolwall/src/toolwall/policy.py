"""Value-level policy rules, evaluated after schema and before execution.

Schema answers "is the shape right". Policy answers "is this value allowed".
Rules are plain callables returning truthy/falsy. A raising rule fails closed.
"""

from __future__ import annotations

import math
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

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


_EMAIL_LOCAL = re.compile(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+")


def email_domain(*domains: str) -> Rule:
    """Exactly one bare email address whose domain is one of `domains`.

    Rejects anything a mail API could read as more than one recipient or as an
    extra header: commas, semicolons, angle brackets, whitespace, CR/LF, a second
    "@". Domains match exactly, case-insensitively; subdomains are not included
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
    """Per-tool policy: arg constraints, an optional cross-arg rule, approval flag.

    constraints: {arg_name: rule}. Absent args are skipped (schema owns presence).
    cross: receives the full args dict; returns an error string, a list of error
           strings, or None. Raising fails closed.
    require_approval: passing calls become NEEDS_APPROVAL instead of ALLOW.
    """

    constraints: dict[str, Rule] = field(default_factory=dict)
    cross: CrossRule | None = None
    require_approval: bool = False

    def validate(self, args: dict[str, Any]) -> list[str]:
        errors: list[str] = []
        for key, rule in self.constraints.items():
            if key not in args:
                continue
            name = getattr(rule, "__name__", "rule")
            try:
                ok = bool(rule(args[key]))
            except Exception as exc:
                errors.append(
                    f"policy rule {name} for arg {key!r} raised {type(exc).__name__}: fails closed"
                )
                continue
            if not ok:
                errors.append(f"policy violation: arg {key!r} rejected by {name}")
        if self.cross is not None:
            try:
                verdict = self.cross(dict(args))
            except Exception as exc:
                errors.append(f"policy cross-rule raised {type(exc).__name__}: fails closed")
            else:
                if isinstance(verdict, str):
                    errors.append(verdict)
                elif verdict:
                    errors.extend(verdict)
        return errors
