"""Business rules for the arguments of an agent's tool calls.

    from toolwall import rules as r

    wall.rule("issue_refund",
        amount=r.positive() & r.at_most(500),
        order_id=r.owned_by("customer_id", lookup=orders.owner_of),
        ask_if=r.over("amount", 200))

Every rule takes one argument value and returns True to allow it. Rules compose
with `&` (both), `|` (either) and `~` (not). Rules are strict: a value of the wrong
kind fails rather than being coerced, so "40" is not a number and True is not 1.
Rules that read the request context (`equals_context`, `owned_by`) fail when the
key isn't set: no context, no permission.

Rules are synchronous. A lookup that returns an awaitable fails the rule (the
awaitable is closed); async lookups arrive with the framework adapters.
"""

from __future__ import annotations

import decimal
import fnmatch
import inspect
import math
import os
import re
from collections.abc import Callable
from typing import Any
from urllib.parse import urlsplit

from toolwall import context as _ctx
from toolwall._aio import discard_awaitable
from toolwall.policy import email_domain as _email_domain
from toolwall.policy import matches as _matches

__all__ = [
    "Rule", "at_most", "at_least", "between", "positive", "one_of", "max_len",
    "matches", "email_domain", "equals_context", "owned_by", "sql_readonly",
    "path_under", "url_host", "over",
]


class Rule:
    """A named predicate over one argument value. Compose with &, | and ~."""

    def __init__(self, fn: Callable[[Any], bool], name: str) -> None:
        self._fn = fn
        self.__name__ = name

    def __call__(self, value: Any) -> bool:
        return bool(self._fn(value))

    def __and__(self, other: Callable[[Any], bool]) -> "Rule":
        other = _as_rule(other)
        return Rule(lambda v: self(v) and other(v), f"({self.__name__} & {other.__name__})")

    def __or__(self, other: Callable[[Any], bool]) -> "Rule":
        other = _as_rule(other)
        return Rule(lambda v: self(v) or other(v), f"({self.__name__} | {other.__name__})")

    def __invert__(self) -> "Rule":
        return Rule(lambda v: not self(v), f"~{self.__name__}")

    def __repr__(self) -> str:
        return f"<rule {self.__name__}>"


def _as_rule(fn: Callable[[Any], bool]) -> Rule:
    if isinstance(fn, Rule):
        return fn
    return Rule(fn, getattr(fn, "__name__", "rule"))


# -- numbers ----------------------------------------------------------------------


def _number(value: Any) -> float | None:
    """A finite real number, or None. bool and numeric strings are not numbers."""
    if isinstance(value, bool) or not isinstance(value, (int, float, decimal.Decimal)):
        return None
    try:
        number = float(value)
    except (OverflowError, ValueError):
        return None
    return number if math.isfinite(number) else None


def at_most(limit: float) -> Rule:
    return Rule(lambda v: (n := _number(v)) is not None and n <= limit, f"at_most({limit})")


def at_least(limit: float) -> Rule:
    return Rule(lambda v: (n := _number(v)) is not None and n >= limit, f"at_least({limit})")


def between(lo: float, hi: float) -> Rule:
    return Rule(lambda v: (n := _number(v)) is not None and lo <= n <= hi, f"between({lo}, {hi})")


def positive() -> Rule:
    return Rule(lambda v: (n := _number(v)) is not None and n > 0, "positive()")


# -- values -----------------------------------------------------------------------


def one_of(*allowed: Any) -> Rule:
    """Exactly one of these values, same type: one_of(1) rejects True and 1.0."""
    return Rule(lambda v: any(type(v) is type(a) and v == a for a in allowed), f"one_of{allowed!r}")


def max_len(limit: int) -> Rule:
    return Rule(lambda v: isinstance(v, (str, list, tuple, dict)) and len(v) <= limit, f"max_len({limit})")


def matches(pattern: str) -> Rule:
    """The whole value matches the regular expression (full match)."""
    return _as_rule(_matches(pattern))


def email_domain(*domains: str) -> Rule:
    """Exactly one bare address on one of these exact domains."""
    return _as_rule(_email_domain(*domains))


# -- request context --------------------------------------------------------------


def equals_context(key: str) -> Rule:
    """The value equals the request context's `key` (e.g. the customer's own email)."""

    def check(value: Any) -> bool:
        expected = _ctx.current().get(key, _UNSET)
        return expected is not _UNSET and type(value) is type(expected) and value == expected

    return Rule(check, f"equals_context({key!r})")


def owned_by(key: str, *, lookup: Callable[[Any], Any]) -> Rule:
    """`lookup(value)` returns the record's owner; it must equal context[key].

    owned_by("customer_id", lookup=orders.owner_of) on an order_id argument
    allows only orders of the customer the agent is serving. A missing record
    (lookup returns None) or a missing context key fails. A lookup that raises
    fails closed through the policy. A lookup that returns an awaitable fails.
    """

    def check(value: Any) -> bool:
        expected = _ctx.current().get(key, _UNSET)
        if expected is _UNSET or expected is None:
            return False
        owner = lookup(value)
        if inspect.isawaitable(owner):
            discard_awaitable(owner)
            return False
        return owner is not None and owner == expected

    return Rule(check, f"owned_by({key!r})")


_UNSET = object()


# -- data access --------------------------------------------------------------------

_SQL_COMMENT = re.compile(r"--[^\n]*|/\*.*?\*/", re.S)
_SQL_STRING = re.compile(r"'(?:[^']|'')*'")
_SQL_WRITE = re.compile(
    r"\b(insert|update|delete|merge|upsert|replace|drop|alter|create|truncate|rename|grant|"
    r"revoke|attach|detach|copy|call|exec|execute|do|vacuum|reindex|pragma|set|lock|into)\b",
    re.I,
)


def sql_readonly() -> Rule:
    """One read-only statement: starts with SELECT or WITH, no second statement,
    and no write keyword anywhere (including CTEs like WITH x AS (DELETE ...)).

    Conservative on purpose: a keyword inside a string literal is ignored, but
    any write keyword outside one blocks, even where a database would accept it.
    Pair it with a read-only database role; this rule is a second line, not the
    only one.
    """

    def check(value: Any) -> bool:
        if not isinstance(value, str):
            return False
        text = _SQL_STRING.sub("''", _SQL_COMMENT.sub(" ", value)).strip()
        text = text[:-1].rstrip() if text.endswith(";") else text
        if not text or ";" in text:
            return False
        if not re.match(r"(select|with)\b", text, re.I):
            return False
        return _SQL_WRITE.search(text) is None

    return Rule(check, "sql_readonly()")


def path_under(root: str, *, deny: tuple[str, ...] = (".env", ".env.*", "*.pem", "*.key", "id_rsa*")) -> Rule:
    """The path resolves (symlinks followed) to somewhere inside `root`, and no
    part of it matches a `deny` glob. Relative paths are taken relative to root."""
    real_root = os.path.realpath(root)

    def check(value: Any) -> bool:
        if not isinstance(value, str) or not value or "\x00" in value:
            return False
        candidate = value if os.path.isabs(value) else os.path.join(real_root, value)
        real = os.path.realpath(candidate)
        if real != real_root and not real.startswith(real_root + os.sep):
            return False
        parts = os.path.relpath(real, real_root).split(os.sep)
        return not any(fnmatch.fnmatch(part, pattern) for part in parts for pattern in deny)

    return Rule(check, f"path_under({root!r})")


def url_host(*hosts: str, schemes: tuple[str, ...] = ("https",)) -> Rule:
    """An absolute URL whose host is exactly one of `hosts`, with an allowed scheme
    and no user info (user@host hides the real host from careless parsers)."""
    allowed = {h.lower().rstrip(".") for h in hosts}

    def check(value: Any) -> bool:
        if not isinstance(value, str):
            return False
        try:
            parts = urlsplit(value)
            host = parts.hostname
        except ValueError:
            return False
        if parts.scheme.lower() not in schemes or not host or "@" in parts.netloc:
            return False
        return host.lower().rstrip(".") in allowed

    return Rule(check, f"url_host{tuple(sorted(allowed))!r}")


# -- when to ask a human ------------------------------------------------------------


def over(arg: str, limit: float) -> Callable[[dict[str, Any]], bool]:
    """For ask_if: True when `arg` is above `limit`. A value that isn't a clean
    number also asks, so a human sees anything the rules couldn't read."""

    def predicate(args: dict[str, Any]) -> bool:
        if arg not in args:
            return False
        number = _number(args[arg])
        return number is None or number > limit

    predicate.__name__ = f"over({arg!r}, {limit})"
    return predicate
