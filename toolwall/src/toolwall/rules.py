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

Rules are synchronous. A rule or lookup that returns an awaitable fails closed
(the awaitable is closed); async lookups arrive with the framework adapters.

Context: a rule that reads the request context raises when its key is unset,
and the policy blocks a raising rule, so `~equals_context("k")` blocks too
when no context is set. No context, no permission, negated or not.

Context follows the thread or asyncio task. Work handed to a thread pool does
not see it unless you carry it over (`asyncio.to_thread`,
`contextvars.copy_context().run`); there the rules see no context and deny.
"""

from __future__ import annotations

import decimal
import fnmatch
from concurrent.futures import Future as _Future
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


def _refuse_lazy(value: Any, what: str) -> None:
    """Raise if value is not an answer but a promise of one.

    Awaitables, generators, async generators and Futures are all truthy. Read as
    a verdict they pass; turned into False, ~ makes them pass. Raising is the
    only fail-closed option: the policy blocks a raising rule.
    """
    if inspect.isawaitable(value):
        discard_awaitable(value)
        raise TypeError(f"{what} returned an awaitable; it must be synchronous")
    if inspect.isgenerator(value) or inspect.isasyncgen(value) or isinstance(value, _Future):
        raise TypeError(f"{what} returned a lazy value (generator or Future), not an answer")


class Rule:
    """A named predicate over one argument value. Compose with &, | and ~."""

    def __init__(self, fn: Callable[[Any], bool], name: str) -> None:
        self._fn = fn
        self.__name__ = name

    def __call__(self, value: Any) -> bool:
        verdict = self._fn(value)
        _refuse_lazy(verdict, f"rule {self.__name__}")
        return bool(verdict)

    def __and__(self, other: Callable[[Any], bool]) -> "Rule":
        other = _as_rule(other)
        return Rule(lambda v: self(v) and other(v), f"({self.__name__} & {other.__name__})")

    def __rand__(self, other: Callable[[Any], bool]) -> "Rule":
        return _as_rule(other) & self

    def __or__(self, other: Callable[[Any], bool]) -> "Rule":
        other = _as_rule(other)
        return Rule(lambda v: self(v) or other(v), f"({self.__name__} | {other.__name__})")

    def __ror__(self, other: Callable[[Any], bool]) -> "Rule":
        return _as_rule(other) | self

    def __invert__(self) -> "Rule":
        return Rule(lambda v: not self(v), f"~{self.__name__}")

    def __repr__(self) -> str:
        return f"<rule {self.__name__}>"


def _as_rule(fn: Callable[[Any], bool]) -> Rule:
    if isinstance(fn, Rule):
        return fn
    return Rule(fn, getattr(fn, "__name__", "rule"))


# -- numbers ----------------------------------------------------------------------


def _number(value: Any) -> int | float | decimal.Decimal | None:
    """The value itself when it is a finite real number, else None.

    bool and numeric strings are not numbers. The value is returned unconverted,
    so comparisons are exact: Python compares int, float and Decimal exactly, and
    a float conversion would round 2**53 + 1 or Decimal("500.0000000000000000001")
    onto the limit.
    """
    if isinstance(value, bool) or not isinstance(value, (int, float, decimal.Decimal)):
        return None
    if isinstance(value, float) and not math.isfinite(value):
        return None
    if isinstance(value, decimal.Decimal) and not value.is_finite():
        return None
    return value


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
        expected = _context_value(key)
        return type(value) is type(expected) and value == expected

    return Rule(check, f"equals_context({key!r})")


def owned_by(key: str, *, lookup: Callable[[Any], Any]) -> Rule:
    """`lookup(value)` returns the record's owner; it must equal context[key].

    owned_by("customer_id", lookup=orders.owner_of) on an order_id argument
    allows only orders of the customer the agent is serving. A missing record
    (lookup returns None) or a missing context key fails. A lookup that raises
    fails closed through the policy. A lookup that returns an awaitable fails.
    """

    def check(value: Any) -> bool:
        expected = _context_value(key)
        owner = lookup(value)
        # Raise rather than return False: ~owned_by(...) would turn False into a pass.
        _refuse_lazy(owner, "owned_by lookup")
        # Type-strict like equals_context: True is not 1, and 1.0 is not 1.
        return owner is not None and type(owner) is type(expected) and owner == expected

    return Rule(check, f"owned_by({key!r})")


_UNSET = object()


def _context_value(key: str) -> Any:
    """The context value, or raise: a rule that needs the context must not answer
    without it, and an answer of False would let ~rule pass."""
    value = _ctx.current().get(key, _UNSET)
    if value is _UNSET or value is None:
        raise LookupError(f"context {key!r} is not set")
    return value


# -- data access --------------------------------------------------------------------

# sql_readonly accepts a portable subset of SQL and refuses everything else.
# Databases disagree about comments (# in MySQL, nested /* */ and \r in
# Postgres), about quoting ([x] in sqlite and SQL Server, `x` in MySQL, $tag$ in
# Postgres, backslash escapes in MySQL strings) and about where a statement ends.
# A rule that tries to parse every dialect gets one of them wrong, and a
# disagreement is exactly where a second statement hides. So: outside the two
# quoting forms every database agrees on ('...' and "..." with doubling), only
# plain ASCII identifiers, numbers, operators and spaces are allowed.
_SQL_QUOTED = re.compile(r"'(?:[^'\\\x00\r]|'')*'|\"(?:[^\"\\\x00\r]|\"\")*\"")
# No @ or : either: sqlite reads @name(...) and :name(...) as one variable token
# that can swallow a quote, so the same text splits differently there.
_SQL_ALLOWED_OUTSIDE = re.compile(r"[A-Za-z0-9_ \t\n(),.*=<>!+\-/%;|&^~?]*")
_SQL_WRITE = re.compile(
    r"\b(insert|update|delete|merge|upsert|replace|drop|alter|create|truncate|rename|grant|"
    r"revoke|attach|detach|copy|call|exec|execute|do|vacuum|reindex|pragma|set|lock|into|"
    r"load|handler|import|outfile|dumpfile|"
    # SQL Server ends a statement without ';', so its statement verbs can start a
    # second statement mid-text: refuse them anywhere.
    r"shutdown|kill|backup|restore|dbcc|deny|checkpoint|waitfor|use|begin|commit|"
    r"rollback|disable|enable|receive|send|declare|deallocate|raiserror|throw|goto|"
    r"print|reconfigure|bulk|openrowset|opendatasource|openquery|xp_\w+|sp_\w+)\b",
    re.I,
)


def _sql_code(text: str) -> str | None:
    """The statement with its quoted parts blanked, or None when anything falls
    outside the portable subset (comments, other quoting, backslashes, $, #,
    brackets, backticks, \r, NUL, non-ASCII outside quotes, an unterminated quote)."""
    code = _SQL_QUOTED.sub(" _ ", text)
    if not _SQL_ALLOWED_OUTSIDE.fullmatch(code):
        return None
    if "--" in code or "/*" in code or "*/" in code:
        return None
    return code


def sql_readonly() -> Rule:
    """One read-only statement in a portable subset of SQL.

    Allowed: a single statement starting with SELECT or WITH (one trailing ;),
    '...' strings and "..." identifiers with doubled quotes, plain ASCII
    identifiers, numbers and operators, and no write keyword outside quotes
    (including CTEs like WITH x AS (DELETE ...)).

    Refused, because databases disagree about them and a disagreement is where a
    second statement hides: comments of any kind, backslashes, $ (dollar quoting
    and $1 placeholders), #, @ and : (sqlite variables, MySQL @vars, Postgres ::
    casts), [brackets], `backticks`, \r, NUL, and non-ASCII outside quotes. SQL
    Server statement verbs (SHUTDOWN, KILL, BACKUP, DBCC, WAITFOR, BEGIN...) are
    refused anywhere, because T-SQL needs no ';' between statements. Ordinary
    LLM-written reads fit the subset; anything else is a false block, by design,
    including columns named like a write keyword (load, lock, set, use...) and
    replace() as a string function.

    It does not know which functions have side effects: pg_sleep, nextval, setval,
    set_config, lo_import, pg_read_file, dblink_exec and pg_terminate_backend all
    pass. Pair it with a read-only database role; this rule is a second line, not
    the only one.
    """

    def check(value: Any) -> bool:
        if not isinstance(value, str):
            return False
        code = _sql_code(value)
        if code is None:
            return False
        code = code.strip()
        code = code[:-1].rstrip() if code.endswith(";") else code
        if not code or ";" in code:
            return False
        if not re.match(r"(select|with)\b", code, re.I):
            return False
        return _SQL_WRITE.search(code) is None

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
        # Case-insensitive: on macOS and Windows ".ENV" opens ".env".
        return not any(
            fnmatch.fnmatchcase(part.casefold(), pattern.casefold())
            for part in parts for pattern in deny
        )

    return Rule(check, f"path_under({root!r})")


def url_host(*hosts: str, schemes: tuple[str, ...] = ("https",)) -> Rule:
    """An absolute URL whose host is exactly one of `hosts`, with an allowed scheme
    and no user info (user@host hides the real host from careless parsers).
    Any port is accepted; pin the port with matches() if it matters."""
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
