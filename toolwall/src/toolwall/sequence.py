"""Sequence rules: what may run after what, within one session.

Every other check looks at one call. A sequence rule looks at what already ran
in the same session:

    wall.after("lookup_customer", block="send_email")
    wall.after("read_file", ask=["http_post", "send_email"])

    with wall.context(session_id="s_81", customer_id="c_42"):
        ...  # once lookup_customer has run in s_81, send_email is refused there

Only calls that ran count: a blocked or held call arms nothing. A call counts
as run once ToolWall lets it through to the tool (wall.call/acall, or an
"allow" from decide() that your framework then runs), so a call that failed
part-way still counts: its side effects may have happened.

The session comes from the request context (`session_id` by default; change it
with ToolWall(session_key=...)). A call that a sequence rule applies to, made
with no session in the context, is blocked: no session, no way to know what ran
before.

Sessions are remembered in this process, for the most recent `max_sessions`
sessions. Two processes don't share them.
"""

from __future__ import annotations

import threading
from collections import OrderedDict
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any, Literal

DEFAULT_SESSION_KEY = "session_id"
DEFAULT_MAX_SESSIONS = 100_000

Action = Literal["block", "ask"]


@dataclass(frozen=True)
class SequenceRule:
    after: str
    then: str
    action: Action


def _names(value: str | Iterable[str] | None, what: str) -> tuple[str, ...]:
    if value is None:
        return ()
    names = (value,) if isinstance(value, str) else tuple(value)
    for n in names:
        if not isinstance(n, str) or not n:
            raise TypeError(f"{what} must be tool names (strings)")
    return names


class Sequences:
    """The wall's sequence rules and, per session, which trigger tools ran."""

    def __init__(self, session_key: str = DEFAULT_SESSION_KEY,
                 max_sessions: int = DEFAULT_MAX_SESSIONS) -> None:
        if not isinstance(session_key, str) or not session_key:
            raise ValueError("session_key must be a non-empty string")
        if isinstance(max_sessions, bool) or not isinstance(max_sessions, int) or max_sessions < 1:
            raise ValueError("max_sessions must be a positive whole number")
        self.session_key = session_key
        self.max_sessions = max_sessions
        self.rules: list[SequenceRule] = []
        self._ran: OrderedDict[Any, set[str]] = OrderedDict()
        self._lock = threading.Lock()

    def add(self, after: str, *, block: str | Iterable[str] | None = None,
            ask: str | Iterable[str] | None = None) -> None:
        first = _names(after, "after")
        if len(first) != 1:
            raise TypeError("after must be one tool name")
        blocked, asked = _names(block, "block"), _names(ask, "ask")
        if not blocked and not asked:
            raise ValueError("say what happens after it: block=... and/or ask=...")
        for name in blocked:
            self.rules.append(SequenceRule(first[0], name, "block"))
        for name in asked:
            self.rules.append(SequenceRule(first[0], name, "ask"))

    def _session(self, ctx: Mapping[str, Any]) -> Any:
        session = ctx.get(self.session_key)
        if session is None:
            return None
        try:
            hash(session)
        except TypeError:
            return None
        return session

    def check(self, tool: str, ctx: Mapping[str, Any]) -> tuple[str, str] | None:
        """None (no rule applies, or none is triggered), or (kind, reason) where
        kind is "block", "ask", or "no_session" (a rule applies but the context
        has no session: treat it as a block)."""
        rules = [r for r in self.rules if r.then == tool]
        if not rules:
            return None
        session = self._session(ctx)
        if session is None:
            return ("no_session", f"sequence rules apply to {tool!r} but the context has no "
                             f"{self.session_key!r}: fails closed")
        with self._lock:
            ran = set(self._ran.get(session, ()))
        hit = [r for r in rules if r.after in ran]
        if not hit:
            return None
        blocking = [r for r in hit if r.action == "block"]
        rule = blocking[0] if blocking else hit[0]
        verb = "not allowed" if rule.action == "block" else "needs approval"
        return (rule.action, f"{tool!r} {verb} after {rule.after!r} in this session")

    def ran(self, tool: str, ctx: Mapping[str, Any]) -> None:
        """Record that `tool` ran in the context's session, if a rule watches it."""
        if not any(r.after == tool for r in self.rules):
            return
        session = self._session(ctx)
        if session is None:
            return
        with self._lock:
            seen = self._ran.pop(session, set())
            seen.add(tool)
            self._ran[session] = seen
            while len(self._ran) > self.max_sessions:
                self._ran.popitem(last=False)

    def forget(self, session: Any) -> None:
        """Drop what ran in a session (say, when the conversation ends)."""
        with self._lock:
            self._ran.pop(session, None)
