"""Request context: who the agent is acting for, available to every rule.

Values set with `context(...)` (or `ToolWall.context(...)`) are visible to rules
evaluated in the same thread or asyncio task, and to nothing else: contextvars
give each task and thread its own copy, so two customers served concurrently
can never see each other's context. Contexts nest; inner values override outer
ones and are restored on exit.

The audit log records which context keys were set, never their values.
"""

from __future__ import annotations

from contextvars import ContextVar, Token
from types import MappingProxyType
from typing import Any, Mapping

_EMPTY: Mapping[str, Any] = MappingProxyType({})
_current: ContextVar[Mapping[str, Any]] = ContextVar("toolwall_context", default=_EMPTY)

_MISSING = object()


def current() -> Mapping[str, Any]:
    """The context in effect here (read-only)."""
    return _current.get()


def get(key: str, default: Any = _MISSING) -> Any:
    """One context value; raises KeyError when it isn't set and no default is given."""
    value = _current.get().get(key, default)
    if value is _MISSING:
        raise KeyError(f"context {key!r} is not set")
    return value


class context:
    """`with context(customer_id="c_42"): ...` (also `async with`)."""

    def __init__(self, **values: Any) -> None:
        self._values = values
        self._tokens: list[Token] = []

    def __enter__(self) -> Mapping[str, Any]:
        merged = MappingProxyType({**_current.get(), **self._values})
        self._tokens.append(_current.set(merged))
        return merged

    def __exit__(self, *exc: object) -> None:
        _current.reset(self._tokens.pop())

    async def __aenter__(self) -> Mapping[str, Any]:
        return self.__enter__()

    async def __aexit__(self, *exc: object) -> None:
        self.__exit__(*exc)


class exactly(context):
    """Like context(), but replaces the context in effect instead of adding to
    it: an approved ticket runs in exactly the context it was approved in."""

    def __enter__(self) -> Mapping[str, Any]:
        values = MappingProxyType(dict(self._values))
        self._tokens.append(_current.set(values))
        return values
