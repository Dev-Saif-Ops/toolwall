"""Small helpers for telling async callables and awaitables apart (stdlib only).

An awaitable is truthy and is not the value it will produce. Anywhere the gate
reads a callable's result as a decision or as output, an awaitable must either
be awaited (async path) or refused (sync path); reading it as-is approves or
leaks.
"""

from __future__ import annotations

import asyncio
import functools
import inspect
from typing import Any


def is_async_callable(fn: Any) -> bool:
    """True for `async def` functions, partials of them, and objects whose
    `__call__` is `async def`."""
    while isinstance(fn, functools.partial):
        fn = fn.func
    if inspect.iscoroutinefunction(fn):
        return True
    call = getattr(fn, "__call__", None)  # noqa: B004 (is __call__ async, not "is it callable")
    return call is not None and inspect.iscoroutinefunction(call)


def discard_awaitable(value: Any) -> None:
    """Drop an awaitable we refuse to await, without a 'never awaited' warning."""
    if inspect.iscoroutine(value):
        value.close()
    elif isinstance(value, asyncio.Future):
        value.cancel()
