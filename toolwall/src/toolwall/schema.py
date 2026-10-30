"""Tool schema validation, run before a tool is allowed to execute."""

from __future__ import annotations

import inspect
import types
import typing
from dataclasses import dataclass, field
from typing import Any


@dataclass
class ToolSchema:
    """Minimal schema: required keys + optional crude types."""

    required: list[str] = field(default_factory=list)
    types: dict[str, type | tuple[type, ...]] = field(default_factory=dict)
    allow_extra: bool = True
    # Known-but-not-required arg names. Only consulted when allow_extra is False,
    # so that an optional parameter carrying no type annotation (and therefore
    # absent from `types`) is not mistaken for an unexpected argument.
    optional: list[str] = field(default_factory=list)

    def validate(self, args: dict[str, Any]) -> list[str]:
        errors: list[str] = []
        for key in self.required:
            if key not in args:
                errors.append(f"Missing required arg: {key}")
        if not self.allow_extra:
            allowed = set(self.required) | set(self.types) | set(self.optional)
            for key in args:
                if key not in allowed:
                    errors.append(f"Unexpected arg: {key}")
        for key, expected in self.types.items():
            if key not in args:
                continue
            if not isinstance(args[key], expected):
                errors.append(
                    f"Arg {key!r} expected {expected}, got {type(args[key]).__name__}"
                )
        return errors


def _signature(fn: Any) -> inspect.Signature:
    # eval_str resolves string annotations (modules using `from __future__ import
    # annotations`), so types are enforced there too. If any annotation can't be
    # resolved, fall back to the raw signature: those annotations stay strings and
    # are treated as unsupported, which means no inference rather than an error.
    try:
        return inspect.signature(fn, eval_str=True)
    except Exception:
        return inspect.signature(fn)


_ANY = object()  # an annotation that constrains nothing (typing.Any)


def _resolve_annotation(ann: Any) -> "tuple[type, ...] | object | None":
    """Map an annotation to the classes isinstance() should accept.

    Returns a tuple of classes, _ANY for typing.Any, or None when the annotation
    can't be checked with isinstance (Literal, TypedDict, a string, a TypeVar...).
    Generic containers check the container only: list[str] accepts any list.
    float also accepts int, because JSON has one number type.
    """
    if ann is typing.Any:
        return _ANY
    origin = typing.get_origin(ann)
    if origin is typing.Annotated:
        return _resolve_annotation(typing.get_args(ann)[0])
    if origin is typing.Union or origin is types.UnionType:
        accepted: list[type] = []
        for member in typing.get_args(ann):
            resolved = _resolve_annotation(member)
            if resolved is None:
                return None
            if resolved is _ANY:
                return _ANY
            accepted.extend(resolved)  # type: ignore[arg-type]
        return tuple(dict.fromkeys(accepted))
    if origin is not None:
        # list[str] -> list, typing.List[str] -> list; Literal's origin is not a class.
        return (origin,) if isinstance(origin, type) else None
    if ann is None or ann is type(None):
        return (type(None),)
    # On 3.10, isinstance(list[str], type) is True; GenericAlias is handled above.
    if isinstance(ann, type) and not isinstance(ann, types.GenericAlias):
        return (int, float) if ann is float else (ann,)
    return None


def _named_params(sig: inspect.Signature) -> list[inspect.Parameter]:
    return [
        p for name, p in sig.parameters.items()
        if name not in ("self", "cls") and p.kind is not p.VAR_POSITIONAL
    ]


def _fully_annotated(sig: inspect.Signature) -> bool:
    named = _named_params(sig)
    if any(p.kind is p.VAR_KEYWORD for p in named):
        return False
    if sig.return_annotation is inspect.Signature.empty:
        return False
    # Parameter.empty is itself a class, so it must be excluded explicitly.
    return all(
        p.annotation is not p.empty and _resolve_annotation(p.annotation) is not None
        for p in named
    )


def fully_annotated(fn: Any) -> bool:
    """True when every named parameter has an annotation toolwall can check (a
    class, X | None, Union, Optional, a generic container, Any, Annotated[...]),
    the return value is annotated, and there is no **kwargs: the author declared
    the whole signature, so it can stand in for a schema. A lambda never does."""
    try:
        return _fully_annotated(_signature(fn))
    except (TypeError, ValueError):
        return False


def infer_schema_if_annotated(fn: Any) -> "ToolSchema | None":
    """One signature read: the inferred schema, or None when fn isn't fully
    annotated. Annotation expressions are evaluated once."""
    try:
        sig = _signature(fn)
    except (TypeError, ValueError):
        return None
    if not _fully_annotated(sig):
        return None
    return schema_from_signature(fn, _sig=sig)


def schema_from_signature(
    fn: Any, *, required: list[str] | None = None, _sig: inspect.Signature | None = None
) -> ToolSchema:
    """Best-effort schema from a callable signature (stdlib inspect).

    Extra arguments are rejected, because the signature already tells us exactly
    what the callable accepts. Passing one would raise TypeError inside the tool,
    which surfaces as an executed=False result carrying an error rather than as a
    verdict; a clean BLOCK is both more honest and fails closed.

    The exception is a callable that declares **kwargs: it genuinely accepts
    arguments we cannot enumerate, so extras stay allowed there.
    """
    sig = _sig if _sig is not None else _signature(fn)
    req: list[str] = []
    opt: list[str] = []
    types: dict[str, type | tuple[type, ...]] = {}
    takes_var_kwargs = False
    for name, param in sig.parameters.items():
        if name in ("self", "cls"):
            continue
        if param.kind is param.VAR_KEYWORD:
            takes_var_kwargs = True
            continue
        if param.kind is param.VAR_POSITIONAL:
            continue
        if param.default is inspect.Parameter.empty:
            req.append(name)
        else:
            opt.append(name)
        ann = param.annotation
        if ann is not inspect.Parameter.empty:
            resolved = _resolve_annotation(ann)
            if isinstance(resolved, tuple):
                types[name] = resolved[0] if len(resolved) == 1 else resolved
    if required is not None:
        # A caller-supplied required list overrides which args are mandatory, but
        # every name from the signature is still a known argument.
        opt = [n for n in req + opt if n not in required]
        req = list(required)
    return ToolSchema(
        required=req, types=types, allow_extra=takes_var_kwargs, optional=opt
    )
