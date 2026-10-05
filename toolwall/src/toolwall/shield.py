"""Secret detection and redaction at the toolwall checkpoint (D-019).

Findings and audit events carry the pattern class and location only, NEVER the
secret value. Detection is pattern + entropy based and is never 100%; the
detection tests define exactly what is covered. Structureless generic passwords
are out of detection scope by design.
"""

from __future__ import annotations

import dataclasses
import datetime as _dt
import decimal
import enum
import math
import numbers
import re
import uuid
from collections import Counter
from collections.abc import Mapping
from collections.abc import Set as AbstractSet
from dataclasses import dataclass
from typing import Any, Iterator, Literal

Mode = Literal["redact", "block", "warn"]

DEFAULT_PATTERNS: tuple[tuple[str, "re.Pattern[str]"], ...] = (
    ("private-key-block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("aws-access-key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("stripe-key", re.compile(r"\b[rs]k_(?:live|test)_[A-Za-z0-9]{16,}\b")),
    ("slack-token", re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}\b")),
    ("openai-key", re.compile(r"\bsk-[A-Za-z0-9_\-]{20,}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{4,}\b")),
    (
        "credential-assignment",
        re.compile(
            r"(?i)\b(?:api[_-]?key|secret|token|password|passwd)\b\s*[:=]\s*['\"]?(?P<val>[^\s'\"]{8,})"
        ),
    ),
)

_ENTROPY_CANDIDATE = re.compile(r"\b[A-Za-z0-9+/=_\-]{24,}\b")


def shannon_entropy(text: str) -> float:
    """Bits per character over the string's own distribution."""
    if not text:
        return 0.0
    counts = Counter(text)
    total = len(text)
    return -sum((n / total) * math.log2(n / total) for n in counts.values())


@dataclass
class Finding:
    """Where a secret-shaped value was seen. Deliberately value-free."""

    kind: str
    start: int
    end: int
    arg: str | None = None
    placeholder: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "start": self.start,
            "end": self.end,
            "arg": self.arg,
            "placeholder": self.placeholder,
        }


class Shield:
    """Scan/redact secrets in text and in tool-call args.

    Modes (used by Gate when attached):
      block  -> any finding blocks the call (recommended for tool args)
      redact -> values are replaced with placeholders, call proceeds
      warn   -> findings are recorded, call proceeds unchanged

    The placeholder-to-value vault lives only in process memory.
    """

    def __init__(
        self,
        mode: Mode = "redact",
        *,
        patterns: tuple[tuple[str, "re.Pattern[str]"], ...] = DEFAULT_PATTERNS,
        entropy: bool = True,
        entropy_threshold: float = 4.5,
        allowlist: tuple[str, ...] | set[str] = (),
        scan_output: bool = True,
    ) -> None:
        if mode not in ("redact", "block", "warn"):
            raise ValueError(f"mode must be redact|block|warn, got {mode!r}")
        self.mode: Mode = mode
        self.patterns = patterns
        self.entropy = entropy
        self.entropy_threshold = entropy_threshold
        self.allowlist = set(allowlist)
        # Also apply this shield to tool return values, not just call arguments.
        self.scan_output = scan_output
        self._vault: dict[str, str] = {}
        self._counts: dict[str, int] = {}

    # -- scanning ------------------------------------------------------------

    def scan(self, text: str) -> list[Finding]:
        if not isinstance(text, str) or not text:
            return []
        spans: list[tuple[int, int, str]] = []
        for kind, pattern in self.patterns:
            for match in pattern.finditer(text):
                if "val" in (match.groupdict() or {}):
                    start, end = match.span("val")
                else:
                    start, end = match.span()
                if text[start:end] in self.allowlist:
                    continue
                spans.append((start, end, kind))
        if self.entropy:
            for match in _ENTROPY_CANDIDATE.finditer(text):
                value = match.group()
                if value in self.allowlist:
                    continue
                if shannon_entropy(value) >= self.entropy_threshold:
                    spans.append((match.start(), match.end(), "high-entropy-string"))
        spans.sort(key=lambda s: (s[0], -s[1]))
        findings: list[Finding] = []
        last_end = -1
        for start, end, kind in spans:
            if start < last_end:
                continue
            findings.append(Finding(kind=kind, start=start, end=end))
            last_end = end
        return findings

    def scan_args(self, args: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        for path, text in _walk_strings(args):
            for f in self.scan(text):
                f.arg = path
                findings.append(f)
        return findings

    # -- redaction -----------------------------------------------------------

    def redact_text(self, text: str) -> tuple[str, list[Finding]]:
        findings = self.scan(text)
        out = text
        for f in reversed(findings):
            placeholder = self._placeholder(f.kind)
            self._vault[placeholder] = text[f.start : f.end]
            f.placeholder = placeholder
            out = out[: f.start] + placeholder + out[f.end :]
        return out, findings

    def redact_args(self, args: dict[str, Any]) -> tuple[dict[str, Any], list[Finding]]:
        """Redact secrets anywhere in args, keys included, keeping container types.

        Raises on input it cannot walk safely (a reference cycle, nesting deeper
        than the interpreter allows, an object whose str() raises); the gate turns
        that into a block or a withheld output, never into a pass-through.
        """
        findings: list[Finding] = []
        active: set[int] = set()

        def text(value: str, path: str) -> str:
            clean, found = self.redact_text(value)
            for f in found:
                f.arg = path
            findings.extend(found)
            return clean

        def transform(value: Any, path: str) -> Any:
            if isinstance(value, str):
                return text(value, path)
            if isinstance(value, (bytes, bytearray)):
                decoded = bytes(value).decode("utf-8", "replace")
                clean = text(decoded, path)
                return value if clean == decoded else type(value)(clean.encode("utf-8"))
            if _is_inert(value):
                return value
            if id(value) in active:
                raise ValueError(f"reference cycle at {path or 'value'}")
            active.add(id(value))
            try:
                if isinstance(value, Mapping):
                    return {
                        transform(k, _key_path(path)): transform(v, _child_path(path, k))
                        for k, v in value.items()
                    }
                if isinstance(value, tuple) and hasattr(value, "_fields"):  # namedtuple
                    return type(value)(*(transform(v, f"{path}[{i}]") for i, v in enumerate(value)))
                if isinstance(value, (list, tuple)):
                    return type(value)(transform(v, f"{path}[{i}]") for i, v in enumerate(value))
                if isinstance(value, AbstractSet):
                    return type(value)(transform(v, f"{path}[{i}]") for i, v in enumerate(value))
                # Anything else (a dataclass, a driver row, an arbitrary object) cannot be
                # rebuilt with its secret removed. If it carries one, replace it whole.
                found = self.scan_args({"v": value})
                if not found:
                    return value
                for f in found:
                    f.arg = path
                findings.extend(found)
                return self._placeholder("object")
            finally:
                active.discard(id(value))

        clean_args = {
            transform(k, _key_path("")): transform(v, _child_path("", k)) for k, v in args.items()
        }
        return clean_args, findings

    def restore(self, text: str) -> str:
        for placeholder, value in self._vault.items():
            text = text.replace(placeholder, value)
        return text

    def _placeholder(self, kind: str) -> str:
        self._counts[kind] = self._counts.get(kind, 0) + 1
        return f"[REDACTED:{kind}-{self._counts[kind]}]"


# Values that cannot carry free text from the model or a data source.
_INERT = (
    numbers.Number, decimal.Decimal, _dt.date, _dt.time, _dt.timedelta, uuid.UUID,
    enum.Enum, type(None),
)


def _is_inert(value: Any) -> bool:
    return isinstance(value, _INERT)


def _child_path(path: str, key: Any) -> str:
    return f"{path}.{key}" if path else str(key)


def _key_path(path: str) -> str:
    return f"{path}.<key>" if path else "<key>"


def _walk_strings(value: Any, path: str = "") -> Iterator[tuple[str, str]]:
    """Yield (path, text) for every piece of text reachable from value.

    Iterative, so nesting depth cannot raise RecursionError, and cycle-safe.
    Covers str, bytes, mapping keys and values, list/tuple/set, dataclasses, and
    objects with attributes; anything else is scanned through str(). A str()
    that raises propagates, and callers treat that as fail-closed.
    """
    seen: set[int] = set()
    stack: list[tuple[Any, str]] = [(value, path)]
    while stack:
        item, where = stack.pop()
        if isinstance(item, str):
            yield where or "value", item
            continue
        if isinstance(item, (bytes, bytearray, memoryview)):
            yield where or "value", bytes(item).decode("utf-8", "replace")
            continue
        if _is_inert(item):
            continue
        if id(item) in seen:
            continue
        seen.add(id(item))
        if isinstance(item, Mapping):
            for k, v in item.items():
                stack.append((k, _key_path(where)))
                stack.append((v, _child_path(where, k)))
        elif isinstance(item, (list, tuple, AbstractSet)):
            for i, v in enumerate(item):
                stack.append((v, f"{where}[{i}]"))
        elif dataclasses.is_dataclass(item) and not isinstance(item, type):
            for fld in dataclasses.fields(item):
                stack.append((getattr(item, fld.name, None), _child_path(where, fld.name)))
        elif callable(getattr(item, "keys", None)) and hasattr(item, "__getitem__"):
            # Row-like objects (sqlite3.Row, many driver records).
            for k in item.keys():
                stack.append((k, _key_path(where)))
                stack.append((item[k], _child_path(where, k)))
        elif hasattr(item, "__dict__") and not isinstance(item, type):
            stack.append((vars(item), where))
            yield where or "value", str(item)
        else:
            yield where or "value", str(item)
