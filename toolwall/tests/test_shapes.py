"""Secret scanning must reach every shape a tool argument or return value takes.

Found in the 2026-10-05 red-team: the walker only descended into str, dict values
and lists. A sqlite3/psycopg fetchall() (a list of tuples), bytes, a dataclass, an
exception message, or a secret used as a dict KEY all went through unscanned.
"""

import sqlite3
from dataclasses import dataclass

import pytest

from toolwall import Gate, Shield, ToolSchema, Verdict

AWS_KEY = "AKIA" + "IOSFODNN7EXAMPLE"
OPENAI_KEY = "sk-" + "Abc123def456Ghi789jklMNO"


@dataclass
class Row:
    id: int
    secret: str


def gate_returning(value, mode="block"):
    gate = Gate(default="allow", shield=Shield(mode=mode))
    gate.register("tool", lambda: value)
    return gate


def sqlite_rows():
    con = sqlite3.connect(":memory:")
    con.execute("create table users (id int, api_key text)")
    con.execute("insert into users values (1, ?)", (f"deploy key {AWS_KEY}",))
    return con.execute("select * from users").fetchall()  # [(1, '...')]


OUTPUT_SHAPES = {
    "fetchall list[tuple]": sqlite_rows,
    "tuple": lambda: (1, f"key {AWS_KEY}"),
    "set": lambda: {f"key {AWS_KEY}"},
    "frozenset": lambda: frozenset({f"key {AWS_KEY}"}),
    "bytes": lambda: f"key {AWS_KEY}".encode(),
    "bytearray": lambda: bytearray(f"key {AWS_KEY}".encode()),
    "dataclass": lambda: Row(1, f"key {AWS_KEY}"),
    "dict key": lambda: {AWS_KEY: 1},
    "nested tuple in dict": lambda: {"rows": [(1, (2, f"key {AWS_KEY}"))]},
    "plain object": lambda: type("Obj", (), {"__init__": lambda s: setattr(s, "k", AWS_KEY)})(),
}


@pytest.mark.parametrize("shape", OUTPUT_SHAPES)
def test_output_secret_withheld_in_every_shape(shape):
    result = gate_returning(OUTPUT_SHAPES[shape]()).run({"name": "tool", "args": {}})
    assert result.executed
    assert result.return_value is None, f"{shape}: secret returned to the model"
    assert "tool output withheld" in result.error


@pytest.mark.parametrize("shape", OUTPUT_SHAPES)
def test_output_secret_redacted_in_every_shape(shape):
    result = gate_returning(OUTPUT_SHAPES[shape](), mode="redact").run({"name": "tool", "args": {}})
    assert result.executed
    assert AWS_KEY not in repr(result.return_value), f"{shape}: secret survived redaction"
    assert AWS_KEY.encode() not in repr(result.return_value).encode()
    assert result.findings


def test_redact_keeps_container_types():
    value = {"rows": [(1, f"key {AWS_KEY}")], "tags": {"a"}}
    result = gate_returning(value, mode="redact").run({"name": "tool", "args": {}})
    assert isinstance(result.return_value["rows"][0], tuple)
    assert result.return_value["rows"][0][0] == 1
    assert result.return_value["tags"] == {"a"}


def test_clean_output_shapes_untouched():
    value = {"rows": [(1, "alice"), (2, "bob")], "raw": b"ok", "ids": {1, 2}}
    result = gate_returning(value).run({"name": "tool", "args": {}})
    assert result.return_value == value
    assert result.error is None


def test_self_referential_output_is_scanned_without_crashing():
    loop: dict = {"note": f"key {AWS_KEY}"}
    loop["self"] = loop
    result = gate_returning(loop).run({"name": "tool", "args": {}})
    assert result.return_value is None
    assert "tool output withheld" in result.error


def test_output_scan_failure_fails_closed():
    class Hostile:
        def __str__(self):
            raise RuntimeError("cannot render")

        __repr__ = __str__

    gate = Gate(default="allow", shield=Shield(mode="block"))
    gate.register("tool", lambda: [Hostile()])
    result = gate.run({"name": "tool", "args": {}})
    assert result.executed
    assert result.return_value is None
    assert "withheld" in result.error


def test_secret_in_tool_exception_message_is_not_passed_on():
    def failing():
        raise RuntimeError(f"auth failed using api key {OPENAI_KEY}")

    gate = Gate(default="allow", shield=Shield(mode="block"))
    gate.register("tool", failing)
    result = gate.run({"name": "tool", "args": {}})
    assert not result.executed
    assert result.error.startswith("RuntimeError")
    assert OPENAI_KEY not in result.error


def test_secret_as_dict_key_in_args_is_blocked():
    gate = Gate(default="allow", shield=Shield(mode="block"))
    gate.register("delete_records", lambda filter: None)
    result = gate.run({"name": "delete_records", "args": {"filter": {AWS_KEY: "1"}}})
    assert result.verdict is Verdict.BLOCK
    assert not result.executed


def test_secret_as_top_level_arg_name_is_blocked():
    gate = Gate(default="allow", shield=Shield(mode="block"))
    gate.register("tool", lambda **kw: None)
    result = gate.run({"name": "tool", "args": {AWS_KEY: "x"}})
    assert result.verdict is Verdict.BLOCK


def test_secret_as_dict_key_is_redacted_in_args():
    seen = []
    gate = Gate(default="allow", shield=Shield(mode="redact"))
    gate.register("tool", lambda meta: seen.append(meta))
    gate.run({"name": "tool", "args": {"meta": {AWS_KEY: "1"}}})
    assert seen and AWS_KEY not in repr(seen)


def test_deeply_nested_args_block_instead_of_raising():
    deep: dict = {}
    node = deep
    for _ in range(5000):
        node["d"] = {}
        node = node["d"]
    gate = Gate(default="allow", shield=Shield(mode="block"))
    gate.register("tool", lambda **kw: None, schema=ToolSchema())
    result = gate.run({"name": "tool", "args": {"x": deep}})
    assert result.verdict is Verdict.BLOCK
    assert not result.executed
