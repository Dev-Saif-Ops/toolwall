"""The first thing a new user writes should work (0.4.3).

Audit 2026-10-30: `wall.register("get_weather", get_weather)` followed by a call
was blocked with "no schema registered", and the fix (infer_schema=True) was in
neither README. ToolWall now infers the schema when every parameter is
annotated, so the signature itself is the declaration. Unannotated functions
still need an explicit schema, and Gate's default-deny is unchanged.
"""

from toolwall import Gate, ToolSchema, ToolWall, Verdict


def get_weather(city: str, days: int = 1) -> str:
    return f"{city}:{days}"


def untyped(city, days=1):
    return city


def test_fully_annotated_function_works_without_a_schema():
    wall = ToolWall()
    wall.register("get_weather", get_weather)
    r = wall.call("get_weather", {"city": "Delhi"})
    assert r.executed and r.return_value == "Delhi:1"


def test_inferred_schema_still_checks_types_and_unknown_args():
    wall = ToolWall()
    wall.register("get_weather", get_weather)
    assert wall.call("get_weather", {"city": 5}).verdict is Verdict.BLOCK
    assert wall.call("get_weather", {"city": "a", "bcc": "x"}).verdict is Verdict.BLOCK
    assert wall.call("get_weather", {}).verdict is Verdict.BLOCK


def test_unannotated_function_is_still_denied_by_default():
    wall = ToolWall()
    wall.register("untyped", untyped)
    r = wall.call("untyped", {"city": "a"})
    assert r.verdict is Verdict.BLOCK and "no schema" in r.reason


def test_partly_annotated_function_is_not_inferred():
    def half(city: str, days=1):
        return city

    wall = ToolWall()
    wall.register("half", half)
    assert wall.call("half", {"city": "a"}).verdict is Verdict.BLOCK


def test_explicit_opt_out_and_explicit_schema_win():
    wall = ToolWall()
    wall.register("get_weather", get_weather, infer_schema=False)
    assert wall.call("get_weather", {"city": "a"}).verdict is Verdict.BLOCK
    wall2 = ToolWall()
    wall2.register("get_weather", get_weather, schema=ToolSchema(required=["city", "days"]))
    assert wall2.call("get_weather", {"city": "a"}).verdict is Verdict.BLOCK


def test_gate_default_is_unchanged():
    gate = Gate()
    gate.register("get_weather", get_weather)
    assert gate.run({"name": "get_weather", "args": {"city": "a"}}).verdict is Verdict.BLOCK


def test_async_annotated_function_is_inferred_too():
    import asyncio

    async def lookup(id: str) -> str:
        return id

    wall = ToolWall()
    wall.register("lookup", lookup)
    assert asyncio.run(wall.acall("lookup", {"id": "x"})).return_value == "x"


def test_string_annotations_are_resolved_and_enforced():
    ns: dict = {}
    exec("from __future__ import annotations\ndef f(n: int) -> int:\n    return n\n", ns)
    wall = ToolWall()
    wall.register("f", ns["f"])
    assert wall.call("f", {"n": 2}).return_value == 2
    assert wall.call("f", {"n": "2"}).verdict is Verdict.BLOCK


def test_missing_return_annotation_is_not_inferred():
    def no_return(city: str):
        return city

    wall = ToolWall()
    wall.register("no_return", no_return)
    assert wall.call("no_return", {"city": "a"}).verdict is Verdict.BLOCK


def test_zero_arg_typed_function_is_inferred_and_rejects_args():
    def ping() -> str:
        return "pong"

    wall = ToolWall()
    wall.register("ping", ping)
    assert wall.call("ping").return_value == "pong"
    assert wall.call("ping", {"x": 1}).verdict is Verdict.BLOCK
