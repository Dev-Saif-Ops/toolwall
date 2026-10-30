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


# --- round 2 (critic, 0.4.3): annotations people actually write -----------------

from typing import Annotated, Any, List, Optional, Union


def test_optional_and_union_annotations_are_inferred_and_enforced():
    def f(city: str | None, unit: Optional[str] = None, n: Union[int, str] = 1) -> str:
        return f"{city}{unit}{n}"

    wall = ToolWall()
    wall.register("f", f)
    assert wall.call("f", {"city": None}).executed
    assert wall.call("f", {"city": "a", "unit": "c", "n": "x"}).executed
    assert wall.call("f", {"city": 5}).verdict is Verdict.BLOCK
    assert wall.call("f", {"city": "a", "n": 2.5}).verdict is Verdict.BLOCK


def test_generic_containers_check_the_container():
    def f(tags: list[str], meta: dict[str, int], old: List[str]) -> int:
        return len(tags)

    wall = ToolWall()
    wall.register("f", f)
    assert wall.call("f", {"tags": ["a"], "meta": {}, "old": []}).executed
    assert wall.call("f", {"tags": "a", "meta": {}, "old": []}).verdict is Verdict.BLOCK


def test_any_and_annotated_are_callable():
    def f(payload: Any, note: Annotated[str, "free text"]) -> str:
        return note

    wall = ToolWall()
    wall.register("f", f)
    assert wall.call("f", {"payload": {"x": 1}, "note": "hi"}).return_value == "hi"
    assert wall.call("f", {"payload": 1, "note": 2}).verdict is Verdict.BLOCK


def test_float_parameter_accepts_a_json_integer():
    def refund(amount: float) -> str:
        return str(amount)

    wall = ToolWall()
    wall.register("refund", refund)
    assert wall.call("refund", {"amount": 40}).executed
    assert wall.call("refund", {"amount": "40"}).verdict is Verdict.BLOCK


def test_unsupported_annotation_is_not_inferred():
    from typing import Literal

    def f(mode: Literal["a", "b"]) -> str:
        return mode

    wall = ToolWall()
    wall.register("f", f)
    r = wall.call("f", {"mode": "a"})
    assert r.verdict is Verdict.BLOCK and "no schema" in r.reason


def test_kwargs_stops_inference():
    def f(a: str, **extra: str) -> str:
        return a

    wall = ToolWall()
    wall.register("f", f)
    assert wall.call("f", {"a": "x", "b": "y"}).verdict is Verdict.BLOCK


def test_broken_annotation_does_not_break_register():
    ns: dict = {}
    exec("from __future__ import annotations\nimport typing\n"
         "def f(n: typing.DoesNotExist) -> int:\n    return 1\n", ns)
    wall = ToolWall()
    wall.register("f", ns["f"])            # must not raise
    assert wall.call("f", {"n": 1}).verdict is Verdict.BLOCK


def test_annotations_are_evaluated_once_at_registration():
    seen = []
    ns = {"mark": lambda: (seen.append(1), int)[1]}
    exec("from __future__ import annotations\ndef f(n: mark()) -> int:\n    return n\n", ns)
    ToolWall().register("f", ns["f"])
    assert len(seen) == 1


# --- round 3 (critic, 0.4.3) ----------------------------------------------------

from typing import Literal, Protocol, TypedDict


class Filters(TypedDict):
    city: str


class Greeter(Protocol):
    def greet(self) -> str: ...


def test_typeddict_and_protocol_params_are_not_inferred():
    def search(filters: Filters) -> str:
        return "ok"

    def greet(g: Greeter) -> str:
        return "ok"

    def maybe(filters: Optional[Filters] = None) -> str:
        return "ok"

    for name, fn in (("search", search), ("greet", greet), ("maybe", maybe)):
        wall = ToolWall()
        wall.register(name, fn)
        r = wall.call(name, {})
        assert r.verdict is Verdict.BLOCK and "no schema" in r.reason, name
    # and with an explicit schema the TypedDict tool works
    wall = ToolWall()
    wall.register("search", search, schema=ToolSchema(required=["filters"], types={"filters": dict}))
    assert wall.call("search", {"filters": {"city": "Riyadh"}}).executed


def test_union_with_an_unsupported_member_is_not_inferred():
    def f(x: Union[Literal["a"], int]) -> str:
        return "ok"

    wall = ToolWall()
    wall.register("f", f)
    assert "no schema" in wall.call("f", {"x": 1}).reason


def test_union_with_any_accepts_anything():
    def f(x: Union[Any, int]) -> str:
        return "ok"

    wall = ToolWall()
    wall.register("f", f)
    assert wall.call("f", {"x": {"any": "thing"}}).executed
