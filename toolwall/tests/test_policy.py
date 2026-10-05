"""Policy layer: value constraints, cross rules, fail-closed on rule errors."""

from toolwall import Gate, Policy, ToolSchema, Verdict, in_range, matches, max_len, not_empty, one_of
from toolwall.policy import ends_with, starts_with


def test_constraint_pass_and_fail():
    policy = Policy(constraints={"limit": in_range(1, 100)})
    assert policy.validate({"limit": 50}) == []
    assert policy.validate({"limit": 10_000_000}) != []
    assert policy.validate({"limit": 0}) != []


def test_absent_arg_is_schemas_job():
    policy = Policy(constraints={"limit": in_range(1, 100)})
    assert policy.validate({}) == []


def test_raising_rule_fails_closed():
    policy = Policy(constraints={"limit": in_range(1, 100)})
    errors = policy.validate({"limit": "not-a-number"})
    assert errors and "fails closed" in errors[0]


def test_cross_rule():
    policy = Policy(cross=lambda args: "path traversal" if ".." in args.get("path", "") else None)
    assert policy.validate({"path": "/app/ok.txt"}) == []
    assert policy.validate({"path": "/app/../etc/passwd"}) == ["path traversal"]


def test_cross_rule_raising_fails_closed():
    policy = Policy(cross=lambda args: 1 / 0)
    errors = policy.validate({"x": 1})
    assert errors and "fails closed" in errors[0]


def test_rule_helpers():
    assert one_of("staging", "prod")("staging")
    assert not one_of("staging")("prod")
    assert matches(r"[a-z]+@ourco\.com")("dev@ourco.com")
    assert not matches(r"[a-z]+@ourco\.com")("dev@evil.com")
    assert max_len(5)("abc")
    assert not max_len(2)("abc")
    assert ends_with("@ourco.com")("a@ourco.com")
    assert not ends_with("@ourco.com")("a@ourco.com.evil.net")
    assert starts_with("/app/")("/app/x")
    assert not starts_with("/app/")("/etc/passwd")
    assert not_empty({"id": 1})
    assert not not_empty({})


def test_gate_blocks_on_policy_violation():
    gate = Gate(default="deny")
    gate.register(
        "db_query",
        lambda q, limit=10: {"rows": 1},
        schema=ToolSchema(required=["q"], types={"q": str, "limit": int}),
        policy=Policy(constraints={"limit": in_range(1, 100)}),
    )
    blocked = gate.run({"name": "db_query", "args": {"q": "x", "limit": 10_000_000}})
    assert blocked.verdict is Verdict.BLOCK
    assert not blocked.executed
    allowed = gate.run({"name": "db_query", "args": {"q": "x", "limit": 5}})
    assert allowed.executed


def test_empty_filter_delete_blocked():
    gate = Gate(default="deny")
    gate.register(
        "delete_records",
        lambda filter: {"deleted": 1},
        schema=ToolSchema(required=["filter"], types={"filter": dict}),
        policy=Policy(constraints={"filter": not_empty}),
    )
    result = gate.run({"name": "delete_records", "args": {"filter": {}}})
    assert result.verdict is Verdict.BLOCK
    assert not result.executed


def test_in_range_rejects_non_finite_and_bool():
    rule = in_range(0, 1000)
    for bad in (float("nan"), "nan", "NaN", float("inf"), "-inf", True, False):
        assert not rule(bad), f"in_range accepted {bad!r}"
    for good in (0, 5, 5.5, "7", 1000):
        assert rule(good), f"in_range rejected {good!r}"


def test_openai_json_nan_and_infinity_are_rejected_at_intake():
    gate = Gate(default="deny")
    ran = []
    gate.register("transfer", lambda amount: ran.append(amount),
                  schema=ToolSchema(required=["amount"], types={"amount": (int, float)}),
                  policy=Policy(constraints={"amount": in_range(0, 1000)}))
    for literal in ("NaN", "Infinity", "-Infinity"):
        payload = {"choices": [{"message": {"tool_calls": [{"id": "1", "function": {
            "name": "transfer", "arguments": '{"amount": %s}' % literal}}]}}]}
        result = gate.run(payload)
        assert result.verdict is Verdict.BLOCK, literal
        assert "intake" in result.reason
    assert ran == []


def test_email_domain_allows_one_internal_address():
    from toolwall import email_domain
    rule = email_domain("ourco.com")
    for good in ("ops@ourco.com", "first.last+tag@OURCO.com", "a_b-c@ourco.com"):
        assert rule(good), good


def test_email_domain_rejects_the_ends_with_bypasses():
    from toolwall import email_domain
    rule = email_domain("ourco.com")
    for bad in (
        "attacker@evil.com,ops@ourco.com",
        "attacker@evil.com, ops@ourco.com",
        "attacker@evil.com;ops@ourco.com",
        "attacker@evil.com\r\nBcc: x@ourco.com",
        "x@evil.com@ourco.com",
        "Boss <x@evil.com> ops@ourco.com",
        "ops@ourco.com.evil.net",
        "ops@sub.ourco.com",
        "ops@ourco.com.",
        "ops@ourсo.com",            # Cyrillic 'с'
        "@ourco.com",
        "ops@",
        "",
        None,
        ["ops@ourco.com"],
    ):
        assert not rule(bad), repr(bad)


def test_ends_with_still_admits_comma_lists_so_do_not_use_it_for_email():
    # Documents why email_domain exists: ends_with is a string rule.
    assert ends_with("@ourco.com")("attacker@evil.com,ops@ourco.com")


def test_email_domain_rejects_percent_and_bang_routing():
    # Postfix's allow_percent_hack can rewrite user%host@domain to user@host.
    from toolwall import email_domain
    rule = email_domain("ourco.com")
    assert not rule("attacker%evil.com@ourco.com")
    assert not rule("evil.com!attacker@ourco.com")
