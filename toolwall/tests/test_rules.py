"""toolwall.rules: business rules for customer-facing agents (0.5)."""

import math
from decimal import Decimal

import pytest

from toolwall import ToolWall, Verdict
from toolwall import rules as r


# --- numbers -------------------------------------------------------------------


def test_at_most_at_least_between_positive():
    assert r.at_most(500)(500) and not r.at_most(500)(500.01)
    assert r.at_least(1)(1) and not r.at_least(1)(0)
    assert r.between(1, 10)(Decimal("5")) and not r.between(1, 10)(11)
    assert r.positive()(0.01) and not r.positive()(0) and not r.positive()(-1)


@pytest.mark.parametrize("bad", [float("nan"), float("inf"), True, False, "40", None, [1], {"a": 1}])
def test_number_rules_reject_non_numbers(bad):
    for rule in (r.at_most(500), r.at_least(0), r.between(0, 10**9), r.positive()):
        assert not rule(bad), (rule.__name__, bad)


# --- composition -----------------------------------------------------------------


def test_and_or_not_compose_and_name_themselves():
    rule = r.positive() & r.at_most(500)
    assert rule(40) and not rule(0) and not rule(501)
    either = r.one_of("a") | r.one_of("b")
    assert either("b") and not either("c")
    assert (~r.one_of("x"))("y") and not (~r.one_of("x"))("x")
    assert "positive" in rule.__name__ and "at_most(500)" in rule.__name__


def test_one_of_is_type_exact():
    rule = r.one_of(1, "a")
    assert rule(1) and rule("a")
    assert not rule(True) and not rule(1.0) and not rule("1")


# --- recipients and context ------------------------------------------------------


def test_equals_context_reads_the_current_context():
    wall = ToolWall()
    rule = r.equals_context("customer_email")
    assert not rule("amal@example.com")  # no context set: fail closed
    with wall.context(customer_email="amal@example.com"):
        assert rule("amal@example.com")
        assert not rule("other@example.com")


def test_email_rule_composes_with_context():
    wall = ToolWall()
    rule = r.email_domain("ourco.com") | r.equals_context("customer_email")
    with wall.context(customer_email="amal@example.com"):
        assert rule("ops@ourco.com") and rule("amal@example.com")
        assert not rule("x@evil.com,ops@ourco.com")


def test_owned_by_checks_the_lookup_against_context():
    owners = {"o_9": "c_42", "o_77": "c_7"}
    rule = r.owned_by("customer_id", lookup=owners.get)
    wall = ToolWall()
    with wall.context(customer_id="c_42"):
        assert rule("o_9")
        assert not rule("o_77")
        assert not rule("o_missing")  # lookup returns None: not owned
    assert not rule("o_9")  # no context: fail closed


def test_owned_by_fails_closed_on_lookup_errors_and_async_lookups():
    import asyncio
    import warnings

    def boom(_):
        raise RuntimeError("db down")

    async def async_lookup(_):
        return "c_42"

    wall = ToolWall()
    with wall.context(customer_id="c_42"):
        with pytest.raises(RuntimeError):
            r.owned_by("customer_id", lookup=boom)("o_9")  # Policy turns a raise into a block
        with warnings.catch_warnings():
            warnings.simplefilter("error")
            assert not r.owned_by("customer_id", lookup=async_lookup)("o_9")


# --- data access -----------------------------------------------------------------


@pytest.mark.parametrize("sql", [
    "SELECT * FROM orders WHERE customer_id = 42",
    "select id from t limit 5",
    "WITH x AS (SELECT 1) SELECT * FROM x",
    "SELECT * FROM t;",
])
def test_sql_readonly_allows_reads(sql):
    assert r.sql_readonly()(sql)


@pytest.mark.parametrize("sql", [
    "DELETE FROM orders",
    "SELECT 1; DROP TABLE orders",
    "UPDATE t SET a = 1",
    "INSERT INTO t VALUES (1)",
    "SELECT * INTO backup FROM orders",
    "WITH x AS (DELETE FROM t RETURNING *) SELECT * FROM x",
    "SELECT 1 -- harmless\n; DROP TABLE t",
    "SELECT /* */ 1; TRUNCATE t",
    "GRANT ALL ON t TO public",
    "",
    123,
])
def test_sql_readonly_blocks_writes_and_stacking(sql):
    assert not r.sql_readonly()(sql)


def test_path_under_keeps_paths_inside_root(tmp_path):
    root = tmp_path / "app"
    (root / "data").mkdir(parents=True)
    (root / "data" / "a.txt").write_text("x")
    (root / ".env").write_text("SECRET=1")
    rule = r.path_under(str(root))
    assert rule(str(root / "data" / "a.txt"))
    assert not rule(str(root / ".." / "etc" / "passwd"))
    assert not rule("/etc/passwd")
    assert not rule(str(root / ".env"))
    assert not rule(str(root / "keys" / "id.pem"))


def test_path_under_follows_symlinks_out_of_root(tmp_path):
    root = tmp_path / "app"
    root.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("x")
    (root / "link.txt").symlink_to(outside)
    assert not r.path_under(str(root))(str(root / "link.txt"))


def test_path_under_resolves_relative_paths_against_root(tmp_path):
    root = tmp_path / "app"
    (root / "data").mkdir(parents=True)
    rule = r.path_under(str(root))
    assert rule("data/a.txt")
    assert not rule("../outside.txt")


@pytest.mark.parametrize("url,ok", [
    ("https://api.ourco.com/v1/x", True),
    ("https://API.OURCO.COM/x", True),
    ("http://api.ourco.com/x", False),           # scheme not allowed
    ("https://api.ourco.com.evil.net/x", False),
    ("https://evil.net/?u=https://api.ourco.com", False),
    ("https://user@api.ourco.com/x", False),      # userinfo hides the real host in some parsers
    ("https://api.ourco.com:8443/x", True),
    ("api.ourco.com/x", False),
    ("", False),
])
def test_url_host(url, ok):
    assert r.url_host("api.ourco.com")(url) is ok


# --- ask_if ----------------------------------------------------------------------


def test_over_predicate():
    pred = r.over("amount", 200)
    assert pred({"amount": 250}) and not pred({"amount": 200})
    assert pred({"amount": float("nan")})  # not a clean number: ask a human
    assert not pred({})  # absent: schema decides presence


# --- rules on a real wall ----------------------------------------------------------


def refund(order_id: str, amount: float) -> str:
    return f"refunded {amount} on {order_id}"


def build():
    owners = {"o_9": "c_42", "o_77": "c_7"}
    wall = ToolWall()
    wall.register("issue_refund", refund)
    wall.rule("issue_refund",
              amount=r.positive() & r.at_most(500),
              order_id=r.owned_by("customer_id", lookup=owners.get),
              ask_if=r.over("amount", 200))
    return wall


def test_rule_on_a_registered_tool():
    wall = build()
    with wall.context(customer_id="c_42"):
        assert wall.call("issue_refund", {"order_id": "o_9", "amount": 40}).executed
        assert wall.call("issue_refund", {"order_id": "o_9", "amount": 5000}).blocked
        assert wall.call("issue_refund", {"order_id": "o_77", "amount": 40}).blocked
        assert wall.call("issue_refund", {"order_id": "o_9", "amount": 300}).needs_approval
    assert wall.call("issue_refund", {"order_id": "o_9", "amount": 40}).blocked  # no context


def test_rule_replaces_the_previous_policy_but_keeps_the_schema():
    wall = build()
    wall.rule("issue_refund", amount=r.at_most(10))
    with wall.context(customer_id="c_42"):
        assert wall.call("issue_refund", {"order_id": "o_77", "amount": 5}).executed
        assert wall.call("issue_refund", {"order_id": "o_9", "amount": 11}).blocked
        assert wall.call("issue_refund", {"order_id": "o_9", "amount": "x"}).blocked  # schema kept


def test_rule_on_an_unknown_tool_needs_a_schema():
    wall = ToolWall()
    with pytest.raises(ValueError):
        wall.rule("Bash", command=r.one_of("ls"))


def test_ask_if_that_raises_or_is_async_fails_closed():
    def broken(args):
        raise RuntimeError("x")

    async def async_pred(args):
        return False

    for pred in (broken, async_pred):
        wall = ToolWall()
        wall.register("issue_refund", refund)
        wall.rule("issue_refund", ask_if=pred)
        res = wall.call("issue_refund", {"order_id": "o_9", "amount": 1})
        assert res.verdict is Verdict.BLOCK
