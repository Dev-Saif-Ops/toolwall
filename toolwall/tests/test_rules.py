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
            # Raises (the policy blocks it) rather than returning False, which ~ would invert.
            with pytest.raises(TypeError):
                r.owned_by("customer_id", lookup=async_lookup)("o_9")


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


# --- critic round 1 (0.5) ----------------------------------------------------------

import warnings


def _quiet(fn):
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        return fn()


@pytest.mark.parametrize("combine", ["and_left", "and_right", "or", "invert", "wrap"])
def test_composed_async_check_fails_closed(combine):
    async def is_theirs(value):
        return True

    plain = r.max_len(20)
    rule = {
        "and_left": lambda: r.Rule(is_theirs, "async") & plain,
        "and_right": lambda: plain & is_theirs,
        "or": lambda: r.one_of("never") | is_theirs,
        "invert": lambda: ~r.Rule(is_theirs, "async"),
        "wrap": lambda: r.Rule(is_theirs, "async"),
    }[combine]()
    ran = []
    wall = ToolWall()
    wall.register("issue_refund", lambda order_id: ran.append(order_id),
                  schema=__import__("toolwall").ToolSchema(required=["order_id"]))
    wall.rule("issue_refund", order_id=rule)
    res = _quiet(lambda: wall.call("issue_refund", {"order_id": "o_77"}))
    if combine == "invert":
        assert res.blocked  # ~ of an unreadable check is still unreadable: block
    else:
        assert res.blocked and ran == []


def test_plain_callables_compose_on_either_side():
    rule = (lambda v: v == "a") | r.one_of("b")
    assert rule("a") and rule("b") and not rule("c")
    both = (lambda v: isinstance(v, str)) & r.max_len(2)
    assert both("ab") and not both("abc")


@pytest.mark.parametrize("sql", [
    "SELECT '--', 1; DROP TABLE t",
    "SELECT '/*'; DROP TABLE t; SELECT '*/'",
    "SELECT 1 AS \"'\"; DROP TABLE t; SELECT 1 AS \"'\"",
    "SELECT $$ ' $$; DROP TABLE t; SELECT $$ ' $$",
    "SELECT $tag$ x $tag$; DROP TABLE t",
    "SELECT 'it\\'s'; DROP TABLE t; SELECT ''",
    "SELECT 'unterminated",
    "SELECT 1 /* unterminated",
    "SELECT 1; SELECT 2",
])
def test_sql_readonly_quoting_bypasses_are_blocked(sql):
    assert not r.sql_readonly()(sql)


def test_sql_readonly_still_allows_quoted_keywords():
    assert r.sql_readonly()("SELECT 'delete; drop' AS note, \"update\" FROM t WHERE a = 'it''s'")


@pytest.mark.parametrize("sql", [
    # critic round 2: dialect forms the lexer can't agree on with every database
    "WITH x AS (SELECT 1 AS [']) DELETE FROM orders --'])",
    "WITH x AS (SELECT 1 AS a$q$) DELETE FROM orders -- $q$",
    "SELECT 1 AS [']; DROP TABLE t; SELECT 1 AS [']",
    "SELECT 1 AS x$a$ ; DROP TABLE t; SELECT 1 AS y$a$",
    "SELECT 1 --x\r; DROP TABLE t",
    "SELECT 1 /* /* */ ' */ ; DROP TABLE t; -- '",
    "SELECT $a$ $$ ' $a$; DROP TABLE t; -- '",
    'SELECT "\\"" ; DROP TABLE t; -- "',
    "SELECT 1 # '\n; DROP TABLE t; -- '",
    "SELECT * FROM users /*! INTO OUTFILE '/tmp/x' */",
    "SELECT 1--1; DROP TABLE t",
    "SELECT `a` FROM t",
    "SELECT $1",
    "SELECT 1\r",
    "SELECT 1 \uff1b DROP TABLE t",
    "LOAD DATA INFILE 'x' INTO TABLE t",
    "SELECT 1 FROM t -- trailing comment",
])
def test_sql_readonly_refuses_dialect_ambiguous_forms(sql):
    assert not r.sql_readonly()(sql)


@pytest.mark.parametrize("sql", [
    "SELECT id, name FROM customers WHERE id = 42",
    "SELECT * FROM orders WHERE note = 'it''s here' AND \"from\" = 'x'",
    "WITH recent AS (SELECT * FROM orders WHERE created > '2026-01-01') SELECT count(*) FROM recent",
    "select a.id from a join b on a.id = b.a_id where b.x in (1, 2, 3) order by a.id limit 10;",
    "SELECT 'café' AS name",
])
def test_sql_readonly_allows_ordinary_portable_reads(sql):
    assert r.sql_readonly()(sql)


def test_sql_readonly_blocks_a_real_single_statement_delete_in_sqlite():
    import sqlite3

    con = sqlite3.connect(":memory:")
    con.execute("create table orders (id)")
    con.executemany("insert into orders values (?)", [(1,), (2,)])
    for sql in ("WITH x AS (SELECT 1 AS [']) DELETE FROM orders --'])",
                "WITH x AS (SELECT 1 AS a$q$) DELETE FROM orders -- $q$"):
        if r.sql_readonly()(sql):
            con.execute(sql)
    assert con.execute("select count(*) from orders").fetchone()[0] == 2


def test_sql_readonly_stacked_queries_really_are_blocked_in_sqlite():
    import sqlite3

    for sql in ("SELECT '--', 1; DROP TABLE t", "SELECT 1 AS \"'\"; DROP TABLE t; SELECT 1 AS \"'\""):
        con = sqlite3.connect(":memory:")
        con.execute("create table t (a)")
        if r.sql_readonly()(sql):
            con.executescript(sql)
        assert con.execute("select count(*) from sqlite_master where name='t'").fetchone()[0] == 1


@pytest.mark.parametrize("name", [".ENV", ".Env", "secret.PEM", "ID_RSA", ".env.LOCAL"])
def test_path_under_deny_list_ignores_case(tmp_path, name):
    root = tmp_path / "app"
    root.mkdir()
    assert not r.path_under(str(root))(name)


def test_path_under_rejects_a_sibling_with_the_same_prefix(tmp_path):
    (tmp_path / "app").mkdir()
    (tmp_path / "app2").mkdir()
    assert not r.path_under(str(tmp_path / "app"))(str(tmp_path / "app2" / "x.txt"))


def test_number_rules_compare_exactly():
    assert not r.at_most(500)(Decimal("500.0000000000000000001"))
    assert not r.at_most(2**53)(2**53 + 1)
    assert r.positive()(10**400)
    assert not r.at_most(10)(10**400)


def test_owned_by_is_type_strict():
    wall = ToolWall()
    with wall.context(customer_id=1):
        assert not r.owned_by("customer_id", lookup=lambda _: True)("o")
        assert not r.owned_by("customer_id", lookup=lambda _: 1.0)("o")
        assert r.owned_by("customer_id", lookup=lambda _: 1)("o")



def test_negated_owned_by_with_an_async_lookup_fails_closed():
    async def owner_of(_):
        return "c_42"

    wall = ToolWall()
    wall.register("rate_listing", lambda listing_id: "rated",
                  schema=__import__("toolwall").ToolSchema(required=["listing_id"]))
    wall.rule("rate_listing", listing_id=~r.owned_by("customer_id", lookup=owner_of))
    with wall.context(customer_id="c_42"):
        res = _quiet(lambda: wall.call("rate_listing", {"listing_id": "l_1"}))
    assert res.blocked and not res.executed


def test_rule_returning_a_lazy_value_fails_closed():
    import concurrent.futures

    def gen_rule(v):
        yield True

    fut = concurrent.futures.Future()
    for fn in (gen_rule, lambda v: fut):
        with pytest.raises(TypeError):
            r.Rule(fn, "lazy")("x")


def test_decimal_infinity_is_not_a_number():
    assert not r.positive()(Decimal("Infinity"))
    assert not r.at_least(0)(Decimal("Infinity"))
