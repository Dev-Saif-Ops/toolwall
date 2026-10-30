"""LangChain middleware, run inside a real create_agent graph with a scripted model.

Skipped unless langchain (>= 1.0) and langgraph are installed.
"""

import asyncio
import itertools

import pytest

pytest.importorskip("langchain.agents.middleware")

from langchain.agents import create_agent  # noqa: E402
from langchain.messages import AIMessage, ToolMessage  # noqa: E402
from langchain.tools import tool  # noqa: E402
from langchain_core.language_models.fake_chat_models import GenericFakeChatModel  # noqa: E402
from langgraph.checkpoint.memory import InMemorySaver  # noqa: E402
from langgraph.types import Command  # noqa: E402

from toolwall import ToolSchema, ToolWall  # noqa: E402
from toolwall import rules as r  # noqa: E402
from toolwall.integrations.langchain import ToolWallMiddleware  # noqa: E402

AWS_KEY = "AKIA" + "IOSFODNN7EXAMPLE"
OWNERS = {"o_9": "c_42", "o_77": "c_7"}
_ids = itertools.count()


class ScriptedModel(GenericFakeChatModel):
    def bind_tools(self, tools, **kwargs):
        return self


def scripted(name, args):
    return ScriptedModel(messages=iter([
        AIMessage(content="", tool_calls=[{"name": name, "args": args, "id": "call_1"}]),
        AIMessage(content="done"),
    ]))


def make(ran, approvals=True):
    wall = ToolWall()

    @tool
    def issue_refund(order_id: str, amount: float) -> str:
        """Refund an order."""
        ran.append((order_id, amount))
        return f"refunded {amount} on {order_id}"

    wall.rule("issue_refund", schema=ToolSchema(required=["order_id", "amount"],
                                                 types={"order_id": str, "amount": (int, float)}),
              amount=r.positive() & r.at_most(500),
              order_id=r.owned_by("customer_id", lookup=OWNERS.get),
              ask_if=r.over("amount", 200))
    return wall, issue_refund, ToolWallMiddleware(wall, approvals=approvals)


def agent_for(model, tools, middleware):
    return create_agent(model, tools, middleware=[middleware], checkpointer=InMemorySaver())


def config():
    return {"configurable": {"thread_id": f"t{next(_ids)}"}}


def tool_messages(state):
    return [m for m in state["messages"] if isinstance(m, ToolMessage)]


def test_allowed_call_runs():
    ran = []
    wall, issue_refund, mw = make(ran)
    agent = agent_for(scripted("issue_refund", {"order_id": "o_9", "amount": 40}), [issue_refund], mw)
    with wall.context(customer_id="c_42"):
        state = agent.invoke({"messages": [("user", "refund")]}, config())
    assert ran == [("o_9", 40)]
    assert "refunded" in tool_messages(state)[0].content


def test_denied_call_does_not_run_and_the_model_gets_a_safe_reason():
    ran = []
    wall, issue_refund, mw = make(ran)
    agent = agent_for(scripted("issue_refund", {"order_id": "o_77", "amount": 40}), [issue_refund], mw)
    with wall.context(customer_id="c_42"):
        state = agent.invoke({"messages": [("user", "refund")]}, config())
    assert ran == []
    msg = tool_messages(state)[0]
    assert msg.status == "error" and "c_7" not in msg.content and "owned_by" not in msg.content


def test_held_call_interrupts_and_runs_once_approved():
    ran = []
    wall, issue_refund, mw = make(ran)
    agent = agent_for(scripted("issue_refund", {"order_id": "o_9", "amount": 300}), [issue_refund], mw)
    cfg = config()
    with wall.context(customer_id="c_42"):
        state = agent.invoke({"messages": [("user", "refund")]}, cfg)
        assert ran == []
        pending = state["__interrupt__"][0].value
        assert pending["toolwall"] == "approval" and pending["tool"] == "issue_refund"
        agent.invoke(Command(resume=True), cfg)
    assert ran == [("o_9", 300)]


def test_held_call_declined_never_runs():
    ran = []
    wall, issue_refund, mw = make(ran)
    agent = agent_for(scripted("issue_refund", {"order_id": "o_9", "amount": 300}), [issue_refund], mw)
    cfg = config()
    with wall.context(customer_id="c_42"):
        agent.invoke({"messages": [("user", "refund")]}, cfg)
        state = agent.invoke(Command(resume=False), cfg)
    assert ran == []
    assert "declined" in tool_messages(state)[0].content


def test_without_approvals_a_held_call_is_refused():
    ran = []
    wall, issue_refund, mw = make(ran, approvals=False)
    agent = agent_for(scripted("issue_refund", {"order_id": "o_9", "amount": 300}), [issue_refund], mw)
    with wall.context(customer_id="c_42"):
        state = agent.invoke({"messages": [("user", "refund")]}, config())
    assert ran == [] and "__interrupt__" not in state
    assert tool_messages(state)[0].status == "error"


def test_secret_in_output_is_withheld_from_the_model():
    wall = ToolWall()

    @tool
    def lookup_customer(customer_id: str) -> str:
        """Look up a customer."""
        return f"plan pro, key {AWS_KEY}"

    wall.rule("lookup_customer", schema=ToolSchema(required=["customer_id"]))
    agent = agent_for(scripted("lookup_customer", {"customer_id": "c_42"}), [lookup_customer],
                      ToolWallMiddleware(wall))
    state = agent.invoke({"messages": [("user", "who")]}, config())
    assert all(AWS_KEY not in str(m.content) for m in state["messages"])


def test_async_agent_goes_through_the_wall():
    ran = []
    wall, issue_refund, mw = make(ran)
    agent = agent_for(scripted("issue_refund", {"order_id": "o_77", "amount": 40}), [issue_refund], mw)

    async def go():
        with wall.context(customer_id="c_42"):
            return await agent.ainvoke({"messages": [("user", "refund")]}, config())

    state = asyncio.run(go())
    assert ran == [] and tool_messages(state)[0].status == "error"


def test_no_context_means_no_refund():
    ran = []
    wall, issue_refund, mw = make(ran)
    agent = agent_for(scripted("issue_refund", {"order_id": "o_9", "amount": 40}), [issue_refund], mw)
    agent.invoke({"messages": [("user", "refund")]}, config())
    assert ran == []
