"""LangChain middleware, run inside a real create_agent graph with a scripted model.

Skipped unless langchain (>= 1.0) and langgraph are installed.
"""

import asyncio
import itertools
from typing import Annotated

import pytest

pytest.importorskip("langchain.agents.middleware")

from langchain.agents import create_agent  # noqa: E402
from langchain.messages import AIMessage, HumanMessage, ToolMessage  # noqa: E402
from langchain.tools import tool  # noqa: E402
from langchain_core.tools import InjectedToolCallId  # noqa: E402
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


def test_a_tool_returning_a_command_has_its_messages_scanned():
    wall = ToolWall()

    @tool
    def lookup_customer(customer_id: str, tool_call_id: Annotated[str, InjectedToolCallId]) -> Command:
        """Look up a customer."""
        return Command(update={"messages": [
            ToolMessage(content=f"plan pro, key {AWS_KEY}", tool_call_id=tool_call_id)]})

    wall.rule("lookup_customer", schema=ToolSchema(required=["customer_id"]))
    agent = agent_for(scripted("lookup_customer", {"customer_id": "c_42"}), [lookup_customer],
                      ToolWallMiddleware(wall))
    state = agent.invoke({"messages": [("user", "who")]}, config())
    assert all(AWS_KEY not in str(m.content) for m in state["messages"])


def test_redacted_arguments_reach_the_tool():
    seen = []
    wall = ToolWall(redact=True)

    @tool
    def note(text: str) -> str:
        """Save a note."""
        seen.append(text)
        return "ok"

    wall.rule("note", schema=ToolSchema(required=["text"], types={"text": str}))
    agent = agent_for(scripted("note", {"text": f"key {AWS_KEY}"}), [note], ToolWallMiddleware(wall))
    agent.invoke({"messages": [("user", "note")]}, config())
    assert len(seen) == 1 and AWS_KEY not in seen[0]


def test_only_true_approves_a_held_call():
    ran = []
    wall, issue_refund, mw = make(ran)
    agent = agent_for(scripted("issue_refund", {"order_id": "o_9", "amount": 300}), [issue_refund], mw)
    cfg = config()
    with wall.context(customer_id="c_42"):
        agent.invoke({"messages": [("user", "refund")]}, cfg)
        agent.invoke(Command(resume="yes"), cfg)
    assert ran == []


def test_an_approved_call_takes_a_budget_slot():
    ran = []
    wall, issue_refund, mw = make(ran)
    wall.budget(max_calls=1)
    agent = agent_for(scripted("issue_refund", {"order_id": "o_9", "amount": 300}), [issue_refund], mw)
    cfg = config()
    with wall.context(customer_id="c_42"):
        state = agent.invoke({"messages": [("user", "refund")]}, cfg)
        assert state["__interrupt__"], "the held call should pause first"
        agent.invoke(Command(resume=True), cfg)
        assert ran == [("o_9", 300)]
        # The approval took the only slot, so the next (allowed) call is refused.
        assert wall.decide("issue_refund", {"order_id": "o_9", "amount": 40}).verdict == "deny"


def test_artifact_carrying_a_secret_is_dropped():
    wall = ToolWall()

    @tool(response_format="content_and_artifact")
    def lookup_customer(customer_id: str):
        """Look up a customer."""
        return "plan pro", {"key": AWS_KEY}

    wall.rule("lookup_customer", schema=ToolSchema(required=["customer_id"]))
    agent = agent_for(scripted("lookup_customer", {"customer_id": "c_42"}), [lookup_customer],
                      ToolWallMiddleware(wall))
    state = agent.invoke({"messages": [("user", "who")]}, config())
    assert tool_messages(state)[0].artifact is None


def test_a_command_message_with_a_secret_in_its_tool_calls_is_withheld():
    wall = ToolWall()

    @tool
    def plan(customer_id: str, tool_call_id: Annotated[str, InjectedToolCallId]) -> Command:
        """Plan the next step."""
        return Command(update={"messages": [
            ToolMessage(content="planned", tool_call_id=tool_call_id),
            AIMessage(content="", tool_calls=[{"name": "x", "args": {"key": AWS_KEY}, "id": "c9"}]),
        ]})

    wall.rule("plan", schema=ToolSchema(required=["customer_id"]))
    agent = agent_for(scripted("plan", {"customer_id": "c_42"}), [plan], ToolWallMiddleware(wall))
    state = agent.invoke({"messages": [("user", "plan")]}, config())
    assert AWS_KEY not in repr(state["messages"])


def test_a_secret_in_another_state_key_withholds_the_command():
    wall = ToolWall()

    @tool
    def lookup(customer_id: str, tool_call_id: Annotated[str, InjectedToolCallId]) -> Command:
        """Look up."""
        return Command(update={"notes": f"key {AWS_KEY}",
                               "messages": [ToolMessage(content="ok", tool_call_id=tool_call_id)]})

    wall.rule("lookup", schema=ToolSchema(required=["customer_id"]))
    mw = ToolWallMiddleware(wall)
    request = type("R", (), {"tool_call": {"name": "lookup", "id": "c1", "args": {}}})()
    out = mw._after(request, lookup.func("c_42", "c1"))
    assert isinstance(out, ToolMessage) and out.status == "error"


def _after(wall, tool_result, name="t"):
    mw = ToolWallMiddleware(wall)
    request = type("R", (), {"tool_call": {"name": name, "id": "call_1", "args": {}}})()
    return mw._after(request, tool_result)


REAL_HISTORY = [
    AIMessage(content="", id="chatcmpl-AqZk3PqL9vT2mN8rB4wY6zA1cE7fG",
              response_metadata={"id": "msg_01Xk3PqL9vT2mN8rB4wY6zA1", "model_name": "gpt-5"},
              tool_calls=[{"name": "transfer", "args": {"to": "bob"},
                           "id": "call_Xk3PqL9vT2mN8rB4wY6zA1cE"}]),
    AIMessage(content="ok", id="toolu_01Q8vT2mN8rB4wY6zA1cE7fGh"),
]


def test_a_handoff_with_real_provider_ids_passes():
    from langgraph.types import Send

    cmd = Command(goto=[Send("bob", {"messages": REAL_HISTORY})],
                  update={"messages": REAL_HISTORY + [
                      ToolMessage(content="handed off", tool_call_id="call_Xk3PqL9vT2mN8rB4wY6zA1cE")]})
    out = _after(ToolWall(), cmd)
    assert isinstance(out, Command)


def test_a_secret_in_a_send_payload_withholds_the_command():
    from langgraph.types import Send

    cmd = Command(update={"messages": [ToolMessage(content="ok", tool_call_id="call_1")]},
                  goto=[Send("model", {"messages": [HumanMessage(content=f"key {AWS_KEY}")]})])
    out = _after(ToolWall(), cmd)
    assert isinstance(out, ToolMessage) and out.status == "error"


def test_a_known_secret_pattern_in_an_id_is_still_caught():
    cmd = Command(update={"messages": [
        ToolMessage(content="ok", tool_call_id="call_1"),
        AIMessage(content="", tool_calls=[{"name": "x", "args": {}, "id": AWS_KEY}])]})
    assert isinstance(_after(ToolWall(), cmd), ToolMessage)


def test_a_message_that_cannot_be_scanned_withholds_the_command():
    class Broken:
        def model_dump(self):
            raise RuntimeError("no")

    cmd = Command(update={"messages": [ToolMessage(content="ok", tool_call_id="call_1"), Broken()]})
    assert isinstance(_after(ToolWall(), cmd), ToolMessage)


THINKING = AIMessage(
    content=[{"type": "thinking", "thinking": "plan the refund",
              "signature": "ErUBCkYIBRgCIkBq3Rz9vT2mN8rB4wY6zA1cE7fGhJ5kLp0QxWs8dF3gH2jK4lM6nO8pQ1rS3tU5vW7xY9z"},
             {"type": "tool_use", "id": "toolu_01Q8vT2mN8rB4wY6zA1cE7fG", "name": "transfer",
              "input": {"to": "bob"}}],
    id="msg_01Xk3PqL9vT2mN8rB4wY6zA1",
    tool_calls=[{"name": "transfer", "args": {"to": "bob"}, "id": "toolu_01Q8vT2mN8rB4wY6zA1cE7fG"}])
RANDOM_SECRET = "Zq8vT2mN8rB4wY6zA1cE7fGhJ5kLp0QxWs8dF3gH"  # no known pattern, high entropy


def _after_with_state(wall, tool_result, state_messages):
    mw = ToolWallMiddleware(wall)
    request = type("R", (), {"tool_call": {"name": "t", "id": "call_1", "args": {}},
                             "state": {"messages": state_messages}})()
    return mw._after(request, tool_result)


def test_a_handoff_after_a_reasoning_model_turn_passes():
    from langgraph.types import Send

    history = [HumanMessage(content="refund o_9", id="h1"), THINKING]
    tm = ToolMessage(content="handed off", tool_call_id="toolu_01Q8vT2mN8rB4wY6zA1cE7fG")
    cmd = Command(graph=Command.PARENT, goto=[Send("bob", {"messages": history + [tm]})],
                  update={"messages": history + [tm]})
    assert isinstance(_after_with_state(ToolWall(), cmd, history), Command)


def test_a_new_message_the_tool_adds_is_still_scanned():
    added = AIMessage(content=f"note {RANDOM_SECRET}", id="new1")
    cmd = Command(update={"messages": [ToolMessage(content="ok", tool_call_id="call_1"), added]})
    assert isinstance(_after_with_state(ToolWall(), cmd, [THINKING]), ToolMessage)


def test_an_id_inside_tool_arguments_gets_the_full_check():
    added = AIMessage(content="", id="new2",
                      tool_calls=[{"name": "x", "args": {"id": RANDOM_SECRET}, "id": "call_9"}])
    cmd = Command(update={"messages": [ToolMessage(content="ok", tool_call_id="call_1"), added]})
    assert isinstance(_after_with_state(ToolWall(), cmd, []), ToolMessage)


def test_a_single_send_is_scanned():
    from langgraph.types import Send

    cmd = Command(goto=Send("model", {"messages": [HumanMessage(content=f"key {AWS_KEY}")]}))
    assert isinstance(_after(ToolWall(), cmd), ToolMessage)


def test_redact_mode_withholds_a_command_message_with_a_secret():
    added = AIMessage(content=f"key {AWS_KEY}", id="new3")
    cmd = Command(update={"messages": [ToolMessage(content="ok", tool_call_id="call_1"), added]})
    out = _after(ToolWall(redact=True), cmd)
    assert isinstance(out, ToolMessage) and AWS_KEY not in str(out.content)
