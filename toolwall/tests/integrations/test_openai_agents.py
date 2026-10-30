"""OpenAI Agents SDK adapter, run inside the real Runner with a scripted model.

Skipped unless openai-agents is installed (CI installs it in its own job).
"""

import asyncio
import json

import pytest

agents = pytest.importorskip("agents")

from agents import Agent, Runner, function_tool  # noqa: E402
from agents.items import ModelResponse  # noqa: E402
from agents.models.interface import Model  # noqa: E402
from agents.usage import Usage  # noqa: E402
from openai.types.responses import (  # noqa: E402
    ResponseFunctionToolCall,
    ResponseOutputMessage,
    ResponseOutputText,
)

from toolwall import ToolWall  # noqa: E402
from toolwall import rules as r  # noqa: E402
from toolwall.integrations.openai_agents import guard_tool, guardrails  # noqa: E402

AWS_KEY = "AKIA" + "IOSFODNN7EXAMPLE"
OWNERS = {"o_9": "c_42", "o_77": "c_7"}


class ScriptedModel(Model):
    """Calls one tool with fixed arguments, then answers with text. Records
    every input it was given, so tests can see what the model was told."""

    def __init__(self, tool: str, args: dict):
        self.tool, self.args, self.seen = tool, args, []

    async def get_response(self, system_instructions, input, model_settings, tools,
                           output_schema, handoffs, tracing, **kwargs):
        self.seen.append(input)
        if len(self.seen) == 1:
            item = ResponseFunctionToolCall(type="function_call", call_id="c1", id="fc1",
                                            name=self.tool, arguments=json.dumps(self.args))
        else:
            item = ResponseOutputMessage(id="m1", type="message", role="assistant", status="completed",
                                         content=[ResponseOutputText(type="output_text", text="done",
                                                                     annotations=[])])
        return ModelResponse(output=[item], usage=Usage(), response_id=None)

    def stream_response(self, *a, **k):  # pragma: no cover
        raise NotImplementedError


def tool_output_seen(model: ScriptedModel) -> str:
    """The function_call_output the model received on its second turn."""
    for item in model.seen[-1]:
        if isinstance(item, dict) and item.get("type") == "function_call_output":
            return str(item.get("output"))
    raise AssertionError("no tool output reached the model")


def make(ran):
    wall = ToolWall()

    @guard_tool(wall)
    def issue_refund(order_id: str, amount: int | float) -> str:
        ran.append((order_id, amount))
        return f"refunded {amount} on {order_id}"

    wall.rule("issue_refund", schema=__import__("toolwall").ToolSchema(
        required=["order_id", "amount"], types={"order_id": str, "amount": (int, float)}),
        amount=r.positive() & r.at_most(500),
        order_id=r.owned_by("customer_id", lookup=OWNERS.get),
        ask_if=r.over("amount", 200))
    return wall, issue_refund


def run(agent, prompt="go"):
    return asyncio.run(Runner.run(agent, prompt))


def test_allowed_call_runs():
    ran = []
    wall, tool = make(ran)
    model = ScriptedModel("issue_refund", {"order_id": "o_9", "amount": 40})
    with wall.context(customer_id="c_42"):
        run(Agent(name="support", model=model, tools=[tool]))
    assert ran == [("o_9", 40)]
    assert "refunded" in tool_output_seen(model)


def test_denied_call_does_not_run_and_the_model_gets_a_safe_reason():
    ran = []
    wall, tool = make(ran)
    model = ScriptedModel("issue_refund", {"order_id": "o_77", "amount": 40})
    with wall.context(customer_id="c_42"):
        run(Agent(name="support", model=model, tools=[tool]))
    assert ran == []
    told = tool_output_seen(model)
    assert "order_id" in told and "owned_by" not in told and "c_7" not in told


def test_held_call_pauses_for_approval_and_runs_once_approved():
    ran = []
    wall, tool = make(ran)
    model = ScriptedModel("issue_refund", {"order_id": "o_9", "amount": 300})
    agent = Agent(name="support", model=model, tools=[tool])
    with wall.context(customer_id="c_42"):
        result = run(agent)
        assert ran == []
        assert result.interruptions, "the SDK should pause for approval"
        state = result.to_state()
        state.approve(result.interruptions[0])
        asyncio.run(Runner.run(agent, state))
    assert ran == [("o_9", 300)]


def test_held_call_declined_never_runs():
    ran = []
    wall, tool = make(ran)
    model = ScriptedModel("issue_refund", {"order_id": "o_9", "amount": 300})
    agent = Agent(name="support", model=model, tools=[tool])
    with wall.context(customer_id="c_42"):
        result = run(agent)
        state = result.to_state()
        state.reject(result.interruptions[0])
        asyncio.run(Runner.run(agent, state))
    assert ran == []


def test_without_a_tool_name_a_held_call_is_rejected_not_run():
    ran = []
    wall, _ = make(ran)

    @function_tool(**guardrails(wall))
    def issue_refund(order_id: str, amount: int | float) -> str:
        ran.append(order_id)
        return "x"

    model = ScriptedModel("issue_refund", {"order_id": "o_9", "amount": 300})
    with wall.context(customer_id="c_42"):
        result = run(Agent(name="support", model=model, tools=[issue_refund]))
    assert ran == [] and not result.interruptions
    assert "approval" in tool_output_seen(model)


def test_secret_in_output_is_withheld_from_the_model():
    wall = ToolWall()

    @guard_tool(wall)
    def lookup_customer(customer_id: str) -> str:
        return f"plan pro, key {AWS_KEY}"

    wall.rule("lookup_customer", schema=__import__("toolwall").ToolSchema(required=["customer_id"]))
    model = ScriptedModel("lookup_customer", {"customer_id": "c_42"})
    run(Agent(name="support", model=model, tools=[lookup_customer]))
    assert AWS_KEY not in tool_output_seen(model)


def test_no_context_means_no_refund():
    ran = []
    wall, tool = make(ran)
    model = ScriptedModel("issue_refund", {"order_id": "o_9", "amount": 40})
    run(Agent(name="support", model=model, tools=[tool]))  # no wall.context
    assert ran == []


def test_sdk_holds_a_call_its_own_coercion_changed():
    # amount: float turns the model's 40 into 40.0; the SDK then holds the call
    # for approval without asking the wall (documented in the adapter). Safe
    # direction: nothing runs unasked.
    ran = []
    wall = ToolWall()

    @guard_tool(wall)
    def issue_refund(order_id: str, amount: float) -> str:
        ran.append(order_id)
        return "x"

    wall.rule("issue_refund", amount=r.positive())
    model = ScriptedModel("issue_refund", {"order_id": "o_9", "amount": 40})
    result = run(Agent(name="support", model=model, tools=[issue_refund]))
    assert ran == [] and result.interruptions
