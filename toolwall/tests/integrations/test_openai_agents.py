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

    def __init__(self, tool: str, args: dict, namespace: str | None = None):
        self.tool, self.args, self.seen, self.namespace = tool, args, [], namespace

    async def get_response(self, system_instructions, input, model_settings, tools,
                           output_schema, handoffs, tracing, **kwargs):
        self.seen.append(input)
        if len(self.seen) == 1:
            extra = {"namespace": self.namespace} if self.namespace else {}
            item = ResponseFunctionToolCall(type="function_call", call_id="c1", id="fc1",
                                            name=self.tool, arguments=json.dumps(self.args), **extra)
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


def test_arguments_carrying_a_secret_are_rejected_not_run():
    # redact mode would clean them, but the SDK can't swap what the tool gets.
    ran = []
    wall = ToolWall(redact=True)

    @guard_tool(wall)
    def note(text: str) -> str:
        ran.append(text)
        return "ok"

    model = ScriptedModel("note", {"text": f"key {AWS_KEY}"})
    run(Agent(name="support", model=model, tools=[note]))
    assert ran == [] and AWS_KEY not in tool_output_seen(model)


def test_approval_check_does_not_spend_the_budget():
    ran = []
    wall, tool = make(ran)
    wall.budget(max_calls=1)
    model = ScriptedModel("issue_refund", {"order_id": "o_9", "amount": 40})
    with wall.context(customer_id="c_42"):
        run(Agent(name="support", model=model, tools=[tool]))
    assert ran == [("o_9", 40)]  # needs_approval + guardrail took one slot, not two


def test_a_ticket_approved_out_of_band_runs_without_another_pause():
    ran = []
    wall, tool = make(ran)
    agent_model = ScriptedModel("issue_refund", {"order_id": "o_9", "amount": 300})
    with wall.context(customer_id="c_42"):
        result = run(Agent(name="support", model=agent_model, tools=[tool]))
        assert result.interruptions and ran == []
        ticket = wall.approvals.pending()[0].id
        wall.approvals.approve(ticket, by="ops")
        again = run(Agent(name="support", model=ScriptedModel("issue_refund", {"order_id": "o_9", "amount": 300}),
                          tools=[tool]))
    assert not again.interruptions and ran == [("o_9", 300)]
    assert wall.approvals.get(ticket).status == "used"


def test_a_ticket_used_up_between_the_check_and_the_guardrail_does_not_run():
    # The SDK's needs_approval sees an approved ticket and doesn't pause; someone
    # else uses it before the input guardrail runs. Nobody approved this call.
    ran = []
    wall, tool = make(ran)
    with wall.context(customer_id="c_42"):
        first = wall.decide("issue_refund", {"order_id": "o_9", "amount": 300})
    wall.approvals.approve(first.ticket, by="ops")
    real_decide = wall.decide

    def decide_after_someone_else_used_it(name, args=None):
        ticket = wall.approvals.store.get(first.ticket)
        if ticket.status == "approved":
            wall.approvals.redeem(ticket)
        return real_decide(name, args)

    wall.decide = decide_after_someone_else_used_it
    with wall.context(customer_id="c_42"):
        result = run(Agent(name="support", tools=[tool],
                           model=ScriptedModel("issue_refund", {"order_id": "o_9", "amount": 300})))
    assert ran == [] and not result.interruptions


def test_approving_in_the_sdk_settles_the_ticket():
    ran = []
    wall, tool = make(ran)
    agent = Agent(name="support", model=ScriptedModel("issue_refund", {"order_id": "o_9", "amount": 300}),
                  tools=[tool])
    with wall.context(customer_id="c_42"):
        result = run(agent)
        ticket = wall.approvals.pending()[0].id
        state = result.to_state()
        state.approve(result.interruptions[0])
        asyncio.run(Runner.run(agent, state))
    assert ran == [("o_9", 300)]
    assert wall.approvals.pending() == [] and wall.approvals.get(ticket).status == "used"


def test_an_approved_call_to_a_namespaced_tool_runs():
    from agents.tool import tool_namespace

    ran = []
    wall, tool = make(ran)
    agent = Agent(name="support", tools=tool_namespace(name="billing", description="Billing", tools=[tool]),
                  model=ScriptedModel("issue_refund", {"order_id": "o_9", "amount": 300}, namespace="billing"))
    with wall.context(customer_id="c_42"):
        result = run(agent)
        assert result.interruptions and ran == []
        state = result.to_state()
        state.approve(result.interruptions[0])
        asyncio.run(Runner.run(agent, state))
    assert ran == [("o_9", 300)]


class TurnModel(Model):
    """One scripted response per turn, then a text answer."""

    def __init__(self, turns):
        self.turns, self.n = turns, 0

    async def get_response(self, *a, **k):
        out = self.turns[self.n] if self.n < len(self.turns) else [
            ResponseOutputMessage(id="m", type="message", role="assistant", status="completed",
                                  content=[ResponseOutputText(type="output_text", text="done",
                                                              annotations=[])])]
        self.n += 1
        return ModelResponse(output=out, usage=Usage(), response_id=None)

    def stream_response(self, *a, **k):  # pragma: no cover
        raise NotImplementedError


def refund_call(call_id, amount, namespace=None, name="issue_refund", args=None):
    extra = {"namespace": namespace} if namespace else {}
    return ResponseFunctionToolCall(type="function_call", call_id=call_id, id="fc_" + call_id, name=name,
                                    arguments=json.dumps(args if args is not None else
                                                         {"order_id": "o_9", "amount": amount}), **extra)


def twin_tools():
    """Two tools with the same name on one wall; B's approval check is raced:
    right after it sees an approved ticket, another worker uses that ticket."""
    from toolwall import ToolSchema

    wall = ToolWall()
    ran = []

    def mk(tag):
        @guard_tool(wall)
        def issue_refund(order_id: str, amount: int | float) -> str:
            ran.append((tag, amount))
            return "ok"
        return issue_refund

    wall.rule("issue_refund", schema=ToolSchema(required=["order_id", "amount"],
                                                types={"order_id": str, "amount": (int, float)}),
              ask_if=r.over("amount", 200))
    a, b = mk("A"), mk("B")
    probe = b.needs_approval

    async def raced(run_context, args, call_id):
        answer = await probe(run_context, args, call_id)
        ticket = wall.approvals.lookup("issue_refund", args, {})
        if ticket is not None and ticket.status == "approved":
            wall.approvals.redeem(ticket)
        return answer

    b.needs_approval = raced
    return wall, a, b, ran


def approve_always_then_queue_5000(wall, agent):
    result = run(agent)
    state = result.to_state()
    for item in result.interruptions:
        state.approve(item, always_approve=True)
    held = wall.decide("issue_refund", {"order_id": "o_9", "amount": 5000})
    wall.approvals.approve(held.ticket, by="ops")
    return asyncio.run(Runner.run(agent, state))


def test_always_approve_on_one_tool_does_not_cover_a_namesake_in_a_namespace():
    from agents.tool import tool_namespace

    wall, a, b, ran = twin_tools()
    agent = Agent(name="support", tools=[a, *tool_namespace(name="billing", description="b", tools=[b])],
                  model=TurnModel([[refund_call("c1", 300)], [refund_call("c2", 5000, "billing")]]))
    approve_always_then_queue_5000(wall, agent)
    assert ran == [("A", 300)]


def test_always_approve_on_one_agent_does_not_cover_a_namesake_after_a_handoff():
    wall, a, b, ran = twin_tools()
    second = Agent(name="b", tools=[b], model=TurnModel([[refund_call("c2", 5000)]]))
    first = Agent(name="a", tools=[a], handoffs=[second],
                  model=TurnModel([[refund_call("c1", 300)],
                                   [refund_call("h1", 0, name="transfer_to_b", args={})]]))
    approve_always_then_queue_5000(wall, first)
    assert ran == [("A", 300)]


def test_the_approval_check_failing_counts_as_not_approved():
    import toolwall.integrations.openai_agents as oa

    class Broken:
        agent = Agent(name="support")
        tool_call = refund_call("c1", 300)
        tool_name = "issue_refund"
        tool_namespace = None
        tool_call_id = "c1"

        def get_approval_status(self, *a, **k):
            raise RuntimeError("sdk changed")

    assert oa._approved_in_sdk(Broken()) is False
