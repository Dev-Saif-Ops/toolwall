"""ToolWall for LangChain and LangGraph agents (langchain >= 1.0 middleware).

    from langchain.agents import create_agent
    from toolwall.integrations.langchain import ToolWallMiddleware

    agent = create_agent(model, tools, middleware=[ToolWallMiddleware(wall)],
                         checkpointer=checkpointer)   # needed for approvals
    with wall.context(customer_id="c_42"):
        agent.invoke({"messages": [...]}, config)

Around every tool call:
- "deny": the tool doesn't run; the model gets a ToolMessage (status "error")
  with the model-safe reason.
- "ask": the run pauses with a LangGraph interrupt carrying
  {"toolwall": "approval", "tool", "args", "reason", "ticket"}. Resume with
  Command(resume=True) to approve or Command(resume=False) to decline. Approving
  takes the budget slot. Interrupts need a checkpointer. Or approve the ticket
  later (wall.approvals.approve) and run the agent again: the same call, in the
  same context, then runs once without pausing.
- "allow": the tool runs (with the wall's redacted arguments, if it redacted a
  secret), and its output is scanned before the model sees it, including the
  messages in a Command a tool returns.

The tool's name in LangChain is the name the wall's rules use.
"""

from __future__ import annotations

import dataclasses
from typing import TYPE_CHECKING, Any

from langchain.agents.middleware import AgentMiddleware

if TYPE_CHECKING:  # pragma: no cover
    from toolwall.wall import ToolWall

# Framework- and provider-generated identifiers are high-entropy by nature, so
# the entropy check would read every one as a secret. Only the id slots of the
# message schema are lifted out and scanned for known secret patterns; ids
# inside tool arguments or state are scanned like any other value.
_MESSAGE_ID_KEYS = ("id", "tool_call_id", "response_metadata", "usage_metadata")
_CALL_LISTS = ("tool_calls", "invalid_tool_calls", "tool_call_chunks")
_CALL_BLOCKS = frozenset({"tool_use", "tool_call", "server_tool_use"})


def _message_view(message: Any, ids: list[Any]) -> Any:
    """A plain copy of one message with its schema id slots moved into `ids`."""
    dump = message.model_dump() if callable(getattr(message, "model_dump", None)) else message
    if not isinstance(dump, dict):
        return dump  # tuple or str form: scanned whole
    view = dict(dump)
    for key in _MESSAGE_ID_KEYS:
        if key in view:
            ids.append(view.pop(key))
    for key in _CALL_LISTS:
        calls = view.get(key)
        if isinstance(calls, list):
            view[key] = [_lift_id(c, ids) for c in calls]
    content = view.get("content")
    if isinstance(content, list):
        view["content"] = [_lift_id(b, ids) if isinstance(b, dict) and b.get("type") in _CALL_BLOCKS
                           else b for b in content]
    return view


def _lift_id(item: Any, ids: list[Any]) -> Any:
    if not isinstance(item, dict) or "id" not in item:
        return item
    item = dict(item)
    ids.append(item.pop("id"))
    return item


def _same_message(a: Any, b: Any) -> bool:
    if a is b:
        return True
    try:
        return type(a) is type(b) and getattr(a, "id", None) is not None and a == b
    except Exception:
        return False


class ToolWallMiddleware(AgentMiddleware):
    """Agent middleware that puts every tool call through a ToolWall."""

    def __init__(self, wall: "ToolWall", *, approvals: bool = True) -> None:
        super().__init__()
        self.wall = wall
        self.approvals = approvals

    # -- shared ----------------------------------------------------------------------

    def _before(self, request: Any) -> tuple[Any, Any]:
        """(possibly rewritten request, or None) and a blocking ToolMessage, or None."""
        from langchain.messages import ToolMessage

        call = request.tool_call
        name, args, call_id = call.get("name"), call.get("args"), call.get("id")
        if not isinstance(args, dict):
            return None, ToolMessage(content="The arguments for this call could not be read.",
                                     tool_call_id=call_id, status="error")
        decision = self.wall.decide(name, args)
        if decision.needs_approval:
            if not self.approvals:
                return None, ToolMessage(content=decision.reason, tool_call_id=call_id, status="error")
            from langgraph.types import interrupt

            approved = interrupt({
                "toolwall": "approval", "tool": name, "args": dict(decision.args),
                "reason": decision.reason, "ticket": decision.ticket,
            })
            if approved is not True:
                self.wall.decline(decision)
                return None, ToolMessage(content="A person declined this call.",
                                         tool_call_id=call_id, status="error")
            decision = self.wall.take_slot(decision)
        if not decision.allowed:
            return None, ToolMessage(content=decision.reason or "This call isn't allowed.",
                                     tool_call_id=call_id, status="error")
        if decision.args != args:
            request = request.override(tool_call={**call, "args": dict(decision.args)})
        return request, None

    def _after(self, request: Any, result: Any) -> Any:
        from langchain.messages import ToolMessage
        from langgraph.types import Command

        if isinstance(result, Command):
            return self._after_command(request, result)
        if not isinstance(result, ToolMessage):
            return result
        return self._scan_message(request, result)

    def _after_command(self, request: Any, command: Any) -> Any:
        """A tool that returns a Command carries messages in its update and in any
        Send in goto: scan what the tool adds. Messages already in the agent's
        state (a handoff passing the history on) were seen by the model already
        and aren't scanned again. Any other update shape is withheld rather than
        passed unscanned."""
        from langchain.messages import ToolMessage

        seen = self._state_messages(request)
        goto = command.goto if isinstance(command.goto, (list, tuple)) else [command.goto]
        for send in goto:
            if hasattr(send, "arg") and hasattr(send, "node") and not self._send_clean(request, send.arg, seen):
                return self._withheld_command(request, command)
        update = command.update
        if update is None:
            return command
        if not isinstance(update, dict):
            return self._withheld_command(request, command)
        messages = update.get("messages")
        others = {k: v for k, v in update.items() if k != "messages"}
        if others:
            checked = self.wall.check_output(request.tool_call.get("name"), others)
            if checked.withheld:
                return self._withheld_command(request, command)
            if checked.value is not others:
                others = checked.value
        if messages is None:
            return dataclasses.replace(command, update=others)
        if not isinstance(messages, list):
            messages = [messages]
        cleaned = []
        for m in messages:
            if isinstance(m, ToolMessage):
                cleaned.append(self._scan_message(request, m))
                continue
            if any(_same_message(m, s) for s in seen):
                cleaned.append(m)
                continue
            # Every field the provider may send (content, tool_calls,
            # invalid_tool_calls...), not just the text.
            ids: list[Any] = []
            try:
                view = _message_view(m, ids)
            except Exception:
                return self._withheld_command(request, command)
            if not self._clean(request, view, ids):
                return self._withheld_command(request, command)
            cleaned.append(m)
        return dataclasses.replace(command, update={**others, "messages": cleaned})

    @staticmethod
    def _state_messages(request: Any) -> list[Any]:
        state = getattr(request, "state", None)
        messages = state.get("messages") if isinstance(state, dict) else getattr(state, "messages", None)
        return list(messages) if isinstance(messages, (list, tuple)) else []

    def _send_clean(self, request: Any, arg: Any, seen: list[Any]) -> bool:
        """A Send payload: its new messages as messages, everything else whole."""
        ids: list[Any] = []
        if isinstance(arg, dict) and isinstance(arg.get("messages"), list):
            try:
                new = [_message_view(m, ids) for m in arg["messages"]
                       if not any(_same_message(m, s) for s in seen)]
            except Exception:
                return False
            arg = {**{k: v for k, v in arg.items() if k != "messages"}, "messages": new}
        return self._clean(request, arg, ids)

    def _clean(self, request: Any, view: Any, ids: list[Any]) -> bool:
        """True when no secret is found: the view fully, the lifted ids for known
        secret patterns only. Anything that can't be scanned is not clean."""
        from toolwall.shield import Shield

        checked = self.wall.check_output(request.tool_call.get("name"), view)
        if checked.withheld or checked.value is not view:
            return False
        shield = self.wall.gate.shield
        if shield is None or not ids:
            return True
        patterns_only = Shield(mode="redact", patterns=shield.patterns, entropy=False,
                               allowlist=shield.allowlist)
        try:
            _, findings = patterns_only.redact_args({"ids": ids})
        except Exception:
            return False
        return not findings

    def _withheld_command(self, request: Any, command: Any) -> Any:
        from langchain.messages import ToolMessage

        return ToolMessage(content="The tool's output was withheld because it contained what "
                                   "looks like a secret or couldn't be checked.",
                           tool_call_id=request.tool_call.get("id"), status="error")

    def _scan_message(self, request: Any, result: Any) -> Any:
        checked = self.wall.check_output(request.tool_call.get("name"), result.content)
        if checked.withheld:
            return result.model_copy(update={"content": checked.reason, "status": "error",
                                             "artifact": None})
        if checked.value is not result.content:
            return result.model_copy(update={"content": checked.value, "artifact": None})
        if getattr(result, "artifact", None) is not None:
            artifact = self.wall.check_output(request.tool_call.get("name"), result.artifact)
            if artifact.withheld or artifact.value is not result.artifact:
                return result.model_copy(update={"artifact": None})
        return result

    # -- middleware hooks ----------------------------------------------------------

    def wrap_tool_call(self, request: Any, handler: Any) -> Any:
        request, blocked = self._before(request)
        if blocked is not None:
            return blocked
        return self._after(request, handler(request))

    async def awrap_tool_call(self, request: Any, handler: Any) -> Any:
        request, blocked = self._before(request)
        if blocked is not None:
            return blocked
        return self._after(request, await handler(request))
