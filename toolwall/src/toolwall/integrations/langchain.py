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
  {"toolwall": "approval", "tool", "args", "reason"}. Resume with
  Command(resume=True) to approve or Command(resume=False) to decline. Approving
  takes the budget slot. Interrupts need a checkpointer.
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
                "reason": decision.reason,
            })
            if approved is not True:
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
        """A tool that returns a Command carries its messages in update: scan
        those. Any other update shape is withheld rather than passed unscanned."""
        from langchain.messages import ToolMessage

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
            # Every field the provider may send (content, tool_calls,
            # invalid_tool_calls...), not just the text.
            try:
                fields = m.model_dump() if hasattr(m, "model_dump") else m
            except Exception:
                return self._withheld_command(request, command)
            checked = self.wall.check_output(request.tool_call.get("name"), fields)
            if checked.withheld or checked.value is not fields:
                return self._withheld_command(request, command)
            cleaned.append(m)
        return dataclasses.replace(command, update={**others, "messages": cleaned})

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
