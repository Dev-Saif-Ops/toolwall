"""Adapters that put a ToolWall into the "before tool" hook of a framework.

Each module imports its framework lazily, so toolwall itself keeps zero
dependencies. Every adapter is a thin translation of decide() and
check_output(): the rules, context, budgets and secret scanning are the wall's.

- toolwall.integrations.openai_agents  OpenAI Agents SDK tool guardrails
- toolwall.integrations.claude_agent_sdk  Claude Agent SDK PreToolUse/PostToolUse hooks
- toolwall.integrations.langchain  LangChain / LangGraph agent middleware
- toolwall.integrations.mcp  MCP server tools (mcp 1.x FastMCP and 2.x MCPServer)
"""
