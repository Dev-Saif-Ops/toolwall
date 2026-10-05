#!/usr/bin/env python3
"""Put toolwall in front of an MCP-style server. No mcp install needed.

`forward` stands in for the real downstream server call. In a live setup it
would invoke the wrapped MCP server; here it just echoes, so you can see which
calls get through the gate and which are stopped before they ever arrive.

    python examples/mcp_guard_demo.py
"""

from toolwall import Gate, Meter, MCPGuard, Policy, Shield, ToolSchema, email_domain, in_range, not_empty


# Stand-in for the downstream MCP server. The gate decides what reaches it.
def forward_to_server(name: str, args: dict):
    return {"server": "handled", "tool": name, "args": args}


def build_guard() -> MCPGuard:
    gate = Gate(default="deny", meter=Meter(model="mcp-demo"), shield=Shield(mode="block"))
    gate.register(
        "search_docs",
        lambda q, limit=10: None,
        schema=ToolSchema(required=["q"], types={"q": str, "limit": int}),
        policy=Policy(constraints={"limit": in_range(1, 50)}),
    )
    gate.register(
        "delete_doc",
        lambda id: None,
        schema=ToolSchema(required=["id"], types={"id": str}),
        policy=Policy(require_approval=True),
    )
    gate.register(
        "notify",
        lambda to, text: None,
        schema=ToolSchema(required=["to", "text"], types={"to": str, "text": str}),
        policy=Policy(constraints={"to": email_domain("ourco.com")}),
    )
    return MCPGuard(gate, forward_to_server)


CALLS = [
    ("search_docs", {"q": "onboarding", "limit": 5}),                 # allowed
    ("search_docs", {"q": "everything", "limit": 9999}),             # blocked: out of range
    ("delete_doc", {"id": "doc-42"}),                                # held: needs approval
    ("notify", {"to": "outsider@example.com", "text": "hi"}),        # blocked: wrong domain
    ("notify", {"to": "team@ourco.com", "text": "key AKIA" + "IOSFODNN7EXAMPLE"}),  # blocked: secret
    ("open_admin_panel", {}),                                        # blocked: not registered
]


def main() -> None:
    guard = build_guard()
    print("call                 -> verdict     forwarded to server?")
    print("-" * 58)
    for name, args in CALLS:
        out = guard.handle(name, args)
        print(f"{name:20} -> {out.verdict:11} {out.forwarded}")
    print("\nOnly the safe call reached the server. Everything else stopped at the gate.")


if __name__ == "__main__":
    main()
