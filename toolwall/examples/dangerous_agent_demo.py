#!/usr/bin/env python3
"""The demo: an unsafe agent, with and without toolwall.

An agent that has gone off the rails (confused, or fed bad context) tries six
side-effectful actions. We replay the same tool calls twice: once ungated
(everything runs), once gated (unsafe ones blocked + audited). No API key, no
real side effects; the "tools" just record what they were asked to do so the
impact is visible without being real. This is a defensive demonstration: the
whole point is what the gate stops.

    python examples/dangerous_agent_demo.py
"""

from toolwall import Gate, Meter, Policy, Shield, ToolSchema, email_domain, in_range, not_empty, one_of

# --- a fake world the agent can damage ----------------------------------------

WORLD = {"rows": 10_000, "emails_sent": [], "deployed": None, "files_read": []}


def db_query(q: str, limit: int = 10):
    return {"rows": min(limit, WORLD["rows"])}


def delete_records(filter: dict):
    wiped = WORLD["rows"] if not filter else 1
    WORLD["rows"] -= wiped
    return {"deleted": wiped}


def send_email(to: str, subject: str, body: str):
    WORLD["emails_sent"].append((to, body))
    return {"sent": True}


def read_file(path: str):
    WORLD["files_read"].append(path)
    return "SECRET_CONTENTS"


def deploy(env: str, version: str):
    WORLD["deployed"] = (env, version)
    return {"deployed": env}


TOOLS = {
    "db_query": db_query,
    "delete_records": delete_records,
    "send_email": send_email,
    "read_file": read_file,
    "deploy": deploy,
}

# What the off-the-rails agent decided to do (all valid, well-formed calls):
AGENT_PLAN = [
    {"name": "db_query", "args": {"q": "customers", "limit": 50}},                  # fine
    {"name": "delete_records", "args": {"filter": {}}},                             # wipes the table
    {"name": "send_email", "args": {"to": "outsider@example.com",
                                    "subject": "list", "body": "customer list attached"}},
    {"name": "read_file", "args": {"path": "/srv/private/notes.txt"}},              # path escape
    {"name": "send_email", "args": {"to": "ops@ourco.com", "subject": "keys",
                                    "body": "aws key AKIA" + "IOSFODNN7EXAMPLE"}},   # secret leak
    {"name": "deploy", "args": {"env": "production", "version": "untested-1.0"}},   # unauthorized deploy
]


def run_ungated():
    print("=== WITHOUT toolwall ===")
    for step in AGENT_PLAN:
        TOOLS[step["name"]](**step["args"])
    print(f"  rows left in table : {WORLD['rows']}   (started at 10000)")
    print(f"  emails sent        : {len(WORLD['emails_sent'])}  -> {[t for t, _ in WORLD['emails_sent']]}")
    print(f"  files read         : {WORLD['files_read']}")
    print(f"  deployed           : {WORLD['deployed']}")
    print("  => table wiped, secrets emailed out, prod deployed without review.\n")


def build_gate():
    gate = Gate(default="deny", meter=Meter(model="demo"), shield=Shield(mode="block"))
    gate.register("db_query", db_query,
                  schema=ToolSchema(required=["q"], types={"q": str, "limit": int}),
                  policy=Policy(constraints={"limit": in_range(1, 100)}))
    gate.register("delete_records", delete_records,
                  schema=ToolSchema(required=["filter"], types={"filter": dict}),
                  policy=Policy(constraints={"filter": not_empty}, require_approval=True))
    gate.register("send_email", send_email,
                  schema=ToolSchema(required=["to", "subject", "body"],
                                    types={"to": str, "subject": str, "body": str}),
                  policy=Policy(constraints={"to": email_domain("ourco.com")}))
    gate.register("read_file", read_file,
                  schema=ToolSchema(required=["path"], types={"path": str}),
                  policy=Policy(cross=lambda a: "path traversal" if ".." in a["path"]
                                or not a["path"].startswith("/app/") else None))
    gate.register("deploy", deploy,
                  schema=ToolSchema(required=["env", "version"], types={"env": str, "version": str}),
                  policy=Policy(constraints={"env": one_of("staging", "prod")}, require_approval=True))
    return gate


def run_gated():
    for k, v in {"rows": 10_000, "emails_sent": [], "deployed": None, "files_read": []}.items():
        WORLD[k] = v
    print("=== WITH toolwall (no approval handler = destructive calls held) ===")
    gate = build_gate()
    for step in AGENT_PLAN:
        result = gate.run(step)
        mark = {"allow": "RAN  ", "block": "BLOCK", "needs_approval": "HELD "}[result.verdict.value]
        reason = result.reasons[0] if result.reasons else "ok"
        print(f"  [{mark}] {step['name']:15} {reason}")
    print(f"\n  rows left in table : {WORLD['rows']}   (untouched)")
    print(f"  emails sent        : {len(WORLD['emails_sent'])}")
    print(f"  deployed           : {WORLD['deployed']}")
    r = gate.report()
    print(f"  gate report        : {r['verdicts']}")
    print(f"  secrets caught     : {r['secret_findings_by_kind']}")
    print("  => nothing destructive executed. Every decision in the audit log.")


if __name__ == "__main__":
    run_ungated()
    run_gated()
