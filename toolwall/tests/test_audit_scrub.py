"""The audit log, block reasons and reports must never carry a secret value.

Found in the 2026-10-05 red-team: reasons echo raw tool names ("unknown tool"),
raw arg keys ("Unexpected arg") and arg paths, and those went verbatim into the
audit JSON/CSV. A prompt-injected model could write a key into the log by using
it as a tool name or argument name.
"""

import pytest

from toolwall import Gate, Meter, Policy, Shield, ToolSchema, ToolWall

AWS_KEY = "AKIA" + "IOSFODNN7EXAMPLE"
OPENAI_KEY = "sk-" + "Abc123def456Ghi789jklMNO"
GITHUB_TOKEN = "ghp_" + "Ab1Cd2Ef3Gh4Ij5Kl6Mn7Op8Qr9St0Uv1Wx2"
SECRETS = (AWS_KEY, OPENAI_KEY, GITHUB_TOKEN)


def build(shield=True):
    meter = Meter(model="test")
    gate = Gate(default="deny", meter=meter, shield=Shield(mode="block") if shield else None)
    gate.register("strict", lambda q: None, schema=ToolSchema(required=["q"], allow_extra=False))
    gate.register("loose", lambda **kw: None, schema=ToolSchema())
    gate.register(
        "crossy",
        lambda note: None,
        schema=ToolSchema(required=["note"]),
        policy=Policy(cross=lambda a: f"rejected note {a['note']}"),
    )
    return gate, meter


ATTEMPTS = [
    {"name": GITHUB_TOKEN, "args": {}},                               # unknown tool name
    {"name": "strict", "args": {"q": "x", OPENAI_KEY: "1"}},          # unexpected arg key
    {"name": "loose", "args": {"meta": {AWS_KEY: "1"}}},              # key inside a dict arg
    {"name": "loose", "args": {AWS_KEY: {"v": f"also {OPENAI_KEY}"}}},  # value path through a key
    {"name": "crossy", "args": {"note": f"key {AWS_KEY}"}},            # user cross-rule echoes a value
]


@pytest.mark.parametrize("shield", [True, False])
def test_no_secret_reaches_audit_export_or_reasons(tmp_path, shield):
    gate, meter = build(shield=shield)
    results = [gate.run(a) for a in ATTEMPTS]
    if shield:
        assert all(not r.executed for r in results)
    # Without a shield nothing promises the calls are blocked, but the gate's own
    # text (reasons, audit, report) still must not carry the values.

    paths = meter.export(tmp_path / "a.json", tmp_path / "a.csv")
    report = repr(gate.report())
    for secret in SECRETS:
        for p in paths.values():
            assert secret not in p.read_text(encoding="utf-8"), f"{secret[:6]}... in {p.name}"
        assert secret not in report
        for r in results:
            assert all(secret not in reason for reason in r.reasons)
            assert all(secret not in (f.arg or "") for f in r.findings)


def test_scrubbed_reasons_still_say_what_happened():
    gate, _ = build()
    r = gate.run({"name": GITHUB_TOKEN, "args": {}})
    assert r.reason.startswith("unknown tool:")
    assert "REDACTED" in r.reason


def test_wall_audit_has_no_secret(tmp_path):
    wall = ToolWall()
    wall.register("t", lambda q: None, schema=ToolSchema(required=["q"], allow_extra=False))
    wall.call("t", {"q": "x", AWS_KEY: "y"})
    wall.call(OPENAI_KEY, {})
    paths = wall.export(str(tmp_path / "w.json"), str(tmp_path / "w.csv"))
    for p in paths.values():
        text = p.read_text(encoding="utf-8")
        assert AWS_KEY not in text and OPENAI_KEY not in text
