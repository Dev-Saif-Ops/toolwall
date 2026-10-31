"""Shield: secret detection/redaction. Audit safety is the critical property."""

import json

import pytest

from toolwall import Gate, Meter, Shield, ToolSchema, Verdict
from toolwall.shield import shannon_entropy

# Fixtures are built by concatenation so repo secret-scanners never text-match
# them; toolwall's own runtime detection still catches the assembled strings.
AWS_KEY = "AKIA" + "IOSFODNN7EXAMPLE"
OPENAI_KEY = "sk-" + "Abc123def456Ghi789jklMNO"
GITHUB_TOKEN = "ghp_" + "Ab1Cd2Ef3Gh4Ij5Kl6Mn7Op8Qr9St0Uv1Wx2"
STRIPE_KEY = "sk_test_" + "FakeFakeFakeFake1234Fake"
JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9P"
PEM = "-----BEGIN RSA PRIVATE KEY-----"


def kinds(findings):
    return {f.kind for f in findings}


def test_pattern_detection():
    shield = Shield()
    assert kinds(shield.scan(f"creds: {AWS_KEY}")) == {"aws-access-key"}
    assert kinds(shield.scan(f"key={OPENAI_KEY}"))  # openai (or credential-assignment)
    assert "github-token" in kinds(shield.scan(f"push with {GITHUB_TOKEN}"))
    assert "stripe-key" in kinds(shield.scan(f"charge via {STRIPE_KEY}"))
    assert "jwt" in kinds(shield.scan(f"Bearer {JWT}"))
    assert "private-key-block" in kinds(shield.scan(f"{PEM}\nMIIEow..."))


def test_credential_assignment():
    shield = Shield(entropy=False)
    found = shield.scan('config: password = "hunter2secret"')
    assert "credential-assignment" in kinds(found)


def test_entropy_detection_and_threshold():
    shield = Shield()
    blob = "9f8Kj2Lm5Qw7Rt4Yx6Zv1Bn3Cp8Dq0Fs2Gh5Jk7M"
    assert shannon_entropy(blob) >= shield.entropy_threshold  # sample qualifies
    assert "high-entropy-string" in kinds(shield.scan(f"value: {blob}"))


def test_clean_text_no_false_positives():
    shield = Shield()
    clean = (
        "Please rotate the AWS keys safely and update /app/config/settings_backup.json. "
        "Ticket id: 550e8400e29b41d4a716446655440000 tracks the migration."
    )
    assert shield.scan(clean) == []


def test_allowlist():
    shield = Shield(allowlist=(AWS_KEY,))
    assert shield.scan(f"test fixture key {AWS_KEY}") == []


def test_redact_and_restore():
    shield = Shield(mode="redact")
    clean, findings = shield.redact_text(f"use {AWS_KEY} for s3")
    assert AWS_KEY not in clean
    assert "[REDACTED:aws-access-key-1]" in clean
    assert findings[0].placeholder == "[REDACTED:aws-access-key-1]"
    assert shield.restore(clean) == f"use {AWS_KEY} for s3"


def test_scan_args_nested():
    shield = Shield()
    findings = shield.scan_args({"body": {"text": f"key {AWS_KEY}"}, "tags": [f"{STRIPE_KEY}"]})
    assert {f.arg for f in findings} == {"body.text", "tags[0]"}


def test_findings_never_carry_values():
    shield = Shield()
    findings = shield.scan(f"leak {AWS_KEY}")
    dumped = json.dumps([f.to_dict() for f in findings])
    assert AWS_KEY not in dumped


def gate_with_shield(mode):
    gate = Gate(default="deny", shield=Shield(mode=mode), meter=Meter(model="test"))
    gate.register(
        "send_email",
        lambda to, body: {"sent": True, "body": body},
        schema=ToolSchema(required=["to", "body"], types={"to": str, "body": str}),
    )
    return gate


EXFIL = {"name": "send_email", "args": {"to": "a@ourco.com", "body": f"creds: {AWS_KEY}"}}


def test_gate_block_mode():
    gate = gate_with_shield("block")
    result = gate.run(EXFIL)
    assert result.verdict is Verdict.BLOCK
    assert not result.executed
    assert "aws-access-key" in result.reasons[0]


def test_gate_redact_mode_executes_with_placeholder():
    gate = gate_with_shield("redact")
    result = gate.run(EXFIL)
    assert result.executed
    assert AWS_KEY not in result.call.args["body"]
    assert "[REDACTED:aws-access-key-1]" in result.return_value["body"]


def test_gate_warn_mode_executes_unchanged():
    gate = gate_with_shield("warn")
    result = gate.run(EXFIL)
    assert result.executed
    assert AWS_KEY in result.call.args["body"]
    assert result.findings and result.findings[0].kind == "aws-access-key"


def test_audit_export_never_contains_secret(tmp_path):
    gate = gate_with_shield("block")
    gate.run(EXFIL)
    paths = gate.meter.export(tmp_path / "audit.json", tmp_path / "audit.csv")
    for path in paths.values():
        content = path.read_text(encoding="utf-8")
        assert AWS_KEY not in content, f"secret leaked into {path.name}"


# -- 0.8: keys glued to other text ------------------------------------------------

GLUED = [
    ("aws-access-key", "handing offAKIA" + "IOSFODNN7EXAMPLE"),
    ("aws-access-key", "key=AKIA" + "IOSFODNN7EXAMPLEand more"),
    ("aws-access-key", "tempASIA" + "IOSFODNN7EXAMPLE"),
    ("github-token", "tokenghp_" + "a" * 36),
    ("stripe-key", "paywithsk_live_" + "Abc123" * 4),
    ("slack-token", "botxoxb-" + "12345678901234"),
    ("google-api-key", "mapAIza" + "B" * 35),
    ("jwt", "beareyJ" + "hbGciOiJIUzI1.eyJzdWIiOiIx.SflKxwRJSM"),
]


@pytest.mark.parametrize("kind, text", GLUED)
def test_a_key_glued_to_a_word_is_found(kind, text):
    assert kind in {f.kind for f in Shield(mode="block").scan(text)}


@pytest.mark.parametrize("text", [
    "task-management-dashboard-version-two",      # "sk-" inside a word
    "SOUTHEASTASIAPACIFICREGION2024",              # "ASIA" inside an upper-case word
    "MALAKIAN", "the Asian market report",
])
def test_ordinary_words_are_not_keys(text):
    kinds = {f.kind for f in Shield(mode="block", entropy=False).scan(text)}
    assert not kinds & {"aws-access-key", "openai-key"}
