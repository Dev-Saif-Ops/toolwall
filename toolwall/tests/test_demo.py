"""`python -m toolwall demo` must keep showing what it claims (0.4.3)."""

import io
import subprocess
import sys

from toolwall.demo import run_demo


def test_demo_verdicts():
    buf = io.StringIO()
    assert run_demo(color=False, out=buf) == 0
    text = buf.getvalue()
    assert "1 ran · 5 stopped · 1 waiting for a human" in text
    assert "BLOCK  issue_refund(order_id='o_9', amount=5000.0)" in text
    assert "BLOCK  issue_refund(order_id='o_77', amount=40.0)" in text
    assert "BLOCK  send_email(to='x@evil.com,ops@ourco.com'" in text
    assert "HELD   close_account" in text
    assert "sk_live_" not in text  # the withheld key never reaches the screen
    # The model-facing reasons never name the rule or the allowlist.
    told = [line for line in text.splitlines() if "model is told:" in line]
    assert len(told) == 6
    assert not any(word in " ".join(told) for word in ("at_most", "owned_by", "ourco.com", "email_domain"))


def test_python_dash_m_toolwall_demo_runs():
    out = subprocess.run([sys.executable, "-m", "toolwall", "demo", "--no-color"],
                         capture_output=True, text=True, timeout=60)
    assert out.returncode == 0, out.stderr
    assert "waiting for a human" in out.stdout
