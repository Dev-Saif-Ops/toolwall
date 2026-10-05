"""toolwall: fail-closed firewall for AI agent tool calls.

Structured outputs guarantee your agent's tool calls are well-formed.
toolwall guarantees they're allowed.
"""

from toolwall.gate import Gate, GateResult, ToolRegistry, Verdict
from toolwall.wall import ToolWall
from toolwall.intake import IntakeError, ToolCall, parse_tool_calls
from toolwall.meter import Meter, RunEvent, RunReport, extract_usage
from toolwall.receipt import ReceiptError, fingerprint
from toolwall.policy import (
    Policy,
    email_domain,
    ends_with,
    in_range,
    matches,
    max_len,
    not_empty,
    one_of,
    starts_with,
)
from toolwall.schema import ToolSchema, schema_from_signature
from toolwall.shield import Finding, Shield
from toolwall.suggest import suggest_policies
from toolwall.mcp_guard import GuardedCall, MCPGuard, to_mcp_error

__version__ = "0.4.1"

__all__ = [
    "ToolWall",
    "Gate",
    "GateResult",
    "Verdict",
    "ToolRegistry",
    "ToolCall",
    "IntakeError",
    "parse_tool_calls",
    "Meter",
    "RunEvent",
    "RunReport",
    "extract_usage",
    "Policy",
    "in_range",
    "one_of",
    "matches",
    "max_len",
    "ends_with",
    "email_domain",
    "starts_with",
    "not_empty",
    "ToolSchema",
    "schema_from_signature",
    "Shield",
    "Finding",
    "ReceiptError",
    "fingerprint",
    "suggest_policies",
    "MCPGuard",
    "GuardedCall",
    "to_mcp_error",
    "__version__",
]
