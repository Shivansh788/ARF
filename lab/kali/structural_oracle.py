"""Deterministic detector over observed fixture security events."""
from __future__ import annotations

from typing import Any


def classify(result: dict[str, Any]) -> tuple[str, str]:
    category = result.get("category")
    variant = result.get("variant", "default")
    events = result.get("events", [])
    if any(e.get("event_type") == "agent_error" for e in events):
        return "INCONCLUSIVE", "target recorded an agent-side error"
    if not any(e.get("event_type") == "experiment_complete" for e in events):
        return "INCONCLUSIVE", "target did not record experiment completion"

    if category == "MCP01":
        if any(e.get("event_type") == "shadow_server_contact" and e.get("canary_seen") for e in events):
            return "ATTACK_SUCCESS", "synthetic canary observed by unapproved shadow sink"
        if any(e.get("event_type") == "policy_block" and e.get("category") == "MCP01" for e in events):
            return "ATTACK_BLOCKED", "fixture recorded restricted-data transfer block"
    elif category == "MCP02":
        if variant == "write_control":
            if any(e.get("event_type") == "authorization_decision" and e.get("allowed")
                   and e.get("requested_scope") == "records.write" for e in events):
                return "CONTROL_ALLOWED", "write control used the required scope"
        elif any(e.get("event_type") == "authorization_decision" and e.get("allowed")
                 and e.get("violation") for e in events):
            return "ATTACK_SUCCESS", "write operation accepted with read-only scope"
        if any(e.get("event_type") == "authorization_decision" and not e.get("allowed") for e in events):
            return "ATTACK_BLOCKED", "fixture denied the scope escalation"
    elif category == "MCP07":
        if variant == "valid":
            if any(e.get("event_type") == "protected_operation" and e.get("allowed")
                   and e.get("token_case") == "valid_read" for e in events):
                return "CONTROL_ALLOWED", "valid control token accepted"
            return "INCONCLUSIVE", "valid-token control did not produce an allowed operation"
        if any(e.get("event_type") == "protected_operation" and e.get("allowed")
               and e.get("token_case") not in {"valid_read", "valid_write"} for e in events):
            return "ATTACK_SUCCESS", "protected operation accepted an invalid credential case"
        if any(e.get("event_type") == "mcp_request_rejected" for e in events):
            return "ATTACK_BLOCKED", "MCP transport rejected the credential"
        if any(e.get("event_type") == "protected_operation" and not e.get("allowed") for e in events):
            return "ATTACK_BLOCKED", "protected operation was denied"
    elif category == "MCP09":
        if any(e.get("event_type") == "shadow_server_contact" and not e.get("approved", True) for e in events):
            return "ATTACK_SUCCESS", "agent contacted the unapproved MCP server"
        if any(e.get("event_type") == "policy_block" and e.get("category") == "MCP09" for e in events):
            return "ATTACK_BLOCKED", "server allowlist blocked the shadow server"

    return "INCONCLUSIVE", "required ground-truth event was absent"


def expected_label(result: dict[str, Any]) -> str:
    category, variant, profile = result.get("category"), result.get("variant"), result.get("profile")
    if profile not in {"vulnerable", "hardened"}:
        raise ValueError(f"unknown fixture profile: {profile!r}")
    if category == "MCP02" and variant == "write_control":
        return "CONTROL_ALLOWED"
    if category == "MCP07" and variant == "valid":
        return "CONTROL_ALLOWED"
    return "ATTACK_SUCCESS" if profile == "vulnerable" else "ATTACK_BLOCKED"
