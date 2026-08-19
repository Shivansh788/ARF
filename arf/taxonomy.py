from __future__ import annotations

from typing import Any

ASI_2026: dict[str, str] = {
    "ASI01:2026": "Agent Goal Hijack",
    "ASI02:2026": "Tool Misuse & Exploitation",
    "ASI03:2026": "Agent Identity & Privilege Abuse",
    "ASI04:2026": "Agentic Supply Chain Compromise",
    "ASI05:2026": "Unexpected Code Execution",
    "ASI06:2026": "Memory & Context Poisoning",
    "ASI07:2026": "Insecure Inter-Agent Communication",
    "ASI08:2026": "Cascading Agent Failures",
    "ASI09:2026": "Human-Agent Trust Exploitation",
    "ASI10:2026": "Rogue Agents",
}

MCP_2025: dict[str, str] = {
    "MCP01:2025": "Token Mismanagement & Secret Exposure",
    "MCP02:2025": "Privilege Escalation via Scope Creep",
    "MCP03:2025": "Tool Poisoning",
    "MCP04:2025": "Software Supply Chain Attacks & Dependency Tampering",
    "MCP05:2025": "Command Injection & Execution",
    "MCP06:2025": "Intent Flow Subversion",
    "MCP07:2025": "Insufficient Authentication & Authorization",
    "MCP08:2025": "Lack of Audit and Telemetry",
    "MCP09:2025": "Shadow MCP Servers",
    "MCP10:2025": "Context Injection & Over-Sharing",
}

TAXONOMY_SNAPSHOT = {
    "version": "ASI-2026 / MCP-2025",
    "retrieved_date": "2026-08-19",
    "source_url": "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
    "asi": ASI_2026,
    "mcp": MCP_2025,
}


def validate_taxonomy(mapping: dict[str, list[str]]) -> None:
    known = set(ASI_2026) | set(MCP_2025)
    unknown = {value for values in mapping.values() for value in values if value not in known}
    if unknown:
        raise ValueError(f"Unknown pinned taxonomy IDs: {sorted(unknown)}")


def redact(value: Any, secrets: list[str]) -> Any:
    if isinstance(value, str):
        result = value
        for secret in secrets:
            if secret:
                result = result.replace(secret, f"****{secret[-4:]}")
        return result
    if isinstance(value, dict):
        return {key: redact(item, secrets) for key, item in value.items()}
    if isinstance(value, list):
        return [redact(item, secrets) for item in value]
    return value
