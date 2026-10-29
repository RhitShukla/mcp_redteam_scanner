"""
Attack registry — metadata and phase mapping for all 15 attack modules.

Each attack has:
- id: Short code (E1, A1, B1, etc.)
- name: Human-readable name
- phase: Execution phase (0=passive, 1=transport, 2=active probing, 3=authz+data)
- risk: Default severity level
- owasp: OWASP LLM Top 10 mapping
- module_path: Import path for the attack class
- class_name: Class name to instantiate
- description: What the attack tests
"""

from __future__ import annotations
from typing import Any


ATTACK_REGISTRY: dict[str, dict[str, Any]] = {
    "E1": {
        "name": "Weak Authentication",
        "phase": 1,
        "risk": "HIGH",
        "owasp": "LLM09",
        "module_path": "src.attacks.e1_weak_auth",
        "class_name": "E1WeakAuth",
        "description": "Flags endpoints running without auth or exposing privileged metadata.",
    },
    "E3": {
        "name": "TLS Origin Validation",
        "phase": 1,
        "risk": "MEDIUM",
        "owasp": "LLM05",
        "module_path": "src.attacks.e3_tls_origin_validation",
        "class_name": "E3TLSOriginValidation",
        "description": "Tests URL scheme for HTTPS enforcement and certificate validation.",
    },
    "E5": {
        "name": "Rate Limit Probe",
        "phase": 1,
        "risk": "LOW",
        "owasp": "LLM04",
        "module_path": "src.attacks.e5_rate_limit_probe",
        "class_name": "E5RateLimitProbe",
        "description": "Burst requests to test throttling and DoS protection.",
    },
    "A1": {
        "name": "Description Poisoning",
        "phase": 0,
        "risk": "CRITICAL",
        "owasp": "LLM01",
        "module_path": "src.attacks.a1_description_poisoning",
        "class_name": "A1DescriptionPoisoning",
        "description": "Tests if malicious instructions in tool descriptions can manipulate LLM behavior.",
    },
    "A2": {
        "name": "Schema Manipulation",
        "phase": 0,
        "risk": "MEDIUM",
        "owasp": "LLM03",
        "module_path": "src.attacks.a2_schema_manipulation",
        "class_name": "A2SchemaManipulation",
        "description": "Tests input schema validation strictness and additionalProperties.",
    },
    "A3": {
        "name": "Tool Shadowing",
        "phase": 0,
        "risk": "HIGH",
        "owasp": "LLM08",
        "module_path": "src.attacks.mcp_tool_shadowing",
        "class_name": "MCPToolShadowing",
        "description": "Detects tools with benign names but risky capabilities.",
    },
    "A4": {
        "name": "Enumeration Leakage",
        "phase": 0,
        "risk": "MEDIUM",
        "owasp": "LLM06",
        "module_path": "src.attacks.a4_enumeration_leakage",
        "class_name": "A4EnumerationLeakage",
        "description": "Tests for excessive tool/resource/prompt exposure.",
    },
    "B1": {
        "name": "Parameter Injection",
        "phase": 2,
        "risk": "MEDIUM",
        "owasp": "LLM01",
        "module_path": "src.attacks.b1_parameter_injection",
        "class_name": "B1ParameterInjection",
        "description": "Runs non-destructive injection probes against risky parameters.",
    },
    "B2": {
        "name": "SSRF Probe",
        "phase": 2,
        "risk": "MEDIUM",
        "owasp": "LLM05",
        "module_path": "src.attacks.b2_ssrf_probe",
        "class_name": "B2SSRFProbe",
        "description": "Tests URL-like parameters with localhost/metadata targets.",
    },
    "S1": {
        "name": "SSRF Network Probe",
        "phase": 2,
        "risk": "HIGH",
        "owasp": "LLM05",
        "module_path": "src.attacks.s1_ssrf",
        "class_name": "S1SSRF",
        "description": "Deterministic, oracle-backed SSRF detection for URL-capable MCP tools.",
    },
    "B3": {
        "name": "Path Traversal",
        "phase": 2,
        "risk": "HIGH",
        "owasp": "LLM06",
        "module_path": "src.attacks.b3_path_traversal",
        "class_name": "B3PathTraversal",
        "description": "Attempts directory traversal attacks using ../ sequences.",
    },
    "B5": {
        "name": "Error Info Disclosure",
        "phase": 2,
        "risk": "MEDIUM",
        "owasp": "LLM06",
        "module_path": "src.attacks.b5_error_info_disclosure",
        "class_name": "B5ErrorInfoDisclosure",
        "description": "Triggers errors to check for stack traces and debug info leaks.",
    },
    "E2": {
        "name": "Auth Wall Break",
        "phase": 3,
        "risk": "HIGH",
        "owasp": "LLM08",
        "module_path": "src.attacks.a3_auth_wall_break",
        "class_name": "A3AuthWallBreak",
        "description": "Tests authorization boundaries by calling privileged tools.",
    },
    "D1": {
        "name": "Sensitive Data Exposure",
        "phase": 3,
        "risk": "CRITICAL",
        "owasp": "LLM06",
        "module_path": "src.attacks.d1_sensitive_data",
        "class_name": "D1SensitiveData",
        "description": "Scans tool responses for PII, credentials, API keys, and tokens.",
    },
    "D2": {
        "name": "API Key & Secret Extraction",
        "phase": 3,
        "risk": "CRITICAL",
        "owasp": "LLM06",
        "module_path": "src.attacks.d2_api_key_stealing",
        "class_name": "D2APIKeyStealing",
        "description": "Triggers error paths to extract API keys, connection strings, and cloud credentials from error messages.",
    },
    "MCP": {
        "name": "Excessive Permission Scope",
        "phase": 1,
        "risk": "HIGH",
        "owasp": "LLM08",
        "module_path": "src.attacks.mcp_excessive_perms",
        "class_name": "MCPExcessivePerms",
        "description": "Checks if current identity can enumerate privileged/internal capabilities.",
    },
}

# Phase execution order
PHASE_ORDER = [0, 1, 2, 3]

# Phase labels for progress reporting
PHASE_LABELS = {
    0: "Passive Analysis",
    1: "Transport & Auth",
    2: "Active Probing",
    3: "Authorization & Data",
}


def get_attacks_for_phase(phase: int) -> list[str]:
    """Return attack IDs belonging to a specific phase, in execution order."""
    return [aid for aid, meta in ATTACK_REGISTRY.items() if meta["phase"] == phase]


def get_attack_metadata(attack_id: str) -> dict[str, Any] | None:
    """Return metadata for a specific attack, or None if not found."""
    return ATTACK_REGISTRY.get(attack_id)


def get_all_attack_ids() -> list[str]:
    """Return all registered attack IDs."""
    return list(ATTACK_REGISTRY.keys())


def get_phases_with_attacks(enabled_attacks: list[str]) -> list[tuple[int, list[str]]]:
    """
    Given a list of enabled attack IDs, return (phase, [attack_ids]) tuples
    in execution order, filtering to only include enabled attacks.
    """
    result = []
    for phase in PHASE_ORDER:
        phase_attacks = [
            aid for aid in get_attacks_for_phase(phase) if aid in enabled_attacks
        ]
        if phase_attacks:
            result.append((phase, phase_attacks))
    return result
