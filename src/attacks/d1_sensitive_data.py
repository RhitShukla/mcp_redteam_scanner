"""
D1 — Sensitive Data in Tool Responses.

Layer 2 attack module.

What it tests:
    Invokes every discovered tool with benign inputs and scans responses
    for PII patterns (SSN, email, API keys, internal IDs, credit cards).
    Uses regex-based detection, not ML.

Why it matters:
    MCP tools that return raw data from backends may leak PII or secrets
    to LLM contexts. This data can then be exfiltrated via model output,
    logged in conversation history, or cached in intermediate systems.
    Tools should sanitize responses before returning them.
"""

from __future__ import annotations

import re
from typing import Any

from src.attack_base import AttackModule
from src.models import (
    Evidence,
    EvidenceType,
    Fixability,
    Finding,
    ReplayInfo,
    Severity,
)
from src.probe_engine import ProbeEngine


# ── PII Detection Patterns ──

PII_PATTERNS: dict[str, dict[str, Any]] = {
    "ssn": {
        "pattern": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
        "label": "Social Security Number",
        "severity": Severity.HIGH,
    },
    "email": {
        "pattern": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),
        "label": "Email Address",
        "severity": Severity.MEDIUM,
    },
    "api_key_generic": {
        "pattern": re.compile(r"\b(?:sk|ak|api[_-]?key)[_-][A-Za-z0-9-]{10,}\b", re.IGNORECASE),
        "label": "API Key",
        "severity": Severity.CRITICAL,
    },
    "credit_card": {
        "pattern": re.compile(r"\b(?:\d{4}[- ]?){3}\d{4}\b"),
        "label": "Credit Card Number",
        "severity": Severity.HIGH,
    },
    "aws_key": {
        "pattern": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        "label": "AWS Access Key",
        "severity": Severity.CRITICAL,
    },
    "private_ip": {
        "pattern": re.compile(
            r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b"
        ),
        "label": "Internal/Private IP Address",
        "severity": Severity.LOW,
    },
    "jwt_token": {
        "pattern": re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
        "label": "JWT Token",
        "severity": Severity.HIGH,
    },
}


def _extract_text_from_response(response: dict[str, Any]) -> str:
    """Pull all text content from an MCP tool response."""
    parts: list[str] = []
    for item in response.get("content", []):
        if isinstance(item, dict) and item.get("type") == "text":
            parts.append(item.get("text", ""))
        elif isinstance(item, dict):
            # Capture any string values in non-text content blocks
            parts.append(str(item))
    return "\n".join(parts)


def scan_for_pii(text: str) -> list[dict[str, Any]]:
    """Scan text for PII patterns. Returns list of matches."""
    matches: list[dict[str, Any]] = []
    for pattern_name, info in PII_PATTERNS.items():
        found = info["pattern"].findall(text)
        for match in found:
            matches.append({
                "pattern": pattern_name,
                "label": info["label"],
                "matched_value": match,
                "severity": info["severity"],
            })
    return matches


def _generate_benign_args(tool: dict[str, Any]) -> dict[str, Any]:
    """
    Generate safe, benign arguments for a tool based on its input schema.
    Uses type-appropriate defaults that shouldn't trigger errors.
    """
    schema = tool.get("input_schema", tool.get("inputSchema", {}))
    properties = schema.get("properties", {})
    required = schema.get("required", [])
    args: dict[str, Any] = {}

    for param_name, param_schema in properties.items():
        param_type = param_schema.get("type", "string")
        if param_type == "string":
            args[param_name] = "test"
        elif param_type == "integer":
            args[param_name] = 1
        elif param_type == "number":
            args[param_name] = 1.0
        elif param_type == "boolean":
            args[param_name] = True
        elif param_type == "array":
            args[param_name] = []
        elif param_type == "object":
            args[param_name] = {}
        else:
            args[param_name] = "test"

    return args


class D1SensitiveData(AttackModule):
    """Scan tool responses for sensitive data leakage."""

    name = "Sensitive Data in Tool Responses"
    surface = "D - Data Flow & Exfiltration"
    module_id = "D1"
    description = (
        "Invokes every discovered tool with benign inputs and scans "
        "responses for PII patterns (SSN, email, API keys, etc.). "
        "Detects data that should be filtered before reaching LLM contexts."
    )

    async def run(self) -> list[Finding]:
        self.findings.clear()
        self._finding_counter = 0

        # Step 1: Reuse Phase 0 map when available (avoids duplicate discovery).
        phase0 = self.get_phase0_context()
        tools = phase0.get("tools") if isinstance(phase0, dict) else None
        if not isinstance(tools, list):
            tools = await self.engine.list_tools()
        if not tools:
            return self.findings

        # Step 2: Invoke each tool with benign args, scan responses
        for tool in tools:
            tool_name = tool["name"]
            args = _generate_benign_args(tool)

            try:
                result = await self.engine.call_tool(tool_name, args)
            except Exception:
                # Tool call failed — not a data leak, skip
                continue

            if result.get("isError"):
                continue

            # Step 3: Extract text and scan for PII
            text = _extract_text_from_response(result)
            pii_matches = scan_for_pii(text)

            if not pii_matches:
                continue

            # Step 4: Group matches by severity for this tool
            # One finding per tool (aggregates all PII types found)
            # Severity enum: CRITICAL=0, HIGH=1, ..., INFO=4
            # Worst = lowest index
            worst_severity = min(
                (m["severity"] for m in pii_matches),
                key=lambda s: list(Severity).index(s),
            )

            match_descriptions = [
                f"- {m['label']}: `{m['matched_value']}`"
                for m in pii_matches
            ]
            match_summary = "\n".join(match_descriptions)

            pii_types = list({m["label"] for m in pii_matches})

            finding = Finding(
                id=self._next_finding_id(),
                title=f"Sensitive data exposed in {tool_name} tool response",
                surface=self.surface,
                module=f"{self.module_id} - {self.name}",
                severity=worst_severity,
                fixability=Fixability.CONFIGURATION,
                fixability_rationale=(
                    f"Output filtering can be added to the {tool_name} tool handler "
                    f"to strip {', '.join(pii_types)} before returning results. "
                    f"This is a configuration-level fix that does not require "
                    f"architectural changes."
                ),
                description=(
                    f"The {tool_name} tool returns sensitive data in its response "
                    f"when invoked with benign inputs. Detected PII types: "
                    f"{', '.join(pii_types)}. This data would be exposed to any "
                    f"LLM context consuming tool results."
                ),
                attack_narrative=(
                    f"1. Connected to MCP endpoint\n"
                    f"2. Discovered tool '{tool_name}' via tools/list\n"
                    f"3. Generated benign arguments: {args}\n"
                    f"4. Invoked tool with benign arguments\n"
                    f"5. Scanned response text for PII patterns\n"
                    f"6. Found {len(pii_matches)} sensitive data match(es):\n"
                    f"{match_summary}"
                ),
                evidence=[
                    Evidence(
                        type=EvidenceType.TOOL_INVOCATION,
                        request={"tool": tool_name, "arguments": args},
                        response=result,
                        trace_entry_id=self._find_trace_id(tool_name, args),
                    )
                ],
                replay=ReplayInfo(
                    command=(
                        f"mcp-redteam replay --finding {self.module_id}-{self._finding_counter:03d} "
                        f"--target {self.engine.config.endpoint_url}"
                    ),
                    trace_file=f"traces/{self.module_id}-{self._finding_counter:03d}.json",
                ),
                recommendation=(
                    f"Add output filtering to the {tool_name} tool handler to strip "
                    f"{', '.join(pii_types)} before returning results. Implement a "
                    f"response sanitizer that runs regex-based PII detection and "
                    f"redacts matched patterns before the response reaches the LLM context."
                ),
            )
            self.add_finding(finding)

        return self.findings

    def _find_trace_id(self, tool_name: str, args: dict[str, Any]) -> str | None:
        """Find the trace entry ID for a specific tool call."""
        for trace in reversed(self.engine.traces):
            if (
                trace.method == "tools/call"
                and trace.request.get("name") == tool_name
                and trace.request.get("arguments") == args
            ):
                return trace.id
        return None
