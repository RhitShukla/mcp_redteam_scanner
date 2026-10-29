"""
Blueprint Analyzer — Challenge 1: Basic Enumeration & Data Exposure.

Passive reconnaissance module that runs IMMEDIATELY after connection.
Analyzes the server's tool/resource/prompt map for security flaws
WITHOUT invoking any tools — purely metadata-based analysis.

This runs before all active attack modules and provides context to them.

Detection Rules:
    BP-001: Suspicious tool names (admin, debug, shell, exec, eval)
    BP-002: Prompt injection in tool descriptions
    BP-003: Dangerous parameter names without sanitization
    BP-004: Resource URIs exposing internal structure
    BP-005: Tool sprawl (excessive tool count)
    BP-006: Missing input validation in schemas
    BP-007: Prompt exposure

Layer mapping: Sits between Layer 1 (Probe Engine) and Layer 2 (Attacks).
"""

from __future__ import annotations

import re
from typing import Any

from src.models import (
    Evidence,
    EvidenceType,
    Fixability,
    Finding,
    ReplayInfo,
    Severity,
)
from src.probe_engine import ProbeEngine


# ── Detection Configurations ──

# BP-001: Tool names that indicate internal/dangerous functionality
SUSPICIOUS_TOOL_NAMES: set[str] = {
    "admin", "admin_console", "admin_panel", "admin_tool",
    "debug", "internal_debug", "debug_mode", "debug_console",
    "shell", "bash", "sh", "cmd", "terminal", "console",
    "exec", "execute", "eval", "run_command", "system",
    "sudo", "root", "superuser",
    "deploy", "migrate", "drop", "truncate", "delete_all",
    "internal", "private", "backdoor", "test_endpoint",
    "dump", "export_all", "backup",
    "config", "set_config", "update_config",
}

# Words within tool names that are suspicious (partial match)
SUSPICIOUS_NAME_KEYWORDS: list[str] = [
    "admin", "debug", "internal", "shell", "exec", "eval",
    "sudo", "root", "dump", "backdoor", "private", "secret",
    "unsafe", "raw", "unfiltered", "bypass",
]

# BP-002: Prompt injection markers in tool descriptions
DESCRIPTION_INJECTION_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"ignore\s+(all\s+)?previous\s+instructions?", re.IGNORECASE),
    re.compile(r"you\s+must\s+(always\s+)?", re.IGNORECASE),
    re.compile(r"you\s+are\s+now\s+", re.IGNORECASE),
    re.compile(r"<\|im_start\|>", re.IGNORECASE),
    re.compile(r"<\|im_end\|>", re.IGNORECASE),
    re.compile(r"<system>", re.IGNORECASE),
    re.compile(r"</system>", re.IGNORECASE),
    re.compile(r"\[SYSTEM\]", re.IGNORECASE),
    re.compile(r"ADMIN\s+OVERRIDE", re.IGNORECASE),
    re.compile(r"DEBUG\s+MODE", re.IGNORECASE),
    re.compile(r"forget\s+(everything|all)", re.IGNORECASE),
    re.compile(r"new\s+task\s*:", re.IGNORECASE),
    re.compile(r"disregard\s+(prior|previous|above)", re.IGNORECASE),
    re.compile(r"override\s+safety", re.IGNORECASE),
    re.compile(r"skip\s+(all\s+)?safety", re.IGNORECASE),
]

# BP-003: Parameter names that indicate dangerous operations
DANGEROUS_PARAM_NAMES: set[str] = {
    "command", "cmd", "exec", "execute", "eval",
    "query", "sql", "sql_query", "raw_query",
    "path", "file_path", "filepath", "filename", "file",
    "url", "uri", "endpoint", "target", "host",
    "code", "script", "expression", "shell",
    "system", "os_command",
}

# BP-004: Resource URI patterns that leak internal structure
SUSPICIOUS_RESOURCE_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"file://", re.IGNORECASE),
    re.compile(r"config://", re.IGNORECASE),
    re.compile(r"internal://", re.IGNORECASE),
    re.compile(r"admin://", re.IGNORECASE),
    re.compile(r"debug://", re.IGNORECASE),
    re.compile(r"(?:localhost|127\.0\.0\.1|0\.0\.0\.0)", re.IGNORECASE),
    re.compile(r"\.corp\.|\.internal\.|\.local\.", re.IGNORECASE),
    re.compile(r"(?:password|secret|key|token|credential)", re.IGNORECASE),
    re.compile(r"(?:\.env|\.config|\.yml|\.yaml|\.json|\.ini)", re.IGNORECASE),
    re.compile(r"(?:database|db|mongo|redis|postgres|mysql)", re.IGNORECASE),
]

# BP-005: Tool sprawl threshold
DEFAULT_TOOL_SPRAWL_THRESHOLD: int = 20


class BlueprintAnalyzer:
    """
    Passive security analyzer for MCP server blueprints.

    Analyzes tool definitions, resource URIs, and prompt metadata
    without ever invoking any tools. Produces Finding objects
    compatible with the Layer 2 reporting pipeline.

    Usage:
        analyzer = BlueprintAnalyzer(engine)
        findings = await analyzer.analyze()
    """

    def __init__(
        self,
        engine: ProbeEngine,
        tool_sprawl_threshold: int = DEFAULT_TOOL_SPRAWL_THRESHOLD,
    ) -> None:
        self.engine = engine
        self.tool_sprawl_threshold = tool_sprawl_threshold
        self.findings: list[Finding] = []
        self._finding_counter: int = 0

        # Cached discovery data (shared with attack modules if needed)
        self.discovered_tools: list[dict[str, Any]] = []
        self.discovered_resources: list[dict[str, Any]] = []
        self.discovered_prompts: list[dict[str, Any]] = []
        self.attack_map: dict[str, Any] = {
            "targets": [],
            "by_surface": {},
            "by_severity": {},
            "summary": {},
        }

    def _next_finding_id(self) -> str:
        self._finding_counter += 1
        return f"BP-{self._finding_counter:03d}"

    def _add_finding(self, finding: Finding) -> None:
        self.findings.append(finding)

    @staticmethod
    def _as_text(value: Any) -> str:
        """Normalize untrusted metadata to safe display text."""
        if isinstance(value, str):
            return value
        if value is None:
            return ""
        return str(value)

    def _record_attack_target(
        self,
        finding: Finding,
        *,
        target_type: str,
        target_name: str,
        signal: str,
    ) -> None:
        """Persist an attack hint map that later modules can consume."""
        target = {
            "finding_id": finding.id,
            "severity": finding.severity.value,
            "surface": finding.surface,
            "target_type": target_type,
            "target_name": target_name,
            "signal": signal,
            "recommended_attack_focus": finding.title,
        }
        self.attack_map["targets"].append(target)

        by_surface = self.attack_map["by_surface"]
        if finding.surface not in by_surface:
            by_surface[finding.surface] = []
        by_surface[finding.surface].append(target)

        by_severity = self.attack_map["by_severity"]
        if finding.severity.value not in by_severity:
            by_severity[finding.severity.value] = []
        by_severity[finding.severity.value].append(target)

    def _refresh_attack_summary(self) -> None:
        self.attack_map["summary"] = {
            "total_targets": len(self.attack_map["targets"]),
            "critical_targets": len(self.attack_map["by_severity"].get("Critical", [])),
            "high_targets": len(self.attack_map["by_severity"].get("High", [])),
            "medium_targets": len(self.attack_map["by_severity"].get("Medium", [])),
            "low_targets": len(self.attack_map["by_severity"].get("Low", [])),
        }

    async def analyze(self) -> list[Finding]:
        """
        Run all passive analysis checks.

        Must be called inside an active engine.connect() context.
        Returns list of validated Finding objects.
        """
        self.findings.clear()
        self._finding_counter = 0
        self.attack_map = {
            "targets": [],
            "by_surface": {},
            "by_severity": {},
            "summary": {},
        }

        # Fetch server map
        try:
            self.discovered_tools = await self.engine.list_tools()
        except Exception:
            self.discovered_tools = []

        try:
            self.discovered_resources = await self.engine.list_resources()
        except Exception:
            self.discovered_resources = []

        try:
            self.discovered_prompts = await self.engine.list_prompts()
        except Exception:
            self.discovered_prompts = []

        # Run each detection rule
        self._check_suspicious_tool_names(self.discovered_tools)
        self._check_description_poisoning(self.discovered_tools)
        self._check_dangerous_parameters(self.discovered_tools)
        self._check_resource_exposure(self.discovered_resources)
        self._check_tool_sprawl(self.discovered_tools)
        self._check_schema_validation(self.discovered_tools)
        self._check_prompt_exposure(self.discovered_prompts)
        self._refresh_attack_summary()

        return self.findings

    # ── BP-001: Suspicious Tool Names ──

    def _check_suspicious_tool_names(self, tools: list[dict[str, Any]]) -> None:
        """Flag tools with names that suggest internal/dangerous functionality."""
        for tool in tools:
            name = self._as_text(tool.get("name", ""))
            name_lower = name.lower()

            # Exact match
            flagged = name_lower in SUSPICIOUS_TOOL_NAMES

            # Keyword partial match
            matched_keywords = []
            if not flagged:
                for keyword in SUSPICIOUS_NAME_KEYWORDS:
                    if keyword in name_lower:
                        flagged = True
                        matched_keywords.append(keyword)

            if flagged:
                keyword_info = (
                    f"Matched keywords: {', '.join(matched_keywords)}"
                    if matched_keywords
                    else f"Exact match: '{name_lower}'"
                )
                finding = Finding(
                    id=self._next_finding_id(),
                    title=f"Suspicious tool exposed: '{name}'",
                    surface="A - Tool Definition & Discovery",
                    module="BP - Blueprint Analyzer",
                    severity=Severity.HIGH,
                    fixability=Fixability.CONFIGURATION,
                    fixability_rationale=(
                        f"The tool '{name}' appears to provide internal/administrative "
                        f"functionality. Remove it from the public tool list or restrict "
                        f"access via role-based permissions. This is a configuration change."
                    ),
                    description=(
                        f"The MCP server exposes a tool named '{name}' which suggests "
                        f"internal or dangerous functionality. {keyword_info}. "
                        f"Description: {tool.get('description', 'N/A')}. "
                        f"Tools with these names should not be visible to untrusted clients."
                    ),
                    attack_narrative=(
                        f"1. Connected to MCP endpoint\n"
                        f"2. Called tools/list to enumerate available tools\n"
                        f"3. Found tool '{name}' — name matches suspicious patterns\n"
                        f"4. {keyword_info}\n"
                        f"5. This tool may grant elevated access or leak internal data"
                    ),
                    evidence=[Evidence(
                        type=EvidenceType.TOOL_INVOCATION,
                        request={"method": "tools/list"},
                        response={"tool": tool},
                    )],
                    replay=ReplayInfo(
                        command=f"mcp-redteam replay --finding {self._finding_counter:03d}",
                        trace_file=f"traces/BP-{self._finding_counter:03d}.json",
                    ),
                    recommendation=(
                        f"Remove '{name}' from the public tool registry or gate it "
                        f"behind authentication/authorization. If this tool is needed "
                        f"for development, use environment-based feature flags to "
                        f"disable it in production."
                    ),
                )
                self._add_finding(finding)
                self._record_attack_target(
                    finding,
                    target_type="tool",
                    target_name=name or "<unnamed-tool>",
                    signal=keyword_info,
                )

    # ── BP-002: Description Poisoning ──

    def _check_description_poisoning(self, tools: list[dict[str, Any]]) -> None:
        """Flag tools with prompt injection markers in their descriptions."""
        for tool in tools:
            name = self._as_text(tool.get("name", ""))
            description = self._as_text(tool.get("description", ""))

            matched_patterns = []
            for pattern in DESCRIPTION_INJECTION_PATTERNS:
                if pattern.search(description):
                    matched_patterns.append(pattern.pattern)

            if matched_patterns:
                finding = Finding(
                    id=self._next_finding_id(),
                    title=f"Prompt injection detected in '{name}' description",
                    surface="A - Tool Definition & Discovery",
                    module="BP - Blueprint Analyzer",
                    severity=Severity.CRITICAL,
                    fixability=Fixability.DESIGN,
                    fixability_rationale=(
                        f"Tool descriptions are passed to LLMs as context. Injection "
                        f"markers in the description of '{name}' can manipulate LLM "
                        f"behavior. Requires redesigning how tool metadata is authored "
                        f"and reviewed — not a simple config change."
                    ),
                    description=(
                        f"The tool '{name}' contains prompt injection patterns in its "
                        f"description. These patterns can manipulate LLM behavior when "
                        f"the tool is presented in context. Matched patterns: "
                        f"{', '.join(matched_patterns[:3])}. Full description: "
                        f"'{description[:200]}'"
                    ),
                    attack_narrative=(
                        f"1. Connected to MCP endpoint\n"
                        f"2. Called tools/list to enumerate available tools\n"
                        f"3. Inspected description of tool '{name}'\n"
                        f"4. Found {len(matched_patterns)} prompt injection pattern(s)\n"
                        f"5. These patterns can override LLM instructions when the "
                        f"tool metadata is loaded into context"
                    ),
                    evidence=[Evidence(
                        type=EvidenceType.TOOL_INVOCATION,
                        request={"method": "tools/list"},
                        response={"tool_name": name, "description": description},
                    )],
                    replay=ReplayInfo(
                        command=f"mcp-redteam replay --finding {self._finding_counter:03d}",
                        trace_file=f"traces/BP-{self._finding_counter:03d}.json",
                    ),
                    recommendation=(
                        f"Sanitize the description of '{name}' to remove injection "
                        f"patterns. Implement a review process for tool descriptions "
                        f"and consider using a description schema that restricts content "
                        f"to plain declarative text."
                    ),
                )
                self._add_finding(finding)
                self._record_attack_target(
                    finding,
                    target_type="tool-description",
                    target_name=name or "<unnamed-tool>",
                    signal=f"Matched patterns: {', '.join(matched_patterns[:3])}",
                )

    # ── BP-003: Dangerous Parameters ──

    def _check_dangerous_parameters(self, tools: list[dict[str, Any]]) -> None:
        """Flag tools with parameter names that suggest injection surfaces."""
        for tool in tools:
            name = self._as_text(tool.get("name", ""))
            schema = tool.get("inputSchema", {})
            if not isinstance(schema, dict):
                schema = {}
            properties = schema.get("properties", {})
            if not isinstance(properties, dict):
                properties = {}

            dangerous_params = []
            for param_name in properties:
                if param_name.lower() in DANGEROUS_PARAM_NAMES:
                    dangerous_params.append(param_name)

            if dangerous_params:
                finding = Finding(
                    id=self._next_finding_id(),
                    title=f"Dangerous parameter(s) in tool '{name}': {', '.join(dangerous_params)}",
                    surface="B - Tool Invocation & Execution",
                    module="BP - Blueprint Analyzer",
                    severity=Severity.MEDIUM,
                    fixability=Fixability.DESIGN,
                    fixability_rationale=(
                        f"Parameters named {', '.join(dangerous_params)} in '{name}' "
                        f"suggest the tool accepts raw commands, queries, or file paths. "
                        f"Proper input validation/sanitization requires design changes to "
                        f"the tool handler."
                    ),
                    description=(
                        f"The tool '{name}' has parameters that suggest it accepts "
                        f"potentially dangerous input: {', '.join(dangerous_params)}. "
                        f"These may be vulnerable to injection attacks (SQL, command, "
                        f"path traversal) if the tool handler does not sanitize inputs."
                    ),
                    attack_narrative=(
                        f"1. Connected to MCP endpoint\n"
                        f"2. Called tools/list to enumerate available tools\n"
                        f"3. Inspected input schema of tool '{name}'\n"
                        f"4. Found parameter(s) with dangerous names: "
                        f"{', '.join(dangerous_params)}\n"
                        f"5. These parameters are candidates for injection testing"
                    ),
                    evidence=[Evidence(
                        type=EvidenceType.TOOL_INVOCATION,
                        request={"method": "tools/list"},
                        response={
                            "tool_name": name,
                            "dangerous_params": dangerous_params,
                            "schema": schema,
                        },
                    )],
                    replay=ReplayInfo(
                        command=f"mcp-redteam replay --finding {self._finding_counter:03d}",
                        trace_file=f"traces/BP-{self._finding_counter:03d}.json",
                    ),
                    recommendation=(
                        f"Add input validation to '{name}' for parameters: "
                        f"{', '.join(dangerous_params)}. Use parameterized queries "
                        f"instead of string concatenation, whitelist allowed paths, "
                        f"and sanitize command inputs."
                    ),
                )
                self._add_finding(finding)
                self._record_attack_target(
                    finding,
                    target_type="tool-parameter",
                    target_name=name or "<unnamed-tool>",
                    signal=f"Dangerous parameters: {', '.join(dangerous_params)}",
                )

    # ── BP-004: Resource Exposure ──

    def _check_resource_exposure(self, resources: list[dict[str, Any]]) -> None:
        """Flag resources whose URIs or names expose internal structure."""
        for resource in resources:
            uri = self._as_text(resource.get("uri", resource.get("name", "")))
            description = self._as_text(resource.get("description", ""))
            combined = f"{uri} {description}"

            matched_patterns = []
            for pattern in SUSPICIOUS_RESOURCE_PATTERNS:
                if pattern.search(combined):
                    matched_patterns.append(pattern.pattern)

            if matched_patterns:
                finding = Finding(
                    id=self._next_finding_id(),
                    title=f"Resource URI exposes internal structure: '{uri}'",
                    surface="D - Data Flow & Exfiltration",
                    module="BP - Blueprint Analyzer",
                    severity=Severity.MEDIUM,
                    fixability=Fixability.CONFIGURATION,
                    fixability_rationale=(
                        f"Resource '{uri}' exposes internal infrastructure details. "
                        f"Use opaque resource identifiers instead of descriptive URIs. "
                        f"This is a configuration change to the resource registry."
                    ),
                    description=(
                        f"The resource '{uri}' has a URI or description that reveals "
                        f"internal infrastructure (file paths, config locations, internal "
                        f"hostnames, database references). This information aids "
                        f"attackers in mapping the internal topology."
                    ),
                    attack_narrative=(
                        f"1. Connected to MCP endpoint\n"
                        f"2. Called resources/list to enumerate available resources\n"
                        f"3. Found resource '{uri}' with revealing metadata\n"
                        f"4. Matched patterns: {', '.join(matched_patterns[:3])}\n"
                        f"5. This information leaks internal architecture details"
                    ),
                    evidence=[Evidence(
                        type=EvidenceType.RESOURCE_READ,
                        request={"method": "resources/list"},
                        response={"resource": resource},
                    )],
                    replay=ReplayInfo(
                        command=f"mcp-redteam replay --finding {self._finding_counter:03d}",
                        trace_file=f"traces/BP-{self._finding_counter:03d}.json",
                    ),
                    recommendation=(
                        f"Replace the URI '{uri}' with an opaque identifier. "
                        f"Move sensitive configuration to environment variables "
                        f"and avoid exposing internal hostnames, file paths, or "
                        f"database references in resource metadata."
                    ),
                )
                self._add_finding(finding)
                self._record_attack_target(
                    finding,
                    target_type="resource",
                    target_name=uri or "<unnamed-resource>",
                    signal=f"Matched patterns: {', '.join(matched_patterns[:3])}",
                )

    # ── BP-005: Tool Sprawl ──

    def _check_tool_sprawl(self, tools: list[dict[str, Any]]) -> None:
        """Flag servers that expose an excessive number of tools."""
        if len(tools) > self.tool_sprawl_threshold:
            tool_names = [t.get("name", "unknown") for t in tools]
            finding = Finding(
                id=self._next_finding_id(),
                title=f"Excessive tool count: {len(tools)} tools exposed (threshold: {self.tool_sprawl_threshold})",
                surface="A - Tool Definition & Discovery",
                module="BP - Blueprint Analyzer",
                severity=Severity.LOW,
                fixability=Fixability.ARCHITECTURAL,
                fixability_rationale=(
                    f"The server exposes {len(tools)} tools, suggesting a lack of "
                    f"scoping or segmentation. Reducing the tool surface may require "
                    f"architectural changes to implement role-based tool visibility."
                ),
                description=(
                    f"The MCP server exposes {len(tools)} tools, exceeding the "
                    f"threshold of {self.tool_sprawl_threshold}. A large tool surface "
                    f"increases attack area and suggests the server may not implement "
                    f"proper tool scoping per client/role."
                ),
                attack_narrative=(
                    f"1. Connected to MCP endpoint\n"
                    f"2. Called tools/list — received {len(tools)} tools\n"
                    f"3. Tool count exceeds threshold of {self.tool_sprawl_threshold}\n"
                    f"4. Large tool surfaces increase the probability of "
                    f"misconfigured or insecure handlers"
                ),
                evidence=[Evidence(
                    type=EvidenceType.TOOL_INVOCATION,
                    request={"method": "tools/list"},
                    response={"tool_count": len(tools), "tools": tool_names},
                )],
                replay=ReplayInfo(
                    command=f"mcp-redteam replay --finding {self._finding_counter:03d}",
                    trace_file=f"traces/BP-{self._finding_counter:03d}.json",
                ),
                recommendation=(
                    f"Reduce the tool surface by implementing role-based tool "
                    f"visibility. Only expose tools relevant to the connecting "
                    f"client's authorization level. Use tool grouping and lazy "
                    f"registration to limit the default attack surface."
                ),
            )
            self._add_finding(finding)
            self._record_attack_target(
                finding,
                target_type="toolset",
                target_name="tools/list",
                signal=f"Tool count={len(tools)} threshold={self.tool_sprawl_threshold}",
            )

    # ── BP-006: Missing Input Validation ──

    def _check_schema_validation(self, tools: list[dict[str, Any]]) -> None:
        """Flag tools with weak or missing input schemas."""
        for tool in tools:
            name = self._as_text(tool.get("name", ""))
            schema = tool.get("inputSchema", {})
            if not isinstance(schema, dict):
                schema = {}
            properties = schema.get("properties", {})
            if not isinstance(properties, dict):
                properties = {}
            required = schema.get("required", [])
            if not isinstance(required, list):
                required = []
            issues: list[str] = []

            # No schema at all
            if not schema or not properties:
                issues.append("No input schema defined — accepts arbitrary input")

            # additionalProperties allowed
            if schema.get("additionalProperties", False) is True:
                issues.append("additionalProperties is true — accepts undeclared parameters")

            # Required fields without type constraints
            for param_name in required:
                param_schema = properties.get(param_name, {})
                if not param_schema.get("type"):
                    issues.append(
                        f"Required parameter '{param_name}' has no type constraint"
                    )

            # Parameters with no type at all
            for param_name, param_schema in properties.items():
                if not param_schema.get("type") and param_name not in required:
                    issues.append(
                        f"Optional parameter '{param_name}' has no type constraint"
                    )

            if issues:
                finding = Finding(
                    id=self._next_finding_id(),
                    title=f"Weak input validation on tool '{name}'",
                    surface="B - Tool Invocation & Execution",
                    module="BP - Blueprint Analyzer",
                    severity=Severity.LOW,
                    fixability=Fixability.CONFIGURATION,
                    fixability_rationale=(
                        f"Tool '{name}' has weak input schemas. Adding type constraints, "
                        f"format validation, and disabling additionalProperties are "
                        f"configuration-level improvements."
                    ),
                    description=(
                        f"The tool '{name}' has input validation issues: "
                        f"{'; '.join(issues)}. Weak schemas allow unexpected inputs "
                        f"that can trigger errors, crashes, or injection attacks."
                    ),
                    attack_narrative=(
                        f"1. Connected to MCP endpoint\n"
                        f"2. Called tools/list to enumerate available tools\n"
                        f"3. Inspected input schema of tool '{name}'\n"
                        f"4. Found {len(issues)} validation issue(s)\n"
                        f"5. Issues: {'; '.join(issues)}"
                    ),
                    evidence=[Evidence(
                        type=EvidenceType.TOOL_INVOCATION,
                        request={"method": "tools/list"},
                        response={"tool_name": name, "schema": schema, "issues": issues},
                    )],
                    replay=ReplayInfo(
                        command=f"mcp-redteam replay --finding {self._finding_counter:03d}",
                        trace_file=f"traces/BP-{self._finding_counter:03d}.json",
                    ),
                    recommendation=(
                        f"Strengthen the input schema for '{name}': add type constraints "
                        f"to all parameters, set additionalProperties to false, add "
                        f"format/pattern validators for string inputs, and define "
                        f"min/max constraints for numeric inputs."
                    ),
                )
                self._add_finding(finding)
                self._record_attack_target(
                    finding,
                    target_type="tool-schema",
                    target_name=name or "<unnamed-tool>",
                    signal=f"Schema issues: {'; '.join(issues[:2])}",
                )

    # ── BP-007: Prompt Exposure ──

    def _check_prompt_exposure(self, prompts: list[dict[str, Any]]) -> None:
        """
        Flag prompt metadata that can leak internal or privileged instructions.
        """
        for prompt in prompts:
            name = self._as_text(prompt.get("name", ""))
            description = self._as_text(prompt.get("description", ""))
            combined = f"{name} {description}".lower()

            if any(k in combined for k in ("admin", "internal", "system", "secret", "override", "debug")):
                finding = Finding(
                    id=self._next_finding_id(),
                    title=f"Prompt metadata may expose privileged context: '{name or 'unnamed'}'",
                    surface="C - Prompt Context & Injection",
                    module="BP - Blueprint Analyzer",
                    severity=Severity.MEDIUM,
                    fixability=Fixability.CONFIGURATION,
                    fixability_rationale=(
                        "Prompt names/descriptions appear to expose privileged intent. "
                        "Restrict prompt visibility or sanitize metadata."
                    ),
                    description=(
                        f"Prompt '{name or 'unnamed'}' includes metadata keywords that may "
                        f"signal privileged/system behavior. Exposed prompt metadata can "
                        f"guide attackers toward higher-value prompt injection targets."
                    ),
                    attack_narrative=(
                        "1. Connected to MCP endpoint\n"
                        "2. Called prompts/list to enumerate prompt metadata\n"
                        f"3. Found potentially sensitive prompt context in '{name or 'unnamed'}'\n"
                        "4. Metadata suggests privileged/system-level behavior\n"
                        "5. Prompt becomes a prioritized social-engineering/injection target"
                    ),
                    evidence=[Evidence(
                        type=EvidenceType.PROMPT_RESPONSE,
                        request={"method": "prompts/list"},
                        response={"prompt": prompt},
                    )],
                    replay=ReplayInfo(
                        command=f"mcp-redteam replay --finding {self._finding_counter:03d}",
                        trace_file=f"traces/BP-{self._finding_counter:03d}.json",
                    ),
                    recommendation=(
                        f"Review prompt '{name or 'unnamed'}' metadata and avoid exposing "
                        "privileged/system semantics in public prompt listings."
                    ),
                )
                self._add_finding(finding)
                self._record_attack_target(
                    finding,
                    target_type="prompt",
                    target_name=name or "<unnamed-prompt>",
                    signal="Privileged prompt keywords in metadata",
                )

    def summary(self) -> dict[str, Any]:
        """Summary for reporting."""
        return {
            "module": "BP",
            "name": "Blueprint Analyzer",
            "surface": "Passive Analysis",
            "tools_analyzed": len(self.discovered_tools),
            "resources_analyzed": len(self.discovered_resources),
            "prompts_analyzed": len(self.discovered_prompts),
            "findings_count": len(self.findings),
            "attack_targets_count": len(self.attack_map.get("targets", [])),
            "severities": {
                s: sum(1 for f in self.findings if f.severity.value == s)
                for s in ["Critical", "High", "Medium", "Low", "Info"]
                if any(f.severity.value == s for f in self.findings)
            },
        }

    def attack_surface_map(self) -> dict[str, Any]:
        """
        Return prioritized attack map derived from passive blueprint analysis.
        """
        return self.attack_map
