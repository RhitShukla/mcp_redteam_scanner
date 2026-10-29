"""
Phase 2 - Shadow tool detection.

Goal:
    Identify tools with benign names but risky capabilities/descriptions, or
    tools where naming and behavior intent look intentionally mismatched.

Plan A:
    Use Phase 0 tool map.
Plan B:
    Pull tools/list directly if needed.
"""

from __future__ import annotations

from src.attack_base import AttackModule
from src.models import Evidence, EvidenceType, Fixability, Finding, ReplayInfo, Severity


BENIGN_NAME_HINTS = ("safe", "helper", "calc", "calculator", "util", "assistant", "echo")
RISKY_HINTS = (
    "exec",
    "shell",
    "command",
    "system",
    "file",
    "path",
    "query",
    "sql",
    "internal",
    "debug",
    "admin",
    "http",
    "url",
)


class MCPToolShadowing(AttackModule):
    name = "Tool Shadowing Detection"
    surface = "A - Tool Definition & Discovery"
    module_id = "A3"
    description = (
        "Detects potentially deceptive tools where friendly naming hides risky "
        "capabilities or dangerous argument surfaces."
    )

    async def run(self) -> list[Finding]:
        self.findings.clear()
        self._finding_counter = 0

        phase0 = self.get_phase0_context()
        tools = phase0.get("tools")
        if not isinstance(tools, list):
            try:
                tools = await self.engine.list_tools()
            except Exception:
                tools = []
        if not tools:
            return self.findings

        for tool in tools:
            name = str(tool.get("name", ""))
            desc = str(tool.get("description", ""))
            schema = tool.get("inputSchema", {})
            properties = schema.get("properties", {}) if isinstance(schema, dict) else {}
            param_names = [str(k).lower() for k in properties.keys()]

            name_l = name.lower()
            desc_l = desc.lower()
            is_benign_named = any(k in name_l for k in BENIGN_NAME_HINTS)
            risky_hits = sorted(
                {
                    k
                    for k in RISKY_HINTS
                    if k in name_l or k in desc_l or any(k in p for p in param_names)
                }
            )

            # Primary signal: benign-looking name with risky capabilities.
            if not (is_benign_named and risky_hits):
                continue

            finding = Finding(
                id=self._next_finding_id(),
                title=f"Potential shadow tool detected: '{name}'",
                surface=self.surface,
                module=f"{self.module_id} - {self.name}",
                severity=Severity.HIGH,
                fixability=Fixability.DESIGN,
                fixability_rationale=(
                    "Tool intent appears ambiguous/deceptive. Renaming and capability "
                    "separation requires interface and design changes."
                ),
                description=(
                    f"Tool '{name}' appears benign by name but exposes risky signals: "
                    f"{', '.join(risky_hits)}."
                ),
                attack_narrative=(
                    "1. Enumerated tools from server metadata\n"
                    f"2. Classified '{name}' as benign-looking by naming pattern\n"
                    f"3. Found risky indicators in description/schema: {', '.join(risky_hits)}\n"
                    "4. This mismatch can trick reviewers and increase exploitation risk"
                ),
                evidence=[
                    Evidence(
                        type=EvidenceType.TOOL_INVOCATION,
                        request={"method": "tools/list"},
                        response={
                            "tool_name": name,
                            "description": desc,
                            "schema_properties": list(properties.keys()),
                            "risky_indicators": risky_hits,
                        },
                    )
                ],
                replay=ReplayInfo(
                    command=f"mcp-redteam replay --finding {self.module_id}-{self._finding_counter:03d}",
                    trace_file=f"traces/{self.module_id}-{self._finding_counter:03d}.json",
                ),
                recommendation=(
                    "Rename tools to accurately reflect privilege level and action type. "
                    "Split risky operations into explicitly privileged tools and gate "
                    "them by authorization policy."
                ),
            )
            self.add_finding(finding)

        return self.findings
