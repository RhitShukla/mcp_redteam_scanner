from __future__ import annotations

from src.attack_base import AttackModule
from src.models import Evidence, EvidenceType, Fixability, Finding, ReplayInfo, Severity


class A2SchemaManipulation(AttackModule):
    name = "Tool Schema Manipulation Checks"
    surface = "A - Tool Definition & Discovery"
    module_id = "A2"
    description = "Flags weak schemas that accept undeclared or untyped arguments."

    async def run(self) -> list[Finding]:
        self.findings.clear()
        self._finding_counter = 0
        tools = self.get_phase0_context().get("tools", [])
        for tool in tools:
            name = str(tool.get("name", ""))
            schema = tool.get("inputSchema", {})
            if not isinstance(schema, dict):
                continue
            props = schema.get("properties", {})
            if not isinstance(props, dict):
                props = {}
            weak = schema.get("additionalProperties") is True or not props
            if not weak:
                continue
            self.add_finding(Finding(
                id=self._next_finding_id(),
                title=f"Weak or over-flexible schema on '{name}'",
                surface=self.surface,
                module=f"{self.module_id} - {self.name}",
                severity=Severity.MEDIUM,
                fixability=Fixability.CONFIGURATION,
                fixability_rationale="Schema strictness can be tightened without redesigning transport.",
                description=f"Tool `{name}` may accept undeclared/unbounded inputs.",
                attack_narrative="1. Parsed inputSchema metadata\n2. Found missing properties or additionalProperties=true\n3. Tool may allow hidden parameters",
                evidence=[Evidence(type=EvidenceType.TOOL_INVOCATION, request={"method": "tools/list"}, response={"tool": name, "schema": schema})],
                replay=ReplayInfo(command=f"mcp-redteam replay --finding {self.module_id}-{self._finding_counter:03d}", trace_file=f"traces/{self.module_id}-{self._finding_counter:03d}.json"),
                recommendation="Set additionalProperties=false and define strict types/constraints for each field.",
            ))
        return self.findings
