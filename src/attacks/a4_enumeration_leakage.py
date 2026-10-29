from __future__ import annotations

from src.attack_base import AttackModule
from src.models import Evidence, EvidenceType, Fixability, Finding, ReplayInfo, Severity


class A4EnumerationLeakage(AttackModule):
    name = "Tool Enumeration Disclosure"
    surface = "A - Tool Definition & Discovery"
    module_id = "A4"
    description = "Detects broad capability leakage via discovery endpoints."

    async def run(self) -> list[Finding]:
        self.findings.clear()
        self._finding_counter = 0
        p0 = self.get_phase0_context()
        tools = p0.get("tools", [])
        resources = p0.get("resources", [])
        prompts = p0.get("prompts", [])

        if not isinstance(tools, list) or not tools:
            try:
                tools = await self.engine.list_tools()
            except Exception:
                tools = []
        if not isinstance(resources, list) or not resources:
            try:
                resources = await self.engine.list_resources()
            except Exception:
                resources = []
        if not isinstance(prompts, list) or not prompts:
            try:
                prompts = await self.engine.list_prompts()
            except Exception:
                prompts = []

        if not tools and not resources and not prompts:
            return self.findings

        if len(tools) + len(resources) + len(prompts) >= 10:
            self.add_finding(Finding(
                id=self._next_finding_id(),
                title="Broad enumeration disclosure from discovery endpoints",
                surface=self.surface,
                module=f"{self.module_id} - {self.name}",
                severity=Severity.MEDIUM,
                fixability=Fixability.CONFIGURATION,
                fixability_rationale="Discovery filtering is a policy/configuration concern.",
                description="Server exposes a large amount of metadata through list endpoints.",
                attack_narrative="1. Used Phase 0 discovery responses\n2. Counted visible tools/resources/prompts\n3. Large inventory exposed to a single session",
                evidence=[Evidence(type=EvidenceType.TOOL_INVOCATION, request={"method": "discovery-summary"}, response={"tools": len(tools), "resources": len(resources), "prompts": len(prompts)})],
                replay=ReplayInfo(command=f"mcp-redteam replay --finding {self.module_id}-{self._finding_counter:03d}", trace_file=f"traces/{self.module_id}-{self._finding_counter:03d}.json"),
                recommendation="Limit discovery output by role; hide non-essential/internal capabilities.",
            ))
        return self.findings
