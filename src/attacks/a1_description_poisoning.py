from __future__ import annotations

import re

from src.attack_base import AttackModule
from src.models import Evidence, EvidenceType, Fixability, Finding, ReplayInfo, Severity


PATTERNS = [
    re.compile(r"ignore\s+(all\s+)?previous\s+instructions?", re.IGNORECASE),
    re.compile(r"you\s+must\s+", re.IGNORECASE),
    re.compile(r"<system>", re.IGNORECASE),
]


class A1DescriptionPoisoning(AttackModule):
    name = "Tool Description Poisoning"
    surface = "A - Tool Definition & Discovery"
    module_id = "A1"
    description = "Detects prompt-injection style instructions embedded in tool descriptions."

    async def run(self) -> list[Finding]:
        self.findings.clear()
        self._finding_counter = 0
        tools = self.get_phase0_context().get("tools", [])
        if not isinstance(tools, list) or not tools:
            try:
                tools = await self.engine.list_tools()
            except Exception:
                tools = []

        for tool in tools:
            name = str(tool.get("name", ""))
            desc = str(tool.get("description", ""))
            matched = [p.pattern for p in PATTERNS if p.search(desc)]
            if not matched:
                continue
            self.add_finding(Finding(
                id=self._next_finding_id(),
                title=f"Description poisoning signal in '{name}'",
                surface=self.surface,
                module=f"{self.module_id} - {self.name}",
                severity=Severity.CRITICAL,
                fixability=Fixability.DESIGN,
                fixability_rationale="Description authoring and trust boundaries require design control.",
                description=f"Tool `{name}` description contains injection markers: {', '.join(matched[:2])}.",
                attack_narrative="1. Reviewed tool metadata from discovery\n2. Matched injection patterns in description\n3. Metadata can steer model behavior unsafely",
                evidence=[Evidence(type=EvidenceType.TOOL_INVOCATION, request={"method": "tools/list"}, response={"tool": name, "description": desc})],
                replay=ReplayInfo(command=f"mcp-redteam replay --finding {self.module_id}-{self._finding_counter:03d}", trace_file=f"traces/{self.module_id}-{self._finding_counter:03d}.json"),
                recommendation="Sanitize descriptions to declarative text only and add metadata review gates.",
            ))
        return self.findings
