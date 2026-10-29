"""
Phase 1 - Excessive permission exposure checks.

Goal:
    Verify whether the connected identity can see privileged tools/resources/prompts
    that should usually be hidden from low-trust clients.

Plan A:
    Use Phase 0 map from shared context bus.
Plan B:
    Re-discover directly from ProbeEngine if context is missing.
"""

from __future__ import annotations

from typing import Any

from src.attack_base import AttackModule
from src.models import Evidence, EvidenceType, Fixability, Finding, ReplayInfo, Severity


PRIVILEGED_KEYWORDS = (
    "admin",
    "internal",
    "debug",
    "root",
    "sudo",
    "secret",
    "credential",
    "token",
    "key",
    "config",
)


def _contains_privileged_signal(text: str) -> bool:
    lowered = text.lower()
    return any(k in lowered for k in PRIVILEGED_KEYWORDS)


class MCPExcessivePerms(AttackModule):
    name = "Excessive Permission Scope"
    surface = "E - Transport & Authentication"
    module_id = "MCP"
    description = (
        "Checks if the current MCP identity can enumerate privileged/internal "
        "capabilities that should be permission-gated."
    )

    async def run(self) -> list[Finding]:
        self.findings.clear()
        self._finding_counter = 0

        phase0 = self.get_phase0_context()
        tools = phase0.get("tools")
        resources = phase0.get("resources")
        prompts = phase0.get("prompts")

        # Plan B fallback: always stay functional even if Phase 0 context missing.
        if not isinstance(tools, list):
            try:
                tools = await self.engine.list_tools()
            except Exception:
                tools = []
        if not isinstance(resources, list):
            try:
                resources = await self.engine.list_resources()
            except Exception:
                resources = []
        if not isinstance(prompts, list):
            try:
                prompts = await self.engine.list_prompts()
            except Exception:
                prompts = []

        exposed: list[dict[str, str]] = []

        for tool in tools:
            name = str(tool.get("name", ""))
            desc = str(tool.get("description", ""))
            if _contains_privileged_signal(f"{name} {desc}"):
                exposed.append({"type": "tool", "name": name or "<unnamed>", "why": desc[:120]})

        for resource in resources:
            uri = str(resource.get("uri", resource.get("name", "")))
            desc = str(resource.get("description", ""))
            if _contains_privileged_signal(f"{uri} {desc}"):
                exposed.append({"type": "resource", "name": uri or "<unnamed>", "why": desc[:120]})

        for prompt in prompts:
            name = str(prompt.get("name", ""))
            desc = str(prompt.get("description", ""))
            if _contains_privileged_signal(f"{name} {desc}"):
                exposed.append({"type": "prompt", "name": name or "<unnamed>", "why": desc[:120]})

        if not exposed:
            return self.findings

        finding = Finding(
            id=self._next_finding_id(),
            title=f"Potential excessive permission scope: {len(exposed)} privileged item(s) visible",
            surface=self.surface,
            module=f"{self.module_id} - {self.name}",
            severity=Severity.HIGH,
            fixability=Fixability.CONFIGURATION,
            fixability_rationale=(
                "Visibility rules for tools/resources/prompts can be constrained by role "
                "or identity policy without changing core architecture."
            ),
            description=(
                "The current connected identity can enumerate metadata that appears "
                "privileged/internal. This may indicate weak scope enforcement."
            ),
            attack_narrative=(
                "1. Enumerated tools/resources/prompts for current identity\n"
                "2. Matched privileged keywords in returned metadata\n"
                f"3. Found {len(exposed)} potentially over-exposed item(s)\n"
                "4. This can help attackers discover high-impact attack paths early"
            ),
            evidence=[
                Evidence(
                    type=EvidenceType.CONNECTION_ATTEMPT,
                    request={"method": "phase1/visibility-check"},
                    response={"exposed_items": exposed},
                )
            ],
            replay=ReplayInfo(
                command=f"mcp-redteam replay --finding {self.module_id}-{self._finding_counter:03d}",
                trace_file=f"traces/{self.module_id}-{self._finding_counter:03d}.json",
            ),
            recommendation=(
                "Apply least-privilege visibility controls. Hide internal/admin/debug "
                "tools and resources from default identities; expose only role-scoped "
                "capabilities required for the caller."
            ),
        )
        self.add_finding(finding)
        return self.findings
