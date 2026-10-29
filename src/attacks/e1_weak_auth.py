from __future__ import annotations

from src.attack_base import AttackModule
from src.models import Evidence, EvidenceType, Fixability, Finding, ReplayInfo, Severity


class E1WeakAuth(AttackModule):
    name = "Weak or Missing Authentication"
    surface = "E - Transport & Authentication"
    module_id = "E1"
    description = "Flags endpoints running without auth or exposing privileged metadata."

    async def run(self) -> list[Finding]:
        self.findings.clear()
        self._finding_counter = 0
        phase0 = self.get_phase0_context()
        tools = phase0.get("tools", [])

        if self.engine.config.auth_method.value == "none":
            self.add_finding(
                Finding(
                    id=self._next_finding_id(),
                    title="Endpoint scanned without authentication",
                    surface=self.surface,
                    module=f"{self.module_id} - {self.name}",
                    severity=Severity.HIGH,
                    fixability=Fixability.CONFIGURATION,
                    fixability_rationale="Auth can be required at gateway/server configuration.",
                    description="Server accepted unauthenticated session for MCP discovery.",
                    attack_narrative=(
                        "1. Connected without token\n2. Ran discovery calls successfully\n"
                        "3. Unauthenticated users can map and test attack surface"
                    ),
                    evidence=[Evidence(type=EvidenceType.CONNECTION_ATTEMPT, request={"auth_method": "none"}, response={"tools_visible": len(tools)})],
                    replay=ReplayInfo(command=f"mcp-redteam replay --finding {self.module_id}-{self._finding_counter:03d}", trace_file=f"traces/{self.module_id}-{self._finding_counter:03d}.json"),
                    recommendation="Require authentication for MCP transports before discovery/tool access.",
                )
            )
        return self.findings
