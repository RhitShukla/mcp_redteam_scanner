from __future__ import annotations

from src.attack_base import AttackModule
from src.models import Evidence, EvidenceType, Fixability, Finding, ReplayInfo, Severity
from src.attacks.d1_sensitive_data import _generate_benign_args


class E5RateLimitProbe(AttackModule):
    name = "Rate Limiting Quick Probe"
    surface = "E - Transport & Authentication"
    module_id = "E5"
    description = "Runs a small burst of safe calls to detect obvious missing throttling."

    async def run(self) -> list[Finding]:
        self.findings.clear()
        self._finding_counter = 0
        tools = self.get_phase0_context().get("tools", [])
        if not tools:
            try:
                tools = await self.engine.list_tools()
            except Exception:
                return self.findings
        if not tools:
            return self.findings

        tool = tools[0]
        name = str(tool.get("name", ""))
        if not name:
            return self.findings
        args = _generate_benign_args(tool)

        success = 0
        for _ in range(5):
            try:
                resp = await self.engine.call_tool(name, args)
                if isinstance(resp, dict) and not resp.get("isError"):
                    success += 1
            except Exception:
                pass

        if success >= 5:
            self.add_finding(
                Finding(
                    id=self._next_finding_id(),
                    title="No obvious rate limiting in quick burst test",
                    surface=self.surface,
                    module=f"{self.module_id} - {self.name}",
                    severity=Severity.LOW,
                    fixability=Fixability.CONFIGURATION,
                    fixability_rationale="Rate limiting is usually configurable at API gateway or middleware.",
                    description=f"Five immediate calls to `{name}` succeeded without throttling signal.",
                    attack_narrative="1. Picked a safe discovered tool\n2. Sent 5 rapid calls\n3. All succeeded\n4. Throttling controls may be absent",
                    evidence=[Evidence(type=EvidenceType.TOOL_INVOCATION, request={"tool": name, "burst_count": 5}, response={"success_count": success})],
                    replay=ReplayInfo(command=f"mcp-redteam replay --finding {self.module_id}-{self._finding_counter:03d}", trace_file=f"traces/{self.module_id}-{self._finding_counter:03d}.json"),
                    recommendation="Add per-identity and per-IP rate limits for discovery and tool invocation APIs.",
                )
            )
        return self.findings
