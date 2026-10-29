from __future__ import annotations

from src.attack_base import AttackModule
from src.models import Evidence, EvidenceType, Fixability, Finding, ReplayInfo, Severity


class B2SSRFProbe(AttackModule):
    name = "SSRF Non-Destructive Probe"
    surface = "B - Tool Invocation & Execution"
    module_id = "B2"
    description = "Tests URL-like parameters with localhost metadata targets (safe probes)."

    async def run(self) -> list[Finding]:
        self.findings.clear()
        self._finding_counter = 0
        tools = self.get_phase0_context().get("tools", [])
        payloads = ("http://127.0.0.1/", "http://localhost/")

        for tool in tools:
            name = str(tool.get("name", ""))
            schema = tool.get("inputSchema", {})
            props = schema.get("properties", {}) if isinstance(schema, dict) else {}
            url_params = [p for p in props.keys() if any(k in str(p).lower() for k in ("url", "uri", "endpoint", "host", "target"))]
            if not url_params:
                continue
            args = {str(p): payloads[0] for p in url_params}
            try:
                resp = await self.engine.call_tool(name, args)
            except Exception:
                continue
            text = str(resp).lower()
            if any(k in text for k in ("localhost", "127.0.0.1", "connection refused", "timed out")):
                self.add_finding(Finding(
                    id=self._next_finding_id(),
                    title=f"Possible SSRF behavior in '{name}'",
                    surface=self.surface,
                    module=f"{self.module_id} - {self.name}",
                    severity=Severity.MEDIUM,
                    fixability=Fixability.DESIGN,
                    fixability_rationale="Outbound fetch restrictions require policy and handler design.",
                    description=f"Tool `{name}` appears to process attacker-controlled URL targets.",
                    attack_narrative="1. Identified URL-like parameters\n2. Sent localhost probe target\n3. Response hints server attempted outbound request",
                    evidence=[Evidence(type=EvidenceType.TOOL_INVOCATION, request={"tool": name, "arguments": args}, response=resp)],
                    replay=ReplayInfo(command=f"mcp-redteam replay --finding {self.module_id}-{self._finding_counter:03d}", trace_file=f"traces/{self.module_id}-{self._finding_counter:03d}.json"),
                    recommendation="Enforce strict outbound URL allowlists and block local/internal network ranges.",
                ))
        return self.findings
