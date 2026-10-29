from __future__ import annotations

from urllib.parse import urlparse

from src.attack_base import AttackModule
from src.models import Evidence, EvidenceType, Fixability, Finding, ReplayInfo, Severity


class E3TLSOriginValidation(AttackModule):
    name = "TLS and Origin Validation"
    surface = "E - Transport & Authentication"
    module_id = "E3"
    description = "Checks for plaintext transport or localhost-only trust assumptions."

    async def run(self) -> list[Finding]:
        self.findings.clear()
        self._finding_counter = 0
        endpoint = self.engine.config.endpoint_url
        parsed = urlparse(endpoint)
        host = (parsed.hostname or "").lower()

        if parsed.scheme != "https" and host not in {"127.0.0.1", "localhost"}:
            self.add_finding(
                Finding(
                    id=self._next_finding_id(),
                    title="MCP endpoint uses non-TLS transport",
                    surface=self.surface,
                    module=f"{self.module_id} - {self.name}",
                    severity=Severity.MEDIUM,
                    fixability=Fixability.CONFIGURATION,
                    fixability_rationale="TLS termination and strict origin policy are deploy-time controls.",
                    description=f"Endpoint `{endpoint}` is not HTTPS.",
                    attack_narrative="1. Parsed target URL\n2. Detected non-HTTPS transport\n3. Traffic may be intercepted or modified in transit",
                    evidence=[Evidence(type=EvidenceType.CONNECTION_ATTEMPT, request={"target": endpoint}, response={"scheme": parsed.scheme})],
                    replay=ReplayInfo(command=f"mcp-redteam replay --finding {self.module_id}-{self._finding_counter:03d}", trace_file=f"traces/{self.module_id}-{self._finding_counter:03d}.json"),
                    recommendation="Use HTTPS with certificate validation and restrict accepted origins.",
                )
            )
        return self.findings
