from __future__ import annotations

import pytest

from src.attacks.e5_rate_limit_probe import E5RateLimitProbe
from tests.attack_test_utils import MockEngine, set_phase0


@pytest.mark.asyncio
async def test_e5_reports_when_burst_succeeds():
    engine = MockEngine()
    set_phase0(engine, tools=[{"name": "echo", "inputSchema": {"type": "object", "properties": {}}, "description": "Echo"}])

    findings = await E5RateLimitProbe(engine).run()

    assert len(findings) == 1
    finding = findings[0]
    assert finding.id.startswith("E5-")
    assert finding.evidence[0].request == {"tool": "echo", "burst_count": 5}
    assert finding.evidence[0].response == {"success_count": 5}
    assert len(engine.call_history) == 5


@pytest.mark.asyncio
async def test_e5_does_not_report_when_burst_is_throttled():
    engine = MockEngine()
    set_phase0(engine, tools=[{"name": "echo", "inputSchema": {"type": "object", "properties": {}}, "description": "Echo"}])

    async def _call_tool_throttled(name: str, arguments=None):
        engine.call_history.append({"name": name, "arguments": arguments or {}})
        if len(engine.call_history) >= 3:
            raise RuntimeError("429 Too Many Requests")
        return {"isError": False, "content": [{"type": "text", "text": "ok"}]}

    engine.call_tool = _call_tool_throttled  # type: ignore[assignment]

    findings = await E5RateLimitProbe(engine).run()

    assert findings == []
    assert len(engine.call_history) == 5
