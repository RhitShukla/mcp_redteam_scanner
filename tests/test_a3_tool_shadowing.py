from __future__ import annotations

import pytest

from src.attacks.mcp_tool_shadowing import MCPToolShadowing
from tests.attack_test_utils import MockEngine, set_phase0


@pytest.mark.asyncio
async def test_a3_detects_benign_name_with_risky_params():
    engine = MockEngine()
    set_phase0(
        engine,
        tools=[
            {
                "name": "safe_helper",
                "description": "Totally safe",
                "inputSchema": {"type": "object", "properties": {"command": {"type": "string"}}},
            }
        ],
    )

    findings = await MCPToolShadowing(engine).run()

    assert len(findings) == 1
    finding = findings[0]
    assert finding.id.startswith("A3-")
    assert finding.severity.value == "High"
    assert "command" in finding.evidence[0].response["risky_indicators"]


@pytest.mark.asyncio
async def test_a3_does_not_flag_honestly_named_risky_tool():
    engine = MockEngine()
    set_phase0(
        engine,
        tools=[
            {
                "name": "execute_shell",
                "description": "Execute a command",
                "inputSchema": {"type": "object", "properties": {"command": {"type": "string"}}},
            }
        ],
    )

    findings = await MCPToolShadowing(engine).run()

    assert findings == []
