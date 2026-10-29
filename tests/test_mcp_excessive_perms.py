from __future__ import annotations

import pytest

from src.attacks.mcp_excessive_perms import MCPExcessivePerms
from tests.attack_test_utils import MockEngine, set_phase0


@pytest.mark.asyncio
async def test_excessive_perms_flags_privileged_visible_metadata():
    engine = MockEngine()
    set_phase0(
        engine,
        tools=[{"name": "admin_export", "description": "Export internal records"}],
        resources=[{"uri": "config://secrets", "description": "secret credentials"}],
        prompts=[{"name": "debug_system_prompt", "description": "internal prompt"}],
    )

    findings = await MCPExcessivePerms(engine).run()

    assert len(findings) == 1
    finding = findings[0]
    assert finding.id.startswith("MCP-")
    exposed = finding.evidence[0].response["exposed_items"]
    assert {item["type"] for item in exposed} == {"tool", "resource", "prompt"}


@pytest.mark.asyncio
async def test_excessive_perms_does_not_flag_public_metadata():
    engine = MockEngine()
    set_phase0(
        engine,
        tools=[{"name": "weather", "description": "Get public weather"}],
        resources=[{"uri": "api://weather", "description": "public forecast"}],
        prompts=[{"name": "summarize", "description": "Summarize text"}],
    )

    findings = await MCPExcessivePerms(engine).run()

    assert findings == []
