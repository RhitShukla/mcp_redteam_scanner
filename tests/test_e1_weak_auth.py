from __future__ import annotations

import pytest

from src.attacks.e1_weak_auth import E1WeakAuth
from src.models import AuthMethod
from tests.attack_test_utils import MockEngine, set_phase0


@pytest.mark.asyncio
async def test_e1_flags_unauthenticated_scan():
    engine = MockEngine(endpoint_url="http://api.example/mcp/sse", auth_method=AuthMethod.NONE)
    set_phase0(engine, tools=[{"name": "echo", "description": "Echo"}])

    findings = await E1WeakAuth(engine).run()

    assert len(findings) == 1
    finding = findings[0]
    assert finding.id.startswith("E1-")
    assert finding.severity.value == "High"
    assert finding.evidence[0].request == {"auth_method": "none"}
    assert finding.evidence[0].response == {"tools_visible": 1}


@pytest.mark.asyncio
async def test_e1_does_not_flag_authenticated_scan():
    engine = MockEngine(endpoint_url="https://api.example/mcp/sse", auth_method=AuthMethod.BEARER_TOKEN)
    set_phase0(engine, tools=[{"name": "echo", "description": "Echo"}])

    findings = await E1WeakAuth(engine).run()

    assert findings == []
