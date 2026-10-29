from __future__ import annotations

import pytest

from src.attacks.a4_enumeration_leakage import A4EnumerationLeakage
from tests.attack_test_utils import MockEngine, set_phase0


@pytest.mark.asyncio
async def test_a4_flags_large_inventory():
    engine = MockEngine()
    tools = [{"name": f"t{i}"} for i in range(10)]
    set_phase0(engine, tools=tools, resources=[], prompts=[])

    findings = await A4EnumerationLeakage(engine).run()

    assert len(findings) == 1
    finding = findings[0]
    assert finding.id.startswith("A4-")
    assert finding.evidence[0].response == {"tools": 10, "resources": 0, "prompts": 0}


@pytest.mark.asyncio
async def test_a4_does_not_flag_small_inventory():
    engine = MockEngine()
    set_phase0(engine, tools=[{"name": "echo"}], resources=[], prompts=[])

    findings = await A4EnumerationLeakage(engine).run()

    assert findings == []
