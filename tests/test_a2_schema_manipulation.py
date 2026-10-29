from __future__ import annotations

import pytest

from src.attacks.a2_schema_manipulation import A2SchemaManipulation
from tests.attack_test_utils import MockEngine, set_phase0


@pytest.mark.asyncio
async def test_a2_flags_additional_properties():
    engine = MockEngine()
    schema = {
        "type": "object",
        "properties": {"q": {"type": "string"}},
        "additionalProperties": True,
    }
    set_phase0(engine, tools=[{"name": "flex", "inputSchema": schema}])

    findings = await A2SchemaManipulation(engine).run()

    assert len(findings) == 1
    finding = findings[0]
    assert finding.id.startswith("A2-")
    assert finding.severity.value == "Medium"
    assert finding.evidence[0].response["schema"] == schema


@pytest.mark.asyncio
async def test_a2_flags_missing_properties_schema():
    engine = MockEngine()
    set_phase0(engine, tools=[{"name": "accepts_anything", "inputSchema": {"type": "object"}}])

    findings = await A2SchemaManipulation(engine).run()

    assert len(findings) == 1
    assert "accepts_anything" in findings[0].title


@pytest.mark.asyncio
async def test_a2_accepts_strict_schema():
    engine = MockEngine()
    set_phase0(
        engine,
        tools=[
            {
                "name": "strict_search",
                "inputSchema": {
                    "type": "object",
                    "properties": {"q": {"type": "string"}},
                    "additionalProperties": False,
                },
            }
        ],
    )

    findings = await A2SchemaManipulation(engine).run()

    assert findings == []
