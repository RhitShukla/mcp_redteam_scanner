from __future__ import annotations

import pytest

from src.attacks.b2_ssrf_probe import B2SSRFProbe
from tests.attack_test_utils import MockEngine, set_phase0


@pytest.mark.asyncio
async def test_b2_flags_localhost_signal():
    engine = MockEngine()
    set_phase0(
        engine,
        tools=[
            {
                "name": "fetch_url",
                "inputSchema": {"type": "object", "properties": {"url": {"type": "string"}}},
            }
        ],
    )
    expected_args = {"url": "http://127.0.0.1/"}
    engine._call_results[("fetch_url", str(sorted(expected_args.items())))] = {
        "isError": False,
        "content": [{"type": "text", "text": "connection refused to 127.0.0.1"}],
    }

    findings = await B2SSRFProbe(engine).run()

    assert len(findings) == 1
    finding = findings[0]
    assert finding.id.startswith("B2-")
    assert finding.evidence[0].request == {"tool": "fetch_url", "arguments": expected_args}
    assert engine.call_history == [{"name": "fetch_url", "arguments": expected_args}]


@pytest.mark.asyncio
async def test_b2_does_not_flag_clean_fetch_response():
    engine = MockEngine()
    set_phase0(
        engine,
        tools=[
            {
                "name": "fetch_url",
                "inputSchema": {"type": "object", "properties": {"url": {"type": "string"}}},
            }
        ],
    )

    findings = await B2SSRFProbe(engine).run()

    assert findings == []


@pytest.mark.asyncio
async def test_b2_skips_tools_without_url_like_parameters():
    engine = MockEngine()
    set_phase0(
        engine,
        tools=[{"name": "echo", "inputSchema": {"type": "object", "properties": {"message": {"type": "string"}}}}],
    )

    findings = await B2SSRFProbe(engine).run()

    assert findings == []
    assert engine.call_history == []
