from __future__ import annotations

import pytest

from src.attacks.e3_tls_origin_validation import E3TLSOriginValidation
from src.models import AuthMethod
from tests.attack_test_utils import MockEngine, set_phase0


@pytest.mark.asyncio
async def test_e3_flags_non_https_remote():
    engine = MockEngine(endpoint_url="http://api.example/mcp/sse", auth_method=AuthMethod.BEARER_TOKEN)
    set_phase0(engine)

    findings = await E3TLSOriginValidation(engine).run()

    assert len(findings) == 1
    finding = findings[0]
    assert finding.id.startswith("E3-")
    assert finding.severity.value == "Medium"
    assert finding.evidence[0].response == {"scheme": "http"}


@pytest.mark.asyncio
async def test_e3_allows_localhost_http():
    engine = MockEngine(endpoint_url="http://127.0.0.1:9999/sse", auth_method=AuthMethod.NONE)
    set_phase0(engine)

    findings = await E3TLSOriginValidation(engine).run()

    assert findings == []


@pytest.mark.asyncio
async def test_e3_allows_https_remote():
    engine = MockEngine(endpoint_url="https://api.example/mcp/sse", auth_method=AuthMethod.BEARER_TOKEN)
    set_phase0(engine)

    findings = await E3TLSOriginValidation(engine).run()

    assert findings == []
