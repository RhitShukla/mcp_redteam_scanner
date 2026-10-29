"""
Tests for D1 — Sensitive Data in Tool Responses.

Tests both the PII scanner (unit) and the full module against the mock server (integration).
"""

from __future__ import annotations

import multiprocessing
import time

import pytest

from src.attacks.d1_sensitive_data import (
    D1SensitiveData,
    PII_PATTERNS,
    _extract_text_from_response,
    _generate_benign_args,
    scan_for_pii,
)
from src.models import AuthMethod, Severity, TargetConfig, TransportType
from src.probe_engine import ProbeEngine


# ── Server Fixture (reused from test_probe_engine) ──

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 9997


def _run_mock_server():
    from tests.mock_mcp_server import mcp
    import uvicorn

    uvicorn.run(mcp.sse_app(), host=SERVER_HOST, port=SERVER_PORT, log_level="error")


@pytest.fixture(scope="module")
def mock_server():
    proc = multiprocessing.Process(target=_run_mock_server, daemon=True)
    proc.start()
    time.sleep(2)
    yield f"http://{SERVER_HOST}:{SERVER_PORT}"
    proc.terminate()
    proc.join(timeout=5)


def _make_config(base_url: str) -> TargetConfig:
    return TargetConfig(
        endpoint_url=f"{base_url}/sse",
        transport=TransportType.SSE,
        auth_method=AuthMethod.NONE,
    )


# ── Unit Tests: PII Scanner ──


class TestPIIScanner:
    def test_detects_ssn(self):
        matches = scan_for_pii("SSN: 123-45-6789")
        assert len(matches) == 1
        assert matches[0]["pattern"] == "ssn"
        assert matches[0]["matched_value"] == "123-45-6789"
        assert matches[0]["severity"] == Severity.HIGH

    def test_detects_email(self):
        matches = scan_for_pii("Contact: user@example.com")
        assert len(matches) == 1
        assert matches[0]["pattern"] == "email"
        assert matches[0]["matched_value"] == "user@example.com"

    def test_detects_api_key(self):
        matches = scan_for_pii("Key: sk-test-1234567890abcdef")
        assert len(matches) == 1
        assert matches[0]["pattern"] == "api_key_generic"
        assert matches[0]["severity"] == Severity.CRITICAL

    def test_detects_aws_key(self):
        matches = scan_for_pii("AWS: AKIAIOSFODNN7EXAMPLE")
        assert len(matches) == 1
        assert matches[0]["pattern"] == "aws_key"

    def test_detects_private_ip(self):
        matches = scan_for_pii("Server: 10.0.1.55")
        assert len(matches) == 1
        assert matches[0]["pattern"] == "private_ip"
        assert matches[0]["severity"] == Severity.LOW

    def test_detects_multiple_pii_types(self):
        text = "Name: Jane, SSN: 123-45-6789, Email: jane@example.com"
        matches = scan_for_pii(text)
        patterns = {m["pattern"] for m in matches}
        assert "ssn" in patterns
        assert "email" in patterns

    def test_no_matches_on_clean_text(self):
        matches = scan_for_pii("Hello, this is a normal response with no PII.")
        assert len(matches) == 0

    def test_detects_jwt(self):
        token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        matches = scan_for_pii(token)
        patterns = {m["pattern"] for m in matches}
        assert "jwt_token" in patterns


# ── Unit Tests: Text Extraction ──


class TestTextExtraction:
    def test_extracts_text_content(self):
        response = {
            "content": [
                {"type": "text", "text": "Hello world"},
                {"type": "text", "text": "More data"},
            ]
        }
        text = _extract_text_from_response(response)
        assert "Hello world" in text
        assert "More data" in text

    def test_handles_empty_response(self):
        text = _extract_text_from_response({})
        assert text == ""

    def test_handles_non_text_content(self):
        response = {
            "content": [
                {"type": "image", "data": "base64..."},
            ]
        }
        text = _extract_text_from_response(response)
        # Non-text content is stringified for scanning
        assert "image" in text


# ── Unit Tests: Benign Arg Generation ──


class TestBenignArgs:
    def test_string_params(self):
        tool = {
            "inputSchema": {
                "properties": {"name": {"type": "string"}},
                "required": ["name"],
            }
        }
        args = _generate_benign_args(tool)
        assert args["name"] == "test"

    def test_integer_params(self):
        tool = {
            "inputSchema": {
                "properties": {"count": {"type": "integer"}},
            }
        }
        args = _generate_benign_args(tool)
        assert args["count"] == 1

    def test_mixed_params(self):
        tool = {
            "inputSchema": {
                "properties": {
                    "query": {"type": "string"},
                    "limit": {"type": "integer"},
                    "verbose": {"type": "boolean"},
                },
            }
        }
        args = _generate_benign_args(tool)
        assert args["query"] == "test"
        assert args["limit"] == 1
        assert args["verbose"] is True

    def test_no_schema(self):
        tool = {"inputSchema": {}}
        args = _generate_benign_args(tool)
        assert args == {}


# ── Integration Tests: Full Module ──


class TestD1Integration:
    @pytest.mark.asyncio
    async def test_finds_pii_in_mock_server(self, mock_server):
        """D1 should detect PII in customer_lookup response."""
        config = _make_config(mock_server)
        engine = ProbeEngine(config)

        async with engine.connect():
            module = D1SensitiveData(engine)
            findings = await module.run()

        # customer_lookup returns SSN, email, and API key
        assert len(findings) > 0
        # At least one finding should be about customer_lookup
        customer_findings = [
            f for f in findings if "customer_lookup" in f.title
        ]
        assert len(customer_findings) >= 1

        # Verify finding structure
        finding = customer_findings[0]
        assert finding.id.startswith("D1-")
        assert finding.surface == "D - Data Flow & Exfiltration"
        assert finding.module == "D1 - Sensitive Data in Tool Responses"
        assert finding.severity in (Severity.CRITICAL, Severity.HIGH)
        assert finding.fixability.value == "Configuration"
        assert len(finding.evidence) == 1
        assert finding.evidence[0].type.value == "tool_invocation"
        assert finding.evidence[0].request["tool"] == "customer_lookup"
        assert finding.evidence[0].response is not None
        assert finding.recommendation != ""
        assert finding.replay.trace_file.startswith("traces/D1-")

    @pytest.mark.asyncio
    async def test_finding_has_trace_link(self, mock_server):
        """Evidence should link back to the trace entry."""
        config = _make_config(mock_server)
        engine = ProbeEngine(config)

        async with engine.connect():
            module = D1SensitiveData(engine)
            findings = await module.run()

        for finding in findings:
            for evidence in finding.evidence:
                if evidence.trace_entry_id:
                    # Verify the trace entry actually exists
                    matching = [
                        t for t in engine.traces
                        if t.id == evidence.trace_entry_id
                    ]
                    assert len(matching) == 1

    @pytest.mark.asyncio
    async def test_all_interactions_traced(self, mock_server):
        """Every tool call D1 makes should be in the engine traces."""
        config = _make_config(mock_server)
        engine = ProbeEngine(config)

        async with engine.connect():
            tools = await engine.list_tools()
            tool_count = len(tools)

            # Clear and re-run to count only D1's traces
            engine.clear_traces()
            module = D1SensitiveData(engine)
            await module.run()

        # D1 calls each tool once
        call_traces = [t for t in engine.traces if t.method == "tools/call"]
        # Should have one trace per tool (D1 also calls list_tools in run)
        list_traces = [t for t in engine.traces if t.method == "tools/list"]
        assert len(list_traces) == 1
        assert len(call_traces) == tool_count

    @pytest.mark.asyncio
    async def test_summary(self, mock_server):
        """Module summary should reflect findings."""
        config = _make_config(mock_server)
        engine = ProbeEngine(config)

        async with engine.connect():
            module = D1SensitiveData(engine)
            await module.run()

        summary = module.summary()
        assert summary["module"] == "D1"
        assert summary["findings_count"] > 0

    @pytest.mark.asyncio
    async def test_rerun_resets_findings(self, mock_server):
        """Running the module twice should not accumulate findings."""
        config = _make_config(mock_server)
        engine = ProbeEngine(config)

        async with engine.connect():
            module = D1SensitiveData(engine)
            findings1 = await module.run()
            count1 = len(findings1)
            findings2 = await module.run()
            count2 = len(findings2)

        assert count1 == count2
