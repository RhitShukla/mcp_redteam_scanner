"""Tests for shared data models. Validates contracts between layers."""

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from src.models import (
    AuthMethod,
    CrossTenantConfig,
    Evidence,
    EvidenceType,
    Finding,
    Fixability,
    ReplayInfo,
    Severity,
    SessionInfo,
    TargetConfig,
    TenantCredential,
    TraceEntry,
    TraceFile,
    TransportType,
)


# ── Helpers ──


def make_evidence() -> Evidence:
    return Evidence(
        type=EvidenceType.TOOL_INVOCATION,
        request={"tool": "customer_lookup", "arguments": {"id": "123"}},
        response={"result": "John Doe, SSN: 123-45-6789"},
        trace_entry_id="trace-abc",
    )


def make_finding(**overrides) -> Finding:
    defaults = dict(
        id="D1-001",
        title="PII exposed in customer_lookup tool response",
        surface="D - Data Flow & Exfiltration",
        module="D1 - Sensitive data in tool responses",
        severity=Severity.HIGH,
        fixability=Fixability.CONFIGURATION,
        fixability_rationale="Output filtering can be added to the tool handler without redesign.",
        description="The customer_lookup tool returns raw SSN in its response.",
        attack_narrative=(
            "1. Connected to endpoint\n"
            "2. Discovered tool customer_lookup\n"
            "3. Invoked with arguments {id: '123'}\n"
            "4. Response contained SSN pattern 123-45-6789"
        ),
        evidence=[make_evidence()],
        replay=ReplayInfo(
            command="mcp-redteam replay --finding D1-001 --target http://localhost:8080",
            trace_file="traces/D1-001.json",
        ),
        recommendation=(
            "Add output filtering to the customer_lookup tool handler "
            "to strip SSN fields before returning results."
        ),
    )
    defaults.update(overrides)
    return Finding(**defaults)


# ── Finding Tests ──


class TestFinding:
    def test_valid_finding(self):
        finding = make_finding()
        assert finding.id == "D1-001"
        assert finding.severity == Severity.HIGH
        assert finding.fixability == Fixability.CONFIGURATION
        assert len(finding.evidence) == 1

    def test_missing_required_field_raises(self):
        with pytest.raises(ValidationError):
            Finding(
                id="D1-001",
                title="Incomplete finding",
                # missing all other required fields
            )

    def test_invalid_severity_raises(self):
        with pytest.raises(ValidationError):
            make_finding(severity="SuperCritical")

    def test_invalid_fixability_raises(self):
        with pytest.raises(ValidationError):
            make_finding(fixability="Easy")

    def test_json_round_trip(self):
        original = make_finding()
        json_str = original.model_dump_json()
        restored = Finding.model_validate_json(json_str)
        assert original == restored

    def test_dict_round_trip(self):
        original = make_finding()
        data = original.model_dump()
        restored = Finding.model_validate(data)
        assert original == restored

    def test_multiple_evidence_items(self):
        finding = make_finding(
            evidence=[make_evidence(), make_evidence()]
        )
        assert len(finding.evidence) == 2

    def test_empty_evidence_list_allowed(self):
        """Modules may emit info-level findings with no evidence."""
        finding = make_finding(evidence=[])
        assert finding.evidence == []


# ── TraceEntry Tests ──


class TestTraceEntry:
    def test_auto_generated_id(self):
        t1 = TraceEntry(
            session_id="sess-1",
            method="tools/call",
            request={"tool": "echo", "arguments": {"msg": "hi"}},
        )
        t2 = TraceEntry(
            session_id="sess-1",
            method="tools/call",
            request={"tool": "echo", "arguments": {"msg": "hi"}},
        )
        assert t1.id != t2.id  # UUIDs are unique

    def test_auto_generated_timestamp(self):
        entry = TraceEntry(
            session_id="sess-1",
            method="tools/call",
            request={"tool": "echo"},
        )
        assert entry.timestamp is not None
        assert entry.timestamp.tzinfo is not None  # must be timezone-aware

    def test_failed_call_has_error(self):
        entry = TraceEntry(
            session_id="sess-1",
            method="tools/call",
            request={"tool": "broken"},
            response=None,
            error="ConnectionRefused",
        )
        assert entry.response is None
        assert entry.error == "ConnectionRefused"

    def test_json_round_trip(self):
        entry = TraceEntry(
            session_id="sess-1",
            method="tools/call",
            request={"tool": "echo"},
            response={"result": "ok"},
            duration_ms=42.5,
        )
        restored = TraceEntry.model_validate_json(entry.model_dump_json())
        assert entry == restored


# ── SessionInfo Tests ──


class TestSessionInfo:
    def test_defaults(self):
        session = SessionInfo(
            endpoint_url="http://localhost:8080/mcp",
            transport=TransportType.SSE,
            auth_method=AuthMethod.BEARER_TOKEN,
        )
        assert session.session_id  # auto-generated
        assert session.server_capabilities == {}
        assert session.connected_at is None

    def test_with_capabilities(self):
        session = SessionInfo(
            endpoint_url="http://localhost:8080/mcp",
            transport=TransportType.SSE,
            auth_method=AuthMethod.BEARER_TOKEN,
            server_capabilities={"tools": True, "resources": True},
        )
        assert session.server_capabilities["tools"] is True


# ── TargetConfig Tests ──


class TestTargetConfig:
    def test_from_dict(self):
        """Simulates loading from parsed YAML."""
        data = {
            "endpoint_url": "http://localhost:8080/mcp",
            "transport": "sse",
            "auth_method": "bearer_token",
            "auth_token": "test-token-123",
            "cross_tenant": {
                "enabled": True,
                "tenant_a": {"token": "tok-a", "identifier": "tenant-alpha"},
                "tenant_b": {"token": "tok-b", "identifier": "tenant-beta"},
            },
        }
        config = TargetConfig.model_validate(data)
        assert config.endpoint_url == "http://localhost:8080/mcp"
        assert config.transport == TransportType.SSE
        assert config.auth_method == AuthMethod.BEARER_TOKEN
        assert config.cross_tenant.enabled is True
        assert config.cross_tenant.tenant_a.identifier == "tenant-alpha"
        assert config.cross_tenant.tenant_b.identifier == "tenant-beta"

    def test_defaults(self):
        config = TargetConfig(endpoint_url="http://localhost:8080/mcp")
        assert config.transport == TransportType.SSE
        assert config.auth_method == AuthMethod.BEARER_TOKEN
        assert config.cross_tenant.enabled is False
        assert config.output_dir == "./output"

    def test_missing_endpoint_raises(self):
        with pytest.raises(ValidationError):
            TargetConfig()


# ── TraceFile Tests ──


class TestTraceFile:
    def test_self_contained_trace(self):
        session = SessionInfo(
            endpoint_url="http://localhost:8080/mcp",
            transport=TransportType.SSE,
            auth_method=AuthMethod.BEARER_TOKEN,
            auth_identity="tenant-alpha",
        )
        entries = [
            TraceEntry(
                session_id=session.session_id,
                method="tools/list",
                request={},
                response={"tools": [{"name": "echo"}]},
            ),
            TraceEntry(
                session_id=session.session_id,
                method="tools/call",
                request={"tool": "echo", "arguments": {"msg": "test"}},
                response={"result": "test"},
                duration_ms=15.2,
            ),
        ]
        trace = TraceFile(
            session=session,
            entries=entries,
            finding_id="B1-001",
        )
        assert trace.finding_id == "B1-001"
        assert len(trace.entries) == 2
        # Verify round-trip for replay
        restored = TraceFile.model_validate_json(trace.model_dump_json())
        assert restored == trace
