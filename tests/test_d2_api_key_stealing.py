from __future__ import annotations

from typing import Any

import pytest

from src.attacks.d2_api_key_stealing import (
    VERDICT_CONFIRMED_DIAGNOSTIC,
    VERDICT_CONFIRMED_SECRET,
    D2APIKeyStealing,
)
from src.models import Severity
from tests.attack_test_utils import MockEngine, set_phase0


# ── Shared helpers ──


def _call_key(tool_name: str, arguments: dict[str, Any]) -> tuple[str, str]:
    return (tool_name, str(sorted(arguments.items())))


def _set_result(
    engine: MockEngine,
    tool_name: str,
    arguments: dict[str, Any],
    text: str,
    is_error: bool = False,
) -> None:
    engine._call_results[_call_key(tool_name, arguments)] = {
        "isError": is_error,
        "content": [{"type": "text", "text": text}],
    }


def _set_error(
    engine: MockEngine,
    tool_name: str,
    arguments: dict[str, Any],
    text: str,
) -> None:
    engine._call_errors[_call_key(tool_name, arguments)] = RuntimeError(text)


class _TraceEntry:
    def __init__(self, entry_id: str, method: str, request: dict[str, Any]):
        self.id = entry_id
        self.method = method
        self.request = request
        self.response = None
        self.error = None


class TraceMockEngine(MockEngine):
    """Mock engine that records exact trace entries for correlation tests."""

    def __init__(self, *args: Any, **kwargs: Any):
        super().__init__(*args, **kwargs)
        self._trace_counter = 0

    async def call_tool(self, name: str, arguments: dict[str, Any] | None = None):
        args = arguments or {}
        self.call_history.append({"name": name, "arguments": args})
        key = _call_key(name, args)
        if key in self._call_errors:
            raise self._call_errors[key]
        response = self._call_results.get(
            key,
            {"isError": False, "content": [{"type": "text", "text": "ok"}]},
        )
        self._trace_counter += 1
        self.traces.append(
            _TraceEntry(
                entry_id=f"trace-{self._trace_counter}",
                method="tools/call",
                request={"name": name, "arguments": args},
            )
        )
        return response


# ── Existing compatibility tests ──


@pytest.mark.asyncio
async def test_d2_detects_secret_in_normal_tool_response():
    engine = MockEngine(endpoint_url="https://api.example/mcp/sse")
    set_phase0(
        engine,
        tools=[
            {
                "name": "get_config",
                "inputSchema": {
                    "type": "object",
                    "properties": {"name": {"type": "string"}},
                },
            }
        ],
    )
    _set_result(
        engine,
        "get_config",
        {"name": "test"},
        "postgresql://app_user:password@db.internal:5432/app",
    )

    findings = await D2APIKeyStealing(engine).run()

    assert len(findings) >= 1
    finding = findings[0]
    assert finding.id.startswith("D2-")
    assert "Database Connection String" in finding.description
    assert finding.severity == Severity.CRITICAL
    assert finding.evidence[0].request["tool"] == "get_config"


@pytest.mark.asyncio
async def test_d2_detects_secret_leaked_through_exception_message():
    engine = MockEngine(endpoint_url="https://api.example/mcp/sse")
    set_phase0(
        engine,
        tools=[
            {
                "name": "create_upload",
                "inputSchema": {
                    "type": "object",
                    "properties": {"path": {"type": "string"}},
                },
            }
        ],
    )
    _set_error(
        engine,
        "create_upload",
        {"path": None},
        (
            "Unhandled error: DefaultEndpointsProtocol=https;"
            "AccountName=storageacct;AccountKey="
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789=="
        ),
    )

    findings = await D2APIKeyStealing(engine).run()

    assert any(f.id.startswith("D2-") for f in findings)
    assert any("Azure Storage Connection String" in f.description for f in findings)


# ── Positive secret detection ──


@pytest.mark.asyncio
async def test_d2_detects_openai_api_key_in_normal_response():
    engine = MockEngine()
    set_phase0(
        engine,
        tools=[
            {
                "name": "get_openai_key",
                "inputSchema": {
                    "type": "object",
                    "properties": {"key": {"type": "string"}},
                },
            }
        ],
    )
    _set_result(
        engine,
        "get_openai_key",
        {"key": "test"},
        "sk-abcdefghijklmnopqrstuvwxyz1234567890ABCDEF",
    )

    findings = await D2APIKeyStealing(engine).run()

    assert any("OpenAI API Key" in f.description for f in findings)


@pytest.mark.asyncio
async def test_d2_detects_aws_credentials_in_exception():
    engine = MockEngine()
    set_phase0(
        engine,
        tools=[
            {
                "name": "create_bucket",
                "inputSchema": {
                    "type": "object",
                    "properties": {"bucket": {"type": "string"}},
                },
            }
        ],
    )
    _set_error(
        engine,
        "create_bucket",
        {"bucket": None},
        (
            "AWS error: AKIAIOSFODNN7EXAMPLE with "
            "aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        ),
    )

    findings = await D2APIKeyStealing(engine).run()

    labels = {label for f in findings for label in f.description.split("Detected categories: ")[-1].split(", ")}
    assert any("AWS" in f.description for f in findings)


@pytest.mark.asyncio
async def test_d2_detects_bearer_token_in_exception():
    engine = MockEngine()
    set_phase0(
        engine,
        tools=[
            {
                "name": "fetch",
                "inputSchema": {
                    "type": "object",
                    "properties": {"url": {"type": "string"}},
                },
            }
        ],
    )
    _set_error(
        engine,
        "fetch",
        {"url": None},
        "Authorization: Bearer abcdefghijklmnopqrstuvwxyz1234567890",
    )

    findings = await D2APIKeyStealing(engine).run()

    assert any("Bearer Token" in f.description for f in findings)


@pytest.mark.asyncio
async def test_d2_detects_private_key_in_normal_response():
    engine = MockEngine()
    set_phase0(
        engine,
        tools=[
            {
                "name": "get_key",
                "inputSchema": {
                    "type": "object",
                    "properties": {"name": {"type": "string"}},
                },
            }
        ],
    )
    key_text = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy0AHB7MhgwMbRvI0MBZhpI\n"
        "D2a8M+k0gqI4jdh6j5n6j8j6j9j6j9j6j9j6j9j6j9j6j9j6j9j6j9j6j9j6j9j6j9j\n"
        "-----END RSA PRIVATE KEY-----"
    )
    _set_result(engine, "get_key", {"name": "test"}, key_text)

    findings = await D2APIKeyStealing(engine).run()

    assert any("Private Key" in f.description for f in findings)


# ── Redaction and evidence quality ──


@pytest.mark.asyncio
async def test_d2_redacts_secret_in_evidence():
    engine = MockEngine()
    set_phase0(
        engine,
        tools=[
            {
                "name": "get_config",
                "inputSchema": {
                    "type": "object",
                    "properties": {"name": {"type": "string"}},
                },
            }
        ],
    )
    _set_result(
        engine,
        "get_config",
        {"name": "test"},
        "postgresql://app_user:secret_password@db.internal:5432/app",
    )

    findings = await D2APIKeyStealing(engine).run()
    finding_str = str(findings[0].model_dump())

    assert "secret_password" not in finding_str
    assert "[REDACTED]" in finding_str or "<redacted" in finding_str


@pytest.mark.asyncio
async def test_d2_evidence_includes_probe_type_and_channel():
    engine = MockEngine()
    set_phase0(
        engine,
        tools=[
            {
                "name": "get_config",
                "inputSchema": {
                    "type": "object",
                    "properties": {"name": {"type": "string"}},
                },
            }
        ],
    )
    _set_result(
        engine,
        "get_config",
        {"name": "test"},
        "postgresql://app_user:password@db.internal:5432/app",
    )

    findings = await D2APIKeyStealing(engine).run()
    evidence = findings[0].evidence[0]

    assert evidence.request["probe_type"] == "baseline"
    assert evidence.request["channel"] == "normal_response"
    assert evidence.request["verdict"] == VERDICT_CONFIRMED_SECRET
    assert evidence.trace_entry_id is None  # MockEngine does not populate traces


# ── Negative / false-positive cases ──


@pytest.mark.asyncio
async def test_d2_ignores_passwordless_db_url():
    engine = MockEngine()
    set_phase0(
        engine,
        tools=[
            {
                "name": "get_config",
                "inputSchema": {
                    "type": "object",
                    "properties": {"name": {"type": "string"}},
                },
            }
        ],
    )
    _set_result(
        engine,
        "get_config",
        {"name": "test"},
        "postgresql://app_user@db.internal:5432/app",
    )

    findings = await D2APIKeyStealing(engine).run()
    secret_findings = [f for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]
    assert secret_findings == []


@pytest.mark.asyncio
async def test_d2_ignores_placeholder_secret():
    engine = MockEngine()
    set_phase0(
        engine,
        tools=[
            {
                "name": "get_config",
                "inputSchema": {
                    "type": "object",
                    "properties": {"name": {"type": "string"}},
                },
            }
        ],
    )
    _set_result(
        engine,
        "get_config",
        {"name": "test"},
        'api_key="example_key"',
    )

    findings = await D2APIKeyStealing(engine).run()
    assert findings == []


@pytest.mark.asyncio
async def test_d2_azure_endpoint_is_diagnostic_not_secret():
    engine = MockEngine()
    set_phase0(
        engine,
        tools=[
            {
                "name": "get_config",
                "inputSchema": {
                    "type": "object",
                    "properties": {"name": {"type": "string"}},
                },
            }
        ],
    )
    _set_result(
        engine,
        "get_config",
        {"name": "test"},
        "https://myaccount.openai.azure.com/v1/deployments/gpt-4",
    )

    findings = await D2APIKeyStealing(engine).run()
    secret_findings = [f for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]
    assert secret_findings == []
    assert any("Diagnostic disclosure" in f.title for f in findings)


@pytest.mark.asyncio
async def test_d2_stack_trace_is_diagnostic_not_secret():
    engine = MockEngine()
    set_phase0(
        engine,
        tools=[
            {
                "name": "read_file",
                "inputSchema": {
                    "type": "object",
                    "properties": {"path": {"type": "string"}},
                },
            }
        ],
    )
    _set_result(
        engine,
        "read_file",
        {"path": "test"},
        "Traceback (most recent call last):\n  File \"/app/src/main.py\", line 42",
        is_error=True,
    )

    findings = await D2APIKeyStealing(engine).run()
    secret_findings = [f for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]
    assert secret_findings == []
    assert any("Stack Trace" in f.description for f in findings)


# ── Error channels ──


@pytest.mark.asyncio
async def test_d2_detects_secret_in_iserror_response():
    engine = MockEngine()
    set_phase0(
        engine,
        tools=[
            {
                "name": "get_config",
                "inputSchema": {
                    "type": "object",
                    "properties": {"name": {"type": "string"}},
                },
            }
        ],
    )
    _set_result(
        engine,
        "get_config",
        {"name": "test"},
        "postgresql://app_user:password@db.internal:5432/app",
        is_error=True,
    )

    findings = await D2APIKeyStealing(engine).run()
    assert any("Database Connection String" in f.description for f in findings)
    assert findings[0].evidence[0].response["is_error"] is True


@pytest.mark.asyncio
async def test_d2_detects_secret_in_nested_error():
    engine = MockEngine()
    set_phase0(
        engine,
        tools=[
            {
                "name": "get_config",
                "inputSchema": {
                    "type": "object",
                    "properties": {"name": {"type": "string"}},
                },
            }
        ],
    )
    engine._call_results[_call_key("get_config", {"name": "test"})] = {
        "isError": True,
        "error": {
            "message": "Database connection failed",
            "details": "postgresql://app_user:password@db.internal:5432/app",
        },
    }

    findings = await D2APIKeyStealing(engine).run()
    assert any("Database Connection String" in f.description for f in findings)


# ── Schema behavior and safety ──


@pytest.mark.asyncio
async def test_d2_skips_dangerous_required_sibling():
    engine = MockEngine()
    set_phase0(
        engine,
        tools=[
            {
                "name": "run_shell",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "command": {"type": "string"},
                        "path": {"type": "string"},
                    },
                    "required": ["command", "path"],
                },
            }
        ],
    )

    module = D2APIKeyStealing(engine)
    findings = await module.run()

    assert findings == []
    assert engine.call_history == []
    assert module.stats["skipped"] >= 1


@pytest.mark.asyncio
async def test_d2_skips_tool_with_no_schema():
    engine = MockEngine()
    set_phase0(
        engine,
        tools=[{"name": "no_schema_tool"}],
    )

    module = D2APIKeyStealing(engine)
    findings = await module.run()

    assert findings == []
    assert engine.call_history == []


@pytest.mark.asyncio
async def test_d2_supports_input_schema_snake_case():
    engine = MockEngine()
    set_phase0(
        engine,
        tools=[
            {
                "name": "get_config",
                "input_schema": {
                    "type": "object",
                    "properties": {"name": {"type": "string"}},
                },
            }
        ],
    )
    _set_result(
        engine,
        "get_config",
        {"name": "test"},
        "postgresql://app_user:password@db.internal:5432/app",
    )

    findings = await D2APIKeyStealing(engine).run()
    assert any("Database Connection String" in f.description for f in findings)


@pytest.mark.asyncio
async def test_d2_fills_required_sibling_from_default():
    engine = MockEngine()
    set_phase0(
        engine,
        tools=[
            {
                "name": "read_file",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string"},
                        "recursive": {"type": "boolean", "default": False},
                    },
                    "required": ["path"],
                },
            }
        ],
    )
    _set_result(engine, "read_file", {"path": "test", "recursive": False}, "ok")

    await D2APIKeyStealing(engine).run()

    baseline_call = next(
        c for c in engine.call_history if c["arguments"].get("path") == "test"
    )
    assert baseline_call["arguments"]["recursive"] is False


@pytest.mark.asyncio
async def test_d2_fills_required_sibling_from_enum():
    engine = MockEngine()
    set_phase0(
        engine,
        tools=[
            {
                "name": "read_file",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string"},
                        "encoding": {
                            "type": "string",
                            "enum": ["utf-8", "base64"],
                        },
                    },
                    "required": ["path", "encoding"],
                },
            }
        ],
    )
    _set_result(engine, "read_file", {"path": "test", "encoding": "utf-8"}, "ok")

    await D2APIKeyStealing(engine).run()

    baseline_call = next(
        c for c in engine.call_history if c["arguments"].get("path") == "test"
    )
    assert baseline_call["arguments"]["encoding"] == "utf-8"


# ── Probe limits and adversarial behavior ──


@pytest.mark.asyncio
async def test_d2_executes_adversarial_null_probe():
    engine = MockEngine()
    set_phase0(
        engine,
        tools=[
            {
                "name": "create_upload",
                "inputSchema": {
                    "type": "object",
                    "properties": {"path": {"type": "string"}},
                },
            }
        ],
    )
    _set_error(engine, "create_upload", {"path": None}, "validation failed")

    module = D2APIKeyStealing(engine)
    await module.run()

    null_probe = next(
        r for r in module.probe_results if r.probe_type == "null_field"
    )
    assert null_probe.args == {"path": None}
    assert null_probe.channel == "exception"


@pytest.mark.asyncio
async def test_d2_respects_total_probe_limit():
    engine = MockEngine()
    set_phase0(
        engine,
        tools=[
            {
                "name": "multi_param",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "a": {"type": "string"},
                        "b": {"type": "string"},
                        "c": {"type": "string"},
                        "d": {"type": "string"},
                        "e": {"type": "string"},
                    },
                },
            }
        ],
    )

    module = D2APIKeyStealing(engine, max_total_probes=3)
    await module.run()

    assert module.stats["attempted"] <= 3


@pytest.mark.asyncio
async def test_d2_aggregates_duplicate_findings():
    engine = MockEngine()
    set_phase0(
        engine,
        tools=[
            {
                "name": "get_config",
                "inputSchema": {
                    "type": "object",
                    "properties": {"name": {"type": "string"}},
                },
            }
        ],
    )
    secret = "postgresql://app_user:password@db.internal:5432/app"
    _set_result(engine, "get_config", {"name": "test"}, secret)
    _set_result(engine, "get_config", {"name": None}, secret)

    findings = await D2APIKeyStealing(engine).run()

    db_findings = [f for f in findings if "Database Connection String" in f.description]
    assert len(db_findings) == 1
    assert len(db_findings[0].evidence) == 2


# ── Trace correlation and state ──


@pytest.mark.asyncio
async def test_d2_trace_correlation_uses_exact_arguments():
    engine = TraceMockEngine()
    set_phase0(
        engine,
        tools=[
            {
                "name": "get_config",
                "inputSchema": {
                    "type": "object",
                    "properties": {"name": {"type": "string"}},
                },
            }
        ],
    )
    _set_result(
        engine,
        "get_config",
        {"name": "test"},
        "postgresql://app_user:password@db.internal:5432/app",
    )

    findings = await D2APIKeyStealing(engine).run()

    assert findings[0].evidence[0].trace_entry_id == "trace-1"


@pytest.mark.asyncio
async def test_d2_repeated_run_resets_state():
    engine = MockEngine()
    set_phase0(
        engine,
        tools=[
            {
                "name": "get_config",
                "inputSchema": {
                    "type": "object",
                    "properties": {"name": {"type": "string"}},
                },
            }
        ],
    )
    _set_result(
        engine,
        "get_config",
        {"name": "test"},
        "postgresql://app_user:password@db.internal:5432/app",
    )

    module = D2APIKeyStealing(engine)
    findings1 = await module.run()
    findings2 = await module.run()

    assert len(findings1) == len(findings2) == 1
    assert findings1[0].id == findings2[0].id == "D2-001"
    # Baseline + four adversarial probes for a single string parameter.
    assert module.stats["attempted"] == 5


@pytest.mark.asyncio
async def test_d2_results_are_deterministic():
    engine = MockEngine()
    set_phase0(
        engine,
        tools=[
            {
                "name": "get_config",
                "inputSchema": {
                    "type": "object",
                    "properties": {"name": {"type": "string"}},
                },
            }
        ],
    )
    _set_result(
        engine,
        "get_config",
        {"name": "test"},
        "postgresql://app_user:password@db.internal:5432/app",
    )

    findings1 = await D2APIKeyStealing(engine).run()
    findings2 = await D2APIKeyStealing(engine).run()

    ids1 = [f.id for f in findings1]
    ids2 = [f.id for f in findings2]
    assert ids1 == ids2


@pytest.mark.asyncio
async def test_d2_truncates_large_responses():
    engine = MockEngine()
    set_phase0(
        engine,
        tools=[
            {
                "name": "get_config",
                "inputSchema": {
                    "type": "object",
                    "properties": {"name": {"type": "string"}},
                },
            }
        ],
    )
    secret = "postgresql://app_user:password@db.internal:5432/app"
    large_text = secret + " " + ("x" * 50_000)
    _set_result(engine, "get_config", {"name": "test"}, large_text)

    findings = await D2APIKeyStealing(engine).run()
    excerpt = findings[0].evidence[0].response["redacted_excerpt"]

    assert "password" not in str(excerpt)
    assert len(excerpt) <= 10_000 + 20
    assert findings[0].evidence[0].response["truncated"] is True
