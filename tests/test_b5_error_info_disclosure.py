from __future__ import annotations

from typing import Any

import pytest

from src.attacks.b5_error_info_disclosure import B5ErrorInfoDisclosure
from src.models import TraceEntry
from tests.attack_test_utils import MockEngine, set_phase0


# ── Helpers ──


def _tool(name: str, schema: dict[str, Any] | None = None) -> dict[str, Any]:
    if schema is None:
        return {"name": name}
    return {"name": name, "inputSchema": schema}


def _string_schema(
    required: list[str] | None = None,
    **properties: Any,
) -> dict[str, Any]:
    return {
        "type": "object",
        "properties": {name: {"type": "string", **opts} for name, opts in properties.items()},
        "required": required or [],
    }


# ── Positive disclosure tests ──


@pytest.mark.asyncio
async def test_b5_detects_python_traceback_via_exception():
    engine = MockEngine()
    set_phase0(engine, tools=[_tool("lookup_user", _string_schema(required=["user_id"], user_id={}))])

    async def _call(name: str, arguments: dict[str, Any] | None = None):
        raise RuntimeError(
            'Traceback (most recent call last):\n'
            '  File "/var/app/services/users.py", line 87, in get_user\n'
            '    raise ValueError("bad id")\nValueError: bad id'
        )

    engine.call_tool = _call  # type: ignore[assignment]
    findings = await B5ErrorInfoDisclosure(engine).run()

    assert len(findings) == 1
    assert findings[0].id.startswith("B5-")
    assert "stack_trace_source" in findings[0].title
    evidence = findings[0].evidence[0]
    assert evidence.request["probe_type"] is not None
    assert evidence.response["pattern_id"] == "python_stack_trace"
    assert evidence.response["verdict"] == "confirmed_disclosure"


@pytest.mark.asyncio
async def test_b5_detects_node_stack_in_normal_response():
    engine = MockEngine()
    set_phase0(engine, tools=[_tool("fetch", _string_schema(required=["url"], url={}))])

    async def _call(name: str, arguments: dict[str, Any] | None = None):
        return {
            "isError": False,
            "content": [
                {
                    "type": "text",
                    "text": (
                        "Error: connect ECONNREFUSED\n"
                        "    at TCPConnectWrap.afterConnect [as oncomplete] "
                        "(/app/node_modules/express/lib/router/index.js:12:3)"
                    ),
                }
            ],
        }

    engine.call_tool = _call  # type: ignore[assignment]
    findings = await B5ErrorInfoDisclosure(engine).run()

    assert len(findings) == 1
    assert findings[0].evidence[0].response["pattern_id"] == "node_stack_trace"


@pytest.mark.asyncio
async def test_b5_detects_sql_schema_in_iserror_response():
    engine = MockEngine()
    set_phase0(engine, tools=[_tool("query", _string_schema(required=["user_id"], user_id={}))])

    async def _call(name: str, arguments: dict[str, Any] | None = None):
        return {
            "isError": True,
            "content": [
                {
                    "type": "text",
                    "text": "SQLSTATE 42P01: relation 'tenant_users_internal' does not exist",
                }
            ],
        }

    engine.call_tool = _call  # type: ignore[assignment]
    findings = await B5ErrorInfoDisclosure(engine).run()

    assert len(findings) == 1
    resp = findings[0].evidence[0].response
    assert resp["category"] == "sql_schema"
    assert resp["pattern_id"] in {"sql_state", "sql_relation_missing"}


@pytest.mark.asyncio
async def test_b5_detects_internal_network_in_exception():
    engine = MockEngine()
    set_phase0(engine, tools=[_tool("save", _string_schema(required=["payload"], payload={}))])

    async def _call(name: str, arguments: dict[str, Any] | None = None):
        raise RuntimeError("connect ECONNREFUSED 10.0.4.21:5432")

    engine.call_tool = _call  # type: ignore[assignment]
    findings = await B5ErrorInfoDisclosure(engine).run()

    assert len(findings) == 1
    assert findings[0].evidence[0].response["category"] == "internal_network"


@pytest.mark.asyncio
async def test_b5_detects_source_path_in_error_details():
    engine = MockEngine()
    set_phase0(engine, tools=[_tool("read", _string_schema(required=["path"], path={}))])

    async def _call(name: str, arguments: dict[str, Any] | None = None):
        return {
            "isError": False,
            "error": {
                "message": "failed",
                "details": "could not read /workspace/app/config/settings.yaml",
            },
        }

    engine.call_tool = _call  # type: ignore[assignment]
    findings = await B5ErrorInfoDisclosure(engine).run()

    assert len(findings) == 1
    assert findings[0].evidence[0].response["category"] == "source_path"


@pytest.mark.asyncio
async def test_b5_detects_prisma_orm_in_nested_error():
    engine = MockEngine()
    set_phase0(engine, tools=[_tool("find_user", _string_schema(required=["id"], id={}))])

    async def _call(name: str, arguments: dict[str, Any] | None = None):
        return {
            "isError": True,
            "error": {
                "cause": {
                    "message": "Invalid `prisma.user.findUnique()` invocation"
                }
            },
        }

    engine.call_tool = _call  # type: ignore[assignment]
    findings = await B5ErrorInfoDisclosure(engine).run()

    assert len(findings) == 1
    assert findings[0].evidence[0].response["pattern_id"] == "prisma_invocation"


@pytest.mark.asyncio
async def test_b5_detects_internal_endpoint_url():
    engine = MockEngine()
    set_phase0(engine, tools=[_tool("notify", _string_schema(required=["url"], url={}))])

    async def _call(name: str, arguments: dict[str, Any] | None = None):
        return {
            "isError": True,
            "content": [
                {
                    "type": "text",
                    "text": "upstream error: https://payments-api.default.svc.cluster.local/invoices",
                }
            ],
        }

    engine.call_tool = _call  # type: ignore[assignment]
    findings = await B5ErrorInfoDisclosure(engine).run()

    assert len(findings) >= 1
    categories = {ev.response["category"] for f in findings for ev in f.evidence}
    assert "internal_endpoint" in categories or "internal_network" in categories


@pytest.mark.asyncio
async def test_b5_detects_authorization_implementation():
    engine = MockEngine()
    set_phase0(engine, tools=[_tool("admin", _string_schema(required=["tenant_id"], tenant_id={}))])

    async def _call(name: str, arguments: dict[str, Any] | None = None):
        raise RuntimeError(
            "TenantPolicy.requireMembership failed in /app/auth/tenant_guard.py:44"
        )

    engine.call_tool = _call  # type: ignore[assignment]
    findings = await B5ErrorInfoDisclosure(engine).run()

    assert len(findings) == 1
    assert findings[0].evidence[0].response["category"] == "authorization_implementation"


@pytest.mark.asyncio
async def test_b5_detects_configuration_deployment():
    engine = MockEngine()
    set_phase0(engine, tools=[_tool("deploy", _string_schema(required=["service"], service={}))])

    async def _call(name: str, arguments: dict[str, Any] | None = None):
        return {
            "isError": True,
            "content": [
                {"type": "text", "text": "namespace: payments-prod, cluster: us-east-1"}
            ],
        }

    engine.call_tool = _call  # type: ignore[assignment]
    findings = await B5ErrorInfoDisclosure(engine).run()

    assert len(findings) == 1
    assert findings[0].evidence[0].response["category"] == "configuration_deployment"


@pytest.mark.asyncio
async def test_b5_detects_runtime_version():
    engine = MockEngine()
    set_phase0(engine, tools=[_tool("compute", _string_schema(required=["x"], x={}))])

    async def _call(name: str, arguments: dict[str, Any] | None = None):
        raise RuntimeError("Node.js v20.11.1: unhandled exception")

    engine.call_tool = _call  # type: ignore[assignment]
    findings = await B5ErrorInfoDisclosure(engine).run()

    assert len(findings) == 1
    assert findings[0].evidence[0].response["category"] == "runtime_dependency"


# ── Negative tests ──


@pytest.mark.asyncio
async def test_b5_ignores_generic_validation_error():
    engine = MockEngine()
    set_phase0(engine, tools=[_tool("tool1", _string_schema(required=["input"], input={}))])

    async def _call(name: str, arguments: dict[str, Any] | None = None):
        raise ValueError("Invalid input")

    engine.call_tool = _call  # type: ignore[assignment]
    findings = await B5ErrorInfoDisclosure(engine).run()

    assert findings == []


@pytest.mark.asyncio
async def test_b5_ignores_generic_exception_message():
    engine = MockEngine()
    set_phase0(engine, tools=[_tool("tool1", _string_schema(required=["input"], input={}))])

    async def _call(name: str, arguments: dict[str, Any] | None = None):
        raise RuntimeError("Exception occurred")

    engine.call_tool = _call  # type: ignore[assignment]
    findings = await B5ErrorInfoDisclosure(engine).run()

    assert findings == []


@pytest.mark.asyncio
async def test_b5_ignores_generic_sql_error():
    engine = MockEngine()
    set_phase0(engine, tools=[_tool("tool1", _string_schema(required=["input"], input={}))])

    async def _call(name: str, arguments: dict[str, Any] | None = None):
        raise RuntimeError("SQL error")

    engine.call_tool = _call  # type: ignore[assignment]
    findings = await B5ErrorInfoDisclosure(engine).run()

    assert findings == []


@pytest.mark.asyncio
async def test_b5_ignores_isolated_var_path():
    engine = MockEngine()
    set_phase0(engine, tools=[_tool("tool1", _string_schema(required=["input"], input={}))])

    async def _call(name: str, arguments: dict[str, Any] | None = None):
        raise RuntimeError("path /var/ is not allowed")

    engine.call_tool = _call  # type: ignore[assignment]
    findings = await B5ErrorInfoDisclosure(engine).run()

    assert findings == []


@pytest.mark.asyncio
async def test_b5_ignores_isolated_windows_path():
    engine = MockEngine()
    set_phase0(engine, tools=[_tool("tool1", _string_schema(required=["input"], input={}))])

    async def _call(name: str, arguments: dict[str, Any] | None = None):
        raise RuntimeError(r"drive C:\ is unavailable")

    engine.call_tool = _call  # type: ignore[assignment]
    findings = await B5ErrorInfoDisclosure(engine).run()

    assert findings == []


@pytest.mark.asyncio
async def test_b5_ignores_public_hostname():
    engine = MockEngine()
    set_phase0(engine, tools=[_tool("tool1", _string_schema(required=["input"], input={}))])

    async def _call(name: str, arguments: dict[str, Any] | None = None):
        raise RuntimeError("could not reach api.example.com")

    engine.call_tool = _call  # type: ignore[assignment]
    findings = await B5ErrorInfoDisclosure(engine).run()

    assert findings == []


@pytest.mark.asyncio
async def test_b5_ignores_request_id():
    engine = MockEngine()
    set_phase0(engine, tools=[_tool("tool1", _string_schema(required=["input"], input={}))])

    async def _call(name: str, arguments: dict[str, Any] | None = None):
        raise RuntimeError("request id: req-12345-abcde")

    engine.call_tool = _call  # type: ignore[assignment]
    findings = await B5ErrorInfoDisclosure(engine).run()

    assert findings == []


@pytest.mark.asyncio
async def test_b5_ignores_sensitive_tool_name():
    engine = MockEngine()
    set_phase0(
        engine,
        tools=[
            _tool(
                "get_secret_token",
                _string_schema(required=["input"], input={"description": "password api_key"}),
            )
        ],
    )

    async def _call(name: str, arguments: dict[str, Any] | None = None):
        raise RuntimeError("Invalid input")

    engine.call_tool = _call  # type: ignore[assignment]
    findings = await B5ErrorInfoDisclosure(engine).run()

    assert findings == []


# ── Channel coverage ──


@pytest.mark.asyncio
async def test_b5_detects_is_error_true():
    engine = MockEngine()
    set_phase0(engine, tools=[_tool("t", _string_schema(required=["x"], x={}))])

    async def _call(name: str, arguments: dict[str, Any] | None = None):
        return {
            "is_error": True,
            "content": [
                {"type": "text", "text": "Traceback: File '/var/app/main.py', line 10"}
            ],
        }

    engine.call_tool = _call  # type: ignore[assignment]
    findings = await B5ErrorInfoDisclosure(engine).run()

    assert len(findings) == 1
    assert findings[0].evidence[0].response["channel"] == "mcp_error"


@pytest.mark.asyncio
async def test_b5_detects_result_type_error():
    engine = MockEngine()
    set_phase0(engine, tools=[_tool("t", _string_schema(required=["x"], x={}))])

    async def _call(name: str, arguments: dict[str, Any] | None = None):
        return {
            "result_type": "error",
            "error": {"message": "SQLSTATE 42703: column 'secret_col' does not exist"},
        }

    engine.call_tool = _call  # type: ignore[assignment]
    findings = await B5ErrorInfoDisclosure(engine).run()

    assert len(findings) == 1
    assert findings[0].evidence[0].response["category"] == "sql_schema"


@pytest.mark.asyncio
async def test_b5_detects_error_stack_field():
    engine = MockEngine()
    set_phase0(engine, tools=[_tool("t", _string_schema(required=["x"], x={}))])

    async def _call(name: str, arguments: dict[str, Any] | None = None):
        return {
            "isError": True,
            "error": {
                "stack": "at getUser (/app/src/users.js:42:10)",
            },
        }

    engine.call_tool = _call  # type: ignore[assignment]
    findings = await B5ErrorInfoDisclosure(engine).run()

    assert len(findings) == 1
    assert findings[0].evidence[0].response["pattern_id"] == "node_stack_trace"


@pytest.mark.asyncio
async def test_b5_detects_cause_field():
    engine = MockEngine()
    set_phase0(engine, tools=[_tool("t", _string_schema(required=["x"], x={}))])

    async def _call(name: str, arguments: dict[str, Any] | None = None):
        return {
            "isError": True,
            "error": {
                "cause": "panic: runtime error at /app/main.go:33",
            },
        }

    engine.call_tool = _call  # type: ignore[assignment]
    findings = await B5ErrorInfoDisclosure(engine).run()

    assert len(findings) == 1
    assert findings[0].evidence[0].response["category"] == "stack_trace_source"


@pytest.mark.asyncio
async def test_b5_detects_serialized_json_error():
    engine = MockEngine()
    set_phase0(engine, tools=[_tool("t", _string_schema(required=["x"], x={}))])

    async def _call(name: str, arguments: dict[str, Any] | None = None):
        return {
            "isError": True,
            "content": [
                {
                    "type": "text",
                    "text": '{"error": "table \\"audit_logs\\" does not exist"}',
                }
            ],
        }

    engine.call_tool = _call  # type: ignore[assignment]
    findings = await B5ErrorInfoDisclosure(engine).run()

    assert len(findings) == 1
    assert findings[0].evidence[0].response["category"] == "sql_schema"


# ── Schema coverage ──


@pytest.mark.asyncio
async def test_b5_uses_input_schema_alias():
    engine = MockEngine()
    set_phase0(
        engine,
        tools=[{"name": "t", "input_schema": {"type": "object", "properties": {"x": {"type": "string"}}, "required": ["x"]}}],
    )

    calls: list[dict[str, Any]] = []

    async def _call(name: str, arguments: dict[str, Any] | None = None):
        calls.append({"name": name, "arguments": arguments or {}})
        raise RuntimeError("Traceback: File '/var/app/t.py', line 1")

    engine.call_tool = _call  # type: ignore[assignment]
    findings = await B5ErrorInfoDisclosure(engine).run()

    assert len(calls) >= 1
    assert len(findings) == 1


@pytest.mark.asyncio
async def test_b5_respects_required_fields():
    engine = MockEngine()
    set_phase0(
        engine,
        tools=[
            _tool(
                "t",
                {
                    "type": "object",
                    "properties": {
                        "a": {"type": "string"},
                        "b": {"type": "string"},
                    },
                    "required": ["a"],
                },
            )
        ],
    )

    calls: list[dict[str, Any]] = []

    async def _call(name: str, arguments: dict[str, Any] | None = None):
        calls.append(arguments or {})
        raise RuntimeError("invalid")

    engine.call_tool = _call  # type: ignore[assignment]
    await B5ErrorInfoDisclosure(engine).run()

    # Baseline should include the required field.
    assert any(call.get("a") is not None for call in calls)
    # Missing-required probe should drop the required field.
    assert any("a" not in call for call in calls)


@pytest.mark.asyncio
async def test_b5_uses_defaults_examples_enums():
    engine = MockEngine()
    set_phase0(
        engine,
        tools=[
            _tool(
                "t",
                {
                    "type": "object",
                    "properties": {
                        "status": {"type": "string", "enum": ["active", "inactive"]},
                        "count": {"type": "integer", "default": 5},
                        "name": {"type": "string", "examples": ["alice"]},
                    },
                    "required": ["status"],
                },
            )
        ],
    )

    calls: list[dict[str, Any]] = []

    async def _call(name: str, arguments: dict[str, Any] | None = None):
        calls.append(arguments or {})
        raise RuntimeError("invalid")

    engine.call_tool = _call  # type: ignore[assignment]
    await B5ErrorInfoDisclosure(engine).run()

    baseline = calls[0]
    assert baseline.get("status") == "active"
    assert baseline.get("count") == 5
    assert baseline.get("name") == "alice"


@pytest.mark.asyncio
async def test_b5_skips_schema_less_tools():
    engine = MockEngine()
    set_phase0(engine, tools=[_tool("no_schema")])

    calls: list[dict[str, Any]] = []

    async def _call(name: str, arguments: dict[str, Any] | None = None):
        calls.append(arguments or {})
        raise RuntimeError("Traceback: File '/var/app/main.py', line 1")

    engine.call_tool = _call  # type: ignore[assignment]
    findings = await B5ErrorInfoDisclosure(engine).run()

    assert calls == []
    assert findings == []


@pytest.mark.asyncio
async def test_b5_skips_dangerous_required_sibling():
    engine = MockEngine()
    set_phase0(
        engine,
        tools=[
            _tool(
                "t",
                {
                    "type": "object",
                    "properties": {
                        "command": {"type": "string"},
                        "arg": {"type": "string"},
                    },
                    "required": ["command", "arg"],
                },
            )
        ],
    )

    calls: list[dict[str, Any]] = []

    async def _call(name: str, arguments: dict[str, Any] | None = None):
        calls.append(arguments or {})
        raise RuntimeError("Traceback: File '/var/app/main.py', line 1")

    engine.call_tool = _call  # type: ignore[assignment]
    findings = await B5ErrorInfoDisclosure(engine).run()

    assert calls == []
    assert findings == []


@pytest.mark.asyncio
async def test_b5_handles_nested_object_schema():
    engine = MockEngine()
    set_phase0(
        engine,
        tools=[
            _tool(
                "t",
                {
                    "type": "object",
                    "properties": {
                        "filter": {
                            "type": "object",
                            "properties": {"id": {"type": "string"}},
                            "required": ["id"],
                        }
                    },
                    "required": ["filter"],
                },
            )
        ],
    )

    calls: list[dict[str, Any]] = []

    async def _call(name: str, arguments: dict[str, Any] | None = None):
        calls.append(arguments or {})
        raise RuntimeError("Traceback: File '/var/app/main.py', line 1")

    engine.call_tool = _call  # type: ignore[assignment]
    findings = await B5ErrorInfoDisclosure(engine).run()

    assert len(calls) >= 1
    assert calls[0].get("filter") == {"id": "test"}
    assert len(findings) == 1


# ── Probe behavior ──


@pytest.mark.asyncio
async def test_b5_generates_baseline_call():
    engine = MockEngine()
    set_phase0(engine, tools=[_tool("t", _string_schema(required=["x"], x={}))])

    calls: list[dict[str, Any]] = []

    async def _call(name: str, arguments: dict[str, Any] | None = None):
        calls.append(arguments or {})
        raise RuntimeError("invalid")

    engine.call_tool = _call  # type: ignore[assignment]
    await B5ErrorInfoDisclosure(engine).run()

    assert calls
    assert calls[0] == {"x": "test"}


@pytest.mark.asyncio
async def test_b5_preserves_required_siblings():
    engine = MockEngine()
    set_phase0(
        engine,
        tools=[
            _tool(
                "t",
                {
                    "type": "object",
                    "properties": {
                        "a": {"type": "string"},
                        "b": {"type": "string"},
                    },
                    "required": ["a", "b"],
                },
            )
        ],
    )

    calls: list[dict[str, Any]] = []

    async def _call(name: str, arguments: dict[str, Any] | None = None):
        calls.append(arguments or {})
        raise RuntimeError("invalid")

    engine.call_tool = _call  # type: ignore[assignment]
    await B5ErrorInfoDisclosure(engine).run()

    for call in calls:
        assert "a" in call and "b" in call or len(call) < 2


@pytest.mark.asyncio
async def test_b5_generates_null_mutation():
    engine = MockEngine()
    set_phase0(engine, tools=[_tool("t", _string_schema(required=["x"], x={}))])

    calls: list[dict[str, Any]] = []

    async def _call(name: str, arguments: dict[str, Any] | None = None):
        calls.append(arguments or {})
        raise RuntimeError("invalid")

    engine.call_tool = _call  # type: ignore[assignment]
    await B5ErrorInfoDisclosure(engine).run()

    assert any(call.get("x") is None for call in calls)


@pytest.mark.asyncio
async def test_b5_generates_invalid_enum_mutation():
    engine = MockEngine()
    set_phase0(
        engine,
        tools=[
            _tool(
                "t",
                {
                    "type": "object",
                    "properties": {"status": {"type": "string", "enum": ["on", "off"]}},
                    "required": ["status"],
                },
            )
        ],
    )

    calls: list[dict[str, Any]] = []

    async def _call(name: str, arguments: dict[str, Any] | None = None):
        calls.append(arguments or {})
        raise RuntimeError("invalid")

    engine.call_tool = _call  # type: ignore[assignment]
    await B5ErrorInfoDisclosure(engine).run()

    assert any("___b5_invalid_enum_value" in str(call.get("status", "")) for call in calls)


@pytest.mark.asyncio
async def test_b5_generates_overlong_string():
    engine = MockEngine()
    set_phase0(engine, tools=[_tool("t", _string_schema(required=["x"], x={}))])

    calls: list[dict[str, Any]] = []

    async def _call(name: str, arguments: dict[str, Any] | None = None):
        calls.append(arguments or {})
        raise RuntimeError("invalid")

    engine.call_tool = _call  # type: ignore[assignment]
    await B5ErrorInfoDisclosure(engine).run()

    assert any(isinstance(call.get("x"), str) and len(call["x"]) >= 4000 for call in calls)


@pytest.mark.asyncio
async def test_b5_enforces_max_probes_per_tool():
    engine = MockEngine()
    set_phase0(
        engine,
        tools=[
            _tool(
                "t",
                {
                    "type": "object",
                    "properties": {
                        "a": {"type": "string"},
                        "b": {"type": "string"},
                        "c": {"type": "string"},
                        "d": {"type": "string"},
                        "e": {"type": "string"},
                        "f": {"type": "string"},
                    },
                    "required": list("abcdef"),
                },
            )
        ],
    )

    calls: list[dict[str, Any]] = []

    async def _call(name: str, arguments: dict[str, Any] | None = None):
        calls.append(arguments or {})
        raise RuntimeError("invalid")

    engine.call_tool = _call  # type: ignore[assignment]
    await B5ErrorInfoDisclosure(engine, max_probes_per_tool=4).run()

    assert len(calls) == 4


@pytest.mark.asyncio
async def test_b5_enforces_max_total_probes():
    engine = MockEngine()
    tools = [
        _tool(f"t{i}", _string_schema(required=["x"], x={}))
        for i in range(10)
    ]
    set_phase0(engine, tools=tools)

    calls: list[dict[str, Any]] = []

    async def _call(name: str, arguments: dict[str, Any] | None = None):
        calls.append(arguments or {})
        raise RuntimeError("invalid")

    engine.call_tool = _call  # type: ignore[assignment]
    await B5ErrorInfoDisclosure(engine, max_total_probes=3).run()

    assert len(calls) == 3


@pytest.mark.asyncio
async def test_b5_deterministic_order():
    engine = MockEngine()
    tools = [
        _tool("z", _string_schema(required=["x"], x={})),
        _tool("a", _string_schema(required=["x"], x={})),
        _tool("m", _string_schema(required=["x"], x={})),
    ]
    set_phase0(engine, tools=tools)

    calls: list[tuple[str, dict[str, Any]]] = []

    async def _call(name: str, arguments: dict[str, Any] | None = None):
        calls.append((name, arguments or {}))
        raise RuntimeError("invalid")

    engine.call_tool = _call  # type: ignore[assignment]
    await B5ErrorInfoDisclosure(engine).run()
    first_run = [c[0] for c in calls]

    calls.clear()
    await B5ErrorInfoDisclosure(engine).run()
    second_run = [c[0] for c in calls]

    assert first_run == second_run
    assert sorted(set(first_run)) == ["a", "m", "z"]
    assert first_run == sorted(first_run)


@pytest.mark.asyncio
async def test_b5_does_not_use_specialized_payloads():
    engine = MockEngine()
    set_phase0(engine, tools=[_tool("t", _string_schema(required=["path"], path={}))])

    calls: list[dict[str, Any]] = []

    async def _call(name: str, arguments: dict[str, Any] | None = None):
        calls.append(arguments or {})
        raise RuntimeError("invalid")

    engine.call_tool = _call  # type: ignore[assignment]
    await B5ErrorInfoDisclosure(engine).run()

    for call in calls:
        for value in call.values():
            if isinstance(value, str):
                assert "../" not in value
                assert ";" not in value or "___b5" not in value
                assert "http://" not in value
                assert "SELECT " not in value.upper()


# ── Evidence / trace / aggregation ──


@pytest.mark.asyncio
async def test_b5_evidence_contains_probe_details():
    engine = MockEngine()
    set_phase0(engine, tools=[_tool("t", _string_schema(required=["x"], x={}))])

    async def _call(name: str, arguments: dict[str, Any] | None = None):
        raise RuntimeError("Traceback: File '/var/app/main.py', line 1")

    engine.call_tool = _call  # type: ignore[assignment]
    findings = await B5ErrorInfoDisclosure(engine).run()

    assert len(findings) == 1
    ev = findings[0].evidence[0]
    assert ev.request["tool"] == "t"
    assert "arguments" in ev.request
    assert "probe_type" in ev.request
    assert "channel" in ev.response
    assert "category" in ev.response
    assert "confidence" in ev.response
    assert "verdict" in ev.response
    assert "sanitized_excerpt" in ev.response


@pytest.mark.asyncio
async def test_b5_redacts_credentials_in_excerpt():
    engine = MockEngine()
    set_phase0(engine, tools=[_tool("t", _string_schema(required=["x"], x={}))])

    async def _call(name: str, arguments: dict[str, Any] | None = None):
        raise RuntimeError(
            "Traceback: File '/var/app/main.py', line 1; "
            "connection string: postgresql://user:supersecret@10.0.0.1/db"
        )

    engine.call_tool = _call  # type: ignore[assignment]
    findings = await B5ErrorInfoDisclosure(engine).run()

    assert len(findings) >= 1
    excerpts = [
        ev.response["sanitized_excerpt"]
        for f in findings
        for ev in f.evidence
    ]
    assert any("supersecret" not in excerpt for excerpt in excerpts)
    assert any("[REDACTED]" in excerpt for excerpt in excerpts)


@pytest.mark.asyncio
async def test_b5_correlates_trace_entry():
    engine = MockEngine()
    set_phase0(engine, tools=[_tool("t", _string_schema(required=["x"], x={}))])

    trace_id = "trace-123"

    async def _call(name: str, arguments: dict[str, Any] | None = None):
        engine.traces.append(
            TraceEntry(
                session_id="s1",
                method="tools/call",
                request={"name": name, "arguments": arguments or {}},
                error="Traceback: File '/var/app/main.py', line 1",
                id=trace_id,
            )
        )
        raise RuntimeError("Traceback: File '/var/app/main.py', line 1")

    engine.call_tool = _call  # type: ignore[assignment]
    findings = await B5ErrorInfoDisclosure(engine).run()

    assert len(findings) == 1
    assert findings[0].evidence[0].trace_entry_id == trace_id


@pytest.mark.asyncio
async def test_b5_aggregates_by_family():
    engine = MockEngine()
    set_phase0(engine, tools=[_tool("t", _string_schema(required=["x"], x={}))])

    call_count = 0

    async def _call(name: str, arguments: dict[str, Any] | None = None):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            raise RuntimeError("Traceback: File '/var/app/main.py', line 1")
        raise RuntimeError("connect ECONNREFUSED 10.0.0.1:5432")

    engine.call_tool = _call  # type: ignore[assignment]
    findings = await B5ErrorInfoDisclosure(engine).run()

    families = {f.evidence[0].response["category"] for f in findings}
    # Should aggregate into at most two findings, one per family.
    assert len(findings) <= 2
    assert len(families) <= 2


@pytest.mark.asyncio
async def test_b5_resets_state_between_runs():
    engine = MockEngine()
    set_phase0(engine, tools=[_tool("t", _string_schema(required=["x"], x={}))])

    async def _call(name: str, arguments: dict[str, Any] | None = None):
        raise RuntimeError("Traceback: File '/var/app/main.py', line 1")

    engine.call_tool = _call  # type: ignore[assignment]

    mod = B5ErrorInfoDisclosure(engine)
    findings1 = await mod.run()
    findings2 = await mod.run()

    assert len(findings1) == len(findings2) == 1
    assert findings1[0].id == findings2[0].id == "B5-001"
    assert mod.stats["attempted"] > 0
