from __future__ import annotations

import asyncio
import multiprocessing
import re
import socket
import time
from typing import Any

import pytest
import uvicorn
from mcp.server.mcpserver import MCPServer

from src.attacks.b1_parameter_injection import B1ParameterInjection
from src.models import AuthMethod, Severity, TargetConfig, TraceEntry, TransportType
from src.probe_engine import ProbeEngine
from tests.attack_test_utils import MockEngine, set_phase0


# ── Test helpers ──


def _tool(
    name: str,
    schema: dict[str, Any] | None = None,
    description: str = "",
) -> dict[str, Any]:
    tool: dict[str, Any] = {"name": name}
    if description:
        tool["description"] = description
    if schema is not None:
        tool["inputSchema"] = schema
    return tool


def _schema(required: list[str] | None = None, **fields: Any) -> dict[str, Any]:
    return {
        "type": "object",
        "properties": fields,
        "required": required or [],
    }


def _field(type: str = "string", **opts: Any) -> dict[str, Any]:
    return {"type": type, **opts}


def _extract_nonce_and_marker(text: str) -> tuple[str, str] | None:
    # Extract the B1 nonce from a payload like "; printf 'B1_<nonce>_'$((40+2)); #"
    # or from a response containing the computed marker "B1_<nonce>_42".
    m = re.search(r"B1_([A-Za-z0-9_-]+)_", text)
    if not m:
        return None
    nonce = m.group(1)
    marker = f"B1_{nonce}_42"
    return nonce, marker


async def _run_b1(engine: MockEngine) -> list[Any]:
    return await B1ParameterInjection(engine).run()


def _attack_evidence(findings: list[Any]) -> Any:
    """Return the first attack-role evidence item from a finding."""
    assert findings
    for ev in findings[0].evidence:
        if ev.request.get("role") == "attack":
            return ev
    raise AssertionError("no attack evidence found")


# ── Positive / oracle tests ──


@pytest.mark.asyncio
async def test_b1_confirms_command_injection_with_computed_marker():
    engine = MockEngine()
    set_phase0(
        engine,
        tools=[
            _tool(
                "exec_process",
                _schema(
                    required=["args"],
                    args=_field(description="arguments for the process command"),
                ),
                description="execute a system process",
            )
        ],
    )

    async def _call(name: str, arguments: dict[str, Any] | None = None):
        args = arguments or {}
        engine.call_history.append({"name": name, "arguments": args})
        val = args.get("args", "")
        if isinstance(val, str) and "B1_" in val and "$((" in val:
            marker_match = _extract_nonce_and_marker(val)
            if marker_match:
                return {
                    "isError": False,
                    "content": [
                        {"type": "text", "text": f"started\n{marker_match[1]}\ndone"}
                    ],
                }
        return {"isError": False, "content": [{"type": "text", "text": "started"}]}

    engine.call_tool = _call  # type: ignore[assignment]
    findings = await _run_b1(engine)

    assert len(findings) == 1
    f = findings[0]
    assert f.id.startswith("B1-")
    assert "command injection" in f.title.lower()
    assert "B1_" in str(_attack_evidence(findings).response.get("observed_marker", ""))


@pytest.mark.asyncio
async def test_b1_confirms_sql_injection_with_boolean_differential():
    engine = MockEngine()
    set_phase0(
        engine,
        tools=[
            _tool(
                "search_users",
                _schema(
                    required=["tenant_id", "query"],
                    tenant_id=_field(),
                    query=_field(description="search query string"),
                ),
                description="SQL user search",
            )
        ],
    )

    async def _call(name: str, arguments: dict[str, Any] | None = None):
        args = arguments or {}
        engine.call_history.append({"name": name, "arguments": args})
        q = args.get("query", "")
        if q == "'":
            return {
                "isError": True,
                "content": [{"type": "text", "text": "SQL syntax error near '"}],
            }
        if "OR (1=1)" in q:
            return {
                "isError": False,
                "content": [
                    {"type": "text", "text": "alice"},
                    {"type": "text", "text": "bob"},
                    {"type": "text", "text": "carol"},
                ],
            }
        if "OR (1=2)" in q:
            return {"isError": False, "content": []}
        return {"isError": False, "content": [{"type": "text", "text": "alice"}]}

    engine.call_tool = _call  # type: ignore[assignment]
    findings = await _run_b1(engine)

    assert len(findings) == 1
    f = findings[0]
    assert "sql injection" in f.title.lower()
    assert _attack_evidence(findings).response["verdict"] == "confirmed_injection"


@pytest.mark.asyncio
async def test_b1_confirms_ssti_with_computed_expression():
    engine = MockEngine()
    set_phase0(
        engine,
        tools=[
            _tool(
                "render_email",
                _schema(
                    required=["template"],
                    template=_field(description="email template to render"),
                ),
                description="render email templates",
            )
        ],
    )

    async def _call(name: str, arguments: dict[str, Any] | None = None):
        args = arguments or {}
        engine.call_history.append({"name": name, "arguments": args})
        val = args.get("template", "")
        marker_match = _extract_nonce_and_marker(str(val))
        if marker_match and val != marker_match[1]:
            return {
                "isError": False,
                "content": [{"type": "text", "text": f"Subject\n{marker_match[1]}"}],
            }
        return {"isError": False, "content": [{"type": "text", "text": "Subject"}]}

    engine.call_tool = _call  # type: ignore[assignment]
    findings = await _run_b1(engine)

    assert len(findings) == 1
    f = findings[0]
    assert "template injection" in f.title.lower()
    assert _attack_evidence(findings).response["verdict"] == "confirmed_injection"


@pytest.mark.asyncio
async def test_b1_confirms_expression_evaluation():
    engine = MockEngine()
    set_phase0(
        engine,
        tools=[
            _tool(
                "calc",
                _schema(required=["expr"], expr=_field(description="expression")),
                description="evaluate numeric expressions",
            )
        ],
    )

    # Pin the nonce so the expected computed marker is known in the mock.
    import src.attacks.b1_parameter_injection as b1mod

    original_fresh_nonce = b1mod._fresh_nonce
    b1mod._fresh_nonce = lambda: "EXPRTEST"
    try:

        async def _call(name: str, arguments: dict[str, Any] | None = None):
            args = arguments or {}
            engine.call_history.append({"name": name, "arguments": args})
            val = args.get("expr", "")
            if val in ("40+2", "20+22"):
                return {
                    "isError": False,
                    "content": [{"type": "text", "text": "result: B1_EXPRTEST_42"}],
                }
            return {"isError": False, "content": [{"type": "text", "text": "result: 0"}]}

        engine.call_tool = _call  # type: ignore[assignment]
        findings = await _run_b1(engine)

        assert len(findings) == 1
        assert "expression evaluation" in findings[0].title.lower()
        assert _attack_evidence(findings).response["verdict"] == "confirmed_injection"
    finally:
        b1mod._fresh_nonce = original_fresh_nonce


@pytest.mark.asyncio
async def test_b1_confirms_nosql_object_injection():
    engine = MockEngine()
    set_phase0(
        engine,
        tools=[
            _tool(
                "find_users",
                _schema(
                    required=["filter"],
                    filter=_field(
                        type="object",
                        properties={"name": _field()},
                        required=["name"],
                        description="mongodb filter object",
                    ),
                ),
                description="query mongodb users",
            )
        ],
    )

    async def _call(name: str, arguments: dict[str, Any] | None = None):
        args = arguments or {}
        engine.call_history.append({"name": name, "arguments": args})
        f = args.get("filter", {})
        if isinstance(f, dict) and f.get("$ne") == "__b1_absent__":
            return {
                "isError": False,
                "content": [
                    {"type": "text", "text": "alice"},
                    {"type": "text", "text": "bob"},
                    {"type": "text", "text": "carol"},
                ],
            }
        if isinstance(f, dict) and f.get("$eq") == "__b1_absent__":
            return {"isError": False, "content": []}
        return {"isError": False, "content": [{"type": "text", "text": "alice"}]}

    engine.call_tool = _call  # type: ignore[assignment]
    findings = await _run_b1(engine)

    assert len(findings) == 1
    assert "query filter injection" in findings[0].title.lower()
    assert _attack_evidence(findings).response["verdict"] == "confirmed_injection"


# ── Negative / reflection tests ──


@pytest.mark.asyncio
async def test_b1_rejects_exact_reflection():
    engine = MockEngine()
    set_phase0(
        engine,
        tools=[
            _tool(
                "echo",
                _schema(required=["msg"], msg=_field(description="message echo")),
                description="echo input back",
            )
        ],
    )

    async def _call(name: str, arguments: dict[str, Any] | None = None):
        args = arguments or {}
        engine.call_history.append({"name": name, "arguments": args})
        return {"isError": False, "content": [{"type": "text", "text": str(args.get("msg", ""))}]}

    engine.call_tool = _call  # type: ignore[assignment]
    findings = await _run_b1(engine)

    assert findings == []


@pytest.mark.asyncio
async def test_b1_rejects_generic_validation_error():
    engine = MockEngine()
    set_phase0(
        engine,
        tools=[
            _tool(
                "lookup",
                _schema(required=["id"], id=_field(description="user id")),
                description="lookup user",
            )
        ],
    )

    async def _call(name: str, arguments: dict[str, Any] | None = None):
        args = arguments or {}
        engine.call_history.append({"name": name, "arguments": args})
        if args.get("id", "").startswith("'"):
            return {"isError": True, "content": [{"type": "text", "text": "Invalid input"}]}
        return {"isError": False, "content": [{"type": "text", "text": "ok"}]}

    engine.call_tool = _call  # type: ignore[assignment]
    findings = await _run_b1(engine)

    assert findings == []


@pytest.mark.asyncio
async def test_b1_rejects_generic_error_without_parser_or_differential():
    engine = MockEngine()
    set_phase0(
        engine,
        tools=[
            _tool(
                "search",
                _schema(required=["q"], q=_field(description="query")),
                description="SQL search",
            )
        ],
    )

    async def _call(name: str, arguments: dict[str, Any] | None = None):
        args = arguments or {}
        engine.call_history.append({"name": name, "arguments": args})
        q = str(args.get("q", ""))
        if q.startswith("'") or "OR (1=1)" in q or "OR (1=2)" in q:
            return {"isError": True, "content": [{"type": "text", "text": "query rejected"}]}
        return {"isError": False, "content": [{"type": "text", "text": "ok"}]}

    engine.call_tool = _call  # type: ignore[assignment]
    findings = await _run_b1(engine)

    assert findings == []


# ── Schema tests ──


@pytest.mark.asyncio
async def test_b1_uses_input_schema_alias():
    engine = MockEngine()
    set_phase0(
        engine,
        tools=[
            {
                "name": "t",
                "description": "execute a system process",
                "input_schema": {
                    "type": "object",
                    "properties": {"args": {"type": "string", "description": "process args"}},
                    "required": ["args"],
                },
            }
        ],
    )

    calls: list[dict[str, Any]] = []

    async def _call(name: str, arguments: dict[str, Any] | None = None):
        calls.append(arguments or {})
        return {"isError": False, "content": [{"type": "text", "text": "ok"}]}

    engine.call_tool = _call  # type: ignore[assignment]
    findings = await _run_b1(engine)

    assert len(calls) >= 1
    assert findings == []


@pytest.mark.asyncio
async def test_b1_preserves_required_siblings():
    engine = MockEngine()
    set_phase0(
        engine,
        tools=[
            _tool(
                "search",
                _schema(
                    required=["tenant_id", "query"],
                    tenant_id=_field(),
                    query=_field(description="search query"),
                ),
                description="SQL search",
            )
        ],
    )

    calls: list[dict[str, Any]] = []

    async def _call(name: str, arguments: dict[str, Any] | None = None):
        calls.append(arguments or {})
        return {"isError": False, "content": [{"type": "text", "text": "ok"}]}

    engine.call_tool = _call  # type: ignore[assignment]
    await _run_b1(engine)

    assert all("tenant_id" in call for call in calls)


@pytest.mark.asyncio
async def test_b1_handles_nested_object_parameter():
    engine = MockEngine()
    set_phase0(
        engine,
        tools=[
            _tool(
                "search",
                _schema(
                    required=["filter"],
                    filter=_field(
                        type="object",
                        properties={"name": _field(description="name filter")},
                        required=["name"],
                    ),
                ),
                description="SQL user query",
            )
        ],
    )

    calls: list[dict[str, Any]] = []

    async def _call(name: str, arguments: dict[str, Any] | None = None):
        calls.append(arguments or {})
        q = (arguments or {}).get("filter", {}).get("name", "")
        marker_match = _extract_nonce_and_marker(str(q))
        if marker_match and q != marker_match[1]:
            return {"isError": False, "content": [{"type": "text", "text": marker_match[1]}]}
        return {"isError": False, "content": [{"type": "text", "text": "ok"}]}

    engine.call_tool = _call  # type: ignore[assignment]
    findings = await _run_b1(engine)

    assert any("filter" in call and isinstance(call["filter"], dict) for call in calls)
    assert findings == [] or "template_injection" in findings[0].title.lower()


@pytest.mark.asyncio
async def test_b1_skips_url_parameter_without_interpreter_context():
    engine = MockEngine()
    set_phase0(
        engine,
        tools=[
            _tool(
                "fetch",
                _schema(required=["url"], url=_field(description="URL to fetch")),
                description="fetch a remote URL",
            )
        ],
    )

    calls: list[dict[str, Any]] = []

    async def _call(name: str, arguments: dict[str, Any] | None = None):
        calls.append(arguments or {})
        return {"isError": False, "content": [{"type": "text", "text": "ok"}]}

    engine.call_tool = _call  # type: ignore[assignment]
    findings = await _run_b1(engine)

    # Only the safe baseline call should be made; no attack probes for a bare URL.
    assert all(c == {"url": "test"} for c in calls)
    assert findings == []


@pytest.mark.asyncio
async def test_b1_url_parameter_with_interpreter_context_is_tested():
    engine = MockEngine()
    set_phase0(
        engine,
        tools=[
            _tool(
                "curl_to_shell",
                _schema(required=["url"], url=_field(description="URL passed to shell curl")),
                description="execute curl command for URL",
            )
        ],
    )

    calls: list[dict[str, Any]] = []

    async def _call(name: str, arguments: dict[str, Any] | None = None):
        calls.append(arguments or {})
        val = (arguments or {}).get("url", "")
        marker_match = _extract_nonce_and_marker(str(val))
        if marker_match and val != marker_match[1]:
            return {"isError": False, "content": [{"type": "text", "text": marker_match[1]}]}
        return {"isError": False, "content": [{"type": "text", "text": "ok"}]}

    engine.call_tool = _call  # type: ignore[assignment]
    findings = await _run_b1(engine)

    assert len(calls) >= 1
    assert len(findings) == 1


@pytest.mark.asyncio
async def test_b1_skips_dangerous_required_sibling_without_safe_value():
    engine = MockEngine()
    set_phase0(
        engine,
        tools=[
            _tool(
                "render",
                _schema(
                    required=["command", "template"],
                    command=_field(),
                    template=_field(description="email template"),
                ),
                description="render a template",
            )
        ],
    )

    calls: list[dict[str, Any]] = []

    async def _call(name: str, arguments: dict[str, Any] | None = None):
        calls.append(arguments or {})
        return {"isError": False, "content": [{"type": "text", "text": "ok"}]}

    engine.call_tool = _call  # type: ignore[assignment]
    findings = await B1ParameterInjection(engine, max_params_per_tool=1).run()

    # The baseline call is still made; the candidate must be skipped.
    attack_calls = [
        c for c in calls if c.get("template") != "test" or c.get("command") != "test"
    ]
    assert attack_calls == []
    assert findings == []


@pytest.mark.asyncio
async def test_b1_uses_defaults_examples_enums():
    engine = MockEngine()
    set_phase0(
        engine,
        tools=[
            _tool(
                "search",
                _schema(
                    required=["tenant_id", "query"],
                    tenant_id=_field(default="default-tenant"),
                    query=_field(examples=["alice"], description="search query"),
                ),
                description="SQL search",
            )
        ],
    )

    calls: list[dict[str, Any]] = []

    async def _call(name: str, arguments: dict[str, Any] | None = None):
        calls.append(arguments or {})
        return {"isError": False, "content": [{"type": "text", "text": "ok"}]}

    engine.call_tool = _call  # type: ignore[assignment]
    await _run_b1(engine)

    baseline = calls[0]
    assert baseline.get("tenant_id") == "default-tenant"
    assert baseline.get("query") == "alice"


@pytest.mark.asyncio
async def test_b1_skips_schema_less_tools():
    engine = MockEngine()
    set_phase0(engine, tools=[_tool("no_schema")])

    calls: list[dict[str, Any]] = []

    async def _call(name: str, arguments: dict[str, Any] | None = None):
        calls.append(arguments or {})
        return {"isError": False, "content": [{"type": "text", "text": "ok"}]}

    engine.call_tool = _call  # type: ignore[assignment]
    findings = await _run_b1(engine)

    assert calls == []
    assert findings == []


# ── Positive E2E / transport test ──


def run_b1_vulnerable_server(host: str, port: int) -> None:
    """MCP server with one intentionally vulnerable command-like tool."""
    mcp = MCPServer("b1-vulnerable-target")

    @mcp.tool()
    def run_command(command: str) -> str:
        """Execute a system command. Vulnerable to command injection for testing."""
        # Controlled, self-contained interpreter: only the B1 test marker is
        # ever computed; arbitrary host commands are not executed.
        match = re.search(r"B1_([A-Za-z0-9_-]+)_", command)
        if match:
            nonce = match.group(1)
            return f"Command output: B1_{nonce}_42"
        return f"Command executed: {command}"

    app = mcp.sse_app(host=host)
    uvicorn.run(app, host=host, port=port, log_level="error")


def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_b1_command_injection_e2e():
    """B1 confirms command injection through a real MCP SSE transport."""
    port = _find_free_port()
    process = multiprocessing.Process(
        target=run_b1_vulnerable_server,
        args=("127.0.0.1", port),
        daemon=True,
    )
    process.start()

    try:
        time.sleep(2)

        config = TargetConfig(
            endpoint_url=f"http://127.0.0.1:{port}/sse",
            transport=TransportType.SSE,
            auth_method=AuthMethod.NONE,
        )
        engine = ProbeEngine(config)

        async def run_b1() -> list[Any]:
            async with engine.connect():
                return await B1ParameterInjection(engine).run()

        findings = asyncio.run(run_b1())

        assert len(findings) == 1
        finding = findings[0]
        assert "command injection" in finding.title.lower()
        assert finding.severity == Severity.HIGH

        attack_ev = _attack_evidence(findings)
        assert attack_ev.response["verdict"] == "confirmed_injection"
        observed_marker = attack_ev.response.get("observed_marker", "")
        assert observed_marker and observed_marker.startswith("B1_")
        assert attack_ev.trace_entry_id is not None
    finally:
        process.terminate()
        process.join(timeout=5)
        if process.is_alive():
            process.kill()
            process.join(timeout=2)



# ── Payload safety tests ──


@pytest.mark.asyncio
async def test_b1_does_not_send_destructive_default_payloads():
    engine = MockEngine()
    set_phase0(
        engine,
        tools=[
            _tool(
                "exec_process",
                _schema(required=["args"], args=_field(description="process args")),
                description="execute a system process",
            )
        ],
    )

    sent: list[str] = []

    async def _call(name: str, arguments: dict[str, Any] | None = None):
        args = arguments or {}
        sent.append(str(args.get("args", "")))
        return {"isError": False, "content": [{"type": "text", "text": "ok"}]}

    engine.call_tool = _call  # type: ignore[assignment]
    await _run_b1(engine)

    for payload in sent:
        lowered = payload.lower()
        assert "rm " not in lowered
        assert "drop " not in lowered
        assert "delete " not in lowered
        assert "/etc/passwd" not in lowered
        assert "reverse" not in lowered
        assert "bash -i" not in lowered


# ── Response channel tests ──


@pytest.mark.asyncio
async def test_b1_detects_marker_in_iserror_response():
    engine = MockEngine()
    set_phase0(
        engine,
        tools=[
            _tool(
                "exec",
                _schema(required=["args"], args=_field(default="echo test")),
                description="execute a system process",
            )
        ],
    )

    async def _call(name: str, arguments: dict[str, Any] | None = None):
        args = arguments or {}
        val = args.get("args", "")
        marker_match = _extract_nonce_and_marker(str(val))
        if marker_match and val != marker_match[1]:
            return {
                "isError": True,
                "error": {"message": f"command failed: {marker_match[1]}"},
            }
        return {"isError": False, "content": [{"type": "text", "text": "ok"}]}

    engine.call_tool = _call  # type: ignore[assignment]
    findings = await _run_b1(engine)

    assert len(findings) == 1
    assert _attack_evidence(findings).response["channel"] == "mcp_error"


@pytest.mark.asyncio
async def test_b1_detects_marker_in_exception():
    engine = MockEngine()
    set_phase0(
        engine,
        tools=[
            _tool(
                "exec",
                _schema(required=["args"], args=_field(default="echo test")),
                description="execute a system process",
            )
        ],
    )

    async def _call(name: str, arguments: dict[str, Any] | None = None):
        args = arguments or {}
        val = args.get("args", "")
        marker_match = _extract_nonce_and_marker(str(val))
        if marker_match and val != marker_match[1]:
            raise RuntimeError(f"shell error: {marker_match[1]}")
        return {"isError": False, "content": [{"type": "text", "text": "ok"}]}

    engine.call_tool = _call  # type: ignore[assignment]
    findings = await _run_b1(engine)

    assert len(findings) == 1
    assert _attack_evidence(findings).response["channel"] == "exception"


@pytest.mark.asyncio
async def test_b1_detects_nested_error_message():
    engine = MockEngine()
    set_phase0(
        engine,
        tools=[
            _tool(
                "search",
                _schema(required=["q"], q=_field(description="query")),
                description="SQL search",
            )
        ],
    )

    async def _call(name: str, arguments: dict[str, Any] | None = None):
        args = arguments or {}
        if "'" == args.get("q", ""):
            return {
                "isError": True,
                "error": {
                    "cause": {
                        "message": "SQL syntax error near '"
                    }
                },
            }
        if "OR (1=1)" in str(args.get("q", "")):
            return {"isError": False, "content": [{"type": "text", "text": "a"}, {"type": "text", "text": "b"}]}
        if "OR (1=2)" in str(args.get("q", "")):
            return {"isError": False, "content": []}
        return {"isError": False, "content": [{"type": "text", "text": "ok"}]}

    engine.call_tool = _call  # type: ignore[assignment]
    findings = await _run_b1(engine)

    assert len(findings) == 1
    assert _attack_evidence(findings).response["verdict"] == "confirmed_injection"


@pytest.mark.asyncio
async def test_b1_detects_serialized_json_error():
    engine = MockEngine()
    set_phase0(
        engine,
        tools=[
            _tool(
                "search",
                _schema(required=["q"], q=_field(description="query")),
                description="SQL search",
            )
        ],
    )

    async def _call(name: str, arguments: dict[str, Any] | None = None):
        args = arguments or {}
        if "'" == args.get("q", ""):
            return {
                "isError": True,
                "content": [
                    {
                        "type": "text",
                        "text": '{"error": "SQLSTATE 42601: syntax error"}',
                    }
                ],
            }
        if "OR (1=1)" in str(args.get("q", "")):
            return {"isError": False, "content": [{"type": "text", "text": "a"}, {"type": "text", "text": "b"}]}
        if "OR (1=2)" in str(args.get("q", "")):
            return {"isError": False, "content": []}
        return {"isError": False, "content": [{"type": "text", "text": "ok"}]}

    engine.call_tool = _call  # type: ignore[assignment]
    findings = await _run_b1(engine)

    assert len(findings) == 1


# ── Oracle tests ──


@pytest.mark.asyncio
async def test_b1_parser_evidence_produces_suspected_without_confirmation():
    engine = MockEngine()
    set_phase0(
        engine,
        tools=[
            _tool(
                "search",
                _schema(required=["q"], q=_field(description="query")),
                description="SQL search",
            )
        ],
    )

    async def _call(name: str, arguments: dict[str, Any] | None = None):
        args = arguments or {}
        if args.get("q", "") in ("'", '"'):
            return {"isError": True, "content": [{"type": "text", "text": "SQL syntax error"}]}
        if "OR (1=1)" in str(args.get("q", "")) or "OR (1=2)" in str(args.get("q", "")):
            return {"isError": True, "content": [{"type": "text", "text": "SQL syntax error"}]}
        return {"isError": False, "content": [{"type": "text", "text": "ok"}]}

    engine.call_tool = _call  # type: ignore[assignment]
    findings = await _run_b1(engine)

    assert len(findings) == 1
    assert _attack_evidence(findings).response["verdict"] == "suspected_injection"


@pytest.mark.asyncio
async def test_b1_reflected_only_differential_is_rejected():
    engine = MockEngine()
    set_phase0(
        engine,
        tools=[
            _tool(
                "search",
                _schema(required=["q"], q=_field(description="query")),
                description="SQL search",
            )
        ],
    )

    async def _call(name: str, arguments: dict[str, Any] | None = None):
        args = arguments or {}
        q = str(args.get("q", ""))
        # Echo payload but vary length artificially to simulate false differential.
        if "OR (1=1)" in q:
            return {"isError": False, "content": [{"type": "text", "text": q + " extra"}]}
        if "OR (1=2)" in q:
            return {"isError": False, "content": [{"type": "text", "text": q}]}
        return {"isError": False, "content": [{"type": "text", "text": "ok"}]}

    engine.call_tool = _call  # type: ignore[assignment]
    findings = await _run_b1(engine)

    assert findings == []


# ── Trace / evidence tests ──


@pytest.mark.asyncio
async def test_b1_correlates_exact_trace_entry():
    engine = MockEngine()
    set_phase0(
        engine,
        tools=[
            _tool(
                "exec",
                _schema(required=["args"], args=_field(default="echo test")),
                description="execute a system process",
            )
        ],
    )

    trace_id = "trace-b1-123"

    async def _call(name: str, arguments: dict[str, Any] | None = None):
        args = arguments or {}
        engine.traces.append(
            TraceEntry(
                session_id="s1",
                method="tools/call",
                request={"name": name, "arguments": args},
                response={"ok": True},
                id=trace_id,
            )
        )
        val = args.get("args", "")
        marker_match = _extract_nonce_and_marker(str(val))
        if marker_match and val != marker_match[1]:
            return {"isError": False, "content": [{"type": "text", "text": marker_match[1]}]}
        return {"isError": False, "content": [{"type": "text", "text": "ok"}]}

    engine.call_tool = _call  # type: ignore[assignment]
    findings = await _run_b1(engine)

    assert len(findings) == 1
    assert _attack_evidence(findings).trace_entry_id == trace_id


@pytest.mark.asyncio
async def test_b1_evidence_contains_parameter_path_and_payload_id():
    engine = MockEngine()
    set_phase0(
        engine,
        tools=[
            _tool(
                "exec",
                _schema(required=["args"], args=_field(default="echo test")),
                description="execute a system process",
            )
        ],
    )

    async def _call(name: str, arguments: dict[str, Any] | None = None):
        args = arguments or {}
        val = args.get("args", "")
        marker_match = _extract_nonce_and_marker(str(val))
        if marker_match and val != marker_match[1]:
            return {"isError": False, "content": [{"type": "text", "text": marker_match[1]}]}
        return {"isError": False, "content": [{"type": "text", "text": "ok"}]}

    engine.call_tool = _call  # type: ignore[assignment]
    findings = await _run_b1(engine)

    ev = _attack_evidence(findings)
    assert ev.request["parameter"] == "args"
    assert "payload_id" in ev.request
    assert "family" in ev.request
    assert "oracle_type" in ev.request
    assert "rationale" in ev.response


@pytest.mark.asyncio
async def test_b1_redacts_credentials_in_evidence():
    engine = MockEngine()
    set_phase0(
        engine,
        tools=[
            _tool(
                "exec",
                _schema(required=["args"], args=_field(default="echo test")),
                description="execute a system process",
            )
        ],
    )

    async def _call(name: str, arguments: dict[str, Any] | None = None):
        args = arguments or {}
        val = args.get("args", "")
        marker_match = _extract_nonce_and_marker(str(val))
        if marker_match and val != marker_match[1]:
            return {
                "isError": False,
                "content": [
                    {
                        "type": "text",
                        "text": f"{marker_match[1]}; password=supersecret",
                    }
                ],
            }
        return {"isError": False, "content": [{"type": "text", "text": "ok"}]}

    engine.call_tool = _call  # type: ignore[assignment]
    findings = await _run_b1(engine)

    excerpt = _attack_evidence(findings).response["excerpt"]
    assert "supersecret" not in excerpt
    assert "[REDACTED]" in excerpt


# ── Limit / state tests ──


@pytest.mark.asyncio
async def test_b1_enforces_max_total_probes():
    engine = MockEngine()
    set_phase0(
        engine,
        tools=[
            _tool(
                "search",
                _schema(required=["q"], q=_field(description="query")),
                description="SQL search",
            )
        ],
    )

    calls: list[dict[str, Any]] = []

    async def _call(name: str, arguments: dict[str, Any] | None = None):
        calls.append(arguments or {})
        return {"isError": False, "content": [{"type": "text", "text": "ok"}]}

    engine.call_tool = _call  # type: ignore[assignment]
    await B1ParameterInjection(engine, max_total_probes=3).run()

    # Baseline is not counted toward max_total_probes; at most 3 attack probes.
    attack_calls = [c for c in calls if c.get("q") != "test"]
    assert len(attack_calls) <= 3
    assert len(calls) >= 1


@pytest.mark.asyncio
async def test_b1_deterministic_ordering():
    engine = MockEngine()
    tools = [
        _tool("z", _schema(required=["q"], q=_field(description="query")), "SQL search"),
        _tool("a", _schema(required=["q"], q=_field(description="query")), "SQL search"),
        _tool("m", _schema(required=["q"], q=_field(description="query")), "SQL search"),
    ]
    set_phase0(engine, tools=tools)

    calls: list[str] = []

    async def _call(name: str, arguments: dict[str, Any] | None = None):
        calls.append(name)
        return {"isError": False, "content": [{"type": "text", "text": "ok"}]}

    engine.call_tool = _call  # type: ignore[assignment]
    await B1ParameterInjection(engine).run()
    first = list(calls)

    calls.clear()
    await B1ParameterInjection(engine).run()
    second = list(calls)

    assert first == second
    assert sorted(set(first)) == ["a", "m", "z"]


@pytest.mark.asyncio
async def test_b1_resets_state_between_runs():
    engine = MockEngine()
    set_phase0(
        engine,
        tools=[
            _tool(
                "exec",
                _schema(required=["args"], args=_field(default="echo test")),
                description="execute a system process",
            )
        ],
    )

    async def _call(name: str, arguments: dict[str, Any] | None = None):
        args = arguments or {}
        val = args.get("args", "")
        marker_match = _extract_nonce_and_marker(str(val))
        if marker_match and val != marker_match[1]:
            return {"isError": False, "content": [{"type": "text", "text": marker_match[1]}]}
        return {"isError": False, "content": [{"type": "text", "text": "ok"}]}

    engine.call_tool = _call  # type: ignore[assignment]

    mod = B1ParameterInjection(engine)
    f1 = await mod.run()
    f2 = await mod.run()

    assert len(f1) == len(f2) == 1
    assert f1[0].id == f2[0].id == "B1-001"


@pytest.mark.asyncio
async def test_b1_aggregates_multiple_probes_into_one_finding():
    engine = MockEngine()
    set_phase0(
        engine,
        tools=[
            _tool(
                "exec",
                _schema(required=["args"], args=_field(default="echo test")),
                description="execute a system process",
            )
        ],
    )

    async def _call(name: str, arguments: dict[str, Any] | None = None):
        args = arguments or {}
        val = args.get("args", "")
        marker_match = _extract_nonce_and_marker(str(val))
        if marker_match and val != marker_match[1]:
            return {"isError": False, "content": [{"type": "text", "text": marker_match[1]}]}
        return {"isError": False, "content": [{"type": "text", "text": "ok"}]}

    engine.call_tool = _call  # type: ignore[assignment]
    findings = await _run_b1(engine)

    assert len(findings) == 1
    assert findings[0].id == "B1-001"


# ── Adaptive escalation tests ──


@pytest.mark.asyncio
async def test_b1_parser_evidence_triggers_boolean_confirmation():
    engine = MockEngine()
    set_phase0(
        engine,
        tools=[
            _tool(
                "search",
                _schema(required=["q"], q=_field(description="query")),
                description="SQL search",
            )
        ],
    )

    async def _call(name: str, arguments: dict[str, Any] | None = None):
        args = arguments or {}
        q = args.get("q", "")
        if q == "'":
            return {"isError": True, "content": [{"type": "text", "text": "SQL syntax error"}]}
        if "OR (1=1)" in str(q):
            return {"isError": False, "content": [{"type": "text", "text": "a"}, {"type": "text", "text": "b"}]}
        if "OR (1=2)" in str(q):
            return {"isError": False, "content": []}
        return {"isError": False, "content": [{"type": "text", "text": "ok"}]}

    engine.call_tool = _call  # type: ignore[assignment]
    findings = await _run_b1(engine)

    assert len(findings) == 1
    assert _attack_evidence(findings).response["verdict"] == "confirmed_injection"


@pytest.mark.asyncio
async def test_b1_stops_after_confirmed_injection():
    engine = MockEngine()
    set_phase0(
        engine,
        tools=[
            _tool(
                "exec",
                _schema(required=["args"], args=_field(default="echo test")),
                description="execute a system process",
            )
        ],
    )

    call_count = 0

    async def _call(name: str, arguments: dict[str, Any] | None = None):
        nonlocal call_count
        call_count += 1
        args = arguments or {}
        val = args.get("args", "")
        marker_match = _extract_nonce_and_marker(str(val))
        if marker_match and val != marker_match[1]:
            return {"isError": False, "content": [{"type": "text", "text": marker_match[1]}]}
        return {"isError": False, "content": [{"type": "text", "text": "ok"}]}

    engine.call_tool = _call  # type: ignore[assignment]
    findings = await _run_b1(engine)

    assert len(findings) == 1
    # Baseline + at least one attack. Should stop sending further probes for
    # the same family once confirmed, so call count stays bounded.
    assert call_count <= 4


# ── Windows / platform tests ──


@pytest.mark.asyncio
async def test_b1_windows_command_probe():
    engine = MockEngine()
    set_phase0(
        engine,
        tools=[
            _tool(
                "exec",
                _schema(required=["args"], args=_field(default="echo test")),
                description="execute a windows command",
            )
        ],
    )

    async def _call(name: str, arguments: dict[str, Any] | None = None):
        args = arguments or {}
        val = args.get("args", "")
        marker_match = _extract_nonce_and_marker(str(val))
        if marker_match and "powershell" in val and val != marker_match[1]:
            return {"isError": False, "content": [{"type": "text", "text": marker_match[1]}]}
        return {"isError": False, "content": [{"type": "text", "text": "ok"}]}

    engine.call_tool = _call  # type: ignore[assignment]
    findings = await _run_b1(engine)

    assert len(findings) == 1


# ── Fallback discovery test ──


@pytest.mark.asyncio
async def test_b1_falls_back_to_list_tools_when_phase0_empty():
    engine = MockEngine()
    engine._tools = [
        _tool(
            "search",
            _schema(required=["q"], q=_field(description="query")),
            description="SQL search",
        )
    ]
    set_phase0(engine, tools=[])

    calls: list[dict[str, Any]] = []

    async def _call(name: str, arguments: dict[str, Any] | None = None):
        calls.append(arguments or {})
        return {"isError": False, "content": [{"type": "text", "text": "ok"}]}

    engine.call_tool = _call  # type: ignore[assignment]
    findings = await _run_b1(engine)

    assert len(calls) >= 1
    assert findings == []
