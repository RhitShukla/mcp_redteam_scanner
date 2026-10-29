from __future__ import annotations

import asyncio
import multiprocessing
import socket
import time
from contextlib import contextmanager
from typing import Any, Generator

import pytest
import uvicorn
from mcp.server.mcpserver import MCPServer

from src.attacks.a3_auth_wall_break import (
    A3AuthWallBreak,
    VERDICT_CONFIRMED_BYPASS,
    VERDICT_DENIED,
    VERDICT_INCONCLUSIVE,
    VERDICT_NOT_RUN,
    VERDICT_NOT_TESTABLE,
    VERDICT_SUSPECTED_BYPASS,
)
from src.models import AuthMethod, Severity, TargetConfig, TransportType
from src.probe_engine import ProbeEngine
from tests.attack_test_utils import MockEngine, set_phase0


# ── Vulnerable MCP server for E2E tests ──


def run_e2_auth_server(host: str, port: int, mode: str) -> None:
    """
    Dedicated MCP server for E2 authorization-boundary tests.

    Modes:
      - vulnerable:        admin_read_probe returns the protected marker without auth.
      - secure:            admin_read_probe returns an authorization-denial message.
      - admin_allowed:     admin_read_probe returns marker (models admin-authorized).
      - reflect:           admin_console reflects input.
      - generic_success:   admin_read_probe returns a generic success string.
      - status:            admin_status returns ordinary status.
      - unsafe_schema:     exposes a tool with dangerous required parameters.
    """
    mcp = MCPServer("e2-auth-target")
    mode = str(mode)

    @mcp.tool()
    def admin_read_probe(scope: str = "audit") -> str:
        """Read protected audit data. Requires administrator authorization."""
        if mode == "vulnerable":
            return "E2_PROTECTED_CAPABILITY_MARKER"
        if mode == "secure":
            return "Error: authorization required - admin access denied"
        if mode == "admin_allowed":
            return "E2_PROTECTED_CAPABILITY_MARKER"
        if mode == "generic_success":
            return "OK"
        return "OK"

    @mcp.tool()
    def admin_console(command: str) -> str:
        """Administrative console for server management."""
        if mode == "reflect":
            return f"Admin executed: {command}"
        return f"Admin executed: {command}"

    @mcp.tool()
    def admin_status() -> str:
        """Public server status endpoint."""
        return "status: healthy"

    @mcp.tool()
    def unsafe_admin_run(command: str, path: str) -> str:
        """Run an administrative command. Requires dangerous inputs."""
        return "ran"

    app = mcp.sse_app(host=host)
    uvicorn.run(app, host=host, port=port, log_level="error")


def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


@contextmanager
def _server(mode: str) -> Generator[str, None, None]:
    """Yield the SSE endpoint URL for a freshly started E2 test server."""
    port = _find_free_port()
    proc = multiprocessing.Process(
        target=run_e2_auth_server,
        args=("127.0.0.1", port, mode),
        daemon=True,
    )
    proc.start()
    try:
        time.sleep(2)
        yield f"http://127.0.0.1:{port}/sse"
    finally:
        proc.terminate()
        proc.join(timeout=5)
        if proc.is_alive():
            proc.kill()
            proc.join(timeout=2)


async def _run_e2(config: TargetConfig) -> list[Any]:
    engine = ProbeEngine(config)
    async with engine.connect():
        return await A3AuthWallBreak(engine).run()


# ── Positive E2E ──


def test_e2_confirmed_bypass_anonymous():
    """Anonymous caller executes a protected capability -> confirmed bypass."""
    with _server("vulnerable") as endpoint:
        config = TargetConfig(
            endpoint_url=endpoint,
            transport=TransportType.SSE,
            auth_method=AuthMethod.NONE,
        )
        findings = asyncio.run(_run_e2(config))

    assert len(findings) == 1
    finding = findings[0]
    assert finding.id.startswith("E2-")
    assert finding.severity == Severity.HIGH
    assert "authorization bypass" in finding.title.lower()

    ev = finding.evidence[0]
    assert ev.response["verdict"] == VERDICT_CONFIRMED_BYPASS
    assert ev.response["protected_capability_marker"] == "E2_PROTECTED_CAPABILITY_MARKER"
    assert ev.trace_entry_id is not None
    assert ev.request["auth_method"] == "none"
    assert ev.request["effective_context"] == "unauthenticated"
    assert ev.request["token_present"] is False


# ── Negative E2E against real MCP server ──


def test_e2_anonymous_denial_no_finding():
    """Anonymous caller is explicitly denied -> no finding."""
    with _server("secure") as endpoint:
        config = TargetConfig(
            endpoint_url=endpoint,
            transport=TransportType.SSE,
            auth_method=AuthMethod.NONE,
        )
        findings = asyncio.run(_run_e2(config))

    assert findings == []


def test_e2_authenticated_unknown_no_finding():
    """Authenticated session with unknown role succeeds -> no finding."""
    with _server("admin_allowed") as endpoint:
        config = TargetConfig(
            endpoint_url=endpoint,
            transport=TransportType.SSE,
            auth_method=AuthMethod.BEARER_TOKEN,
            auth_token="admin-token-123",
        )
        findings = asyncio.run(_run_e2(config))

    assert findings == []


# ── Unit / regression tests with MockEngine ──


def _make_engine(auth_method: AuthMethod = AuthMethod.NONE, token: str | None = None) -> MockEngine:
    engine = MockEngine(auth_method=auth_method)
    if token is not None:
        engine.config.auth_token = token
    return engine


@pytest.mark.asyncio
async def test_e2_reflection_only_admin_console_is_inconclusive():
    """admin_console that merely reflects input does not confirm a bypass."""
    engine = _make_engine(AuthMethod.NONE)
    set_phase0(
        engine,
        tools=[
            {
                "name": "admin_console",
                "description": "Administrative console",
                "inputSchema": {
                    "type": "object",
                    "properties": {"command": {"type": "string"}},
                    "required": ["command"],
                },
            }
        ],
    )

    async def _call(name: str, arguments: dict[str, Any] | None = None):
        args = arguments or {}
        return {"isError": False, "content": [{"type": "text", "text": f"Admin executed: {args.get('command')}"}]}

    engine.call_tool = _call  # type: ignore[assignment]
    findings = await A3AuthWallBreak(engine).run()
    assert findings == []


@pytest.mark.asyncio
async def test_e2_replay_success_without_oracle_is_inconclusive():
    """Replay success without protected-capability proof is not a bypass."""
    engine = _make_engine(AuthMethod.NONE)
    set_phase0(
        engine,
        tools=[
            {
                "name": "admin_read_probe",
                "description": "Read protected audit data",
                "inputSchema": {
                    "type": "object",
                    "properties": {"scope": {"type": "string", "default": "audit"}},
                    "required": ["scope"],
                },
            }
        ],
    )

    async def _call(name: str, arguments: dict[str, Any] | None = None):
        return {"isError": False, "content": [{"type": "text", "text": "OK"}]}

    engine.call_tool = _call  # type: ignore[assignment]
    findings = await A3AuthWallBreak(engine).run()
    assert findings == []


@pytest.mark.asyncio
async def test_e2_ordinary_public_status_is_inconclusive():
    """A privileged-looking tool that returns ordinary public status is not a bypass."""
    engine = _make_engine(AuthMethod.NONE)
    set_phase0(
        engine,
        tools=[
            {
                "name": "admin_status",
                "description": "Public server status",
                "inputSchema": {"type": "object", "properties": {}},
            }
        ],
    )

    async def _call(name: str, arguments: dict[str, Any] | None = None):
        return {"isError": False, "content": [{"type": "text", "text": "status: healthy"}]}

    engine.call_tool = _call  # type: ignore[assignment]
    findings = await A3AuthWallBreak(engine).run()
    assert findings == []


@pytest.mark.asyncio
async def test_e2_authenticated_unknown_token_no_finding():
    """A token with unknown role accessing a protected marker is not reported."""
    engine = _make_engine(AuthMethod.BEARER_TOKEN, token="unknown-role-token")
    set_phase0(
        engine,
        tools=[
            {
                "name": "admin_read_probe",
                "description": "Read protected audit data",
                "inputSchema": {
                    "type": "object",
                    "properties": {"scope": {"type": "string", "default": "audit"}},
                    "required": ["scope"],
                },
            }
        ],
    )

    async def _call(name: str, arguments: dict[str, Any] | None = None):
        return {"isError": False, "content": [{"type": "text", "text": "E2_PROTECTED_CAPABILITY_MARKER"}]}

    engine.call_tool = _call  # type: ignore[assignment]
    findings = await A3AuthWallBreak(engine).run()
    assert findings == []


@pytest.mark.asyncio
async def test_e2_unsafe_required_schema_is_not_testable():
    """A privileged tool with dangerous required parameters and no safe values is skipped."""
    engine = _make_engine(AuthMethod.NONE)
    set_phase0(
        engine,
        tools=[
            {
                "name": "unsafe_admin_run",
                "description": "Run admin command",
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

    calls: list[dict[str, Any]] = []

    async def _call(name: str, arguments: dict[str, Any] | None = None):
        calls.append(arguments or {})
        return {"isError": False, "content": [{"type": "text", "text": "ran"}]}

    engine.call_tool = _call  # type: ignore[assignment]
    findings = await A3AuthWallBreak(engine).run()

    assert findings == []
    assert calls == []


@pytest.mark.asyncio
async def test_e2_no_tools_is_not_run():
    """No tools available -> module reports not_run state and no findings."""
    engine = _make_engine(AuthMethod.NONE)
    set_phase0(engine, tools=[])
    findings = await A3AuthWallBreak(engine).run()
    assert findings == []


@pytest.mark.asyncio
async def test_e2_auth_configured_no_token_treated_as_unauthenticated():
    """Bearer configured but no token is effectively unauthenticated."""
    engine = _make_engine(AuthMethod.BEARER_TOKEN, token=None)
    set_phase0(
        engine,
        tools=[
            {
                "name": "admin_read_probe",
                "description": "Read protected audit data",
                "inputSchema": {
                    "type": "object",
                    "properties": {"scope": {"type": "string", "default": "audit"}},
                    "required": ["scope"],
                },
            }
        ],
    )

    async def _call(name: str, arguments: dict[str, Any] | None = None):
        return {"isError": False, "content": [{"type": "text", "text": "E2_PROTECTED_CAPABILITY_MARKER"}]}

    engine.call_tool = _call  # type: ignore[assignment]
    findings = await A3AuthWallBreak(engine).run()

    assert len(findings) == 1
    assert findings[0].evidence[0].request["effective_context"] == "auth_configured_no_token"


@pytest.mark.asyncio
async def test_e2_suspected_bypass_from_capability_signal():
    """Unauthenticated success with privileged content signal yields suspected bypass."""
    engine = _make_engine(AuthMethod.NONE)
    set_phase0(
        engine,
        tools=[
            {
                "name": "admin_read_probe",
                "description": "Read protected audit data",
                "inputSchema": {
                    "type": "object",
                    "properties": {"scope": {"type": "string", "default": "audit"}},
                    "required": ["scope"],
                },
            }
        ],
    )

    async def _call(name: str, arguments: dict[str, Any] | None = None):
        # Contains a privileged signal but not the deterministic protected marker.
        return {"isError": False, "content": [{"type": "text", "text": "secret=config-value"}]}

    engine.call_tool = _call  # type: ignore[assignment]
    findings = await A3AuthWallBreak(engine).run()

    assert len(findings) == 1
    ev = findings[0].evidence[0]
    assert ev.response["verdict"] == VERDICT_SUSPECTED_BYPASS
    assert findings[0].severity == Severity.MEDIUM


@pytest.mark.asyncio
async def test_e2_uses_input_schema_alias():
    """Schema discovery supports the input_schema alias used by some servers."""
    engine = _make_engine(AuthMethod.NONE)
    set_phase0(
        engine,
        tools=[
            {
                "name": "admin_read_probe",
                "description": "Read protected audit data",
                "input_schema": {
                    "type": "object",
                    "properties": {"scope": {"type": "string", "default": "audit"}},
                    "required": ["scope"],
                },
            }
        ],
    )

    async def _call(name: str, arguments: dict[str, Any] | None = None):
        return {"isError": False, "content": [{"type": "text", "text": "E2_PROTECTED_CAPABILITY_MARKER"}]}

    engine.call_tool = _call  # type: ignore[assignment]
    findings = await A3AuthWallBreak(engine).run()

    assert len(findings) == 1
    assert findings[0].evidence[0].response["verdict"] == VERDICT_CONFIRMED_BYPASS


@pytest.mark.asyncio
async def test_e2_respects_candidate_and_call_limits():
    """Module bounds the number of candidates and calls it makes."""
    engine = _make_engine(AuthMethod.NONE)
    tools = [
        {
            "name": f"admin_tool_{i}",
            "description": "Administrative tool",
            "inputSchema": {
                "type": "object",
                "properties": {"scope": {"type": "string", "default": "audit"}},
                "required": ["scope"],
            },
        }
        for i in range(10)
    ]
    set_phase0(engine, tools=tools)

    call_count = 0

    async def _call(name: str, arguments: dict[str, Any] | None = None):
        nonlocal call_count
        call_count += 1
        return {"isError": False, "content": [{"type": "text", "text": "OK"}]}

    engine.call_tool = _call  # type: ignore[assignment]
    await A3AuthWallBreak(engine, max_candidates=3, max_calls_per_candidate=2, max_total_calls=4).run()

    assert call_count <= 4


@pytest.mark.asyncio
async def test_e2_does_not_expose_credentials_in_evidence():
    """Evidence must never contain the configured authentication token."""
    engine = _make_engine(AuthMethod.NONE)
    # A token may be present in config even when the active session is unauthenticated.
    engine.config.auth_token = "super-secret-token"
    set_phase0(
        engine,
        tools=[
            {
                "name": "admin_read_probe",
                "description": "Read protected audit data",
                "inputSchema": {
                    "type": "object",
                    "properties": {"scope": {"type": "string", "default": "audit"}},
                    "required": ["scope"],
                },
            }
        ],
    )

    async def _call(name: str, arguments: dict[str, Any] | None = None):
        return {"isError": False, "content": [{"type": "text", "text": "E2_PROTECTED_CAPABILITY_MARKER"}]}

    engine.call_tool = _call  # type: ignore[assignment]
    findings = await A3AuthWallBreak(engine).run()

    assert len(findings) == 1
    raw = findings[0].model_dump_json()
    assert "super-secret-token" not in raw
    # Evidence should only indicate token presence in the configured context.
    assert findings[0].evidence[0].request["token_present"] is False
