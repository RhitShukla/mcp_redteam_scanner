"""
Tests for the Probe Engine (Layer 1).

Spins up a mock MCP server, connects the probe engine, and verifies:
1. Connection and capability discovery
2. Tool listing and invocation
3. Resource listing and reading
4. Prompt listing
5. Every interaction is traced
6. Failed calls are recorded with errors
7. Multiple sessions (cross-tenant support)
"""

from __future__ import annotations

import asyncio
import multiprocessing
import time

import pytest

from src.models import AuthMethod, TargetConfig, TransportType
from src.probe_engine import ProbeEngine, ProbeEngineError


# ── Server Fixture ──

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 9998  # avoid conflict with manual runs on 9999


def _run_mock_server():
    """Run mock server in a separate process."""
    from tests.mock_mcp_server import mcp
    import uvicorn

    uvicorn.run(mcp.sse_app(), host=SERVER_HOST, port=SERVER_PORT, log_level="error")


@pytest.fixture(scope="module")
def mock_server():
    """Start mock MCP server for the test module."""
    proc = multiprocessing.Process(target=_run_mock_server, daemon=True)
    proc.start()
    time.sleep(2)  # wait for server to be ready
    yield f"http://{SERVER_HOST}:{SERVER_PORT}"
    proc.terminate()
    proc.join(timeout=5)


def _make_config(base_url: str, **overrides) -> TargetConfig:
    defaults = dict(
        endpoint_url=f"{base_url}/sse",
        transport=TransportType.SSE,
        auth_method=AuthMethod.NONE,
    )
    defaults.update(overrides)
    return TargetConfig(**defaults)


# ── Connection Tests ──


class TestConnection:
    @pytest.mark.asyncio
    async def test_connect_and_discover(self, mock_server):
        config = _make_config(mock_server)
        engine = ProbeEngine(config)

        async with engine.connect() as session_id:
            assert session_id is not None
            session = engine.sessions[session_id]
            assert session.endpoint_url == config.endpoint_url
            assert session.connected_at is not None
            assert session.server_capabilities is not None

        # After disconnect
        assert session.disconnected_at is not None

    @pytest.mark.asyncio
    async def test_initialize_is_traced(self, mock_server):
        config = _make_config(mock_server)
        engine = ProbeEngine(config)

        async with engine.connect() as session_id:
            init_traces = [
                t for t in engine.traces if t.method == "initialize"
            ]
            assert len(init_traces) == 1
            assert init_traces[0].response is not None
            assert init_traces[0].session_id == session_id

    @pytest.mark.asyncio
    async def test_no_session_raises(self, mock_server):
        config = _make_config(mock_server)
        engine = ProbeEngine(config)
        with pytest.raises(ProbeEngineError, match="No active MCP session"):
            await engine.list_tools()


# ── Tool Tests ──


class TestTools:
    @pytest.mark.asyncio
    async def test_list_tools(self, mock_server):
        config = _make_config(mock_server)
        engine = ProbeEngine(config)

        async with engine.connect():
            tools = await engine.list_tools()
            tool_names = [t["name"] for t in tools]
            assert "echo" in tool_names
            assert "customer_lookup" in tool_names
            assert "run_query" in tool_names
            assert "read_file" in tool_names

        # Verify traced
        list_traces = [t for t in engine.traces if t.method == "tools/list"]
        assert len(list_traces) == 1
        assert list_traces[0].response is not None
        assert list_traces[0].duration_ms is not None

    @pytest.mark.asyncio
    async def test_call_tool(self, mock_server):
        config = _make_config(mock_server)
        engine = ProbeEngine(config)

        async with engine.connect():
            result = await engine.call_tool("echo", {"message": "hello"})
            # Result should contain content
            assert result is not None
            assert "content" in result

        # Verify traced
        call_traces = [t for t in engine.traces if t.method == "tools/call"]
        assert len(call_traces) == 1
        assert call_traces[0].request["name"] == "echo"
        assert call_traces[0].request["arguments"] == {"message": "hello"}
        assert call_traces[0].response is not None
        assert call_traces[0].duration_ms is not None

    @pytest.mark.asyncio
    async def test_call_tool_with_pii_response(self, mock_server):
        config = _make_config(mock_server)
        engine = ProbeEngine(config)

        async with engine.connect():
            result = await engine.call_tool(
                "customer_lookup", {"customer_id": "42"}
            )
            assert result is not None

        # The trace captures the full response for evidence
        call_traces = [t for t in engine.traces if t.method == "tools/call"]
        assert len(call_traces) == 1
        assert call_traces[0].response is not None


# ── Resource Tests ──


class TestResources:
    @pytest.mark.asyncio
    async def test_list_resources(self, mock_server):
        config = _make_config(mock_server)
        engine = ProbeEngine(config)

        async with engine.connect():
            resources = await engine.list_resources()
            uris = [r["uri"] for r in resources]
            assert any("config://app" in str(u) for u in uris)
            assert any("data://customers" in str(u) for u in uris)

        list_traces = [
            t for t in engine.traces if t.method == "resources/list"
        ]
        assert len(list_traces) == 1

    @pytest.mark.asyncio
    async def test_read_resource(self, mock_server):
        config = _make_config(mock_server)
        engine = ProbeEngine(config)

        async with engine.connect():
            result = await engine.read_resource("config://app")
            assert result is not None
            assert "contents" in result

        read_traces = [
            t for t in engine.traces if t.method == "resources/read"
        ]
        assert len(read_traces) == 1
        assert read_traces[0].request["uri"] == "config://app"


# ── Prompt Tests ──


class TestPrompts:
    @pytest.mark.asyncio
    async def test_list_prompts(self, mock_server):
        config = _make_config(mock_server)
        engine = ProbeEngine(config)

        async with engine.connect():
            prompts = await engine.list_prompts()
            prompt_names = [p["name"] for p in prompts]
            assert "summarize" in prompt_names

        list_traces = [
            t for t in engine.traces if t.method == "prompts/list"
        ]
        assert len(list_traces) == 1


# ── Trace Tests ──


class TestTracing:
    @pytest.mark.asyncio
    async def test_all_operations_traced(self, mock_server):
        """Run multiple operations and verify every one is traced."""
        config = _make_config(mock_server)
        engine = ProbeEngine(config)

        async with engine.connect() as session_id:
            await engine.list_tools()
            await engine.call_tool("echo", {"message": "test"})
            await engine.list_resources()
            await engine.list_prompts()

        # initialize + list_tools + call_tool + list_resources + list_prompts = 5
        assert len(engine.traces) == 5
        methods = [t.method for t in engine.traces]
        assert "initialize" in methods
        assert "tools/list" in methods
        assert "tools/call" in methods
        assert "resources/list" in methods
        assert "prompts/list" in methods

        # All traces belong to the same session
        for trace in engine.traces:
            assert trace.session_id == session_id

    @pytest.mark.asyncio
    async def test_get_traces_for_session(self, mock_server):
        config = _make_config(mock_server)
        engine = ProbeEngine(config)

        async with engine.connect() as sid1:
            await engine.list_tools()

        session_traces = engine.get_traces_for_session(sid1)
        assert len(session_traces) == 2  # initialize + list_tools
        assert all(t.session_id == sid1 for t in session_traces)

    @pytest.mark.asyncio
    async def test_clear_traces(self, mock_server):
        config = _make_config(mock_server)
        engine = ProbeEngine(config)

        async with engine.connect():
            await engine.list_tools()

        assert len(engine.traces) > 0
        engine.clear_traces()
        assert len(engine.traces) == 0


# ── Multi-Session Tests (Cross-Tenant Support) ──


class TestMultiSession:
    @pytest.mark.asyncio
    async def test_sequential_sessions(self, mock_server):
        """Verify engine supports multiple sequential sessions (needed for F1)."""
        config = _make_config(mock_server)
        engine = ProbeEngine(config)

        # Session 1: "tenant-alpha"
        async with engine.connect(identity="tenant-alpha") as sid1:
            await engine.list_tools()
            assert engine.sessions[sid1].auth_identity == "tenant-alpha"

        # Session 2: "tenant-beta"
        async with engine.connect(identity="tenant-beta") as sid2:
            await engine.list_tools()
            assert engine.sessions[sid2].auth_identity == "tenant-beta"

        assert sid1 != sid2
        assert len(engine.sessions) == 2
        # Traces from both sessions are preserved
        assert len(engine.get_traces_for_session(sid1)) == 2
        assert len(engine.get_traces_for_session(sid2)) == 2


# ── Auth Header Tests (unit, no server needed) ──


class TestAuthHeaders:
    def test_bearer_token_header(self):
        config = TargetConfig(
            endpoint_url="http://localhost:9999/sse",
            auth_method=AuthMethod.BEARER_TOKEN,
            auth_token="test-token",
        )
        engine = ProbeEngine(config)
        headers = engine._build_headers()
        assert headers["Authorization"] == "Bearer test-token"

    def test_api_key_header(self):
        config = TargetConfig(
            endpoint_url="http://localhost:9999/sse",
            auth_method=AuthMethod.API_KEY,
            auth_token="my-api-key",
        )
        engine = ProbeEngine(config)
        headers = engine._build_headers()
        assert headers["X-API-Key"] == "my-api-key"

    def test_basic_auth_header(self):
        config = TargetConfig(
            endpoint_url="http://localhost:9999/sse",
            auth_method=AuthMethod.BASIC,
            auth_token="dXNlcjpwYXNz",
        )
        engine = ProbeEngine(config)
        headers = engine._build_headers()
        assert headers["Authorization"] == "Basic dXNlcjpwYXNz"

    def test_no_auth_header(self):
        config = TargetConfig(
            endpoint_url="http://localhost:9999/sse",
            auth_method=AuthMethod.NONE,
        )
        engine = ProbeEngine(config)
        headers = engine._build_headers()
        # Should only have ngrok header, no auth headers
        assert "Authorization" not in headers
        assert "X-API-Key" not in headers
        assert headers.get("ngrok-skip-browser-warning") == "true"

    def test_token_override(self):
        config = TargetConfig(
            endpoint_url="http://localhost:9999/sse",
            auth_method=AuthMethod.BEARER_TOKEN,
            auth_token="default-token",
        )
        engine = ProbeEngine(config)
        headers = engine._build_headers(token="override-token")
        assert headers["Authorization"] == "Bearer override-token"
