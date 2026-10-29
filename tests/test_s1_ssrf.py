from __future__ import annotations

import asyncio
import multiprocessing
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

import pytest

from src.attacks.s1_ssrf import (
    FixedOracleChecker,
    LocalhostOracleChecker,
    OracleObservation,
    SSRFPayload,
    SSRFPayloadProvider,
    S1SSRF,
    SSRF_VERDICT_CONFIRMED_BLIND,
    SSRF_VERDICT_CONFIRMED_REFLECTIVE,
    SSRF_VERDICT_INCONCLUSIVE,
    SSRF_VERDICT_NOT_RUN,
    SSRF_VERDICT_NOT_TESTABLE,
    build_default_payloads,
    find_url_candidates,
    get_tool_schema,
    is_mcp_error_response,
    response_contains_marker,
)
from src.models import AuthMethod, Severity, TargetConfig, TransportType
from src.probe_engine import ProbeEngine

SSRF_MARKER = "S1_SSRF_CONTROLLED_MARKER"


# ── Oracle Fixtures ──


class SSRFOracleHandler(BaseHTTPRequestHandler):
    """HTTP endpoint used to prove that a request was actually received."""

    requests_received: int = 0
    seen_payload_ids: set[str] = set()
    request_counts: dict[str, int] = {}

    @classmethod
    def reset(cls) -> None:
        cls.requests_received = 0
        cls.seen_payload_ids.clear()
        cls.request_counts.clear()

    def do_GET(self) -> None:
        SSRFOracleHandler.requests_received += 1

        path = self.path
        clean_path = path.split("?", 1)[0]
        path_parts = clean_path.strip("/").split("/")
        payload_id = path_parts[0] if path_parts and path_parts[0] else ""
        if payload_id:
            SSRFOracleHandler.seen_payload_ids.add(payload_id)
            SSRFOracleHandler.request_counts[payload_id] = (
                SSRFOracleHandler.request_counts.get(payload_id, 0) + 1
            )

        # Return a marker that includes the probe nonce so that a reflective
        # SSRF response can be confirmed independently from a simple echo.
        nonce = ""
        if "?" in path:
            query = path.split("?", 1)[1]
            for part in query.split("&"):
                if part.startswith("probe="):
                    nonce = part.split("=", 1)[1]
                    break
        marker = f"MCP_SSRF_MARKER-{nonce}" if nonce else SSRF_MARKER
        body = marker.encode()

        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        """Keep the test output quiet."""
        pass


def start_ssrf_oracle() -> tuple[HTTPServer, threading.Thread]:
    """Start the controlled SSRF oracle on localhost."""
    server = HTTPServer(("127.0.0.1", 0), SSRFOracleHandler)

    thread = threading.Thread(
        target=server.serve_forever,
        daemon=True,
    )
    thread.start()

    return server, thread


def reset_oracle() -> None:
    SSRFOracleHandler.reset()


def run_server_process(host: str, port: int) -> multiprocessing.Process:
    from tests.mock_mcp_server import run_server

    process = multiprocessing.Process(
        target=run_server,
        kwargs={"host": host, "port": port},
        daemon=True,
    )
    process.start()
    return process


def make_config(endpoint_url: str) -> TargetConfig:
    return TargetConfig(
        endpoint_url=endpoint_url,
        transport=TransportType.SSE,
        auth_method=AuthMethod.NONE,
    )


async def run_s1_with_oracle(
    endpoint_url: str,
    oracle_base_url: str,
) -> tuple[list[Any], S1SSRF]:
    """Connect, build payloads from the oracle, run S1, return findings + module."""
    payloads = build_default_payloads(oracle_base_url)

    engine = ProbeEngine(make_config(endpoint_url))
    async with engine.connect():
        checker = LocalhostOracleChecker(
            request_counts={
                p.payload_id: SSRFOracleHandler.requests_received
                for p in payloads
            }
        )
        module = S1SSRF(engine, payloads=payloads, oracle_checker=checker)
        findings = await module.run()
        return findings, module


# ── A. Positive reflective SSRF against mock server ──


def test_s1_ssrf_against_mock_server():
    """fetch_url reaches the oracle and returns the marker -> confirmed_reflective."""
    reset_oracle()
    oracle, thread = start_ssrf_oracle()
    oracle_host, oracle_port = oracle.server_address

    process = run_server_process("127.0.0.1", 9997)

    try:
        time.sleep(2)

        oracle_base_url = f"http://{oracle_host}:{oracle_port}"
        payloads = build_default_payloads(oracle_base_url)

        engine = ProbeEngine(make_config("http://127.0.0.1:9997/sse"))

        async def run_s1():
            async with engine.connect():
                # Read live request counts from the shared oracle handler.
                checker = LocalhostOracleChecker(
                    state_source=lambda: SSRFOracleHandler.request_counts
                )
                module = S1SSRF(
                    engine,
                    payloads=payloads,
                    oracle_checker=checker,
                )
                return await module.run()

        findings = asyncio.run(run_s1())

        # The oracle must have observed at least the fetch_url probe.
        assert SSRFOracleHandler.requests_received >= 1

        # fetch_url reflects the oracle body -> confirmed_reflective.
        fetch_url_findings = [
            f for f in findings
            if f.evidence[0].request.get("tool") == "fetch_url"
        ]
        assert len(fetch_url_findings) == 1
        fetch_finding = fetch_url_findings[0]
        assert fetch_finding.severity == Severity.HIGH
        assert "confirmed reflective" in fetch_finding.title.lower()

        # echo_url does not contact the oracle -> no confirmed finding.
        echo_confirmed = [
            f for f in findings
            if f.evidence[0].request.get("tool") == "echo_url"
            and "confirmed" in f.title.lower()
        ]
        assert echo_confirmed == []

    finally:
        process.terminate()
        process.join(timeout=5)
        oracle.shutdown()
        oracle.server_close()


# ── B. Blind-style positive SSRF ──


@pytest.mark.asyncio
async def test_s1_confirms_blind_ssrf():
    """Oracle sees the request but response has no marker -> confirmed_blind."""
    tool = {
        "name": "fetch_url_blind",
        "inputSchema": {
            "type": "object",
            "properties": {"url": {"type": "string"}},
            "required": ["url"],
        },
    }
    payload = SSRFPayload(
        payload_id="s1-blind",
        label="blind",
        url="http://127.0.0.1:1/probe",
        nonce="nonce-blind",
        marker="marker-blind",
        oracle_type="http",
    )

    class BlindResponseEngine:
        def __init__(self):
            self.config = type("Config", (), {"endpoint_url": "http://test/sse"})()
            self.shared_context: dict[str, Any] = {}
            self.traces = []

        async def list_tools(self):
            return [tool]

        async def call_tool(self, name: str, arguments: dict[str, Any] | None = None):
            self.traces.append(
                type(
                    "Trace",
                    (),
                    {
                        "id": "trace-blind",
                        "method": "tools/call",
                        "request": {"name": name, "arguments": arguments or {}},
                        "response": None,
                        "error": None,
                    },
                )
            )
            # Response does NOT contain the marker.
            return {
                "content": [{"type": "text", "text": "status: 200"}],
                "isError": False,
            }

    engine = BlindResponseEngine()
    checker = FixedOracleChecker(received=True)
    module = S1SSRF(engine, payloads=[payload], oracle_checker=checker)
    findings = await module.run()

    assert len(findings) == 1
    finding = findings[0]
    assert finding.title.startswith("SSRF in 'fetch_url_blind.url'")
    assert "confirmed blind" in finding.title.lower()


# ── C. Negative echo SSRF ──


@pytest.mark.asyncio
async def test_s1_rejects_simple_echo():
    """Tool echoes the supplied URL/marker; oracle never sees a request."""
    tool = {
        "name": "echo_url",
        "inputSchema": {
            "type": "object",
            "properties": {"url": {"type": "string"}},
            "required": ["url"],
        },
    }
    payload = SSRFPayload(
        payload_id="s1-echo",
        label="echo",
        url="http://127.0.0.1:1/probe?x=marker-echo-nonce",
        nonce="nonce-echo",
        marker="marker-echo",
        oracle_type="http",
    )

    class EchoEngine:
        def __init__(self):
            self.config = type("Config", (), {"endpoint_url": "http://test/sse"})()
            self.shared_context: dict[str, Any] = {}
            self.traces = []

        async def list_tools(self):
            return [tool]

        async def call_tool(self, name: str, arguments: dict[str, Any] | None = None):
            self.traces.append(
                type(
                    "Trace",
                    (),
                    {
                        "id": "trace-echo",
                        "method": "tools/call",
                        "request": {"name": name, "arguments": arguments or {}},
                        "response": None,
                        "error": None,
                    },
                )
            )
            url = (arguments or {}).get("url", "")
            return {
                "content": [{"type": "text", "text": f"echo_url: {url}"}],
                "isError": False,
            }

    engine = EchoEngine()
    checker = FixedOracleChecker(received=False)
    module = S1SSRF(engine, payloads=[payload], oracle_checker=checker)
    findings = await module.run()

    confirmed = [f for f in findings if "confirmed" in f.title.lower()]
    assert confirmed == []


# ── D. MCP error response produces no confirmed finding ──


@pytest.mark.asyncio
async def test_s1_errors_are_inconclusive_not_confirmed():
    """A tool error response should never produce a confirmed SSRF finding."""
    tool = {
        "name": "fetch_url",
        "inputSchema": {
            "type": "object",
            "properties": {"url": {"type": "string"}},
            "required": ["url"],
        },
    }
    payload = SSRFPayload(
        payload_id="s1-err",
        label="error",
        url="http://127.0.0.1:1/probe",
        nonce="nonce-err",
        marker="marker-err",
        oracle_type="http",
    )

    class ErrorEngine:
        def __init__(self):
            self.config = type("Config", (), {"endpoint_url": "http://test/sse"})()
            self.shared_context: dict[str, Any] = {}
            self.traces = []

        async def list_tools(self):
            return [tool]

        async def call_tool(self, name: str, arguments: dict[str, Any] | None = None):
            self.traces.append(
                type(
                    "Trace",
                    (),
                    {
                        "id": "trace-err",
                        "method": "tools/call",
                        "request": {"name": name, "arguments": arguments or {}},
                        "response": None,
                        "error": None,
                    },
                )
            )
            return {
                "content": [{"type": "text", "text": "marker-err"}],
                "isError": True,
            }

    engine = ErrorEngine()
    checker = FixedOracleChecker(received=True)
    module = S1SSRF(engine, payloads=[payload], oracle_checker=checker)
    findings = await module.run()

    confirmed = [f for f in findings if "confirmed" in f.title.lower()]
    assert confirmed == []


# ── E. execute_shell is skipped due to dangerous required siblings ──


@pytest.mark.asyncio
async def test_s1_skips_dangerous_siblings():
    """execute_shell has required command/path; S1 must not invent values."""
    tool = {
        "name": "execute_shell",
        "inputSchema": {
            "type": "object",
            "properties": {
                "command": {"type": "string"},
                "path": {"type": "string"},
                "url": {"type": "string"},
            },
            "required": ["command", "path", "url"],
        },
    }
    payload = SSRFPayload(
        payload_id="s1-shell",
        label="shell",
        url="http://127.0.0.1:1/probe",
        nonce="nonce-shell",
        marker="marker-shell",
        oracle_type="http",
    )

    class ShellEngine:
        def __init__(self):
            self.config = type("Config", (), {"endpoint_url": "http://test/sse"})()
            self.shared_context: dict[str, Any] = {"tools": [tool]}
            self.traces = []

        async def list_tools(self):
            return [tool]

        async def call_tool(self, name: str, arguments: dict[str, Any] | None = None):
            self.traces.append(
                type(
                    "Trace",
                    (),
                    {
                        "id": "trace-shell",
                        "method": "tools/call",
                        "request": {"name": name, "arguments": arguments or {}},
                        "response": None,
                        "error": None,
                    },
                )
            )
            return {"content": [{"type": "text", "text": "ok"}], "isError": False}

    engine = ShellEngine()
    checker = FixedOracleChecker(received=False)
    module = S1SSRF(engine, payloads=[payload], oracle_checker=checker)
    findings = await module.run()

    confirmed = [f for f in findings if "confirmed" in f.title.lower()]
    assert confirmed == []
    assert module.stats["skipped"] >= 1


# ── F. Schema compatibility: input_schema and inputSchema ──


def test_s1_accepts_both_schema_keys():
    """find_url_candidates and get_tool_schema handle both key variants."""
    tool_snake = {
        "name": "t1",
        "input_schema": {
            "type": "object",
            "properties": {"url": {"type": "string"}},
            "required": ["url"],
        },
    }
    tool_camel = {
        "name": "t2",
        "inputSchema": {
            "type": "object",
            "properties": {"target": {"type": "string", "format": "uri"}},
            "required": ["target"],
        },
    }

    assert get_tool_schema(tool_snake) == tool_snake["input_schema"]
    assert get_tool_schema(tool_camel) == tool_camel["inputSchema"]

    assert find_url_candidates(tool_snake) == [("url", {"type": "string"})]
    assert find_url_candidates(tool_camel) == [("target", {"type": "string", "format": "uri"})]


# ── G. Empty/no payload configuration ──


@pytest.mark.asyncio
async def test_s1_reports_not_run_without_payloads():
    """S1 without payloads must report not_run, not silently return empty."""
    engine = type(
        "Engine",
        (),
        {
            "config": type("Config", (), {"endpoint_url": "http://test/sse"})(),
            "shared_context": {},
            "traces": [],
        },
    )()
    module = S1SSRF(engine, payloads=[])
    findings = await module.run()

    assert len(findings) == 1
    assert findings[0].title == f"S1 SSRF scan status: {SSRF_VERDICT_NOT_RUN}"
    assert findings[0].severity == Severity.INFO


@pytest.mark.asyncio
async def test_s1_reports_not_run_without_oracle_checker():
    """S1 without oracle checker must report not_run."""
    engine = type(
        "Engine",
        (),
        {
            "config": type("Config", (), {"endpoint_url": "http://test/sse"})(),
            "shared_context": {},
            "traces": [],
        },
    )()
    payload = SSRFPayload(
        payload_id="s1-nochecker",
        label="x",
        url="http://127.0.0.1:1",
        nonce="n",
        marker="m",
        oracle_type="http",
    )
    module = S1SSRF(engine, payloads=[payload], oracle_checker=None)
    findings = await module.run()

    assert len(findings) == 1
    assert findings[0].title == f"S1 SSRF scan status: {SSRF_VERDICT_NOT_RUN}"


# ── H. Repeated run resets state correctly ──


@pytest.mark.asyncio
async def test_s1_rerun_resets_state():
    """Running the module twice yields identical finding IDs and counts."""
    tool = {
        "name": "fetch_url",
        "inputSchema": {
            "type": "object",
            "properties": {"url": {"type": "string"}},
            "required": ["url"],
        },
    }
    payload = SSRFPayload(
        payload_id="s1-reset",
        label="reset",
        url="http://127.0.0.1:1/probe",
        nonce="nonce-reset",
        marker="marker-reset",
        oracle_type="http",
    )

    class ResetEngine:
        def __init__(self):
            self.config = type("Config", (), {"endpoint_url": "http://test/sse"})()
            self.shared_context = {"tools": [tool]}
            self.traces = []
            self._calls = 0

        async def list_tools(self):
            return [tool]

        async def call_tool(self, name: str, arguments: dict[str, Any] | None = None):
            self._calls += 1
            self.traces.append(
                type(
                    "Trace",
                    (),
                    {
                        "id": f"trace-{self._calls}",
                        "method": "tools/call",
                        "request": {"name": name, "arguments": arguments or {}},
                        "response": None,
                        "error": None,
                    },
                )
            )
            return {
                "content": [{"type": "text", "text": "marker-reset nonce-reset"}],
                "isError": False,
            }

    engine = ResetEngine()
    checker = FixedOracleChecker(received=True)
    module = S1SSRF(engine, payloads=[payload], oracle_checker=checker)

    findings1 = await module.run()
    findings2 = await module.run()

    assert len(findings1) == len(findings2) == 1
    assert findings1[0].id == findings2[0].id == "S1-001"
    assert module.stats["attempted"] == 1


# ── I. Trace correlation ──


def test_s1_trace_id_matches_last_call():
    """Confirmed finding links to the exact MCP invocation trace entry."""
    tool = {
        "name": "fetch_url",
        "inputSchema": {
            "type": "object",
            "properties": {"url": {"type": "string"}},
            "required": ["url"],
        },
    }
    payload = SSRFPayload(
        payload_id="s1-trace",
        label="trace",
        url="http://127.0.0.1:1/probe",
        nonce="nonce-trace",
        marker="marker-trace",
        oracle_type="http",
    )

    class TraceEngine:
        def __init__(self):
            self.config = type("Config", (), {"endpoint_url": "http://test/sse"})()
            self.shared_context = {"tools": [tool]}
            self.traces = []

        async def list_tools(self):
            return [tool]

        async def call_tool(self, name: str, arguments: dict[str, Any] | None = None):
            entry = type(
                "Trace",
                (),
                {
                    "id": "exact-trace-id",
                    "method": "tools/call",
                    "request": {"name": name, "arguments": arguments or {}},
                    "response": None,
                    "error": None,
                },
            )
            self.traces.append(entry)
            return {
                "content": [{"type": "text", "text": "marker-trace nonce-trace"}],
                "isError": False,
            }

    engine = TraceEngine()
    checker = FixedOracleChecker(received=True)
    module = S1SSRF(engine, payloads=[payload], oracle_checker=checker)

    async def run():
        return await module.run()

    findings = asyncio.run(run())
    assert findings[0].evidence[0].trace_entry_id == "exact-trace-id"


# ── Unit helpers ──


def test_is_mcp_error_response_detects_errors():
    assert is_mcp_error_response({"isError": True}) is True
    assert is_mcp_error_response({"is_error": True}) is True
    assert is_mcp_error_response({"result_type": "error"}) is True
    assert is_mcp_error_response({"isError": False}) is False
    assert is_mcp_error_response(None) is True


def test_response_contains_marker_requires_both_marker_and_nonce():
    resp = {"content": [{"type": "text", "text": "marker-abc nonce-abc"}]}
    assert response_contains_marker(resp, "marker-abc", "nonce-abc") is True
    assert response_contains_marker(resp, "marker-abc", "wrong-nonce") is False
    assert response_contains_marker(resp, "", "nonce-abc") is False


def test_payload_provider_generates_unique_nonces():
    provider = SSRFPayloadProvider("http://127.0.0.1:1234")
    p1 = provider.create_payload()
    p2 = provider.create_payload()
    assert p1.nonce != p2.nonce
    assert p1.payload_id != p2.payload_id
    assert p1.marker.startswith("MCP_SSRF_MARKER-")


def test_localhost_oracle_checker_counts():
    checker = LocalhostOracleChecker(request_counts={"p1": 2, "p2": 0})
    p1 = SSRFPayload(payload_id="p1", label="", url="", nonce="", marker="", oracle_type="")
    p2 = SSRFPayload(payload_id="p2", label="", url="", nonce="", marker="", oracle_type="")

    async def check():
        r1 = await checker.check(p1)
        r2 = await checker.check(p2)
        return r1, r2

    r1, r2 = asyncio.run(check())
    assert r1.received is True
    assert r1.request_count == 2
    assert r2.received is False
