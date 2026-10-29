"""
Probe Engine — Layer 1.

The ONLY component that talks to MCP. Owns session lifecycle, capability
discovery, and the interaction log. Attack modules call methods on this
engine; they never construct their own MCP connections.
"""

from __future__ import annotations

import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any

import httpx2 as httpx
from mcp.client.session import ClientSession
from mcp.client.sse import sse_client

try:
    from mcp.client.streamable_http import streamable_http_client
except Exception:  # pragma: no cover
    streamable_http_client = None  # type: ignore[assignment]

try:
    from mcp.shared._httpx_utils import create_mcp_http_client
except Exception:  # pragma: no cover
    create_mcp_http_client = None  # type: ignore[assignment]

from pydantic import AnyUrl

from src.models import (
    AuthMethod,
    SessionInfo,
    TargetConfig,
    TraceEntry,
    TransportType,
)


class ProbeEngineError(Exception):
    """Raised when probe engine encounters an unrecoverable error."""


class ProbeEngine:
    """
    Manages MCP sessions and records every interaction.

    Usage:
        engine = ProbeEngine(config)
        async with engine.connect() as session_id:
            tools = await engine.list_tools()
            result = await engine.call_tool("echo", {"msg": "hi"})
        # engine.traces has every interaction recorded
    """

    def __init__(self, config: TargetConfig) -> None:
        self.config = config
        self.traces: list[TraceEntry] = []
        self.sessions: dict[str, SessionInfo] = {}
        self._active_session_id: str | None = None
        self._client_session: ClientSession | None = None

        # Shared cross-module context bus (Phase 0 -> active modules).
        self.shared_context: dict[str, Any] = {}

    @property
    def active_session(self) -> SessionInfo | None:
        if self._active_session_id is None:
            return None
        return self.sessions.get(self._active_session_id)

    def _build_headers(self, token: str | None = None) -> dict[str, str]:
        """Build auth headers based on config."""
        headers: dict[str, str] = {
            "ngrok-skip-browser-warning": "true",
        }

        tok = token or self.config.auth_token

        if self.config.auth_method == AuthMethod.BEARER_TOKEN and tok:
            headers["Authorization"] = f"Bearer {tok}"
        elif self.config.auth_method == AuthMethod.API_KEY and tok:
            headers["X-API-Key"] = tok
        elif self.config.auth_method == AuthMethod.BASIC and tok:
            headers["Authorization"] = f"Basic {tok}"

        return headers

    def _record(
        self,
        method: str,
        request: dict[str, Any],
        response: dict[str, Any] | None = None,
        error: str | None = None,
        duration_ms: float | None = None,
    ) -> TraceEntry:
        """Record an MCP interaction. Called after every SDK call."""
        entry = TraceEntry(
            session_id=self._active_session_id or "no-session",
            method=method,
            request=request,
            response=response,
            error=error,
            duration_ms=duration_ms,
        )

        self.traces.append(entry)
        return entry

    @asynccontextmanager
    async def connect(
        self,
        token: str | None = None,
        identity: str | None = None,
    ):
        """
        Connect to the MCP endpoint. Yields the session_id.

        Args:
            token: Override auth token (for cross-tenant testing).
            identity: Label for this session (e.g. "tenant-alpha").
        """
        session_id = str(uuid.uuid4())
        headers = self._build_headers(token)

        session_info = SessionInfo(
            session_id=session_id,
            endpoint_url=self.config.endpoint_url,
            transport=self.config.transport,
            auth_method=self.config.auth_method,
            auth_identity=identity,
            connected_at=datetime.now(timezone.utc),
        )

        try:
            if self.config.transport == TransportType.SSE:
                async with sse_client(
                    url=self.config.endpoint_url,
                    headers=headers,
                ) as (read_stream, write_stream):
                    async with ClientSession(read_stream, write_stream) as client:
                        self._client_session = client
                        self._active_session_id = session_id

                        # Initialize and capture capabilities.
                        init_result = await client.initialize()

                        caps = client.server_capabilities
                        session_info.server_capabilities = (
                            caps.model_dump() if caps else {}
                        )

                        self.sessions[session_id] = session_info

                        self._record(
                            method="initialize",
                            request={},
                            response={
                                "server_info": (
                                    init_result.server_info.model_dump()
                                    if init_result.server_info
                                    else {}
                                ),
                                "capabilities": session_info.server_capabilities,
                            },
                        )

                        yield session_id

            elif self.config.transport == TransportType.STREAMABLE_HTTP:
                if (
                    streamable_http_client is None
                    or create_mcp_http_client is None
                ):
                    raise ProbeEngineError(
                        "STREAMABLE_HTTP transport requested, but this MCP SDK "
                        "version does not provide streamable-http client support."
                    )

                http_client = create_mcp_http_client(
                    headers=headers,
                    timeout=httpx.Timeout(30, read=300),
                )

                async with streamable_http_client(
                    url=self.config.endpoint_url,
                    http_client=http_client,
                ) as (read_stream, write_stream):
                    async with ClientSession(read_stream, write_stream) as client:
                        self._client_session = client
                        self._active_session_id = session_id

                        # Initialize and capture capabilities.
                        init_result = await client.initialize()

                        caps = client.server_capabilities
                        session_info.server_capabilities = (
                            caps.model_dump() if caps else {}
                        )

                        self.sessions[session_id] = session_info

                        self._record(
                            method="initialize",
                            request={},
                            response={
                                "server_info": (
                                    init_result.server_info.model_dump()
                                    if init_result.server_info
                                    else {}
                                ),
                                "capabilities": session_info.server_capabilities,
                            },
                        )

                        yield session_id

            else:
                raise ProbeEngineError(
                    f"Unsupported transport: {self.config.transport}"
                )

        except Exception as exc:
            self._record(
                method="connect",
                request={"endpoint": self.config.endpoint_url},
                error=str(exc),
            )
            raise

        finally:
            session_info.disconnected_at = datetime.now(timezone.utc)
            self._client_session = None
            self._active_session_id = None

    def _require_session(self) -> ClientSession:
        if self._client_session is None:
            raise ProbeEngineError(
                "No active MCP session. Call connect() first."
            )

        return self._client_session

    async def list_tools(self) -> list[dict[str, Any]]:
        """Discover all tools on the server. Returns list of tool dicts."""
        client = self._require_session()
        start = time.monotonic()

        try:
            result = await client.list_tools()
            duration = (time.monotonic() - start) * 1000
            tools = [t.model_dump() for t in result.tools]

            self._record(
                method="tools/list",
                request={},
                response={"tools": tools},
                duration_ms=duration,
            )

            return tools

        except Exception as exc:
            duration = (time.monotonic() - start) * 1000

            self._record(
                method="tools/list",
                request={},
                error=str(exc),
                duration_ms=duration,
            )

            raise

    async def call_tool(
        self,
        name: str,
        arguments: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Call a tool and return the response as a dict. Records the interaction."""
        client = self._require_session()
        req = {"name": name, "arguments": arguments or {}}
        start = time.monotonic()

        try:
            result = await client.call_tool(name, arguments)
            duration = (time.monotonic() - start) * 1000
            response = result.model_dump()

            self._record(
                method="tools/call",
                request=req,
                response=response,
                duration_ms=duration,
            )

            return response

        except Exception as exc:
            duration = (time.monotonic() - start) * 1000

            self._record(
                method="tools/call",
                request=req,
                error=str(exc),
                duration_ms=duration,
            )

            raise

    async def list_resources(self) -> list[dict[str, Any]]:
        """Discover all resources on the server."""
        client = self._require_session()
        start = time.monotonic()

        try:
            result = await client.list_resources()
            duration = (time.monotonic() - start) * 1000
            resources = [r.model_dump() for r in result.resources]

            self._record(
                method="resources/list",
                request={},
                response={"resources": resources},
                duration_ms=duration,
            )

            return resources

        except Exception as exc:
            duration = (time.monotonic() - start) * 1000

            self._record(
                method="resources/list",
                request={},
                error=str(exc),
                duration_ms=duration,
            )

            raise

    async def read_resource(self, uri: str) -> dict[str, Any]:
        """Read a resource by URI."""
        client = self._require_session()
        req = {"uri": uri}
        start = time.monotonic()

        try:
            result = await client.read_resource(uri)
            duration = (time.monotonic() - start) * 1000
            response = result.model_dump()

            self._record(
                method="resources/read",
                request=req,
                response=response,
                duration_ms=duration,
            )

            return response

        except Exception as exc:
            duration = (time.monotonic() - start) * 1000

            self._record(
                method="resources/read",
                request=req,
                error=str(exc),
                duration_ms=duration,
            )

            raise

    async def list_prompts(self) -> list[dict[str, Any]]:
        """Discover all prompts on the server."""
        client = self._require_session()
        start = time.monotonic()

        try:
            result = await client.list_prompts()
            duration = (time.monotonic() - start) * 1000
            prompts = [p.model_dump() for p in result.prompts]

            self._record(
                method="prompts/list",
                request={},
                response={"prompts": prompts},
                duration_ms=duration,
            )

            return prompts

        except Exception as exc:
            duration = (time.monotonic() - start) * 1000

            self._record(
                method="prompts/list",
                request={},
                error=str(exc),
                duration_ms=duration,
            )

            raise

    async def get_prompt(
        self,
        name: str,
        arguments: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Get a prompt by name."""
        client = self._require_session()
        req = {"name": name, "arguments": arguments or {}}
        start = time.monotonic()

        try:
            result = await client.get_prompt(name, arguments)
            duration = (time.monotonic() - start) * 1000
            response = result.model_dump()

            self._record(
                method="prompts/get",
                request=req,
                response=response,
                duration_ms=duration,
            )

            return response

        except Exception as exc:
            duration = (time.monotonic() - start) * 1000

            self._record(
                method="prompts/get",
                request=req,
                error=str(exc),
                duration_ms=duration,
            )

            raise

    def get_traces_for_session(
        self,
        session_id: str,
    ) -> list[TraceEntry]:
        """Get all trace entries for a specific session."""
        return [
            t for t in self.traces
            if t.session_id == session_id
        ]

    def clear_traces(self) -> None:
        """Clear all traces. Useful between test runs."""
        self.traces.clear()
