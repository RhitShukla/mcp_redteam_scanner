"""
MCP Harness — Web-compatible wrapper around ProbeEngine.

Bridges the existing CLI scanner (src.probe_engine.ProbeEngine) to the
web backend. Handles connection lifecycle, tool discovery, and provides
the interface that attack modules consume.

Usage:
    harness = MCPHarness()
    await harness.connect(sse_url, auth_method, token)
    tools = harness.tools
    result = await harness.call_tool("echo", {"message": "test"})
    await harness.disconnect()
"""

from __future__ import annotations

import asyncio
from typing import Any

from src.models import TargetConfig, AuthMethod
from src.probe_engine import ProbeEngine
from src.blueprint_analyzer import BlueprintAnalyzer
from scanner.logger import log


class MCPHarness:
    """
    Web-compatible MCP connection harness.

    Wraps ProbeEngine for use by the web runner — handles config conversion,
    connection lifecycle, and exposes discovered metadata.
    """

    def __init__(self):
        self.engine: ProbeEngine | None = None
        self.config: TargetConfig | None = None
        self.tools: list[dict] = []
        self.resources: list[dict] = []
        self.prompts: list[dict] = []
        self.phase0_findings: list = []
        self.phase0_context: dict = {}
        self._connected = False

    @staticmethod
    def _parse_auth_method(method_str: str) -> AuthMethod:
        """Convert config string to AuthMethod enum."""
        mapping = {
            "none": AuthMethod.NONE,
            "bearer_token": AuthMethod.BEARER_TOKEN,
            "bearer": AuthMethod.BEARER_TOKEN,
            "api_key": AuthMethod.API_KEY,
            "apikey": AuthMethod.API_KEY,
            "basic": AuthMethod.BASIC,
        }
        return mapping.get(method_str.lower(), AuthMethod.NONE)

    def build_config(self, sse_url: str, auth_method: str = "none", token: str = "") -> TargetConfig:
        """Build a TargetConfig from web config values."""
        return TargetConfig(
            endpoint_url=sse_url,
            transport="sse",
            auth_method=self._parse_auth_method(auth_method),
            auth_token=token or None,
        )

    async def connect(self, sse_url: str, auth_method: str = "none", token: str = ""):
        """
        Connect to an MCP server and run Phase 0 discovery.

        After this call:
        - self.tools / self.resources / self.prompts are populated
        - self.phase0_findings contains BlueprintAnalyzer results
        - self.phase0_context has the attack surface map
        """
        self.config = self.build_config(sse_url, auth_method, token)
        self.engine = ProbeEngine(self.config)

        log("harness_connecting", url=sse_url, auth=auth_method)

        # Connect and discover
        self._connect_cm = self.engine.connect()
        self._session_info = await self._connect_cm.__aenter__()
        self._connected = True

        # Discover capabilities
        self.tools = await self.engine.list_tools()
        try:
            self.resources = await self.engine.list_resources()
        except Exception:
            self.resources = []
        try:
            self.prompts = await self.engine.list_prompts()
        except Exception:
            self.prompts = []

        log(
            "harness_discovered",
            tools=len(self.tools),
            resources=len(self.resources),
            prompts=len(self.prompts),
        )

        # Run Blueprint Analyzer (Phase 0)
        analyzer = BlueprintAnalyzer(self.engine)
        self.phase0_findings = await analyzer.analyze()
        self.phase0_context = {
            "tools": self.tools,
            "resources": self.resources,
            "prompts": self.prompts,
            "blueprint_findings": [f.model_dump(mode="json") for f in self.phase0_findings],
            "attack_map": analyzer.attack_map if hasattr(analyzer, "attack_map") else {},
        }

        # Store phase0 context in engine for attack modules
        self.engine.shared_context["phase0"] = self.phase0_context

        log("harness_phase0_complete", findings=len(self.phase0_findings))

    async def disconnect(self):
        """Close the MCP connection."""
        if self._connected and hasattr(self, "_connect_cm"):
            try:
                await self._connect_cm.__aexit__(None, None, None)
            except Exception:
                pass
            self._connected = False
            log("harness_disconnected")

    async def call_tool(self, name: str, args: dict[str, Any] = None) -> Any:
        """Call a tool on the connected MCP server."""
        if not self._connected or not self.engine:
            raise RuntimeError("Not connected. Call connect() first.")
        return await self.engine.call_tool(name, args or {})

    @property
    def is_connected(self) -> bool:
        return self._connected

    @property
    def traces(self) -> list:
        """Get all interaction traces from the engine."""
        if self.engine:
            return self.engine.traces
        return []
