"""
Shared test utilities for attack modules.

Keeps each attack test in its own file while reusing a small MockEngine that
mimics the subset of ProbeEngine behavior needed by modules.
"""

from __future__ import annotations

from typing import Any

from src.models import AuthMethod


class _Config:
    def __init__(self, endpoint_url: str, auth_method: AuthMethod):
        self.endpoint_url = endpoint_url
        self.auth_method = auth_method


class MockEngine:
    def __init__(
        self,
        *,
        endpoint_url: str = "http://example/sse",
        auth_method: AuthMethod = AuthMethod.NONE,
    ):
        self.config = _Config(endpoint_url, auth_method)
        self.shared_context: dict[str, Any] = {"phase0": {}}

        self._tools: list[dict[str, Any]] = []
        self._resources: list[dict[str, Any]] = []
        self._prompts: list[dict[str, Any]] = []
        self._call_results: dict[tuple[str, str], dict[str, Any]] = {}
        self._call_errors: dict[tuple[str, str], Exception] = {}
        self.call_history: list[dict[str, Any]] = []
        self.traces: list[Any] = []

    async def list_tools(self):
        return self._tools

    async def list_resources(self):
        return self._resources

    async def list_prompts(self):
        return self._prompts

    async def call_tool(self, name: str, arguments: dict[str, Any] | None = None):
        args = arguments or {}
        self.call_history.append({"name": name, "arguments": args})
        key = (name, str(sorted(args.items())))
        if key in self._call_errors:
            raise self._call_errors[key]
        return self._call_results.get(
            key,
            {"isError": False, "content": [{"type": "text", "text": "ok"}]},
        )


def set_phase0(
    engine: MockEngine,
    *,
    tools: list[dict[str, Any]] | None = None,
    resources: list[dict[str, Any]] | None = None,
    prompts: list[dict[str, Any]] | None = None,
    attack_map: dict[str, Any] | None = None,
) -> None:
    engine.shared_context["phase0"] = {
        "tools": tools or [],
        "resources": resources or [],
        "prompts": prompts or [],
        "attack_map": attack_map or {"targets": [], "by_severity": {}},
    }

