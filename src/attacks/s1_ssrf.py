"""
S1 — Server-Side Request Forgery.

Deterministic, schema-aware, oracle-backed SSRF detection for MCP tools
that accept URL-like parameters.

Design principles:
- The oracle receipt is the authoritative confirmation source.
- A marker appearing in the MCP response alone is never enough.
- Required dangerous sibling parameters (command, exec, shell, sql, etc.)
  are never invented.
- All verdicts are deterministic; no LLM participates in the verdict.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from typing import Any, Callable
from urllib.parse import urlparse, urlunsplit

from src.attack_base import AttackModule
from src.models import (
    Evidence,
    EvidenceType,
    Fixability,
    Finding,
    ReplayInfo,
    Severity,
)
from src.probe_engine import ProbeEngine


# ── URL Candidate Detection ──

# Name hints that strongly suggest the parameter accepts a URL/URI.
_URL_NAME_HINTS = {
    "url",
    "uri",
    "endpoint",
    "webhook",
    "callback",
}

# Name hints that are weaker and require corroborating schema signals.
_WEAK_URL_NAME_HINTS = {
    "host",
    "target",
    "link",
    "href",
    "address",
    "location",
}

# String patterns that, if found in a name, strongly indicate a URL parameter.
_URL_NAME_SUBSTRINGS = (
    "_url",
    "_uri",
    "_endpoint",
    "_webhook",
    "_callback",
)

# Dangerous parameter names. If any of these are required by the same tool
# as the URL parameter, the candidate is marked not_testable rather than
# having S1 invent a safe-looking value that might still execute code.
_DANGEROUS_REQUIRED_PARAMS = {
    "command",
    "cmd",
    "exec",
    "execute",
    "shell",
    "sh",
    "script",
    "code",
    "sql",
    "query",
    "sql_query",
    "raw_query",
    "eval",
    "system",
    "os_command",
    "terminal",
    "run_command",
    "program",
}


# ── Verdict Contract ──

SSRF_VERDICT_CONFIRMED_REFLECTIVE = "confirmed_reflective"
SSRF_VERDICT_CONFIRMED_BLIND = "confirmed_blind"
SSRF_VERDICT_SUSPECTED = "suspected"
SSRF_VERDICT_INCONCLUSIVE = "inconclusive"
SSRF_VERDICT_NOT_TESTABLE = "not_testable"
SSRF_VERDICT_NOT_RUN = "not_run"


# ── Payload Architecture ──

@dataclass
class SSRFPayload:
    """A single SSRF probe payload."""

    payload_id: str
    label: str
    url: str
    nonce: str
    marker: str
    oracle_type: str  # e.g. "http", "dns"
    expected_method: str = "GET"
    marker_prefix: str = "MCP_SSRF_MARKER"


class SSRFPayloadProvider:
    """
    Produces unique, correlated SSRF payloads for each probe.

    This provider is intentionally minimal. It is meant to be wired with an
    operator-controlled oracle endpoint. The default test configuration uses
    a localhost oracle; no external OAST service is introduced here.
    """

    def __init__(
        self,
        oracle_base_url: str,
        marker_prefix: str = "MCP_SSRF_MARKER",
    ) -> None:
        self.oracle_base_url = oracle_base_url.rstrip("/")
        self.marker_prefix = marker_prefix

    def create_payload(
        self,
        label: str = "controlled-oracle",
        oracle_type: str = "http",
        expected_method: str = "GET",
    ) -> SSRFPayload:
        """Generate a payload with a unique nonce."""
        nonce = secrets.token_urlsafe(16)
        payload_id = f"s1-{nonce[:16]}"
        marker = f"{self.marker_prefix}-{nonce}"
        url = f"{self.oracle_base_url}/{payload_id}?probe={nonce}"
        return SSRFPayload(
            payload_id=payload_id,
            label=label,
            url=url,
            nonce=nonce,
            marker=marker,
            oracle_type=oracle_type,
            expected_method=expected_method,
            marker_prefix=self.marker_prefix,
        )


def build_default_payloads(oracle_base_url: str) -> list[SSRFPayload]:
    """Build a small safe default payload set for a single oracle endpoint."""
    provider = SSRFPayloadProvider(oracle_base_url)
    return [provider.create_payload(label="controlled-oracle")]


def _extract_oracle_base_url(url: str) -> str:
    """Return scheme://host from a payload URL."""
    parsed = urlparse(url)
    return urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))


# ── Schema Normalization and Safe Argument Generation ──


def get_tool_schema(tool: dict[str, Any]) -> dict[str, Any]:
    """Normalize MCP tool input schema keys."""
    schema = tool.get("input_schema", tool.get("inputSchema", {}))
    if not isinstance(schema, dict):
        return {}
    return schema


def get_schema_properties(schema: dict[str, Any]) -> dict[str, Any]:
    """Return schema properties dict, defaulting to empty dict."""
    properties = schema.get("properties", {})
    return properties if isinstance(properties, dict) else {}


def get_schema_required(schema: dict[str, Any]) -> set[str]:
    """Return set of required property names."""
    required = schema.get("required", [])
    return set(required) if isinstance(required, (list, tuple)) else set()


def _is_url_name(parameter_name: str) -> bool:
    """Conservative name-based URL parameter detection."""
    name_lower = parameter_name.lower()
    if name_lower in _URL_NAME_HINTS:
        return True
    if name_lower.endswith(_URL_NAME_SUBSTRINGS):
        return True
    return False


def _is_likely_url_param(
    parameter_name: str,
    param_schema: dict[str, Any],
) -> bool:
    """
    Decide whether a parameter is a URL candidate.

    Strong names are accepted outright. Weak names require corroborating
    schema signals (format: uri, examples containing http, or explicit
    description hints). Arbitrary suffix matches like `endpoint_id` or
    `callback_token` are rejected.
    """
    if _is_url_name(parameter_name):
        return True

    name_lower = parameter_name.lower()
    weak_match = name_lower in _WEAK_URL_NAME_HINTS or any(
        name_lower.endswith(f"_{hint}") for hint in _WEAK_URL_NAME_HINTS
    )
    if not weak_match:
        return False

    # Require corroboration for weak names.
    param_format = str(param_schema.get("format", "")).lower()
    if param_format in {"uri", "url", "uri-reference"}:
        return True

    examples = param_schema.get("examples") or []
    if isinstance(examples, list):
        for example in examples:
            if isinstance(example, str) and example.lower().startswith(
                ("http://", "https://")
            ):
                return True

    description = str(param_schema.get("description", "")).lower()
    if any(
        term in description
        for term in (
            "url",
            "uri",
            "web address",
            "http",
            "https",
            "endpoint",
            "webhook",
            "callback",
        )
    ):
        return True

    return False


def _safe_default_for_type(param_schema: dict[str, Any]) -> Any:
    """Return a safe default for a given schema property."""
    param_type = param_schema.get("type", "string")
    if param_type == "string":
        return "test"
    if param_type == "integer":
        return 1
    if param_type == "number":
        return 1.0
    if param_type == "boolean":
        return True
    if param_type == "array":
        return []
    if param_type == "object":
        return {}
    return "test"


def _safe_value_for_param(
    parameter_name: str,
    param_schema: dict[str, Any],
) -> tuple[Any, str | None]:
    """
    Generate a safe value for a non-URL parameter.

    Returns (value, reason) where reason is set if the parameter is
    considered dangerous and should not be filled automatically.
    """
    name_lower = parameter_name.lower()
    if name_lower in _DANGEROUS_REQUIRED_PARAMS:
        return (None, f"dangerous required parameter '{parameter_name}'")

    # Prefer examples when available and safe.
    examples = param_schema.get("examples") or []
    if isinstance(examples, list) and examples:
        first = examples[0]
        if isinstance(first, str) and first.lower().startswith(
            ("http://", "https://")
        ):
            # Reuse as-is; should already be handled by URL selection.
            return (first, None)
        return (first, None)

    # Use enum first value if present.
    enum_values = param_schema.get("enum")
    if isinstance(enum_values, list) and enum_values:
        return (enum_values[0], None)

    # Use default if provided (be cautious with strings).
    default = param_schema.get("default")
    if default is not None:
        return (default, None)

    return (_safe_default_for_type(param_schema), None)


def build_safe_arguments(
    tool_name: str,
    schema: dict[str, Any],
    url_param: str,
    url_value: str,
) -> tuple[dict[str, Any], str | None]:
    """
    Build schema-valid arguments for a tool probe.

    The URL parameter is set to the probe URL. All required siblings are
    filled with safe defaults. If a required sibling is dangerous, the
    candidate is marked not_testable and (None, reason) is returned.
    """
    properties = get_schema_properties(schema)
    required = get_schema_required(schema)

    args: dict[str, Any] = {}

    for parameter_name, param_schema in properties.items():
        if parameter_name == url_param:
            args[parameter_name] = url_value
            continue

        if parameter_name not in required:
            # Skip optional parameters to avoid unintended side effects.
            continue

        value, reason = _safe_value_for_param(parameter_name, param_schema)
        if reason:
            return (None, reason)
        args[parameter_name] = value

    # Ensure the URL parameter itself was included.
    if url_param not in args:
        return (None, "URL parameter missing from generated arguments")

    return (args, None)


def find_url_candidates(tool: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    """Return list of (parameter_name, param_schema) URL candidates."""
    schema = get_tool_schema(tool)
    properties = get_schema_properties(schema)

    candidates: list[tuple[str, dict[str, Any]]] = []
    for parameter_name, param_schema in properties.items():
        if not isinstance(param_schema, dict):
            param_schema = {}
        if _is_likely_url_param(parameter_name, param_schema):
            candidates.append((parameter_name, param_schema))
    return candidates


# ── Response Evaluation ──


def _extract_text_from_response(response: dict[str, Any]) -> str:
    """Extract text content from an MCP tool response, similar to D1."""
    parts: list[str] = []
    for item in response.get("content", []):
        if isinstance(item, dict) and item.get("type") == "text":
            parts.append(str(item.get("text", "")))
        elif isinstance(item, dict):
            parts.append(str(item))
        else:
            parts.append(str(item))
    return "\n".join(parts)


def is_mcp_error_response(response: dict[str, Any] | None) -> bool:
    """Return True if the response represents an MCP tool error."""
    if response is None:
        return True
    if response.get("isError") or response.get("is_error"):
        return True
    if response.get("result_type") == "error":
        return True
    return False


def response_contains_marker(
    response: dict[str, Any] | None,
    marker: str,
    nonce: str,
) -> bool:
    """
    Check whether the response contains the unique marker.

    The check requires that both marker and nonce appear in the extracted
    text. This prevents a simple echo of the supplied payload URL from
    being treated as confirmation.
    """
    if not marker or not nonce:
        return False
    if response is None:
        return False
    if is_mcp_error_response(response):
        return False

    text = _extract_text_from_response(response)
    if not text:
        return False

    # Require the marker and the nonce both to be present.
    return marker in text and nonce in text


# ── Oracle Observation ──


@dataclass
class OracleObservation:
    """Result of checking whether the oracle received the probe."""

    received: bool
    request_count: int = 0
    details: dict[str, Any] = field(default_factory=dict)


class OracleChecker:
    """Abstract oracle receipt checker."""

    async def check(
        self,
        payload: SSRFPayload,
    ) -> OracleObservation:
        """Return whether the oracle observed the probe."""
        raise NotImplementedError


class LocalhostOracleChecker(OracleChecker):
    """
    Placeholder oracle checker for tests with a shared localhost oracle.

    The test harness owns the actual oracle server and records request
    counts. This checker can read either a static request_counts map or a
    live state_source callable.
    """

    def __init__(
        self,
        request_counts: dict[str, int] | None = None,
        state_source: Callable[[], dict[str, int]] | None = None,
    ) -> None:
        self._request_counts = request_counts or {}
        self._state_source = state_source

    async def check(self, payload: SSRFPayload) -> OracleObservation:
        counts = self._state_source() if self._state_source else self._request_counts
        count = counts.get(payload.payload_id, 0)
        return OracleObservation(
            received=count > 0,
            request_count=count,
            details={"payload_id": payload.payload_id},
        )


class FixedOracleChecker(OracleChecker):
    """
    Test checker that returns a fixed observation regardless of payload.

    Useful for unit tests where the exact payload ID is not known because
    S1 generates a unique payload per probe.
    """

    def __init__(
        self,
        received: bool,
        request_count: int | None = None,
    ) -> None:
        self.received = received
        self.request_count = (
            request_count if request_count is not None else (1 if received else 0)
        )

    async def check(self, payload: SSRFPayload) -> OracleObservation:
        return OracleObservation(
            received=self.received,
            request_count=self.request_count,
            details={"payload_id": payload.payload_id},
        )


# ── Result Aggregation ──


@dataclass
class ProbeResult:
    """Internal result of one SSRF probe."""

    tool_name: str
    parameter: str
    payload: SSRFPayload
    args: dict[str, Any]
    verdict: str
    reason: str
    response: dict[str, Any] | None = None
    trace_entry_id: str | None = None
    oracle_observation: OracleObservation | None = None


class S1SSRF(AttackModule):
    """Detect SSRF behavior in URL-capable MCP tools."""

    name = "SSRF Network Probe"
    surface = "S - Network & SSRF Surface"
    module_id = "S1"
    description = (
        "Deterministic, schema-aware, oracle-backed SSRF detection for "
        "MCP tools that accept URL-like parameters."
    )

    def __init__(
        self,
        engine: ProbeEngine,
        payloads: list[SSRFPayload] | None = None,
        oracle_checker: OracleChecker | None = None,
        payload_provider: SSRFPayloadProvider | None = None,
        per_tool_probe_limit: int = 5,
        total_probe_limit: int = 50,
        response_max_chars: int = 10000,
    ) -> None:
        super().__init__(engine)
        self.payloads = payloads or []
        self.oracle_checker = oracle_checker
        self.per_tool_probe_limit = per_tool_probe_limit
        self.total_probe_limit = total_probe_limit
        self.response_max_chars = response_max_chars

        # Runtime observability counters.
        self.stats: dict[str, int] = {
            "attempted": 0,
            "skipped": 0,
            "failed": 0,
            "inconclusive": 0,
            "confirmed": 0,
        }
        self.probe_results: list[ProbeResult] = []

        # Build a provider from the first payload template if none supplied.
        self.payload_provider = payload_provider
        if self.payload_provider is None and self.payloads:
            template = self.payloads[0]
            base_url = _extract_oracle_base_url(template.url)
            self.payload_provider = SSRFPayloadProvider(
                base_url,
                marker_prefix=template.marker_prefix,
            )

    def _fresh_payload(self, template: SSRFPayload | None) -> SSRFPayload:
        """Generate a unique payload for a single probe."""
        if self.payload_provider is None:
            raise RuntimeError("No payload provider available")
        if template is None:
            return self.payload_provider.create_payload()
        return self.payload_provider.create_payload(
            label=template.label,
            oracle_type=template.oracle_type,
            expected_method=template.expected_method,
        )

    async def run(self) -> list[Finding]:
        """Execute deterministic SSRF probes."""
        self.findings.clear()
        self._finding_counter = 0
        self.stats = {
            "attempted": 0,
            "skipped": 0,
            "failed": 0,
            "inconclusive": 0,
            "confirmed": 0,
        }
        self.probe_results = []

        if self.payload_provider is None or self.oracle_checker is None:
            reason = (
                "No SSRF payloads configured; skipping S1."
                if self.payload_provider is None
                else "No oracle checker configured; cannot confirm SSRF."
            )
            self._emit_status_finding(
                SSRF_VERDICT_NOT_RUN,
                reason,
                severity=Severity.INFO,
            )
            return self.findings

        tools = await self._get_tools()
        if not tools:
            self._emit_status_finding(
                SSRF_VERDICT_NOT_RUN,
                "No tools discovered; skipping S1.",
                severity=Severity.INFO,
            )
            return self.findings

        # Templates drive label/oracle_type/expected_method. If no templates
        # were supplied but a provider was, generate one default payload per
        # candidate.
        templates = self.payloads or [None]
        total_probes = 0

        for tool in tools:
            tool_name = str(tool.get("name", ""))
            if not tool_name:
                continue

            candidates = find_url_candidates(tool)
            if not candidates:
                continue

            tool_probes = 0
            schema = get_tool_schema(tool)

            for parameter, _ in candidates:
                for template in templates:
                    if tool_probes >= self.per_tool_probe_limit:
                        break
                    if total_probes >= self.total_probe_limit:
                        break

                    total_probes += 1
                    tool_probes += 1
                    self.stats["attempted"] += 1

                    payload = self._fresh_payload(template)

                    args, reason = build_safe_arguments(
                        tool_name,
                        schema,
                        parameter,
                        payload.url,
                    )
                    if args is None:
                        self.stats["skipped"] += 1
                        self.probe_results.append(
                            ProbeResult(
                                tool_name=tool_name,
                                parameter=parameter,
                                payload=payload,
                                args={},
                                verdict=SSRF_VERDICT_NOT_TESTABLE,
                                reason=reason or "unknown safety reason",
                            )
                        )
                        continue

                    response, trace_entry_id, call_error = await self._call_tool(
                        tool_name,
                        args,
                    )

                    if call_error:
                        self.stats["failed"] += 1
                        self.probe_results.append(
                            ProbeResult(
                                tool_name=tool_name,
                                parameter=parameter,
                                payload=payload,
                                args=args,
                                verdict=SSRF_VERDICT_INCONCLUSIVE,
                                reason=f"Tool call failed: {call_error}",
                                response=response,
                                trace_entry_id=trace_entry_id,
                            )
                        )
                        continue

                    if is_mcp_error_response(response):
                        self.stats["inconclusive"] += 1
                        self.probe_results.append(
                            ProbeResult(
                                tool_name=tool_name,
                                parameter=parameter,
                                payload=payload,
                                args=args,
                                verdict=SSRF_VERDICT_INCONCLUSIVE,
                                reason="Tool returned an error response.",
                                response=response,
                                trace_entry_id=trace_entry_id,
                            )
                        )
                        continue

                    oracle_obs = await self.oracle_checker.check(payload)
                    marker_returned = response_contains_marker(
                        response,
                        payload.marker,
                        payload.nonce,
                    )

                    if oracle_obs.received and marker_returned:
                        verdict = SSRF_VERDICT_CONFIRMED_REFLECTIVE
                        self.stats["confirmed"] += 1
                        reason = (
                            "Oracle received the probe and the target response "
                            "contained the unique marker."
                        )
                    elif oracle_obs.received:
                        verdict = SSRF_VERDICT_CONFIRMED_BLIND
                        self.stats["confirmed"] += 1
                        reason = (
                            "Oracle received the probe, but the target response "
                            "did not contain the unique marker."
                        )
                    else:
                        verdict = SSRF_VERDICT_INCONCLUSIVE
                        self.stats["inconclusive"] += 1
                        reason = (
                            "Oracle did not observe the probe; cannot confirm "
                            "server-side request."
                        )

                    self.probe_results.append(
                        ProbeResult(
                            tool_name=tool_name,
                            parameter=parameter,
                            payload=payload,
                            args=args,
                            verdict=verdict,
                            reason=reason,
                            response=response,
                            trace_entry_id=trace_entry_id,
                            oracle_observation=oracle_obs,
                        )
                    )

                    if verdict in (
                        SSRF_VERDICT_CONFIRMED_REFLECTIVE,
                        SSRF_VERDICT_CONFIRMED_BLIND,
                    ):
                        self._emit_confirmed_finding(
                            tool_name,
                            parameter,
                            payload,
                            args,
                            response,
                            trace_entry_id,
                            oracle_obs,
                            verdict,
                        )

        # If no confirmed findings were emitted but probes were attempted,
        # emit a single informational finding summarizing the run. This keeps
        # the run observable without manufacturing false positives.
        if self.stats["confirmed"] == 0 and self.stats["attempted"] > 0:
            summary = (
                f"S1 completed without confirmed SSRF: "
                f"attempted={self.stats['attempted']}, "
                f"skipped={self.stats['skipped']}, "
                f"failed={self.stats['failed']}, "
                f"inconclusive={self.stats['inconclusive']}"
            )
            self._emit_status_finding(
                SSRF_VERDICT_INCONCLUSIVE,
                summary,
                severity=Severity.INFO,
            )

        return self.findings

    async def _get_tools(self) -> list[dict[str, Any]]:
        """Return tools from Phase 0 context or live discovery."""
        phase0 = self.get_phase0_context()
        tools = phase0.get("tools") if isinstance(phase0, dict) else None
        if not isinstance(tools, list):
            try:
                return await self.engine.list_tools()
            except Exception:
                return []
        return tools

    async def _call_tool(
        self,
        tool_name: str,
        args: dict[str, Any],
    ) -> tuple[dict[str, Any] | None, str | None, str | None]:
        """
        Call a tool via ProbeEngine and return (response, trace_id, error).

        The trace entry is the most recently recorded tools/call entry. The
        engine records synchronously inside call_tool, so this is reliable.
        """
        try:
            response = await self.engine.call_tool(tool_name, args)
        except Exception as exc:
            trace_id = self._find_last_trace_id(tool_name, args)
            return (None, trace_id, str(exc))

        trace_id = self._find_last_trace_id(tool_name, args)
        return (response, trace_id, None)

    def _find_last_trace_id(
        self,
        tool_name: str,
        args: dict[str, Any],
    ) -> str | None:
        """Return the trace ID of the most recent matching tool call."""
        for trace in reversed(self.engine.traces):
            if (
                trace.method == "tools/call"
                and trace.request.get("name") == tool_name
                and trace.request.get("arguments") == args
            ):
                return trace.id
        return None

    def _emit_confirmed_finding(
        self,
        tool_name: str,
        parameter: str,
        payload: SSRFPayload,
        args: dict[str, Any],
        response: dict[str, Any] | None,
        trace_entry_id: str | None,
        oracle_obs: OracleObservation,
        verdict: str,
    ) -> None:
        """Emit a confirmed SSRF finding."""
        reflected = verdict == SSRF_VERDICT_CONFIRMED_REFLECTIVE
        title_suffix = "confirmed reflective" if reflected else "confirmed blind"
        title = f"SSRF in '{tool_name}.{parameter}' ({title_suffix})"

        evidence_items: list[Evidence] = [
            Evidence(
                type=EvidenceType.TOOL_INVOCATION,
                request={
                    "tool": tool_name,
                    "arguments": args,
                    "payload_id": payload.payload_id,
                    "nonce": payload.nonce,
                },
                response=self._truncate_response(response),
                trace_entry_id=trace_entry_id,
            ),
            Evidence(
                type=EvidenceType.CONNECTION_ATTEMPT,
                request={"url": payload.url},
                response={
                    "received": oracle_obs.received,
                    "request_count": oracle_obs.request_count,
                    **oracle_obs.details,
                },
            ),
        ]

        description = (
            f"The MCP tool '{tool_name}' accepted a controlled URL in parameter "
            f"'{parameter}' and the SSRF oracle observed the resulting outbound "
            f"request. Verdict: {verdict}."
        )

        attack_narrative = (
            "1. Inspected Phase 0 / live tool schema\n"
            f"2. Identified URL parameter '{parameter}' in '{tool_name}'\n"
            f"3. Generated safe arguments: {args}\n"
            f"4. Supplied controlled SSRF oracle URL: {payload.url}\n"
            "5. Target tool performed a server-side request\n"
            f"6. Oracle received the probe (count={oracle_obs.request_count})\n"
            f"7. Marker returned in response: {reflected}\n"
            "8. SSRF confirmed by independent oracle receipt"
        )

        self.add_finding(
            Finding(
                id=self._next_finding_id(),
                title=title,
                surface=self.surface,
                module=f"{self.module_id} - {self.name}",
                severity=Severity.HIGH,
                fixability=Fixability.DESIGN,
                fixability_rationale=(
                    "The tool performs server-side outbound requests to "
                    "attacker-controlled URLs. Restricting outbound destinations "
                    "requires handler/policy design."
                ),
                description=description,
                attack_narrative=attack_narrative,
                evidence=evidence_items,
                replay=ReplayInfo(
                    command=(
                        f"mcp-redteam replay --finding "
                        f"{self.module_id}-{self._finding_counter:03d} "
                        f"--target {self.engine.config.endpoint_url}"
                    ),
                    trace_file=(
                        f"traces/{self.module_id}-"
                        f"{self._finding_counter:03d}.json"
                    ),
                ),
                recommendation=(
                    "Restrict outbound requests using an explicit destination "
                    "allowlist and block loopback, private, link-local, and "
                    "metadata address ranges. Reject or sanitize attacker-"
                    "controlled URLs before fetching them server-side."
                ),
            )
        )

    def _emit_status_finding(
        self,
        verdict: str,
        description: str,
        severity: Severity = Severity.INFO,
    ) -> None:
        """Emit a non-confirmatory status finding for observability."""
        self.add_finding(
            Finding(
                id=self._next_finding_id(),
                title=f"S1 SSRF scan status: {verdict}",
                surface=self.surface,
                module=f"{self.module_id} - {self.name}",
                severity=severity,
                fixability=Fixability.CONFIGURATION,
                fixability_rationale=(
                    "This is a scan-status observation, not a confirmed "
                    "vulnerability."
                ),
                description=description,
                attack_narrative=(
                    "1. S1 module initialized\n"
                    f"2. Verdict: {verdict}\n"
                    f"3. Details: {description}"
                ),
                evidence=[
                    Evidence(
                        type=EvidenceType.CONNECTION_ATTEMPT,
                        request={"verdict": verdict},
                        response={"stats": self.stats},
                    )
                ],
                replay=ReplayInfo(
                    command="n/a",
                    trace_file="n/a",
                ),
                recommendation=(
                    "If SSRF coverage is expected, ensure payloads and an oracle "
                    "checker are configured."
                ),
            )
        )

    def _truncate_response(
        self,
        response: dict[str, Any] | None,
    ) -> dict[str, Any] | None:
        """Bound response size stored in evidence."""
        if response is None:
            return None
        text = _extract_text_from_response(response)
        if len(text) > self.response_max_chars:
            truncated = text[: self.response_max_chars] + "... [truncated]"
            return {
                "isError": is_mcp_error_response(response),
                "truncated_text": truncated,
                "original_size": len(text),
            }
        return response
