"""
D2 — API Key & Secret Extraction via Error Channels.

Deterministic, schema-aware, evidence-driven secret disclosure detection for
MCP tools. D2 sends a small set of controlled adversarial probes, normalizes
the resulting responses and exceptions, scans them for credential-like
material, and emits high-quality redacted findings.

Design principles:
- Adversarial/error-inducing probes are intentional and bounded.
- All probing is schema-aware; dangerous required siblings are never invented.
- Secrets are redacted before they enter findings, evidence, or narratives.
- Findings are deterministic and aggregated by (tool, pattern).
"""

from __future__ import annotations

import base64
import json
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


# ── Verdicts ──

VERDICT_CONFIRMED_SECRET = "confirmed_secret"
VERDICT_SUSPECTED_SECRET = "suspected_secret"
VERDICT_CONFIRMED_DIAGNOSTIC = "confirmed_diagnostic"
VERDICT_INCONCLUSIVE = "inconclusive"
VERDICT_NOT_TESTABLE = "not_testable"
VERDICT_NOT_RUN = "not_run"


# ── Structured Secret Patterns ──

@dataclass(frozen=True)
class SecretPatternSpec:
    """Metadata for a single secret/detection pattern."""

    pattern_id: str
    category: str
    label: str
    regex: re.Pattern
    severity: Severity
    confidence: str  # high | medium | low
    kind: str  # secret | diagnostic
    redact_mode: str = "full"  # full | db_password | azure_key


@dataclass(frozen=True)
class SecretMatch:
    """A single pattern match in normalized text."""

    pattern_id: str
    category: str
    label: str
    severity: Severity
    confidence: str
    kind: str
    start: int
    end: int
    matched_value: str
    redacted_value: str


# ── Pattern Registry ──

def _build_patterns() -> tuple[SecretPatternSpec, ...]:
    return (
        SecretPatternSpec(
            pattern_id="database_connection_string",
            category="database",
            label="Database Connection String",
            regex=re.compile(
                r"(?i)(?:mongodb|mongodb\+srv|postgres|postgresql|mysql|mysql2|"
                r"mariadb|redis|prisma|sqlite|mssql|oracle|jdbc)://"
                r"[^:@\s\"'/]+:[^@\s\"'/]+@[^\s\"'<>]+"
            ),
            severity=Severity.CRITICAL,
            confidence="high",
            kind="secret",
            redact_mode="db_password",
        ),
        SecretPatternSpec(
            pattern_id="azure_storage_connection_string",
            category="cloud",
            label="Azure Storage Connection String",
            regex=re.compile(
                r"(?i)DefaultEndpointsProtocol=https?;AccountName=[^;\s]+;AccountKey=[^;\s]+"
            ),
            severity=Severity.CRITICAL,
            confidence="high",
            kind="secret",
            redact_mode="azure_key",
        ),
        SecretPatternSpec(
            pattern_id="aws_access_key_id",
            category="cloud",
            label="AWS Access Key ID",
            regex=re.compile(r"(?<![A-Z0-9])(AKIA|ASIA)[0-9A-Z]{16}(?![A-Z0-9])"),
            severity=Severity.CRITICAL,
            confidence="high",
            kind="secret",
        ),
        SecretPatternSpec(
            pattern_id="aws_secret_access_key",
            category="cloud",
            label="AWS Secret Access Key",
            regex=re.compile(
                r"(?i)(?:aws_secret_access_key|secret_access_key|aws_secret)"
                r"[\"'\s:=]+([A-Za-z0-9/+=]{40})"
            ),
            severity=Severity.CRITICAL,
            confidence="high",
            kind="secret",
        ),
        SecretPatternSpec(
            pattern_id="openai_api_key",
            category="api_key",
            label="OpenAI API Key",
            regex=re.compile(r"\bsk-[a-zA-Z0-9_-]{20,}\b"),
            severity=Severity.HIGH,
            confidence="high",
            kind="secret",
        ),
        SecretPatternSpec(
            pattern_id="google_api_key",
            category="api_key",
            label="Google API Key",
            regex=re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
            severity=Severity.HIGH,
            confidence="high",
            kind="secret",
        ),
        SecretPatternSpec(
            pattern_id="github_token",
            category="api_key",
            label="GitHub Token",
            regex=re.compile(r"\b(ghp_|gho_|ghs_|github_pat_)[A-Za-z0-9_]{30,}\b"),
            severity=Severity.HIGH,
            confidence="high",
            kind="secret",
        ),
        SecretPatternSpec(
            pattern_id="bearer_token",
            category="token",
            label="Bearer Token",
            regex=re.compile(r"(?i)Bearer\s+([A-Za-z0-9_\-./]{20,})"),
            severity=Severity.HIGH,
            confidence="medium",
            kind="secret",
        ),
        SecretPatternSpec(
            pattern_id="basic_auth",
            category="token",
            label="Basic Authorization Credential",
            regex=re.compile(r"(?i)Basic\s+([A-Za-z0-9+/=]{20,})"),
            severity=Severity.HIGH,
            confidence="medium",
            kind="secret",
        ),
        SecretPatternSpec(
            pattern_id="jwt_token",
            category="token",
            label="JWT Token",
            regex=re.compile(
                r"\beyJ[A-Za-z0-9_-]{2,}\.[A-Za-z0-9_-]{2,}\.[A-Za-z0-9_-]{2,}\b"
            ),
            severity=Severity.HIGH,
            confidence="medium",
            kind="secret",
        ),
        SecretPatternSpec(
            pattern_id="private_key_pem",
            category="cryptographic",
            label="Private Key (PEM)",
            regex=re.compile(
                r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----\r?\n"
                r"[\s\S]{100,}?\r?\n-----END (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
                re.MULTILINE,
            ),
            severity=Severity.CRITICAL,
            confidence="high",
            kind="secret",
        ),
        SecretPatternSpec(
            pattern_id="private_key_header_only",
            category="cryptographic",
            label="Private Key Header (PEM)",
            regex=re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
            severity=Severity.MEDIUM,
            confidence="low",
            kind="secret",
        ),
        SecretPatternSpec(
            pattern_id="azure_sas_url",
            category="signed_url",
            label="Azure SAS URL",
            regex=re.compile(
                r"(?i)https?://[^\s\"'<>?]*\?[^\s\"'<>]*"
                r"(?:sv|se|sp|st|spr)=[^&\s\"'<>]+[^\s\"'<>]*"
                r"&sig=[A-Za-z0-9%+/=]{20,}"
            ),
            severity=Severity.HIGH,
            confidence="high",
            kind="secret",
        ),
        SecretPatternSpec(
            pattern_id="aws_presigned_url",
            category="signed_url",
            label="AWS Presigned URL",
            regex=re.compile(
                r"(?i)https?://[^\s\"'<>?]*\?[^\s\"'<>]*"
                r"X-Amz-Credential=[^&\s\"'<>]+[^\s\"'<>]*"
                r"X-Amz-Signature=[A-Za-z0-9%]{20,}"
            ),
            severity=Severity.HIGH,
            confidence="high",
            kind="secret",
        ),
        SecretPatternSpec(
            pattern_id="secret_assignment",
            category="config",
            label="Secret Assignment",
            regex=re.compile(
                r"(?i)(?:password|passwd|client_secret|api_key|access_token|"
                r"refresh_token|auth_token|secret_key)\s*[:=]\s*\"([^\"]{8,})\""
            ),
            severity=Severity.HIGH,
            confidence="medium",
            kind="secret",
        ),
        SecretPatternSpec(
            pattern_id="env_credential",
            category="config",
            label="Environment Credential",
            regex=re.compile(
                r"(?i)(?:process\.env|os\.environ)\[?\"'?"
                r"([A-Z_]*(?:SECRET|KEY|TOKEN|API_KEY|ACCESS_TOKEN|PASSWORD|PWD))"
                r"\"'?\]?\s*[:=]\s*\"([^\"]{8,})\""
            ),
            severity=Severity.HIGH,
            confidence="medium",
            kind="secret",
        ),
        # ── Diagnostics (not credentials) ──
        SecretPatternSpec(
            pattern_id="stack_trace_with_path",
            category="diagnostic",
            label="Stack Trace with Internal Path",
            regex=re.compile(
                r"(?:at\s+|File\s+\"|Traceback)[^\n]*(?:/app/|/home/|/var/|/src/|\\app\\|\\src\\)[^\n]+"
            ),
            severity=Severity.MEDIUM,
            confidence="medium",
            kind="diagnostic",
        ),
        SecretPatternSpec(
            pattern_id="prisma_invocation",
            category="diagnostic",
            label="Prisma ORM Query Structure",
            regex=re.compile(r"Invalid\s+`prisma\.\w+\.\w+\(\)`\s+invocation", re.IGNORECASE),
            severity=Severity.MEDIUM,
            confidence="medium",
            kind="diagnostic",
        ),
        SecretPatternSpec(
            pattern_id="database_constraint",
            category="diagnostic",
            label="Database Constraint Name",
            regex=re.compile(
                r"(?:Foreign key|Unique) constraint (?:violated|failed) on.*?`([^`]+)`",
                re.IGNORECASE,
            ),
            severity=Severity.LOW,
            confidence="medium",
            kind="diagnostic",
        ),
        SecretPatternSpec(
            pattern_id="azure_openai_endpoint",
            category="diagnostic",
            label="Azure OpenAI Endpoint",
            regex=re.compile(
                r"https://[a-z0-9-]+\.openai\.azure\.com[^\s\"'<>]*",
                re.IGNORECASE,
            ),
            severity=Severity.LOW,
            confidence="low",
            kind="diagnostic",
        ),
    )


SECRET_PATTERNS: tuple[SecretPatternSpec, ...] = _build_patterns()


# ── Configuration ──

_DEFAULT_MAX_TOOLS = 50
_DEFAULT_MAX_PROBES_PER_TOOL = 8
_DEFAULT_MAX_TOTAL_PROBES = 200
_DEFAULT_MAX_RESPONSE_CHARS = 10_000
_DEFAULT_MAX_ARG_CHARS = 512
_DEFAULT_MAX_PAYLOAD_CHARS = 4_096
_DEFAULT_MAX_FINDINGS = 100

_PLACEHOLDER_VALUES = {
    "",
    "test",
    "testing",
    "example",
    "sample",
    "dummy",
    "placeholder",
    "redacted",
    "changeme",
    "password",
    "secret",
    "token",
    "key",
    "admin",
    "user",
    "null",
    "undefined",
    "none",
}

_DANGEROUS_PARAM_NAMES = {
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
    "raw_query",
    "sql_query",
    "eval",
    "system",
    "os_command",
    "terminal",
    "run_command",
    "program",
    "delete",
    "remove",
    "drop",
    "write",
    "overwrite",
    "upload",
    "download",
    "move",
    "copy",
    "destination",
    "action",
    "operation",
}


# ── Schema Helpers ──


def get_tool_schema(tool: dict[str, Any]) -> dict[str, Any]:
    """Normalize MCP tool input schema keys."""
    schema = tool.get("inputSchema") or tool.get("input_schema") or {}
    return schema if isinstance(schema, dict) else {}


def get_schema_properties(schema: dict[str, Any]) -> dict[str, Any]:
    """Return schema properties dict."""
    properties = schema.get("properties", {})
    return properties if isinstance(properties, dict) else {}


def get_schema_required(schema: dict[str, Any]) -> set[str]:
    """Return set of required property names."""
    required = schema.get("required", [])
    return set(required) if isinstance(required, (list, tuple)) else set()


# ── Normalized Observation ──


@dataclass
class NormalizedObservation:
    """A normalized view of one tool invocation result."""

    channel: str
    text: str
    is_error: bool
    exception_type: str | None = None
    trace_entry_id: str | None = None
    original_text_size: int = 0


@dataclass
class D2ProbeResult:
    """Internal result of one D2 probe."""

    tool_name: str
    probe_type: str
    args: dict[str, Any]
    verdict: str = ""
    reason: str = ""
    channel: str = ""
    matches: list[SecretMatch] = field(default_factory=list)
    response: dict[str, Any] | None = None
    exception_type: str | None = None
    trace_entry_id: str | None = None
    original_text_size: int = 0


# ── Safe Argument Generation ──


def _is_placeholder(value: str) -> bool:
    """Return True if the matched value looks like a placeholder/example."""
    lowered = value.strip().lower()
    if lowered in _PLACEHOLDER_VALUES:
        return True
    # Reject obvious documentation placeholders only when they appear as whole
    # tokens, so that real credentials containing substrings such as "EXAMPLE"
    # are not discarded.
    if re.search(
        r"(^|[^a-z0-9])(example|dummy|placeholder|sample|redacted|test|changeme)([^a-z0-9]|$)",
        lowered,
    ):
        return True
    return False


def _is_dangerous_param(name: str, param_schema: dict[str, Any]) -> bool:
    """Return True if the parameter should not be filled automatically."""
    lowered = name.lower()
    if lowered in _DANGEROUS_PARAM_NAMES:
        return True
    # Heuristic: operation-like enum values indicating destructive behavior.
    enum_values = param_schema.get("enum") or []
    if isinstance(enum_values, list) and enum_values:
        destructive_terms = {"delete", "drop", "remove", "write", "overwrite", "execute", "run"}
        if any(str(v).lower() in destructive_terms for v in enum_values):
            return True
    return False


def _safe_default_for_type(param_schema: dict[str, Any]) -> Any:
    """Return a neutral default for a schema property."""
    param_type = param_schema.get("type", "string")
    if param_type == "string":
        return "test"
    if param_type == "integer":
        minimum = param_schema.get("minimum")
        return int(minimum) if isinstance(minimum, (int, float)) else 1
    if param_type == "number":
        minimum = param_schema.get("minimum")
        return float(minimum) if isinstance(minimum, (int, float)) else 1.0
    if param_type == "boolean":
        return False
    if param_type == "array":
        return []
    if param_type == "object":
        return {}
    return "test"


def _safe_value_for_property(
    name: str, param_schema: dict[str, Any], include_optional: bool
) -> tuple[Any, str | None]:
    """
    Generate a safe value for a single schema property.

    Returns (value, reason) where reason is set if the property is dangerous
    and should cause the candidate to be skipped.
    """
    required = param_schema.get("required_in_context", False)  # not used here
    is_required = bool(param_schema.get("_required", False))

    if _is_dangerous_param(name, param_schema):
        if is_required:
            return (None, f"dangerous required parameter '{name}'")
        if not include_optional:
            return (None, None)
        # Dangerous optional is omitted.
        return (None, None)

    if not is_required and not include_optional:
        return (None, None)

    # Prefer default, then example, then enum, then type default.
    default = param_schema.get("default")
    if default is not None:
        return (default, None)

    examples = param_schema.get("examples") or []
    if isinstance(examples, list) and examples:
        return (examples[0], None)

    enum_values = param_schema.get("enum")
    if isinstance(enum_values, list) and enum_values:
        return (enum_values[0], None)

    return (_safe_default_for_type(param_schema), None)


def build_safe_arguments(
    schema: dict[str, Any],
    include_optional: bool = True,
) -> tuple[dict[str, Any], str | None]:
    """
    Build safe arguments from a tool schema.

    Returns (args, reason). If a required sibling is dangerous, reason is set
    and the tool should be marked not_testable.
    """
    properties = get_schema_properties(schema)
    required = get_schema_required(schema)
    args: dict[str, Any] = {}

    for name, param_schema in sorted(properties.items()):
        if not isinstance(param_schema, dict):
            param_schema = {}
        param_schema = {**param_schema, "_required": name in required}
        value, reason = _safe_value_for_property(
            name, param_schema, include_optional=include_optional
        )
        if reason:
            return (None, reason)
        if value is not None:
            args[name] = value

    # Fill any missing required values with neutral defaults.
    for name in required:
        if name not in args:
            param_schema = properties.get(name, {})
            if not isinstance(param_schema, dict):
                param_schema = {}
            args[name] = _safe_default_for_type(param_schema)

    return (args, None)


# ── Adversarial Probe Generation ──


def _truncate_string(value: str, max_len: int = _DEFAULT_MAX_PAYLOAD_CHARS) -> str:
    """Bound a string payload size."""
    if len(value) > max_len:
        return value[:max_len]
    return value


def _wrong_type_value(declared_type: str) -> Any:
    """Return a deliberately wrong-typed value."""
    if declared_type == "string":
        return 12345
    if declared_type == "integer":
        return "not-an-integer"
    if declared_type == "number":
        return "not-a-number"
    if declared_type == "boolean":
        return "not-a-boolean"
    if declared_type == "array":
        return "not-an-array"
    if declared_type == "object":
        return "not-an-object"
    return None


def _malformed_identifier(name: str, declared_type: str) -> str | None:
    """Return an invalid identifier when the property name suggests one."""
    lowered = name.lower()
    if declared_type != "string":
        return None
    if any(term in lowered for term in ("id", "uuid", "ref", "identifier")):
        return "not-a-valid-uuid-0000"
    return None


def _malformed_enum_value(param_schema: dict[str, Any]) -> str | None:
    """Return a value not present in the declared enum."""
    enum_values = param_schema.get("enum")
    if not isinstance(enum_values, list) or not enum_values:
        return None
    candidate = "___d2_invalid_enum_value___"
    if candidate not in enum_values:
        return candidate
    return "___d2_invalid_enum_value_alt___"


def build_probe_plans(
    schema: dict[str, Any],
    max_probes: int = _DEFAULT_MAX_PROBES_PER_TOOL,
) -> list[tuple[str, dict[str, Any]]]:
    """
    Build a deterministic list of (probe_type, args) adversarial probes.

    The first plan is always a safe baseline invocation. Remaining plans are
    bounded, schema-aware mutations intended to trigger validation or
    downstream errors.
    """
    properties = get_schema_properties(schema)
    required = get_schema_required(schema)
    safe_properties = sorted(
        name
        for name in properties
        if not _is_dangerous_param(name, properties.get(name, {}))
    )

    baseline, reason = build_safe_arguments(schema, include_optional=True)
    if baseline is None or not safe_properties:
        return []

    plans: list[tuple[str, dict[str, Any]]] = [("baseline", baseline)]

    def add_plan(probe_type: str, args: dict[str, Any]) -> bool:
        if len(plans) >= max_probes:
            return False
        # Deduplicate exact args.
        if any(existing_args == args for _, existing_args in plans):
            return True
        plans.append((probe_type, args))
        return True

    for name in safe_properties:
        if len(plans) >= max_probes:
            break
        param_schema = properties.get(name, {})
        if not isinstance(param_schema, dict):
            param_schema = {}
        declared_type = param_schema.get("type", "string")

        # Null mutation.
        args_null = dict(baseline)
        args_null[name] = None
        if not add_plan("null_field", args_null):
            break

        # Wrong primitive type.
        wrong = _wrong_type_value(declared_type)
        if wrong is not None:
            args_wrong = dict(baseline)
            args_wrong[name] = wrong
            if not add_plan("wrong_type", args_wrong):
                break

        # Empty value for strings.
        if declared_type == "string":
            args_empty = dict(baseline)
            args_empty[name] = ""
            if not add_plan("empty_string", args_empty):
                break

            # Bounded overlong string.
            args_long = dict(baseline)
            args_long[name] = _truncate_string("A" * 4096)
            if not add_plan("overlong_string", args_long):
                break

            # Malformed identifier.
            invalid_id = _malformed_identifier(name, declared_type)
            if invalid_id:
                args_id = dict(baseline)
                args_id[name] = invalid_id
                if not add_plan("invalid_identifier", args_id):
                    break

        # Invalid enum value.
        invalid_enum = _malformed_enum_value(param_schema)
        if invalid_enum:
            args_enum = dict(baseline)
            args_enum[name] = invalid_enum
            if not add_plan("invalid_enum", args_enum):
                break

        # Invalid structured object.
        if declared_type == "object":
            args_obj = dict(baseline)
            args_obj[name] = "not-a-json-object"
            if not add_plan("invalid_object", args_obj):
                break

        # Missing required field.
        if name in required:
            args_missing = {k: v for k, v in baseline.items() if k != name}
            if not add_plan("missing_required", args_missing):
                break

    return plans


# ── Response/Error Normalization ──


def _is_mcp_error_response(response: dict[str, Any] | None) -> bool:
    """Return True if the response represents an MCP tool error."""
    if response is None:
        return True
    if response.get("isError") or response.get("is_error"):
        return True
    if response.get("result_type") == "error":
        return True
    if response.get("error") is not None:
        return True
    return False


def _extract_text_fragments(value: Any, fragments: set[str]) -> None:
    """Recursively collect unique text fragments from a response structure."""
    if isinstance(value, str):
        fragments.add(value)
        # Also collect a single JSON-unescaped version if applicable.
        if "\\" in value:
            try:
                unescaped = json.loads(value)
                if isinstance(unescaped, str):
                    fragments.add(unescaped)
            except Exception:
                pass
        return
    if isinstance(value, (list, tuple)):
        for item in value:
            _extract_text_fragments(item, fragments)
        return
    if isinstance(value, dict):
        for k, v in value.items():
            # Include keys because they provide context (e.g., api_key).
            if isinstance(k, str):
                fragments.add(k)
            _extract_text_fragments(v, fragments)
        return


def _normalize_response(response: dict[str, Any] | None) -> NormalizedObservation:
    """Normalize an MCP response into a single bounded text observation."""
    is_error = _is_mcp_error_response(response)
    channel = "mcp_error" if is_error else "normal_response"
    fragments: set[str] = set()

    if isinstance(response, dict):
        _extract_text_fragments(response.get("content"), fragments)
        _extract_text_fragments(response.get("error"), fragments)
        _extract_text_fragments(response.get("message"), fragments)
        _extract_text_fragments(response.get("details"), fragments)
        _extract_text_fragments(response.get("stack"), fragments)
        _extract_text_fragments(response.get("cause"), fragments)
        # One pass over the whole response as fallback.
        fragments.add(str(response))

    text = "\n".join(sorted(fragments))
    original_size = len(text)
    if len(text) > _DEFAULT_MAX_RESPONSE_CHARS:
        text = text[:_DEFAULT_MAX_RESPONSE_CHARS]

    return NormalizedObservation(
        channel=channel,
        text=text,
        is_error=is_error,
        original_text_size=original_size,
    )


def _normalize_exception(exc: BaseException) -> NormalizedObservation:
    """Normalize an exception into a text observation."""
    exc_type = type(exc).__name__
    text = f"{exc_type}: {exc}"
    original_size = len(text)
    if len(text) > _DEFAULT_MAX_RESPONSE_CHARS:
        text = text[:_DEFAULT_MAX_RESPONSE_CHARS]
    return NormalizedObservation(
        channel="exception",
        text=text,
        is_error=True,
        exception_type=exc_type,
        original_text_size=original_size,
    )


# ── Secret Scanning & Redaction ──


def _looks_like_valid_jwt(header_b64: str) -> bool:
    """Quick structural check that a JWT header segment decodes to JSON with alg."""
    try:
        padded = header_b64 + "=" * (-len(header_b64) % 4)
        decoded = base64.urlsafe_b64decode(padded)
        header = json.loads(decoded)
        return isinstance(header, dict) and "alg" in header
    except Exception:
        return False


def _redact_match(matched_value: str, pattern: SecretPatternSpec) -> str:
    """Return a redacted representation of a matched secret."""
    if pattern.redact_mode == "db_password":
        # Preserve user and host; redact password.
        redacted = re.sub(
            r"(?i)^([a-z]+://[^:/]+):[^@]+(@.*)$",
            r"\1:[REDACTED]\2",
            matched_value,
        )
        return redacted
    if pattern.redact_mode == "azure_key":
        redacted = re.sub(
            r"(?i)(AccountKey=)[^;\s]+",
            r"\1[REDACTED]",
            matched_value,
        )
        return redacted
    return f"<redacted:{pattern.pattern_id}:length={len(matched_value)}>"


def _scan_text(text: str) -> list[SecretMatch]:
    """Scan normalized text for secret patterns."""
    matches: list[SecretMatch] = []
    for pattern in SECRET_PATTERNS:
        for m in pattern.regex.finditer(text):
            matched_value = m.group(0)
            start, end = m.start(), m.end()
            confidence = pattern.confidence

            # Placeholder filtering for secret patterns.
            if pattern.kind == "secret" and _is_placeholder(matched_value):
                continue

            # JWT structural validation.
            if pattern.pattern_id == "jwt_token":
                parts = matched_value.split(".")
                if len(parts) >= 3 and not _looks_like_valid_jwt(parts[0]):
                    confidence = "low"

            redacted_value = _redact_match(matched_value, pattern)
            matches.append(
                SecretMatch(
                    pattern_id=pattern.pattern_id,
                    category=pattern.category,
                    label=pattern.label,
                    severity=pattern.severity,
                    confidence=confidence,
                    kind=pattern.kind,
                    start=start,
                    end=end,
                    matched_value=matched_value,
                    redacted_value=redacted_value,
                )
            )

    # Sort and remove overlapping matches, preferring secrets over diagnostics
    # and higher confidence / earlier start.
    matches.sort(key=lambda x: (x.start, 0 if x.kind == "secret" else 1, x.confidence))
    filtered: list[SecretMatch] = []
    last_end = -1
    for match in matches:
        if match.start >= last_end:
            filtered.append(match)
            last_end = match.end
    return filtered


def _verdict_for_match(match: SecretMatch) -> str:
    """Map a match to a verdict."""
    if match.kind == "diagnostic":
        return VERDICT_CONFIRMED_DIAGNOSTIC
    if match.confidence == "high":
        return VERDICT_CONFIRMED_SECRET
    return VERDICT_SUSPECTED_SECRET


def _redact_text(text: str, matches: list[SecretMatch]) -> str:
    """Build a redacted version of text using the match redacted values."""
    if not matches:
        return text
    # Matches are non-overlapping and sorted.
    parts: list[str] = []
    pos = 0
    for match in matches:
        parts.append(text[pos : match.start])
        parts.append(match.redacted_value)
        pos = match.end
    parts.append(text[pos:])
    return "".join(parts)


def _severity_for_verdict(verdict: str, pattern_severity: Severity) -> Severity:
    """Adjust severity for suspected or diagnostic findings."""
    if verdict == VERDICT_CONFIRMED_SECRET:
        return pattern_severity
    if verdict == VERDICT_SUSPECTED_SECRET:
        if pattern_severity == Severity.CRITICAL:
            return Severity.HIGH
        if pattern_severity == Severity.HIGH:
            return Severity.MEDIUM
        return Severity.LOW
    if verdict == VERDICT_CONFIRMED_DIAGNOSTIC:
        if pattern_severity in (Severity.CRITICAL, Severity.HIGH):
            return Severity.MEDIUM
        return pattern_severity
    return Severity.INFO


# ── Trace Correlation ──


def _find_exact_trace_id(
    traces: list[Any], tool_name: str, args: dict[str, Any]
) -> str | None:
    """Return the trace ID of the most recent exact matching tool call."""
    for trace in reversed(traces):
        if getattr(trace, "method", None) != "tools/call":
            continue
        request = getattr(trace, "request", {}) or {}
        if request.get("name") == tool_name and request.get("arguments") == args:
            return getattr(trace, "id", None)
    return None


# ── D2 Module ──


class D2APIKeyStealing(AttackModule):
    """Probe error channels for API keys, secrets, and infrastructure leakage."""

    name = "API Key & Secret Extraction via Error Channels"
    surface = "D - Data Flow & Exfiltration"
    module_id = "D2"
    description = (
        "Deterministic, schema-aware secret disclosure detection. Sends bounded "
        "adversarial probes, normalizes responses and exceptions, and reports "
        "redacted evidence for leaked credentials."
    )

    def __init__(
        self,
        engine: Any,
        max_tools: int = _DEFAULT_MAX_TOOLS,
        max_probes_per_tool: int = _DEFAULT_MAX_PROBES_PER_TOOL,
        max_total_probes: int = _DEFAULT_MAX_TOTAL_PROBES,
        max_response_chars: int = _DEFAULT_MAX_RESPONSE_CHARS,
        max_payload_chars: int = _DEFAULT_MAX_PAYLOAD_CHARS,
        max_findings: int = _DEFAULT_MAX_FINDINGS,
    ) -> None:
        super().__init__(engine)
        self.max_tools = max_tools
        self.max_probes_per_tool = max_probes_per_tool
        self.max_total_probes = max_total_probes
        self.max_response_chars = max_response_chars
        self.max_payload_chars = max_payload_chars
        self.max_findings = max_findings

        self.stats: dict[str, int] = {
            "attempted": 0,
            "skipped": 0,
            "failed": 0,
            "inconclusive": 0,
            "confirmed_secret": 0,
            "suspected_secret": 0,
            "confirmed_diagnostic": 0,
        }
        self.probe_results: list[D2ProbeResult] = []

    async def run(self) -> list[Finding]:
        """Execute deterministic secret-extraction probes."""
        self.findings.clear()
        self._finding_counter = 0
        self.stats = {
            "attempted": 0,
            "skipped": 0,
            "failed": 0,
            "inconclusive": 0,
            "confirmed_secret": 0,
            "suspected_secret": 0,
            "confirmed_diagnostic": 0,
        }
        self.probe_results = []

        tools = await self._get_tools()
        if not tools:
            return self.findings

        # Deterministic ordering.
        tools = sorted(tools, key=lambda t: str(t.get("name", "")))
        tools = tools[: self.max_tools]

        total_probes = 0
        stop_outer = False

        for tool in tools:
            if stop_outer:
                break

            tool_name = str(tool.get("name", ""))
            if not tool_name:
                continue

            schema = get_tool_schema(tool)
            properties = get_schema_properties(schema)

            # Skip tools with no usable schema or only dangerous parameters.
            if not properties:
                self.stats["skipped"] += 1
                self.probe_results.append(
                    D2ProbeResult(
                        tool_name=tool_name,
                        probe_type="none",
                        args={},
                        verdict=VERDICT_NOT_TESTABLE,
                        reason="tool has no usable input schema",
                    )
                )
                continue

            # Check for dangerous required siblings before generating probes.
            required = get_schema_required(schema)
            dangerous_required = [
                name
                for name in required
                if _is_dangerous_param(name, properties.get(name, {}))
            ]
            if dangerous_required:
                self.stats["skipped"] += 1
                self.probe_results.append(
                    D2ProbeResult(
                        tool_name=tool_name,
                        probe_type="none",
                        args={},
                        verdict=VERDICT_NOT_TESTABLE,
                        reason=f"dangerous required parameter(s): {', '.join(dangerous_required)}",
                    )
                )
                continue

            plans = build_probe_plans(schema, max_probes=self.max_probes_per_tool)
            if not plans:
                self.stats["skipped"] += 1
                self.probe_results.append(
                    D2ProbeResult(
                        tool_name=tool_name,
                        probe_type="none",
                        args={},
                        verdict=VERDICT_NOT_TESTABLE,
                        reason="could not generate safe probe plans",
                    )
                )
                continue

            for probe_type, args in plans:
                if total_probes >= self.max_total_probes:
                    stop_outer = True
                    break

                total_probes += 1
                self.stats["attempted"] += 1

                observation, response = await self._invoke(tool_name, args)
                observation.trace_entry_id = _find_exact_trace_id(
                    getattr(self.engine, "traces", []), tool_name, args
                )

                matches = _scan_text(observation.text)

                if not matches:
                    self.stats["inconclusive"] += 1
                    self.probe_results.append(
                        D2ProbeResult(
                            tool_name=tool_name,
                            probe_type=probe_type,
                            args=args,
                            verdict=VERDICT_INCONCLUSIVE,
                            reason="no secret pattern matched",
                            channel=observation.channel,
                            response=response,
                            exception_type=observation.exception_type,
                            trace_entry_id=observation.trace_entry_id,
                            original_text_size=observation.original_text_size,
                        )
                    )
                    continue

                # Use the highest-confidence secret verdict among matches.
                verdicts = {_verdict_for_match(m) for m in matches}
                if VERDICT_CONFIRMED_SECRET in verdicts:
                    verdict = VERDICT_CONFIRMED_SECRET
                    self.stats["confirmed_secret"] += 1
                elif VERDICT_SUSPECTED_SECRET in verdicts:
                    verdict = VERDICT_SUSPECTED_SECRET
                    self.stats["suspected_secret"] += 1
                else:
                    verdict = VERDICT_CONFIRMED_DIAGNOSTIC
                    self.stats["confirmed_diagnostic"] += 1

                self.probe_results.append(
                    D2ProbeResult(
                        tool_name=tool_name,
                        probe_type=probe_type,
                        args=args,
                        verdict=verdict,
                        reason=f"matched {len(matches)} pattern(s)",
                        channel=observation.channel,
                        matches=matches,
                        response=response,
                        exception_type=observation.exception_type,
                        trace_entry_id=observation.trace_entry_id,
                        original_text_size=observation.original_text_size,
                    )
                )

        self._aggregate_findings()
        return self.findings

    async def _get_tools(self) -> list[dict[str, Any]]:
        """Return tools from Phase 0 context or live discovery."""
        phase0 = self.get_phase0_context()
        tools = phase0.get("tools") if isinstance(phase0, dict) else None
        if isinstance(tools, list) and tools:
            return tools
        try:
            return await self.engine.list_tools()
        except Exception:
            return []

    async def _invoke(
        self, tool_name: str, args: dict[str, Any]
    ) -> tuple[NormalizedObservation, dict[str, Any] | None]:
        """Call a tool and return normalized observation plus raw response."""
        try:
            response = await self.engine.call_tool(tool_name, args)
            observation = _normalize_response(response)
            return observation, response
        except Exception as exc:
            observation = _normalize_exception(exc)
            return observation, {"error": str(exc)}

    def _aggregate_findings(self) -> None:
        """Aggregate probe results into findings by (tool, pattern_id)."""
        # Group confirmed/suspected/diagnostic observations by tool+pattern.
        groups: dict[tuple[str, str], list[D2ProbeResult]] = {}
        for result in self.probe_results:
            if result.verdict in (
                VERDICT_INCONCLUSIVE,
                VERDICT_NOT_TESTABLE,
                VERDICT_NOT_RUN,
            ):
                continue
            if not result.matches:
                continue
            for match in result.matches:
                key = (result.tool_name, match.pattern_id)
                groups.setdefault(key, []).append(result)

        for (tool_name, pattern_id), results in sorted(groups.items()):
            if len(self.findings) >= self.max_findings:
                break

            # Use the first result to extract pattern metadata.
            first_match = next(
                m for r in results for m in r.matches if m.pattern_id == pattern_id
            )
            verdict = first_match.kind == "diagnostic" and VERDICT_CONFIRMED_DIAGNOSTIC
            # Determine worst verdict in the group.
            group_verdicts = set()
            for r in results:
                for m in r.matches:
                    if m.pattern_id == pattern_id:
                        group_verdicts.add(_verdict_for_match(m))
            if VERDICT_CONFIRMED_SECRET in group_verdicts:
                verdict = VERDICT_CONFIRMED_SECRET
            elif VERDICT_SUSPECTED_SECRET in group_verdicts:
                verdict = VERDICT_SUSPECTED_SECRET
            else:
                verdict = VERDICT_CONFIRMED_DIAGNOSTIC

            severity = _severity_for_verdict(verdict, first_match.severity)

            evidence_items: list[Evidence] = []
            seen_observations: set[str] = set()
            for result in results:
                # Deduplicate observations by a simple fingerprint.
                fingerprint = (
                    f"{result.probe_type}:{result.channel}:"
                    f"{result.exception_type or ''}:{str(result.args)}"
                )
                if fingerprint in seen_observations:
                    continue
                seen_observations.add(fingerprint)

                observation_text = ""
                if result.response is not None:
                    observation_text = _normalize_response(result.response).text
                elif result.exception_type:
                    observation_text = f"{result.exception_type}: <exception>"

                # Redact all matches in this observation for the excerpt.
                all_matches = _scan_text(observation_text)
                redacted_excerpt = _redact_text(observation_text, all_matches)
                if len(redacted_excerpt) > self.max_response_chars:
                    redacted_excerpt = (
                        redacted_excerpt[: self.max_response_chars] + "... [truncated]"
                    )

                match_meta = [
                    {
                        "pattern_id": m.pattern_id,
                        "category": m.category,
                        "label": m.label,
                        "confidence": m.confidence,
                        "kind": m.kind,
                        "match_length": len(m.matched_value),
                        "redacted_match": m.redacted_value,
                    }
                    for m in result.matches
                    if m.pattern_id == pattern_id
                ]

                evidence_items.append(
                    Evidence(
                        type=EvidenceType.TOOL_INVOCATION,
                        request={
                            "tool": tool_name,
                            "arguments": _truncate_args(result.args),
                            "probe_type": result.probe_type,
                            "channel": result.channel,
                            "verdict": verdict,
                        },
                        response={
                            "channel": result.channel,
                            "is_error": result.channel
                            in ("mcp_error", "exception"),
                            "exception_type": result.exception_type,
                            "redacted_excerpt": redacted_excerpt,
                            "match": match_meta[0] if match_meta else {},
                            "truncated": result.original_text_size
                            > self.max_response_chars,
                        },
                        trace_entry_id=result.trace_entry_id,
                    )
                )

            if not evidence_items:
                continue

            labels = sorted({m.label for r in results for m in r.matches})
            title = (
                f"Secret leaked in {tool_name}"
                if first_match.kind == "secret"
                else f"Diagnostic disclosure in {tool_name}"
            )

            description = (
                f"Tool '{tool_name}' exposed {first_match.label} "
                f"({verdict}) across {len(evidence_items)} probe(s). "
                f"Detected categories: {', '.join(labels)}."
            )

            attack_narrative = (
                "1. Discovered tool via Phase 0 / tools/list\n"
                f"2. Generated schema-aware probes for '{tool_name}'\n"
                f"3. Executed {len(evidence_items)} probe observation(s)\n"
                f"4. Detected pattern '{pattern_id}' ({first_match.label})\n"
                f"5. Verdict: {verdict}\n"
                "6. Redacted matched material before storing evidence"
            )

            self.add_finding(
                Finding(
                    id=self._next_finding_id(),
                    title=title,
                    surface=self.surface,
                    module=f"{self.module_id} - {self.name}",
                    severity=severity,
                    fixability=Fixability.CONFIGURATION,
                    fixability_rationale=(
                        "Sensitive material reached the MCP client through a tool "
                        "response or error channel. Sanitize error output and avoid "
                        "returning raw credentials or diagnostic details to clients."
                    ),
                    description=description,
                    attack_narrative=attack_narrative,
                    evidence=evidence_items,
                    replay=ReplayInfo(
                        command=(
                            f"mcp-redteam replay --finding {self.module_id}-"
                            f"{self._finding_counter:03d} "
                            f"--target {self.engine.config.endpoint_url}"
                        ),
                        trace_file=(
                            f"traces/{self.module_id}-{self._finding_counter:03d}.json"
                        ),
                    ),
                    recommendation=(
                        "1. Strip credentials and internal diagnostics from tool "
                        "responses and exceptions before returning them to MCP clients. "
                        "2. Use generic error messages on the client boundary and log "
                        "details server-side only. "
                        "3. Rotate any credentials observed in scan output."
                    ),
                )
            )


def _truncate_args(args: dict[str, Any], max_len: int = _DEFAULT_MAX_ARG_CHARS) -> dict[str, Any]:
    """Return a shallow copy of args with overlong string values truncated."""
    truncated: dict[str, Any] = {}
    for k, v in args.items():
        if isinstance(v, str) and len(v) > max_len:
            truncated[k] = v[:max_len] + "... [truncated]"
        else:
            truncated[k] = v
    return truncated
