"""
B5 — Error Information Disclosure.

Deterministic, schema-aware adversarial probing that intentionally triggers
validation, application, and downstream errors in MCP tools, then inspects all
error channels for meaningful internal implementation or infrastructure
disclosure.

B5 does NOT detect credentials/secrets (D2 owns that) and does NOT run
specialized injection payloads (B1/B2/B3/S1 own those).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

from src.attack_base import AttackModule
from src.models import Evidence, EvidenceType, Fixability, Finding, ReplayInfo, Severity


# ── Verdicts ──

VERDICT_CONFIRMED_DISCLOSURE = "confirmed_disclosure"
VERDICT_SUSPECTED_DISCLOSURE = "suspected_disclosure"
VERDICT_INCONCLUSIVE = "inconclusive"
VERDICT_NOT_TESTABLE = "not_testable"
VERDICT_NOT_RUN = "not_run"


# ── Configuration ──

_DEFAULT_MAX_TOOLS = 20
_DEFAULT_MAX_PROBES_PER_TOOL = 6
_DEFAULT_MAX_TOTAL_PROBES = 100
_DEFAULT_MAX_RESPONSE_CHARS = 10_000
_DEFAULT_MAX_ARG_CHARS = 512
_DEFAULT_MAX_PAYLOAD_CHARS = 4_096
_DEFAULT_MAX_FINDINGS = 100

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


# ── Structured Disclosure Patterns ──

@dataclass(frozen=True)
class DisclosurePatternSpec:
    """Metadata for a single disclosure detector pattern."""

    pattern_id: str
    family: str
    label: str
    regex: re.Pattern
    severity: Severity
    confidence: str  # high | medium | low


@dataclass
class DisclosureMatch:
    """A single pattern match in normalized text."""

    pattern_id: str
    family: str
    label: str
    severity: Severity
    confidence: str
    start: int
    end: int
    matched_value: str


# ── Pattern Registry ──


def _build_patterns() -> tuple[DisclosurePatternSpec, ...]:
    return (
        # A. Stack/source disclosure
        DisclosurePatternSpec(
            pattern_id="python_stack_trace",
            family="stack_trace_source",
            label="Python Traceback with Source Path",
            regex=re.compile(
                r"Traceback \(most recent call last\):[\s\S]*?File \"([^\"]+)\", line \d+",
                re.IGNORECASE,
            ),
            severity=Severity.HIGH,
            confidence="high",
        ),
        DisclosurePatternSpec(
            pattern_id="node_stack_trace",
            family="stack_trace_source",
            label="Node.js Stack Frame with Source Path",
            regex=re.compile(
                r"at .*?\((?:/[^:)]+|\w:\\[^:)]+):\d+:\d+\)"
            ),
            severity=Severity.HIGH,
            confidence="high",
        ),
        DisclosurePatternSpec(
            pattern_id="java_stack_trace",
            family="stack_trace_source",
            label="Java Stack Frame",
            regex=re.compile(
                r"at [a-z][\w.$]*\([\w]+\.java:\d+\)"
            ),
            severity=Severity.HIGH,
            confidence="high",
        ),
        DisclosurePatternSpec(
            pattern_id="dotnet_stack_trace",
            family="stack_trace_source",
            label=".NET Stack Trace with Source Path",
            regex=re.compile(
                r"at .+ in (?:/[^:]+%s[^:]*|[a-zA-Z]:\\[^:]+%s[^:]*)\.\w+:\d+"
                % ("(?:cs|vb|fs)", "(?:cs|vb|fs)")
            ),
            severity=Severity.HIGH,
            confidence="high",
        ),
        DisclosurePatternSpec(
            pattern_id="go_panic",
            family="stack_trace_source",
            label="Go Panic with Source Path",
            regex=re.compile(
                r"panic: [\s\S]*?(/[^:\s]+\.go:\d+)"
            ),
            severity=Severity.HIGH,
            confidence="high",
        ),
        DisclosurePatternSpec(
            pattern_id="rust_panic",
            family="stack_trace_source",
            label="Rust Panic with Source Path",
            regex=re.compile(
                r"thread '[^']+' panicked at[\s\S]*?(/[^:\s]+\.rs:\d+)"
            ),
            severity=Severity.HIGH,
            confidence="high",
        ),
        # B. Source paths
        DisclosurePatternSpec(
            pattern_id="unix_source_path",
            family="source_path",
            label="Unix Application Source Path",
            regex=re.compile(
                r"(?:^|[^\w/\\.])(/app/|/workspace/|/home/|/opt/|/srv/|/usr/src/|/var/app/|/var/www/|/usr/local/|/etc/)[^\s\"'<>]+(?:\.[a-z]{2,6})?",
                re.IGNORECASE,
            ),
            severity=Severity.MEDIUM,
            confidence="medium",
        ),
        DisclosurePatternSpec(
            pattern_id="windows_source_path",
            family="source_path",
            label="Windows Application Source Path",
            regex=re.compile(
                r"(?:^|[^\w:])([a-zA-Z]:\\(?:Users|Program Files|ProgramData|Windows|App|Workspace|Src|Inetpub|Var)[^\\]*\\[^\s\"'<>]+\.[a-z]{2,6})",
                re.IGNORECASE,
            ),
            severity=Severity.MEDIUM,
            confidence="medium",
        ),
        # C. SQL / database schema
        DisclosurePatternSpec(
            pattern_id="sql_state",
            family="sql_schema",
            label="SQLSTATE Code",
            regex=re.compile(
                r"\bSQLSTATE\s+[0-9A-Z]{5}\b", re.IGNORECASE
            ),
            severity=Severity.HIGH,
            confidence="high",
        ),
        DisclosurePatternSpec(
            pattern_id="sql_relation_missing",
            family="sql_schema",
            label="Missing SQL Relation",
            regex=re.compile(
                r"(?i)relation\s+[`\"']?(\w+)[`\"']?\s+does\s+not\s+exist"
            ),
            severity=Severity.HIGH,
            confidence="high",
        ),
        DisclosurePatternSpec(
            pattern_id="sql_column_missing",
            family="sql_schema",
            label="Missing SQL Column",
            regex=re.compile(
                r"(?i)column\s+[`\"']?(\w+)[`\"']?\s+(?:does\s+not\s+exist|not\s+found|unknown)"
            ),
            severity=Severity.HIGH,
            confidence="high",
        ),
        DisclosurePatternSpec(
            pattern_id="sql_table_missing",
            family="sql_schema",
            label="Missing SQL Table",
            regex=re.compile(
                r"(?i)table\s+[`\"']?(\w+)[`\"']?\s+(?:does\s+not\s+exist|not\s+found)"
            ),
            severity=Severity.HIGH,
            confidence="high",
        ),
        DisclosurePatternSpec(
            pattern_id="sql_schema_missing",
            family="sql_schema",
            label="Missing SQL Schema",
            regex=re.compile(
                r"(?i)schema\s+[`\"']?(\w+)[`\"']?\s+(?:does\s+not\s+exist|not\s+found)"
            ),
            severity=Severity.HIGH,
            confidence="high",
        ),
        DisclosurePatternSpec(
            pattern_id="sql_query_fragment",
            family="sql_schema",
            label="SQL Query Fragment",
            regex=re.compile(
                r"(?i)(?:SELECT|INSERT|UPDATE|DELETE|FROM|JOIN|WHERE)\s+[\w\s,`\"']+\s+(?:FROM|JOIN|INTO|WHERE|VALUES)\s+[`\"']?(\w+)"
            ),
            severity=Severity.MEDIUM,
            confidence="medium",
        ),
        # D. ORM internals
        DisclosurePatternSpec(
            pattern_id="prisma_invocation",
            family="orm_internal",
            label="Prisma ORM Invocation",
            regex=re.compile(
                r"Invalid\s+`prisma\.\w+\.\w+\(\)`\s+invocation",
                re.IGNORECASE,
            ),
            severity=Severity.MEDIUM,
            confidence="medium",
        ),
        DisclosurePatternSpec(
            pattern_id="sqlalchemy_error",
            family="orm_internal",
            label="SQLAlchemy Internal Error",
            regex=re.compile(
                r"(?i)sqlalchemy\.\w*error"
            ),
            severity=Severity.MEDIUM,
            confidence="medium",
        ),
        DisclosurePatternSpec(
            pattern_id="django_db_error",
            family="orm_internal",
            label="Django DB Internal Error",
            regex=re.compile(
                r"Django\.db\.utils\.\w+Error"
            ),
            severity=Severity.MEDIUM,
            confidence="medium",
        ),
        DisclosurePatternSpec(
            pattern_id="typeorm_query_failed",
            family="orm_internal",
            label="TypeORM Query Failed",
            regex=re.compile(
                r"TypeORMQueryFailedError"
            ),
            severity=Severity.MEDIUM,
            confidence="medium",
        ),
        # E. Internal network
        DisclosurePatternSpec(
            pattern_id="private_ip_connection",
            family="internal_network",
            label="Private IP in Backend Connection Context",
            regex=re.compile(
                r"(?i)(?:connect(?:ion)?|upstream|backend|database|redis|service|host|endpoint)\b.*?"
                r"\b((?:10(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}|"
                r"172\.(?:1[6-9]|2\d|3[01])(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){2}|"
                r"192\.168(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){2})(?::\d+)?)\b"
            ),
            severity=Severity.HIGH,
            confidence="high",
        ),
        DisclosurePatternSpec(
            pattern_id="internal_hostname_connection",
            family="internal_network",
            label="Internal Hostname in Backend Context",
            regex=re.compile(
                r"(?i)(?:connect(?:ion)?|upstream|backend|database|redis|service|host|endpoint)\b.*?"
                r"\b([a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:internal|corp|local|lan|svc\.cluster\.local))\b"
            ),
            severity=Severity.MEDIUM,
            confidence="medium",
        ),
        DisclosurePatternSpec(
            pattern_id="kubernetes_service_name",
            family="internal_network",
            label="Kubernetes Service Name",
            regex=re.compile(
                r"\b([a-z0-9-]+\.[a-z0-9-]+\.svc\.cluster\.local)\b",
                re.IGNORECASE,
            ),
            severity=Severity.MEDIUM,
            confidence="medium",
        ),
        # F. Internal endpoint
        DisclosurePatternSpec(
            pattern_id="internal_endpoint_url",
            family="internal_endpoint",
            label="Internal Endpoint URL",
            regex=re.compile(
                r"(?i)https?://"
                r"((?:10(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}|"
                r"172\.(?:1[6-9]|2\d|3[01])(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){2}|"
                r"192\.168(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){2}|"
                r"[a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:internal|corp|local|svc\.cluster\.local))"
                r"[^\s\"'<>]*)"
            ),
            severity=Severity.MEDIUM,
            confidence="medium",
        ),
        # G. Runtime / dependency
        DisclosurePatternSpec(
            pattern_id="runtime_version",
            family="runtime_dependency",
            label="Runtime Version Disclosure",
            regex=re.compile(
                r"(?i)(?:node\.js|python[/ ]|ruby |go |java |php )\s*(?:v(?:ersion)?)?\s*[\d.]+"
            ),
            severity=Severity.LOW,
            confidence="low",
        ),
        DisclosurePatternSpec(
            pattern_id="framework_version",
            family="runtime_dependency",
            label="Framework Version Disclosure",
            regex=re.compile(
                r"(?i)(?:django|flask|fastapi|express|nestjs|rails|spring boot|laravel|dotnet)\s*(?:v(?:ersion)?)?\s*[\d.]+"
            ),
            severity=Severity.LOW,
            confidence="low",
        ),
        DisclosurePatternSpec(
            pattern_id="dependency_module",
            family="runtime_dependency",
            label="Dependency Module Version",
            regex=re.compile(
                r"(?i)(?:module|package|library)\s+[`\"']?(@?[\w/-]+)[`\"']?\s*(?:v(?:ersion)?)?\s*[\d.]+"
            ),
            severity=Severity.LOW,
            confidence="low",
        ),
        # H. Configuration / deployment
        DisclosurePatternSpec(
            pattern_id="config_file_path",
            family="configuration_deployment",
            label="Configuration File Path",
            regex=re.compile(
                r"(?i)(?:loading|reading|parsing|config|configuration|file)\s+[`\"']?"
                r"(/[^`\"'<>]+\.(?:yml|yaml|json|toml|ini|conf|config|env|properties))"
                r"[`\"']?"
            ),
            severity=Severity.MEDIUM,
            confidence="medium",
        ),
        DisclosurePatternSpec(
            pattern_id="deployment_context",
            family="configuration_deployment",
            label="Deployment Context Identifier",
            regex=re.compile(
                r"(?i)(?:region|cluster|namespace|environment|deployment|stage)\s*(?:=|:)\s*[`\"']?([\w-]+)[`\"']?"
            ),
            severity=Severity.LOW,
            confidence="low",
        ),
        # I. Authorization implementation
        DisclosurePatternSpec(
            pattern_id="auth_handler_path",
            family="authorization_implementation",
            label="Authorization Handler Source Path",
            regex=re.compile(
                r"(?i)(?:auth|authorize|authorization|tenant|permission|policy|guard|rbac|role).*?"
                r"(?:file|path|at|in)\s+[`\"']?(/[^`\"'<>]+\.(?:py|js|ts|java|cs|go|rs))[`\"']?"
            ),
            severity=Severity.HIGH,
            confidence="high",
        ),
        DisclosurePatternSpec(
            pattern_id="auth_policy_name",
            family="authorization_implementation",
            label="Authorization Policy Name",
            regex=re.compile(
                r"(?i)(?:policy|middleware|guard|handler)\s+[`\"']?(\w*[\w\s]*?(?:auth|tenant|permission|role|guard))[`\"']?"
            ),
            severity=Severity.MEDIUM,
            confidence="medium",
        ),
        # J. Infrastructure context
        DisclosurePatternSpec(
            pattern_id="infrastructure_identifier",
            family="infrastructure_context",
            label="Infrastructure Identifier",
            regex=re.compile(
                r"(?i)(?:pod|node|cluster|namespace|region|service|instance)\s*(?:name|id)?\s*(?:=|:)\s*[`\"']?([\w-]+)[`\"']?"
            ),
            severity=Severity.LOW,
            confidence="low",
        ),
    )


DISCLOSURE_PATTERNS: tuple[DisclosurePatternSpec, ...] = _build_patterns()


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


# ── Observation Models ──


@dataclass
class DisclosureObservation:
    """A normalized view of one tool invocation result."""

    channel: str
    text: str
    is_error: bool
    exception_type: str | None = None
    trace_entry_id: str | None = None
    original_text_size: int = 0


@dataclass
class B5ProbeResult:
    """Internal result of one B5 probe."""

    tool_name: str
    probe_type: str
    args: dict[str, Any]
    verdict: str = ""
    reason: str = ""
    channel: str = ""
    matches: list[DisclosureMatch] = field(default_factory=list)
    response: dict[str, Any] | None = None
    exception_type: str | None = None
    trace_entry_id: str | None = None
    original_text_size: int = 0


# ── Safe Argument Generation ──


def _is_dangerous_param(name: str, param_schema: dict[str, Any]) -> bool:
    """Return True if the parameter should not be filled automatically."""
    lowered = name.lower()
    if lowered in _DANGEROUS_PARAM_NAMES:
        return True
    enum_values = param_schema.get("enum") or []
    if isinstance(enum_values, list) and enum_values:
        destructive_terms = {"delete", "drop", "remove", "write", "overwrite", "execute", "run"}
        if any(str(v).lower() in destructive_terms for v in enum_values):
            return True
    return False


def _safe_default_for_type(param_schema: dict[str, Any], depth: int = 0) -> Any:
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
        if depth < 2:
            items = param_schema.get("items")
            if isinstance(items, dict):
                return [_safe_default_for_type(items, depth + 1)]
        return []
    if param_type == "object":
        if depth < 2:
            properties = param_schema.get("properties", {})
            required = set(param_schema.get("required", []))
            obj: dict[str, Any] = {}
            for name, sub_schema in sorted(properties.items()):
                if not isinstance(sub_schema, dict):
                    sub_schema = {}
                if name in required:
                    obj[name] = _safe_default_for_type(sub_schema, depth + 1)
            return obj
        return {}
    return "test"


def _safe_value_for_property(
    name: str, param_schema: dict[str, Any], is_required: bool, include_optional: bool
) -> tuple[Any, str | None]:
    """
    Generate a safe value for a single schema property.

    Returns (value, reason) where reason is set if the property is dangerous
    and required, causing the tool to be marked not_testable.
    """
    if _is_dangerous_param(name, param_schema):
        if is_required:
            return (None, f"dangerous required parameter '{name}'")
        if not include_optional:
            return (None, None)
        return (None, None)

    if not is_required and not include_optional:
        return (None, None)

    default = param_schema.get("default")
    if default is not None:
        return (default, None)

    examples = param_schema.get("examples") or []
    if isinstance(examples, list) and examples:
        return (examples[0], None)

    example = param_schema.get("example")
    if example is not None:
        return (example, None)

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
        value, reason = _safe_value_for_property(
            name, param_schema, is_required=name in required, include_optional=include_optional
        )
        if reason:
            return (None, reason)
        if value is not None:
            args[name] = value

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
    return value[:max_len] if len(value) > max_len else value


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
    if declared_type != "string":
        return None
    lowered = name.lower()
    if any(term in lowered for term in ("id", "uuid", "ref", "identifier")):
        return "not-a-valid-uuid-0000"
    return None


def _invalid_enum_value(param_schema: dict[str, Any]) -> str | None:
    """Return a value not present in the declared enum."""
    enum_values = param_schema.get("enum")
    if not isinstance(enum_values, list) or not enum_values:
        return None
    candidate = "___b5_invalid_enum_value___"
    return "___b5_invalid_enum_value_alt___" if candidate in enum_values else candidate


def _out_of_range_value(param_schema: dict[str, Any]) -> Any | None:
    """Return a numeric value outside declared min/max bounds."""
    param_type = param_schema.get("type", "")
    if param_type not in ("integer", "number"):
        return None
    minimum = param_schema.get("minimum")
    maximum = param_schema.get("maximum")
    if maximum is not None:
        return maximum + 1
    if minimum is not None:
        return minimum - 1
    return None


def _param_priority(name: str, param_schema: dict[str, Any], required: set[str]) -> int:
    """Lower numbers are probed first."""
    if name in required:
        return 0
    if param_schema.get("enum") or param_schema.get("format"):
        return 1
    lowered = name.lower()
    if any(term in lowered for term in ("id", "uuid", "ref", "identifier")):
        return 2
    if param_schema.get("type") == "object":
        return 3
    return 4


def _generate_field_mutations(
    name: str,
    param_schema: dict[str, Any],
    baseline: dict[str, Any],
    is_required: bool,
) -> list[tuple[str, dict[str, Any]]]:
    """Yield mutation plans for a single field in priority order."""
    declared_type = param_schema.get("type", "string")
    plans: list[tuple[str, dict[str, Any]]] = []

    # 1. null mutation
    args_null = dict(baseline)
    args_null[name] = None
    plans.append(("null_field", args_null))

    # 2. wrong primitive type
    wrong = _wrong_type_value(declared_type)
    if wrong is not None:
        args_wrong = dict(baseline)
        args_wrong[name] = wrong
        plans.append(("wrong_type", args_wrong))

    # 3. invalid enum value
    invalid_enum = _invalid_enum_value(param_schema)
    if invalid_enum is not None:
        args_enum = dict(baseline)
        args_enum[name] = invalid_enum
        plans.append(("invalid_enum", args_enum))

    # 4. string-specific mutations
    if declared_type == "string":
        args_empty = dict(baseline)
        args_empty[name] = ""
        plans.append(("empty_string", args_empty))

        args_long = dict(baseline)
        args_long[name] = _truncate_string("A" * 4096)
        plans.append(("overlong_string", args_long))

        invalid_id = _malformed_identifier(name, declared_type)
        if invalid_id:
            args_id = dict(baseline)
            args_id[name] = invalid_id
            plans.append(("invalid_identifier", args_id))

    # 5. invalid structured object
    if declared_type == "object":
        args_obj = dict(baseline)
        args_obj[name] = "not-a-json-object"
        plans.append(("invalid_object", args_obj))

    # 6. out-of-range numeric value
    out_of_range = _out_of_range_value(param_schema)
    if out_of_range is not None:
        args_range = dict(baseline)
        args_range[name] = out_of_range
        plans.append(("out_of_range", args_range))

    # 7. missing required field
    if is_required:
        args_missing = {k: v for k, v in baseline.items() if k != name}
        plans.append(("missing_required", args_missing))

    return plans


def build_probe_plans(
    schema: dict[str, Any],
    max_probes: int = _DEFAULT_MAX_PROBES_PER_TOOL,
) -> list[tuple[str, dict[str, Any]]]:
    """
    Build a deterministic list of (probe_type, args) adversarial probes.

    The first plan is always a safe baseline. Remaining plans are bounded,
    schema-aware mutations intended to trigger validation or downstream errors.
    """
    properties = get_schema_properties(schema)
    required = get_schema_required(schema)

    safe_properties = sorted(
        name
        for name in properties
        if isinstance(properties.get(name), dict) and not _is_dangerous_param(name, properties[name])
    )

    baseline, reason = build_safe_arguments(schema, include_optional=True)
    if baseline is None or not safe_properties:
        return []

    plans: list[tuple[str, dict[str, Any]]] = [("baseline", baseline)]

    def add_plan(probe_type: str, args: dict[str, Any]) -> bool:
        if len(plans) >= max_probes:
            return False
        if any(existing_args == args for _, existing_args in plans):
            return True
        plans.append((probe_type, args))
        return True

    sorted_fields = sorted(
        safe_properties,
        key=lambda n: (_param_priority(n, properties.get(n, {}), required), n),
    )

    for name in sorted_fields:
        if len(plans) >= max_probes:
            break
        param_schema = properties.get(name, {})
        if not isinstance(param_schema, dict):
            param_schema = {}
        for probe_type, args in _generate_field_mutations(
            name, param_schema, baseline, name in required
        ):
            if not add_plan(probe_type, args):
                break

    return plans


# ── Response / Error Normalization ──


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


def _extract_text_fragments(
    value: Any,
    fragments: list[str],
    seen: set[str],
) -> None:
    """Recursively collect unique text fragments in encounter order."""
    if isinstance(value, str):
        if value not in seen:
            seen.add(value)
            fragments.append(value)
        if "\\" in value:
            try:
                unescaped = json.loads(value)
                _extract_text_fragments(unescaped, fragments, seen)
            except Exception:
                pass
        return
    if isinstance(value, (list, tuple)):
        for item in value:
            _extract_text_fragments(item, fragments, seen)
        return
    if isinstance(value, dict):
        for k, v in value.items():
            if isinstance(k, str) and k not in seen:
                seen.add(k)
                fragments.append(k)
            _extract_text_fragments(v, fragments, seen)
        return


def _normalize_response(response: dict[str, Any] | None) -> DisclosureObservation:
    """Normalize an MCP response into a single bounded text observation."""
    is_error = _is_mcp_error_response(response)
    channel = "mcp_error" if is_error else "normal_response"
    fragments: list[str] = []
    seen: set[str] = set()

    if isinstance(response, dict):
        for key in ("content", "error", "message", "details", "stack", "cause"):
            _extract_text_fragments(response.get(key), fragments, seen)
    else:
        _extract_text_fragments(response, fragments, seen)

    text = "\n".join(fragments)
    original_size = len(text)
    if len(text) > _DEFAULT_MAX_RESPONSE_CHARS:
        text = text[:_DEFAULT_MAX_RESPONSE_CHARS]

    return DisclosureObservation(
        channel=channel,
        text=text,
        is_error=is_error,
        original_text_size=original_size,
    )


def _normalize_exception(exc: BaseException) -> DisclosureObservation:
    """Normalize an exception into a text observation."""
    exc_type = type(exc).__name__
    text = f"{exc_type}: {exc}"
    original_size = len(text)
    if len(text) > _DEFAULT_MAX_RESPONSE_CHARS:
        text = text[:_DEFAULT_MAX_RESPONSE_CHARS]
    return DisclosureObservation(
        channel="exception",
        text=text,
        is_error=True,
        exception_type=exc_type,
        original_text_size=original_size,
    )


# ── Disclosure Scanning ──


def _scan_text(text: str) -> list[DisclosureMatch]:
    """Scan normalized text for disclosure patterns."""
    matches: list[DisclosureMatch] = []
    for pattern in DISCLOSURE_PATTERNS:
        for m in pattern.regex.finditer(text):
            matches.append(
                DisclosureMatch(
                    pattern_id=pattern.pattern_id,
                    family=pattern.family,
                    label=pattern.label,
                    severity=pattern.severity,
                    confidence=pattern.confidence,
                    start=m.start(),
                    end=m.end(),
                    matched_value=m.group(0),
                )
            )

    # Prefer high-confidence, earlier matches when overlaps occur.
    confidence_order = {"high": 0, "medium": 1, "low": 2}
    matches.sort(
        key=lambda x: (
            x.start,
            confidence_order.get(x.confidence, 2),
            -_severity_rank(x.severity),
        )
    )
    filtered: list[DisclosureMatch] = []
    last_end = -1
    for match in matches:
        if match.start >= last_end:
            filtered.append(match)
            last_end = match.end
    return filtered


# ── Verdict / Severity ──


def _verdict_for_observation(
    matches: list[DisclosureMatch], is_error: bool
) -> str:
    """Map matches and channel to a verdict."""
    if not matches:
        return VERDICT_INCONCLUSIVE
    confidences = {m.confidence for m in matches}
    if "high" in confidences:
        return VERDICT_CONFIRMED_DISCLOSURE
    if is_error:
        return VERDICT_SUSPECTED_DISCLOSURE
    return VERDICT_INCONCLUSIVE


def _severity_for_verdict(verdict: str, pattern_severity: Severity) -> Severity:
    """Adjust severity for suspected disclosures."""
    if verdict == VERDICT_CONFIRMED_DISCLOSURE:
        return pattern_severity
    if verdict == VERDICT_SUSPECTED_DISCLOSURE:
        if pattern_severity == Severity.CRITICAL:
            return Severity.HIGH
        if pattern_severity == Severity.HIGH:
            return Severity.MEDIUM
        if pattern_severity == Severity.MEDIUM:
            return Severity.LOW
        return Severity.INFO
    return Severity.INFO


# ── Evidence Redaction ──


def _redact_text(text: str) -> str:
    """Redact likely credentials from evidence excerpts."""
    # URI passwords
    text = re.sub(
        r"([a-z][a-z0-9+.-]*://[^:@\s]+):[^@\s]+(@[^\s\"'<>]+)",
        r"\1:[REDACTED]\2",
        text,
        flags=re.IGNORECASE,
    )
    # Key/value credential assignments
    text = re.sub(
        r"(?i)(password|passwd|client_secret|secret|api_key|access_token|"
        r"refresh_token|auth_token|secret_key|token)\s*[:=]\s*[\"'][^\"']{4,}[\"']",
        r"\1=[REDACTED]",
        text,
    )
    # Authorization headers
    text = re.sub(
        r"(?i)(Authorization\s*:\s*(?:Basic|Bearer)\s+)[A-Za-z0-9+/=._\-]{8,}",
        r"\1[REDACTED]",
        text,
    )
    # PEM private keys
    text = re.sub(
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----[\s\S]*?"
        r"-----END (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
        "[REDACTED PEM PRIVATE KEY]",
        text,
    )
    # JWTs
    text = re.sub(
        r"\beyJ[A-Za-z0-9_-]{2,}\.[A-Za-z0-9_-]{2,}\.[A-Za-z0-9_-]{2,}\b",
        "[REDACTED JWT]",
        text,
    )
    return text


# ── Trace Correlation ──


def _find_exact_trace_id(
    traces: list[Any],
    tool_name: str,
    args: dict[str, Any],
    after_index: int = 0,
) -> str | None:
    """Return the trace ID of the first exact matching tool call after index."""
    for trace in traces[after_index:]:
        if getattr(trace, "method", None) != "tools/call":
            continue
        request = getattr(trace, "request", {}) or {}
        if request.get("name") == tool_name and request.get("arguments") == args:
            return getattr(trace, "id", None)
    return None


# ── Utility ──


def _truncate_args(args: dict[str, Any], max_len: int = _DEFAULT_MAX_ARG_CHARS) -> dict[str, Any]:
    """Return a shallow copy of args with overlong string values truncated."""
    truncated: dict[str, Any] = {}
    for k, v in args.items():
        if isinstance(v, str) and len(v) > max_len:
            truncated[k] = v[:max_len] + "... [truncated]"
        else:
            truncated[k] = v
    return truncated


# ── B5 Module ──


class B5ErrorInfoDisclosure(AttackModule):
    """
    Detect internal implementation/infrastructure disclosure through MCP tool
    error paths.
    """

    name = "Error Information Disclosure"
    surface = "B - Tool Invocation & Execution"
    module_id = "B5"
    description = (
        "Deterministic, schema-aware adversarial probing that triggers error "
        "paths and detects meaningful internal disclosure in responses and exceptions."
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
            "confirmed_disclosure": 0,
            "suspected_disclosure": 0,
        }
        self.probe_results: list[B5ProbeResult] = []

    async def run(self) -> list[Finding]:
        """Execute deterministic error-information-disclosure probes."""
        self.findings.clear()
        self._finding_counter = 0
        self.stats = {
            "attempted": 0,
            "skipped": 0,
            "failed": 0,
            "inconclusive": 0,
            "confirmed_disclosure": 0,
            "suspected_disclosure": 0,
        }
        self.probe_results = []

        tools = await self._get_tools()
        if not tools:
            return self.findings

        # Deterministic ordering and bounded selection.
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

            if not properties:
                self.stats["skipped"] += 1
                self.probe_results.append(
                    B5ProbeResult(
                        tool_name=tool_name,
                        probe_type="none",
                        args={},
                        verdict=VERDICT_NOT_TESTABLE,
                        reason="tool has no usable input schema",
                    )
                )
                continue

            required = get_schema_required(schema)
            dangerous_required = [
                name
                for name in required
                if _is_dangerous_param(name, properties.get(name, {}))
            ]
            if dangerous_required:
                self.stats["skipped"] += 1
                self.probe_results.append(
                    B5ProbeResult(
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
                    B5ProbeResult(
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

                traces = getattr(self.engine, "traces", [])
                trace_index_before = len(traces)
                observation, response = await self._invoke(tool_name, args)
                observation.trace_entry_id = _find_exact_trace_id(
                    traces,
                    tool_name,
                    args,
                    after_index=trace_index_before,
                )

                matches = _scan_text(observation.text)
                verdict = _verdict_for_observation(matches, observation.is_error)

                if verdict == VERDICT_CONFIRMED_DISCLOSURE:
                    self.stats["confirmed_disclosure"] += 1
                elif verdict == VERDICT_SUSPECTED_DISCLOSURE:
                    self.stats["suspected_disclosure"] += 1
                else:
                    self.stats["inconclusive"] += 1

                self.probe_results.append(
                    B5ProbeResult(
                        tool_name=tool_name,
                        probe_type=probe_type,
                        args=args,
                        verdict=verdict,
                        reason=f"matched {len(matches)} disclosure pattern(s)"
                        if matches
                        else "no disclosure pattern matched",
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
            return list(tools)
        try:
            return await self.engine.list_tools()
        except Exception:
            return []

    async def _invoke(
        self, tool_name: str, args: dict[str, Any]
    ) -> tuple[DisclosureObservation, dict[str, Any] | None]:
        """Call a tool and return normalized observation plus raw response."""
        try:
            response = await self.engine.call_tool(tool_name, args)
            observation = _normalize_response(response)
            return observation, response
        except Exception as exc:
            observation = _normalize_exception(exc)
            return observation, {"error": str(exc)}

    def _aggregate_findings(self) -> None:
        """Aggregate probe results into findings by (tool_name, family)."""
        groups: dict[tuple[str, str], list[B5ProbeResult]] = {}
        for result in self.probe_results:
            if result.verdict not in (
                VERDICT_CONFIRMED_DISCLOSURE,
                VERDICT_SUSPECTED_DISCLOSURE,
            ):
                continue
            if not result.matches:
                continue
            for match in result.matches:
                key = (result.tool_name, match.family)
                groups.setdefault(key, []).append(result)

        for (tool_name, family), results in sorted(groups.items()):
            if len(self.findings) >= self.max_findings:
                break

            # Determine worst verdict and highest severity in the group.
            group_verdicts = set()
            max_severity = Severity.INFO
            labels: set[str] = set()
            for result in results:
                for match in result.matches:
                    group_verdicts.add(_verdict_for_observation([match], result.channel != "normal_response"))
                    labels.add(match.label)
                    sev = _severity_for_verdict(
                        _verdict_for_observation([match], result.channel != "normal_response"),
                        match.severity,
                    )
                    if _severity_rank(sev) > _severity_rank(max_severity):
                        max_severity = sev

            if VERDICT_CONFIRMED_DISCLOSURE in group_verdicts:
                verdict = VERDICT_CONFIRMED_DISCLOSURE
            else:
                verdict = VERDICT_SUSPECTED_DISCLOSURE

            evidence_items: list[Evidence] = []
            seen_observations: set[str] = set()

            for result in results:
                for match in result.matches:
                    fingerprint = (
                        f"{result.probe_type}:{result.channel}:"
                        f"{match.pattern_id}:{str(result.args)}"
                    )
                    if fingerprint in seen_observations:
                        continue
                    seen_observations.add(fingerprint)

                    observation_text = ""
                    if result.response is not None:
                        observation_text = _normalize_response(result.response).text
                    elif result.exception_type:
                        observation_text = f"{result.exception_type}: <exception>"

                    redacted_text = _redact_text(observation_text)
                    if len(redacted_text) > self.max_response_chars:
                        redacted_text = redacted_text[: self.max_response_chars] + "... [truncated]"

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
                                "is_error": result.channel != "normal_response",
                                "exception_type": result.exception_type,
                                "pattern_id": match.pattern_id,
                                "category": match.family,
                                "label": match.label,
                                "confidence": match.confidence,
                                "verdict": verdict,
                                "sanitized_excerpt": redacted_text,
                                "truncated": result.original_text_size
                                > self.max_response_chars,
                            },
                            trace_entry_id=result.trace_entry_id,
                        )
                    )

            if not evidence_items:
                continue

            title_prefix = "Error information disclosure" if verdict == VERDICT_CONFIRMED_DISCLOSURE else "Suspected error information disclosure"
            title = f"{title_prefix} in '{tool_name}' ({family})"

            description = (
                f"Tool '{tool_name}' exposed internal information through an error "
                f"path (family: {family}; verdict: {verdict}). Detected patterns: "
                f"{', '.join(sorted(labels))}."
            )

            attack_narrative = (
                "1. Discovered tool via Phase 0 / tools/list\n"
                f"2. Generated schema-aware probes for '{tool_name}'\n"
                f"3. Executed {len(evidence_items)} probe observation(s)\n"
                f"4. Detected disclosure family '{family}'\n"
                f"5. Verdict: {verdict}\n"
                "6. Sanitized matched material before storing evidence"
            )

            self.add_finding(
                Finding(
                    id=self._next_finding_id(),
                    title=title,
                    surface=self.surface,
                    module=f"{self.module_id} - {self.name}",
                    severity=max_severity,
                    fixability=Fixability.CONFIGURATION,
                    fixability_rationale=(
                        "Internal diagnostic or infrastructure details reached the MCP "
                        "client through a tool response or exception. Sanitize error "
                        "output and keep implementation details server-side only."
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
                        "1. Return generic, client-safe error messages from MCP tool "
                        "handlers. 2. Keep stack traces, source paths, database schema, "
                        "and infrastructure identifiers in server-side logs only. "
                        "3. Apply consistent error-redaction middleware before serializing "
                        "MCP responses."
                    ),
                )
            )


def _severity_rank(severity: Severity) -> int:
    """Numerical rank for severity comparison."""
    order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
    return order.index(severity)
