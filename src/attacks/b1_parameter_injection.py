"""
B1 — Parameter Injection.

Active, schema-aware adversarial probing that determines whether
attacker-controlled MCP tool parameters cross interpreter boundaries and
become interpreted by downstream components.

This module intentionally sends shell metacharacters, SQL syntax, template
expressions, query operators, and malformed interpreter input. It uses
deterministic oracles to distinguish interpretation from simple reflection.

Design notes:
- Reflection alone is never treated as injection.
- A baseline invocation is performed for every tested tool.
- Required sibling arguments are preserved so probes reach application code.
- Specialized modules own their domains: S1/B2 (SSRF), B3 (path traversal),
  B5 (error disclosure), D2 (secret detection). B1 does not duplicate them.
"""

from __future__ import annotations

import asyncio
import copy
import json
import re
import secrets
from dataclasses import dataclass, field
from typing import Any

from src.attack_base import AttackModule
from src.models import Evidence, EvidenceType, Fixability, Finding, ReplayInfo, Severity


# ── Verdicts ──

VERDICT_CONFIRMED_INJECTION = "confirmed_injection"
VERDICT_SUSPECTED_INJECTION = "suspected_injection"
VERDICT_REFLECTED_ONLY = "reflected_only"
VERDICT_INCONCLUSIVE = "inconclusive"
VERDICT_NOT_TESTABLE = "not_testable"
VERDICT_NOT_RUN = "not_run"


# ── Configuration ──

_DEFAULT_MAX_TOOLS = 25
_DEFAULT_MAX_PARAMS_PER_TOOL = 3
_DEFAULT_MAX_PROBES_PER_TOOL = 12
_DEFAULT_MAX_TOTAL_PROBES = 250
_DEFAULT_MAX_PAYLOAD_CHARS = 512
_DEFAULT_MAX_ARGUMENT_CHARS = 16_384
_DEFAULT_MAX_RESPONSE_CHARS = 12_000
_DEFAULT_MAX_FINDINGS = 100
_DEFAULT_MAX_SCHEMA_DEPTH = 2
_DEFAULT_MAX_JSON_DECODE_DEPTH = 3
_DEFAULT_MAX_CALL_SECONDS = 15

# Parameters that should not be fabricated automatically when they are
# required siblings of a candidate parameter.
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
    "raw_query",
    "query",
    "sql_query",
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
    "eval",
    "system",
    "os_command",
    "terminal",
    "run_command",
    "program",
}

# Families
FAMILY_COMMAND = "command_injection"
FAMILY_SQL = "sql_injection"
FAMILY_TEMPLATE = "template_injection"
FAMILY_EXPRESSION = "expression_evaluation"
FAMILY_QUERY = "query_filter_injection"

_FAMILY_SEVERITY = {
    FAMILY_COMMAND: Severity.HIGH,
    FAMILY_SQL: Severity.HIGH,
    FAMILY_TEMPLATE: Severity.HIGH,
    FAMILY_EXPRESSION: Severity.HIGH,
    FAMILY_QUERY: Severity.MEDIUM,
}

# Contextual indicators used to score parameters.
_FAMILY_INDICATORS: dict[str, dict[str, set[str]]] = {
    FAMILY_COMMAND: {
        "names": {
            "command", "cmd", "shell", "exec", "execute", "script", "program",
            "argv", "args", "flags", "run", "process", "bin", "binary",
        },
        "desc": {
            "shell", "command", "execute", "subprocess", "popen", "system",
            "run", "spawn", "os command", "command line", "powershell",
        },
        "tool": {
            "shell", "command", "exec", "run", "script", "process", "spawn",
        },
    },
    FAMILY_SQL: {
        "names": {
            "sql", "query", "query_text", "statement", "where", "filter",
            "search", "sort", "order", "column", "field", "predicate",
            "selector", "condition", "clause", "criteria",
        },
        "desc": {
            "sql", "database", "query", "select", "where", "clause", "raw sql",
            "orm", "jdbc", "db", "sql statement", "query string",
        },
        "tool": {
            "sql", "query", "database", "db", "search", "lookup", "filter",
        },
    },
    FAMILY_TEMPLATE: {
        "names": {
            "template", "expression", "expr", "format", "render", "eval",
            "evaluate", "formula", "condition", "predicate",
        },
        "desc": {
            "template", "jinja", "freemarker", "velocity", "render", "evaluate",
            "expression", "mustache", "twig", "template engine", "format string",
        },
        "tool": {
            "template", "render", "format", "evaluate", "email", "message",
        },
    },
    FAMILY_QUERY: {
        "names": {
            "filter", "predicate", "selector", "criteria", "query", "where",
            "search", "match", "operator",
        },
        "desc": {
            "filter", "query", "criteria", "mongodb", "nosql", "ldap",
            "search predicate", "query operator", "bson", "document filter",
        },
        "tool": {
            "filter", "query", "search", "criteria", "nosql", "mongodb", "ldap",
        },
    },
    FAMILY_EXPRESSION: {
        "names": {
            "expression", "expr", "eval", "evaluate", "formula", "math",
            "calc", "compute", "arithmetic",
        },
        "desc": {
            "expression", "evaluate", "formula", "math", "arithmetic",
            "calculation", "compute", "numeric expression",
        },
        "tool": {
            "calc", "evaluate", "expression", "math", "compute", "formula",
        },
    },
}

# Parameter names that normally belong to other modules unless the tool
# context explicitly indicates interpreter embedding.
_CONTEXTUAL_PARAM_NAMES = {
    "url", "uri", "endpoint", "host", "path", "file", "filename",
    "directory", "dir", "folder", "target", "link", "href", "address",
    "location",
}


# ── Data models ──


@dataclass(frozen=True)
class InjectionPayload:
    """A single adversarial probe with full provenance."""

    payload_id: str
    family: str
    label: str
    value: Any
    oracle_type: str
    expected_marker: str | None = None
    platform: str = "any"
    pair_id: str | None = None
    branch: str | None = None  # for boolean pairs: "true", "false"


@dataclass
class ProbeResult:
    """Internal result of one probe invocation (or a boolean pair)."""

    tool_name: str
    parameter_path: str
    family: str
    probe_type: str
    payload_id: str
    oracle_type: str
    args: dict[str, Any]
    verdict: str = ""
    reason: str = ""
    confidence: str = ""
    channel: str = ""
    observation_text: str = ""
    response_shape: dict[str, Any] = field(default_factory=dict)
    payload: InjectionPayload = field(default_factory=lambda: InjectionPayload("", "", "", "", ""))
    expected_marker: str | None = None
    observed_marker: str | None = None
    reflected: bool = False
    parser_match: str | None = None
    baseline_shape: dict[str, Any] = field(default_factory=dict)
    baseline_text: str = ""
    trace_entry_id: str | None = None
    related_trace_entry_id: str | None = None  # for boolean pair partner
    platform: str = "any"
    likely_engine: str | None = None


@dataclass
class NormalizedObservation:
    """A normalized view of one tool invocation result."""

    channel: str
    text: str
    is_error: bool
    exception_type: str | None = None
    response_shape: dict[str, Any] = field(default_factory=dict)
    original_size: int = 0
    truncated: bool = False


@dataclass
class ParameterCandidate:
    """A selected parameter path and its inferred injection family."""

    path: list[str]
    path_str: str
    family: str
    score: int
    param_schema: dict[str, Any]


# ── Payload generation ──


def _make_marker(nonce: str, value: int = 42) -> str:
    return f"B1_{nonce}_{value}"


def _fresh_nonce() -> str:
    return secrets.token_urlsafe(8)


def _generate_command_payloads(nonce: str) -> list[InjectionPayload]:
    marker = _make_marker(nonce)
    return [
        InjectionPayload(
            payload_id="cmd_unix_semicolon",
            family=FAMILY_COMMAND,
            label="Unix semicolon computed marker",
            value=f"; printf 'B1_{nonce}_'$((40+2)); #",
            oracle_type="computed_marker",
            expected_marker=marker,
            platform="unix",
        ),
        InjectionPayload(
            payload_id="cmd_unix_substitution",
            family=FAMILY_COMMAND,
            label="Unix command substitution computed marker",
            value=f"$(printf 'B1_{nonce}_'$((20+22)))",
            oracle_type="computed_marker",
            expected_marker=marker,
            platform="unix",
        ),
        InjectionPayload(
            payload_id="cmd_unix_backtick",
            family=FAMILY_COMMAND,
            label="Unix backtick substitution computed marker",
            value=f"`printf 'B1_{nonce}_'$((21*2))`",
            oracle_type="computed_marker",
            expected_marker=marker,
            platform="unix",
        ),
        InjectionPayload(
            payload_id="cmd_unix_newline",
            family=FAMILY_COMMAND,
            label="Unix newline separator computed marker",
            value=f"\nprintf 'B1_{nonce}_'$((40+2))\n#",
            oracle_type="computed_marker",
            expected_marker=marker,
            platform="unix",
        ),
        InjectionPayload(
            payload_id="cmd_windows_powershell",
            family=FAMILY_COMMAND,
            label="Windows PowerShell computed marker",
            value=(
                f"& powershell -Command \"Write-Host ('B1_{nonce}_' + (40+2))\" & rem"
            ),
            oracle_type="computed_marker",
            expected_marker=marker,
            platform="windows",
        ),
    ]


def _generate_sql_payloads(nonce: str) -> list[InjectionPayload]:
    pair_id = f"sql_bool_{nonce}"
    return [
        InjectionPayload(
            payload_id="sql_quote_single",
            family=FAMILY_SQL,
            label="SQL single-quote parser probe",
            value="'",
            oracle_type="parser_evidence",
        ),
        InjectionPayload(
            payload_id="sql_quote_double",
            family=FAMILY_SQL,
            label="SQL double-quote parser probe",
            value='"',
            oracle_type="parser_evidence",
        ),
        InjectionPayload(
            payload_id="sql_bool_true",
            family=FAMILY_SQL,
            label="SQL boolean TRUE branch",
            value=f"' OR (1=1) -- B1_{nonce}",
            oracle_type="boolean_differential",
            pair_id=pair_id,
            branch="true",
        ),
        InjectionPayload(
            payload_id="sql_bool_false",
            family=FAMILY_SQL,
            label="SQL boolean FALSE branch",
            value=f"' OR (1=2) -- B1_{nonce}",
            oracle_type="boolean_differential",
            pair_id=pair_id,
            branch="false",
        ),
    ]


def _generate_template_payloads(nonce: str) -> list[InjectionPayload]:
    marker = _make_marker(nonce)
    return [
        InjectionPayload(
            payload_id="ssti_jinja",
            family=FAMILY_TEMPLATE,
            label="Jinja/Twig expression computed marker",
            value=f"{{{{'B1_{nonce}_'~(40+2)}}}}",
            oracle_type="computed_marker",
            expected_marker=marker,
        ),
        InjectionPayload(
            payload_id="ssti_freemarker",
            family=FAMILY_TEMPLATE,
            label="FreeMarker expression computed marker",
            value=f"${{'B1_{nonce}_'+(40+2)}}",
            oracle_type="computed_marker",
            expected_marker=marker,
        ),
        InjectionPayload(
            payload_id="ssti_erb",
            family=FAMILY_TEMPLATE,
            label="ERB expression computed marker",
            value=f"<%= 'B1_{nonce}_' %><%= 40+2 %>",
            oracle_type="computed_marker",
            expected_marker=marker,
        ),
        InjectionPayload(
            payload_id="ssti_slim",
            family=FAMILY_TEMPLATE,
            label="Ruby Slim expression computed marker",
            value=f"#{{'B1_{nonce}_' + (40+2).to_s}}",
            oracle_type="computed_marker",
            expected_marker=marker,
        ),
        InjectionPayload(
            payload_id="ssti_polyglot_jinja",
            family=FAMILY_TEMPLATE,
            label="Jinja/Twig fingerprint probe",
            value="{{7*7}}",
            oracle_type="computed_marker",
            expected_marker="49",
        ),
        InjectionPayload(
            payload_id="ssti_polyglot_freemarker",
            family=FAMILY_TEMPLATE,
            label="FreeMarker/Velocity fingerprint probe",
            value="${7*7}",
            oracle_type="computed_marker",
            expected_marker="49",
        ),
        InjectionPayload(
            payload_id="ssti_polyglot_erb",
            family=FAMILY_TEMPLATE,
            label="ERB fingerprint probe",
            value="<%= 7*7 %>",
            oracle_type="computed_marker",
            expected_marker="49",
        ),
    ]


def _generate_expression_payloads(nonce: str) -> list[InjectionPayload]:
    marker = _make_marker(nonce)
    return [
        InjectionPayload(
            payload_id="expr_arithmetic_1",
            family=FAMILY_EXPRESSION,
            label="Arithmetic expression computed marker",
            value="40+2",
            oracle_type="computed_marker",
            expected_marker=marker,
        ),
        InjectionPayload(
            payload_id="expr_arithmetic_2",
            family=FAMILY_EXPRESSION,
            label="Alternate arithmetic expression computed marker",
            value="20+22",
            oracle_type="computed_marker",
            expected_marker=marker,
        ),
    ]


def _generate_query_payloads(nonce: str, is_object: bool) -> list[InjectionPayload]:
    if is_object:
        return [
            InjectionPayload(
                payload_id="nosql_ne",
                family=FAMILY_QUERY,
                label="NoSQL $ne operator differential",
                value={"$ne": "__b1_absent__"},
                oracle_type="boolean_differential",
                pair_id=f"nosql_{nonce}",
                branch="true",
            ),
            InjectionPayload(
                payload_id="nosql_eq",
                family=FAMILY_QUERY,
                label="NoSQL $eq absent differential",
                value={"$eq": "__b1_absent__"},
                oracle_type="boolean_differential",
                pair_id=f"nosql_{nonce}",
                branch="false",
            ),
        ]
    # String-typed filter candidates get a wildcard/absent-value pair.
    return [
        InjectionPayload(
            payload_id="filter_wildcard",
            family=FAMILY_QUERY,
            label="Filter wildcard differential",
            value="*",
            oracle_type="boolean_differential",
            pair_id=f"filter_{nonce}",
            branch="true",
        ),
        InjectionPayload(
            payload_id="filter_absent",
            family=FAMILY_QUERY,
            label="Filter absent-value differential",
            value="__b1_absent__",
            oracle_type="boolean_differential",
            pair_id=f"filter_{nonce}",
            branch="false",
        ),
    ]


# ── Schema helpers ──


def _get_tool_schema(tool: dict[str, Any]) -> dict[str, Any]:
    """Return the usable input schema, preferring the standard key."""
    standard = tool.get("inputSchema")
    alias = tool.get("input_schema")
    if isinstance(standard, dict) and standard:
        return standard
    if isinstance(alias, dict) and alias:
        return alias
    return {}


def _schema_type(param_schema: dict[str, Any]) -> str:
    """Return a single representative type from a schema fragment."""
    t = param_schema.get("type")
    if isinstance(t, list):
        for candidate in t:
            if candidate in ("string", "integer", "number", "boolean", "object", "array"):
                return candidate
        return "string"
    if t in ("string", "integer", "number", "boolean", "object", "array"):
        return t
    # Shallow oneOf/anyOf
    for key in ("oneOf", "anyOf"):
        variants = param_schema.get(key)
        if isinstance(variants, list):
            for v in variants:
                if isinstance(v, dict):
                    vt = v.get("type")
                    if isinstance(vt, str) and vt in (
                        "string", "integer", "number", "boolean", "object", "array"
                    ):
                        return vt
    return "string"


def _is_string_like(param_schema: dict[str, Any]) -> bool:
    """Return True if the schema accepts or coerces to string."""
    t = param_schema.get("type")
    if t == "string":
        return True
    if isinstance(t, list) and "string" in t:
        return True
    if "enum" in param_schema:
        enum_values = param_schema.get("enum")
        if isinstance(enum_values, list) and enum_values:
            return all(isinstance(v, str) for v in enum_values)
    for key in ("oneOf", "anyOf"):
        variants = param_schema.get(key)
        if isinstance(variants, list):
            for v in variants:
                if isinstance(v, dict) and v.get("type") == "string":
                    return True
    return False


def _is_dangerous_param(name: str, param_schema: dict[str, Any]) -> bool:
    lowered = name.lower()
    if lowered in _DANGEROUS_PARAM_NAMES:
        return True
    enum_values = param_schema.get("enum") or []
    if isinstance(enum_values, list) and enum_values:
        destructive = {"delete", "drop", "remove", "write", "overwrite", "execute", "run"}
        if any(str(v).lower() in destructive for v in enum_values):
            return True
    return False


def _safe_default_for_type(param_schema: dict[str, Any], depth: int = 0) -> Any:
    """Generate a neutral, safe value for a schema fragment."""
    t = _schema_type(param_schema)
    if t == "string":
        return "test"
    if t == "integer":
        minimum = param_schema.get("minimum")
        return int(minimum) if isinstance(minimum, (int, float)) else 1
    if t == "number":
        minimum = param_schema.get("minimum")
        return float(minimum) if isinstance(minimum, (int, float)) else 1.0
    if t == "boolean":
        return False
    if t == "array":
        if depth < _DEFAULT_MAX_SCHEMA_DEPTH:
            items = param_schema.get("items")
            if isinstance(items, dict):
                return [_safe_default_for_type(items, depth + 1)]
        return []
    if t == "object":
        if depth < _DEFAULT_MAX_SCHEMA_DEPTH:
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
    name: str,
    param_schema: dict[str, Any],
    is_required: bool,
    include_optional: bool,
    depth: int = 0,
) -> tuple[Any, str | None]:
    """
    Generate a safe value for a single property.

    Returns (value, reason). reason is set when a required sibling is
    dangerous and cannot be filled automatically.
    """
    if _is_dangerous_param(name, param_schema):
        # Required dangerous parameters are allowed as candidate targets; we
        # still need a safe baseline value for them. Optional dangerous
        # parameters are skipped entirely.
        if not is_required:
            return (None, None)

    if not is_required and not include_optional:
        return (None, None)

    default = param_schema.get("default")
    if default is not None:
        return (default, None)

    example = param_schema.get("example")
    if example is not None:
        return (example, None)

    examples = param_schema.get("examples")
    if isinstance(examples, list) and examples:
        return (examples[0], None)

    enum_values = param_schema.get("enum")
    if isinstance(enum_values, list) and enum_values:
        return (enum_values[0], None)

    return (_safe_default_for_type(param_schema, depth), None)


def build_safe_arguments(
    schema: dict[str, Any],
    include_optional: bool = True,
    depth: int = 0,
) -> tuple[dict[str, Any], str | None]:
    """
    Build safe arguments from a tool schema.

    Returns (args, reason). If a required sibling is dangerous and has no
    usable value, reason is set and the tool is not testable.
    """
    properties = schema.get("properties", {})
    if not isinstance(properties, dict):
        properties = {}
    required = set(schema.get("required", []))
    args: dict[str, Any] = {}

    for name, param_schema in sorted(properties.items()):
        if not isinstance(param_schema, dict):
            param_schema = {}
        value, reason = _safe_value_for_property(
            name, param_schema, name in required, include_optional, depth
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
            args[name] = _safe_default_for_type(param_schema, depth)

    return (args, None)


def _has_dangerous_required_sibling(
    schema: dict[str, Any],
    candidate_path: list[str],
) -> bool:
    """Return True if a required sibling (not the candidate) is dangerous."""
    properties = schema.get("properties", {})
    if not isinstance(properties, dict):
        return False
    required = set(schema.get("required", []))
    candidate_root = candidate_path[0]
    for name in required:
        if name == candidate_root:
            continue
        param_schema = properties.get(name, {})
        if not isinstance(param_schema, dict):
            param_schema = {}
        if _is_dangerous_param(name, param_schema):
            return True
    return False


def _set_path(args: dict[str, Any], path: list[str], value: Any) -> dict[str, Any]:
    """Return a deep copy of args with value set at the nested path."""
    new_args = copy.deepcopy(args)
    node = new_args
    for key in path[:-1]:
        if key not in node or not isinstance(node[key], dict):
            node[key] = {}
        node = node[key]
    node[path[-1]] = value
    return new_args


# ── Candidate discovery ──


def _score_text(text: str, indicators: set[str]) -> int:
    lowered = text.lower()
    return sum(1 for ind in indicators if ind in lowered)


def _score_parameter(
    path: list[str],
    param_schema: dict[str, Any],
    tool: dict[str, Any],
) -> tuple[str, int]:
    """Return (family, score) for a parameter path."""
    name = path[-1]
    name_lower = name.lower()
    desc = str(param_schema.get("description", ""))
    tool_name = str(tool.get("name", "")).lower()
    tool_desc = str(tool.get("description", "")).lower()

    best_family = ""
    best_score = 0

    for family, inds in _FAMILY_INDICATORS.items():
        score = 0
        score += 30 * _score_text(name_lower, inds["names"])
        score += 15 * _score_text(desc, inds["desc"])
        score += 10 * _score_text(tool_name, inds["tool"])
        score += 8 * _score_text(tool_desc, inds["tool"])

        # Contextual names (url/path/file) only score if tool context
        # indicates the value is embedded in an interpreter.
        if name_lower in _CONTEXTUAL_PARAM_NAMES:
            interpreter_context = (
                _score_text(tool_desc, inds["desc"])
                + _score_text(tool_name, inds["tool"])
            )
            if interpreter_context:
                score += 10

        if score > best_score:
            best_score = score
            best_family = family

    # Object-typed parameters that look like filters are strong NoSQL/query
    # candidates even if the name is generic.
    if _schema_type(param_schema) == "object" and (
        _score_text(name_lower, _FAMILY_INDICATORS[FAMILY_QUERY]["names"])
        or _score_text(desc, _FAMILY_INDICATORS[FAMILY_QUERY]["desc"])
        or _score_text(tool_desc, _FAMILY_INDICATORS[FAMILY_QUERY]["tool"])
    ):
        if best_score < 25:
            best_family = FAMILY_QUERY
            best_score = max(best_score, 25)

    return best_family, best_score


def _enumerate_scalar_paths(
    schema: dict[str, Any],
    tool: dict[str, Any],
    prefix: list[str] | None = None,
    depth: int = 0,
) -> list[ParameterCandidate]:
    """Enumerate candidate parameter paths up to MAX_SCHEMA_DEPTH."""
    prefix = prefix or []
    if depth > _DEFAULT_MAX_SCHEMA_DEPTH:
        return []

    properties = schema.get("properties", {})
    if not isinstance(properties, dict):
        return []

    candidates: list[ParameterCandidate] = []
    for name, param_schema in sorted(properties.items()):
        if not isinstance(param_schema, dict):
            param_schema = {}
        path = prefix + [name]
        t = _schema_type(param_schema)

        if t == "object":
            # Object paths can be query/filter candidates.
            family, score = _score_parameter(path, param_schema, tool)
            if score >= 10 and family == FAMILY_QUERY:
                candidates.append(
                    ParameterCandidate(
                        path=path,
                        path_str=".".join(path),
                        family=family,
                        score=score,
                        param_schema=param_schema,
                    )
                )
            # Recurse into nested object properties.
            candidates.extend(
                _enumerate_scalar_paths(param_schema, tool, path, depth + 1)
            )
        elif _is_string_like(param_schema):
            family, score = _score_parameter(path, param_schema, tool)
            if score >= 10:
                candidates.append(
                    ParameterCandidate(
                        path=path,
                        path_str=".".join(path),
                        family=family,
                        score=score,
                        param_schema=param_schema,
                    )
                )
        # Arrays are not primary candidates in this version to keep the
        # module focused and bounded.

    return candidates


def _select_candidates(
    tool: dict[str, Any],
    max_params: int,
) -> list[ParameterCandidate]:
    """Return up to max_params candidate parameters for a tool."""
    schema = _get_tool_schema(tool)
    all_candidates = _enumerate_scalar_paths(schema, tool)
    # Sort by descending score, then deterministic path string.
    all_candidates.sort(key=lambda c: (-c.score, c.path_str))
    seen: set[str] = set()
    selected: list[ParameterCandidate] = []
    for cand in all_candidates:
        if cand.path_str in seen:
            continue
        seen.add(cand.path_str)
        selected.append(cand)
        if len(selected) >= max_params:
            break
    return selected


# ── Response normalization ──


def _is_mcp_error_response(response: dict[str, Any] | None) -> bool:
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
    depth: int = 0,
) -> None:
    """Recursively collect unique text fragments in encounter order."""
    if isinstance(value, str):
        if value not in seen:
            seen.add(value)
            fragments.append(value)
        if depth < _DEFAULT_MAX_JSON_DECODE_DEPTH and "\\" in value:
            try:
                parsed = json.loads(value)
                _extract_text_fragments(parsed, fragments, seen, depth + 1)
            except Exception:
                pass
        return
    if isinstance(value, (list, tuple)):
        for item in value:
            _extract_text_fragments(item, fragments, seen, depth)
        return
    if isinstance(value, dict):
        for k, v in value.items():
            if isinstance(k, str) and k not in seen:
                seen.add(k)
                fragments.append(k)
            _extract_text_fragments(v, fragments, seen, depth)
        return


def _response_shape(response: dict[str, Any] | None) -> dict[str, Any]:
    """Return a lightweight fingerprint of response structure."""
    shape: dict[str, Any] = {
        "has_error": _is_mcp_error_response(response),
        "content_items": 0,
        "content_text_len": 0,
    }
    if isinstance(response, dict):
        content = response.get("content")
        if isinstance(content, list):
            shape["content_items"] = len(content)
            for item in content:
                if isinstance(item, dict) and item.get("type") == "text":
                    shape["content_text_len"] += len(str(item.get("text", "")))
        elif isinstance(content, str):
            shape["content_text_len"] = len(content)
    return shape


def _normalize_response(response: dict[str, Any] | None) -> NormalizedObservation:
    fragments: list[str] = []
    seen: set[str] = set()

    if isinstance(response, dict):
        for key in ("content", "error", "message", "details", "stack", "cause"):
            _extract_text_fragments(response.get(key), fragments, seen)
    else:
        _extract_text_fragments(response, fragments, seen)

    text = "\n".join(fragments)
    original_size = len(text)
    truncated = False
    if len(text) > _DEFAULT_MAX_RESPONSE_CHARS:
        head = text[: _DEFAULT_MAX_RESPONSE_CHARS // 2]
        tail = text[-_DEFAULT_MAX_RESPONSE_CHARS // 2 :]
        text = f"{head}\n...[{original_size - len(head) - len(tail)} bytes omitted]...\n{tail}"
        truncated = True

    return NormalizedObservation(
        channel="mcp_error" if _is_mcp_error_response(response) else "normal_response",
        text=text,
        is_error=_is_mcp_error_response(response),
        response_shape=_response_shape(response),
        original_size=original_size,
        truncated=truncated,
    )


def _normalize_exception(exc: BaseException) -> NormalizedObservation:
    exc_type = type(exc).__name__
    text = f"{exc_type}: {exc}"
    original_size = len(text)
    truncated = False
    if len(text) > _DEFAULT_MAX_RESPONSE_CHARS:
        text = text[: _DEFAULT_MAX_RESPONSE_CHARS]
        truncated = True
    return NormalizedObservation(
        channel="exception",
        text=text,
        is_error=True,
        exception_type=exc_type,
        response_shape={"has_error": True},
        original_size=original_size,
        truncated=truncated,
    )


# ── Oracles and reflection filtering ──


def _parser_evidence(text: str, family: str) -> str | None:
    """Return the matched parser signature if the text contains one."""
    text_lower = text.lower()
    if family == FAMILY_SQL:
        patterns = [
            r"\bSQLSTATE\s+\d{5}\b",
            r"\bSQL syntax error\b",
            r"\bsyntax error\b.*\bnear\b",
            r"\bnear\s+['\"]?.*\bsyntax error\b",
            r"\bpg_query\b|\bpsycopg2\b|\bmysql.connector\b|\bsqlite3\b",
            r"\bincorrect syntax\b",
            r"\bORA-\d{5}\b",
        ]
    elif family == FAMILY_COMMAND:
        patterns = [
            r"\bsyntax error\s+near\s+unexpected token",
            r"\bunexpected\s+(?:end of file|EOF|token)",
            r"\bsh:\s*\d*:\s*syntax error",
            r"\bbash:\s*.*:\s*syntax error",
            r"\bcmd\.exe\b.*\bis not recognized",
            r"\bcommand not found\b",
        ]
    elif family == FAMILY_TEMPLATE:
        patterns = [
            r"\bTemplateSyntaxError\b",
            r"\bTemplateNotFound\b",
            r"\bUnexpected end of template\b",
            r"\bFreemarker\b.*\bError\b",
            r"\bVelocity\b.*\bError\b",
            r"\bSyntaxError\b.*\btemplate\b",
        ]
    elif family == FAMILY_QUERY:
        patterns = [
            r"\bcannot parse\b",
            r"\bfilter\b.*\boperator\b",
            r"\binvalid operator\b",
            r"\bldap\b.*\berror\b",
        ]
    else:
        return None

    for pattern in patterns:
        try:
            if re.search(pattern, text, re.IGNORECASE):
                return pattern
        except re.error:
            continue
    return None


def _is_reflected(observation_text: str, payload_value: Any) -> bool:
    """Return True if the literal payload value appears in the response."""
    if isinstance(payload_value, str):
        return payload_value in observation_text
    # For object payloads, stringify.
    return str(payload_value) in observation_text


def _likely_engine(payload_id: str) -> str | None:
    if payload_id.startswith("ssti_jinja"):
        return "jinja2/twig"
    if payload_id.startswith("ssti_freemarker"):
        return "freemarker/velocity"
    if payload_id.startswith("ssti_erb"):
        return "erb"
    if payload_id.startswith("ssti_slim"):
        return "ruby_slim"
    return None


def _evaluate_computed_marker(
    observation: NormalizedObservation,
    payload: InjectionPayload,
    baseline_text: str,
) -> tuple[str, str] | None:
    """
    Evaluate a computed-marker oracle.

    Returns (verdict, reason) or None if the oracle does not fire.
    """
    expected = payload.expected_marker
    if not expected:
        return None
    if expected in payload.value:
        return None
    if expected in baseline_text:
        return None
    if expected in observation.text:
        engine = _likely_engine(payload.payload_id)
        reason = f"computed marker '{expected}' observed in {observation.channel}"
        if engine:
            reason += f"; likely engine: {engine}"
        return (VERDICT_CONFIRMED_INJECTION, reason)
    return None


def _strip_for_comparison(text: str, payloads: list[InjectionPayload]) -> str:
    """Remove payload literals and nonces from text before differential comparison."""
    for payload in payloads:
        value = payload.value
        if isinstance(value, str):
            text = text.replace(value, "")
        else:
            text = text.replace(str(value), "")
        # Also remove nonce markers such as B1_<nonce> to avoid noise.
        for match in re.findall(r"B1_[A-Za-z0-9_-]+_\d+", text):
            text = text.replace(match, "")
    return text


def _evaluate_boolean_differential(
    baseline_obs: NormalizedObservation,
    pair_results: list[ProbeResult],
) -> tuple[str, str] | None:
    """
    Evaluate a boolean-differential oracle from a true/false pair.

    Returns (verdict, reason) or None.
    """
    if len(pair_results) != 2:
        return None
    branches = {r.payload.branch: r for r in pair_results if r.payload.branch}
    if "true" not in branches or "false" not in branches:
        return None

    true_res = branches["true"]
    false_res = branches["false"]

    payloads = [true_res.payload, false_res.payload]
    base_norm = _strip_for_comparison(baseline_obs.text, payloads)
    true_norm = _strip_for_comparison(true_res.observation_text, payloads)
    false_norm = _strip_for_comparison(false_res.observation_text, payloads)

    base_len = len(base_norm)
    true_len = len(true_norm)
    false_len = len(false_norm)

    # Material difference threshold: at least 20% relative and 10 chars
    # absolute, or a difference in error state / content item count.
    diff_true_false = abs(true_len - false_len)
    rel_diff = diff_true_false / max(1, max(true_len, false_len))
    structural_diff = (
        true_res.response_shape.get("content_items")
        != false_res.response_shape.get("content_items")
        or true_res.response_shape.get("has_error")
        != false_res.response_shape.get("has_error")
    )

    if not structural_diff and rel_diff < 0.2 and diff_true_false < 10:
        return None

    # Prefer the pattern where one branch matches baseline and the other
    # does not, because that is the strongest boolean signal.
    true_base_diff = abs(true_len - base_len)
    false_base_diff = abs(false_len - base_len)
    threshold = max(10, int(0.2 * max(1, base_len, true_len, false_len)))

    if true_base_diff <= threshold and false_base_diff > threshold:
        return (
            VERDICT_CONFIRMED_INJECTION,
            "true branch matches baseline, false branch differs materially",
        )
    if false_base_diff <= threshold and true_base_diff > threshold:
        return (
            VERDICT_CONFIRMED_INJECTION,
            "false branch matches baseline, true branch differs materially",
        )
    if structural_diff or (rel_diff >= 0.2 and diff_true_false >= 10):
        return (
            VERDICT_SUSPECTED_INJECTION,
            "true and false branches differ materially after reflection normalization",
        )
    return None


def _evaluate_parser_evidence(
    observation: NormalizedObservation,
    family: str,
) -> tuple[str, str] | None:
    match = _parser_evidence(observation.text, family)
    if match:
        return (
            VERDICT_SUSPECTED_INJECTION,
            f"{family} parser evidence matched: {match}",
        )
    return None


# ── Trace correlation ──


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


# ── Evidence helpers ──


def _truncate_string(value: str, max_len: int = _DEFAULT_MAX_ARGUMENT_CHARS) -> str:
    if len(value) > max_len:
        return value[:max_len] + "... [truncated]"
    return value


def _truncate_args(args: dict[str, Any], max_len: int = _DEFAULT_MAX_ARGUMENT_CHARS) -> dict[str, Any]:
    truncated: dict[str, Any] = {}
    for k, v in args.items():
        if isinstance(v, str) and len(v) > max_len:
            truncated[k] = _truncate_string(v, max_len)
        else:
            truncated[k] = v
    return truncated


def _redact_text(text: str) -> str:
    """Redact likely credentials from evidence excerpts."""
    text = re.sub(
        r"([a-z][a-z0-9+.-]*://[^:@\s]+):[^@\s]+(@[^\s\"'<>]+)",
        r"\1:[REDACTED]\2",
        text,
        flags=re.IGNORECASE,
    )
    text = re.sub(
        r"(?i)(password|passwd|client_secret|secret|api_key|access_token|"
        r"refresh_token|auth_token|secret_key|token)\s*[:=]\s*(?:[\"'][^\"']{4,}[\"']|\S{4,})",
        r"\1=[REDACTED]",
        text,
    )
    text = re.sub(
        r"(?i)(Authorization\s*:\s*(?:Basic|Bearer)\s+)[A-Za-z0-9+/=._\-]{8,}",
        r"\1[REDACTED]",
        text,
    )
    text = re.sub(
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----[\s\S]*?"
        r"-----END (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
        "[REDACTED PEM PRIVATE KEY]",
        text,
    )
    text = re.sub(
        r"\beyJ[A-Za-z0-9_-]{2,}\.[A-Za-z0-9_-]{2,}\.[A-Za-z0-9_-]{2,}\b",
        "[REDACTED JWT]",
        text,
    )
    return text


def _sanitize_excerpt(text: str, max_len: int = _DEFAULT_MAX_RESPONSE_CHARS) -> tuple[str, bool]:
    redacted = _redact_text(text)
    if len(redacted) > max_len:
        return redacted[:max_len] + "... [truncated]", True
    return redacted, False


def _severity_rank(severity: Severity) -> int:
    order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
    return order.index(severity)


def _confidence_rank(confidence: str) -> int:
    return {"high": 0, "medium": 1, "low": 2}.get(confidence, 2)


# ── B1 Module ──


class B1ParameterInjection(AttackModule):
    """
    Active parameter injection assessment for MCP tools.

    Sends targeted adversarial inputs and uses deterministic oracles to
    decide whether attacker-controlled syntax is interpreted by downstream
    components.
    """

    name = "Parameter Injection"
    surface = "B - Tool Invocation & Execution"
    module_id = "B1"
    description = (
        "Schema-aware active probing for command, SQL, template, expression, "
        "NoSQL, and query/filter injection through MCP tool parameters. "
        "Uses deterministic oracles to distinguish interpretation from reflection."
    )

    def __init__(
        self,
        engine: Any,
        max_tools: int = _DEFAULT_MAX_TOOLS,
        max_params_per_tool: int = _DEFAULT_MAX_PARAMS_PER_TOOL,
        max_probes_per_tool: int = _DEFAULT_MAX_PROBES_PER_TOOL,
        max_total_probes: int = _DEFAULT_MAX_TOTAL_PROBES,
        max_payload_chars: int = _DEFAULT_MAX_PAYLOAD_CHARS,
        max_argument_chars: int = _DEFAULT_MAX_ARGUMENT_CHARS,
        max_response_chars: int = _DEFAULT_MAX_RESPONSE_CHARS,
        max_findings: int = _DEFAULT_MAX_FINDINGS,
        max_schema_depth: int = _DEFAULT_MAX_SCHEMA_DEPTH,
        max_call_seconds: float = _DEFAULT_MAX_CALL_SECONDS,
        aggressive: bool = False,
    ) -> None:
        super().__init__(engine)
        self.max_tools = max_tools
        self.max_params_per_tool = max_params_per_tool
        self.max_probes_per_tool = max_probes_per_tool
        self.max_total_probes = max_total_probes
        self.max_payload_chars = max_payload_chars
        self.max_argument_chars = max_argument_chars
        self.max_response_chars = max_response_chars
        self.max_findings = max_findings
        self.max_schema_depth = max_schema_depth
        self.max_call_seconds = max_call_seconds
        self.aggressive = aggressive

        self.stats: dict[str, int] = {
            "attempted": 0,
            "skipped": 0,
            "failed": 0,
            "confirmed": 0,
            "suspected": 0,
            "reflected": 0,
            "inconclusive": 0,
        }
        self.probe_results: list[ProbeResult] = []
        self.baseline_results: dict[str, NormalizedObservation] = {}

    async def run(self) -> list[Finding]:
        """Execute deterministic parameter-injection probes."""
        self.findings.clear()
        self._finding_counter = 0
        self.stats = {
            "attempted": 0,
            "skipped": 0,
            "failed": 0,
            "confirmed": 0,
            "suspected": 0,
            "reflected": 0,
            "inconclusive": 0,
        }
        self.probe_results = []
        self.baseline_results = {}
        self._baseline_args: dict[str, dict[str, Any]] = {}

        tools = await self._get_tools()
        if not tools:
            return self.findings

        total_probes = 0
        stop_outer = False

        for tool in tools:
            if stop_outer:
                break
            if len(self.findings) >= self.max_findings:
                break

            tool_name = str(tool.get("name", ""))
            if not tool_name:
                continue

            schema = _get_tool_schema(tool)
            if not schema:
                self.stats["skipped"] += 1
                self.probe_results.append(
                    ProbeResult(
                        tool_name=tool_name,
                        parameter_path="",
                        family="",
                        probe_type="none",
                        payload_id="none",
                        oracle_type="none",
                        args={},
                        verdict=VERDICT_NOT_TESTABLE,
                        reason="tool has no usable input schema",
                    )
                )
                continue

            baseline_args, skip_reason = build_safe_arguments(schema)
            if baseline_args is None:
                self.stats["skipped"] += 1
                self.probe_results.append(
                    ProbeResult(
                        tool_name=tool_name,
                        parameter_path="",
                        family="",
                        probe_type="none",
                        payload_id="none",
                        oracle_type="none",
                        args={},
                        verdict=VERDICT_NOT_TESTABLE,
                        reason=skip_reason or "could not build safe baseline",
                    )
                )
                continue

            baseline_obs = await self._invoke(tool_name, baseline_args)
            self.baseline_results[tool_name] = baseline_obs
            self._baseline_args[tool_name] = baseline_args

            candidates = _select_candidates(tool, self.max_params_per_tool)
            if not candidates:
                continue

            # Reject candidates whose required siblings are dangerous and
            # cannot be safely fabricated (e.g. a required "command" sibling).
            safe_candidates = [
                c
                for c in candidates
                if not _has_dangerous_required_sibling(schema, c.path)
            ]
            if not safe_candidates:
                self.stats["skipped"] += 1
                self.probe_results.append(
                    ProbeResult(
                        tool_name=tool_name,
                        parameter_path="",
                        family="",
                        probe_type="none",
                        payload_id="none",
                        oracle_type="none",
                        args={},
                        verdict=VERDICT_NOT_TESTABLE,
                        reason="dangerous required sibling parameter",
                    )
                )
                continue
            candidates = safe_candidates

            per_param_budget = max(
                3, self.max_probes_per_tool // max(1, len(candidates))
            )

            for candidate in candidates:
                if total_probes >= self.max_total_probes:
                    stop_outer = True
                    break
                if len(self.findings) >= self.max_findings:
                    stop_outer = True
                    break

                param_probes = await self._probe_candidate(
                    tool_name,
                    candidate,
                    baseline_args,
                    baseline_obs,
                    per_param_budget,
                    total_probes,
                )
                self.probe_results.extend(param_probes)
                total_probes += sum(1 for r in param_probes if r.verdict != VERDICT_NOT_RUN)

        self._evaluate_boolean_pairs()
        self._aggregate_findings()
        return self.findings

    async def _get_tools(self) -> list[dict[str, Any]]:
        """Return normalized, deduplicated, sorted tools."""
        phase0 = self.get_phase0_context()
        tools = phase0.get("tools") if isinstance(phase0, dict) else None
        if not isinstance(tools, list):
            tools = []
        if not tools:
            try:
                tools = await self.engine.list_tools()
            except Exception:
                tools = []

        normalized: dict[str, dict[str, Any]] = {}
        for tool in tools:
            if not isinstance(tool, dict):
                continue
            name = str(tool.get("name", "")).strip()
            if not name:
                continue
            # Deduplicate by name, keeping the first usable schema.
            if name in normalized:
                existing_schema = _get_tool_schema(normalized[name])
                if not existing_schema:
                    normalized[name] = tool
                continue
            normalized[name] = tool

        sorted_tools = sorted(normalized.values(), key=lambda t: str(t.get("name", "")))
        return sorted_tools[: self.max_tools]

    async def _invoke(
        self,
        tool_name: str,
        args: dict[str, Any],
    ) -> NormalizedObservation:
        """Call a tool with bounded execution and normalize the result."""
        try:
            if self.max_call_seconds and self.max_call_seconds > 0:
                response = await asyncio.wait_for(
                    self.engine.call_tool(tool_name, args),
                    timeout=self.max_call_seconds,
                )
            else:
                response = await self.engine.call_tool(tool_name, args)
            return _normalize_response(response)
        except asyncio.TimeoutError:
            return NormalizedObservation(
                channel="timeout",
                text="probe timed out",
                is_error=True,
                response_shape={"has_error": True},
            )
        except Exception as exc:
            return _normalize_exception(exc)

    def _trace_id_for(
        self,
        tool_name: str,
        args: dict[str, Any],
        before_index: int,
    ) -> str | None:
        return _find_exact_trace_id(
            getattr(self.engine, "traces", []),
            tool_name,
            args,
            after_index=before_index,
        )

    async def _probe_candidate(
        self,
        tool_name: str,
        candidate: ParameterCandidate,
        baseline_args: dict[str, Any],
        baseline_obs: NormalizedObservation,
        per_param_budget: int,
        total_probes_so_far: int,
    ) -> list[ProbeResult]:
        """Execute adaptive probes for one candidate parameter."""
        param_results: list[ProbeResult] = []
        probes_executed = 0
        confirmed_families: set[str] = set()
        parser_families: set[str] = set()

        primary = self._build_primary_probes(candidate, per_param_budget)
        confirmation: list[InjectionPayload] = []
        queue: list[InjectionPayload] = list(primary)

        while queue and probes_executed < per_param_budget:
            if total_probes_so_far + probes_executed >= self.max_total_probes:
                break
            if len(self.findings) >= self.max_findings:
                break

            payload = queue.pop(0)
            if len(str(payload.value)) > self.max_payload_chars:
                continue

            probes_executed += 1
            self.stats["attempted"] += 1

            attack_args = _set_path(baseline_args, candidate.path, payload.value)
            before_index = len(getattr(self.engine, "traces", []))
            observation = await self._invoke(tool_name, attack_args)
            trace_id = self._trace_id_for(tool_name, attack_args, before_index)

            result = ProbeResult(
                tool_name=tool_name,
                parameter_path=candidate.path_str,
                family=candidate.family,
                probe_type=payload.payload_id,
                payload_id=payload.payload_id,
                oracle_type=payload.oracle_type,
                args=attack_args,
                payload=payload,
                observation_text=observation.text,
                response_shape=observation.response_shape,
                baseline_shape=baseline_obs.response_shape,
                baseline_text=baseline_obs.text,
                channel=observation.channel,
                expected_marker=payload.expected_marker,
                platform=payload.platform,
                trace_entry_id=trace_id,
            )
            result.reflected = _is_reflected(observation.text, payload.value)

            # Computed marker oracle
            marker_outcome = _evaluate_computed_marker(
                observation, payload, baseline_obs.text
            )
            if marker_outcome:
                result.verdict, result.reason = marker_outcome
                result.confidence = "high"
                result.observed_marker = payload.expected_marker
                result.likely_engine = _likely_engine(payload.payload_id)
                confirmed_families.add(candidate.family)
                self.stats["confirmed"] += 1
                param_results.append(result)
                # Stop further probes for this family once confirmed.
                if not self.aggressive:
                    queue = [p for p in queue if p.family != candidate.family]
                continue

            # Parser evidence oracle
            parser_outcome = _evaluate_parser_evidence(
                observation, candidate.family
            )
            if parser_outcome:
                result.verdict, result.reason = parser_outcome
                result.confidence = "medium"
                result.parser_match = _parser_evidence(observation.text, candidate.family)
                parser_families.add(candidate.family)
                self.stats["suspected"] += 1
                param_results.append(result)
                # Schedule confirmation probes if not already done.
                if candidate.family not in _scheduled_confirmation_families(confirmation):
                    confirmation.extend(
                        self._build_confirmation_probes(candidate, payload)
                    )
                continue

            # Reflection-only or inconclusive for now; boolean pairs are
            # evaluated later across the whole parameter.
            if result.reflected:
                result.verdict = VERDICT_REFLECTED_ONLY
                result.reason = "payload reflected without interpretation"
                result.confidence = "high"
                self.stats["reflected"] += 1
            else:
                result.verdict = VERDICT_INCONCLUSIVE
                result.reason = "no oracle fired"
                result.confidence = "low"
                self.stats["inconclusive"] += 1
            param_results.append(result)

        return param_results

    def _build_primary_probes(
        self,
        candidate: ParameterCandidate,
        budget: int,
    ) -> list[InjectionPayload]:
        """Build the initial probe list for a candidate."""
        family = candidate.family
        is_object = _schema_type(candidate.param_schema) == "object"
        probes: list[InjectionPayload] = []

        def add(payloads: list[InjectionPayload]) -> None:
            for p in payloads:
                if len(probes) >= budget:
                    break
                probes.append(p)

        nonce = _fresh_nonce()
        if family == FAMILY_COMMAND:
            add(_generate_command_payloads(nonce))
        elif family == FAMILY_SQL:
            add(_generate_sql_payloads(nonce))
        elif family == FAMILY_TEMPLATE:
            add(_generate_template_payloads(nonce))
        elif family == FAMILY_EXPRESSION:
            add(_generate_expression_payloads(nonce))
        elif family == FAMILY_QUERY:
            add(_generate_query_payloads(nonce, is_object))

        # If aggressive mode is enabled, add a second wave of payloads
        # from the same family to increase coverage.
        if self.aggressive and len(probes) < budget:
            nonce2 = _fresh_nonce()
            if family == FAMILY_COMMAND:
                add(_generate_command_payloads(nonce2))
            elif family == FAMILY_SQL:
                add(_generate_sql_payloads(nonce2))
            elif family == FAMILY_TEMPLATE:
                add(_generate_template_payloads(nonce2))

        return probes

    def _build_confirmation_probes(
        self,
        candidate: ParameterCandidate,
        triggering_payload: InjectionPayload,
    ) -> list[InjectionPayload]:
        """Generate additional probes when parser evidence is observed."""
        family = candidate.family
        nonce = _fresh_nonce()
        if family == FAMILY_COMMAND:
            # Try an alternate computed-marker payload.
            return _generate_command_payloads(nonce)[:2]
        if family == FAMILY_SQL:
            # We already sent a boolean pair in the primary SQL set, so
            # no extra probes are needed; evaluation happens later.
            return []
        if family == FAMILY_TEMPLATE:
            # Try alternate delimiter computed markers.
            return _generate_template_payloads(nonce)[:3]
        if family == FAMILY_QUERY:
            is_object = _schema_type(candidate.param_schema) == "object"
            return _generate_query_payloads(nonce, is_object)
        return []

    def _evaluate_boolean_pairs(self) -> None:
        """Evaluate boolean-differential oracles across stored results."""
        pair_map: dict[tuple[str, str, str, str], list[ProbeResult]] = {}
        for result in self.probe_results:
            payload = self._payload_for_result(result)
            if payload and payload.pair_id:
                key = (
                    result.tool_name,
                    result.parameter_path,
                    result.family,
                    payload.pair_id,
                )
                pair_map.setdefault(key, []).append(result)

        baseline_obs = self.baseline_results
        for key, pair_results in pair_map.items():
            tool_name = key[0]
            baseline = baseline_obs.get(tool_name)
            if baseline is None:
                continue
            outcome = _evaluate_boolean_differential(baseline, pair_results)
            if outcome:
                verdict, reason = outcome
                for res in pair_results:
                    old = res.verdict
                    if old == VERDICT_CONFIRMED_INJECTION:
                        continue
                    if verdict == VERDICT_CONFIRMED_INJECTION:
                        res.verdict = verdict
                        res.reason = reason
                        res.confidence = "high"
                        self.stats["confirmed"] += 1
                        if old == VERDICT_SUSPECTED_INJECTION:
                            self.stats["suspected"] = max(0, self.stats["suspected"] - 1)
                        elif old == VERDICT_INCONCLUSIVE:
                            self.stats["inconclusive"] = max(0, self.stats["inconclusive"] - 1)
                        elif old == VERDICT_REFLECTED_ONLY:
                            self.stats["reflected"] = max(0, self.stats["reflected"] - 1)
                    elif verdict == VERDICT_SUSPECTED_INJECTION and old not in (
                        VERDICT_SUSPECTED_INJECTION,
                        VERDICT_CONFIRMED_INJECTION,
                    ):
                        res.verdict = verdict
                        res.reason = reason
                        res.confidence = "medium"
                        self.stats["suspected"] += 1
                        if old == VERDICT_INCONCLUSIVE:
                            self.stats["inconclusive"] = max(0, self.stats["inconclusive"] - 1)
                        elif old == VERDICT_REFLECTED_ONLY:
                            self.stats["reflected"] = max(0, self.stats["reflected"] - 1)

    def _payload_for_result(self, result: ProbeResult) -> InjectionPayload | None:
        """Return the original payload for a result."""
        if result.payload and result.payload.payload_id:
            return result.payload
        return None

    def _aggregate_findings(self) -> None:
        """Aggregate confirmed/suspected results into findings."""
        groups: dict[tuple[str, str, str], list[ProbeResult]] = {}
        for result in self.probe_results:
            if result.verdict not in (
                VERDICT_CONFIRMED_INJECTION,
                VERDICT_SUSPECTED_INJECTION,
            ):
                continue
            key = (result.tool_name, result.parameter_path, result.family)
            groups.setdefault(key, []).append(result)

        for (tool_name, param_path, family), results in sorted(groups.items()):
            if len(self.findings) >= self.max_findings:
                break

            best = self._best_result(results)
            if best is None:
                continue

            baseline_obs = self.baseline_results.get(tool_name)
            evidence_items: list[Evidence] = []

            if baseline_obs is not None:
                baseline_args = self._baseline_args.get(tool_name, {})
                excerpt, truncated = _sanitize_excerpt(
                    baseline_obs.text, self.max_response_chars
                )
                evidence_items.append(
                    Evidence(
                        type=EvidenceType.TOOL_INVOCATION,
                        request={
                            "role": "baseline",
                            "tool": tool_name,
                            "arguments": _truncate_args(baseline_args, self.max_argument_chars),
                            "parameter": param_path,
                        },
                        response={
                            "channel": baseline_obs.channel,
                            "is_error": baseline_obs.is_error,
                            "excerpt": excerpt,
                            "truncated": truncated,
                            "shape": baseline_obs.response_shape,
                        },
                        trace_entry_id=None,
                    )
                )

            # Best attack evidence
            evidence_items.extend(
                self._result_evidence(best, baseline_obs, is_primary=True)
            )

            # One alternate payload if it materially differs
            alternates = [r for r in results if r.payload_id != best.payload_id]
            if alternates:
                alt = self._best_result(alternates)
                if alt and alt.verdict in (
                    VERDICT_CONFIRMED_INJECTION,
                    VERDICT_SUSPECTED_INJECTION,
                ):
                    evidence_items.extend(
                        self._result_evidence(alt, baseline_obs, is_primary=False)
                    )

            if not evidence_items:
                continue

            verdict = best.verdict
            severity = _FAMILY_SEVERITY.get(family, Severity.MEDIUM)
            if verdict == VERDICT_SUSPECTED_INJECTION:
                severity = self._downgrade_severity(severity)

            title = (
                f"Confirmed {family.replace('_', ' ')} in '{tool_name}.{param_path}'"
                if verdict == VERDICT_CONFIRMED_INJECTION
                else f"Suspected {family.replace('_', ' ')} in '{tool_name}.{param_path}'"
            )

            description = (
                f"Tool '{tool_name}' may interpret attacker-controlled input in "
                f"parameter '{param_path}' ({family}). Verdict: {verdict}. "
                f"Oracle: {best.oracle_type}. {best.reason}"
            )

            attack_narrative = (
                f"1. Discovered tool '{tool_name}' via Phase 0 / tools/list\n"
                f"2. Selected parameter '{param_path}' as a {family} candidate\n"
                f"3. Built a valid baseline request preserving required siblings\n"
                f"4. Executed baseline invocation\n"
                f"5. Sent adversarial payload '{best.payload_id}'\n"
                f"6. Observed {best.channel} response\n"
                f"7. Oracle '{best.oracle_type}' produced verdict: {verdict}\n"
                f"8. Rationale: {best.reason}"
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
                        "Parameter injection requires input validation, safe APIs, "
                        "parameterized queries, sandboxed expression handling, or "
                        "strict separation between data and interpreter syntax."
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
                        "1. Validate and sanitize all user-controlled input before "
                        "embedding it in commands, queries, templates, or expressions. "
                        "2. Use parameterized queries and safe APIs instead of string "
                        "interpolation. 3. Run templates and expressions in a sandbox "
                        "with restricted builtins. 4. Avoid passing raw user input to "
                        "shell, SQL, or expression evaluators."
                    ),
                )
            )

    def _best_result(self, results: list[ProbeResult]) -> ProbeResult | None:
        """Return the strongest result from a group."""
        if not results:
            return None
        verdict_order = {
            VERDICT_CONFIRMED_INJECTION: 0,
            VERDICT_SUSPECTED_INJECTION: 1,
        }
        return min(
            results,
            key=lambda r: (
                verdict_order.get(r.verdict, 9),
                _confidence_rank(r.confidence),
                _severity_rank(_FAMILY_SEVERITY.get(r.family, Severity.LOW)),
                r.payload_id,
            ),
        )

    def _result_evidence(
        self,
        result: ProbeResult,
        baseline_obs: NormalizedObservation | None,
        is_primary: bool,
    ) -> list[Evidence]:
        excerpt, truncated = _sanitize_excerpt(
            result.observation_text, self.max_response_chars
        )
        request_meta = {
            "role": "attack" if is_primary else "alternate",
            "tool": result.tool_name,
            "parameter": result.parameter_path,
            "arguments": _truncate_args(result.args, self.max_argument_chars),
            "payload_id": result.payload_id,
            "family": result.family,
            "probe_type": result.probe_type,
            "oracle_type": result.oracle_type,
            "platform": result.platform,
        }
        response_meta = {
            "channel": result.channel,
            "is_error": result.channel in ("mcp_error", "exception", "timeout"),
            "expected_marker": result.expected_marker,
            "observed_marker": result.observed_marker,
            "reflected": result.reflected,
            "parser_match": result.parser_match,
            "likely_engine": result.likely_engine,
            "excerpt": excerpt,
            "truncated": truncated,
            "shape": result.response_shape,
            "rationale": result.reason,
            "verdict": result.verdict,
        }
        if baseline_obs is not None:
            response_meta["baseline_shape"] = baseline_obs.response_shape

        evidence = [
            Evidence(
                type=EvidenceType.TOOL_INVOCATION,
                request=request_meta,
                response=response_meta,
                trace_entry_id=result.trace_entry_id,
            )
        ]

        # For boolean pairs, also include the partner trace when available.
        if result.related_trace_entry_id:
            evidence.append(
                Evidence(
                    type=EvidenceType.TOOL_INVOCATION,
                    request={**request_meta, "role": "boolean_pair"},
                    response={**response_meta, "partner_trace_id": result.related_trace_entry_id},
                    trace_entry_id=result.related_trace_entry_id,
                )
            )
        return evidence

    def _reconstruct_baseline_args(self, result: ProbeResult) -> dict[str, Any]:
        """Best-effort reconstruction of baseline args by removing the payload."""
        args = copy.deepcopy(result.args)
        path = result.parameter_path.split(".")
        node = args
        for key in path[:-1]:
            if isinstance(node, dict) and key in node:
                node = node[key]
            else:
                return args
        if isinstance(node, dict) and path:
            last = path[-1]
            if last in node:
                # Restore a neutral placeholder for the baseline summary.
                node[last] = "<BASELINE>"
        return args

    def _downgrade_severity(self, severity: Severity) -> Severity:
        if severity == Severity.CRITICAL:
            return Severity.HIGH
        if severity == Severity.HIGH:
            return Severity.MEDIUM
        if severity == Severity.MEDIUM:
            return Severity.LOW
        return Severity.INFO


# Helper used by _probe_candidate to avoid scheduling duplicate confirmation
# probes for the same family.
def _scheduled_confirmation_families(confirmation: list[InjectionPayload]) -> set[str]:
    return {p.family for p in confirmation}
