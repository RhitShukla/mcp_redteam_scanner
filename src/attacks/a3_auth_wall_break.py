"""
E2 - Auth Wall Break.

Detects actual authorization-boundary failures, not merely privileged-looking
tools or successful calls by an authenticated identity.

Verdict taxonomy:
    authorized          - known/assumed entitled context (no finding)
    denied              - explicit auth denial (no finding)
    confirmed_bypass    - unauthorized context executed protected capability
    suspected_bypass    - strong unauthorized-access signal, incomplete proof
    inconclusive        - ambiguous result (no finding)
    not_testable        - cannot build safe args / unsafe schema (no finding)
    not_run             - module disabled / no tools (no finding)

Only confirmed_bypass and suspected_bypass produce Finding objects.
"""

from __future__ import annotations

import re
from typing import Any

from src.attack_base import AttackModule
from src.models import AuthMethod, Evidence, EvidenceType, Fixability, Finding, ReplayInfo, Severity


# ── Verdicts ──

VERDICT_AUTHORIZED = "authorized"
VERDICT_DENIED = "denied"
VERDICT_CONFIRMED_BYPASS = "confirmed_bypass"
VERDICT_SUSPECTED_BYPASS = "suspected_bypass"
VERDICT_INCONCLUSIVE = "inconclusive"
VERDICT_NOT_TESTABLE = "not_testable"
VERDICT_NOT_RUN = "not_run"


# ── Configuration ──

_DEFAULT_MAX_CANDIDATES = 5
_DEFAULT_MAX_CALLS_PER_CANDIDATE = 3
_DEFAULT_MAX_TOTAL_CALLS = 25
_DEFAULT_MAX_RESPONSE_CHARS = 12_000
_DEFAULT_MAX_ARGUMENT_CHARS = 4_096
_DEFAULT_MAX_FINDINGS = 50
_DEFAULT_MAX_SCHEMA_DEPTH = 3

_DEFAULT_PROTECTED_CAPABILITY_MARKERS = (
    "E2_PROTECTED_CAPABILITY_MARKER",
)

# Capability-level indicators. These are prioritization/interpretation signals,
# not proof of privilege. A tool name alone never establishes a bypass.
_PRIVILEGED_CAPABILITY_KEYWORDS = (
    "role", "permission", "scope", "acl", "rbac", "policy", "authorize",
    "admin", "administrator", "superuser", "root", "sudo",
    "user_management", "tenant", "impersonate", "delegation",
    "configure", "config", "settings", "system",
    "secret", "credential", "password", "api_key", "token", "private_key",
    "process", "service", "daemon", "exec", "shell", "run_command",
    "audit", "log", "internal", "debug", "diagnostic", "privileged",
)

# Stronger signals used only for suspected_bypass heuristics.
_SUSPECTED_CAPABILITY_SIGNALS = (
    "secret", "password", "credential", "api_key", "token", "private",
    "config", "policy", "role", "permission", "tenant", "user_id",
    "admin", "protected", "restricted",
)

# Parameters that E2 will not fabricate values for unless a safe default,
# example, or enum is provided in the schema.
_DANGEROUS_PARAM_NAMES = {
    "command", "cmd", "shell", "exec", "execute", "script", "code",
    "path", "file", "filename", "filepath", "directory", "dir", "folder",
    "url", "uri", "endpoint", "host", "query", "sql", "raw_query",
    "action", "operation", "system", "eval", "run", "program",
}

_AUTHORIZATION_DENIAL_PATTERNS = [
    re.compile(r"\bunauthorized\b", re.IGNORECASE),
    re.compile(r"\bforbidden\b", re.IGNORECASE),
    re.compile(r"\baccess denied\b", re.IGNORECASE),
    re.compile(r"\bpermission denied\b", re.IGNORECASE),
    re.compile(r"\bauthentication required\b", re.IGNORECASE),
    re.compile(r"\bauth required\b", re.IGNORECASE),
    re.compile(r"\bnot allowed\b", re.IGNORECASE),
    re.compile(r"\binsufficient (?:scope|permission|role|rights|privilege)\b", re.IGNORECASE),
    re.compile(r"\bpolicy denied\b", re.IGNORECASE),
    re.compile(r"\brole required\b", re.IGNORECASE),
    re.compile(r"\blogin required\b", re.IGNORECASE),
    re.compile(r"\bmust be authenticated\b", re.IGNORECASE),
]


# ── Schema helpers ──


def _get_tool_schema(tool: dict[str, Any]) -> dict[str, Any]:
    """Return the usable input schema, supporting both key variants."""
    standard = tool.get("inputSchema")
    alias = tool.get("input_schema")
    if isinstance(standard, dict) and standard:
        return standard
    if isinstance(alias, dict) and alias:
        return alias
    return {}


def _schema_type(param_schema: dict[str, Any]) -> str:
    """Return a representative type from a schema fragment."""
    t = param_schema.get("type")
    if isinstance(t, list):
        for candidate in t:
            if candidate in ("string", "integer", "number", "boolean", "object", "array"):
                return candidate
        return "string"
    if t in ("string", "integer", "number", "boolean", "object", "array"):
        return t
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


def _is_dangerous_param(name: str) -> bool:
    return name.lower() in _DANGEROUS_PARAM_NAMES


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
                    obj[name] = _safe_value_for_property(sub_schema, depth + 1)
            return obj
        return {}
    return "test"


def _safe_value_for_property(param_schema: dict[str, Any], depth: int = 0) -> Any:
    """Return a safe value from default/example/enum/type fallback."""
    default = param_schema.get("default")
    if default is not None:
        return default

    example = param_schema.get("example")
    if example is not None:
        return example

    examples = param_schema.get("examples")
    if isinstance(examples, list) and examples:
        return examples[0]

    enum_values = param_schema.get("enum")
    if isinstance(enum_values, list) and enum_values:
        return enum_values[0]

    return _safe_default_for_type(param_schema, depth)


def _build_safe_args(tool: dict[str, Any]) -> tuple[dict[str, Any] | None, str | None]:
    """
    Build minimally valid, safe arguments for a tool.

    Returns (args, reason). reason is set when the tool is not testable,
    e.g. a dangerous required parameter has no safe value.
    """
    schema = _get_tool_schema(tool)
    if not schema:
        return {}, None

    properties = schema.get("properties", {})
    if not isinstance(properties, dict):
        return {}, None

    required = set(schema.get("required", []))
    args: dict[str, Any] = {}

    for name, spec in sorted(properties.items()):
        if name not in required:
            # Minimally valid: do not populate optional properties.
            continue

        if not isinstance(spec, dict):
            spec = {}

        if _is_dangerous_param(name):
            has_safe_value = any(
                spec.get(k) is not None
                for k in ("default", "example", "examples", "enum")
            )
            if not has_safe_value:
                return None, f"dangerous required parameter '{name}' has no safe value"

        args[name] = _safe_value_for_property(spec)

    return args, None


# ── Auth context ──


def _effective_auth_context(engine: Any) -> dict[str, Any]:
    """Derive the effective authentication context from engine configuration."""
    config = engine.config
    method = getattr(config, "auth_method", AuthMethod.NONE)
    # A token only matters when the configured auth method would actually send it.
    token_present = (
        method != AuthMethod.NONE and bool(getattr(config, "auth_token", None))
    )

    if method == AuthMethod.NONE:
        effective = "unauthenticated"
    elif token_present:
        effective = "authenticated_unknown"
    else:
        effective = "auth_configured_no_token"

    identity = None
    session_id = None
    try:
        session = engine.active_session
        if session is not None:
            identity = session.auth_identity
            session_id = session.session_id
    except Exception:
        pass

    return {
        "auth_method": method.value,
        "token_present": token_present,
        "effective_context": effective,
        "identity": identity,
        "session_id": session_id,
    }


def _is_unauthorized_context(auth_context: dict[str, Any]) -> bool:
    return auth_context["effective_context"] in ("unauthenticated", "auth_configured_no_token")


# ── Response normalization ──


def _extract_text_fragments(value: Any, fragments: list[str], seen: set[str], depth: int = 0) -> None:
    """Recursively collect unique text fragments in encounter order."""
    if isinstance(value, str):
        if value and value not in seen:
            seen.add(value)
            fragments.append(value)
        if depth < 3 and "\\" in value:
            try:
                parsed = __import__("json").loads(value)
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
            if isinstance(k, str):
                _extract_text_fragments(k, fragments, seen, depth)
            _extract_text_fragments(v, fragments, seen, depth)
        return


def _response_text(response: dict[str, Any] | None) -> str:
    """Return normalized text from an MCP response dict."""
    if not isinstance(response, dict):
        return ""
    fragments: list[str] = []
    seen: set[str] = set()
    for key in ("content", "error", "message", "details"):
        _extract_text_fragments(response.get(key), fragments, seen)
    return "\n".join(fragments)


def _is_auth_denial(response: dict[str, Any] | None, error: str | None) -> bool:
    """Return True if response/error contains an explicit authorization denial."""
    text_parts: list[str] = []
    if error:
        text_parts.append(error)
    if isinstance(response, dict):
        for key in ("content", "error", "message", "details"):
            val = response.get(key)
            if isinstance(val, str):
                text_parts.append(val)
            elif isinstance(val, dict):
                text_parts.append(str(val.get("message", "")))
                text_parts.append(str(val.get("code", "")))
            elif isinstance(val, list):
                for item in val:
                    if isinstance(item, dict):
                        text_parts.append(str(item.get("text", "")))
    text = " ".join(text_parts)
    return any(p.search(text) for p in _AUTHORIZATION_DENIAL_PATTERNS)


def _is_reflected(response_text: str, args: dict[str, Any]) -> bool:
    """Return True if any argument value appears literally in the response."""
    for value in args.values():
        if isinstance(value, str) and value and value in response_text:
            return True
        if str(value) in response_text:
            return True
    return False


def _extract_capability_proof(
    response_text: str,
    args: dict[str, Any],
    markers: tuple[str, ...],
) -> str | None:
    """Return the first protected-capability marker that is not reflected from args."""
    arg_values = {str(v) for v in args.values() if v is not None}
    for marker in markers:
        if marker in response_text and not any(marker in av for av in arg_values):
            return marker
    return None


def _suspected_capability_signal(response_text: str, args: dict[str, Any]) -> str | None:
    """Return a suspected signal keyword if present and not merely reflected."""
    if _is_reflected(response_text, args):
        return None
    lowered = response_text.lower()
    for signal in _SUSPECTED_CAPABILITY_SIGNALS:
        if signal in lowered:
            return signal
    return None


# ── Truncation helpers ──


def _truncate_text(text: str, max_len: int = _DEFAULT_MAX_RESPONSE_CHARS) -> str:
    if len(text) <= max_len:
        return text
    head = text[: max_len // 2]
    tail = text[-max_len // 2 :]
    return f"{head}\n...[{len(text) - len(head) - len(tail)} bytes omitted]...\n{tail}"


def _truncate_args(args: dict[str, Any], max_len: int = _DEFAULT_MAX_ARGUMENT_CHARS) -> dict[str, Any]:
    """Return a shallow copy of args with long values truncated for evidence."""
    truncated: dict[str, Any] = {}
    for k, v in args.items():
        s = str(v)
        if len(s) > max_len:
            truncated[k] = s[:max_len] + "...[truncated]"
        else:
            truncated[k] = v
    return truncated


# ── Module ──


class A3AuthWallBreak(AttackModule):
    """
    Authorization-boundary assessment for MCP tools.

    Focuses on whether an unauthorized or unauthenticated caller can execute a
    protected capability. A successful call by an authenticated identity with
    unknown role is NOT reported as a bypass.
    """

    name = "Auth Wall Break Heuristics"
    surface = "E - Transport & Authentication"
    module_id = "E2"
    description = (
        "Tests whether authorization boundaries actually prevent unauthenticated or "
        "unauthorized callers from executing protected capabilities. Requires "
        "deterministic protected-capability evidence before reporting a bypass."
    )

    def __init__(
        self,
        engine: Any,
        *,
        max_candidates: int = _DEFAULT_MAX_CANDIDATES,
        max_calls_per_candidate: int = _DEFAULT_MAX_CALLS_PER_CANDIDATE,
        max_total_calls: int = _DEFAULT_MAX_TOTAL_CALLS,
        max_response_chars: int = _DEFAULT_MAX_RESPONSE_CHARS,
        max_argument_chars: int = _DEFAULT_MAX_ARGUMENT_CHARS,
        max_findings: int = _DEFAULT_MAX_FINDINGS,
        protected_capability_markers: tuple[str, ...] | None = None,
    ) -> None:
        super().__init__(engine)
        self.max_candidates = max_candidates
        self.max_calls_per_candidate = max_calls_per_candidate
        self.max_total_calls = max_total_calls
        self.max_response_chars = max_response_chars
        self.max_argument_chars = max_argument_chars
        self.max_findings = max_findings
        self.protected_markers = protected_capability_markers or _DEFAULT_PROTECTED_CAPABILITY_MARKERS

        self.stats: dict[str, int] = {
            "attempted": 0,
            "denied": 0,
            "confirmed": 0,
            "suspected": 0,
            "inconclusive": 0,
            "not_testable": 0,
            "not_run": 0,
        }

    async def run(self) -> list[Finding]:
        """Execute bounded authorization-boundary probes."""
        self.findings.clear()
        self._finding_counter = 0
        self.stats = {
            "attempted": 0,
            "denied": 0,
            "confirmed": 0,
            "suspected": 0,
            "inconclusive": 0,
            "not_testable": 0,
            "not_run": 0,
        }

        tools = await self._get_tools()
        if not tools:
            self.stats["not_run"] += 1
            return self.findings

        auth_context = _effective_auth_context(self.engine)

        candidates = self._select_candidates(tools)
        if not candidates:
            self.stats["not_run"] += 1
            return self.findings

        total_calls = 0
        results: list[dict[str, Any]] = []

        for tool in candidates:
            if total_calls >= self.max_total_calls:
                break
            if len(self.findings) >= self.max_findings:
                break

            name = str(tool.get("name", ""))
            if not name:
                continue

            args, not_testable_reason = _build_safe_args(tool)
            if args is None:
                self.stats["not_testable"] += 1
                results.append(self._not_testable_result(name, not_testable_reason or "unsafe schema"))
                continue

            # Initial invocation
            response, error, trace_id, session_id = await self._invoke(name, args)
            total_calls += 1
            self.stats["attempted"] += 1

            if total_calls < self.max_total_calls:
                # Replay is supporting evidence only; it must not trigger a finding.
                replay_response, replay_error, replay_trace_id, _ = await self._invoke(name, args)
                total_calls += 1
            else:
                replay_response = replay_error = replay_trace_id = None

            result = self._evaluate_invocation(
                tool_name=name,
                args=args,
                auth_context=auth_context,
                response=response,
                error=error,
                trace_id=trace_id,
                session_id=session_id,
                replay_response=replay_response,
                replay_error=replay_error,
                replay_trace_id=replay_trace_id,
            )
            results.append(result)

        self._aggregate_findings(results, auth_context)
        return self.findings

    async def _get_tools(self) -> list[dict[str, Any]]:
        """Return tools from Phase 0 or from a live tools/list call."""
        phase0 = self.get_phase0_context()
        tools = phase0.get("tools")
        if not isinstance(tools, list):
            try:
                tools = await self.engine.list_tools()
            except Exception:
                tools = []
        return tools if isinstance(tools, list) else []

    def _select_candidates(self, tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Select privileged-looking tools using capability-level signals."""
        # Plan A: exact Phase 0 tool targets (not tool-parameter, tool-description, etc.)
        target_names: set[str] = set()
        for target in self.get_attack_targets("Critical") + self.get_attack_targets("High"):
            if str(target.get("target_type", "")) == "tool":
                target_names.add(str(target.get("target_name", "")).lower())

        scored: list[tuple[int, str, dict[str, Any]]] = []
        for tool in tools:
            name = str(tool.get("name", ""))
            score = self._score_privileged_tool(tool)
            if name.lower() in target_names:
                score += 50
            if score > 0:
                scored.append((score, name, tool))

        scored.sort(key=lambda item: (-item[0], item[1]))
        return [item[2] for item in scored[: self.max_candidates]]

    def _score_privileged_tool(self, tool: dict[str, Any]) -> int:
        """Score a tool by capability-level indicators."""
        name = str(tool.get("name", "")).lower()
        desc = str(tool.get("description", "")).lower()
        schema = _get_tool_schema(tool)
        properties = schema.get("properties", {}) if isinstance(schema, dict) else {}
        param_text = " ".join(str(k).lower() for k in properties.keys())

        score = 0
        for kw in _PRIVILEGED_CAPABILITY_KEYWORDS:
            if kw in name:
                score += 3
            if kw in desc:
                score += 2
            if kw in param_text:
                score += 1
        return score

    async def _invoke(
        self,
        tool_name: str,
        args: dict[str, Any],
    ) -> tuple[dict[str, Any] | None, str | None, str | None, str | None]:
        """Call a tool and correlate with the exact TraceEntry produced by ProbeEngine."""
        before_index = len(getattr(self.engine, "traces", []))
        response: dict[str, Any] | None = None
        error: str | None = None
        try:
            response = await self.engine.call_tool(tool_name, args)
        except Exception as exc:
            error = str(exc)

        trace_id: str | None = None
        session_id: str | None = None
        traces = getattr(self.engine, "traces", [])
        # The engine appends a trace synchronously for each call.
        if len(traces) > before_index:
            entry = traces[-1]
            trace_id = entry.id
            session_id = entry.session_id

        return response, error, trace_id, session_id

    def _evaluate_invocation(
        self,
        *,
        tool_name: str,
        args: dict[str, Any],
        auth_context: dict[str, Any],
        response: dict[str, Any] | None,
        error: str | None,
        trace_id: str | None,
        session_id: str | None,
        replay_response: dict[str, Any] | None,
        replay_error: str | None,
        replay_trace_id: str | None,
    ) -> dict[str, Any]:
        """Classify one candidate invocation and replay."""
        response_text = _response_text(response)

        # Explicit authorization denial
        if _is_auth_denial(response, error):
            self.stats["denied"] += 1
            return {
                "tool_name": tool_name,
                "args": args,
                "auth_context": auth_context,
                "verdict": VERDICT_DENIED,
                "confidence": "high",
                "reason": "authorization denial signal observed",
                "response": response,
                "response_text": response_text,
                "error": error,
                "trace_id": trace_id,
                "session_id": session_id,
                "replay_response": replay_response,
                "replay_error": replay_error,
                "replay_trace_id": replay_trace_id,
            }

        # Transport or handler error without auth signal
        if error:
            self.stats["inconclusive"] += 1
            return {
                "tool_name": tool_name,
                "args": args,
                "auth_context": auth_context,
                "verdict": VERDICT_INCONCLUSIVE,
                "confidence": "low",
                "reason": f"transport/handler error: {_truncate_text(error, 200)}",
                "response": response,
                "response_text": response_text,
                "error": error,
                "trace_id": trace_id,
                "session_id": session_id,
                "replay_response": replay_response,
                "replay_error": replay_error,
                "replay_trace_id": replay_trace_id,
            }

        # MCP-level error without explicit auth signal
        if not isinstance(response, dict) or response.get("isError"):
            self.stats["inconclusive"] += 1
            return {
                "tool_name": tool_name,
                "args": args,
                "auth_context": auth_context,
                "verdict": VERDICT_INCONCLUSIVE,
                "confidence": "low",
                "reason": "tool returned error without authorization denial signal",
                "response": response,
                "response_text": response_text,
                "error": error,
                "trace_id": trace_id,
                "session_id": session_id,
                "replay_response": replay_response,
                "replay_error": replay_error,
                "replay_trace_id": replay_trace_id,
            }

        # Successful response
        proof = _extract_capability_proof(response_text, args, self.protected_markers)

        if auth_context["effective_context"] == "authenticated_unknown":
            if proof:
                verdict = VERDICT_AUTHORIZED
                reason = (
                    "authenticated session executed protected capability; "
                    "assuming authorized because no lower-privilege context is configured"
                )
                confidence = "medium"
            else:
                verdict = VERDICT_INCONCLUSIVE
                reason = "authenticated session succeeded but protected-capability proof absent"
                confidence = "low"
            self.stats["inconclusive" if verdict == VERDICT_INCONCLUSIVE else "authorized"] = (
                self.stats.get(verdict, 0) + 1
            )
            return {
                "tool_name": tool_name,
                "args": args,
                "auth_context": auth_context,
                "verdict": verdict,
                "confidence": confidence,
                "reason": reason,
                "response": response,
                "response_text": response_text,
                "protected_marker": proof,
                "error": error,
                "trace_id": trace_id,
                "session_id": session_id,
                "replay_response": replay_response,
                "replay_error": replay_error,
                "replay_trace_id": replay_trace_id,
            }

        # Unauthenticated / auth-configured-no-token contexts
        if _is_unauthorized_context(auth_context):
            if proof:
                self.stats["confirmed"] += 1
                return {
                    "tool_name": tool_name,
                    "args": args,
                    "auth_context": auth_context,
                    "verdict": VERDICT_CONFIRMED_BYPASS,
                    "confidence": "high",
                    "reason": f"protected capability marker observed in unauthenticated context: {proof}",
                    "response": response,
                    "response_text": response_text,
                    "protected_marker": proof,
                    "error": error,
                    "trace_id": trace_id,
                    "session_id": session_id,
                    "replay_response": replay_response,
                    "replay_error": replay_error,
                    "replay_trace_id": replay_trace_id,
                }

            suspected_signal = _suspected_capability_signal(response_text, args)
            if suspected_signal:
                self.stats["suspected"] += 1
                return {
                    "tool_name": tool_name,
                    "args": args,
                    "auth_context": auth_context,
                    "verdict": VERDICT_SUSPECTED_BYPASS,
                    "confidence": "medium",
                    "reason": f"unauthenticated access to privileged capability suggested by '{suspected_signal}'",
                    "response": response,
                    "response_text": response_text,
                    "protected_marker": None,
                    "error": error,
                    "trace_id": trace_id,
                    "session_id": session_id,
                    "replay_response": replay_response,
                    "replay_error": replay_error,
                    "replay_trace_id": replay_trace_id,
                }

        self.stats["inconclusive"] += 1
        return {
            "tool_name": tool_name,
            "args": args,
            "auth_context": auth_context,
            "verdict": VERDICT_INCONCLUSIVE,
            "confidence": "low",
            "reason": "call succeeded without protected-capability proof or authorization denial",
            "response": response,
            "response_text": response_text,
            "protected_marker": proof,
            "error": error,
            "trace_id": trace_id,
            "session_id": session_id,
            "replay_response": replay_response,
            "replay_error": replay_error,
            "replay_trace_id": replay_trace_id,
        }

    def _not_testable_result(self, tool_name: str, reason: str) -> dict[str, Any]:
        return {
            "tool_name": tool_name,
            "args": {},
            "auth_context": _effective_auth_context(self.engine),
            "verdict": VERDICT_NOT_TESTABLE,
            "confidence": "high",
            "reason": reason,
            "response": None,
            "response_text": "",
            "protected_marker": None,
            "error": None,
            "trace_id": None,
            "session_id": None,
            "replay_response": None,
            "replay_error": None,
            "replay_trace_id": None,
        }

    def _aggregate_findings(
        self,
        results: list[dict[str, Any]],
        auth_context: dict[str, Any],
    ) -> None:
        """Emit findings only for confirmed or suspected bypasses."""
        for result in results:
            if len(self.findings) >= self.max_findings:
                break

            verdict = result["verdict"]
            if verdict not in (VERDICT_CONFIRMED_BYPASS, VERDICT_SUSPECTED_BYPASS):
                continue

            tool_name = result["tool_name"]
            args = result["args"]
            trace_id = result["trace_id"]
            session_id = result["session_id"]
            protected_marker = result.get("protected_marker")
            reason = result["reason"]
            confidence = result["confidence"]
            response_text = result.get("response_text", "")

            if verdict == VERDICT_CONFIRMED_BYPASS:
                severity = Severity.HIGH
                title = f"Confirmed authorization bypass on privileged tool '{tool_name}'"
            else:
                severity = Severity.MEDIUM
                title = f"Suspected authorization bypass on privileged tool '{tool_name}'"

            request_evidence = {
                "role": "attack",
                "tool": tool_name,
                "arguments": _truncate_args(args, self.max_argument_chars),
                "auth_method": auth_context["auth_method"],
                "effective_context": auth_context["effective_context"],
                "token_present": auth_context["token_present"],
                "identity": auth_context["identity"],
                "session_id": session_id,
            }

            response_evidence = {
                "channel": "normal_response",
                "is_error": False,
                "authorization_classification": "success",
                "verdict": verdict,
                "confidence": confidence,
                "protected_capability_marker": protected_marker,
                "excerpt": _truncate_text(response_text, self.max_response_chars),
                "trace_entry_id": trace_id,
                "session_id": session_id,
                "rationale": reason,
            }

            evidence_items: list[Evidence] = [
                Evidence(
                    type=EvidenceType.TOOL_INVOCATION,
                    request=request_evidence,
                    response=response_evidence,
                    trace_entry_id=trace_id,
                )
            ]

            if result.get("replay_response") is not None or result.get("replay_error") is not None:
                replay_text = _response_text(result.get("replay_response"))
                evidence_items.append(
                    Evidence(
                        type=EvidenceType.TOOL_INVOCATION,
                        request={**request_evidence, "role": "replay"},
                        response={
                            "channel": "normal_response",
                            "is_error": bool(result.get("replay_error")),
                            "verdict": "supporting_only",
                            "excerpt": _truncate_text(replay_text, self.max_response_chars),
                            "trace_entry_id": result.get("replay_trace_id"),
                            "session_id": session_id,
                            "rationale": "Replay is supporting evidence, not an authorization proof",
                        },
                        trace_entry_id=result.get("replay_trace_id"),
                    )
                )

            finding = Finding(
                id=self._next_finding_id(),
                title=title,
                surface=self.surface,
                module=f"{self.module_id} - {self.name}",
                severity=severity,
                fixability=Fixability.DESIGN,
                fixability_rationale=(
                    "Authorization boundaries must be enforced at the tool-handler boundary "
                    "and server-side policy layer. This usually requires handler/policy redesign."
                ),
                description=(
                    f"Tool '{tool_name}' was invoked in an '{auth_context['effective_context']}' "
                    f"context (auth_method={auth_context['auth_method']}, token_present={auth_context['token_present']}). "
                    f"Verdict: {verdict}. {reason}"
                ),
                attack_narrative=(
                    "1. Enumerated privileged-looking tools from Phase 0 / tools/list\n"
                    f"2. Selected '{tool_name}' as a protected-capability candidate\n"
                    f"3. Built safe, schema-valid arguments: {args}\n"
                    f"4. Invoked tool in '{auth_context['effective_context']}' context\n"
                    f"5. Observed {response_evidence['authorization_classification']} response\n"
                    f"6. Evaluated protected-capability evidence -> {verdict}\n"
                    f"7. Rationale: {reason}"
                ),
                evidence=evidence_items,
                replay=ReplayInfo(
                    command=f"mcp-redteam replay --finding {self.module_id}-{self._finding_counter:03d}",
                    trace_file=f"traces/{self.module_id}-{self._finding_counter:03d}.json",
                ),
                recommendation=(
                    "Enforce explicit authorization checks before executing privileged tool "
                    "handlers. Use deny-by-default policies, role/scope validation, and "
                    "server-side session policy that is independent of tool metadata."
                ),
            )
            self.add_finding(finding)
