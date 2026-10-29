from __future__ import annotations

from typing import Any

import pytest

from src.attacks.b3_path_traversal import (
    PT_VERDICT_CONFIRMED_FILE_READ,
    PT_VERDICT_INCONCLUSIVE,
    PT_VERDICT_NOT_TESTABLE,
    PT_VERDICT_SUSPECTED,
    B3PathTraversal,
    PathTraversalPayload,
    build_default_payloads,
    find_path_candidates,
    is_path_name,
)
from src.models import Severity
from tests.attack_test_utils import MockEngine, set_phase0


# ── Shared helpers ──


def _is_traversal_value(value: Any) -> bool:
    """Heuristic used by the mock engine to decide which calls are probes."""
    if not isinstance(value, str):
        return False
    lower = value.lower()
    return (
        ".." in value
        or "/etc/passwd" in lower
        or "win.ini" in lower
        or value.startswith("C:\\")
        or value.startswith("C:/")
        or ("%" in value and "passwd" in lower)
        or "...." in value
        or "..;" in value
        or "‥" in value
        or "．" in value
    )


class _TraceEntry:
    def __init__(self, entry_id: str, method: str, request: dict[str, Any]):
        self.id = entry_id
        self.method = method
        self.request = request
        self.response = None
        self.error = None


class TraversalMockEngine(MockEngine):
    """Mock engine that distinguishes control calls from traversal probes."""

    def __init__(
        self,
        traversal_response_text: str = "root:x:0:0:root:/root:/bin/bash\n",
        control_response_text: str = "ok",
        record_traces: bool = False,
        **kwargs: Any,
    ):
        super().__init__(**kwargs)
        self.traversal_response_text = traversal_response_text
        self.control_response_text = control_response_text
        self.record_traces = record_traces
        self._trace_counter = 0

    async def call_tool(self, name: str, arguments: dict[str, Any] | None = None):
        args = arguments or {}
        self.call_history.append({"name": name, "arguments": args})

        if self.record_traces:
            self._trace_counter += 1
            self.traces.append(
                _TraceEntry(
                    entry_id=f"trace-{self._trace_counter}",
                    method="tools/call",
                    request={"name": name, "arguments": args},
                )
            )

        is_traversal = any(_is_traversal_value(v) for v in args.values())
        text = self.traversal_response_text if is_traversal else self.control_response_text

        return {
            "isError": False,
            "content": [{"type": "text", "text": text}],
        }


# ── A. Payload corpus metadata and ordering ──


def test_payload_metadata_complete():
    for payload in build_default_payloads():
        assert isinstance(payload, PathTraversalPayload)
        assert payload.payload_id
        assert payload.category
        assert payload.value
        assert payload.platform
        assert payload.encoding_transform
        assert payload.target_file
        assert payload.expected_signatures
        assert payload.safety == "controlled_read_only"
        assert payload.source
        assert payload.equivalence_group
        assert "/etc/shadow" not in payload.target_file
        assert not payload.target_file.startswith("/proc/")
        assert "file://" not in payload.value


def test_default_order_is_deterministic():
    ids_a = [p.payload_id for p in build_default_payloads()]
    ids_b = [p.payload_id for p in build_default_payloads()]
    assert ids_a == ids_b


def test_default_payloads_have_no_exact_duplicates():
    values = [p.value for p in build_default_payloads()]
    assert len(values) == len(set(values))


def test_literal_encoded_and_mangled_forms_are_preserved():
    payloads = {p.payload_id: p for p in build_default_payloads()}
    assert "rel-depth-3" in payloads
    assert "encoded-dots" in payloads
    assert "encoded-slashes" in payloads
    assert "double-encoded-dots" in payloads
    assert "double-encoded-slashes" in payloads
    assert "mixed-slash-backslash" in payloads
    assert "mangled-four-dot" in payloads


def test_optional_aggressive_payloads_excluded_by_default():
    default = build_default_payloads()
    aggressive_categories = {
        "unicode_normalization",
        "overlong_utf8",
        "null_byte",
        "path_truncation",
        "proxy_specific",
        "windows_relative",
        "windows_encoding",
    }
    for payload in default:
        assert payload.category not in aggressive_categories
        assert payload.platform != "windows"


def test_windows_payloads_only_when_enabled():
    assert not any(p.platform == "windows" for p in build_default_payloads())
    with_windows = build_default_payloads(include_windows=True)
    assert any(p.platform == "windows" for p in with_windows)


def test_aggressive_payloads_only_when_enabled():
    assert not any(p.category == "null_byte" for p in build_default_payloads())
    aggressive = build_default_payloads(include_aggressive=True)
    assert any(p.category == "null_byte" for p in aggressive)
    assert any(p.category == "unicode_normalization" for p in aggressive)


def test_absolute_path_payload_is_distinct():
    payloads = build_default_payloads()
    absolute = [p for p in payloads if p.category == "absolute_path"]
    assert len(absolute) == 1
    assert absolute[0].payload_id == "absolute-unix"


# ── B. Path parameter detection ──


def test_is_path_name_accepts_strong_candidates():
    assert is_path_name("path") is True
    assert is_path_name("file") is True
    assert is_path_name("filepath") is True
    assert is_path_name("file_path") is True
    assert is_path_name("filename") is True
    assert is_path_name("file_name") is True
    assert is_path_name("directory") is True
    assert is_path_name("folder") is True
    assert is_path_name("source_file") is True
    assert is_path_name("target_path") is True


def test_is_path_name_rejects_weak_or_unrelated_candidates():
    assert is_path_name("path_id") is False
    assert is_path_name("file_id") is False
    assert is_path_name("file_type") is False
    assert is_path_name("callback_token") is False
    assert is_path_name("user_id") is False
    assert is_path_name("token") is False


def test_find_path_candidates_supports_both_schema_keys():
    tool_snake = {
        "name": "t1",
        "input_schema": {
            "type": "object",
            "properties": {"path": {"type": "string"}},
        },
    }
    tool_camel = {
        "name": "t2",
        "inputSchema": {
            "type": "object",
            "properties": {"file_path": {"type": "string"}},
        },
    }
    assert find_path_candidates(tool_snake) == [("path", {"type": "string"})]
    assert find_path_candidates(tool_camel) == [("file_path", {"type": "string"})]


def test_find_path_candidates_rejects_non_path_params():
    tool = {
        "name": "t",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path_id": {"type": "string"},
                "file_id": {"type": "string"},
                "file_type": {"type": "string"},
                "callback_token": {"type": "string"},
            },
        },
    }
    assert find_path_candidates(tool) == []


# ── C. Positive detection ──


@pytest.mark.asyncio
async def test_b3_confirms_etc_passwd_read():
    engine = TraversalMockEngine()
    set_phase0(
        engine,
        tools=[
            {
                "name": "read_file",
                "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}},
            }
        ],
    )

    module = B3PathTraversal(engine)
    findings = await module.run()

    assert len(findings) == 1
    finding = findings[0]
    assert finding.id == "B3-001"
    assert finding.severity == Severity.HIGH
    assert finding.evidence[0].request.get("role") == "control"
    confirmed_evidence = finding.evidence[1:]
    assert len(confirmed_evidence) >= 2
    payload_ids = {e.request.get("payload_id") for e in confirmed_evidence}
    assert "rel-depth-3" in payload_ids
    assert "absolute-unix" in payload_ids


@pytest.mark.asyncio
async def test_b3_aggregates_multiple_successful_payloads():
    engine = TraversalMockEngine()
    set_phase0(
        engine,
        tools=[
            {
                "name": "read_file",
                "inputSchema": {"type": "object", "properties": {"file_path": {"type": "string"}}},
            }
        ],
    )

    module = B3PathTraversal(engine)
    findings = await module.run()

    assert len(findings) == 1
    finding = findings[0]
    payload_ids = [e.request.get("payload_id") for e in finding.evidence[1:]]
    assert len(payload_ids) == len(set(payload_ids))
    assert len(payload_ids) > 1


@pytest.mark.asyncio
async def test_b3_encoded_and_double_encoded_payloads_detected():
    engine = TraversalMockEngine()
    set_phase0(
        engine,
        tools=[
            {
                "name": "read_file",
                "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}},
            }
        ],
    )

    module = B3PathTraversal(engine)
    findings = await module.run()

    payload_ids = {e.request.get("payload_id") for e in findings[0].evidence[1:]}
    assert "encoded-dots" in payload_ids
    assert "encoded-slashes" in payload_ids
    assert "fully-encoded" in payload_ids
    assert "double-encoded-dots" in payload_ids
    assert "double-encoded-slashes" in payload_ids


# ── D. Negative / false-positive rejection ──


@pytest.mark.asyncio
async def test_b3_does_not_flag_clean_file_response():
    engine = TraversalMockEngine(
        control_response_text="ok",
        traversal_response_text="contents of requested file",
    )
    set_phase0(
        engine,
        tools=[
            {
                "name": "read_file",
                "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}},
            }
        ],
    )

    findings = await B3PathTraversal(engine).run()
    assert findings == []


@pytest.mark.asyncio
async def test_b3_skips_tools_without_path_like_parameters():
    engine = TraversalMockEngine()
    set_phase0(
        engine,
        tools=[
            {
                "name": "echo",
                "inputSchema": {"type": "object", "properties": {"message": {"type": "string"}}},
            }
        ],
    )

    findings = await B3PathTraversal(engine).run()
    assert findings == []
    assert engine.call_history == []


@pytest.mark.asyncio
async def test_b3_rejects_echo_reflection():
    engine = TraversalMockEngine(traversal_response_text="echo: ../../../etc/passwd")
    set_phase0(
        engine,
        tools=[
            {
                "name": "read_file",
                "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}},
            }
        ],
    )

    findings = await B3PathTraversal(engine).run()
    assert findings == []


@pytest.mark.asyncio
async def test_b3_rejects_permission_denied():
    engine = TraversalMockEngine(traversal_response_text="permission denied: /etc/passwd")
    set_phase0(
        engine,
        tools=[
            {
                "name": "read_file",
                "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}},
            }
        ],
    )

    findings = await B3PathTraversal(engine).run()
    assert findings == []


@pytest.mark.asyncio
async def test_b3_rejects_access_denied():
    engine = TraversalMockEngine(traversal_response_text="access denied: /etc/passwd")
    set_phase0(
        engine,
        tools=[
            {
                "name": "read_file",
                "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}},
            }
        ],
    )

    findings = await B3PathTraversal(engine).run()
    assert findings == []


@pytest.mark.asyncio
async def test_b3_rejects_etc_directory_leak():
    engine = TraversalMockEngine(traversal_response_text="/etc/ directory listing\n.\n..\nhome")
    set_phase0(
        engine,
        tools=[
            {
                "name": "read_file",
                "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}},
            }
        ],
    )

    findings = await B3PathTraversal(engine).run()
    assert findings == []


@pytest.mark.asyncio
async def test_b3_rejects_mcp_error_response():
    engine = MockEngine()
    set_phase0(
        engine,
        tools=[
            {
                "name": "read_file",
                "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}},
            }
        ],
    )
    # All calls return an MCP error.
    engine._call_results = {
        key: {"isError": True, "content": [{"type": "text", "text": "root:x:0:0:root"}]}
        for key in [
            ("read_file", str(sorted({"path": "test.txt"}.items()))),
            ("read_file", str(sorted({"path": "../../../etc/passwd"}.items()))),
        ]
    }

    findings = await B3PathTraversal(engine).run()
    assert findings == []


# ── E. Safe arguments and dangerous siblings ──


@pytest.mark.asyncio
async def test_b3_generates_safe_sibling_arguments():
    engine = TraversalMockEngine()
    set_phase0(
        engine,
        tools=[
            {
                "name": "read_file",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string"},
                        "encoding": {"type": "string", "enum": ["utf-8", "base64"]},
                        "recursive": {"type": "boolean", "default": False},
                        "verbose": {"type": "boolean"},
                    },
                    "required": ["path", "encoding"],
                },
            }
        ],
    )

    await B3PathTraversal(engine).run()

    traversal_calls = [
        call for call in engine.call_history if _is_traversal_value(call["arguments"].get("path"))
    ]
    assert traversal_calls
    for call in traversal_calls:
        assert call["arguments"].get("encoding") == "utf-8"
        # Optional siblings are skipped; only required siblings are filled.
        assert "recursive" not in call["arguments"]
        assert "verbose" not in call["arguments"]


@pytest.mark.asyncio
async def test_b3_skips_dangerous_siblings():
    engine = TraversalMockEngine()
    set_phase0(
        engine,
        tools=[
            {
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
        ],
    )

    module = B3PathTraversal(engine)
    findings = await module.run()

    assert findings == []
    assert engine.call_history == []
    assert module.stats["skipped"] >= 1
    assert any(
        r.verdict == PT_VERDICT_NOT_TESTABLE for r in module.probe_results
    )


# ── F. Limits, tracing, and reset ──


@pytest.mark.asyncio
async def test_b3_enforces_probe_limits():
    engine = TraversalMockEngine()
    set_phase0(
        engine,
        tools=[
            {
                "name": "read_file",
                "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}},
            }
        ],
    )

    module = B3PathTraversal(
        engine,
        max_payloads_per_candidate=12,
        max_total_payloads=5,
    )
    findings = await module.run()

    assert module.stats["attempted"] == 5
    assert len(module.probe_results) == 5
    # The first five default payloads confirm, so one finding is still emitted.
    assert len(findings) == 1


@pytest.mark.asyncio
async def test_b3_trace_entry_ids_correlate():
    engine = TraversalMockEngine(record_traces=True)
    set_phase0(
        engine,
        tools=[
            {
                "name": "read_file",
                "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}},
            }
        ],
    )

    module = B3PathTraversal(engine)
    findings = await module.run()

    confirmed_evidence = findings[0].evidence[1:]
    trace_ids = {e.trace_entry_id for e in confirmed_evidence}
    assert None not in trace_ids
    expected_ids = {f"trace-{i}" for i in range(2, len(confirmed_evidence) + 2)}
    assert trace_ids == expected_ids


@pytest.mark.asyncio
async def test_b3_repeated_run_resets_state():
    engine = TraversalMockEngine()
    set_phase0(
        engine,
        tools=[
            {
                "name": "read_file",
                "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}},
            }
        ],
    )

    module = B3PathTraversal(engine)
    findings1 = await module.run()
    findings2 = await module.run()

    assert len(findings1) == len(findings2) == 1
    assert findings1[0].id == findings2[0].id == "B3-001"
    assert module.stats["attempted"] == len(build_default_payloads())


@pytest.mark.asyncio
async def test_b3_suspected_when_control_contains_signature():
    engine = TraversalMockEngine(
        control_response_text="root:x:0:0:root:/root:/bin/bash\n",
        traversal_response_text="root:x:0:0:root:/root:/bin/bash\n",
    )
    set_phase0(
        engine,
        tools=[
            {
                "name": "read_file",
                "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}},
            }
        ],
    )

    module = B3PathTraversal(engine)
    findings = await module.run()

    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity == Severity.MEDIUM
    assert "suspected" in finding.title.lower()
    assert "control" in finding.evidence[0].request.get("role", "")
