"""
Tests for src/utils/ — The Utility Belt.

Covers:
    - payloads.py: Verify payload arrays exist and are well-formed
    - jwt_helpers.py: Token forging, decoding, and manipulation
    - false_positive_diff.py: Response diffing and false positive detection
"""

from __future__ import annotations

import json

import pytest

from src.utils.payloads import (
    SQLI_PAYLOADS,
    CMD_INJECTION_PAYLOADS,
    PATH_TRAVERSAL_PAYLOADS,
    TYPE_CONFUSION_PAYLOADS,
    PROMPT_INJECTION_PAYLOADS,
)
from src.utils.jwt_helpers import (
    forge_alg_none,
    tamper_role,
    decode_jwt_unsafe,
    forge_with_weak_secret,
    COMMON_JWT_SECRETS,
)
from src.utils.false_positive_diff import (
    compute_response_diff,
    is_significant_diff,
    normalize_response,
    extract_text_from_mcp_response,
    DiffResult,
)


# ═══════════════════════════════════════════
#  Payload Tests
# ═══════════════════════════════════════════


class TestPayloads:
    """Verify payload arrays are non-empty and well-formed."""

    def test_sqli_payloads_exist(self):
        assert len(SQLI_PAYLOADS) >= 40
        assert all(isinstance(p, str) for p in SQLI_PAYLOADS)

    def test_cmd_injection_payloads_exist(self):
        assert len(CMD_INJECTION_PAYLOADS) >= 20
        assert all(isinstance(p, str) for p in CMD_INJECTION_PAYLOADS)

    def test_path_traversal_payloads_exist(self):
        assert len(PATH_TRAVERSAL_PAYLOADS) >= 15
        assert all(isinstance(p, str) for p in PATH_TRAVERSAL_PAYLOADS)

    def test_type_confusion_payloads_exist(self):
        assert len(TYPE_CONFUSION_PAYLOADS) >= 10
        assert all(isinstance(p, str) for p in TYPE_CONFUSION_PAYLOADS)

    def test_prompt_injection_payloads_exist(self):
        assert len(PROMPT_INJECTION_PAYLOADS) >= 10
        assert all(isinstance(p, str) for p in PROMPT_INJECTION_PAYLOADS)

    def test_no_duplicate_payloads(self):
        """Each payload list should not contain exact duplicates."""
        for name, payloads in [
            ("SQLI", SQLI_PAYLOADS),
            ("CMD", CMD_INJECTION_PAYLOADS),
            ("PATH", PATH_TRAVERSAL_PAYLOADS),
            ("TYPE", TYPE_CONFUSION_PAYLOADS),
            ("PROMPT", PROMPT_INJECTION_PAYLOADS),
        ]:
            assert len(payloads) == len(set(payloads)), f"Duplicates found in {name}_PAYLOADS"


# ═══════════════════════════════════════════
#  JWT Helper Tests
# ═══════════════════════════════════════════


class TestJWTHelpers:
    """Test JWT forging and manipulation."""

    def test_forge_alg_none_structure(self):
        """alg=none JWT should have 3 parts with empty signature."""
        token = forge_alg_none({"sub": "admin", "role": "admin"})
        parts = token.split(".")
        assert len(parts) == 3
        assert parts[2] == ""  # empty signature

    def test_forge_alg_none_header(self):
        """Header should contain alg=none."""
        token = forge_alg_none({"sub": "test"})
        decoded = decode_jwt_unsafe(token)
        assert decoded["header"]["alg"] == "none"
        assert decoded["header"]["typ"] == "JWT"

    def test_forge_alg_none_payload_preserved(self):
        """Payload claims should be preserved exactly."""
        claims = {"sub": "user123", "role": "admin", "exp": 9999999999}
        token = forge_alg_none(claims)
        decoded = decode_jwt_unsafe(token)
        assert decoded["payload"]["sub"] == "user123"
        assert decoded["payload"]["role"] == "admin"
        assert decoded["payload"]["exp"] == 9999999999

    def test_decode_jwt_unsafe_valid_token(self):
        """Should decode a well-formed JWT."""
        token = forge_alg_none({"sub": "test", "iss": "mcp-redteam"})
        result = decode_jwt_unsafe(token)
        assert "header" in result
        assert "payload" in result
        assert result["payload"]["sub"] == "test"

    def test_decode_jwt_unsafe_invalid_format(self):
        """Should raise ValueError for malformed tokens."""
        with pytest.raises(ValueError, match="Invalid JWT format"):
            decode_jwt_unsafe("not-a-jwt")

    def test_tamper_role(self):
        """Should change the role claim and re-encode with alg=none."""
        original = forge_with_weak_secret(
            {"sub": "user", "role": "viewer"}, "secret"
        )
        tampered = tamper_role(original, "admin")
        decoded = decode_jwt_unsafe(tampered)
        assert decoded["payload"]["role"] == "admin"
        assert decoded["header"]["alg"] == "none"  # downgraded to none

    def test_tamper_role_custom_field(self):
        """Should work with custom role field names."""
        original = forge_alg_none({"sub": "user", "user_type": "basic"})
        tampered = tamper_role(original, "superuser", role_field="user_type")
        decoded = decode_jwt_unsafe(tampered)
        assert decoded["payload"]["user_type"] == "superuser"

    def test_forge_with_weak_secret(self):
        """Should produce a valid JWT with HS256 signature."""
        token = forge_with_weak_secret(
            {"sub": "admin", "role": "admin"},
            "secret",
        )
        parts = token.split(".")
        assert len(parts) == 3
        assert parts[2] != ""  # non-empty signature
        decoded = decode_jwt_unsafe(token)
        assert decoded["header"]["alg"] == "HS256"

    def test_forge_with_weak_secret_invalid_alg(self):
        """Should reject non-HS256 algorithms."""
        with pytest.raises(ValueError, match="Only HS256 supported"):
            forge_with_weak_secret({"sub": "test"}, "secret", algorithm="RS256")

    def test_common_secrets_list(self):
        """Common secrets list should have reasonable entries."""
        assert len(COMMON_JWT_SECRETS) >= 10
        assert "secret" in COMMON_JWT_SECRETS
        assert "password" in COMMON_JWT_SECRETS
        assert "" in COMMON_JWT_SECRETS  # empty string


# ═══════════════════════════════════════════
#  False Positive Diff Tests
# ═══════════════════════════════════════════


class TestNormalizeResponse:
    """Test response normalization for stable comparison."""

    def test_strips_uuids(self):
        text = "Request 550e8400-e29b-41d4-a716-446655440000 completed"
        normalized = normalize_response(text)
        assert "550e8400" not in normalized
        assert "<DYNAMIC>" in normalized

    def test_strips_timestamps(self):
        text = "Error at 2024-01-15T10:30:00Z: something failed"
        normalized = normalize_response(text)
        assert "2024-01-15" not in normalized

    def test_normalizes_whitespace(self):
        text = "  hello   world  \n\t  foo  "
        normalized = normalize_response(text)
        assert normalized == "hello world foo"


class TestComputeResponseDiff:
    """Test the response comparison engine."""

    def test_identical_responses(self):
        diff = compute_response_diff("Error: invalid input", "Error: invalid input")
        assert diff.similarity_ratio == 1.0
        assert diff.diff_score == 0.0

    def test_completely_different_responses(self):
        diff = compute_response_diff(
            "Success: query completed",
            "FATAL: SQL syntax error near 'OR 1=1' at line 1"
        )
        assert diff.similarity_ratio < 0.5
        assert diff.diff_score > 0.3

    def test_error_keywords_detected(self):
        diff = compute_response_diff(
            "Result: 3 rows",
            "SQL syntax error: unexpected token near 'DROP TABLE'"
        )
        assert len(diff.added_keywords) > 0
        assert "sql" in diff.added_keywords or "error" in diff.added_keywords or "syntax" in diff.added_keywords

    def test_length_ratio_calculated(self):
        diff = compute_response_diff("short", "a much longer response with more data")
        assert diff.length_ratio > 1.0

    def test_error_response_detected(self):
        diff = compute_response_diff(
            "OK",
            'File "/app/handler.py", line 42, in process\n  raise ValueError("bad input")'
        )
        assert diff.is_error_response is True


class TestIsSignificantDiff:
    """Test the significance threshold logic."""

    def test_identical_not_significant(self):
        diff = compute_response_diff("same", "same")
        assert is_significant_diff(diff) is False

    def test_sql_error_is_significant(self):
        diff = compute_response_diff(
            "3 rows returned",
            "SQL syntax error: column 'password' does not exist"
        )
        assert is_significant_diff(diff) is True

    def test_generic_error_with_security_keywords(self):
        diff = compute_response_diff(
            "OK",
            "permission denied: unauthorized access to internal resource"
        )
        assert is_significant_diff(diff) is True

    def test_minor_wording_change_not_significant(self):
        diff = compute_response_diff(
            "Processing complete: 3 items",
            "Processing complete: 4 items"
        )
        assert is_significant_diff(diff) is False


class TestExtractTextFromMCPResponse:
    """Test MCP response text extraction."""

    def test_extracts_text_content(self):
        response = {
            "content": [
                {"type": "text", "text": "Hello world"},
                {"type": "text", "text": "Second line"},
            ]
        }
        text = extract_text_from_mcp_response(response)
        assert "Hello world" in text
        assert "Second line" in text

    def test_handles_empty_content(self):
        response = {"content": []}
        text = extract_text_from_mcp_response(response)
        assert text == ""

    def test_handles_missing_content(self):
        response = {}
        text = extract_text_from_mcp_response(response)
        assert text == ""

    def test_handles_non_text_content(self):
        response = {
            "content": [
                {"type": "image", "data": "base64..."},
                {"type": "text", "text": "Caption"},
            ]
        }
        text = extract_text_from_mcp_response(response)
        assert "Caption" in text
