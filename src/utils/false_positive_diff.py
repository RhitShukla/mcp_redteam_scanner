"""
False Positive Diff Engine — Response comparison to prevent fake alerts.

Compares a 'baseline' response (from a benign input) against an
'attacked' response (from a malicious payload) to determine if the
server actually behaved differently.

Why this matters:
    Many servers return the same generic error for ALL invalid inputs.
    Without diffing, every payload would look like a "successful" attack.
    This engine mathematically compares responses and only flags
    payloads that provoked a genuinely different server reaction.

Usage:
    from src.utils.false_positive_diff import compute_response_diff, is_significant_diff

    baseline = "Error: invalid input"
    attacked = "Error: SQL syntax error near 'OR 1=1'"
    diff = compute_response_diff(baseline, attacked)
    if is_significant_diff(diff):
        # Real finding — server reacted differently to the attack
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from difflib import SequenceMatcher
from typing import Any


# ── Dynamic content patterns to strip before comparison ──
# These change between requests and would cause false diffs.

_DYNAMIC_PATTERNS: list[re.Pattern[str]] = [
    # UUIDs
    re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.IGNORECASE),
    # ISO timestamps
    re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?"),
    # Unix timestamps (10-13 digit)
    re.compile(r"\b\d{10,13}\b"),
    # Session/request IDs (hex strings 16+ chars)
    re.compile(r"\b[0-9a-f]{16,}\b", re.IGNORECASE),
    # Memory addresses
    re.compile(r"0x[0-9a-f]{6,16}", re.IGNORECASE),
]


@dataclass
class DiffResult:
    """Result of comparing a baseline response against an attacked response."""

    similarity_ratio: float  # 0.0 = completely different, 1.0 = identical
    baseline_length: int
    attacked_length: int
    length_ratio: float  # attacked_length / baseline_length (or 0 if baseline is empty)
    added_keywords: list[str] = field(default_factory=list)  # Error-like words only in attacked
    removed_keywords: list[str] = field(default_factory=list)  # Words only in baseline
    is_error_response: bool = False  # True if attacked response looks like an error
    raw_baseline: str = ""
    raw_attacked: str = ""

    @property
    def diff_score(self) -> float:
        """
        Composite score: 0.0 = identical, 1.0 = maximally different.
        Combines text similarity, length change, and keyword signals.
        """
        text_diff = 1.0 - self.similarity_ratio
        length_diff = abs(1.0 - self.length_ratio) if self.length_ratio > 0 else 1.0
        length_diff = min(length_diff, 1.0)  # cap at 1.0

        keyword_bonus = min(len(self.added_keywords) * 0.1, 0.3)

        # Weighted combination
        return min(text_diff * 0.6 + length_diff * 0.2 + keyword_bonus * 0.2, 1.0)


# ── Keywords that signal real vulnerability impact ──

_ERROR_KEYWORDS: set[str] = {
    "syntax", "error", "exception", "traceback", "stack",
    "sql", "query", "column", "table", "database",
    "permission", "denied", "unauthorized", "forbidden",
    "file", "directory", "path", "not found",
    "command", "exec", "shell", "bash", "sh",
    "root", "admin", "password", "secret", "key",
    "internal", "server", "fatal", "panic", "segfault",
    "overflow", "injection", "invalid",
}

_ERROR_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(?:sql|syntax)\s*error", re.IGNORECASE),
    re.compile(r"stack\s*trace", re.IGNORECASE),
    re.compile(r"at\s+\S+\.\S+\(", re.IGNORECASE),  # Java/Python stack frames
    re.compile(r"File\s+\"[^\"]+\",\s+line\s+\d+", re.IGNORECASE),  # Python traceback
    re.compile(r"permission\s+denied", re.IGNORECASE),
    re.compile(r"command\s+not\s+found", re.IGNORECASE),
    re.compile(r"no\s+such\s+file", re.IGNORECASE),
]


def normalize_response(text: str) -> str:
    """
    Strip dynamic content (timestamps, UUIDs, etc.) for stable comparison.

    Args:
        text: Raw response text.

    Returns:
        Cleaned text with dynamic values replaced by placeholders.
    """
    result = text
    for pattern in _DYNAMIC_PATTERNS:
        result = pattern.sub("<DYNAMIC>", result)

    # Normalize whitespace
    result = " ".join(result.split())
    return result.strip()


def _extract_keywords(text: str) -> set[str]:
    """Extract lowercase words from text."""
    return set(re.findall(r"[a-z]+", text.lower()))


def _check_error_signals(text: str) -> bool:
    """Check if text contains error-like patterns."""
    for pattern in _ERROR_PATTERNS:
        if pattern.search(text):
            return True
    return False


def compute_response_diff(baseline: str, attacked: str) -> DiffResult:
    """
    Compare a baseline (benign) response against an attacked response.

    Args:
        baseline: Response from a benign/normal request.
        attacked: Response from the same request with an attack payload.

    Returns:
        DiffResult with similarity metrics and keyword analysis.
    """
    norm_baseline = normalize_response(baseline)
    norm_attacked = normalize_response(attacked)

    # Text similarity
    matcher = SequenceMatcher(None, norm_baseline, norm_attacked)
    similarity = matcher.ratio()

    # Length analysis
    bl = len(norm_baseline)
    al = len(norm_attacked)
    length_ratio = al / bl if bl > 0 else (0.0 if al == 0 else float("inf"))

    # Keyword diff
    baseline_words = _extract_keywords(norm_baseline)
    attacked_words = _extract_keywords(norm_attacked)

    added = attacked_words - baseline_words
    removed = baseline_words - attacked_words

    # Filter to only security-relevant keywords
    added_security = sorted(added & _ERROR_KEYWORDS)
    removed_security = sorted(removed & _ERROR_KEYWORDS)

    # Error detection
    is_error = _check_error_signals(attacked) and not _check_error_signals(baseline)

    return DiffResult(
        similarity_ratio=similarity,
        baseline_length=bl,
        attacked_length=al,
        length_ratio=length_ratio,
        added_keywords=added_security,
        removed_keywords=removed_security,
        is_error_response=is_error,
        raw_baseline=baseline,
        raw_attacked=attacked,
    )


def is_significant_diff(diff: DiffResult, threshold: float = 0.3) -> bool:
    """
    Determine if the diff is significant enough to report as a real finding.

    Args:
        diff: The DiffResult from compute_response_diff.
        threshold: Minimum diff_score to consider significant (default: 0.3).

    Returns:
        True if the response difference is large enough to flag.
    """
    # Identical responses are never significant
    if diff.similarity_ratio >= 0.98:
        return False

    # Error signals are always significant even with high similarity
    if diff.is_error_response:
        return True

    # Security keywords appearing in attacked output are always significant
    if len(diff.added_keywords) >= 2:
        return True

    # General threshold check
    return diff.diff_score >= threshold


def extract_text_from_mcp_response(response: dict[str, Any]) -> str:
    """
    Pull all text content from an MCP tool response dict.

    Shared utility — used by attack modules and the diff engine.

    Args:
        response: MCP CallToolResult dict.

    Returns:
        Concatenated text content.
    """
    parts: list[str] = []
    for item in response.get("content", []):
        if isinstance(item, dict) and item.get("type") == "text":
            parts.append(item.get("text", ""))
        elif isinstance(item, dict):
            parts.append(str(item))
    return "\n".join(parts)
