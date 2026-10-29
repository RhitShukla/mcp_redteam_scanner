"""SSE stream parsing primitives.

Server-Sent Events from chat/LLM endpoints typically emit cumulative `parts[0]`
deltas (each delta is a snapshot of the full text so far, not a diff). The
final delta in a `status=COMPLETED` message carries the complete text. If the
stream is truncated mid-message the closing `"` is missing, so we keep a regex
fallback that doesn't require valid JSON.

See ~/.claude/skills/prompt-exfil/SKILL.md for how these are used in workflow.
"""
from __future__ import annotations

import json
import re
from typing import Optional

_PARTS_REGEX = re.compile(r'"parts":\s*\["((?:[^"\\]|\\.)+)"\]', re.S)


def _parts0(message_dict: dict) -> Optional[str]:
    parts = (message_dict or {}).get("content", {}).get("parts")
    if isinstance(parts, list) and parts:
        return parts[0] if isinstance(parts[0], str) else None
    return None


def longest_parts(sse_text: str) -> str:
    """Return the longest `parts[0]` snapshot found in any data: line.

    SSE deltas are cumulative on most chat backends, so the longest snapshot is
    the most-complete one. Falls back to empty string if nothing parsed.
    """
    longest = ""
    for line in sse_text.split("\n"):
        if not line.startswith("data:"):
            continue
        try:
            j = json.loads(line[5:].strip())
        except (json.JSONDecodeError, ValueError):
            continue
        parts = _parts0(j.get("message") or {})
        if parts and len(parts) > len(longest):
            longest = parts
    return longest


def extract_completed(sse_text: str) -> Optional[str]:
    """Return the parts[0] of the message with status=COMPLETED, if any.

    This is the authoritative final text. If the stream was truncated before
    COMPLETED, returns None — use longest_parts() as fallback.
    """
    for line in sse_text.split("\n"):
        if not line.startswith("data:"):
            continue
        try:
            j = json.loads(line[5:].strip())
        except (json.JSONDecodeError, ValueError):
            continue
        msg = j.get("message") or {}
        if msg.get("status") == "COMPLETED":
            return _parts0(msg)
    return None


def regex_fallback(sse_text: str) -> str:
    """Regex-only longest parts extraction; useful when last delta truncates mid-JSON."""
    best = ""
    for m in _PARTS_REGEX.finditer(sse_text):
        s = m.group(1)
        if len(s) > len(best):
            best = s
    return best


def best_text(sse_text: str) -> str:
    """Return the most-complete user-visible text: COMPLETED > longest parsed > regex fallback."""
    completed = extract_completed(sse_text)
    parsed = longest_parts(sse_text)
    regex = regex_fallback(sse_text)
    return max((completed or "", parsed, regex), key=len)


def concatenate_deltas(sse_text: str) -> str:
    """Concatenate all parsed deltas in order. Use only for backends that emit
    incremental (non-cumulative) chunks — most chat backends are cumulative and
    you want longest_parts() instead.
    """
    out = []
    for line in sse_text.split("\n"):
        if not line.startswith("data:"):
            continue
        try:
            j = json.loads(line[5:].strip())
        except (json.JSONDecodeError, ValueError):
            continue
        parts = _parts0(j.get("message") or {})
        if parts:
            out.append(parts)
    return "".join(out)


def decode_sse_escapes(text: str) -> str:
    """SSE-payload strings often carry literal `\\n` etc. Decode to real chars."""
    if "\\n" in text or "\\t" in text or "\\\"" in text:
        try:
            return text.encode("utf-8").decode("unicode_escape", errors="replace")
        except (UnicodeDecodeError, UnicodeEncodeError):
            return text
    return text


def has_function_call(sse_text: str) -> bool:
    """True if the SSE shows a transfer_to_agent or other function_call dispatch."""
    if "transfer_to_agent" in sse_text:
        return True
    if '"function_call"' in sse_text:
        return True
    if '"resourceName":"transfer' in sse_text:
        return True
    return False
