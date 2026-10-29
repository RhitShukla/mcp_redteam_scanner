"""Manifest-driven JWT decoding + validation.

Thin convenience layer on top of ``src.utils.jwt_helpers.decode_jwt_unsafe``
that knows how to check format and expiry against a Manifest. No new JWT
decoding logic lives here.

See CLAUDE.md "Token management" for the project-wide policy.
"""
from __future__ import annotations

import pathlib
import time
from typing import Any, Optional, Iterable

from src.utils.jwt_helpers import decode_jwt_unsafe


def decode(token: str) -> dict[str, Any]:
    """Decode a JWT to its payload dict. Header is discarded — use
    ``src.utils.jwt_helpers.decode_jwt_unsafe`` directly if you need it.
    """
    return decode_jwt_unsafe(token)["payload"]


def load(token_path: str | pathlib.Path) -> str:
    """Read a token file, strip trailing whitespace."""
    return pathlib.Path(token_path).read_text().strip()


def is_expired(token: str, expiry_key: str = "exp", now: Optional[float] = None) -> bool:
    """True if the JWT payload's `<expiry_key>` is in the past."""
    payload = decode(token)
    exp = payload.get(expiry_key)
    if exp is None:
        return False
    now_ts = now if now is not None else time.time()
    return float(exp) < now_ts


def time_to_expiry(token: str, expiry_key: str = "exp") -> Optional[float]:
    """Seconds until the token expires (negative if already expired). None if
    no expiry claim is present."""
    payload = decode(token)
    exp = payload.get(expiry_key)
    if exp is None:
        return None
    return float(exp) - time.time()


def assert_format(
    token: str,
    expected_keys: Iterable[str],
    *,
    token_label: str = "token",
) -> None:
    """Raise if the token payload doesn't contain every key in `expected_keys`.

    Catches the classic OrbitShift gotcha: a token with camelCase claims
    (`userId`, `tenantId`) sent to an endpoint that expects snake_case
    (`user_id`, `tenant_id`) silently 401s with "unauthorized tenant" — but
    the auth header is structurally valid, so naive probes interpret it as a
    cross-tenant rejection. Run this assertion at token-load time to fail
    fast with a clear message.
    """
    payload = decode(token)
    missing = [k for k in expected_keys if k not in payload]
    if missing:
        present = sorted(payload.keys())
        raise ValueError(
            f"{token_label}: missing expected JWT claim(s) {missing}. "
            f"Present claims: {present}. (Often this means the token has "
            f"camelCase claims when the API expects snake_case, or vice versa.)"
        )
