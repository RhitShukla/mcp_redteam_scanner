"""
Remediation Verification Script — Generic MCP Server (Authenticated)

Verifies every finding from the Red Team report against the client's
remediation response. Each verification runs the exact payload the red team
used and checks the NEW expected outcome described by the client.

Usage:
    # Run all verifications
    python verify_remediations.py --token <JWT> --all

    # Run a single finding
    python verify_remediations.py --token <JWT> --finding SEC-001

    # Run a category
    python verify_remediations.py --token <JWT> --category SEC
    python verify_remediations.py --token <JWT> --category DCR
    python verify_remediations.py --token <JWT> --category EXTRA

    # List all available verifications
    python verify_remediations.py --list

Target MCP Server: https://super-singularity-mcp-redteam-1006143863862.asia-south1.run.app/sse
Auth Server:       https://app.skill10x.com
"""

from __future__ import annotations

import argparse
import asyncio
import json
import re
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import httpx

from src.models import AuthMethod, TargetConfig, TransportType
from src.probe_engine import ProbeEngine

# ── Constants ──────────────────────────────────────────────────────────────────

MCP_ENDPOINT = "https://super-singularity-mcp-redteam-1006143863862.asia-south1.run.app/sse"
AUTH_SERVER   = "https://app.skill10x.com"

# Known course/card IDs from original red team run (used as valid anchors)
KNOWN_COURSE_ID = "8caed3ac-b668-4e30-9e83-fce50dfcafac"
KNOWN_CARD_ID   = "test-card-placeholder"   # replace with a real card ID

# ── Result Models ──────────────────────────────────────────────────────────────

PASS  = "PASS"
FAIL  = "FAIL"
SKIP  = "SKIP"
ERROR = "ERROR"

@dataclass
class VerificationResult:
    finding_id:   str
    status:       str          # PASS | FAIL | SKIP | ERROR
    finding_title: str
    expected:     str
    actual:       str
    evidence:     dict[str, Any] = field(default_factory=dict)
    notes:        str = ""

    def __str__(self) -> str:
        icon = {"PASS": "✅", "FAIL": "❌", "SKIP": "⏭ ", "ERROR": "💥"}.get(self.status, "?")
        lines = [
            f"\n{'─'*70}",
            f"  {icon}  [{self.status}] {self.finding_id} — {self.finding_title}",
            f"{'─'*70}",
            f"  Expected : {self.expected}",
            f"  Actual   : {self.actual}",
        ]
        if self.notes:
            lines.append(f"  Notes    : {self.notes}")
        if self.evidence:
            lines.append(f"  Evidence :")
            for k, v in self.evidence.items():
                v_str = json.dumps(v)[:200] if not isinstance(v, str) else v[:200]
                lines.append(f"    {k}: {v_str}")
        return "\n".join(lines)


# ── Base Verifier ──────────────────────────────────────────────────────────────

class BaseVerifier:
    """Shared helpers for both MCP-tool and HTTP verifications."""

    def __init__(self, token: str, engine: ProbeEngine | None = None) -> None:
        self.token  = token
        self.engine = engine

    # ── MCP helpers ────────────────────────────────────────────────────────────

    async def call_tool(self, name: str, args: dict) -> tuple[str | None, str | None]:
        """Call an MCP tool. Returns (result_text, error_text)."""
        try:
            result = await self.engine.call_tool(name, args)
            if hasattr(result, "content"):
                texts = [c.text if hasattr(c, "text") else str(c)
                         for c in result.content]
                return "\n".join(texts), None
            return str(result), None
        except Exception as exc:
            return None, str(exc)

    # ── HTTP helpers ────────────────────────────────────────────────────────────

    def _http_headers(self, extra: dict | None = None) -> dict:
        h = {"Authorization": f"Bearer {self.token}",
             "Content-Type": "application/json"}
        if extra:
            h.update(extra)
        return h

    def http_post(self, url: str, body: dict, headers: dict | None = None,
                  timeout: int = 15) -> httpx.Response:
        with httpx.Client(timeout=timeout) as client:
            return client.post(url, json=body,
                               headers=headers or self._http_headers())

    def http_get(self, url: str, headers: dict | None = None,
                 timeout: int = 15) -> httpx.Response:
        with httpx.Client(timeout=timeout, follow_redirects=False) as client:
            return client.get(url, headers=headers or self._http_headers())

    # ── Shared pass/fail helpers ────────────────────────────────────────────────

    def _assert_no_pattern(self, text: str, patterns: list[str],
                           finding_id: str, title: str, expected: str) -> VerificationResult:
        """PASS if NONE of the patterns appear in text."""
        found = [p for p in patterns if p.lower() in text.lower()]
        if found:
            return VerificationResult(
                finding_id=finding_id, status=FAIL, finding_title=title,
                expected=expected,
                actual=f"Sensitive pattern(s) still present: {found}",
                evidence={"response_snippet": text[:500]}
            )
        return VerificationResult(
            finding_id=finding_id, status=PASS, finding_title=title,
            expected=expected,
            actual="None of the sensitive patterns found in response",
        )

    def _assert_pattern_present(self, text: str, patterns: list[str],
                                finding_id: str, title: str, expected: str) -> VerificationResult:
        """PASS if AT LEAST ONE of the patterns appears in text."""
        found = [p for p in patterns if p.lower() in text.lower()]
        if not found:
            return VerificationResult(
                finding_id=finding_id, status=FAIL, finding_title=title,
                expected=expected,
                actual=f"Expected pattern(s) not found: {patterns}",
                evidence={"response_snippet": text[:500]}
            )
        return VerificationResult(
            finding_id=finding_id, status=PASS, finding_title=title,
            expected=expected,
            actual=f"Expected pattern found: {found}",
        )


# ── SEC Verifiers (MCP Tool Tests) ─────────────────────────────────────────────

class SECVerifier(BaseVerifier):

    async def verify_SEC_001(self) -> list[VerificationResult]:
        """
        Prisma ORM Query Structure Leaked in Error Responses — Remediated
        Client fix: resource_type enum validation + generic error responses
        """
        results = []
        TITLE = "Prisma ORM Query Structure Leaked in Error Responses"

        # ── Test 1a: Path traversal in resource_type ──────────────────────────
        result, error = await self.call_tool("create_resource_entry_tool", {
            "url": "https://example.com/test.png",
            "course_id": KNOWN_COURSE_ID,
            "card_id": "test",
            "resource_type": "../../../../etc/passwd",
            "source": "test",
            "meta": {}
        })
        text = (result or error or "").lower()

        # FAIL indicators: any Prisma internals in response
        prisma_markers = ["prisma.", "prisma.resource", "data: {", "companyid:", "invocation:"]
        # PASS indicator: enum rejection message
        pass_markers   = ["invalid resource_type", "must be one of", "audio", "image", "video"]

        found_prisma = [m for m in prisma_markers if m in text]
        found_pass   = [m for m in pass_markers   if m in text]

        if found_prisma:
            results.append(VerificationResult(
                finding_id="SEC-001a", status=FAIL, finding_title=TITLE,
                expected="No Prisma internals (companyId, schema, ORM traces) in error response",
                actual=f"Prisma internals still exposed: {found_prisma}",
                evidence={"response": (result or error or "")[:600]}
            ))
        else:
            # No Prisma leak = remediation succeeded.
            # Explicit enum rejection text is desirable but not required for security.
            note = "Explicit enum rejection message present" if found_pass else \
                   "Generic error returned (no Prisma internals — acceptable)"
            results.append(VerificationResult(
                finding_id="SEC-001a", status=PASS, finding_title=TITLE,
                expected="No Prisma internals (companyId, schema, ORM traces) in error response",
                actual=note,
                evidence={"response": (result or error or "")[:300]}
            ))

        # ── Test 1b: Non-existent card_id (FK constraint leak check) ─────────
        result2, error2 = await self.call_tool("create_resource_entry_tool", {
            "url": "https://example.com/test.png",
            "course_id": KNOWN_COURSE_ID,
            "card_id": "00000000-0000-0000-0000-000000000000",
            "resource_type": "image",
            "source": "test",
            "meta": {}
        })
        text2 = (result2 or error2 or "").lower()
        fk_markers = ["resources_card_id_fkey", "foreign key constraint", "constraint violated"]
        found_fk = [m for m in fk_markers if m in text2]
        results.append(VerificationResult(
            finding_id="SEC-001b", status=FAIL if found_fk else PASS,
            finding_title=TITLE + " (FK constraint name leak)",
            expected="Returns 'Resource not found' — no FK constraint name",
            actual=f"FK constraint names still leaked: {found_fk}" if found_fk
                   else "No FK constraint names in response",
            evidence={"response": (result2 or error2 or "")[:300]}
        ))

        # ── Test 1c: 10K-char URL (column size leak check) ───────────────────
        result3, error3 = await self.call_tool("create_resource_entry_tool", {
            "url": "https://example.com/" + "A" * 10000,
            "course_id": KNOWN_COURSE_ID,
            "card_id": "test",
            "resource_type": "image",
            "source": "test",
            "meta": {}
        })
        text3 = (result3 or error3 or "").lower()
        col_markers = ["value too long", "column", "character varying", "varchar"]
        found_col = [m for m in col_markers if m in text3]
        results.append(VerificationResult(
            finding_id="SEC-001c", status=FAIL if found_col else PASS,
            finding_title=TITLE + " (column size constraint leak)",
            expected="Returns 'Server error' — no column size limit leaked",
            actual=f"Column constraint info still leaked: {found_col}" if found_col
                   else "No column constraint info in response",
            evidence={"response": (result3 or error3 or "")[:300]}
        ))

        return results

    async def verify_SEC_002(self) -> list[VerificationResult]:
        """
        Company Tenant ID Leaked via Error Channel — Remediated
        Client fix: error sanitization (SEC-001) + logo URL path changed
        """
        TITLE = "Company Tenant ID Leaked via Error Channel"
        TENANT_ID = "b3612853fd7749a89bbd0b06705d1e57"
        results = []

        # ── Test 2a: Trigger error and check for companyId ───────────────────
        result, error = await self.call_tool("create_resource_entry_tool", {
            "url": "https://example.com/test.png",
            "course_id": KNOWN_COURSE_ID,
            "card_id": "test",
            "resource_type": "../../../../etc/passwd",
            "source": "test",
            "meta": {}
        })
        text = (result or error or "")
        results.append(VerificationResult(
            finding_id="SEC-002a", status=FAIL if TENANT_ID in text else PASS,
            finding_title=TITLE + " (via error channel)",
            expected=f"companyId '{TENANT_ID}' NOT present in error response",
            actual=f"companyId STILL present in error response" if TENANT_ID in text
                   else "companyId not found in error response",
            evidence={"response": text[:400]}
        ))

        # ── Test 2b: Normal course response — check for companyId in blob URL ─
        result2, error2 = await self.call_tool("db_list_recent_courses", {
            "limit": 5,
            "offset": 0
        })
        text2 = (result2 or error2 or "")
        results.append(VerificationResult(
            finding_id="SEC-002b", status=FAIL if TENANT_ID in text2 else PASS,
            finding_title=TITLE + " (in blob URL paths)",
            expected=f"companyId NOT present in blob URL paths in normal responses",
            actual=f"companyId STILL in blob URL paths" if TENANT_ID in text2
                   else "companyId not found in normal tool responses",
            evidence={"response_snippet": text2[:500]}
        ))

        return results

    async def verify_SEC_003(self) -> list[VerificationResult]:
        """
        Azure Blob SAS Tokens in MCP Responses — Remediated
        Client fix: SAS params stripped from all blob URLs in MCP responses
        """
        TITLE = "Azure Blob SAS Tokens in MCP Responses"
        SAS_PARAMS = ["?sv=", "&sig=", "&se=", "&sp=", "&sr="]
        results = []

        # Call multiple tools that return course/card data
        for tool_name, args in [
            ("db_list_recent_courses",  {"limit": 3, "offset": 0}),
            ("get_course",              {"course_id": KNOWN_COURSE_ID}),
            ("db_get_course_details",   {"course_id": KNOWN_COURSE_ID, "include_cards": True}),
        ]:
            result, error = await self.call_tool(tool_name, args)
            text = (result or error or "")
            found_sas = [p for p in SAS_PARAMS if p in text]
            results.append(VerificationResult(
                finding_id="SEC-003",
                status=FAIL if found_sas else PASS,
                finding_title=f"{TITLE} [{tool_name}]",
                expected="Blob URLs have NO SAS query params (?sv=, &sig=, &se=, &sp=, &sr=)",
                actual=f"SAS params still present: {found_sas}" if found_sas
                       else "No SAS query params in blob URLs",
                evidence={"response_snippet": text[:500]}
            ))

        return results

    async def verify_SEC_004(self) -> list[VerificationResult]:
        """
        Azure Blob Assets Publicly Downloadable with SAS URLs — Remediated
        Client fix: downstream of SEC-003 — URLs without SAS return 404
        Verify: extract a blob URL from response and attempt direct download
        """
        TITLE = "Azure Blob Assets Publicly Downloadable with SAS URLs"

        result, error = await self.call_tool("db_get_course_details", {
            "course_id": KNOWN_COURSE_ID,
            "include_cards": True
        })
        text = (result or error or "")

        # Extract any Azure blob URL from the response
        blob_urls = re.findall(
            r'https://[a-z0-9]+\.blob\.core\.windows\.net/[^\s"\'<>]+',
            text
        )

        if not blob_urls:
            return [VerificationResult(
                finding_id="SEC-004", status=SKIP, finding_title=TITLE,
                expected="Blob URL not accessible without SAS token (HTTP 404)",
                actual="No blob URLs found in response to test against",
                notes="SEC-003 may have stripped all URLs — run SEC-003 first to confirm"
            )]

        url = blob_urls[0].split("?")[0]  # ensure no SAS token
        try:
            with httpx.Client(timeout=10, follow_redirects=True) as client:
                resp = client.get(url)
            status_ok = resp.status_code in (200, 206)
            return [VerificationResult(
                finding_id="SEC-004", status=FAIL if status_ok else PASS,
                finding_title=TITLE,
                expected="HTTP 404 (blob URL without SAS token is not accessible)",
                actual=f"HTTP {resp.status_code} — {'still downloadable!' if status_ok else 'access denied as expected'}",
                evidence={"url_tested": url, "http_status": resp.status_code}
            )]
        except Exception as exc:
            return [VerificationResult(
                finding_id="SEC-004", status=ERROR, finding_title=TITLE,
                expected="HTTP 404",
                actual=f"Request error: {exc}",
                evidence={"url_tested": url}
            )]

    async def verify_SEC_005(self) -> list[VerificationResult]:
        """
        Prisma Database Schema Fully Mapped via Error Injection — Remediated
        Client fix: same as SEC-001 (error sanitization closes all leak paths)
        """
        TITLE = "Prisma Database Schema Fully Mapped via Error Injection"
        SCHEMA_MARKERS = [
            "prisma.", "data: {", "companyid:", "courseid:", "cardid:",
            "resources_card_id_fkey", "findmany()", "skip argument",
            "findfirst()", "invocation:", "prisma.resource"
        ]
        results = []

        # Triggers from the original report
        probes = [
            ("create_resource_entry_tool", {"url": "https://x.com/x.png",
             "course_id": KNOWN_COURSE_ID, "card_id": "bad",
             "resource_type": "../../../etc/passwd", "source": "t", "meta": {}}),
            ("db_list_recent_courses", {"limit": 5, "offset": -1}),
            ("db_list_recent_courses", {"limit": 5, "offset": -999999}),
        ]

        for tool_name, args in probes:
            result, error = await self.call_tool(tool_name, args)
            text = (result or error or "").lower()
            leaked = [m for m in SCHEMA_MARKERS if m in text]
            results.append(VerificationResult(
                finding_id="SEC-005",
                status=FAIL if leaked else PASS,
                finding_title=f"{TITLE} [{tool_name} / {list(args.values())[-1]}]",
                expected="Generic error — no schema elements (table names, field names, FK constraints)",
                actual=f"Schema still leaked: {leaked}" if leaked
                       else "No schema elements in response",
                evidence={"response": (result or error or "")[:400]}
            ))

        return results

    async def verify_SEC_006(self) -> list[VerificationResult]:
        """
        Echo Tool Reflects XSS Payloads Without Sanitization — Remediated
        Client fix: echo tool now HTML-encodes all input
        """
        TITLE = "Echo Tool Reflects XSS Payloads Without Sanitization"
        payloads = [
            ("<script>alert(document.cookie)</script>",
             ["&lt;script&gt;", "&lt;/script&gt;"],
             ["<script>", "</script>"]),
            ("<img src=x onerror=alert(1)>",
             ["&lt;img", "onerror"],
             ["<img ", "onerror=alert"]),
        ]
        results = []

        for raw_payload, encoded_markers, raw_markers in payloads:
            result, error = await self.call_tool("echo_message", {"message": raw_payload})
            text = (result or error or "")

            raw_found = [m for m in raw_markers if m in text]
            encoded_found = [m for m in encoded_markers if m in text]

            if raw_found:
                status, actual = FAIL, f"Raw XSS payload reflected unencoded: {raw_found}"
            elif encoded_found:
                status, actual = PASS, f"Payload HTML-encoded as expected"
            else:
                # payload might be stripped entirely — also acceptable
                status, actual = PASS, f"Payload not present in output (stripped or encoded)"

            results.append(VerificationResult(
                finding_id="SEC-006", status=status, finding_title=TITLE,
                expected=f"HTML-encoded output — no raw '<script>' or onerror reflected",
                actual=actual,
                evidence={"payload": raw_payload, "response": text[:300]}
            ))

        return results

    async def verify_SEC_007(self) -> list[VerificationResult]:
        """
        Negative Offset Triggers Unhandled Prisma AssertionError — Remediated
        Client fix: offset clamped to ≥0, limit clamped to 1–100 at both layers
        """
        TITLE = "Negative Offset Triggers Unhandled Prisma AssertionError"
        ASSERTION_MARKERS = ["assertionerror", "prisma.course.findmany", "skip argument",
                             "value can only be positive"]
        results = []

        for offset_val in [-1, -999999]:
            result, error = await self.call_tool("db_list_recent_courses",
                                                  {"limit": 5, "offset": offset_val})
            text = (result or error or "").lower()
            leaked = [m for m in ASSERTION_MARKERS if m in text]
            results.append(VerificationResult(
                finding_id="SEC-007",
                status=FAIL if leaked else PASS,
                finding_title=f"{TITLE} [offset={offset_val}]",
                expected=f"Normal result set (offset clamped to 0) — no AssertionError",
                actual=f"AssertionError/Prisma internals still exposed: {leaked}" if leaked
                       else "Normal response returned, no Prisma error",
                evidence={"response": (result or error or "")[:400]}
            ))

        return results

    async def verify_SEC_008(self) -> list[VerificationResult]:
        """
        ElevenLabs Usage Quota Leaked in Error Response — Remediated
        Client fix: quota response now shows remaining only — no Limit / Used fields
        """
        TITLE = "ElevenLabs Usage Quota Leaked in Error Response"

        # Trigger quota check via audio generation (will fail gracefully or hit quota message)
        result, error = await self.call_tool("generate_audio_from_text", {
            "card_id": "00000000-0000-0000-0000-000000000000",
            "text": "A" * 5000,
            "title": "verification-test"
        })
        text = (result or error or "")

        LEAK_MARKERS = ["limit: 25", "used: 3", "- limit:", "- used:", "3.17"]
        GENERIC_MARKERS = ["remaining", "quota", "contact support"]

        leaked = [m for m in LEAK_MARKERS if m.lower() in text.lower()]
        if leaked:
            return [VerificationResult(
                finding_id="SEC-008", status=FAIL, finding_title=TITLE,
                expected="Quota message shows remaining only — no Limit/Used numbers",
                actual=f"Specific quota numbers still present: {leaked}",
                evidence={"response": text[:400]}
            )]
        elif any(m.lower() in text.lower() for m in GENERIC_MARKERS):
            return [VerificationResult(
                finding_id="SEC-008", status=PASS, finding_title=TITLE,
                expected="Quota message shows remaining only — no Limit/Used numbers",
                actual="Quota message is generic (no exact Limit/Used exposed)",
                evidence={"response": text[:300]}
            )]
        else:
            return [VerificationResult(
                finding_id="SEC-008", status=SKIP, finding_title=TITLE,
                expected="Quota message shows remaining only",
                actual="Could not trigger quota message (card_id invalid before quota check)",
                notes="May need a valid card_id to reach the quota check code path"
            )]

    async def verify_SEC_009(self) -> list[VerificationResult]:
        """
        Full Infrastructure Stack Disclosed via Error Responses — Remediated
        Client fix: error sanitization removes ORM/provider strings from all errors
        """
        TITLE = "Full Infrastructure Stack Disclosed via Error Responses"
        INFRA_MARKERS = [
            "prisma", "postgresql", "microsoft-azure-application-gateway",
            "supersingularitystorage", "elevenlabs", "azure openai",
            "pydantic", "validation error for call"
        ]

        # Trigger errors from multiple tools
        all_text = ""
        for tool_name, args in [
            ("create_resource_entry_tool", {"url": "x", "course_id": "bad",
             "card_id": "bad", "resource_type": "../etc", "source": "x", "meta": {}}),
            ("db_list_recent_courses", {"limit": 5, "offset": -1}),
            ("echo_message", {"message": "<script>test</script>"}),
        ]:
            result, error = await self.call_tool(tool_name, args)
            all_text += (result or error or "") + "\n"

        leaked = [m for m in INFRA_MARKERS if m.lower() in all_text.lower()]
        return [VerificationResult(
            finding_id="SEC-009", status=FAIL if leaked else PASS,
            finding_title=TITLE,
            expected="Generic error messages — no ORM, DB, WAF, or provider names leaked",
            actual=f"Infrastructure identifiers still present: {leaked}" if leaked
                   else "No infrastructure identifiers found across error responses",
            evidence={"combined_responses": all_text[:600]}
        )]

    async def verify_SEC_010(self) -> list[VerificationResult]:
        """
        Course Instructions Leak Internal Architecture (27K chars) — Remediated
        Client fix: provider names replaced with generic terms
        """
        TITLE = "Course Instructions Leak Internal Architecture"
        PROVIDER_MARKERS = ["azure openai", "elevenlabs", "openai", "azure blob"]

        result, error = await self.call_tool("get_course_creation_instructions", {})
        text = (result or error or "")

        leaked = [m for m in PROVIDER_MARKERS if m.lower() in text.lower()]
        return [VerificationResult(
            finding_id="SEC-010", status=FAIL if leaked else PASS,
            finding_title=TITLE,
            expected="Provider names replaced with generic terms ('image generation service', etc.)",
            actual=f"Provider names still present: {leaked}" if leaked
                   else f"No provider names found in {len(text)}-char instruction document",
            evidence={"doc_length": len(text), "leaked": leaked}
        )]

    async def verify_SEC_011(self) -> list[VerificationResult]:
        """
        Negative Limit Bypass Exposes Hidden/Inactive Courses — Remediated
        Client fix: limit clamped to 1–100, prevents code-path bypass
        """
        TITLE = "Negative Limit Bypass Exposes Hidden/Inactive Courses"

        # Collect normal visible courses
        result_normal, _ = await self.call_tool("db_list_recent_courses",
                                                 {"limit": 10, "offset": 0})
        # Probe with negative limit
        result_neg, _ = await self.call_tool("db_list_recent_courses",
                                              {"limit": -1, "offset": 0})

        text_neg = (result_neg or "").lower()
        assertion_markers = ["assertionerror", "prisma", "skip argument", "value can only be positive"]
        assertion_found = [m for m in assertion_markers if m in text_neg]

        # Check: negative limit should return ≥1 result (clamped to 1) and no error
        # The hidden course d0c33c79 should NOT appear if clamping is working
        HIDDEN_COURSE = "d0c33c79"
        hidden_exposed = HIDDEN_COURSE in (result_neg or "")

        if assertion_found:
            return [VerificationResult(
                finding_id="SEC-011", status=FAIL, finding_title=TITLE,
                expected="limit clamped to 1 — returns 1 result, does NOT expose hidden courses",
                actual=f"AssertionError still triggered: {assertion_found}",
                evidence={"response": result_neg[:400] if result_neg else ""}
            )]
        elif hidden_exposed:
            return [VerificationResult(
                finding_id="SEC-011", status=FAIL, finding_title=TITLE,
                expected="Hidden course d0c33c79 NOT accessible via negative limit",
                actual=f"Hidden course d0c33c79 STILL exposed via limit=-1",
                evidence={"neg_response": result_neg[:400] if result_neg else ""}
            )]
        else:
            return [VerificationResult(
                finding_id="SEC-011", status=PASS, finding_title=TITLE,
                expected="limit clamped to 1 — returns 1 result, does NOT expose hidden courses",
                actual="Negative limit handled correctly — no bypass or hidden course exposure",
                evidence={"neg_response": result_neg[:300] if result_neg else ""}
            )]

    async def verify_SEC_012(self) -> list[VerificationResult]:
        """
        create_link_card Accepts URLs with Embedded Credentials — Remediated
        Client fix: URL parser now rejects userinfo components
        """
        TITLE = "create_link_card Accepts URLs with Embedded Credentials"
        results = []

        # ── Test A: credential URL should be REJECTED ─────────────────────────
        result, error = await self.call_tool("create_link_card", {
            "course_id": KNOWN_COURSE_ID,
            "title": "verification-test",
            "link_url": "https://user:password@internal.server.com/",
            "link_caption": "test"
        })
        text = (result or error or "")
        was_accepted = '"success": true' in text.lower() or '"cardid"' in text.lower() or "cardid" in text.lower()
        results.append(VerificationResult(
            finding_id="SEC-012a", status=FAIL if was_accepted else PASS,
            finding_title=f"{TITLE} — credential URL rejected",
            expected="Rejected with error about embedded credentials",
            actual="URL with credentials still ACCEPTED and stored" if was_accepted
                   else "URL with credentials correctly rejected",
            evidence={"response": text[:300]}
        ))

        # ── Test B: normal URL should still WORK ──────────────────────────────
        result2, error2 = await self.call_tool("create_link_card", {
            "course_id": KNOWN_COURSE_ID,
            "title": "verification-test-normal",
            "link_url": "https://example.com/page",
            "link_caption": "test"
        })
        text2 = (result2 or error2 or "")
        normal_accepted = '"success"' in text2.lower() or "cardid" in text2.lower()
        results.append(VerificationResult(
            finding_id="SEC-012b", status=PASS if normal_accepted else FAIL,
            finding_title=f"{TITLE} — normal URL still works",
            expected="Normal https:// URL accepted successfully",
            actual="Normal URL accepted" if normal_accepted else "Normal URL unexpectedly rejected",
            evidence={"response": text2[:300]}
        ))

        return results

    async def verify_SEC_014(self) -> list[VerificationResult]:
        """
        SSRF Attack Surface — Already Blocked (confirmed by original red team)
        Verify: all SSRF targets still blocked
        """
        TITLE = "5 Tools Accept URL Parameters — SSRF Attack Surface"
        results = []

        ssrf_payloads = [
            ("create_resource_entry_tool", "url",
             "http://metadata.google.internal/computeMetadata/v1/"),
            ("create_resource_entry_tool", "url",
             "http://169.254.169.254/latest/meta-data/"),
            ("create_resource_entry_tool", "url",
             "file:///etc/passwd"),
        ]

        for tool_name, param, ssrf_url in ssrf_payloads:
            args = {"url": ssrf_url, "course_id": KNOWN_COURSE_ID,
                    "card_id": "test", "resource_type": "image",
                    "source": "test", "meta": {}}
            result, error = await self.call_tool(tool_name, args)
            text = (result or error or "").lower()

            # Any successful fetch of internal metadata is a FAIL
            success_markers = ["ami-id", "instance-id", "root:", "169.254", "computemetadata"]
            leaked = [m for m in success_markers if m in text]
            results.append(VerificationResult(
                finding_id="SEC-014",
                status=FAIL if leaked else PASS,
                finding_title=f"{TITLE} [{ssrf_url[:50]}]",
                expected="SSRF blocked — no internal metadata in response",
                actual=f"SSRF leaked internal data: {leaked}" if leaked
                       else "SSRF probe blocked",
                evidence={"ssrf_url": ssrf_url, "response": (result or error or "")[:300]}
            ))

        return results

    async def verify_SEC_015(self) -> list[VerificationResult]:
        """
        Weak/No Input Schema on 14 Tools — Remediated
        Client fix: Pydantic Field() constraints + generic error messages
        """
        TITLE = "Weak/No Input Schema on 14 Tools"
        results = []

        probes = [
            ("create_course", {"title": "X" * 1000, "description": "test"},
             "oversized title (1000 chars)"),
            ("db_list_recent_courses", {"limit": 999999, "offset": 0},
             "limit capped at 100"),
            ("db_search_courses", {"query": "' OR '1'='1", "limit": 10},
             "SQL injection in query field"),
        ]

        INTERNAL_MARKERS = ["pydantic", "validation error for call", "field required",
                            "value_error", "typeerror", "prisma"]

        for tool_name, args, scenario in probes:
            result, error = await self.call_tool(tool_name, args)
            text = (result or error or "").lower()
            leaked_internals = [m for m in INTERNAL_MARKERS if m in text]
            results.append(VerificationResult(
                finding_id="SEC-015",
                status=FAIL if leaked_internals else PASS,
                finding_title=f"{TITLE} [{scenario}]",
                expected="'Invalid input parameters' — no Pydantic class names or field details",
                actual=f"Internal validation details leaked: {leaked_internals}" if leaked_internals
                       else "Generic error or normal response — no internals exposed",
                evidence={"scenario": scenario, "response": (result or error or "")[:300]}
            ))

        return results

    async def verify_SEC_016_017(self) -> list[VerificationResult]:
        """
        SEC-016/017: Injection Behavior Signal — Remediated (via error sanitization)
        Client fix: all errors now generic — no differential signal
        """
        results = []

        # ── SEC-016: db_search_courses injection signal ───────────────────────
        TITLE_16 = "Injection Behavior Signal in db_search_courses"
        # Send normal query
        result_normal, _ = await self.call_tool("db_search_courses",
                                                  {"query": "python", "limit": 5})
        # Send injection query
        result_inject, error_inject = await self.call_tool("db_search_courses",
                                                             {"query": "' OR '1'='1", "limit": 5})
        normal_text  = (result_normal or "").lower()
        inject_text  = (result_inject or error_inject or "").lower()

        DIFF_MARKERS = ["prisma", "sql", "syntax error", "database", "ora-", "pg_"]
        diff_found = [m for m in DIFF_MARKERS if m in inject_text and m not in normal_text]
        results.append(VerificationResult(
            finding_id="SEC-016", status=FAIL if diff_found else PASS,
            finding_title=TITLE_16,
            expected="No differential error signal — injection response is generic",
            actual=f"Differential signal still present: {diff_found}" if diff_found
                   else "No differential injection signal — error responses are uniform",
            evidence={"normal": normal_text[:200], "injection": inject_text[:200]}
        ))

        # ── SEC-017: create_resource_entry_tool injection ─────────────────────
        TITLE_17 = "Injection Behavior Signal in create_resource_entry_tool"
        result_inj, error_inj = await self.call_tool("create_resource_entry_tool", {
            "url": "https://example.com/x.png",
            "course_id": KNOWN_COURSE_ID,
            "card_id": "test",
            "resource_type": "'; DROP TABLE courses; --",
            "source": "test",
            "meta": {}
        })
        text17 = (result_inj or error_inj or "").lower()
        prisma_found = [m for m in ["prisma.", "invocation:", "data: {"] if m in text17]
        enum_rejected = any(m in text17 for m in ["invalid resource_type", "must be one of"])
        results.append(VerificationResult(
            finding_id="SEC-017", status=FAIL if prisma_found else PASS,
            finding_title=TITLE_17,
            expected="Enum validation rejects before DB — no Prisma diff signal",
            actual=f"Prisma diff signal still present: {prisma_found}" if prisma_found
                   else f"Enum validation blocked injection ({'enum msg found' if enum_rejected else 'generic error'})",
            evidence={"response": (result_inj or error_inj or "")[:300]}
        ))

        return results

    async def verify_SEC_020(self) -> list[VerificationResult]:
        """
        Validation Errors Leak Pydantic Internals — Remediated
        Client fix: validation error middleware returns generic message
        """
        TITLE = "Validation Errors Leak Pydantic Internals"
        PYDANTIC_MARKERS = ["pydantic", "validation error for call", "field required",
                            "value_error.missing", "typeerror", "literalerror",
                            "class 'str'", "class 'int'"]
        results = []

        probes = [
            ("db_list_recent_courses", {"limit": "not-a-number", "offset": 0}),
            ("create_course", {"title": 12345}),  # wrong type
        ]

        for tool_name, args in probes:
            result, error = await self.call_tool(tool_name, args)
            text = (result or error or "").lower()
            leaked = [m for m in PYDANTIC_MARKERS if m in text]
            results.append(VerificationResult(
                finding_id="SEC-020",
                status=FAIL if leaked else PASS,
                finding_title=f"{TITLE} [{tool_name}]",
                expected="'Invalid input parameters. Please check the required fields and try again.'",
                actual=f"Pydantic internals still leaked: {leaked}" if leaked
                       else "Generic validation error message returned",
                evidence={"response": (result or error or "")[:300]}
            ))

        return results


# ── DCR Verifiers (OAuth HTTP Tests) ──────────────────────────────────────────

class DCRVerifier(BaseVerifier):

    def _register_client(self, client_name: str, redirect_uri: str = "http://127.0.0.1:9999/cb",
                          scope: str = "mcp:access", extra_headers: dict | None = None) -> httpx.Response:
        headers = {"Content-Type": "application/json"}
        if extra_headers:
            headers.update(extra_headers)
        return self.http_post(
            f"{AUTH_SERVER}/oauth/register",
            body={
                "client_name": client_name,
                "redirect_uris": [redirect_uri],
                "scope": scope,
                "grant_types": ["authorization_code"],
                "response_types": ["code"],
                "token_endpoint_auth_method": "none"
            },
            headers=headers
        )

    def verify_DCR_001_rate_limit(self) -> list[VerificationResult]:
        """
        DCR-001: Rate limit — 5 registrations per IP per hour → 6th returns 429
        """
        TITLE = "DCR-001: Open OAuth Dynamic Client Registration — Rate Limit"
        print(f"\n  [DCR-001] Sending 6 POST /oauth/register requests to trigger 429...")

        last_status = None
        for i in range(1, 7):
            resp = self._register_client(f"VerifyClient-{i}-{int(time.time())}")
            last_status = resp.status_code
            print(f"    Request {i}: HTTP {resp.status_code}")
            if resp.status_code == 429:
                break

        if last_status == 429:
            return [VerificationResult(
                finding_id="DCR-001", status=PASS, finding_title=TITLE,
                expected="6th registration returns HTTP 429 with Retry-After header",
                actual=f"HTTP 429 received as expected",
            )]
        else:
            return [VerificationResult(
                finding_id="DCR-001", status=FAIL, finding_title=TITLE,
                expected="HTTP 429 after 5 registrations from same IP",
                actual=f"6th request returned HTTP {last_status} — rate limit not enforced",
            )]

    def verify_DCR_003_client_name_sanitization(self) -> list[VerificationResult]:
        """
        DCR-003: Client Name Spoofing & XSS Injection — Remediated
        """
        TITLE = "DCR-003: Client Name Spoofing & XSS Injection"
        results = []

        payloads = [
            ("Generic Official App",       400, "brand impersonation (skill10x)"),
            ("Google Account Recovery",      400, "brand impersonation (google)"),
            ("alert('xss')",                400, "HTML/script injection"),
            ("Legitimate App\nX-Header: x", 400, "CRLF injection"),
            ("My Course Builder",           201, "legitimate name — should succeed"),
        ]

        for client_name, expected_status, scenario in payloads:
            resp = self._register_client(f"{client_name} {int(time.time())}"
                                         if expected_status == 201 else client_name)
            results.append(VerificationResult(
                finding_id="DCR-003",
                status=PASS if resp.status_code == expected_status else FAIL,
                finding_title=f"{TITLE} [{scenario}]",
                expected=f"HTTP {expected_status}",
                actual=f"HTTP {resp.status_code}",
                evidence={"response_body": resp.text[:300]}
            ))

        return results

    def verify_DCR_004_uri_canonicalization(self) -> list[VerificationResult]:
        """
        DCR-004: Localhost Redirect URI Bypass via IP Obfuscation — Remediated
        Client fix: redirect URIs stored in canonical form
        """
        TITLE = "DCR-004: Localhost Redirect URI Bypass via IP Obfuscation"
        results = []

        obfuscated_forms = [
            "http://0x7f000001:9999/cb",
            "http://127.1:9999/cb",
            "http://2130706433:9999/cb",
            "http://017700000001:9999/cb",
        ]

        for uri in obfuscated_forms:
            resp = self._register_client(
                f"TestCanon-{int(time.time())}",
                redirect_uri=uri
            )
            if resp.status_code == 201:
                body = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {}
                stored_uris = body.get("redirect_uris", [])
                canonical = "http://127.0.0.1:9999/cb"
                is_canonical = stored_uris and stored_uris[0] == canonical
                results.append(VerificationResult(
                    finding_id="DCR-004",
                    status=PASS if is_canonical else FAIL,
                    finding_title=f"{TITLE} [{uri}]",
                    expected=f"Stored as canonical 'http://127.0.0.1:9999/cb', not '{uri}'",
                    actual=f"Stored as: {stored_uris}",
                    evidence={"input": uri, "stored": stored_uris}
                ))
            else:
                results.append(VerificationResult(
                    finding_id="DCR-004",
                    status=FAIL,
                    finding_title=f"{TITLE} [{uri}]",
                    expected="HTTP 201 with canonical URI stored",
                    actual=f"HTTP {resp.status_code} — registration rejected unexpectedly",
                    evidence={"uri": uri, "response": resp.text[:200]}
                ))

        return results

    def verify_DCR_005_scope_validation(self) -> list[VerificationResult]:
        """
        DCR-005: Arbitrary Scope Registration — Remediated
        Client fix: scope allowlist enforced at registration
        """
        TITLE = "DCR-005: Arbitrary Scope Registration Without Validation"
        results = []

        scope_tests = [
            ("mcp:access admin:full",                      400, "admin escalation scope"),
            ("mcp:access read:all_customers",              400, "customer data scope"),
            ("mcp:access urn:custom:superadmin",           400, "custom superadmin scope"),
            ("mcp:access",                                 201, "valid scope — should succeed"),
        ]

        for scope, expected_status, scenario in scope_tests:
            resp = self._register_client(
                f"ScopeTest-{int(time.time())}",
                scope=scope
            )
            body_text = resp.text.lower()
            has_invalid_scope = "invalid_scope" in body_text
            results.append(VerificationResult(
                finding_id="DCR-005",
                status=PASS if resp.status_code == expected_status else FAIL,
                finding_title=f"{TITLE} [{scenario}]",
                expected=f"HTTP {expected_status}" + (" with invalid_scope error" if expected_status == 400 else ""),
                actual=f"HTTP {resp.status_code}" + (f" (invalid_scope: {has_invalid_scope})" if resp.status_code == 400 else ""),
                evidence={"scope": scope, "response": resp.text[:300]}
            ))

        return results

    def verify_DCR_006_open_redirect(self) -> list[VerificationResult]:
        """
        DCR-006: Open Redirect — Mitigated via consent banner
        Manual check — consent screen must show red unverified banner
        """
        return [VerificationResult(
            finding_id="DCR-006", status=SKIP,
            finding_title="DCR-006: Open Redirect via Authorization Endpoint",
            expected="Consent screen shows red 'Unverified application — registered just now' banner",
            actual="Manual verification required — cannot automate browser consent screen check",
            notes="Register a DCR client, then visit /oauth/authorize with that client_id. "
                  "Verify the consent page shows the red unverified banner and localhost warning."
        )]


# ── EXTRA Verifiers (Additional Hardening HTTP Tests) ─────────────────────────

class EXTRAVerifier(BaseVerifier):

    def verify_EXTRA_01_cross_tenant_quota(self) -> list[VerificationResult]:
        """
        EXTRA-01: Cross-tenant authorization on quota endpoints — Remediated
        Fix: companyId in body must match authenticated user's company
        """
        TITLE = "EXTRA-01: Cross-tenant authorization on quota endpoints"
        FAKE_COMPANY_ID = "00000000000000000000000000000000"  # not our company

        results = []
        for endpoint in ["/api/quota/check", "/api/quota/increment"]:
            body = {
                "companyId": FAKE_COMPANY_ID,
                "type": "audio_minutes",
                "amount": 10
            }
            resp = self.http_post(f"{AUTH_SERVER}{endpoint}", body)
            results.append(VerificationResult(
                finding_id="EXTRA-01",
                status=PASS if resp.status_code == 403 else FAIL,
                finding_title=f"{TITLE} [{endpoint}]",
                expected="HTTP 403 Permission denied for cross-tenant companyId",
                actual=f"HTTP {resp.status_code}",
                evidence={"endpoint": endpoint, "response": resp.text[:200]}
            ))

        return results

    def verify_EXTRA_02_cross_tenant_card_read(self) -> list[VerificationResult]:
        """
        EXTRA-02: Cross-tenant read on GET /api/card/[id] — Remediated
        Fix: handler now verifies card belongs to caller's company
        """
        TITLE = "EXTRA-02: Cross-tenant read on GET /api/card/[id]"
        # Use a fabricated card ID that is unlikely to belong to our company
        FOREIGN_CARD_ID = "00000000-0000-0000-0000-000000000001"

        resp = self.http_get(f"{AUTH_SERVER}/api/card/{FOREIGN_CARD_ID}")
        return [VerificationResult(
            finding_id="EXTRA-02",
            status=PASS if resp.status_code == 404 else FAIL,
            finding_title=TITLE,
            expected="HTTP 404 'Card not found' (not 403, to avoid confirming card exists)",
            actual=f"HTTP {resp.status_code}",
            notes="For full verification, obtain a real card ID from a different test company",
            evidence={"response": resp.text[:200]}
        )]

    def verify_EXTRA_03_pagination_default_cap(self) -> list[VerificationResult]:
        """
        EXTRA-03: Pagination default cap on generic CRUD GET — Remediated
        Fix: default take=50, explicit capped at ≤100
        """
        TITLE = "EXTRA-03: Pagination default cap on generic CRUD GET"
        results = []

        # No ?take param → should return max 50
        resp_no_take = self.http_get(f"{AUTH_SERVER}/api/card?where[isActive]=true")
        # Huge take → capped at 100
        resp_huge   = self.http_get(f"{AUTH_SERVER}/api/card?where[isActive]=true&take=99999")

        for label, resp, max_expected in [
            ("no ?take (default 50)", resp_no_take, 50),
            ("take=99999 (cap 100)", resp_huge, 100),
        ]:
            try:
                body = resp.json()
                count = len(body) if isinstance(body, list) else len(body.get("data", []))
                results.append(VerificationResult(
                    finding_id="EXTRA-03",
                    status=PASS if count <= max_expected else FAIL,
                    finding_title=f"{TITLE} [{label}]",
                    expected=f"≤ {max_expected} records returned",
                    actual=f"{count} records returned",
                    evidence={"http_status": resp.status_code, "count": count}
                ))
            except Exception as exc:
                results.append(VerificationResult(
                    finding_id="EXTRA-03",
                    status=ERROR, finding_title=f"{TITLE} [{label}]",
                    expected=f"≤ {max_expected} records",
                    actual=f"Parse error: {exc} | HTTP {resp.status_code}",
                    evidence={"response": resp.text[:200]}
                ))

        return results

    def verify_EXTRA_06_token_rate_limit(self) -> list[VerificationResult]:
        """
        EXTRA-06: /oauth/token rate limit — 60/minute/IP — Remediated
        Fix: 61st request returns HTTP 429
        """
        TITLE = "EXTRA-06: /oauth/token Rate Limit (60/min)"
        print(f"\n  [EXTRA-06] Sending 61 POST /oauth/token requests (may take ~30s)...")
        last_status = None
        for i in range(1, 62):
            resp = self.http_post(
                f"{AUTH_SERVER}/oauth/token",
                body={"grant_type": "authorization_code",
                      "code": "fake-code",
                      "client_id": "fake-client"},
                headers={"Content-Type": "application/json"}
            )
            last_status = resp.status_code
            if resp.status_code == 429:
                print(f"    429 received on request {i}")
                break
            if i % 10 == 0:
                print(f"    Sent {i} requests, last status: {resp.status_code}")

        return [VerificationResult(
            finding_id="EXTRA-06",
            status=PASS if last_status == 429 else FAIL,
            finding_title=TITLE,
            expected="HTTP 429 with Retry-After: 60 after 61 requests within 1 minute",
            actual=f"Last HTTP status: {last_status}",
        )]

    def verify_EXTRA_07_dcr_failed_attempts_count(self) -> list[VerificationResult]:
        """
        EXTRA-07: DCR rate limit counts failed attempts — Remediated
        Fix: rate limit recorded BEFORE input validation, so blocked names consume quota
        """
        TITLE = "EXTRA-07: DCR Rate Limit Counts Failed Attempts"
        print(f"\n  [EXTRA-07] Sending 6 blocked registrations to trigger rate limit...")

        last_status = None
        for i in range(1, 7):
            resp = self.http_post(
                f"{AUTH_SERVER}/oauth/register",
                body={
                    "client_name": "Generic",  # always blocked by brand filter
                    "redirect_uris": ["http://127.0.0.1:9999/cb"],
                    "scope": "mcp:access"
                },
                headers={"Content-Type": "application/json"}
            )
            last_status = resp.status_code
            print(f"    Request {i}: HTTP {resp.status_code}")
            if resp.status_code == 429:
                break

        return [VerificationResult(
            finding_id="EXTRA-07",
            status=PASS if last_status == 429 else FAIL,
            finding_title=TITLE,
            expected="6th rejected registration returns HTTP 429 (not just 400)",
            actual=f"Last HTTP status: {last_status}",
            notes="If 429 never appears, failed attempts are not consuming the rate-limit budget"
        )]

    def verify_EXTRA_08_dcr_uri_rules(self) -> list[VerificationResult]:
        """
        EXTRA-08: DCR redirect URI rejects userinfo and 0.0.0.0 — Remediated
        """
        TITLE = "EXTRA-08: DCR Redirect URI Additional Rejection Rules"
        results = []

        uri_tests = [
            ("http://user:pw@localhost/cb",   400, "userinfo in URI"),
            ("http://0.0.0.0:9999/cb",        400, "0.0.0.0 host"),
            ("http://[::1]:9999/cb",           201, "IPv6 loopback — accepted"),
            ("http://127.0.0.5:9999/cb",       201, "127.0.0.5 — accepted (127/8 range)"),
        ]

        for uri, expected_status, scenario in uri_tests:
            resp = self.http_post(
                f"{AUTH_SERVER}/oauth/register",
                body={
                    "client_name": f"TestUri-{int(time.time())}",
                    "redirect_uris": [uri],
                    "scope": "mcp:access"
                },
                headers={"Content-Type": "application/json"}
            )
            results.append(VerificationResult(
                finding_id="EXTRA-08",
                status=PASS if resp.status_code == expected_status else FAIL,
                finding_title=f"{TITLE} [{scenario}]",
                expected=f"HTTP {expected_status}",
                actual=f"HTTP {resp.status_code}",
                evidence={"uri": uri, "response": resp.text[:200]}
            ))

        return results

    def verify_EXTRA_09_brand_digit_homoglyphs(self) -> list[VerificationResult]:
        """
        EXTRA-09: Brand impersonation blocklist — digit homoglyphs — Remediated
        """
        TITLE = "EXTRA-09: Brand Impersonation Blocklist — Digit Homoglyphs"
        results = []

        brand_tests = [
            ("g0ogle helper",    400, "google digit homoglyph (0→o)"),
            ("Sk1ll10x Assist",  400, "skill10x digit homoglyph (1→i)"),
            ("Meta Platforms",   400, "meta as standalone token"),
            ("Metadata Manager", 201, "metadata — meta is part of larger word (should pass)"),
        ]

        for client_name, expected_status, scenario in brand_tests:
            resp = self.http_post(
                f"{AUTH_SERVER}/oauth/register",
                body={
                    "client_name": client_name,
                    "redirect_uris": ["http://127.0.0.1:9999/cb"],
                    "scope": "mcp:access"
                },
                headers={"Content-Type": "application/json"}
            )
            results.append(VerificationResult(
                finding_id="EXTRA-09",
                status=PASS if resp.status_code == expected_status else FAIL,
                finding_title=f"{TITLE} [{scenario}]",
                expected=f"HTTP {expected_status}",
                actual=f"HTTP {resp.status_code}",
                evidence={"client_name": client_name, "response": resp.text[:200]}
            ))

        return results


# ── CTISO Verifiers (Cross-Tenant Isolation Tests) ────────────────────────────

class CTISOVerifier(BaseVerifier):
    """
    Cross-tenant isolation tests that require two tenant accounts.

    manish_token  = primary tenant JWT (company_id b3612853fd7749a89bbd0b06705d1e57)
    ankur_token   = attacking tenant JWT (company_id 1696861412093x359184783180300300)
    engine        = ProbeEngine authenticated as Manish (primary)
    """

    # Known Manish course used as the cross-tenant write target
    MANISH_COURSE_ID = "cc1ef47f-799c-4460-a376-0c601514288e"
    MANISH_COMPANY_ID = "b3612853fd7749a89bbd0b06705d1e57"

    def __init__(self, manish_token: str, ankur_token: str,
                 engine: ProbeEngine | None = None) -> None:
        super().__init__(manish_token, engine)
        self.ankur_token = ankur_token

    # ── CTISO-04 ───────────────────────────────────────────────────────────────

    async def verify_CTISO_04(self) -> list[VerificationResult]:
        """
        CTISO-04: Cross-tenant card injection via create_content_card
        Ankur (tenant B) calls create_content_card with a Manish (tenant A) course_id.
        Fix required: companyId ownership pre-check before prisma.card.create().
        Expected after fix: 403 / 'Permission denied' or 'Course not found'.
        """
        TITLE = "Cross-tenant card injection via create_content_card"

        if not self.ankur_token:
            return [VerificationResult(
                finding_id="CTISO-04", status=SKIP, finding_title=TITLE,
                expected="HTTP 403 — Ankur cannot write to Manish course",
                actual="Skipped — ankur token not provided (use --token-ankur)",
            )]

        # Open a fresh MCP session as Ankur (the attacker)
        config_ankur = TargetConfig(
            endpoint_url=MCP_ENDPOINT,
            transport=TransportType.SSE,
            auth_method=AuthMethod.BEARER_TOKEN,
            auth_token=self.ankur_token,
        )
        ankur_engine = ProbeEngine(config_ankur)

        try:
            async with ankur_engine.connect(identity="ankur-attacker"):
                resp = await ankur_engine.call_tool("create_content_card", {
                    "course_id": self.MANISH_COURSE_ID,
                    "header1_text": "CTISO-04 Retest 2026-04-26",
                })
                text = str(resp)

                # Success indicators — card was created (FAIL)
                created = (
                    '"success": true' in text
                    or '"cardId"' in text
                    or '"cardid"' in text.lower()
                )
                # Block indicators — server rejected the cross-tenant write (PASS)
                blocked = any(m in text.lower() for m in [
                    "403", "permission denied", "forbidden",
                    "not found", "not authorized", "access denied",
                    "course not found", "unauthorized",
                ])

                import re
                card_id_match = re.search(r'"cardId":\s*"([^"]+)"', text)
                injected_card = card_id_match.group(1) if card_id_match else "unknown"

                if created:
                    return [VerificationResult(
                        finding_id="CTISO-04", status=FAIL, finding_title=TITLE,
                        expected="HTTP 403 — ownership check blocks cross-tenant write",
                        actual=f"Card CREATED (id={injected_card}) in Manish course — no ownership check",
                        evidence={
                            "attacker": "ankur (1696861412093x359184783180300300)",
                            "target_course": self.MANISH_COURSE_ID,
                            "injected_card_id": injected_card,
                            "response_snippet": text[:400],
                        },
                        notes="create_content_card accepts any course_id without verifying caller's companyId",
                    )]
                elif blocked:
                    return [VerificationResult(
                        finding_id="CTISO-04", status=PASS, finding_title=TITLE,
                        expected="HTTP 403 — ownership check blocks cross-tenant write",
                        actual="Cross-tenant write correctly rejected",
                        evidence={"response_snippet": text[:400]},
                    )]
                else:
                    return [VerificationResult(
                        finding_id="CTISO-04", status=ERROR, finding_title=TITLE,
                        expected="HTTP 403 or explicit success indicator",
                        actual=f"Ambiguous response — manual review required",
                        evidence={"response_snippet": text[:400]},
                    )]
        except Exception as exc:
            return [VerificationResult(
                finding_id="CTISO-04", status=ERROR, finding_title=TITLE,
                expected="HTTP 403 — cross-tenant write rejected",
                actual=f"Exception during Ankur MCP session: {exc}",
            )]

    # ── CTISO-06 ───────────────────────────────────────────────────────────────

    async def verify_CTISO_06(self) -> list[VerificationResult]:
        """
        CTISO-06: companyId embedded in Azure Blob Storage URL path segment.
        Expected after fix: blob URLs use an opaque UUID unrelated to tenant identity.
        Pattern still present: .blob.core.windows.net/media/{companyId}/...
        """
        TITLE = "companyId embedded in Azure Blob Storage URL path"
        results = []
        probes = [
            ("db_list_recent_courses",  {"limit": 5, "offset": 0}),
            ("db_get_course_details",   {"course_id": self.MANISH_COURSE_ID, "include_cards": True}),
        ]

        for tool_name, args in probes:
            result, error = await self.call_tool(tool_name, args)
            text = (result or error or "")

            # Extract any matching blob URLs
            import re
            blob_hits = re.findall(
                rf'https://[a-z0-9]+\.blob\.core\.windows\.net[^\s"\'\\]*{re.escape(self.MANISH_COMPANY_ID)}[^\s"\'\\]*',
                text,
            )

            results.append(VerificationResult(
                finding_id="CTISO-06",
                status=FAIL if blob_hits else PASS,
                finding_title=f"{TITLE} [{tool_name}]",
                expected=f"companyId NOT present in blob URL path — replaced with opaque ID",
                actual=(
                    f"companyId still embedded in {len(blob_hits)} blob URL(s)"
                    if blob_hits
                    else "No companyId found in blob URL paths"
                ),
                evidence={"blob_urls_with_company_id": blob_hits[:3]},
            ))

        return results

    # ── CTISO-10 ───────────────────────────────────────────────────────────────

    def verify_CTISO_10(self) -> list[VerificationResult]:
        """
        CTISO-10: REST API accepts MCP-scoped JWT (wrong aud claim — RFC 7519 §4.1.3).
        Manish's token has aud = MCP endpoint URL, NOT app.skill10x.com.
        After fix: REST JWT middleware must reject tokens with wrong audience.
        """
        TITLE = "REST API accepts MCP-scoped JWT (wrong aud claim)"
        results = []

        rest_probes = [
            ("GET",  f"{AUTH_SERVER}/api/course",        None),
            ("GET",  f"{AUTH_SERVER}/api/card",          None),
        ]

        for method, url, body in rest_probes:
            endpoint = url.replace(AUTH_SERVER, "")
            try:
                resp = self.http_get(url) if method == "GET" else self.http_post(url, body or {})
                accepted = resp.status_code == 200
                results.append(VerificationResult(
                    finding_id="CTISO-10",
                    status=FAIL if accepted else PASS,
                    finding_title=f"{TITLE} [{method} {endpoint}]",
                    expected="HTTP 401 — REST API rejects token whose aud≠app.skill10x.com",
                    actual=(
                        f"HTTP {resp.status_code} — REST API ACCEPTS MCP-scoped JWT; aud claim not validated"
                        if accepted
                        else f"HTTP {resp.status_code} — token rejected as expected"
                    ),
                    evidence={
                        "token_aud": MCP_ENDPOINT,
                        "expected_aud": AUTH_SERVER,
                        "http_status": resp.status_code,
                        "response_snippet": resp.text[:300],
                    },
                    notes="RFC 7519 §4.1.3: recipient MUST verify aud contains its own identifier",
                ))
            except Exception as exc:
                results.append(VerificationResult(
                    finding_id="CTISO-10", status=ERROR, finding_title=f"{TITLE} [{endpoint}]",
                    expected="HTTP 401",
                    actual=f"Request error: {exc}",
                ))

        return results


# ── Registry ───────────────────────────────────────────────────────────────────

def build_registry(token: str, engine: ProbeEngine | None = None,
                   ankur_token: str = "") -> dict:
    """
    Returns a flat dict: { finding_id: (label, coroutine_or_callable) }
    Coroutines = MCP tests (need engine).
    Callables  = HTTP tests (no engine needed).
    """
    sec   = SECVerifier(token, engine)
    dcr   = DCRVerifier(token, engine)
    ext   = EXTRAVerifier(token, engine)
    ctiso = CTISOVerifier(token, ankur_token, engine)

    return {
        # MCP tool verifications (async)
        "SEC-001": ("Prisma ORM query structure leaked",              sec.verify_SEC_001),
        "SEC-002": ("Company Tenant ID leaked",                       sec.verify_SEC_002),
        "SEC-003": ("Azure Blob SAS tokens in MCP responses",         sec.verify_SEC_003),
        "SEC-004": ("Azure Blob assets publicly downloadable",        sec.verify_SEC_004),
        "SEC-005": ("Prisma DB schema fully mapped via errors",       sec.verify_SEC_005),
        "SEC-006": ("Echo tool reflects XSS payloads",                sec.verify_SEC_006),
        "SEC-007": ("Negative offset triggers Prisma AssertionError", sec.verify_SEC_007),
        "SEC-008": ("ElevenLabs usage quota leaked",                  sec.verify_SEC_008),
        "SEC-009": ("Full infra stack disclosed via errors",          sec.verify_SEC_009),
        "SEC-010": ("Course instructions leak internal architecture", sec.verify_SEC_010),
        "SEC-011": ("Negative limit exposes hidden courses",          sec.verify_SEC_011),
        "SEC-012": ("create_link_card accepts credential URLs",       sec.verify_SEC_012),
        "SEC-014": ("SSRF attack surface (already blocked)",          sec.verify_SEC_014),
        "SEC-015": ("Weak/no input schema on 14 tools",               sec.verify_SEC_015),
        "SEC-016": ("Injection signal in db_search_courses",          sec.verify_SEC_016_017),
        "SEC-020": ("Validation errors leak Pydantic internals",      sec.verify_SEC_020),

        # Cross-tenant isolation tests (MCP + HTTP)
        "CTISO-04": ("Cross-tenant card injection via create_content_card", ctiso.verify_CTISO_04),
        "CTISO-06": ("companyId in Azure Blob Storage URL path",            ctiso.verify_CTISO_06),
        "CTISO-10": ("REST API accepts MCP-scoped JWT (wrong aud claim)",   ctiso.verify_CTISO_10),

        # HTTP OAuth verifications (sync)
        "DCR-001": ("Open OAuth Dynamic Client Registration",         dcr.verify_DCR_001_rate_limit),
        "DCR-003": ("Client name spoofing & XSS injection",           dcr.verify_DCR_003_client_name_sanitization),
        "DCR-004": ("Localhost redirect URI bypass via IP obfuscation", dcr.verify_DCR_004_uri_canonicalization),
        "DCR-005": ("Arbitrary scope registration without validation", dcr.verify_DCR_005_scope_validation),
        "DCR-006": ("Open redirect via authorization endpoint",        dcr.verify_DCR_006_open_redirect),

        # EXTRA hardening verifications (sync)
        "EXTRA-01": ("Cross-tenant quota endpoint authorization",     ext.verify_EXTRA_01_cross_tenant_quota),
        "EXTRA-02": ("Cross-tenant card read",                        ext.verify_EXTRA_02_cross_tenant_card_read),
        "EXTRA-03": ("Pagination default cap on CRUD GET",            ext.verify_EXTRA_03_pagination_default_cap),
        "EXTRA-06": ("/oauth/token rate limit",                       ext.verify_EXTRA_06_token_rate_limit),
        "EXTRA-07": ("DCR rate limit counts failed attempts",         ext.verify_EXTRA_07_dcr_failed_attempts_count),
        "EXTRA-08": ("DCR redirect URI rejects userinfo / 0.0.0.0",  ext.verify_EXTRA_08_dcr_uri_rules),
        "EXTRA-09": ("Brand impersonation digit homoglyphs",          ext.verify_EXTRA_09_brand_digit_homoglyphs),
    }


# ── Runner ─────────────────────────────────────────────────────────────────────

async def run_verifications(token: str, finding_ids: list[str],
                            ankur_token: str = "") -> list[VerificationResult]:
    """Run the requested verifications against a live MCP engine session."""
    config = TargetConfig(
        endpoint_url=MCP_ENDPOINT,
        transport=TransportType.SSE,
        auth_method=AuthMethod.BEARER_TOKEN,
        auth_token=token,
    )
    engine = ProbeEngine(config)

    needs_mcp = any(
        fid.startswith("SEC-") or fid in ("CTISO-04", "CTISO-06")
        for fid in finding_ids
    )

    all_results: list[VerificationResult] = []

    async def _run_one(fid: str, registry: dict) -> None:
        import inspect
        if fid not in registry:
            print(f"  [?] Unknown finding: {fid}")
            return
        label, fn = registry[fid]
        print(f"\n[►] Verifying {fid}: {label}")
        try:
            results = await fn() if inspect.iscoroutinefunction(fn) else fn()
            for r in results:
                print(r)
            all_results.extend(results)
        except Exception as exc:
            err = VerificationResult(
                finding_id=fid, status=ERROR, finding_title=label,
                expected="Verification completed",
                actual=f"Verifier raised exception: {exc}",
            )
            print(err)
            all_results.append(err)

    if needs_mcp:
        print(f"\n[*] Connecting to MCP server: {MCP_ENDPOINT}")
        async with engine.connect() as _:
            tools = await engine.list_tools()
            print(f"[+] Connected — {len(tools)} tools discovered\n")
            registry = build_registry(token, engine, ankur_token)
            for fid in finding_ids:
                await _run_one(fid, registry)
    else:
        # HTTP-only — no MCP connection needed
        registry = build_registry(token, engine=None, ankur_token=ankur_token)
        for fid in finding_ids:
            await _run_one(fid, registry)

    return all_results


def print_summary(results: list[VerificationResult]) -> None:
    counts = {PASS: 0, FAIL: 0, SKIP: 0, ERROR: 0}
    for r in results:
        counts[r.status] = counts.get(r.status, 0) + 1

    total = len(results)
    print(f"\n{'='*70}")
    print(f"  VERIFICATION SUMMARY")
    print(f"{'='*70}")
    print(f"  Total checks : {total}")
    print(f"  ✅ PASS      : {counts[PASS]}")
    print(f"  ❌ FAIL      : {counts[FAIL]}")
    print(f"  ⏭  SKIP      : {counts[SKIP]}")
    print(f"  💥 ERROR     : {counts[ERROR]}")
    print(f"{'='*70}")

    if counts[FAIL] or counts[ERROR]:
        print(f"\n  Failed / Error checks:")
        for r in results:
            if r.status in (FAIL, ERROR):
                icon = "❌" if r.status == FAIL else "💥"
                print(f"    {icon} {r.finding_id} — {r.finding_title}")
                print(f"       Expected : {r.expected}")
                print(f"       Actual   : {r.actual}")

    # Save results to file
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    out_path = f"output/verification_{ts}.json"
    with open(out_path, "w") as f:
        json.dump([{
            "finding_id": r.finding_id,
            "status": r.status,
            "title": r.finding_title,
            "expected": r.expected,
            "actual": r.actual,
            "notes": r.notes,
            "evidence": r.evidence,
        } for r in results], f, indent=2)
    print(f"\n  Results saved: {out_path}")


# ── CLI ────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Verify Generic MCP remediations against the live server",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    parser.add_argument("--token", help="Primary bearer token (Manish / app.skill10x.com)")
    parser.add_argument("--token-file", default="token_manish.txt",
                        help="Path to primary token file (default: token_manish.txt)")
    parser.add_argument("--token-ankur", help="Ankur bearer token (required for CTISO-04)")
    parser.add_argument("--token-ankur-file", default="token_ankur.txt",
                        help="Path to Ankur token file (default: token_ankur.txt)")
    parser.add_argument("--finding", help="Run a single finding (e.g. SEC-001, CTISO-04, DCR-003)")
    parser.add_argument("--findings", nargs="+", metavar="ID",
                        help="Run specific findings (e.g. --findings CTISO-04 SEC-002 CTISO-06 CTISO-10)")
    parser.add_argument("--category", choices=["SEC", "DCR", "EXTRA", "CTISO"],
                        help="Run all verifications in a category")
    parser.add_argument("--all", action="store_true", help="Run all verifications")
    parser.add_argument("--list", action="store_true", help="List all available verifications")
    args = parser.parse_args()

    # Load primary token
    token = args.token
    if not token:
        try:
            with open(args.token_file) as f:
                token = f.read().strip()
        except FileNotFoundError:
            pass

    # Load Ankur token (optional; only required for CTISO-04)
    ankur_token = args.token_ankur or ""
    if not ankur_token:
        try:
            with open(args.token_ankur_file) as f:
                ankur_token = f.read().strip()
        except FileNotFoundError:
            pass

    if args.list:
        reg = build_registry(token or "", engine=None, ankur_token=ankur_token)
        print(f"\nAvailable verifications ({len(reg)} total):\n")
        for fid, (label, _) in reg.items():
            print(f"  {fid:<12} {label}")
        return

    if not token:
        print("Error: --token or --token-file required")
        parser.print_help()
        sys.exit(1)

    # Determine which findings to run
    registry_stub = build_registry(token, engine=None, ankur_token=ankur_token)
    if args.all:
        finding_ids = list(registry_stub.keys())
    elif args.category:
        finding_ids = [fid for fid in registry_stub if fid.startswith(args.category)]
    elif args.findings:
        finding_ids = args.findings
    elif args.finding:
        finding_ids = [args.finding]
    else:
        parser.print_help()
        sys.exit(1)

    print(f"\n{'='*70}")
    print(f"  Generic MCP Remediation Verification")
    print(f"  Target    : {MCP_ENDPOINT}")
    print(f"  Auth Svr  : {AUTH_SERVER}")
    print(f"  Checks    : {len(finding_ids)}")
    print(f"  Run at    : {datetime.now(timezone.utc).isoformat()}")
    print(f"{'='*70}")

    results = asyncio.run(run_verifications(token, finding_ids, ankur_token=ankur_token))
    print_summary(results)


if __name__ == "__main__":
    main()
