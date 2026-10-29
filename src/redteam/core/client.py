"""Manifest-driven HTTP client.

Reads `manifest.endpoints[*]` to build URLs by named operation; renders body
templates by substituting `{{ placeholders }}`; provides a streaming SSE drain.

No target names appear in this file. The Client is just the manifest's
mechanical executor.

See ~/.claude/skills/prompt-exfil/SKILL.md for usage.
"""
from __future__ import annotations

import time
from typing import Any, Mapping, Optional

import requests

from src.redteam.target import Manifest, SSEResponse, _render_template


class Client:
    def __init__(self, manifest: Manifest, token: str):
        self.manifest = manifest
        self.token = token
        self.session = requests.Session()
        self.session.headers.update(self._default_headers())

    def _default_headers(self) -> dict[str, str]:
        auth = self.manifest.auth
        h = {
            auth["header"]: f"{auth['scheme']} {self.token}",
        }
        h.setdefault("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) RedTeam/1.0")
        # Allow the manifest to declare extra default headers (e.g. Origin/Referer
        # that the target's CORS policy requires)
        for k, v in (self.manifest.auth.get("default_headers") or {}).items():
            h[k] = v
        return h

    # ---- non-streaming request ----

    def request(
        self,
        endpoint_name: str,
        *,
        vars: Optional[Mapping[str, Any]] = None,
        json_body: Any = None,
        params: Optional[Mapping[str, Any]] = None,
        timeout: int = 30,
    ) -> requests.Response:
        ep = self.manifest.endpoint(endpoint_name)
        method = ep.get("method", "GET").upper()
        url = self.manifest.url(endpoint_name, **(vars or {}))
        query = ep.get("query") or {}
        if params:
            query = {**query, **params}
        if json_body is not None:
            json_body = _render_template(json_body, **(vars or {}))
        return self.session.request(
            method, url, json=json_body if json_body is not None else None,
            params=query or None, timeout=timeout,
        )

    # ---- streaming SSE drain ----

    def drain(
        self,
        endpoint_name: str,
        *,
        vars: Optional[Mapping[str, Any]] = None,
        json_body: Any = None,
        drain_seconds: int = 120,
        byte_cap: int = 2_000_000,
        params: Optional[Mapping[str, Any]] = None,
    ) -> SSEResponse:
        ep = self.manifest.endpoint(endpoint_name)
        if not ep.get("sse", False):
            raise ValueError(
                f"endpoint {endpoint_name!r} is not declared as sse:true in manifest"
            )
        method = ep.get("method", "POST").upper()
        url = self.manifest.url(endpoint_name, **(vars or {}))
        query = ep.get("query") or {}
        if params:
            query = {**query, **params}
        if json_body is not None:
            json_body = _render_template(json_body, **(vars or {}))

        sse_headers = {**self.session.headers, "Accept": "text/event-stream"}

        chunks: list[str] = []
        status = 0
        request_id: Optional[str] = None
        resp_headers: dict[str, str] = {}
        started = time.time()
        try:
            with self.session.request(
                method, url,
                headers=sse_headers,
                json=json_body if json_body is not None else None,
                params=query or None,
                stream=True,
                timeout=drain_seconds + 30,
            ) as r:
                status = r.status_code
                request_id = r.headers.get("x-request-id")
                resp_headers = dict(r.headers)
                deadline = time.time() + drain_seconds
                for chunk in r.iter_content(chunk_size=4096, decode_unicode=True):
                    if time.time() > deadline:
                        chunks.append("\n[CLIENT_TIMEOUT]\n")
                        break
                    if chunk:
                        chunks.append(chunk)
                        if sum(len(c) for c in chunks) > byte_cap:
                            chunks.append("\n[BYTE_CAP]\n")
                            break
        except requests.RequestException as e:
            chunks.append(f"\n[REQUEST_ERR: {e}]\n")

        full = "".join(chunks)
        return SSEResponse(
            status=status,
            request_id=request_id,
            duration_s=round(time.time() - started, 3),
            response_bytes=len(full),
            sse_text=full,
            headers={k: v for k, v in resp_headers.items()
                     if k.lower() in ("content-type", "x-request-id", "date", "server")},
        )

    # ---- raw bytes upload (for canary S3 PUTs) ----

    def put_raw(self, url: str, data: bytes, content_type: str = "application/octet-stream",
                timeout: int = 60) -> requests.Response:
        """PUT raw bytes to an arbitrary URL (typically an S3 presigned URL).
        Does NOT send the auth header — presigned URLs carry their own signature."""
        return requests.put(url, data=data,
                            headers={"Content-Type": content_type},
                            timeout=timeout)
