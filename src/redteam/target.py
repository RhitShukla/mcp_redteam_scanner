"""Manifest loader + TargetAdapter ABC.

The Manifest describes everything target-specific about an engagement:
base URL, auth shape, endpoint paths, body templates, canary flow, JWT format,
known agents. It's loaded from `engagements/<target>/manifest.yml`.

TargetAdapter is the per-target behaviour hook. Most targets need zero
overrides — the default implementation runs everything from the manifest.
Targets with unusual flows (e.g. OrbitShift's askos:true body shape, RFP
canary plant) subclass and override individual methods.

See CLAUDE.md "Starting a new engagement" for the workflow.
"""
from __future__ import annotations

import copy
import pathlib
import re
import time
from abc import ABC
from dataclasses import dataclass, field
from typing import Any, Mapping, Optional

import yaml


# ---------------------------------------------------------------------------
# Manifest
# ---------------------------------------------------------------------------

@dataclass
class Manifest:
    name: str
    base_url: str
    auth: dict[str, Any]
    endpoints: dict[str, dict[str, Any]]
    tokens: dict[str, str]
    canary: dict[str, Any] = field(default_factory=dict)
    known_agents: list[str] = field(default_factory=list)
    output_root: Optional[str] = None
    engagement_dir: pathlib.Path = field(default_factory=pathlib.Path)
    raw: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def load(cls, engagement_dir: str | pathlib.Path) -> "Manifest":
        edir = pathlib.Path(engagement_dir).resolve()
        manifest_path = edir / "manifest.yml"
        if not manifest_path.exists():
            raise FileNotFoundError(f"No manifest.yml in {edir}")
        data = yaml.safe_load(manifest_path.read_text()) or {}
        cls._validate(data, manifest_path)
        return cls(
            name=data["name"],
            base_url=data["base_url"].rstrip("/"),
            auth=data["auth"],
            endpoints=data["endpoints"],
            tokens=data.get("tokens", {}),
            canary=data.get("canary", {}),
            known_agents=list(data.get("known_agents", [])),
            output_root=data.get("output_root"),
            engagement_dir=edir,
            raw=data,
        )

    @staticmethod
    def _validate(data: dict, manifest_path: pathlib.Path) -> None:
        required_top = ("name", "base_url", "auth", "endpoints")
        missing = [k for k in required_top if k not in data]
        if missing:
            raise ValueError(f"{manifest_path}: missing required top-level key(s) {missing}")
        if "jwt" not in data["auth"] or "expected_keys" not in data["auth"]["jwt"]:
            raise ValueError(
                f"{manifest_path}: auth.jwt.expected_keys is required; this is the "
                f"format-assertion list that catches camelCase/snake_case mismatches."
            )

    # ---- token + path resolution ----

    def token_path(self, role: str) -> pathlib.Path:
        if role not in self.tokens:
            raise KeyError(
                f"manifest.tokens has no entry for role={role!r}. "
                f"Available roles: {sorted(self.tokens.keys())}"
            )
        rel = self.tokens[role]
        p = pathlib.Path(rel)
        return p if p.is_absolute() else self.engagement_dir / rel

    def endpoint(self, name: str) -> dict[str, Any]:
        if name not in self.endpoints:
            raise KeyError(
                f"manifest.endpoints has no entry for {name!r}. "
                f"Available: {sorted(self.endpoints.keys())}"
            )
        return self.endpoints[name]

    def url(self, endpoint_name: str, **path_vars: Any) -> str:
        """Render the URL for `endpoint_name` by substituting `{placeholders}`.

        Unknown placeholders raise KeyError with a clear message.
        """
        ep = self.endpoint(endpoint_name)
        path = ep["path"]
        try:
            rendered = path.format(**path_vars)
        except KeyError as e:
            raise KeyError(
                f"endpoint {endpoint_name!r} path {path!r} requires {e!s} which "
                f"was not supplied. Got: {sorted(path_vars.keys())}"
            ) from e
        return f"{self.base_url}{rendered}"

    def body_template(self, endpoint_name: str) -> Any:
        """Return a deep copy of the endpoint's body / body_template field (for in-place
        rendering by the caller)."""
        ep = self.endpoint(endpoint_name)
        body = ep.get("body_template") if "body_template" in ep else ep.get("body")
        return copy.deepcopy(body) if body is not None else None

    # ---- raw-results dir (defaults to engagement_dir if not set) ----

    def raw_results_dir(self) -> pathlib.Path:
        if self.output_root:
            return pathlib.Path(self.output_root)
        return self.engagement_dir / "raw_results"


# ---------------------------------------------------------------------------
# Adapter ABC
# ---------------------------------------------------------------------------

@dataclass
class SessionRef:
    session_id: str
    parent_session_id: Optional[str] = None
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass
class CanaryRef:
    marker: str
    parent_session_id: Optional[str]
    sub_session_id: str
    s3_path: str
    file_id: str
    file_name: str


@dataclass
class SSEResponse:
    """Response from a streaming chat endpoint."""
    status: int
    request_id: Optional[str]
    duration_s: float
    response_bytes: int
    sse_text: str
    headers: dict[str, str] = field(default_factory=dict)


class TargetAdapter(ABC):
    """Per-target behaviour hooks. Most targets need zero overrides.

    Default implementations use the manifest. Subclass and override only the
    methods whose flow can't be expressed by the manifest alone.
    """

    def __init__(self, manifest: Manifest, token_role: str):
        self.manifest = manifest
        self.token_role = token_role
        from src.redteam.core import jwt as core_jwt
        self.token = core_jwt.load(manifest.token_path(token_role))
        core_jwt.assert_format(
            self.token,
            manifest.auth["jwt"]["expected_keys"],
            token_label=f"token[{token_role}]",
        )
        ttl = core_jwt.time_to_expiry(self.token, manifest.auth["jwt"].get("expiry_key", "exp"))
        if ttl is not None and ttl <= 0:
            raise ValueError(
                f"token[{token_role}] expired {-ttl:.0f}s ago. Refresh it before probing."
            )
        self.claims = core_jwt.decode(self.token)
        self._client = None

    # ---- accessors ----

    @property
    def client(self):
        """Lazy-initialise the manifest-driven HTTP client."""
        if self._client is None:
            from src.redteam.core.client import Client
            self._client = Client(self.manifest, self.token)
        return self._client

    def vars(self, **extra: Any) -> dict[str, Any]:
        """Default placeholder values for URL rendering: JWT claims + extras."""
        base = dict(self.claims)
        base.update(extra)
        return base

    # ---- workflow hooks (override per target as needed) ----

    def create_session(self, **extra_body: Any) -> SessionRef:
        """Default: POST manifest's session_create endpoint, expect
        ``{"data": {"session_id": "..."}}`` response. Override if the response
        shape differs."""
        body = self.manifest.body_template("session_create")
        if extra_body and isinstance(body, dict):
            body.update(extra_body)
        resp = self.client.request("session_create", vars=self.vars(), json_body=body)
        if resp.status_code != 200:
            raise RuntimeError(
                f"session_create returned HTTP {resp.status_code}: {resp.text[:300]}"
            )
        data = resp.json().get("data") or {}
        sid = data.get("session_id")
        if not sid:
            raise RuntimeError(f"session_create response missing session_id: {data}")
        return SessionRef(session_id=sid, extra=data)

    def chat(
        self,
        session_ref: SessionRef,
        query: str,
        *,
        drain_seconds: int = 120,
        byte_cap: int = 2_000_000,
        extra_body: Optional[Mapping[str, Any]] = None,
    ) -> SSEResponse:
        """Default: render manifest's chat endpoint body_template with
        ``{{ query }}`` substituted; stream SSE.

        Override if the target needs custom body construction (e.g. OrbitShift
        sets ``askos: true``)."""
        body = _render_template(self.manifest.body_template("chat") or {}, query=query)
        if extra_body:
            body.update(extra_body)
        return self.client.drain(
            "chat",
            vars=self.vars(session_id=session_ref.session_id,
                          parent_session_id=session_ref.parent_session_id),
            json_body=body,
            drain_seconds=drain_seconds,
            byte_cap=byte_cap,
        )

    def plant_canary(self, marker: str, file_name: str) -> CanaryRef:
        """Override in target adapters that need a canary plant flow.

        The reference implementation is OrbitShiftAdapter.plant_canary.
        """
        raise NotImplementedError(
            f"plant_canary not implemented for target {self.manifest.name!r}. "
            f"Override TargetAdapter.plant_canary in src/redteam/targets/<target>.py "
            f"if you need cross-tenant canary probes."
        )

    def cleanup(self) -> None:
        """Override if the target requires cleanup (e.g. restore poisoned
        user-pref fields). Default is a no-op."""
        return None


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

_PLACEHOLDER = re.compile(r"\{\{\s*([\w.]+)\s*\}\}")


def _render_template(obj: Any, **vars: Any) -> Any:
    """Recursively substitute ``{{ name }}`` placeholders in any string leaves of
    `obj` with values from `vars`. Returns a fresh structure."""
    if isinstance(obj, str):
        def sub(m):
            key = m.group(1)
            return str(vars.get(key, m.group(0)))
        return _PLACEHOLDER.sub(sub, obj)
    if isinstance(obj, list):
        return [_render_template(x, **vars) for x in obj]
    if isinstance(obj, dict):
        return {k: _render_template(v, **vars) for k, v in obj.items()}
    return obj
