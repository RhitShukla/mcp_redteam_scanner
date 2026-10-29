"""
Shared data models for MCP Red Team system.
All inter-layer communication uses these Pydantic models.

Layer mapping: Shared contract layer — imported by all three layers.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


# ── Enums ──


class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


class Fixability(str, Enum):
    CONFIGURATION = "Configuration"
    DESIGN = "Design"
    ARCHITECTURAL = "Architectural"


class EvidenceType(str, Enum):
    TOOL_INVOCATION = "tool_invocation"
    RESOURCE_READ = "resource_read"
    PROMPT_RESPONSE = "prompt_response"
    CONNECTION_ATTEMPT = "connection_attempt"


class TransportType(str, Enum):
    SSE = "sse"
    STREAMABLE_HTTP = "streamable_http"


class AuthMethod(str, Enum):
    NONE = "none"
    BEARER_TOKEN = "bearer_token"
    API_KEY = "api_key"
    BASIC = "basic"


# ── Trace Models (Layer 1 produces these) ──


class TraceEntry(BaseModel):
    """Single MCP request/response pair. Produced exclusively by the probe engine."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    session_id: str
    method: str  # e.g. "tools/call", "resources/read", "prompts/get"
    request: dict[str, Any]  # exact MCP JSON-RPC request params
    response: dict[str, Any] | None = None  # None if call failed
    error: str | None = None
    duration_ms: float | None = None


class SessionInfo(BaseModel):
    """Metadata about an MCP session. Needed for trace replay."""

    session_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    endpoint_url: str
    transport: TransportType
    auth_method: AuthMethod
    auth_identity: str | None = None  # e.g. "tenant-alpha"
    connected_at: datetime | None = None
    disconnected_at: datetime | None = None
    server_capabilities: dict[str, Any] = Field(default_factory=dict)


# ── Evidence Models (Layer 2 attaches these to Findings) ──


class Evidence(BaseModel):
    """A single piece of evidence tied to a finding. References trace entries."""

    type: EvidenceType
    request: dict[str, Any]
    response: dict[str, Any] | None = None
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    trace_entry_id: str | None = None  # links back to TraceEntry.id


class ReplayInfo(BaseModel):
    """How to reproduce this finding."""

    command: str
    trace_file: str


# ── Finding Model (Layer 2 produces, Layer 3 consumes) ──


class Finding(BaseModel):
    """
    Mandatory schema for every finding. Validated before entering the report.
    ID format: {surface_letter}{module_number}-{sequence}, e.g. D1-001
    """

    id: str
    title: str
    surface: str  # e.g. "D - Data Flow & Exfiltration"
    module: str  # e.g. "D1 - Sensitive data in tool responses"
    severity: Severity
    fixability: Fixability
    fixability_rationale: str
    description: str
    attack_narrative: str  # step-by-step, numbered
    evidence: list[Evidence]
    replay: ReplayInfo
    recommendation: str


# ── Config Models ──


class TenantCredential(BaseModel):
    token: str
    identifier: str


class CrossTenantConfig(BaseModel):
    enabled: bool = False
    tenant_a: TenantCredential | None = None
    tenant_b: TenantCredential | None = None


class TargetConfig(BaseModel):
    """Top-level configuration for a red team run."""

    endpoint_url: str
    transport: TransportType = TransportType.SSE
    auth_method: AuthMethod = AuthMethod.BEARER_TOKEN
    auth_token: str | None = None
    cross_tenant: CrossTenantConfig = Field(default_factory=CrossTenantConfig)
    output_dir: str = "./output"


# ── Trace File Model (for replay) ──


class TraceFile(BaseModel):
    """Self-contained trace for replay. One per finding."""

    session: SessionInfo
    entries: list[TraceEntry]
    finding_id: str
