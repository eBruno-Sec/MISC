from __future__ import annotations

from pydantic import Field

from .common import (
    BaseContract,
    Sensitivity,
    TimestampTZ,
    UUIDv7,
)


class ArtifactRef(BaseContract):
    digest: str
    size: int = Field(ge=0)
    media_type: str
    storage_uri: str


class CaptureMetadata(BaseContract):
    tool: str
    tool_version: str
    captured_at: TimestampTZ
    duration_ms: int | None = Field(default=None, ge=0)
    hostname: str | None = None
    runner_id: str | None = None


class RedactionInfo(BaseContract):
    applied: bool = False
    strategy: str | None = None
    fields_redacted: list[str] = Field(default_factory=list)
    redaction_digest: str | None = None


class LineageEntry(BaseContract):
    parent_evidence_id: UUIDv7
    relationship: str


class RetentionPolicy(BaseContract):
    retain_until: TimestampTZ | None = None
    policy_ref: str | None = None
    auto_delete: bool = False


class EvidenceEnvelope(BaseContract):
    evidence_id: UUIDv7
    tenant_id: UUIDv7
    engagement_revision_id: UUIDv7
    action_id: UUIDv7
    kind: str
    artifact: ArtifactRef
    capture: CaptureMetadata
    redaction: RedactionInfo = Field(default_factory=RedactionInfo)
    lineage: list[LineageEntry] = Field(default_factory=list)
    sensitivity: Sensitivity = Sensitivity.restricted
    retention_policy: RetentionPolicy = Field(default_factory=RetentionPolicy)
    signature: str
