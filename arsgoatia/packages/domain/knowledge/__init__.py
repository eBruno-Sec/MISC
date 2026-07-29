from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import datetime
from uuid import UUID


class AssetType(enum.Enum):
    HOST = "host"
    WEB_APPLICATION = "web_application"
    API = "api"
    SERVICE = "service"
    REPOSITORY = "repository"
    CLOUD_ACCOUNT = "cloud_account"
    CONTAINER = "container"
    KUBERNETES_CLUSTER = "kubernetes_cluster"
    IDENTITY_PROVIDER = "identity_provider"
    AI_ENDPOINT = "ai_endpoint"
    NETWORK_SEGMENT = "network_segment"


class OwnershipConfidence(enum.Enum):
    CONFIRMED = "confirmed"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    CANDIDATE = "candidate"
    CONTRADICTED = "contradicted"


class ProvenanceClass(enum.Enum):
    OBSERVED = "observed"
    INFERRED = "inferred"
    ASSERTED = "asserted"
    CONFIRMED = "confirmed"


@dataclass(frozen=True)
class AssetRecord:
    id: UUID
    tenant_id: UUID
    engagement_id: UUID
    asset_type: AssetType
    canonical_name: str
    ownership_confidence: OwnershipConfidence = OwnershipConfidence.CANDIDATE
    locators: list[str] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)


@dataclass(frozen=True)
class ServiceRecord:
    id: UUID
    tenant_id: UUID
    asset_id: UUID
    protocol: str
    port: int
    name: str | None = None
    version: str | None = None
    technologies: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class EndpointRecord:
    id: UUID
    tenant_id: UUID
    service_id: UUID
    method: str
    path: str
    parameters: list[str] = field(default_factory=list)
    content_type: str | None = None
    authentication_required: bool | None = None


@dataclass(frozen=True)
class ObservationRecord:
    id: UUID
    tenant_id: UUID
    engagement_id: UUID
    observation_type: str
    value: dict
    provenance: ProvenanceClass
    valid_time: datetime | None = None
    observed_time: datetime | None = None
    confidence: float = 1.0
    evidence_refs: list[str] = field(default_factory=list)
    retracted: bool = False
    retracted_reason: str | None = None


def merge_assets(primary: AssetRecord, secondary: AssetRecord) -> AssetRecord:
    merged_locators = list(set(primary.locators) | set(secondary.locators))
    merged_metadata = {**secondary.metadata, **primary.metadata}
    return AssetRecord(
        id=primary.id,
        tenant_id=primary.tenant_id,
        engagement_id=primary.engagement_id,
        asset_type=primary.asset_type,
        canonical_name=primary.canonical_name,
        ownership_confidence=primary.ownership_confidence,
        locators=merged_locators,
        metadata=merged_metadata,
    )
