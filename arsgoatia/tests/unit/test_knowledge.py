from __future__ import annotations

from dataclasses import FrozenInstanceError
from uuid import uuid4

import pytest

from packages.domain.knowledge import (
    AssetRecord,
    AssetType,
    EndpointRecord,
    ObservationRecord,
    OwnershipConfidence,
    ProvenanceClass,
    ServiceRecord,
    merge_assets,
)


def test_asset_record_creation_defaults():
    asset = AssetRecord(
        id=uuid4(),
        tenant_id=uuid4(),
        engagement_id=uuid4(),
        asset_type=AssetType.HOST,
        canonical_name="host1.internal.test",
    )
    assert asset.asset_type == AssetType.HOST
    assert asset.ownership_confidence == OwnershipConfidence.CANDIDATE
    assert asset.locators == []
    assert asset.metadata == {}


def test_asset_record_creation_with_locators_and_metadata():
    asset = AssetRecord(
        id=uuid4(),
        tenant_id=uuid4(),
        engagement_id=uuid4(),
        asset_type=AssetType.WEB_APPLICATION,
        canonical_name="app.example.test",
        ownership_confidence=OwnershipConfidence.CONFIRMED,
        locators=["app.example.test", "10.0.0.5"],
        metadata={"framework": "django"},
    )
    assert asset.ownership_confidence == OwnershipConfidence.CONFIRMED
    assert "10.0.0.5" in asset.locators
    assert asset.metadata["framework"] == "django"


def test_asset_record_is_frozen():
    asset = AssetRecord(
        id=uuid4(),
        tenant_id=uuid4(),
        engagement_id=uuid4(),
        asset_type=AssetType.HOST,
        canonical_name="host1.test",
    )
    with pytest.raises(FrozenInstanceError):
        asset.canonical_name = "changed.test"


def test_service_record_creation():
    asset_id = uuid4()
    svc = ServiceRecord(
        id=uuid4(),
        tenant_id=uuid4(),
        asset_id=asset_id,
        protocol="tcp",
        port=443,
        name="https",
        version="1.1",
        technologies=["nginx"],
    )
    assert svc.asset_id == asset_id
    assert svc.port == 443
    assert svc.technologies == ["nginx"]


def test_service_record_optional_fields_default_none():
    svc = ServiceRecord(id=uuid4(), tenant_id=uuid4(), asset_id=uuid4(), protocol="tcp", port=22)
    assert svc.name is None
    assert svc.version is None
    assert svc.technologies == []


def test_endpoint_record_creation():
    service_id = uuid4()
    ep = EndpointRecord(
        id=uuid4(),
        tenant_id=uuid4(),
        service_id=service_id,
        method="POST",
        path="/api/v1/login",
        parameters=["username", "password"],
        content_type="application/json",
        authentication_required=False,
    )
    assert ep.service_id == service_id
    assert ep.method == "POST"
    assert ep.authentication_required is False


def test_observation_record_creation_defaults():
    obs = ObservationRecord(
        id=uuid4(),
        tenant_id=uuid4(),
        engagement_id=uuid4(),
        observation_type="port_open",
        value={"port": 443, "protocol": "tcp"},
        provenance=ProvenanceClass.OBSERVED,
    )
    assert obs.provenance == ProvenanceClass.OBSERVED
    assert obs.confidence == 1.0
    assert obs.retracted is False
    assert obs.evidence_refs == []


def test_observation_record_retracted():
    obs = ObservationRecord(
        id=uuid4(),
        tenant_id=uuid4(),
        engagement_id=uuid4(),
        observation_type="dns_answer",
        value={"a": "1.2.3.4"},
        provenance=ProvenanceClass.INFERRED,
        confidence=0.4,
        retracted=True,
        retracted_reason="stale rebinding answer",
    )
    assert obs.retracted is True
    assert obs.retracted_reason == "stale rebinding answer"
    assert obs.confidence == 0.4


def test_merge_assets_unions_locators():
    tenant_id, engagement_id, asset_id = uuid4(), uuid4(), uuid4()
    primary = AssetRecord(
        id=asset_id,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        asset_type=AssetType.HOST,
        canonical_name="host1.test",
        locators=["1.2.3.4"],
        metadata={"os": "linux"},
    )
    secondary = AssetRecord(
        id=asset_id,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        asset_type=AssetType.HOST,
        canonical_name="host1.test",
        locators=["host1.test"],
        metadata={"owner": "team-a"},
    )
    merged = merge_assets(primary, secondary)
    assert set(merged.locators) == {"1.2.3.4", "host1.test"}


def test_merge_assets_primary_metadata_wins_on_conflict():
    tenant_id, engagement_id, asset_id = uuid4(), uuid4(), uuid4()
    primary = AssetRecord(
        id=asset_id,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        asset_type=AssetType.HOST,
        canonical_name="host1.test",
        metadata={"owner": "primary-owner"},
    )
    secondary = AssetRecord(
        id=asset_id,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        asset_type=AssetType.HOST,
        canonical_name="host1.test",
        metadata={"owner": "secondary-owner", "extra": "kept"},
    )
    merged = merge_assets(primary, secondary)
    assert merged.metadata["owner"] == "primary-owner"
    assert merged.metadata["extra"] == "kept"


def test_merge_assets_preserves_primary_identity_fields():
    tenant_id, engagement_id, asset_id = uuid4(), uuid4(), uuid4()
    primary = AssetRecord(
        id=asset_id,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        asset_type=AssetType.API,
        canonical_name="api.primary.test",
        ownership_confidence=OwnershipConfidence.HIGH,
    )
    secondary = AssetRecord(
        id=asset_id,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        asset_type=AssetType.SERVICE,
        canonical_name="svc.secondary.test",
        ownership_confidence=OwnershipConfidence.LOW,
    )
    merged = merge_assets(primary, secondary)
    assert merged.asset_type == AssetType.API
    assert merged.canonical_name == "api.primary.test"
    assert merged.ownership_confidence == OwnershipConfidence.HIGH
