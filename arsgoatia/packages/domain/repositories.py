"""Tenant-scoped control-plane repository operations.

All writes flow through here so revision/append-only rules hold above the DB as
well as inside it. RLS is set on the session by the caller (deps.set_tenant), so
these functions never take tenant filters in WHERE clauses — the policy enforces
isolation.

Pure helpers (revision numbering, lab-safe policy rules) are separated so they
are unit-testable without a database.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from domain.models import (
    AccessContext,
    Assessment,
    AssessmentRevision,
    Asset,
    AuthorizationRecord,
    CredentialReference,
    Endpoint,
    Evidence,
    Identity,
    Policy,
    PolicyRevision,
    ScopeDefinition,
    ScopeTarget,
    Service,
    Session,
)


# --------------------------------------------------------------------------- #
# Pure helpers (no I/O)
# --------------------------------------------------------------------------- #
def next_revision_number(existing_max: int | None) -> int:
    return 1 if existing_max is None else existing_max + 1


def default_lab_safe_rules() -> dict[str, Any]:
    """The lab-safe risk-class → decision matrix (§13.2/§13.3).

    R2 (the IDOR differential's default) maps to require_approval so the slice
    exercises the action-bound HITL gate; mutation and high-impact are denied.
    """
    return {
        "profile": "lab-safe",
        "risk_class_decisions": {
            "R0": "allow_with_limits",
            "R1": "allow_with_limits",
            "R2": "require_approval",
            "R3": "require_approval",
            "R4": "deny",
            "R5": "deny",
        },
        "required_approval_class": {"R2": "normal", "R3": "elevated"},
        "limits": {
            "max_requests": 500,
            "max_rps": 2,
            "max_concurrency": 4,
            "max_runtime_seconds": 1800,
            "max_mutations": 0,
            "allowed_methods": ["GET", "HEAD", "POST"],
        },
        "cleanup_required": False,
    }


# --------------------------------------------------------------------------- #
# Operations (require a session with RLS tenant set)
# --------------------------------------------------------------------------- #
async def create_assessment(
    session: AsyncSession, *, tenant_id: str, name: str, assessment_types: list[str]
) -> Assessment:
    row = Assessment(
        tenant_id=tenant_id,
        name=name,
        assessment_types=assessment_types,
        lifecycle_state="DRAFT",
    )
    session.add(row)
    await session.flush()
    return row


async def get_assessment(session: AsyncSession, assessment_id: str) -> Assessment | None:
    return await session.get(Assessment, assessment_id)


async def record_authorization(
    session: AsyncSession,
    *,
    tenant_id: str,
    assessment_id: str,
    authorizing_party: str,
    authorized_testing_types: list[str],
    valid_from: datetime,
    valid_until: datetime,
    artifact_ref: str | None = None,
    artifact_hash: str | None = None,
) -> AuthorizationRecord:
    record = AuthorizationRecord(
        tenant_id=tenant_id,
        assessment_id=assessment_id,
        authorizing_party=authorizing_party,
        authorized_testing_types=authorized_testing_types,
        valid_from=valid_from,
        valid_until=valid_until,
        artifact_ref=artifact_ref,
        artifact_hash=artifact_hash,
        verification_state="verified",
    )
    session.add(record)
    assessment = await session.get(Assessment, assessment_id)
    if assessment is not None:
        assessment.lifecycle_state = "AUTHORIZATION_VALIDATED"
    await session.flush()
    return record


async def ensure_lab_safe_policy(
    session: AsyncSession, *, tenant_id: str, assessment_id: str
) -> PolicyRevision:
    policy = Policy(tenant_id=tenant_id, assessment_id=assessment_id, profile="lab-safe")
    session.add(policy)
    await session.flush()
    rev = PolicyRevision(
        tenant_id=tenant_id,
        policy_id=policy.id,
        revision_number=1,
        profile="lab-safe",
        rules=default_lab_safe_rules(),
    )
    session.add(rev)
    await session.flush()
    policy.current_revision_id = rev.id
    return rev


async def compile_scope(
    session: AsyncSession,
    *,
    tenant_id: str,
    assessment_id: str,
    targets: list[dict[str, Any]],
    third_party_policy: dict | None = None,
    resolution_policy: dict | None = None,
    environment_classification: dict | None = None,
) -> AssessmentRevision:
    """Persist scope, a lab-safe policy revision, and the immutable assessment
    revision that binds authorization + scope + policy, then mark SCOPE_COMPILED."""
    scope = ScopeDefinition(
        tenant_id=tenant_id,
        assessment_id=assessment_id,
        third_party_policy=third_party_policy or {"default": "deny", "exceptions": []},
        resolution_policy=resolution_policy
        or {
            "follow_dns": True,
            "pin_resolved_addresses": True,
            "recheck_redirects": True,
            "reject_resolution_drift": True,
        },
        environment_classification=environment_classification or {"default": "lab"},
    )
    session.add(scope)
    await session.flush()
    for t in targets:
        session.add(
            ScopeTarget(
                tenant_id=tenant_id,
                scope_definition_id=scope.id,
                kind=t.get("kind", "hostname"),
                value=t["value"],
                disposition=t.get("disposition", "include"),
                constraints=t.get("constraints", {}),
                environment_classification=t.get("environment_classification", "lab"),
            )
        )

    policy_rev = await ensure_lab_safe_policy(
        session, tenant_id=tenant_id, assessment_id=assessment_id
    )

    auth = (
        await session.execute(
            select(AuthorizationRecord.id)
            .where(AuthorizationRecord.assessment_id == assessment_id)
            .order_by(AuthorizationRecord.created_at.desc())
            .limit(1)
        )
    ).scalar_one_or_none()

    existing_max = (
        await session.execute(
            select(func.max(AssessmentRevision.revision_number)).where(
                AssessmentRevision.assessment_id == assessment_id
            )
        )
    ).scalar_one_or_none()

    revision = AssessmentRevision(
        tenant_id=tenant_id,
        assessment_id=assessment_id,
        revision_number=next_revision_number(existing_max),
        authorization_record_id=auth,
        scope_definition_id=scope.id,
        policy_revision_id=policy_rev.id,
    )
    session.add(revision)
    await session.flush()

    assessment = await session.get(Assessment, assessment_id)
    if assessment is not None:
        assessment.current_revision_id = revision.id
        assessment.current_policy_revision_id = policy_rev.id
        assessment.lifecycle_state = "SCOPE_COMPILED"
    await session.flush()
    return revision


async def set_workflow_handle(
    session: AsyncSession, *, assessment_id: str, workflow_id: str, run_id: str | None
) -> None:
    assessment = await session.get(Assessment, assessment_id)
    if assessment is not None:
        assessment.temporal_workflow_id = workflow_id
        assessment.temporal_run_id = run_id
    await session.flush()


# --------------------------------------------------------------------------- #
# Recon persistence (M2)
# --------------------------------------------------------------------------- #
async def get_scope_targets(session: AsyncSession, assessment_id: str) -> list[dict]:
    """Return the current scope targets for an assessment as firewall-ready dicts."""
    scope_id = (
        await session.execute(
            select(ScopeDefinition.id)
            .where(ScopeDefinition.assessment_id == assessment_id)
            .order_by(ScopeDefinition.created_at.desc())
            .limit(1)
        )
    ).scalar_one_or_none()
    if scope_id is None:
        return []
    rows = (
        (
            await session.execute(
                select(ScopeTarget).where(ScopeTarget.scope_definition_id == scope_id)
            )
        )
        .scalars()
        .all()
    )
    return [
        {"value": r.value, "disposition": r.disposition, "constraints": r.constraints}
        for r in rows
    ]


async def list_assets(session: AsyncSession, assessment_id: str) -> list[Asset]:
    return list(
        (
            await session.execute(select(Asset).where(Asset.assessment_id == assessment_id))
        )
        .scalars()
        .all()
    )


async def list_endpoints(session: AsyncSession, assessment_id: str) -> list[Endpoint]:
    asset_ids = [a.id for a in await list_assets(session, assessment_id)]
    if not asset_ids:
        return []
    return list(
        (await session.execute(select(Endpoint).where(Endpoint.asset_id.in_(asset_ids))))
        .scalars()
        .all()
    )


async def list_evidence(session: AsyncSession, assessment_id: str) -> list[Evidence]:
    return list(
        (
            await session.execute(select(Evidence).where(Evidence.assessment_id == assessment_id))
        )
        .scalars()
        .all()
    )


async def create_asset(
    session: AsyncSession,
    *,
    tenant_id: str,
    assessment_id: str,
    asset_type: str,
    canonical_name: str,
    scope_status: str = "in_scope",
    identifiers: dict | None = None,
    evidence_refs: list | None = None,
) -> Asset:
    row = Asset(
        tenant_id=tenant_id,
        assessment_id=assessment_id,
        asset_type=asset_type,
        canonical_name=canonical_name,
        scope_status=scope_status,
        identifiers=identifiers or {},
        assertion_state="observed",
        evidence_refs=evidence_refs or [],
    )
    session.add(row)
    await session.flush()
    return row


async def create_service(
    session: AsyncSession, *, tenant_id: str, asset_id: str, protocol: str, port: int | None
) -> Service:
    row = Service(
        tenant_id=tenant_id, asset_id=asset_id, protocol=protocol, port=port, state="open"
    )
    session.add(row)
    await session.flush()
    return row


async def create_endpoint(
    session: AsyncSession,
    *,
    tenant_id: str,
    asset_id: str,
    host: str,
    path_template: str,
    method: str | None,
    protocol: str = "https",
    service_id: str | None = None,
    auth_schemes: list | None = None,
    evidence_refs: list | None = None,
) -> Endpoint:
    row = Endpoint(
        tenant_id=tenant_id,
        asset_id=asset_id,
        service_id=service_id,
        host=host,
        path_template=path_template,
        method=method,
        protocol=protocol,
        auth_schemes=auth_schemes or [],
        evidence_refs=evidence_refs or [],
    )
    session.add(row)
    await session.flush()
    return row


async def create_evidence(session: AsyncSession, *, tenant_id: str, fields: dict) -> Evidence:
    """Persist an Evidence row from an EvidenceStore.put() result."""
    row = Evidence(
        id=fields["id"],
        tenant_id=tenant_id,
        assessment_id=fields["assessment_id"],
        evidence_type=fields["evidence_type"],
        object_uri=fields["object_uri"],
        sha256=fields["sha256"],
        size_bytes=fields["size_bytes"],
        media_type=fields["media_type"],
        captured_by=fields["captured_by"],
        source_execution_id=fields.get("source_execution_id"),
        redaction_state=fields.get("redaction_state", "redacted"),
        sensitivity=fields.get("sensitivity", "confidential"),
        meta=fields.get("metadata", {}),
    )
    session.add(row)
    await session.flush()
    return row


# --------------------------------------------------------------------------- #
# Identity / access (M3)
# --------------------------------------------------------------------------- #
async def create_identity(
    session: AsyncSession,
    *,
    tenant_id: str,
    assessment_id: str,
    principal: str,
    privilege_label: str = "standard_user",
    identity_type: str = "human_user",
    authority: str = "",
) -> Identity:
    row = Identity(
        tenant_id=tenant_id,
        assessment_id=assessment_id,
        identity_type=identity_type,
        principal=principal,
        authority=authority,
        privilege_label=privilege_label,
        state="validated",
    )
    session.add(row)
    await session.flush()
    return row


async def create_credential_reference(
    session: AsyncSession,
    *,
    tenant_id: str,
    assessment_id: str,
    identity_id: str,
    secret_uri: str,
    fingerprint: str,
    credential_type: str = "jwt",
) -> CredentialReference:
    row = CredentialReference(
        tenant_id=tenant_id,
        assessment_id=assessment_id,
        identity_id=identity_id,
        credential_type=credential_type,
        secret_uri=secret_uri,
        fingerprint=fingerprint,
        state="verified",
    )
    session.add(row)
    await session.flush()
    return row


async def create_session(
    session: AsyncSession,
    *,
    tenant_id: str,
    assessment_id: str,
    identity_id: str,
    target_asset_id: str | None,
    credential_reference_id: str,
    session_type: str = "api",
    privilege_label: str = "standard_user",
) -> Session:
    row = Session(
        tenant_id=tenant_id,
        assessment_id=assessment_id,
        identity_id=identity_id,
        target_asset_id=target_asset_id,
        credential_reference_id=credential_reference_id,
        session_type=session_type,
        privilege_label=privilege_label,
        state="active",
    )
    session.add(row)
    await session.flush()
    return row


async def create_access_context(
    session: AsyncSession,
    *,
    tenant_id: str,
    assessment_id: str,
    identity_id: str,
    session_id: str,
    credential_reference_ids: list[str],
    privilege_label: str = "standard_user",
) -> AccessContext:
    row = AccessContext(
        tenant_id=tenant_id,
        assessment_id=assessment_id,
        identity_id=identity_id,
        session_id=session_id,
        credential_reference_ids=credential_reference_ids,
        privilege_label=privilege_label,
        state="active",
    )
    session.add(row)
    await session.flush()
    return row
