"""Async raw-SQL repositories for the ArsGoatia API.

These are deliberately tiny — one file, one function per operation. They
target the tables defined in migration 0001 directly, so there is no ORM/
migration drift risk. Every mutation happens under RLS, which means the
caller must have already set ``app.tenant_id`` on the session.
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession


# ---------------------------------------------------------------------------
# Small helper — every row we return is a plain dict, ready for JSON.
# ---------------------------------------------------------------------------
def _row(m) -> dict[str, Any]:
    return dict(m._mapping) if m is not None else None  # type: ignore[return-value]


# ---------------------------------------------------------------------------
# Engagements
# ---------------------------------------------------------------------------
async def create_engagement(
    session: AsyncSession,
    *,
    tenant_id: UUID,
    name: str,
    spec: dict[str, Any],
    created_by: str,
) -> dict[str, Any]:
    engagement_id = uuid.uuid4()
    now = datetime.now(timezone.utc)

    await session.execute(
        text(
            """
            INSERT INTO governance.engagement
                (id, tenant_id, name, lifecycle_state, created_at, updated_at)
            VALUES
                (:id, :tid, :name, 'DRAFT', :now, :now)
            """
        ),
        {"id": engagement_id, "tid": tenant_id, "name": name, "now": now},
    )

    # Also stamp an initial revision so we always have a compiled spec on record.
    rev_id = uuid.uuid4()
    rev_num = 1
    content_digest = "sha256:" + _digest(spec)
    await session.execute(
        text(
            """
            INSERT INTO governance.engagement_revision
                (id, tenant_id, engagement_id, revision_number, content_digest, spec, created_at, created_by)
            VALUES
                (:id, :tid, :eid, :rn, :dg, CAST(:spec AS jsonb), :now, :who)
            """
        ),
        {
            "id": rev_id,
            "tid": tenant_id,
            "eid": engagement_id,
            "rn": rev_num,
            "dg": content_digest,
            "spec": json.dumps(spec),
            "now": now,
            "who": created_by,
        },
    )
    await session.execute(
        text(
            "UPDATE governance.engagement SET current_revision_id = :rev WHERE id = :id"
        ),
        {"rev": rev_id, "id": engagement_id},
    )

    return {
        "id": engagement_id,
        "tenant_id": tenant_id,
        "name": name,
        "lifecycle_state": "DRAFT",
        "current_revision_id": rev_id,
        "current_revision_number": rev_num,
        "content_digest": content_digest,
        "spec": spec,
        "created_at": now,
        "updated_at": now,
    }


async def get_engagement(session: AsyncSession, engagement_id: UUID) -> dict[str, Any] | None:
    r = (
        await session.execute(
            text(
                """
                SELECT e.id, e.tenant_id, e.name, e.lifecycle_state,
                       e.current_revision_id, e.temporal_workflow_id, e.temporal_run_id,
                       e.created_at, e.updated_at,
                       r.revision_number, r.content_digest, r.spec
                FROM governance.engagement e
                LEFT JOIN governance.engagement_revision r
                       ON r.id = e.current_revision_id
                WHERE e.id = :id
                """
            ),
            {"id": engagement_id},
        )
    ).first()
    return _row(r)


async def list_engagements(
    session: AsyncSession,
    *,
    offset: int = 0,
    limit: int = 50,
    state: str | None = None,
) -> tuple[list[dict[str, Any]], int]:
    where = ""
    params: dict[str, Any] = {"offset": offset, "limit": limit}
    if state:
        where = "WHERE lifecycle_state = :state"
        params["state"] = state

    rows = (
        await session.execute(
            text(
                f"""
                SELECT id, tenant_id, name, lifecycle_state,
                       temporal_workflow_id, created_at, updated_at
                FROM governance.engagement
                {where}
                ORDER BY created_at DESC
                LIMIT :limit OFFSET :offset
                """
            ),
            params,
        )
    ).all()

    total = (
        await session.execute(
            text(
                f"SELECT COUNT(*) FROM governance.engagement {where}",
            ),
            {k: v for k, v in params.items() if k not in ("offset", "limit")},
        )
    ).scalar_one()

    return [_row(r) for r in rows], int(total)


async def update_engagement_state(
    session: AsyncSession,
    engagement_id: UUID,
    *,
    lifecycle_state: str,
    workflow_id: str | None = None,
    run_id: str | None = None,
) -> None:
    now = datetime.now(timezone.utc)
    if workflow_id is not None:
        await session.execute(
            text(
                """
                UPDATE governance.engagement
                SET lifecycle_state = :st,
                    temporal_workflow_id = :wf,
                    temporal_run_id = :run,
                    updated_at = :now
                WHERE id = :id
                """
            ),
            {"st": lifecycle_state, "wf": workflow_id, "run": run_id, "now": now, "id": engagement_id},
        )
    else:
        await session.execute(
            text(
                "UPDATE governance.engagement SET lifecycle_state = :st, updated_at = :now WHERE id = :id"
            ),
            {"st": lifecycle_state, "now": now, "id": engagement_id},
        )


# ---------------------------------------------------------------------------
# Action proposals
# ---------------------------------------------------------------------------
async def create_action_proposal(
    session: AsyncSession,
    *,
    tenant_id: UUID,
    engagement_id: UUID,
    technique_id: str,
    target: str,
    risk_tier: str,
    mutation_class: str,
    parameters: dict[str, Any],
    hypothesis_id: UUID | None = None,
    initial_state: str = "PROPOSED",
) -> dict[str, Any]:
    action_id = uuid.uuid4()
    now = datetime.now(timezone.utc)
    await session.execute(
        text(
            """
            INSERT INTO reasoning.action_proposal
                (id, tenant_id, engagement_id, hypothesis_id, state,
                 technique_id, target, risk_tier, mutation_class, parameters, created_at)
            VALUES
                (:id, :tid, :eid, :hid, :st, :tech, :tgt, :risk, :mut, CAST(:params AS jsonb), :now)
            """
        ),
        {
            "id": action_id,
            "tid": tenant_id,
            "eid": engagement_id,
            "hid": hypothesis_id,
            "st": initial_state,
            "tech": technique_id,
            "tgt": target,
            "risk": risk_tier,
            "mut": mutation_class,
            "params": json.dumps(parameters),
            "now": now,
        },
    )
    return {
        "id": action_id,
        "tenant_id": tenant_id,
        "engagement_id": engagement_id,
        "state": initial_state,
        "technique_id": technique_id,
        "target": target,
        "risk_tier": risk_tier,
        "mutation_class": mutation_class,
        "parameters": parameters,
        "parameters_digest": "sha256:" + _digest(parameters),
        "created_at": now,
    }


async def get_action(session: AsyncSession, action_id: UUID) -> dict[str, Any] | None:
    r = (
        await session.execute(
            text(
                """
                SELECT id, tenant_id, engagement_id, hypothesis_id, state,
                       technique_id, target, risk_tier, mutation_class, parameters, created_at
                FROM reasoning.action_proposal
                WHERE id = :id
                """
            ),
            {"id": action_id},
        )
    ).first()
    return _row(r)


async def update_action_state(
    session: AsyncSession, action_id: UUID, *, state: str
) -> None:
    await session.execute(
        text("UPDATE reasoning.action_proposal SET state = :st WHERE id = :id"),
        {"st": state, "id": action_id},
    )


# ---------------------------------------------------------------------------
# Approvals
# ---------------------------------------------------------------------------
async def create_approval(
    session: AsyncSession,
    *,
    tenant_id: UUID,
    engagement_id: UUID,
    action_id: UUID,
    approver_id: UUID,
    decision: str,
    reason: str = "",
) -> dict[str, Any]:
    approval_id = uuid.uuid4()
    now = datetime.now(timezone.utc)
    binding_input = f"{action_id}|{approver_id}|{decision}|{now.isoformat()}"
    binding_digest = "sha256:" + _digest(binding_input)
    await session.execute(
        text(
            """
            INSERT INTO governance.approval
                (id, tenant_id, engagement_id, action_id, approver_id, decision, reason, created_at)
            VALUES
                (:id, :tid, :eid, :aid, :who, :dec, :why, :now)
            """
        ),
        {
            "id": approval_id,
            "tid": tenant_id,
            "eid": engagement_id,
            "aid": action_id,
            "who": approver_id,
            "dec": decision,
            "why": reason,
            "now": now,
        },
    )
    return {
        "id": approval_id,
        "decision": decision,
        "created_at": now,
        "binding_digest": binding_digest,
    }


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------
async def list_findings(
    session: AsyncSession,
    *,
    engagement_id: UUID | None = None,
    state: str | None = None,
    offset: int = 0,
    limit: int = 50,
) -> tuple[list[dict[str, Any]], int]:
    where = []
    params: dict[str, Any] = {"offset": offset, "limit": limit}
    if engagement_id:
        where.append("engagement_id = :eid")
        params["eid"] = engagement_id
    if state:
        where.append("state = :state")
        params["state"] = state
    where_clause = ("WHERE " + " AND ".join(where)) if where else ""

    rows = (
        await session.execute(
            text(
                f"""
                SELECT id, tenant_id, engagement_id, state, technique_id, target, title,
                       severity, evidence_refs, capability_refs, created_at, updated_at
                FROM findings.finding
                {where_clause}
                ORDER BY created_at DESC
                LIMIT :limit OFFSET :offset
                """
            ),
            params,
        )
    ).all()
    total = (
        await session.execute(
            text(f"SELECT COUNT(*) FROM findings.finding {where_clause}"),
            {k: v for k, v in params.items() if k not in ("offset", "limit")},
        )
    ).scalar_one()
    return [_row(r) for r in rows], int(total)


async def get_finding(session: AsyncSession, finding_id: UUID) -> dict[str, Any] | None:
    r = (
        await session.execute(
            text(
                """
                SELECT id, tenant_id, engagement_id, state, technique_id, target, title,
                       severity, evidence_refs, capability_refs, created_at, updated_at
                FROM findings.finding
                WHERE id = :id
                """
            ),
            {"id": finding_id},
        )
    ).first()
    return _row(r)


# ---------------------------------------------------------------------------
# Evidence
# ---------------------------------------------------------------------------
async def list_evidence(
    session: AsyncSession,
    *,
    engagement_id: UUID | None = None,
    offset: int = 0,
    limit: int = 100,
) -> tuple[list[dict[str, Any]], int]:
    where = ""
    params: dict[str, Any] = {"offset": offset, "limit": limit}
    if engagement_id:
        where = "WHERE engagement_id = :eid"
        params["eid"] = engagement_id
    rows = (
        await session.execute(
            text(
                f"""
                SELECT id, tenant_id, engagement_id, action_id, kind, digest,
                       size_bytes, media_type, storage_uri, sensitivity, created_at
                FROM evidence.evidence
                {where}
                ORDER BY created_at DESC
                LIMIT :limit OFFSET :offset
                """
            ),
            params,
        )
    ).all()
    total = (
        await session.execute(
            text(f"SELECT COUNT(*) FROM evidence.evidence {where}"),
            {k: v for k, v in params.items() if k not in ("offset", "limit")},
        )
    ).scalar_one()
    return [_row(r) for r in rows], int(total)


async def get_evidence(session: AsyncSession, evidence_id: UUID) -> dict[str, Any] | None:
    r = (
        await session.execute(
            text(
                """
                SELECT id, tenant_id, engagement_id, action_id, kind, digest,
                       size_bytes, media_type, storage_uri, sensitivity, created_at
                FROM evidence.evidence
                WHERE id = :id
                """
            ),
            {"id": evidence_id},
        )
    ).first()
    return _row(r)


# ---------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------
async def list_reports(
    session: AsyncSession,
    *,
    engagement_id: UUID | None = None,
    offset: int = 0,
    limit: int = 50,
) -> tuple[list[dict[str, Any]], int]:
    where = ""
    params: dict[str, Any] = {"offset": offset, "limit": limit}
    if engagement_id:
        where = "WHERE engagement_id = :eid"
        params["eid"] = engagement_id
    rows = (
        await session.execute(
            text(
                f"""
                SELECT id, tenant_id, engagement_id, report_type, format,
                       digest, storage_uri, created_at
                FROM reporting.report
                {where}
                ORDER BY created_at DESC
                LIMIT :limit OFFSET :offset
                """
            ),
            params,
        )
    ).all()
    total = (
        await session.execute(
            text(f"SELECT COUNT(*) FROM reporting.report {where}"),
            {k: v for k, v in params.items() if k not in ("offset", "limit")},
        )
    ).scalar_one()
    return [_row(r) for r in rows], int(total)


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------
async def record_audit_event(
    session: AsyncSession,
    *,
    tenant_id: UUID,
    event_type: str,
    actor_id: str | None = None,
    engagement_id: UUID | None = None,
    payload: dict[str, Any] | None = None,
) -> None:
    await session.execute(
        text(
            """
            INSERT INTO audit.audit_event
                (id, tenant_id, event_type, actor_id, engagement_id, payload, created_at)
            VALUES
                (:id, :tid, :et, :actor, :eid, CAST(:payload AS jsonb), :now)
            """
        ),
        {
            "id": uuid.uuid4(),
            "tid": tenant_id,
            "et": event_type,
            "actor": actor_id,
            "eid": engagement_id,
            "payload": json.dumps(payload or {}),
            "now": datetime.now(timezone.utc),
        },
    )


async def list_audit_events(
    session: AsyncSession,
    *,
    engagement_id: UUID | None = None,
    event_type: str | None = None,
    offset: int = 0,
    limit: int = 100,
) -> tuple[list[dict[str, Any]], int]:
    where = []
    params: dict[str, Any] = {"offset": offset, "limit": limit}
    if engagement_id:
        where.append("engagement_id = :eid")
        params["eid"] = engagement_id
    if event_type:
        where.append("event_type = :et")
        params["et"] = event_type
    where_clause = ("WHERE " + " AND ".join(where)) if where else ""

    rows = (
        await session.execute(
            text(
                f"""
                SELECT id, tenant_id, event_type, actor_id, engagement_id, payload, created_at
                FROM audit.audit_event
                {where_clause}
                ORDER BY created_at DESC
                LIMIT :limit OFFSET :offset
                """
            ),
            params,
        )
    ).all()
    total = (
        await session.execute(
            text(f"SELECT COUNT(*) FROM audit.audit_event {where_clause}"),
            {k: v for k, v in params.items() if k not in ("offset", "limit")},
        )
    ).scalar_one()
    return [_row(r) for r in rows], int(total)


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------
def _digest(obj: Any) -> str:
    import hashlib

    if isinstance(obj, (dict, list)):
        payload = json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()
    elif isinstance(obj, bytes):
        payload = obj
    else:
        payload = str(obj).encode()
    return hashlib.sha256(payload).hexdigest()
