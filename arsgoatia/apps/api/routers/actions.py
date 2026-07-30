"""Action proposal + approval endpoints."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Annotated
from uuid import UUID, uuid4

from fastapi import APIRouter, Header, HTTPException, Query, status
from pydantic import BaseModel, Field

from apps.api import temporal as temporal_client
from apps.api.deps import AuthCtx, DbSession, TenantId
from packages.persistence import repos

router = APIRouter(tags=["actions"])


class ActionSummary(BaseModel):
    id: UUID
    engagement_id: UUID
    state: str
    technique_id: str
    target: str
    risk_tier: str
    mutation_class: str
    created_at: datetime


class ActionListResponse(BaseModel):
    items: list[ActionSummary]
    total: int
    offset: int
    limit: int


class ProposeActionRequest(BaseModel):
    engagement_id: UUID
    technique: str = Field(min_length=1)
    target: str = Field(min_length=1)
    parameters: dict[str, object] = Field(default_factory=dict)
    risk_tier: str = Field(default="R0")
    mutation_class: str = Field(default="none")
    access_context_ids: list[UUID] = Field(default_factory=list)


class PolicyEvaluation(BaseModel):
    decision: str
    risk_tier: str
    reason: str
    layers_evaluated: list[str] = Field(default_factory=list)


class ActionProposal(BaseModel):
    id: UUID
    engagement_id: UUID
    technique: str
    target: str
    state: str
    risk_tier: str
    mutation_class: str
    policy_evaluation: PolicyEvaluation
    parameters_digest: str
    created_at: datetime


class ApproveActionRequest(BaseModel):
    reason: str = Field(default="", max_length=2000)


class ApprovalResponse(BaseModel):
    id: UUID
    action_id: UUID
    state: str
    approved_by: str
    approved_at: datetime
    binding_digest: str


class RejectActionRequest(BaseModel):
    reason: str = Field(min_length=1, max_length=2000)


class RejectionResponse(BaseModel):
    id: UUID
    state: str
    rejected_by: str
    rejected_at: datetime
    reason: str


def _evaluate_policy(risk_tier: str, mutation_class: str) -> PolicyEvaluation:
    """Minimal deterministic policy pass (mirrors packages/policy invariants).

    R0/R1 → allow, R2 → allow but requires approval, R3/R4 → require approval,
    R5 → always deny. Real engine lives in packages/policy; this is the API-side
    surface that decides initial action state.
    """
    if risk_tier == "R5":
        return PolicyEvaluation(
            decision="deny",
            risk_tier=risk_tier,
            reason="R5 destructive actions are always denied",
            layers_evaluated=["risk_tier"],
        )
    if risk_tier in ("R3", "R4"):
        return PolicyEvaluation(
            decision="require_approval",
            risk_tier=risk_tier,
            reason=f"{risk_tier} actions require operator approval",
            layers_evaluated=["risk_tier", "mutation_class"],
        )
    if risk_tier == "R2":
        return PolicyEvaluation(
            decision="require_approval",
            risk_tier=risk_tier,
            reason="R2 bounded-active actions gated on rules",
            layers_evaluated=["risk_tier", "mutation_class"],
        )
    return PolicyEvaluation(
        decision="allow",
        risk_tier=risk_tier,
        reason=f"{risk_tier} auto-allowed by default policy",
        layers_evaluated=["risk_tier"],
    )


@router.get(
    "/actions",
    response_model=ActionListResponse,
    summary="List action proposals",
)
async def list_actions(
    tenant_id: TenantId,
    session: DbSession,
    auth: AuthCtx,
    engagement_id: UUID | None = Query(default=None),
    state: str | None = Query(default=None),
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=100, ge=1, le=500),
):
    rows, total = await repos.list_actions(
        session,
        engagement_id=engagement_id,
        state=state,
        offset=offset,
        limit=limit,
    )
    return ActionListResponse(
        items=[ActionSummary(**r) for r in rows],
        total=total,
        offset=offset,
        limit=limit,
    )


@router.get(
    "/approvals/pending",
    response_model=ActionListResponse,
    summary="List actions waiting for approval (R2+ pending)",
)
async def list_pending_approvals(
    tenant_id: TenantId,
    session: DbSession,
    auth: AuthCtx,
    engagement_id: UUID | None = Query(default=None),
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=100, ge=1, le=500),
):
    rows, total = await repos.list_actions(
        session,
        engagement_id=engagement_id,
        state="APPROVAL_REQUIRED",
        offset=offset,
        limit=limit,
    )
    return ActionListResponse(
        items=[ActionSummary(**r) for r in rows],
        total=total,
        offset=offset,
        limit=limit,
    )


@router.post(
    "/actions:propose",
    response_model=ActionProposal,
    status_code=status.HTTP_201_CREATED,
    summary="Create a policy-evaluated action proposal",
)
async def propose_action(
    body: ProposeActionRequest,
    tenant_id: TenantId,
    session: DbSession,
    auth: AuthCtx,
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
):
    policy = _evaluate_policy(body.risk_tier, body.mutation_class)
    if policy.decision == "deny":
        raise HTTPException(status_code=403, detail=policy.reason)

    initial_state = "APPROVAL_REQUIRED" if policy.decision == "require_approval" else "PROPOSED"

    row = await repos.create_action_proposal(
        session,
        tenant_id=tenant_id,
        engagement_id=body.engagement_id,
        technique_id=body.technique,
        target=body.target,
        risk_tier=body.risk_tier,
        mutation_class=body.mutation_class,
        parameters=body.parameters,
        initial_state=initial_state,
    )
    await repos.record_audit_event(
        session,
        tenant_id=tenant_id,
        event_type="action.proposed",
        actor_id=auth["user"],
        engagement_id=body.engagement_id,
        payload={"action_id": str(row["id"]), "risk_tier": body.risk_tier, "decision": policy.decision},
    )
    return ActionProposal(
        id=row["id"],
        engagement_id=body.engagement_id,
        technique=body.technique,
        target=body.target,
        state=row["state"],
        risk_tier=body.risk_tier,
        mutation_class=body.mutation_class,
        policy_evaluation=policy,
        parameters_digest=row["parameters_digest"],
        created_at=row["created_at"],
    )


@router.post(
    "/actions/{action_id}:approve",
    response_model=ApprovalResponse,
    summary="Approve action with signed binding",
)
async def approve_action(
    action_id: UUID,
    body: ApproveActionRequest,
    tenant_id: TenantId,
    session: DbSession,
    auth: AuthCtx,
):
    action = await repos.get_action(session, action_id)
    if not action:
        raise HTTPException(status_code=404, detail="Action not found")
    if action["state"] not in ("APPROVAL_REQUIRED", "PROPOSED"):
        raise HTTPException(status_code=409, detail=f"Action in state {action['state']} cannot be approved")

    approval = await repos.create_approval(
        session,
        tenant_id=tenant_id,
        engagement_id=action["engagement_id"],
        action_id=action_id,
        approver_id=uuid4(),
        decision="approve",
        reason=body.reason,
    )
    await repos.update_action_state(session, action_id, state="APPROVED")

    # Signal the running EngagementWorkflow so it can consume the approval.
    try:
        await temporal_client.signal_engagement(
            str(action["engagement_id"]),
            "provide_approval",
            str(action_id),
            approval["binding_digest"],
        )
    except Exception:
        pass

    await repos.record_audit_event(
        session,
        tenant_id=tenant_id,
        event_type="action.approved",
        actor_id=auth["user"],
        engagement_id=action["engagement_id"],
        payload={"action_id": str(action_id), "binding_digest": approval["binding_digest"]},
    )

    return ApprovalResponse(
        id=approval["id"],
        action_id=action_id,
        state="APPROVED",
        approved_by=auth["user"],
        approved_at=approval["created_at"],
        binding_digest=approval["binding_digest"],
    )


@router.post(
    "/actions/{action_id}:reject",
    response_model=RejectionResponse,
    summary="Reject a proposed action",
)
async def reject_action(
    action_id: UUID,
    body: RejectActionRequest,
    tenant_id: TenantId,
    session: DbSession,
    auth: AuthCtx,
):
    action = await repos.get_action(session, action_id)
    if not action:
        raise HTTPException(status_code=404, detail="Action not found")

    approval = await repos.create_approval(
        session,
        tenant_id=tenant_id,
        engagement_id=action["engagement_id"],
        action_id=action_id,
        approver_id=uuid4(),
        decision="reject",
        reason=body.reason,
    )
    await repos.update_action_state(session, action_id, state="REJECTED")
    await repos.record_audit_event(
        session,
        tenant_id=tenant_id,
        event_type="action.rejected",
        actor_id=auth["user"],
        engagement_id=action["engagement_id"],
        payload={"action_id": str(action_id), "reason": body.reason},
    )

    return RejectionResponse(
        id=approval["id"],
        state="REJECTED",
        rejected_by=auth["user"],
        rejected_at=approval["created_at"],
        reason=body.reason,
    )
