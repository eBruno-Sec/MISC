"""Action proposal, approval, and execution streaming endpoints."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Annotated
from uuid import UUID, uuid4

from fastapi import APIRouter, Header, HTTPException, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from apps.api.deps import AuthCtx, DbSession, TenantId

router = APIRouter(tags=["actions"])


# -- Request / Response models -------------------------------------------------


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
    expires_at: datetime | None = None


class ApproveActionRequest(BaseModel):
    reason: str = Field(default="", max_length=2000)


class ApprovalResponse(BaseModel):
    id: UUID
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


class CancelActionRequest(BaseModel):
    reason: str = Field(default="", max_length=2000)


class CancellationResponse(BaseModel):
    id: UUID
    state: str
    cancelled_by: str
    cancelled_at: datetime


# -- Endpoints -----------------------------------------------------------------


@router.post(
    "/actions:propose",
    response_model=ActionProposal,
    status_code=status.HTTP_201_CREATED,
    summary="Create a policy-evaluated immutable action proposal",
)
async def propose_action(
    body: ProposeActionRequest,
    tenant_id: TenantId,
    session: DbSession,
    auth: AuthCtx,
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
):
    now = datetime.now(timezone.utc)
    action_id = uuid4()

    # TODO: run policy engine evaluation, compute digests
    policy_eval = PolicyEvaluation(
        decision="allow",
        risk_tier=body.risk_tier,
        reason="Policy evaluation pending implementation",
        layers_evaluated=["engagement", "global"],
    )

    initial_state = "PROPOSED" if policy_eval.decision == "allow" else "APPROVAL_REQUIRED"

    return ActionProposal(
        id=action_id,
        engagement_id=body.engagement_id,
        technique=body.technique,
        target=body.target,
        state=initial_state,
        risk_tier=body.risk_tier,
        mutation_class=body.mutation_class,
        policy_evaluation=policy_eval,
        parameters_digest="sha256:placeholder",
        created_at=now,
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
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
):
    now = datetime.now(timezone.utc)
    # TODO: verify action exists, is in APPROVAL_REQUIRED state, sign binding
    return ApprovalResponse(
        id=action_id,
        state="APPROVED",
        approved_by=auth["user"],
        approved_at=now,
        binding_digest="sha256:placeholder",
    )


@router.post(
    "/actions/{action_id}:reject",
    response_model=RejectionResponse,
    summary="Reject proposed action",
)
async def reject_action(
    action_id: UUID,
    body: RejectActionRequest,
    tenant_id: TenantId,
    session: DbSession,
    auth: AuthCtx,
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
):
    now = datetime.now(timezone.utc)
    # TODO: verify action exists, transition to REJECTED
    return RejectionResponse(
        id=action_id,
        state="REJECTED",
        rejected_by=auth["user"],
        rejected_at=now,
        reason=body.reason,
    )


@router.post(
    "/actions/{action_id}:cancel",
    response_model=CancellationResponse,
    summary="Durably cancel a running or pending action",
)
async def cancel_action(
    action_id: UUID,
    body: CancelActionRequest,
    tenant_id: TenantId,
    session: DbSession,
    auth: AuthCtx,
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
):
    now = datetime.now(timezone.utc)
    # TODO: cancel Temporal activity, record cancellation event
    return CancellationResponse(
        id=action_id,
        state="CANCELLED",
        cancelled_by=auth["user"],
        cancelled_at=now,
    )


@router.get(
    "/executions/{execution_id}/stream",
    summary="SSE stream for execution logs and progress",
)
async def stream_execution(
    execution_id: UUID,
    tenant_id: TenantId,
    session: DbSession,
    auth: AuthCtx,
):
    async def event_generator():
        # TODO: subscribe to Temporal execution updates
        yield f"event: connected\ndata: {{\"execution_id\": \"{execution_id}\"}}\n\n"
        yield f"event: status\ndata: {{\"state\": \"pending\", \"message\": \"Awaiting execution start\"}}\n\n"

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
