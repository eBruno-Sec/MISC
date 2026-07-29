from __future__ import annotations

import json
from dataclasses import dataclass, field

from temporalio import activity


@dataclass
class CleanupObligation:
    obligation_id: str
    inverse_action: str
    target_url: str
    persona: str
    metadata: dict[str, str] = field(default_factory=dict)


@dataclass
class CleanupParams:
    engagement_id: str
    tenant_id: str
    obligations: list[CleanupObligation]


@dataclass
class CleanupOutcome:
    obligation_id: str
    success: bool
    detail: str


@dataclass
class CleanupResult:
    outcomes: list[CleanupOutcome] = field(default_factory=list)
    all_verified: bool = False


@activity.defn
async def run_cleanup(params: CleanupParams) -> CleanupResult:
    import httpx  # noqa: PLC0415

    from services.worker.activities.evidence import (  # noqa: PLC0415
        StoreEvidenceParams,
        store_evidence,
    )

    outcomes: list[CleanupOutcome] = []

    async with httpx.AsyncClient(
        timeout=15.0,
        follow_redirects=False,
        verify=True,
    ) as client:
        for i, obligation in enumerate(params.obligations):
            activity.heartbeat(
                f"cleanup {i + 1}/{len(params.obligations)}: "
                f"{obligation.inverse_action}"
            )

            success = False
            detail = ""

            try:
                if obligation.inverse_action == "delete_user":
                    response = await client.delete(
                        f"{obligation.target_url}/users/{obligation.persona}",
                    )
                    success = response.status_code in (200, 204, 404)
                    detail = f"status={response.status_code}"

                elif obligation.inverse_action == "revoke_token":
                    response = await client.post(
                        f"{obligation.target_url}/logout",
                        json={"username": obligation.persona},
                    )
                    success = response.status_code in (200, 204, 401)
                    detail = f"status={response.status_code}"

                else:
                    detail = f"unknown inverse action: {obligation.inverse_action}"

            except Exception as exc:
                detail = f"error: {exc}"

            verify_evidence = json.dumps(
                {
                    "obligation_id": obligation.obligation_id,
                    "inverse_action": obligation.inverse_action,
                    "persona": obligation.persona,
                    "success": success,
                    "detail": detail,
                },
                sort_keys=True,
            ).encode()

            await store_evidence(
                StoreEvidenceParams(
                    engagement_id=params.engagement_id,
                    tenant_id=params.tenant_id,
                    action_id=f"cleanup-{obligation.obligation_id}",
                    kind="cleanup_verification",
                    media_type="application/json",
                    payload=verify_evidence,
                )
            )

            outcomes.append(
                CleanupOutcome(
                    obligation_id=obligation.obligation_id,
                    success=success,
                    detail=detail,
                )
            )

    all_verified = all(o.success for o in outcomes)

    activity.logger.info(
        "Cleanup complete",
        extra={
            "total": len(outcomes),
            "succeeded": sum(1 for o in outcomes if o.success),
            "all_verified": all_verified,
        },
    )

    return CleanupResult(outcomes=outcomes, all_verified=all_verified)
