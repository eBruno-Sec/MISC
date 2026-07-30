"""Juice Shop-specific validation activity — runs the basket-IDOR pack."""
from __future__ import annotations

import json
from dataclasses import dataclass, field

from temporalio import activity


@dataclass
class JuiceShopBOLAParams:
    engagement_id: str
    tenant_id: str
    action_id: str
    target_url: str
    identity_a: dict  # {"persona": str, "token": str}
    identity_b: dict


@dataclass
class JuiceShopBOLAResult:
    finding_status: str  # CONFIRMED | INCONCLUSIVE | REJECTED
    reason: str
    evidence_refs: list[str] = field(default_factory=list)
    basket_a: int | None = None
    basket_b: int | None = None


@activity.defn
async def run_juice_shop_basket_idor(params: JuiceShopBOLAParams) -> JuiceShopBOLAResult:
    import httpx  # noqa: PLC0415

    from packs.techniques.web_authz.juice_shop_basket_idor import validate  # noqa: PLC0415
    from services.worker.activities.evidence import (  # noqa: PLC0415
        StoreEvidenceParams,
        store_evidence,
    )

    activity.heartbeat("probing baskets")

    async with httpx.AsyncClient(
        timeout=15.0,
        follow_redirects=False,
        verify=True,
    ) as client:
        result = await validate(
            client=client,
            base_url=params.target_url,
            identity_a=params.identity_a,
            identity_b=params.identity_b,
        )

    # Store one evidence artifact per exchange + one summary.
    evidence_refs: list[str] = []
    for ex in result.exchanges:
        payload = json.dumps(ex, sort_keys=True).encode()
        ref = await store_evidence(
            StoreEvidenceParams(
                engagement_id=params.engagement_id,
                tenant_id=params.tenant_id,
                action_id=f"{params.action_id}-{ex['label']}",
                kind="juice_shop_basket_probe",
                media_type="application/json",
                payload=payload,
            )
        )
        evidence_refs.append(ref)

    summary_payload = json.dumps(
        {
            "finding_status": result.finding_status,
            "reason": result.reason,
            "exchange_count": len(result.exchanges),
        },
        sort_keys=True,
    ).encode()
    summary_ref = await store_evidence(
        StoreEvidenceParams(
            engagement_id=params.engagement_id,
            tenant_id=params.tenant_id,
            action_id=f"{params.action_id}-summary",
            kind="juice_shop_basket_summary",
            media_type="application/json",
            payload=summary_payload,
        )
    )
    evidence_refs.append(summary_ref)

    activity.logger.info(
        "Juice Shop basket IDOR probe complete",
        extra={"finding_status": result.finding_status, "reason": result.reason},
    )

    return JuiceShopBOLAResult(
        finding_status=result.finding_status,
        reason=result.reason,
        evidence_refs=evidence_refs,
    )
