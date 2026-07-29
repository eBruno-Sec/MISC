from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass, field

from temporalio import activity


@dataclass
class ChainParams:
    engagement_id: str
    tenant_id: str
    finding_id: str
    capability_id: str
    technique: str
    preconditions: list[str] = field(default_factory=list)
    postconditions: list[str] = field(default_factory=list)
    evidence_refs: list[str] = field(default_factory=list)


@activity.defn
async def create_chain_step(params: ChainParams) -> str:
    from services.worker.activities.evidence import (  # noqa: PLC0415
        StoreEvidenceParams,
        store_evidence,
    )

    step_id = str(uuid.uuid4())
    step_data = {
        "step_id": step_id,
        "engagement_id": params.engagement_id,
        "finding_id": params.finding_id,
        "capability_id": params.capability_id,
        "technique": params.technique,
        "preconditions": params.preconditions,
        "postconditions": params.postconditions,
        "evidence_refs": params.evidence_refs,
    }

    payload = json.dumps(step_data, sort_keys=True).encode()

    await store_evidence(
        StoreEvidenceParams(
            engagement_id=params.engagement_id,
            tenant_id=params.tenant_id,
            action_id=f"chain-step-{step_id}",
            kind="attack_chain_step",
            media_type="application/json",
            payload=payload,
        )
    )

    activity.logger.info(
        "Chain step created",
        extra={"step_id": step_id, "finding_id": params.finding_id},
    )
    return step_id
