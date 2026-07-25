"""Chain-planner activity (§10.6, §19).

After the IDOR finding is confirmed and its read_foreign_object capability is
produced, build the first attack-chain step and the capability transition that
records how the starting context reached that capability. Runs on the control
queue (worker-control) — no target egress.
"""

from __future__ import annotations

import logging
from typing import Any

from temporalio import activity

log = logging.getLogger("chain")


@activity.defn(name="create_chain_step")
async def create_chain_step(params: dict[str, Any]) -> dict[str, Any]:
    from chain.engine import build_capability_transition, build_chain_step, chain_severity
    from domain import repositories as repo
    from domain.db import session_scope

    tenant_id = params["tenant_id"]
    assessment_id = params["assessment_id"]
    validation = params.get("validation") or {}
    finding_id = validation.get("finding_id")
    capability_id = validation.get("capability_id")
    starting_context_id = params.get("starting_context_id")

    if not (finding_id and capability_id and validation.get("confirmed")):
        return {"status": "no_confirmed_capability"}

    async with session_scope(tenant_id) as session:
        cap = await repo.get_capability(session, capability_id)
        if cap is None:
            return {"status": "capability_not_found"}
        ctx_id = starting_context_id or str(cap.access_context_id)
        evidence_refs = [str(e) for e in (cap.evidence_refs or [])]

        severity, rationale = chain_severity(
            validated_step_count=1,
            capabilities_gained=[cap.label or cap.capability_type],
            crosses_identity_boundary=True,  # read_foreign_object crosses users
            reaches_sensitive_data=True,  # another user's basket contents
        )

        chain = await repo.create_attack_chain(
            session,
            tenant_id=tenant_id,
            assessment_id=assessment_id,
            title="Cross-user object read chain",
            objective="Read another user's object using a standard-user session",
            starting_context_id=ctx_id,
            chain_severity=severity,
            chain_scoring_rationale=rationale,
            final_capability_ids=[capability_id],
            evidence_refs=evidence_refs,
        )

        step = build_chain_step(
            attack_chain_id=str(chain.id),
            sequence_number=1,
            prerequisite_capability_ids=[],
            source_context_id=ctx_id,
            action_execution_id=None,
            finding_id=finding_id,
            resulting_capability_ids=[capability_id],
            evidence_refs=evidence_refs,
        )
        step_row = await repo.create_attack_chain_step(session, tenant_id=tenant_id, step=step)
        await repo.attach_chain_step(session, attack_chain_id=str(chain.id), step_id=str(step_row.id))

        transition = build_capability_transition(
            source_context_id=ctx_id,
            prerequisite_capability_ids=[],
            action_execution_id=None,
            finding_id=finding_id,
            resulting_capability_ids=[capability_id],
            resulting_context_ids=[ctx_id],
            evidence_refs=evidence_refs,
        )
        await repo.create_capability_transition(
            session, tenant_id=tenant_id, assessment_id=assessment_id, transition=transition
        )

    return {
        "status": "ok",
        "attack_chain_id": str(chain.id),
        "step_id": str(step_row.id),
        "chain_severity": severity,
    }
