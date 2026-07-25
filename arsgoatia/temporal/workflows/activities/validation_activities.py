"""IDOR validation activity (§10.5, high-risk-validation queue).

Runs the web.authorization.idor differential end to end: signs an action envelope
per exchange, executes each through the tool SDK (envelope re-verified, scope +
SSRF re-checked, secret injected at call time), captures immutable evidence,
confirms deterministically, and persists the observation, hypothesis, finding,
and — only on confirmation — the proven read_foreign_object capability.

The confirmation decision is the pure confirm_idor() function; this activity only
wires I/O to it.
"""

from __future__ import annotations

import json
import logging
from datetime import timedelta
from typing import Any
from uuid import uuid4

from temporalio import activity

log = logging.getLogger("validation")

_HERE_MODULE_ID = "web.authorization.idor"


@activity.defn(name="run_idor_validation")
async def run_idor_validation(params: dict[str, Any]) -> dict[str, Any]:
    from config.settings import get_settings
    from domain import repositories as repo
    from domain.db import session_scope
    from evidence.profiles import check_profile
    from evidence.store import EvidenceStore
    from policy.envelope import build_binding, sign
    from policy.scope_firewall import ScopeFirewall
    from schemas.action_envelope import (
        ActionBudget,
        ActionEnvelope,
        Actor,
        ActorKind,
        EnvelopeTarget,
    )
    from schemas.common import RiskClass, utcnow
    from schemas.module_io import Provenance
    from schemas.policy import EnforcedLimits
    from schemas.tool_io import ExitState, ToolRequest
    from secrets_store.store import SecretStore
    from tool_sdk.http_client import execute

    import modules.web.authorization_idor.module as idor

    settings = get_settings()
    key = settings.session_secret
    tenant_id = params["tenant_id"]
    assessment_id = params["assessment_id"]
    base_url = params["base_url"].rstrip("/")
    target_asset_id = params.get("target_asset_id")
    identities = params["identities"]  # [{identity_id, secret_uri, object_id, access_context_id}]
    revision = int(params.get("assessment_revision", 1))
    policy_revision = int(params.get("policy_revision", 1))
    approval_granted = bool(params.get("approval_granted", False))
    action_id = params.get("action_id") or str(uuid4())

    if len(identities) < 2:
        return {"status": "ineligible", "reason": "need 2 identities"}
    a, b = identities[0], identities[1]

    targets = await _load_targets(session_scope, tenant_id, assessment_id, repo)
    firewall = ScopeFirewall.from_targets(targets)
    store = EvidenceStore()

    plan = idor.plan_differential(a, b, base_url)
    results: dict[str, idor.ExchangeResult] = {}
    captured_components: set[str] = set()
    evidence_ids: list[str] = []

    async def secret_getter(secret_uri: str) -> str:
        async with session_scope(tenant_id) as s:
            return await SecretStore().get(s, secret_uri)

    for step in plan:
        # One signed, approval-bound envelope per differential exchange.
        env = ActionEnvelope(
            tenant_id=tenant_id,
            assessment_id=assessment_id,
            assessment_revision=revision,
            policy_revision=policy_revision,
            module_id=_HERE_MODULE_ID,
            module_version="1.0.0",
            actor=Actor(kind=ActorKind.SYSTEM, id="validation"),
            origin_context_id=a.get("access_context_id") or str(uuid4()),
            targets=[
                EnvelopeTarget(
                    asset_id=target_asset_id or str(uuid4()),
                    resolved_destination=base_url.split("://", 1)[-1],
                )
            ],
            requested_effect=f"idor_{step['role']}",
            risk_class=RiskClass.R2,
            approval_ref=action_id,
            budget=ActionBudget(max_requests=1, max_rps=2.0, timeout_seconds=20, max_bytes=1_048_576),
            idempotency_key=f"{action_id}:{step['role']}",
            expires_at=utcnow() + timedelta(minutes=5),
        )
        signed = sign(env, key)

        async def sink(exchange: dict, _role=step["role"]) -> str:
            async with session_scope(tenant_id) as s:
                stored = store.put(
                    tenant_id=tenant_id,
                    assessment_id=assessment_id,
                    evidence_type="http_response",
                    content=json.dumps(exchange, sort_keys=True).encode("utf-8"),
                    media_type="application/json",
                    captured_by="validation",
                    extra={"role": _role, "status": exchange.get("status")},
                )
                await repo.create_evidence(s, tenant_id=tenant_id, fields=stored)
                return stored["id"]

        req = ToolRequest(
            tool_id="http_differential",
            tool_version="1.0.0",
            action_envelope=signed,
            parameters={"url": step["url"], "method": step["method"], "secret_uri": step.get("secret_uri")},
        )
        result = await execute(
            req,
            signing_key=key,
            firewall=firewall,
            secret_getter=secret_getter,
            evidence_sink=sink,
            expected_revision=revision,
            expected_policy_revision=policy_revision,
            allow_private=True,
        )
        status = int((result.normalized_output or {}).get("status", 0))
        obj = idor.extract_object_id((result.normalized_output or {}).get("json"))
        ev_id = str(result.raw_output_evidence_ref) if result.raw_output_evidence_ref else None
        if ev_id:
            evidence_ids.append(ev_id)
        results[step["role"]] = idor.ExchangeResult(
            role=step["role"], status=status, observed_object_id=obj, evidence_id=ev_id
        )
        if result.exit_state is ExitState.SUCCESS or status:
            captured_components.add(step["role"])
        async with session_scope(tenant_id) as s:
            await repo.record_tool_execution(
                s,
                tenant_id=tenant_id,
                assessment_id=assessment_id,
                tool_id="http_differential",
                exit_state=result.exit_state.value,
                raw_output_evidence_ref=ev_id,
                warnings=result.warnings,
            )

    # Deterministic confirmation.
    profile = check_profile("authorization_differential", captured_components)
    envelope_verified = all(
        r.status > 0 for r in results.values()
    )  # every exchange passed preflight (executor verified the envelope)
    confirm = idor.confirm_idor(
        results,
        target_object_id=str(b.get("object_id")),
        envelope_verified=envelope_verified,
        evidence_complete=profile.complete,
    )

    finding_id = None
    capability_id = None
    async with session_scope(tenant_id) as s:
        obs = await repo.create_observation(
            s,
            tenant_id=tenant_id,
            assessment_id=assessment_id,
            observation_type="cross_user_response_difference",
            subject_type="response",
            summary="user A session returned user B's object on GET /rest/basket/{id}",
            structured_data={"reasons": confirm.reasons, "rule_version": confirm.rule_version},
            evidence_refs=evidence_ids,
        )
        hyp = await repo.create_hypothesis(
            s,
            tenant_id=tenant_id,
            assessment_id=assessment_id,
            hypothesis_class="authorization.object_level",
            summary="user-controlled object ID may allow cross-user read",
            rationale="differential request reproduced owner-success against another user's object",
            supporting_observation_refs=[str(obs.id)],
        )
        finding = await repo.create_finding(
            s,
            tenant_id=tenant_id,
            assessment_id=assessment_id,
            internal_class="authorization.object_level",
            title="Broken object-level authorization (IDOR/BOLA) on basket read",
            summary="A standard user can read another user's basket by object ID.",
            technical_description="\n".join(confirm.reasons),
            evidence_profile="authorization_differential",
            severity_label="high",
            evidence_refs=evidence_ids,
            affected_identity_ids=[a.get("identity_id"), b.get("identity_id")],
        )
        finding_id = str(finding.id)

        if confirm.confirmed and approval_granted:
            cap = idor.build_capability(
                subject_identity_id=a.get("identity_id"),
                target_asset_id=target_asset_id,
                access_context_id=a.get("access_context_id"),
                origin_finding_id=finding_id,
                evidence_refs=evidence_ids,
            )
            cap_row = await repo.create_capability(
                s, tenant_id=tenant_id, assessment_id=assessment_id, cap=cap
            )
            capability_id = str(cap_row.id)
            await repo.confirm_finding(s, finding_id=finding_id, capability_refs=[capability_id])

    return {
        "status": "ok",
        "finding_id": finding_id,
        "confirmed": confirm.confirmed and approval_granted,
        "capability_id": capability_id,
        "evidence_profile_complete": profile.complete,
        "reasons": confirm.reasons,
    }


async def _load_targets(session_scope, tenant_id, assessment_id, repo) -> list[dict]:
    async with session_scope(tenant_id) as s:
        return await repo.get_scope_targets(s, assessment_id)
