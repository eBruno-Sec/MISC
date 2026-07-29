from __future__ import annotations

import json
from dataclasses import dataclass, field

from temporalio import activity


@dataclass
class AccessContextParam:
    persona: str
    credential_ref: str


@dataclass
class ActionEnvelopeParam:
    action_id: str
    action_digest: str
    technique: str
    effective_risk_tier: str
    idempotency_key: str


@dataclass
class BOLAParams:
    target_endpoint: str
    access_contexts: list[AccessContextParam]
    engagement_id: str
    tenant_id: str
    action_id: str
    envelope: ActionEnvelopeParam


@dataclass
class BOLAResult:
    finding_status: str
    evidence_refs: list[str] = field(default_factory=list)
    capability_produced: bool = False


@dataclass
class _ExchangeResult:
    label: str
    status_code: int
    expected_codes: list[int]
    matched: bool
    evidence_ref: str


@activity.defn
async def run_bola_validation(params: BOLAParams) -> BOLAResult:
    if len(params.access_contexts) < 2:
        activity.logger.error(
            "BOLA validation requires at least 2 access contexts"
        )
        return BOLAResult(finding_status="INCONCLUSIVE")

    import httpx  # noqa: PLC0415

    from services.worker.activities.evidence import (  # noqa: PLC0415
        StoreEvidenceParams,
        store_evidence,
    )

    identity_a = params.access_contexts[0]
    identity_b = params.access_contexts[1]
    exchanges: list[_ExchangeResult] = []

    async with httpx.AsyncClient(
        timeout=15.0,
        follow_redirects=False,
        verify=True,
    ) as client:
        activity.heartbeat("baseline: identity A -> own resource")
        baseline = await _do_exchange(
            client=client,
            label="baseline",
            url=params.target_endpoint,
            credential_ref=identity_a.credential_ref,
            expected_codes=[200],
            params=params,
            store_evidence_fn=store_evidence,
        )
        exchanges.append(baseline)

        activity.heartbeat("differential: identity A -> B's resource")
        differential = await _do_exchange(
            client=client,
            label="differential",
            url=params.target_endpoint,
            credential_ref=identity_a.credential_ref,
            expected_codes=[401, 403],
            params=params,
            store_evidence_fn=store_evidence,
            impersonate=identity_b.persona,
        )
        exchanges.append(differential)

        activity.heartbeat("positive_control: identity B -> own resource")
        positive_control = await _do_exchange(
            client=client,
            label="positive_control",
            url=params.target_endpoint,
            credential_ref=identity_b.credential_ref,
            expected_codes=[200],
            params=params,
            store_evidence_fn=store_evidence,
        )
        exchanges.append(positive_control)

        activity.heartbeat("negative_control: no auth -> resource")
        negative_control = await _do_exchange(
            client=client,
            label="negative_control",
            url=params.target_endpoint,
            credential_ref=None,
            expected_codes=[401, 403],
            params=params,
            store_evidence_fn=store_evidence,
        )
        exchanges.append(negative_control)

    evidence_refs = [ex.evidence_ref for ex in exchanges]

    baseline_ok = baseline.matched
    positive_ok = positive_control.matched
    negative_ok = negative_control.matched
    differential_vuln = not differential.matched

    if baseline_ok and positive_ok and negative_ok and differential_vuln:
        finding_status = "CONFIRMED"
        capability_produced = True
    elif not baseline_ok or not positive_ok:
        finding_status = "INCONCLUSIVE"
        capability_produced = False
    else:
        finding_status = "REJECTED"
        capability_produced = False

    activity.logger.info(
        "BOLA validation complete",
        extra={
            "finding_status": finding_status,
            "exchanges": [
                {"label": ex.label, "matched": ex.matched} for ex in exchanges
            ],
        },
    )

    return BOLAResult(
        finding_status=finding_status,
        evidence_refs=evidence_refs,
        capability_produced=capability_produced,
    )


async def _do_exchange(
    *,
    client: object,
    label: str,
    url: str,
    credential_ref: str | None,
    expected_codes: list[int],
    params: BOLAParams,
    store_evidence_fn: object,
    impersonate: str | None = None,
) -> _ExchangeResult:
    import httpx  # noqa: PLC0415

    assert isinstance(client, httpx.AsyncClient)

    headers: dict[str, str] = {}
    if credential_ref:
        headers["Authorization"] = f"Bearer {credential_ref}"
    if impersonate:
        headers["X-ArsGoatia-Impersonate"] = impersonate

    try:
        response = await client.get(url, headers=headers)
        status_code = response.status_code
    except httpx.HTTPError:
        status_code = 0

    matched = status_code in expected_codes

    evidence_payload = json.dumps(
        {
            "exchange": label,
            "url": url,
            "credential_ref": credential_ref is not None,
            "impersonate": impersonate,
            "status_code": status_code,
            "expected_codes": expected_codes,
            "matched": matched,
        },
        sort_keys=True,
    ).encode()

    from services.worker.activities.evidence import StoreEvidenceParams  # noqa: PLC0415

    evidence_ref = await store_evidence_fn(
        StoreEvidenceParams(
            engagement_id=params.engagement_id,
            tenant_id=params.tenant_id,
            action_id=f"{params.action_id}-{label}",
            kind="bola_exchange",
            media_type="application/json",
            payload=evidence_payload,
        )
    )

    return _ExchangeResult(
        label=label,
        status_code=status_code,
        expected_codes=expected_codes,
        matched=matched,
        evidence_ref=evidence_ref,
    )
