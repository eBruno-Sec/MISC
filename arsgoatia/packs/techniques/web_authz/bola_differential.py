from __future__ import annotations

from dataclasses import dataclass, field

TECHNIQUE_ID = "web.authz.bola.differential"
TECHNIQUE_VERSION = "1.0.0"
EVIDENCE_PROFILE = "web.authz.bola.differential"
RISK_TIER = "R2"
MUTATION_CLASS = "none"
CONFIRMATION_RULE_VERSION = "1.0.0"


@dataclass(frozen=True)
class ExchangeResult:
    label: str
    status_code: int
    body_contains_object: bool = False
    object_id: str | None = None
    evidence_digest: str | None = None


@dataclass(frozen=True)
class BOLAConfirmation:
    confirmed: bool
    reason: str
    rule_version: str = CONFIRMATION_RULE_VERSION
    exchanges: list[ExchangeResult] = field(default_factory=list)


def confirm_bola(
    baseline: ExchangeResult,
    differential: ExchangeResult,
    positive_control: ExchangeResult,
    negative_control: ExchangeResult,
) -> BOLAConfirmation:
    exchanges = [baseline, differential, positive_control, negative_control]

    if baseline.status_code != 200:
        return BOLAConfirmation(
            confirmed=False,
            reason=f"baseline failed: expected 200, got {baseline.status_code}",
            exchanges=exchanges,
        )

    if positive_control.status_code != 200:
        return BOLAConfirmation(
            confirmed=False,
            reason=f"positive control failed: expected 200, got {positive_control.status_code}",
            exchanges=exchanges,
        )

    if negative_control.status_code not in (401, 403):
        return BOLAConfirmation(
            confirmed=False,
            reason=f"negative control failed: expected 401/403, got {negative_control.status_code}",
            exchanges=exchanges,
        )

    if differential.status_code != 200:
        return BOLAConfirmation(
            confirmed=False,
            reason=(
                f"differential access denied (status {differential.status_code}), not vulnerable"
            ),
            exchanges=exchanges,
        )

    if not differential.body_contains_object:
        return BOLAConfirmation(
            confirmed=False,
            reason="differential response did not contain the target object data",
            exchanges=exchanges,
        )

    return BOLAConfirmation(
        confirmed=True,
        reason=(
            "BOLA confirmed: identity A accessed identity B's object with "
            "discriminating data returned"
        ),
        exchanges=exchanges,
    )


def build_capability(
    actor_id: str,
    access_context_id: str,
    target_object: str,
    evidence_refs: list[str],
) -> dict:
    return {
        "type": "read_foreign_object",
        "actor_id": actor_id,
        "access_context_id": access_context_id,
        "operation": "read",
        "object": target_object,
        "evidence_refs": evidence_refs,
        "technique_id": TECHNIQUE_ID,
        "technique_version": TECHNIQUE_VERSION,
        "confirmation_rule_version": CONFIRMATION_RULE_VERSION,
    }
