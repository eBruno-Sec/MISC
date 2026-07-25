"""web.authorization.idor — object-level authorization (IDOR/BOLA) module.

The confirmation logic is deterministic and evidence-driven (never derived from a
tool's severity label, guardrail 4). A candidate becomes confirmed only when a
positive control defines success, the differential request reproduces that
success against another user's object, and a negative control proves auth is
otherwise enforced — with the envelope verified and the evidence profile complete.

The differential planning and confirmation are pure functions so the safety-
critical decision is exhaustively unit-testable; the module's run() wires them to
the tool SDK.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from module_sdk.base import BaseModule, ModuleContext
from schemas.domain import CapabilityType
from schemas.module_io import ModuleOutput, Provenance

CONFIRMATION_RULE_VERSION = "1.0.0"


@dataclass
class ExchangeResult:
    role: str  # baseline_own | differential | positive_control | negative_control
    status: int
    observed_object_id: str | None = None
    evidence_id: str | None = None


@dataclass
class ConfirmResult:
    confirmed: bool
    reasons: list[str] = field(default_factory=list)
    rule_version: str = CONFIRMATION_RULE_VERSION


def plan_differential(identity_a: dict, identity_b: dict, base_url: str) -> list[dict]:
    """The four exchanges of the authorization_differential profile. Object ids are
    the identities' own objects (Juice Shop basket ids)."""
    a_obj = identity_a.get("object_id")
    b_obj = identity_b.get("object_id")
    base = base_url.rstrip("/")
    return [
        {
            "role": "baseline_own",
            "method": "GET",
            "url": f"{base}/rest/basket/{a_obj}",
            "secret_uri": identity_a.get("secret_uri"),
            "expected_object_id": a_obj,
        },
        {
            "role": "differential",
            "method": "GET",
            "url": f"{base}/rest/basket/{b_obj}",
            "secret_uri": identity_a.get("secret_uri"),  # A's token on B's object
            "expected_object_id": b_obj,
        },
        {
            "role": "positive_control",
            "method": "GET",
            "url": f"{base}/rest/basket/{b_obj}",
            "secret_uri": identity_b.get("secret_uri"),  # B's token on B's object
            "expected_object_id": b_obj,
        },
        {
            "role": "negative_control",
            "method": "GET",
            "url": f"{base}/rest/basket/{b_obj}",
            "secret_uri": None,  # unauthenticated
            "expected_object_id": b_obj,
        },
    ]


def confirm_idor(
    results: dict[str, ExchangeResult],
    *,
    target_object_id: str,
    envelope_verified: bool,
    evidence_complete: bool,
) -> ConfirmResult:
    """Deterministic confirmation. All conditions must hold (§17)."""
    reasons: list[str] = []

    baseline = results.get("baseline_own")
    differential = results.get("differential")
    positive = results.get("positive_control")
    negative = results.get("negative_control")

    if not (baseline and differential and positive and negative):
        return ConfirmResult(False, ["incomplete_exchange_set"])

    success_status = positive.status
    owner_read_ok = positive.status < 400 and positive.observed_object_id == target_object_id
    _record(reasons, "positive_control_defines_success", owner_read_ok)

    _record(reasons, "baseline_own_read_ok", baseline.status < 400)

    diff_matches_success = differential.status == success_status and differential.status < 400
    _record(reasons, "differential_succeeds_like_owner", diff_matches_success)

    diff_returned_foreign_object = differential.observed_object_id == target_object_id
    _record(reasons, "differential_returned_foreign_object", diff_returned_foreign_object)

    negative_denies = negative.status >= 400
    _record(reasons, "auth_otherwise_enforced", negative_denies)

    _record(reasons, "envelope_verified", envelope_verified)
    _record(reasons, "evidence_profile_complete", evidence_complete)

    confirmed = all(
        [
            owner_read_ok,
            baseline.status < 400,
            diff_matches_success,
            diff_returned_foreign_object,
            negative_denies,
            envelope_verified,
            evidence_complete,
        ]
    )
    return ConfirmResult(confirmed, reasons)


def build_capability(
    *,
    subject_identity_id: str,
    target_asset_id: str | None,
    access_context_id: str,
    origin_finding_id: str,
    evidence_refs: list[str],
) -> dict:
    """The read_foreign_object capability produced on confirmation (§18). Written
    as proven only after the finding is confirmed, so evidence backs it."""
    return {
        "capability_type": CapabilityType.READ_OBJECT.value,
        "label": "read_foreign_object",
        "subject_identity_id": subject_identity_id,
        "target_asset_id": target_asset_id,
        "access_context_id": access_context_id,
        "validation_state": "proven",
        "origin_finding_id": origin_finding_id,
        "evidence_refs": evidence_refs,
        "confidence": 0.95,
    }


def extract_object_id(body_json: dict | None) -> str | None:
    """Owner-discriminating field from a Juice Shop basket response: data.id."""
    if not isinstance(body_json, dict):
        return None
    data = body_json.get("data")
    if isinstance(data, dict) and "id" in data:
        return str(data["id"])
    return None


def _record(reasons: list[str], name: str, ok: bool) -> None:
    reasons.append(f"{'PASS' if ok else 'FAIL'}:{name}")


class IDORModule(BaseModule):
    MODULE_ID = "web.authorization.idor"

    def eligibility(self, ctx: ModuleContext) -> tuple[bool, str]:
        standard_users = [
            i for i in ctx.identities if i.get("privilege_label", "standard_user") == "standard_user"
        ]
        with_objects = [i for i in standard_users if i.get("object_id")]
        if len(with_objects) < 2:
            return False, "requires >= 2 standard-user identities with owned objects"
        return True, "eligible"

    async def run(self, ctx: ModuleContext, tool) -> ModuleOutput:  # pragma: no cover - integration
        # Wired by the validation activity: sign an envelope per exchange, execute
        # via the tool SDK, then confirm deterministically. Kept thin here; the
        # decision logic lives in the pure functions above.
        raise NotImplementedError("run() is orchestrated by the validation activity")

    @staticmethod
    def build_output(
        *,
        assessment_id: str,
        provenance: Provenance,
        observation: dict,
        hypothesis: dict,
        candidate_finding: dict,
        capability: dict | None,
        evidence_refs: list[str],
    ) -> ModuleOutput:
        return ModuleOutput(
            module_id=IDORModule.MODULE_ID,
            module_version="1.0.0",
            provenance=provenance,
            observations=[observation],
            hypotheses=[hypothesis],
            candidate_findings=[candidate_finding],
            capabilities=[capability] if capability else [],
            evidence_refs=evidence_refs,
        )
