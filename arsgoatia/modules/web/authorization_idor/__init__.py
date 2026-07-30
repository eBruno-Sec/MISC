"""ArsGoatia IDOR module — web.authorization.idor.differential

Per spec §14.1: deterministic BOLA/IDOR detection via differential access.

Module lifecycle:
  eligibility()       — requires ≥2 identities, ≥1 object endpoint in scope
  build_proposals()   — one R2 proposal per candidate (endpoint, identity pair)
  confirm()           — deterministic: checks four exchanges, no AI, no IO
  run()               — advisory observations only; does not execute requests

This module never imports other modules.  Cross-module progress (e.g.
exploit after BOLA) flows only through the planner via read_foreign_object.
"""

from __future__ import annotations

from typing import Any
from uuid import uuid4

from packages.module_sdk import (
    ActionProposal,
    ConfirmationDecision,
    ConfirmationResult,
    EligibilityDecision,
    EligibilityResult,
    ModuleBase,
    ModuleContext,
    ModuleRunResult,
)

MODULE_ID = "web.authorization.idor.differential"
TECHNIQUE_ID = "web.authz.bola.differential"
VERSION = "1.0.0"
RISK_TIER = "R2"
MUTATION_CLASS = "none"
CONFIRMATION_RULE_VERSION = "1.0.0"
EVIDENCE_PROFILE = "authorization_differential"

# Endpoints that look like object resources (sequential IDs, UUIDs)
_OBJECT_ENDPOINT_PATTERNS = (
    "/{id}",
    "/{uuid}",
    "/basket/",
    "/order/",
    "/profile/",
    "/account/",
    "/document/",
    "/file/",
    "/resource/",
)


def _looks_like_object_endpoint(path: str) -> bool:
    """Heuristic: does this path look like an object-level resource?"""
    normalized = path.lower()
    for pattern in _OBJECT_ENDPOINT_PATTERNS:
        if pattern in normalized:
            return True
    # Also match paths with numeric or uuid-shaped segments
    parts = [p for p in normalized.split("/") if p]
    if len(parts) >= 2:
        last = parts[-1]
        # looks like {id} or a numeric segment placeholder
        if last.startswith("{") and last.endswith("}"):
            return True
        if last.isdigit():
            return True
    return False


class IDORDifferentialModule(ModuleBase):
    """Differential BOLA/IDOR detection module.

    Detects BOLA by making four differential HTTP exchanges:
      baseline_own        — identity A reads its own object (expect 200)
      differential_cross  — identity A reads identity B's object (expect 403)
      positive_control    — identity B reads its own object (expect 200)
      negative_control    — unauthenticated reads B's object (expect 401)

    Confirmation is deterministic: BOLA is confirmed only when the
    differential returns the target object's owner-discriminating content
    AND the negative control is properly denied.
    """

    MODULE_ID = MODULE_ID
    TECHNIQUE_ID = TECHNIQUE_ID
    VERSION = VERSION
    RISK_TIER = RISK_TIER
    MUTATION_CLASS = MUTATION_CLASS
    CONFIRMATION_RULE_VERSION = CONFIRMATION_RULE_VERSION
    EVIDENCE_PROFILE = EVIDENCE_PROFILE

    def eligibility(self, context: ModuleContext) -> EligibilityResult:
        """Check eligibility: need ≥2 identities and ≥1 object endpoint."""
        missing: list[str] = []

        # Need at least 2 identities (A and B)
        identities = context.metadata.get("identities", [])
        if len(identities) < 2:
            missing.append("min_2_identities")

        # Need at least one candidate object endpoint
        endpoints = context.metadata.get("endpoints", [])
        candidates = [ep for ep in endpoints if _looks_like_object_endpoint(ep)]
        if not candidates:
            missing.append("object_level_endpoint")

        if missing:
            return EligibilityResult(
                decision=(
                    EligibilityDecision.PREREQUISITE_MISSING
                    if missing
                    else EligibilityDecision.INSUFFICIENT_DATA
                ),
                reason=f"missing prerequisites: {', '.join(missing)}",
                missing_prerequisites=tuple(missing),
                confidence=0.0,
            )

        return EligibilityResult(
            decision=EligibilityDecision.ELIGIBLE,
            reason=(
                f"found {len(identities)} identities and {len(candidates)} candidate endpoint(s)"
            ),
            confidence=min(0.9, 0.5 + 0.1 * len(candidates)),
        )

    def build_proposals(self, context: ModuleContext) -> list[ActionProposal]:
        """Build one proposal per candidate (endpoint, identity pair)."""
        identities = context.metadata.get("identities", [])
        endpoints = context.metadata.get("endpoints", [])
        candidates = [ep for ep in endpoints if _looks_like_object_endpoint(ep)]

        if len(identities) < 2 or not candidates:
            return []

        proposals = []
        for endpoint in candidates:
            proposals.append(
                ActionProposal(
                    proposal_id=uuid4(),
                    technique_id=self.TECHNIQUE_ID,
                    target_locator=f"{context.target_locator}{endpoint}",
                    risk_tier=self.RISK_TIER,
                    mutation_class=self.MUTATION_CLASS,
                    description=(
                        f"BOLA differential: test object-level authz on {endpoint} "
                        f"using identities {identities[0]!r} and {identities[1]!r}"
                    ),
                    parameters={
                        "endpoint": endpoint,
                        "identity_a": identities[0],
                        "identity_b": identities[1],
                        "evidence_profile": self.EVIDENCE_PROFILE,
                    },
                    expected_evidence_profile=self.EVIDENCE_PROFILE,
                )
            )
        return proposals

    def confirm(
        self,
        evidence: dict[str, Any],
        context: ModuleContext,
    ) -> ConfirmationResult:
        """Deterministically confirm BOLA from the four differential exchanges.

        Evidence must include an 'exchanges' list with all four labels:
          baseline_own, differential_cross, positive_control, negative_control.

        Confirmation rule (rule version 1.0.0):
          1. baseline_own must return HTTP 200
          2. positive_control must return HTTP 200
          3. negative_control must return HTTP 401 or 403
          4. differential_cross must return HTTP 200
          5. differential_cross response must contain owner-discriminating
             content (body_contains_object=True)
        """
        exchanges_raw = evidence.get("exchanges", [])
        exchanges: dict[str, dict[str, Any]] = {
            ex["label"]: ex for ex in exchanges_raw if "label" in ex
        }

        required_labels = {
            "baseline_own",
            "differential_cross",
            "positive_control",
            "negative_control",
        }
        missing_labels = required_labels - set(exchanges.keys())
        if missing_labels:
            return ConfirmationResult(
                decision=ConfirmationDecision.INCONCLUSIVE,
                reason=f"missing required exchanges: {missing_labels}",
                rule_version=self.CONFIRMATION_RULE_VERSION,
            )

        baseline = exchanges["baseline_own"]
        differential = exchanges["differential_cross"]
        positive = exchanges["positive_control"]
        negative = exchanges["negative_control"]

        # Rule 1: baseline must succeed
        if baseline.get("actual_status") != 200:
            return ConfirmationResult(
                decision=ConfirmationDecision.REFUTED,
                reason=(f"baseline_own failed: expected 200, got {baseline.get('actual_status')}"),
                rule_version=self.CONFIRMATION_RULE_VERSION,
            )

        # Rule 2: positive control must succeed
        if positive.get("actual_status") != 200:
            return ConfirmationResult(
                decision=ConfirmationDecision.REFUTED,
                reason=(
                    f"positive_control failed: expected 200, got {positive.get('actual_status')}"
                ),
                rule_version=self.CONFIRMATION_RULE_VERSION,
            )

        # Rule 3: negative control must be denied
        neg_status = negative.get("actual_status")
        if neg_status not in (401, 403):
            return ConfirmationResult(
                decision=ConfirmationDecision.REFUTED,
                reason=(f"negative_control not denied: expected 401/403, got {neg_status}"),
                rule_version=self.CONFIRMATION_RULE_VERSION,
            )

        # Rule 4: differential must succeed (BOLA present)
        diff_status = differential.get("actual_status")
        if diff_status != 200:
            return ConfirmationResult(
                decision=ConfirmationDecision.REFUTED,
                reason=(
                    f"differential_cross returned {diff_status}, "
                    f"authorization appears to be enforced"
                ),
                rule_version=self.CONFIRMATION_RULE_VERSION,
            )

        # Rule 5: differential response must contain owner-discriminating data
        if not differential.get("body_contains_object", False):
            return ConfirmationResult(
                decision=ConfirmationDecision.INCONCLUSIVE,
                reason=(
                    "differential returned 200 but response did not contain "
                    "owner-discriminating object data; cannot confirm BOLA"
                ),
                rule_version=self.CONFIRMATION_RULE_VERSION,
            )

        return ConfirmationResult(
            decision=ConfirmationDecision.CONFIRMED,
            reason=(
                "BOLA confirmed: identity A accessed identity B's object "
                "with owner-discriminating content returned; "
                "negative control properly denied"
            ),
            rule_version=self.CONFIRMATION_RULE_VERSION,
            evidence_digest=evidence.get("evidence_digest"),
            capability_name="read_foreign_object",
            capability_description=(
                "Identity A can read any object belonging to identity B "
                "on the target endpoint without authorization"
            ),
            metadata={
                "differential_status": diff_status,
                "negative_control_status": neg_status,
                "technique_id": self.TECHNIQUE_ID,
                "cwe": "CWE-639",
                "owasp": "API1:2023",
            },
        )

    def run(self, context: ModuleContext) -> ModuleRunResult:
        """Advisory: emit observations about endpoint characteristics."""
        endpoints = context.metadata.get("endpoints", [])
        observations = []
        for ep in endpoints:
            if _looks_like_object_endpoint(ep):
                observations.append(
                    {
                        "type": "candidate_object_endpoint",
                        "endpoint": ep,
                        "reason": "path pattern suggests object-level resource",
                        "confidence": 0.6,
                    }
                )
        return ModuleRunResult(
            module_id=self.MODULE_ID,
            engagement_id=context.engagement_id,
            observations=observations,
            metadata={"candidates_found": len(observations)},
        )


# Module singleton — imported by the module registry
module = IDORDifferentialModule()

__all__ = ["IDORDifferentialModule", "MODULE_ID", "TECHNIQUE_ID", "module"]
