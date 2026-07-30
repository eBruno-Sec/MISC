"""ArsGoatia reversible-mutation module — web.workflow.reversible-preference-update

Per spec §14.2: the mandatory vertical-slice fixture requires a technique that
"creates and restores a harmless state mutation". This module exercises the
mutation + cleanup-verification path that the BOLA technique (mutation: none)
deliberately does not.

Unlike the IDOR module, this technique is state-changing:
  MUTATION_CLASS = "reversible"  → creates a cleanup obligation
  RISK_TIER      = "R3"          → require one-person approval (state-changing)

Confirmation is deterministic (no AI, no IO). A reversible-write capability is
confirmed ONLY when the module can show, from a five-exchange evidence bundle,
that it (a) read a baseline value, (b) mutated it, (c) observed the mutation,
(d) restored the original, and (e) observed the restore succeed. The restore
step is the proof that cleanup was performed — if the value does not return to
baseline, the finding is REFUTED and the cleanup obligation is left FAILED for
escalation.

This module never imports other modules. Cross-module progress flows only
through the produced capability via the planner.
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

MODULE_ID = "web.workflow.reversible_preference_update"
TECHNIQUE_ID = "web.workflow.reversible-preference-update"
VERSION = "1.0.0"
RISK_TIER = "R3"
MUTATION_CLASS = "reversible"
CONFIRMATION_RULE_VERSION = "1.0.0"
EVIDENCE_PROFILE = "reversible_state_mutation"

# Paths that look like a user-writable preference/setting resource.
_PREFERENCE_PATTERNS = (
    "/preference",
    "/preferences",
    "/profile",
    "/settings",
    "/config",
    "/account",
)


def _looks_like_preference_endpoint(path: str) -> bool:
    """Heuristic: does this path look like a writable preference resource?"""
    normalized = path.lower()
    return any(pattern in normalized for pattern in _PREFERENCE_PATTERNS)


class ReversiblePreferenceUpdateModule(ModuleBase):
    """State-changing (reversible) preference-update technique.

    Exchanges expected in the confirmation evidence bundle:
      read_baseline    — GET the preference; expect 200; capture original value
      mutate           — PUT/PATCH a new value; expect 200
      verify_mutation  — GET again; expect 200; value must equal the new value
      restore          — PUT/PATCH the original value back; expect 200
      verify_restore   — GET again; expect 200; value must equal the baseline

    Confirmation is deterministic. The finding is CONFIRMED only when the
    mutation took effect AND the restore returned the resource to its baseline
    (i.e. cleanup is proven). If the restore does not return to baseline the
    finding is REFUTED and cleanup is flagged as not verified.
    """

    MODULE_ID = MODULE_ID
    TECHNIQUE_ID = TECHNIQUE_ID
    VERSION = VERSION
    RISK_TIER = RISK_TIER
    MUTATION_CLASS = MUTATION_CLASS
    CONFIRMATION_RULE_VERSION = CONFIRMATION_RULE_VERSION
    EVIDENCE_PROFILE = EVIDENCE_PROFILE

    def eligibility(self, context: ModuleContext) -> EligibilityResult:
        """Eligible when ≥1 identity and ≥1 writable preference endpoint exist."""
        missing: list[str] = []

        identities = context.metadata.get("identities", [])
        if len(identities) < 1:
            missing.append("min_1_identity")

        endpoints = context.metadata.get("endpoints", [])
        candidates = [ep for ep in endpoints if _looks_like_preference_endpoint(ep)]
        if not candidates:
            missing.append("writable_preference_endpoint")

        if missing:
            return EligibilityResult(
                decision=EligibilityDecision.PREREQUISITE_MISSING,
                reason=f"missing prerequisites: {', '.join(missing)}",
                missing_prerequisites=tuple(missing),
                confidence=0.0,
            )

        return EligibilityResult(
            decision=EligibilityDecision.ELIGIBLE,
            reason=(
                f"found {len(identities)} identity(ies) and "
                f"{len(candidates)} writable preference endpoint(s)"
            ),
            confidence=min(0.9, 0.5 + 0.1 * len(candidates)),
        )

    def build_proposals(self, context: ModuleContext) -> list[ActionProposal]:
        """One reversible R3 proposal per candidate preference endpoint."""
        identities = context.metadata.get("identities", [])
        endpoints = context.metadata.get("endpoints", [])
        candidates = [ep for ep in endpoints if _looks_like_preference_endpoint(ep)]

        if len(identities) < 1 or not candidates:
            return []

        proposals: list[ActionProposal] = []
        for endpoint in candidates:
            proposals.append(
                ActionProposal(
                    proposal_id=uuid4(),
                    technique_id=self.TECHNIQUE_ID,
                    target_locator=f"{context.target_locator}{endpoint}",
                    risk_tier=self.RISK_TIER,
                    mutation_class=self.MUTATION_CLASS,
                    description=(
                        f"Reversible preference update on {endpoint} using "
                        f"identity {identities[0]!r}; original value restored after test"
                    ),
                    parameters={
                        "endpoint": endpoint,
                        "identity": identities[0],
                        "evidence_profile": self.EVIDENCE_PROFILE,
                        "requires_cleanup": True,
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
        """Deterministically confirm a reversible write with proven cleanup.

        Confirmation rule (rule version 1.0.0):
          1. all five exchanges present
          2. read_baseline returns 200 with a captured value
          3. mutate returns 200
          4. verify_mutation returns 200 and value != baseline (mutation took effect)
          5. restore returns 200
          6. verify_restore returns 200 and value == baseline (cleanup proven)
        """
        exchanges_raw = evidence.get("exchanges", [])
        exchanges: dict[str, dict[str, Any]] = {
            ex["label"]: ex for ex in exchanges_raw if "label" in ex
        }

        required = {
            "read_baseline", "mutate", "verify_mutation", "restore", "verify_restore",
        }
        missing = required - set(exchanges.keys())
        if missing:
            return ConfirmationResult(
                decision=ConfirmationDecision.INCONCLUSIVE,
                reason=f"missing required exchanges: {missing}",
                rule_version=self.CONFIRMATION_RULE_VERSION,
            )

        baseline = exchanges["read_baseline"]
        mutate = exchanges["mutate"]
        verify_mutation = exchanges["verify_mutation"]
        restore = exchanges["restore"]
        verify_restore = exchanges["verify_restore"]

        # Rule 2: baseline read must succeed and carry a value.
        if baseline.get("actual_status") != 200 or "value" not in baseline:
            return ConfirmationResult(
                decision=ConfirmationDecision.REFUTED,
                reason=(
                    f"read_baseline failed: status={baseline.get('actual_status')}, "
                    f"value_present={'value' in baseline}"
                ),
                rule_version=self.CONFIRMATION_RULE_VERSION,
            )
        baseline_value = baseline["value"]

        # Rule 3: mutation write must succeed.
        if mutate.get("actual_status") != 200:
            return ConfirmationResult(
                decision=ConfirmationDecision.REFUTED,
                reason=f"mutate failed: expected 200, got {mutate.get('actual_status')}",
                rule_version=self.CONFIRMATION_RULE_VERSION,
            )

        # Rule 4: mutation must be observable and different from baseline.
        if verify_mutation.get("actual_status") != 200:
            return ConfirmationResult(
                decision=ConfirmationDecision.REFUTED,
                reason=(
                    f"verify_mutation failed: expected 200, "
                    f"got {verify_mutation.get('actual_status')}"
                ),
                rule_version=self.CONFIRMATION_RULE_VERSION,
            )
        mutated_value = verify_mutation.get("value")
        if mutated_value == baseline_value:
            return ConfirmationResult(
                decision=ConfirmationDecision.INCONCLUSIVE,
                reason=(
                    "verify_mutation value equals baseline; mutation did not take "
                    "effect, cannot confirm a write"
                ),
                rule_version=self.CONFIRMATION_RULE_VERSION,
            )

        # Rule 5: restore write must succeed.
        if restore.get("actual_status") != 200:
            return ConfirmationResult(
                decision=ConfirmationDecision.REFUTED,
                reason=f"restore failed: expected 200, got {restore.get('actual_status')}",
                rule_version=self.CONFIRMATION_RULE_VERSION,
                metadata={"cleanup_verified": False},
            )

        # Rule 6: restore must return the resource to its baseline value.
        if verify_restore.get("actual_status") != 200 or verify_restore.get("value") != baseline_value:
            return ConfirmationResult(
                decision=ConfirmationDecision.REFUTED,
                reason=(
                    "cleanup failed: state not restored to baseline "
                    f"(baseline={baseline_value!r}, "
                    f"after_restore={verify_restore.get('value')!r})"
                ),
                rule_version=self.CONFIRMATION_RULE_VERSION,
                metadata={"cleanup_verified": False},
            )

        return ConfirmationResult(
            decision=ConfirmationDecision.CONFIRMED,
            reason=(
                "reversible write confirmed: mutation took effect and the "
                "original value was restored (cleanup proven)"
            ),
            rule_version=self.CONFIRMATION_RULE_VERSION,
            evidence_digest=evidence.get("evidence_digest"),
            capability_name="reversible_state_write",
            capability_description=(
                "Identity can write and revert its own preference resource "
                "on the target endpoint; state mutation is fully reversible"
            ),
            metadata={
                "technique_id": self.TECHNIQUE_ID,
                "mutation_class": self.MUTATION_CLASS,
                "cleanup_verified": True,
                "cwe": "CWE-none",
                "owasp": "workflow-state-mutation",
            },
        )

    def run(self, context: ModuleContext) -> ModuleRunResult:
        """Advisory: emit observations about candidate preference endpoints."""
        endpoints = context.metadata.get("endpoints", [])
        observations = [
            {
                "type": "candidate_preference_endpoint",
                "endpoint": ep,
                "reason": "path pattern suggests a writable preference resource",
                "mutation_class": "reversible",
                "confidence": 0.6,
            }
            for ep in endpoints
            if _looks_like_preference_endpoint(ep)
        ]
        return ModuleRunResult(
            module_id=self.MODULE_ID,
            engagement_id=context.engagement_id,
            observations=observations,
            metadata={"candidates_found": len(observations)},
        )


# Module singleton — imported by the module registry
module = ReversiblePreferenceUpdateModule()

__all__ = [
    "ReversiblePreferenceUpdateModule",
    "MODULE_ID",
    "TECHNIQUE_ID",
    "VERSION",
    "module",
]
