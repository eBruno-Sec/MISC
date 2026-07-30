"""ArsGoatia Module SDK — base class for all attack technique modules.

Per spec §14:
  - Modules declare eligibility() deterministically — no IO, no side effects.
  - Modules propose actions via build_proposals() — never execute them.
  - Modules confirm findings via confirm() — deterministic, no AI, no IO.
  - Modules never import other modules; cross-module progress flows only
    through the planner via produced capabilities.
  - Module output validates against output_schema.json before returning.
  - Malformed output is quarantined, not raised directly.
  - AI may be called inside run() for advisory purposes only (layer 6 of
    the planner), but never for eligibility, proposal, or confirmation.

Lifecycle:
  eligibility(context) → EligibilityResult
  build_proposals(context) → list[ActionProposal]
  run(context) → ModuleRunResult          (advisory / recon)
  confirm(evidence, context) → ConfirmationResult   (deterministic)
"""

from __future__ import annotations

import abc
import enum
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import UUID, uuid4


class EligibilityDecision(enum.Enum):
    ELIGIBLE = "eligible"
    NOT_ELIGIBLE = "not_eligible"
    INSUFFICIENT_DATA = "insufficient_data"
    PREREQUISITE_MISSING = "prerequisite_missing"


class ConfirmationDecision(enum.Enum):
    CONFIRMED = "confirmed"
    REFUTED = "refuted"
    INCONCLUSIVE = "inconclusive"


@dataclass(frozen=True)
class EligibilityResult:
    decision: EligibilityDecision
    reason: str = ""
    missing_prerequisites: tuple[str, ...] = ()
    confidence: float = 0.0


@dataclass(frozen=True)
class ActionProposal:
    """A proposed action from the module — never an execution."""

    proposal_id: UUID = field(default_factory=uuid4)
    technique_id: str = ""
    target_locator: str = ""
    risk_tier: str = "R2"
    mutation_class: str = "none"
    description: str = ""
    parameters: dict[str, Any] = field(default_factory=dict)
    expected_evidence_profile: str = ""
    # AI advisory note — never used as a policy decision
    ai_rationale: str | None = None


@dataclass(frozen=True)
class ModuleRunResult:
    """Advisory output from run() — observations and intermediate state.

    run() is for gathering recon / advisory data.  It must NOT execute
    actions against the target (that's the runner-agent's job).
    """

    module_id: str
    engagement_id: UUID
    observations: list[dict[str, Any]] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    ran_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass(frozen=True)
class ConfirmationResult:
    """Deterministic confirmation result from confirm().

    This is the only output that can trigger finding confirmation and
    capability emission.  It must be deterministic — no AI, no IO, no
    randomness.  All inputs (evidence, exchanges) must be passed in.
    """

    decision: ConfirmationDecision
    reason: str
    rule_version: str
    evidence_digest: str | None = None
    capability_name: str | None = None
    capability_description: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def is_confirmed(self) -> bool:
        return self.decision == ConfirmationDecision.CONFIRMED


@dataclass(frozen=True)
class ModuleContext:
    """Read-only context passed to all module methods.

    Modules must not mutate this object.  Side effects (DB writes,
    HTTP calls) are forbidden in eligibility(), build_proposals(),
    and confirm().  run() may call registered activities indirectly
    via the provided activity_refs, but never directly.
    """

    engagement_id: UUID
    tenant_id: UUID
    target_locator: str
    scope_tokens: frozenset[str] = field(default_factory=frozenset)
    capabilities_available: frozenset[str] = field(default_factory=frozenset)
    observations: tuple[dict[str, Any], ...] = ()
    policy_profile: str = "lab-safe"
    metadata: dict[str, Any] = field(default_factory=dict)


class ModuleOutputError(Exception):
    """Raised when module output fails schema validation."""


class ModuleBase(abc.ABC):
    """Abstract base class every ArsGoatia module must subclass.

    Subclasses must:
      - Set ``MODULE_ID``, ``TECHNIQUE_ID``, ``VERSION``, ``RISK_TIER``.
      - Implement eligibility(), build_proposals(), confirm().
      - Optionally override run() for recon/advisory work.
      - Never import other module classes.
      - Never call external IO in eligibility/build_proposals/confirm.
    """

    MODULE_ID: str = ""
    TECHNIQUE_ID: str = ""
    VERSION: str = "1.0.0"
    RISK_TIER: str = "R2"
    MUTATION_CLASS: str = "none"
    CONFIRMATION_RULE_VERSION: str = "1.0.0"
    EVIDENCE_PROFILE: str = ""

    @abc.abstractmethod
    def eligibility(self, context: ModuleContext) -> EligibilityResult:
        """Determine whether this module is eligible to run.

        Must be pure — no IO, no side effects, no randomness.
        May read from context.observations and context.capabilities_available.
        """

    @abc.abstractmethod
    def build_proposals(self, context: ModuleContext) -> list[ActionProposal]:
        """Build action proposals for this module.

        Returns a list of proposals (may be empty if not applicable).
        Must be pure — no IO, no side effects, no randomness.
        Proposals are submitted to the planner; they do not execute actions.
        """

    @abc.abstractmethod
    def confirm(
        self,
        evidence: dict[str, Any],
        context: ModuleContext,
    ) -> ConfirmationResult:
        """Deterministically confirm or refute a finding.

        Must be pure — no AI, no IO, no randomness.
        All inputs needed for confirmation must be in `evidence`.
        The result must be reproducible given the same inputs.
        """

    def run(self, context: ModuleContext) -> ModuleRunResult:
        """Advisory run — gather observations and intermediate state.

        Default implementation returns an empty result.  Override to
        gather recon data, but do not execute actions against the target.
        """
        return ModuleRunResult(
            module_id=self.MODULE_ID,
            engagement_id=context.engagement_id,
        )

    def validate_output(self, output: dict[str, Any]) -> list[str]:
        """Validate module output against the declared schema.

        Returns a list of validation errors.  Empty means valid.
        Default implementation does minimal structural checks; subclasses
        may override to add schema-based validation.
        """
        errors: list[str] = []
        required_keys = ("module_id", "technique_id", "version", "decision")
        for key in required_keys:
            if key not in output:
                errors.append(f"missing required output key: {key!r}")
        return errors


__all__ = [
    "ActionProposal",
    "ConfirmationDecision",
    "ConfirmationResult",
    "EligibilityDecision",
    "EligibilityResult",
    "ModuleBase",
    "ModuleContext",
    "ModuleOutputError",
    "ModuleRunResult",
]
