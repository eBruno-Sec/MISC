"""ArsGoatia technique manifest system.

Technique manifests describe security test logic independent of tool
implementation.  They specify preconditions, risk tier, evidence profile,
validator, cleanup, and safety constraints per §7.2 of the spec.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from packages.contracts.schemas.common import MutationClass, RiskTier


class TargetType(Enum):
    HTTP_ENDPOINT = "http_endpoint"
    DNS_RECORD = "dns_record"
    CLOUD_RESOURCE = "cloud_resource"
    REPOSITORY = "repository"
    NETWORK_SERVICE = "network_service"
    KUBERNETES_RESOURCE = "kubernetes_resource"
    IDENTITY = "identity"


@dataclass(frozen=True)
class ActionBudget:
    max_requests: int = 12
    max_bytes_received: int = 2 * 1024 * 1024
    timeout_seconds: int = 60


@dataclass(frozen=True)
class SafetyConstraints:
    redirects: str = "deny"
    require_pinned_dns: bool = True
    disallow_network_classes: tuple[str, ...] = (
        "loopback",
        "link_local",
        "metadata",
        "control_plane",
    )


@dataclass(frozen=True)
class PromotionRequirements:
    independent_fixtures_required: int = 2
    negative_controls_required: bool = True


@dataclass(frozen=True)
class TechniqueManifest:
    id: str
    version: str
    pack: str
    description: str
    target_types: list[TargetType]
    required_capabilities: list[str]
    risk_tier: RiskTier
    mutation: MutationClass
    preconditions: list[str] = field(default_factory=list)
    parameters_schema: str | None = None
    action_budget: ActionBudget = field(default_factory=ActionBudget)
    evidence_profile: str | None = None
    validator: str | None = None
    cleanup: str = "none"
    safety: SafetyConstraints = field(default_factory=SafetyConstraints)
    promotion: PromotionRequirements = field(default_factory=PromotionRequirements)


_REGISTRY: dict[str, TechniqueManifest] = {}


def register_technique(manifest: TechniqueManifest) -> None:
    _REGISTRY[manifest.id] = manifest


def get_technique(technique_id: str) -> TechniqueManifest | None:
    return _REGISTRY.get(technique_id)


def list_techniques() -> list[TechniqueManifest]:
    return list(_REGISTRY.values())


def check_eligibility(
    manifest: TechniqueManifest,
    available_capabilities: set[str],
    precondition_state: dict[str, object],
) -> tuple[bool, list[str]]:
    """Check if a technique is eligible given current capabilities and state.

    Returns (eligible, list_of_unmet_reasons).
    """
    reasons: list[str] = []

    for cap in manifest.required_capabilities:
        if cap not in available_capabilities:
            reasons.append(f"missing capability: {cap}")

    for pre in manifest.preconditions:
        if " >= " in pre:
            key, _, threshold = pre.partition(" >= ")
            key, threshold = key.strip(), threshold.strip()
            actual = precondition_state.get(key)
            if actual is None:
                reasons.append(f"precondition not met: {pre}")
            else:
                try:
                    if float(str(actual)) < float(threshold):
                        reasons.append(f"precondition failed: {key}={actual}, need >= {threshold}")
                except (ValueError, TypeError):
                    reasons.append(f"precondition not numeric: {key}={actual}")
        elif " == " in pre:
            key, _, expected = pre.partition(" == ")
            key, expected = key.strip(), expected.strip()
            actual = precondition_state.get(key)
            if actual is None:
                reasons.append(f"precondition not met: {pre}")
            elif str(actual).lower() != expected.lower():
                reasons.append(f"precondition failed: {key}={actual}, expected {expected}")
        else:
            actual = precondition_state.get(pre.strip())
            if not actual:
                reasons.append(f"precondition not met: {pre}")

    return len(reasons) == 0, reasons


BOLA_DIFFERENTIAL = TechniqueManifest(
    id="web.authz.bola.differential",
    version="1.0.0",
    pack="arsgoatia-web-authz",
    description="Compare object access across two authorized identities.",
    target_types=[TargetType.HTTP_ENDPOINT],
    required_capabilities=["http.request", "identity.session.two"],
    risk_tier=RiskTier.R2,
    mutation=MutationClass.none,
    preconditions=[
        "endpoint.has_object_identifier == true",
        "access_context_count >= 2",
    ],
    action_budget=ActionBudget(
        max_requests=12, max_bytes_received=2 * 1024 * 1024, timeout_seconds=60
    ),
    evidence_profile="evidence/web-authz-differential@1",
    cleanup="none",
)

register_technique(BOLA_DIFFERENTIAL)
