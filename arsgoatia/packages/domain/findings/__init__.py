from __future__ import annotations

import enum
from dataclasses import dataclass, field


class FindingState(enum.Enum):
    CANDIDATE = "candidate"
    CONFIRMED = "confirmed"
    REJECTED = "rejected"
    INCONCLUSIVE = "inconclusive"
    ACCEPTED_RISK = "accepted_risk"
    REMEDIATION_PLANNED = "remediation_planned"
    REMEDIATED = "remediated"
    RETEST_PENDING = "retest_pending"
    CLOSED = "closed"
    REGRESSED = "regressed"


FINDING_TRANSITIONS: dict[FindingState, frozenset[FindingState]] = {
    FindingState.CANDIDATE: frozenset(
        {FindingState.CONFIRMED, FindingState.REJECTED, FindingState.INCONCLUSIVE}
    ),
    FindingState.CONFIRMED: frozenset(
        {FindingState.ACCEPTED_RISK, FindingState.REMEDIATION_PLANNED}
    ),
    FindingState.REJECTED: frozenset(),
    FindingState.INCONCLUSIVE: frozenset({FindingState.CANDIDATE}),
    FindingState.ACCEPTED_RISK: frozenset(),
    FindingState.REMEDIATION_PLANNED: frozenset({FindingState.REMEDIATED}),
    FindingState.REMEDIATED: frozenset({FindingState.RETEST_PENDING}),
    FindingState.RETEST_PENDING: frozenset({FindingState.CLOSED, FindingState.REGRESSED}),
    FindingState.CLOSED: frozenset(),
    FindingState.REGRESSED: frozenset({FindingState.REMEDIATION_PLANNED}),
}


EVIDENCE_PROFILES: dict[str, dict] = {
    "web.authz.bola.differential": {
        "required_exchanges": [
            "identity_a_positive_control",
            "identity_b_differential",
            "identity_b_own_resource",
            "negative_control_no_auth",
        ],
        "required_fields": [
            "resolved_destination",
            "identity_fingerprints",
            "object_identifiers",
            "exchange_digests",
        ],
        "positive_control_status": [200],
        "negative_control_status": [401, 403],
    },
    "web.injection.sql": {
        "required_exchanges": [
            "stable_baseline",
            "payload_injection",
            "control_pair",
        ],
        "required_fields": [
            "oracle_type",
            "reproducibility_count",
            "false_positive_controls",
        ],
    },
    "web.xss.reflected": {
        "required_exchanges": [
            "source_to_sink_trace",
            "browser_execution_proof",
        ],
        "required_fields": [
            "execution_context",
            "csp_data",
            "nonce_marker",
        ],
    },
}


@dataclass(frozen=True)
class EvidenceProfileCheck:
    profile_name: str
    satisfied: bool
    missing_exchanges: list[str] = field(default_factory=list)
    missing_fields: list[str] = field(default_factory=list)


def check_evidence_profile(
    profile_name: str,
    provided_exchanges: set[str],
    provided_fields: set[str],
) -> EvidenceProfileCheck:
    profile = EVIDENCE_PROFILES.get(profile_name)
    if profile is None:
        return EvidenceProfileCheck(
            profile_name=profile_name,
            satisfied=False,
            missing_exchanges=["unknown_profile"],
        )

    required_ex = set(profile.get("required_exchanges", []))
    required_fl = set(profile.get("required_fields", []))

    missing_ex = sorted(required_ex - provided_exchanges)
    missing_fl = sorted(required_fl - provided_fields)

    return EvidenceProfileCheck(
        profile_name=profile_name,
        satisfied=len(missing_ex) == 0 and len(missing_fl) == 0,
        missing_exchanges=missing_ex,
        missing_fields=missing_fl,
    )


def can_confirm(
    current_state: FindingState,
    evidence_profile_satisfied: bool,
    validator_passed: bool,
) -> bool:
    if current_state != FindingState.CANDIDATE:
        return False
    return evidence_profile_satisfied and validator_passed


def can_transition(current: FindingState, target: FindingState) -> bool:
    return target in FINDING_TRANSITIONS.get(current, frozenset())
