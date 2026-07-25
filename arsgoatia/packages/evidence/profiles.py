"""Evidence-profile completeness (§16, §17).

A finding may become confirmed only when its required evidence profile is
complete. Each profile lists the required evidence components; the module records
which components it captured, and completeness is checked deterministically here.
"""

from __future__ import annotations

from dataclasses import dataclass

# Required components per profile. The slice implements authorization_differential;
# the others are declared so the registry matches the spec's example set (§16).
_REQUIRED: dict[str, set[str]] = {
    "authorization_differential": {
        "baseline_own",  # subject A reads its own object -> success
        "differential",  # subject A reads subject B's object with A's session
        "positive_control",  # subject B reads B's object -> success (object exists)
        "negative_control",  # unauthenticated read -> denied (auth otherwise enforced)
    },
    "authentication_bypass": {"baseline", "bypass_attempt", "control"},
    "session_reuse": {"original_session", "reused_session"},
    "injection_execution": {"baseline", "payload", "observed_effect"},
    "server_side_request": {"trigger", "callback"},
    "network_reachability": {"source_context", "reached_target"},
    "privilege_transition": {"before_context", "after_context"},
}


@dataclass
class ProfileCheck:
    profile: str
    complete: bool
    missing: list[str]


def required_components(profile: str) -> set[str]:
    if profile not in _REQUIRED:
        raise KeyError(f"unknown evidence profile: {profile}")
    return set(_REQUIRED[profile])


def check_profile(profile: str, captured_components: set[str]) -> ProfileCheck:
    """Deterministic completeness check for a profile."""
    required = required_components(profile)
    missing = sorted(required - set(captured_components))
    return ProfileCheck(profile=profile, complete=not missing, missing=missing)
