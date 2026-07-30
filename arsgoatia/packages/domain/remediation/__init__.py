from __future__ import annotations

import enum
from dataclasses import dataclass
from datetime import datetime
from uuid import UUID


class RemediationState(enum.Enum):
    PROPOSED = "proposed"
    DIFF_READY = "diff_ready"
    DIFF_APPROVED = "diff_approved"
    TESTING = "testing"
    TESTS_PASSED = "tests_passed"
    TESTS_FAILED = "tests_failed"
    COMMIT_APPROVED = "commit_approved"
    COMMITTED = "committed"
    PR_CREATED = "pr_created"
    REJECTED = "rejected"
    EXPIRED = "expired"


REMEDIATION_TRANSITIONS: dict[RemediationState, frozenset[RemediationState]] = {
    RemediationState.PROPOSED: frozenset(
        {RemediationState.DIFF_READY, RemediationState.REJECTED, RemediationState.EXPIRED}
    ),
    RemediationState.DIFF_READY: frozenset(
        {RemediationState.DIFF_APPROVED, RemediationState.REJECTED}
    ),
    RemediationState.DIFF_APPROVED: frozenset(
        {RemediationState.TESTING, RemediationState.REJECTED}
    ),
    RemediationState.TESTING: frozenset(
        {RemediationState.TESTS_PASSED, RemediationState.TESTS_FAILED}
    ),
    RemediationState.TESTS_PASSED: frozenset(
        {RemediationState.COMMIT_APPROVED, RemediationState.REJECTED}
    ),
    RemediationState.TESTS_FAILED: frozenset(
        {RemediationState.DIFF_READY, RemediationState.REJECTED}
    ),
    RemediationState.COMMIT_APPROVED: frozenset(
        {RemediationState.COMMITTED, RemediationState.REJECTED}
    ),
    RemediationState.COMMITTED: frozenset({RemediationState.PR_CREATED}),
    RemediationState.PR_CREATED: frozenset(),
    RemediationState.REJECTED: frozenset(),
    RemediationState.EXPIRED: frozenset(),
}


@dataclass(frozen=True)
class RemediationChange:
    id: UUID
    tenant_id: UUID
    finding_id: UUID
    repository_scope: str
    base_commit: str
    proposed_diff: str
    test_results: dict | None
    approval_id: UUID | None
    state: RemediationState
    created_at: datetime


def can_transition(current: RemediationState, target: RemediationState) -> bool:
    return target in REMEDIATION_TRANSITIONS.get(current, frozenset())


def validate_no_force_push(branch: str, protected_branches: set[str]) -> bool:
    return branch not in protected_branches
