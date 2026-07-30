"""Deterministic constraint solver (§1.3, §8.4). Fail-closed."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from reasoning.constraints import ActionCandidate, ConstraintContext, ConstraintSolver
from scope.firewall import ScopeFirewall

from packages.contracts.schemas.engagement import ScopeRule, ScopeSpec


def _ctx(**over) -> ConstraintContext:
    base = dict(
        firewall=ScopeFirewall(
            ScopeSpec(include=[ScopeRule(type="exact_host", value="juice-shop:3000")])
        ),
        max_rps=2.0,
        max_requests_remaining=500,
        allow_mutation=False,
        max_data_sensitivity="confidential",
    )
    base.update(over)
    return ConstraintContext(**base)


def _candidate(**over) -> ActionCandidate:
    base = dict(
        action_class="authorization.object_level",
        destination="juice-shop:3000",
        risk_class="R1",
        mutation=False,
        estimated_requests=4,
        estimated_rps=2.0,
        data_sensitivity="internal",
        requires_approval=False,
        approval_present=False,
    )
    base.update(over)
    return ActionCandidate(**base)


def test_allowed_candidate_passes():
    assert ConstraintSolver().check(_candidate(), _ctx()).satisfied is True


def test_out_of_scope_rejected():
    r = ConstraintSolver().check(_candidate(destination="evil.example.com"), _ctx())
    assert r.satisfied is False and "scope" in r.violations


def test_r5_prohibited():
    r = ConstraintSolver().check(_candidate(risk_class="R5"), _ctx())
    assert r.satisfied is False and "risk_class" in r.violations


def test_mutation_blocked_without_allowance():
    r = ConstraintSolver().check(_candidate(mutation=True), _ctx(allow_mutation=False))
    assert "mutation_not_allowed" in r.violations
    assert ConstraintSolver().check(_candidate(mutation=True), _ctx(allow_mutation=True)).satisfied


def test_rate_and_budget():
    assert "rate_limit" in ConstraintSolver().check(_candidate(estimated_rps=10), _ctx()).violations
    assert (
        "request_budget"
        in ConstraintSolver().check(_candidate(estimated_requests=9999), _ctx()).violations
    )


def test_data_sensitivity_limit():
    r = ConstraintSolver().check(
        _candidate(data_sensitivity="secret"), _ctx(max_data_sensitivity="confidential")
    )
    assert "data_sensitivity" in r.violations


def test_required_approval_must_be_present():
    r = ConstraintSolver().check(_candidate(requires_approval=True, approval_present=False), _ctx())
    assert "approval_required" in r.violations
    ok = ConstraintSolver().check(_candidate(requires_approval=True, approval_present=True), _ctx())
    assert ok.satisfied is True


def test_time_window_fails_closed_and_enforces():
    now = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
    ctx = _ctx(window_start=now, window_end=now + timedelta(hours=1))
    # Inside the window.
    inside = ConstraintSolver().check(_candidate(at_time=now + timedelta(minutes=10)), ctx)
    assert inside.satisfied is True
    # Outside the window.
    outside = ConstraintSolver().check(_candidate(at_time=now + timedelta(hours=2)), ctx)
    assert "time_window" in outside.violations
    # No time provided but a window is set -> fail closed.
    unknown = ConstraintSolver().check(_candidate(at_time=None), ctx)
    assert "time_window_unknown" in unknown.violations


def test_filter_partitions():
    solver = ConstraintSolver()
    allowed, rejected = solver.filter(
        [_candidate(), _candidate(destination="evil.example.com"), _candidate(risk_class="R5")],
        _ctx(),
    )
    assert len(allowed) == 1
    assert len(rejected) == 2
