"""Pure repository helpers (revision numbering, lab-safe policy matrix)."""

from __future__ import annotations

from domain.repositories import default_lab_safe_rules, next_revision_number


def test_next_revision_number():
    assert next_revision_number(None) == 1
    assert next_revision_number(1) == 2
    assert next_revision_number(7) == 8


def test_lab_safe_matrix_requires_approval_for_r2_and_denies_high_risk():
    rules = default_lab_safe_rules()
    matrix = rules["risk_class_decisions"]
    # The IDOR differential is R2 — it must require action-bound approval so the
    # slice exercises the HITL gate.
    assert matrix["R2"] == "require_approval"
    assert rules["required_approval_class"]["R2"] == "normal"
    assert matrix["R4"] == "deny"
    assert matrix["R5"] == "deny"
    # lab-safe is read-only: no mutations allowed by default.
    assert rules["limits"]["max_mutations"] == 0
