"""AI gateway: redaction, JSON extraction, budget, and deterministic fallback."""

from __future__ import annotations

import asyncio

from ai_gateway.gateway import AIGateway, BudgetLedger, extract_json, redact, validate_against_schema


def test_redact_masks_secrets():
    text = (
        "token eyJhbGciOiJIUzI1.abcDEF.sig here, "
        "Authorization: Bearer abc.def.ghi, password=hunter2"
    )
    out = redact(text)
    assert "eyJhbGciOiJIUzI1.abcDEF.sig" not in out
    assert "hunter2" not in out
    assert "abc.def.ghi" not in out


def test_extract_json_from_fenced_and_prose():
    assert extract_json('```json\n{"a": 1}\n```') == {"a": 1}
    assert extract_json('here you go: {"x": [1,2]} thanks') == {"x": [1, 2]}
    assert extract_json("no json here") is None


def test_validate_against_schema():
    schema = {"type": "object", "required": ["a"], "properties": {"a": {"type": "integer"}}}
    ok, _ = validate_against_schema({"a": 1}, schema)
    assert ok is True
    bad, _ = validate_against_schema({"a": "x"}, schema)
    assert bad is False


def test_budget_ledger():
    b = BudgetLedger(request_budget_usd=1, assessment_budget_usd=2, daily_budget_usd=5)
    assert b.can_spend(0.5) is True
    b.record(1.5)
    assert b.can_spend(1.0) is False  # would exceed assessment budget
    assert b.last_denied_reason == "assessment_budget"
    assert b.can_spend(2.0) is False  # exceeds per-request budget
    assert b.last_denied_reason == "request_budget"


def test_complete_structured_falls_back_without_ai_key(monkeypatch):
    # No AI key -> AIUnavailable -> deterministic fallback (AI is advisory).
    monkeypatch.delenv("AI_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    gw = AIGateway()
    schema = {"type": "object"}
    fallback = {"hypothesis_class": "authorization.object_level"}
    result, source = asyncio.run(
        gw.complete_structured(role="hypothesis", prompt="observations...", schema=schema, fallback=fallback)
    )
    assert result == fallback
    assert source.startswith("fallback:")
