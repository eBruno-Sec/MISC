from __future__ import annotations

import pytest

from packages.ai_gateway import (
    AIGateway,
    AIGatewayConfig,
    AIRequest,
    AIUnavailable,
    BudgetTracker,
    build_structured_prompt,
    redact_secrets_from_text,
)


def test_redact_bearer_token():
    text = "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig"
    redacted, labels = redact_secrets_from_text(text)
    assert "eyJ" not in redacted
    assert len(labels) > 0


def test_redact_basic_auth():
    text = "Authorization: Basic dXNlcjpwYXNzd29yZA=="
    redacted, labels = redact_secrets_from_text(text)
    assert "dXNlcjpwYXNz" not in redacted


def test_no_redaction_for_safe_text():
    text = "This is a normal response with no secrets."
    redacted, labels = redact_secrets_from_text(text)
    assert redacted == text
    assert labels == []


def test_budget_tracker():
    bt = BudgetTracker(limit_usd=10.0)
    assert bt.remaining() == 10.0
    assert not bt.is_exceeded()
    bt.record(7.0)
    assert bt.remaining() == 3.0
    bt.record(4.0)
    assert bt.is_exceeded()


def test_build_structured_prompt():
    config = AIGatewayConfig()
    request = AIRequest(role="hypothesis", prompt="Analyze this endpoint for BOLA")
    result = build_structured_prompt(request, config)
    assert isinstance(result, dict)


@pytest.mark.asyncio
async def test_gateway_raises_unavailable():
    config = AIGatewayConfig()
    gateway = AIGateway(config)
    request = AIRequest(role="hypothesis", prompt="test")
    with pytest.raises(AIUnavailable):
        await gateway.complete(request)


def test_gateway_budget_status():
    config = AIGatewayConfig(budget_limit_usd=5.0)
    gateway = AIGateway(config)
    status = gateway.get_budget_status()
    assert status["remaining_usd"] == 5.0
    assert not status["is_exceeded"]


def test_config_defaults():
    config = AIGatewayConfig()
    assert config.temperature == 0.0
    assert config.redact_secrets is True
    assert config.max_tokens == 4096
