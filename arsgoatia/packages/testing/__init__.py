"""ArsGoatia testing utilities — factories, fixtures, and assertion helpers.

Provides deterministic builders for domain objects, contracts, and evidence
so tests stay focused on behavior, not construction boilerplate.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import UUID, uuid4

# ---------------------------------------------------------------------------
# Deterministic UUID factory (sequential for readability in test output)
# ---------------------------------------------------------------------------


class UUIDFactory:
    def __init__(self, start: int = 1) -> None:
        self._counter = start

    def next(self) -> UUID:
        val = self._counter
        self._counter += 1
        return UUID(int=val)


_default_factory = UUIDFactory()


def fresh_uuid() -> UUID:
    return uuid4()


def sequential_uuid(n: int | None = None) -> UUID:
    if n is not None:
        return UUID(int=n)
    return _default_factory.next()


# ---------------------------------------------------------------------------
# Time helpers
# ---------------------------------------------------------------------------


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def hours_ago(n: int) -> datetime:
    return datetime.now(timezone.utc) - timedelta(hours=n)


def hours_from_now(n: int) -> datetime:
    return datetime.now(timezone.utc) + timedelta(hours=n)


def minutes_from_now(n: int) -> datetime:
    return datetime.now(timezone.utc) + timedelta(minutes=n)


# ---------------------------------------------------------------------------
# Engagement factory
# ---------------------------------------------------------------------------


def build_engagement(**overrides: Any) -> dict[str, Any]:
    now = utcnow()
    base: dict[str, Any] = {
        "id": fresh_uuid(),
        "tenant_id": fresh_uuid(),
        "name": "test-engagement",
        "state": "draft",
        "authorization_artifact_digest": "sha256:testdigest",
        "valid_from": now,
        "valid_until": now + timedelta(days=7),
        "scope_rules": [],
        "allowed_risk_tiers": ["R0", "R1", "R2"],
        "budget": {"requests": 50000, "ai_cost_usd": 25},
        "created_at": now,
        "created_by": "test-actor",
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# Action factory
# ---------------------------------------------------------------------------


def build_action(**overrides: Any) -> dict[str, Any]:
    now = utcnow()
    base: dict[str, Any] = {
        "id": fresh_uuid(),
        "tenant_id": fresh_uuid(),
        "engagement_id": fresh_uuid(),
        "technique_id": "web.authz.bola.differential",
        "target_locator": "https://api.test/basket/1",
        "risk_tier": "R2",
        "mutation_class": "none",
        "state": "proposed",
        "parameters": {},
        "access_context_ids": [],
        "created_at": now,
        "created_by": "test-actor",
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# Scope rule factory
# ---------------------------------------------------------------------------


def build_scope_rule(
    rule_type: str = "dns_suffix",
    value: str = "apps.example.test",
    action: str = "allow",
    ports: list[int] | None = None,
) -> dict[str, Any]:
    return {
        "type": rule_type,
        "value": value,
        "action": action,
        "ports": ports or [80, 443],
    }


# ---------------------------------------------------------------------------
# Envelope factory
# ---------------------------------------------------------------------------


def build_envelope(**overrides: Any) -> dict[str, Any]:
    now = utcnow()
    base: dict[str, Any] = {
        "actionId": str(fresh_uuid()),
        "tenantId": str(fresh_uuid()),
        "engagementRevisionId": str(fresh_uuid()),
        "technique": {"id": "web.authz.bola.differential", "version": "1.0.0"},
        "target": {"locator": "https://api.test/basket/1"},
        "effectiveRiskTier": "R2",
        "nonce": uuid4().hex,
        "expiresAt": (now + timedelta(minutes=5)).isoformat(),
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# Evidence factory
# ---------------------------------------------------------------------------


def build_evidence_data(
    content: str = "test evidence content",
    media_type: str = "application/json",
) -> tuple[bytes, str]:
    return content.encode(), media_type


def build_evidence_metadata(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "action_id": str(fresh_uuid()),
        "kind": "http_exchange",
        "label": "baseline_request",
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# Hypothesis factory
# ---------------------------------------------------------------------------


def build_hypothesis(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "id": fresh_uuid(),
        "tenant_id": fresh_uuid(),
        "engagement_id": fresh_uuid(),
        "category": "authorization.object_level",
        "description": "Object-level authorization bypass on basket endpoint",
        "state": "OPEN",
        "confidence": 0.0,
        "supporting_observations": [],
        "refuting_observations": [],
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# Finding factory
# ---------------------------------------------------------------------------


def build_finding(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "id": fresh_uuid(),
        "tenant_id": fresh_uuid(),
        "engagement_id": fresh_uuid(),
        "title": "BOLA on /rest/basket/{id}",
        "state": "CANDIDATE",
        "severity": "high",
        "cwe": "CWE-639",
        "technique_id": "web.authz.bola.differential",
        "evidence_digests": [],
        "capability_ids": [],
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# IAM factory
# ---------------------------------------------------------------------------


def build_principal(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "id": fresh_uuid(),
        "tenant_id": fresh_uuid(),
        "principal_type": "USER",
        "name": "test-user",
        "roles": frozenset({"OPERATOR"}),
        "teams": frozenset(),
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# Assertion helpers
# ---------------------------------------------------------------------------


def assert_event_emitted(events: list[Any], event_type: str, **field_checks: Any) -> None:
    matching = [e for e in events if getattr(e, "event_type", None) == event_type]
    assert matching, f"no event of type {event_type!r} found"
    if field_checks:
        event = matching[0]
        for k, v in field_checks.items():
            actual = getattr(event, k, None)
            if actual is None and hasattr(event, "payload"):
                actual = event.payload.get(k)
            assert actual == v, f"event.{k} = {actual!r}, expected {v!r}"


def assert_audit_recorded(
    entries: list[Any], action: str, resource_type: str | None = None
) -> None:
    matching = [e for e in entries if getattr(e, "action", None) == action]
    assert matching, f"no audit entry with action {action!r} found"
    if resource_type:
        assert any(getattr(e, "resource_type", None) == resource_type for e in matching), (
            f"no audit entry for resource_type {resource_type!r}"
        )


def assert_no_secrets_in_dict(d: dict[str, Any], path: str = "") -> None:
    import re

    secret_patterns = [
        re.compile(r"eyJ[A-Za-z0-9_-]{10,}"),  # JWT
        re.compile(r"Bearer\s+\S{10,}"),
        re.compile(r"(?:password|secret|token)\s*[:=]\s*\S+", re.IGNORECASE),
    ]
    for k, v in d.items():
        current = f"{path}.{k}" if path else k
        if isinstance(v, str):
            for pat in secret_patterns:
                assert not pat.search(v), (
                    f"possible secret at {current}: matched pattern {pat.pattern}"
                )
        elif isinstance(v, dict):
            assert_no_secrets_in_dict(v, current)
        elif isinstance(v, list):
            for i, item in enumerate(v):
                if isinstance(item, dict):
                    assert_no_secrets_in_dict(item, f"{current}[{i}]")
                elif isinstance(item, str):
                    for pat in secret_patterns:
                        assert not pat.search(item), (
                            f"possible secret at {current}[{i}]: matched {pat.pattern}"
                        )
