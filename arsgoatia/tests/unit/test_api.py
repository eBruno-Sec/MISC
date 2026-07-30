"""Unit tests for the ArsGoatia API routers using FastAPI TestClient.

Database and auth dependencies are overridden so no Postgres connection is needed.
"""
from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, MagicMock
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient

from apps.api.main import app
from apps.api.deps import get_session, get_tenant_id, require_auth

# ---------------------------------------------------------------------------
# Dependency overrides
# ---------------------------------------------------------------------------

_TENANT_ID = uuid4()
_TEST_AUTH = {"user": "test-operator", "role": "operator", "source": "test"}


async def _override_tenant() -> UUID:
    return _TENANT_ID


async def _override_session():
    session = AsyncMock()
    yield session


async def _override_auth() -> dict:
    return _TEST_AUTH


TENANT_HDR = {"X-Tenant-Id": str(_TENANT_ID)}
TENANT_AUTH_HDR = {"X-Tenant-Id": str(_TENANT_ID), "X-Auth-User": "tester", "X-Auth-Role": "operator"}


@pytest.fixture(autouse=True)
def _override_deps():
    app.dependency_overrides[get_tenant_id] = _override_tenant
    app.dependency_overrides[get_session] = _override_session
    app.dependency_overrides[require_auth] = _override_auth
    yield
    app.dependency_overrides.clear()


@pytest.fixture()
def client():
    with TestClient(app, raise_server_exceptions=True) as c:
        yield c


# ---------------------------------------------------------------------------
# Health endpoint
# ---------------------------------------------------------------------------


class TestHealth:
    def test_health_ok(self, client):
        r = client.get("/health")
        assert r.status_code == 200
        body = r.json()
        assert body["status"] == "ok"
        assert body["service"] == "arsgoatia-api"


# ---------------------------------------------------------------------------
# Engagements
# ---------------------------------------------------------------------------


class TestCreateEngagement:
    def test_creates_engagement(self, client):
        r = client.post(
            "/api/v1/engagements",
            json={"name": "Juice Shop IDOR Assessment"},
            headers=TENANT_AUTH_HDR,
        )
        assert r.status_code == 201
        body = r.json()
        assert body["name"] == "Juice Shop IDOR Assessment"
        assert body["state"] == "DRAFT"
        assert "id" in body
        assert UUID(body["id"])

    def test_name_required(self, client):
        r = client.post("/api/v1/engagements", json={}, headers=TENANT_AUTH_HDR)
        assert r.status_code == 422

    def test_name_min_length(self, client):
        r = client.post("/api/v1/engagements", json={"name": ""}, headers=TENANT_AUTH_HDR)
        assert r.status_code == 422

    def test_scope_accepted(self, client):
        r = client.post(
            "/api/v1/engagements",
            json={
                "name": "Scoped Assessment",
                "scope": {
                    "include": [{"type": "exact_host", "value": "juice-shop"}],
                    "redirect_policy": "reject",
                },
            },
            headers=TENANT_AUTH_HDR,
        )
        assert r.status_code == 201
        body = r.json()
        assert body["scope"]["include"][0]["type"] == "exact_host"

    def test_tags_accepted(self, client):
        r = client.post(
            "/api/v1/engagements",
            json={"name": "Tagged", "tags": {"env": "lab", "team": "red"}},
            headers=TENANT_AUTH_HDR,
        )
        assert r.status_code == 201
        assert r.json()["tags"]["env"] == "lab"

    def test_idempotency_key_accepted(self, client):
        r = client.post(
            "/api/v1/engagements",
            json={"name": "Idempotent"},
            headers={**TENANT_AUTH_HDR, "Idempotency-Key": "unique-key-123"},
        )
        assert r.status_code == 201


class TestEngagementLifecycle:
    def _make_id(self):
        return uuid4()

    def test_create_revision(self, client):
        eid = self._make_id()
        r = client.post(f"/api/v1/engagements/{eid}/revisions", headers=TENANT_AUTH_HDR)
        assert r.status_code == 201
        body = r.json()
        assert body["engagement_id"] == str(eid)
        assert "revision_id" in body
        assert body["content_digest"].startswith("sha256:")

    def test_start_engagement(self, client):
        eid = self._make_id()
        r = client.post(f"/api/v1/engagements/{eid}:start", headers=TENANT_AUTH_HDR)
        assert r.status_code == 200
        assert r.json()["state"] == "RUNNING"

    def test_pause_engagement(self, client):
        eid = self._make_id()
        r = client.post(f"/api/v1/engagements/{eid}:pause", headers=TENANT_AUTH_HDR)
        assert r.status_code == 200
        assert r.json()["state"] == "PAUSED"

    def test_resume_engagement(self, client):
        eid = self._make_id()
        r = client.post(f"/api/v1/engagements/{eid}:resume", headers=TENANT_AUTH_HDR)
        assert r.status_code == 200
        assert r.json()["state"] == "RUNNING"

    def test_emergency_stop(self, client):
        eid = self._make_id()
        r = client.post(f"/api/v1/engagements/{eid}:emergency-stop", headers=TENANT_AUTH_HDR)
        assert r.status_code == 200
        assert r.json()["state"] == "STOPPING"

    def test_get_engagement(self, client):
        eid = self._make_id()
        r = client.get(f"/api/v1/engagements/{eid}", headers=TENANT_AUTH_HDR)
        assert r.status_code in (200, 404)

    def test_get_coverage(self, client):
        eid = self._make_id()
        r = client.get(f"/api/v1/engagements/{eid}/coverage", headers=TENANT_AUTH_HDR)
        assert r.status_code == 200
        body = r.json()
        assert "total_techniques" in body
        assert "covered" in body

    def test_list_engagements(self, client):
        r = client.get("/api/v1/engagements", headers=TENANT_AUTH_HDR)
        assert r.status_code == 200
        body = r.json()
        assert "items" in body
        assert "total" in body
        assert "offset" in body
        assert "limit" in body

    def test_list_engagements_pagination(self, client):
        r = client.get("/api/v1/engagements?offset=5&limit=10", headers=TENANT_AUTH_HDR)
        assert r.status_code == 200
        body = r.json()
        assert body["offset"] == 5
        assert body["limit"] == 10


class TestTenantIdRequired:
    def test_missing_tenant_returns_401(self, client):
        app.dependency_overrides.clear()
        r = client.post("/api/v1/engagements", json={"name": "Test"})
        assert r.status_code in (401, 422)
        app.dependency_overrides[get_tenant_id] = _override_tenant
        app.dependency_overrides[get_session] = _override_session
        app.dependency_overrides[require_auth] = _override_auth

    def test_invalid_tenant_uuid_returns_422(self, client):
        app.dependency_overrides.clear()
        r = client.post(
            "/api/v1/engagements",
            json={"name": "Test"},
            headers={"X-Tenant-Id": "not-a-uuid"},
        )
        # FastAPI-standard validation error code for a malformed request value.
        assert r.status_code == 422
        app.dependency_overrides[get_tenant_id] = _override_tenant
        app.dependency_overrides[get_session] = _override_session
        app.dependency_overrides[require_auth] = _override_auth


# ---------------------------------------------------------------------------
# Actions
# ---------------------------------------------------------------------------


class TestProposeAction:
    def test_propose_basic(self, client):
        r = client.post(
            "/api/v1/actions:propose",
            json={
                "engagement_id": str(uuid4()),
                "technique": "web.authz.bola.differential",
                "target": "http://juice-shop:3000/rest/basket/1",
                "risk_tier": "R2",
                "mutation_class": "none",
            },
            headers=TENANT_AUTH_HDR,
        )
        assert r.status_code == 201
        body = r.json()
        assert body["technique"] == "web.authz.bola.differential"
        assert body["state"] in ("PROPOSED", "PENDING_APPROVAL", "APPROVED")
        assert "policy_evaluation" in body
        assert "id" in body

    def test_propose_requires_technique(self, client):
        r = client.post(
            "/api/v1/actions:propose",
            json={
                "engagement_id": str(uuid4()),
                "technique": "",
                "target": "http://target/",
            },
            headers=TENANT_AUTH_HDR,
        )
        assert r.status_code == 422

    def test_propose_requires_target(self, client):
        r = client.post(
            "/api/v1/actions:propose",
            json={
                "engagement_id": str(uuid4()),
                "technique": "recon.http",
                "target": "",
            },
            headers=TENANT_AUTH_HDR,
        )
        assert r.status_code == 422

    def test_propose_with_parameters(self, client):
        r = client.post(
            "/api/v1/actions:propose",
            json={
                "engagement_id": str(uuid4()),
                "technique": "recon.http",
                "target": "http://target/",
                "parameters": {"depth": 2, "follow_redirects": False},
            },
            headers=TENANT_AUTH_HDR,
        )
        assert r.status_code == 201


class TestApproveAction:
    def test_approve_action(self, client):
        action_id = uuid4()
        r = client.post(
            f"/api/v1/actions/{action_id}:approve",
            json={"reason": "looks safe"},
            headers=TENANT_AUTH_HDR,
        )
        assert r.status_code == 200
        body = r.json()
        assert body["state"] in ("APPROVED",)
        assert "binding_digest" in body

    def test_reject_action(self, client):
        action_id = uuid4()
        r = client.post(
            f"/api/v1/actions/{action_id}:reject",
            json={"reason": "too risky"},
            headers=TENANT_AUTH_HDR,
        )
        assert r.status_code == 200
        body = r.json()
        assert body["state"] == "REJECTED"

    def test_cancel_action(self, client):
        action_id = uuid4()
        r = client.post(
            f"/api/v1/actions/{action_id}:cancel",
            json={},
            headers=TENANT_AUTH_HDR,
        )
        assert r.status_code == 200
        body = r.json()
        assert body["state"] == "CANCELLED"


# ---------------------------------------------------------------------------
# Evidence
# ---------------------------------------------------------------------------


class TestEvidence:
    def test_create_upload_grant(self, client):
        r = client.post(
            "/api/v1/evidence/uploads",
            json={
                "engagement_id": str(uuid4()),
                "action_id": str(uuid4()),
                "kind": "http_exchange",
                "media_type": "application/json",
            },
            headers=TENANT_AUTH_HDR,
        )
        assert r.status_code == 201
        body = r.json()
        assert "evidence_id" in body
        assert "upload_url" in body
        assert "expires_at" in body

    def test_get_evidence_metadata(self, client):
        evidence_id = uuid4()
        r = client.get(
            f"/api/v1/evidence/{evidence_id}",
            headers=TENANT_AUTH_HDR,
        )
        assert r.status_code in (200, 404)


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------


class TestFindings:
    def test_list_findings_empty(self, client):
        r = client.get("/api/v1/findings", headers=TENANT_AUTH_HDR)
        assert r.status_code == 200
        body = r.json()
        assert body["items"] == []
        assert body["total"] == 0

    def test_list_findings_engagement_filter(self, client):
        eid = uuid4()
        r = client.get(f"/api/v1/findings?engagement_id={eid}", headers=TENANT_AUTH_HDR)
        assert r.status_code == 200

    def test_list_findings_pagination(self, client):
        r = client.get("/api/v1/findings?offset=10&limit=25", headers=TENANT_AUTH_HDR)
        assert r.status_code == 200
        body = r.json()
        assert body["offset"] == 10
        assert body["limit"] == 25

    def test_accept_risk(self, client):
        fid = uuid4()
        r = client.post(
            f"/api/v1/findings/{fid}:accept-risk",
            json={"justification": "Business risk accepted after review"},
            headers=TENANT_AUTH_HDR,
        )
        assert r.status_code == 200
        body = r.json()
        assert body["state"] == "ACCEPTED_RISK"
        assert body["justification"] == "Business risk accepted after review"
        assert body["id"] == str(fid)

    def test_accept_risk_empty_justification(self, client):
        fid = uuid4()
        r = client.post(
            f"/api/v1/findings/{fid}:accept-risk",
            json={"justification": ""},
            headers=TENANT_AUTH_HDR,
        )
        assert r.status_code == 422

    def test_create_retest(self, client):
        fid = uuid4()
        r = client.post(
            f"/api/v1/findings/{fid}:retest",
            json={},
            headers=TENANT_AUTH_HDR,
        )
        assert r.status_code == 201
        body = r.json()
        assert body["finding_id"] == str(fid)
        assert body["state"] == "RETEST_PENDING"


# ---------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------


class TestReports:
    def test_create_report(self, client):
        r = client.post(
            "/api/v1/reports",
            json={
                "engagement_id": str(uuid4()),
                "title": "IDOR Assessment Report",
                "format": "html",
            },
            headers=TENANT_AUTH_HDR,
        )
        assert r.status_code == 201
        body = r.json()
        assert "id" in body
        assert body["title"] == "IDOR Assessment Report"

    def test_get_report_artifacts(self, client):
        rid = uuid4()
        r = client.get(f"/api/v1/reports/{rid}/artifacts", headers=TENANT_AUTH_HDR)
        assert r.status_code in (200, 404)


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------


class TestAudit:
    def test_list_audit_events(self, client):
        r = client.get("/api/v1/audit/events", headers=TENANT_AUTH_HDR)
        assert r.status_code == 200
        body = r.json()
        assert "items" in body
        assert "total" in body

    def test_list_audit_engagement_filter(self, client):
        eid = uuid4()
        r = client.get(f"/api/v1/audit/events?engagement_id={eid}", headers=TENANT_AUTH_HDR)
        assert r.status_code == 200
