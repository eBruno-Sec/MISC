"""E2E: full Juice Shop pentest slice via the API.

Real ArsGoatia stack must be running. Skipped otherwise. Uses only the
public HTTP surface (``ARSGOATIA_API_URL``); no direct DB or Temporal
calls, so this test also validates the operator-facing UX.
"""
from __future__ import annotations

import os
import time
import uuid

import httpx
import pytest

API_URL = os.environ.get("ARSGOATIA_API_URL", "").rstrip("/")
TIMEOUT_SECONDS = int(os.environ.get("ARSGOATIA_E2E_TIMEOUT", "300"))
POLL_INTERVAL = 3

pytestmark = pytest.mark.skipif(
    not API_URL,
    reason="ARSGOATIA_API_URL not set — E2E test requires a running stack",
)


@pytest.fixture(scope="module")
def tenant_id() -> str:
    return str(uuid.uuid4())


@pytest.fixture(scope="module")
def client(tenant_id: str) -> httpx.Client:
    return httpx.Client(
        base_url=f"{API_URL}/api/v1",
        headers={"X-Tenant-Id": tenant_id, "Content-Type": "application/json"},
        timeout=30.0,
    )


@pytest.fixture(scope="module")
def engagement_id(client: httpx.Client) -> str:
    r = client.post(
        "/engagements",
        json={
            "name": f"e2e juice shop {uuid.uuid4().hex[:6]}",
            "target_url": "http://juice-shop:3000",
            "scope": {"include": [{"type": "exact_host", "value": "juice-shop"}]},
            "rules": {"identity_count": 2, "allowed_risk_tiers": ["R0", "R1", "R2"]},
        },
    )
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["state"] == "DRAFT"
    assert body["target_url"] == "http://juice-shop:3000"
    return body["id"]


def _wait_for_terminal(client: httpx.Client, eid: str) -> dict:
    """Poll GET /engagements/{eid} until the workflow reaches a terminal state."""
    deadline = time.monotonic() + TIMEOUT_SECONDS
    last = None
    while time.monotonic() < deadline:
        r = client.get(f"/engagements/{eid}")
        r.raise_for_status()
        last = r.json()
        if last["state"] in ("COMPLETED", "FAILED"):
            return last
        time.sleep(POLL_INTERVAL)
    pytest.fail(f"engagement did not reach terminal state within {TIMEOUT_SECONDS}s: {last}")


def test_health_and_v1_health(client: httpx.Client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_engagement_visible_in_list(client: httpx.Client, engagement_id: str):
    r = client.get("/engagements")
    assert r.status_code == 200
    ids = [e["id"] for e in r.json()["items"]]
    assert engagement_id in ids


def test_start_engagement_launches_temporal_workflow(client: httpx.Client, engagement_id: str):
    r = client.post(f"/engagements/{engagement_id}:start")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["state"] == "RUNNING"
    assert body["temporal_workflow_id"] == f"eng-{engagement_id}"


def test_engagement_runs_to_completion(client: httpx.Client, engagement_id: str):
    final = _wait_for_terminal(client, engagement_id)
    assert final["state"] == "COMPLETED", (
        f"expected COMPLETED, got {final['state']}; workflow_state={final.get('workflow_state')}"
    )
    ws = final.get("workflow_state") or {}
    assert ws.get("progress_pct") == 100
    assert ws.get("phase") in ("completed", "finalized")


def test_evidence_persisted(client: httpx.Client, engagement_id: str):
    r = client.get("/evidence", params={"engagement_id": engagement_id, "limit": 500})
    assert r.status_code == 200
    total = r.json()["total"]
    assert total > 0, "expected engagement to have written evidence rows"
    # At least the four exchange kinds and the reports should be represented.
    kinds = {item["kind"] for item in r.json()["items"]}
    assert "report" in kinds


def test_reports_persisted_and_downloadable(client: httpx.Client, engagement_id: str):
    r = client.get("/reports", params={"engagement_id": engagement_id})
    assert r.status_code == 200
    reports = r.json()["items"]
    assert len(reports) >= 3
    formats = {rep["format"] for rep in reports}
    assert {"json", "html", "sarif"}.issubset(formats)

    # Download the JSON report and check it parses.
    jr = next(rep for rep in reports if rep["format"] == "json")
    dl = client.get(f"/reports/{jr['id']}/download")
    assert dl.status_code == 200
    assert dl.headers["content-type"].startswith("application/json")
    import json

    payload = json.loads(dl.content)
    assert payload["engagement_id"] == engagement_id


def test_audit_log_captured_lifecycle(client: httpx.Client, engagement_id: str):
    r = client.get("/audit/events", params={"engagement_id": engagement_id, "limit": 100})
    assert r.status_code == 200
    types = {ev["event_type"] for ev in r.json()["items"]}
    assert "engagement.created" in types
    assert "engagement.started" in types
