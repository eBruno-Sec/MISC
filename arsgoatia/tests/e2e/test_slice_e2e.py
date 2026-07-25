"""End-to-end lab test (§37, §39).

Drives the control-plane API against a running `docker compose --profile lab`
stack through the full slice: authorized assessment -> scope -> start -> approval
gate -> confirmed IDOR finding -> read_foreign_object capability -> attack-chain
step -> reports. Skipped unless the API is reachable (a dedicated CI job brings
the stack up).
"""

from __future__ import annotations

import os
import time

import pytest

httpx = pytest.importorskip("httpx")

API = os.getenv("ARSGOATIA_API_URL", "http://localhost:8080")


def _reachable() -> bool:
    try:
        return httpx.get(f"{API}/healthz", timeout=2).status_code == 200
    except Exception:  # noqa: BLE001
        return False


pytestmark = pytest.mark.skipif(not _reachable(), reason="ArsGoatia API not reachable")


def _poll_state(client, tenant, aid, timeout=180):
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        r = client.get(f"{API}/api/v1/assessments/{aid}", headers={"X-Tenant-Id": tenant})
        last = r.json()
        wf = last.get("workflow") or {}
        if wf.get("pending_approval") or last.get("lifecycle_state") in {"COMPLETED", "REVIEW"}:
            return last
        time.sleep(2)
    return last


def test_full_idor_slice_against_juice_shop():
    with httpx.Client(timeout=30) as client:
        tenant = client.post(f"{API}/api/v1/tenants", json={"name": "e2e"}).json()["id"]
        h = {"X-Tenant-Id": tenant}

        aid = client.post(
            f"{API}/api/v1/assessments", headers=h, json={"name": "e2e-idor", "assessment_types": ["web"]}
        ).json()["id"]

        client.post(
            f"{API}/api/v1/assessments/{aid}/authorize",
            headers=h,
            json={
                "authorizing_party": "lab",
                "authorized_testing_types": ["web"],
                "valid_from": "2020-01-01T00:00:00Z",
                "valid_until": "2999-01-01T00:00:00Z",
            },
        )
        client.post(
            f"{API}/api/v1/assessments/{aid}/compile-scope",
            headers=h,
            json={"targets": [{"kind": "hostname", "value": "juice-shop:3000"}]},
        )
        client.post(f"{API}/api/v1/assessments/{aid}/start", headers=h)

        # Wait for the action-bound approval gate, then approve.
        state = _poll_state(client, tenant, aid)
        wf = (state or {}).get("workflow") or {}
        if wf.get("pending_approval"):
            client.post(
                f"{API}/api/v1/assessments/{aid}/approvals",
                headers=h,
                json={"action_id": wf["pending_approval"], "granted": True, "resolver": "e2e"},
            )

        # Wait for completion.
        deadline = time.time() + 180
        while time.time() < deadline:
            s = client.get(f"{API}/api/v1/assessments/{aid}", headers=h).json()
            if s.get("lifecycle_state") in {"COMPLETED", "REVIEW"}:
                break
            time.sleep(3)

        findings = client.get(f"{API}/api/v1/assessments/{aid}/findings", headers=h).json()
        caps = client.get(f"{API}/api/v1/assessments/{aid}/capabilities", headers=h).json()
        reports = client.get(f"{API}/api/v1/assessments/{aid}/reports", headers=h).json()
        evidence = client.get(f"{API}/api/v1/assessments/{aid}/evidence", headers=h).json()

        assert any(f["internal_class"] == "authorization.object_level" for f in findings)
        assert any(c.get("label") == "read_foreign_object" for c in caps)
        assert len(reports) >= 1
        assert len(evidence) >= 1
