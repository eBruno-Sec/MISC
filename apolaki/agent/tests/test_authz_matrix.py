"""Authorization-matrix orchestration helpers (pure): object-operation extraction + gap->finding
mapping. The differential analysis itself is authz.build_matrix (tested in test_authz.py)."""
from __future__ import annotations

import authz
import authz_matrix as AM


def test_candidate_operations_picks_object_endpoints():
    urls = [
        "https://t/rest/products",             # list, no id -> skip
        "https://t/login",                     # not object -> skip
        "https://t/api/orders/1",              # object
        "https://t/api/orders/2",              # same shape -> dedup
        "https://t/users/42/profile",          # object
        "https://t/api/basket/9c1f2a3b4d5e6f70",  # long-hex id -> object
    ]
    ops = AM.candidate_operations(urls)
    keys = {o["object_key"] for o in ops}
    assert "orders" in keys and "users" in keys and "basket" in keys
    # dedup: only one orders operation despite two urls
    assert sum(1 for o in ops if o["object_key"] == "orders") == 1
    assert all(o["method"] == "GET" for o in ops)


def test_is_object_path():
    assert AM.is_object_path("/api/orders/1")
    assert AM.is_object_path("/users/550e8400-e29b-41d4-a716-446655440000")
    assert not AM.is_object_path("/api/products")
    assert not AM.is_object_path("/login")


def test_gaps_to_findings_maps_types():
    result = {"gaps": [
        {"type": "missing_authentication", "request": "/api/orders/1", "severity": "high",
         "roles": ["anonymous"], "evidence": "reachable with NO authentication"},
        {"type": "bfla", "request": "/admin/users", "severity": "high",
         "roles": ["user_a"], "evidence": "privileged function reached by user_a"},
        {"type": "cross_tenant", "request": "/api/orders/7", "severity": "critical",
         "roles": ["tenant_b_user"], "evidence": "tenant B read tenant A data"},
    ]}
    fs = AM.gaps_to_findings(result, base_url="https://t")
    conf_by_cwe = {f["cwe"]: f["confidence"] for f in fs}
    # heuristic signals are LEADS (CHAD #2/#4); only tenant/ownership-evidenced gaps are confirmed
    assert conf_by_cwe["CWE-306"] == "lead"          # missing-auth: may be public by design
    assert conf_by_cwe["CWE-285"] == "lead"          # bfla: may be the user's own resource
    assert conf_by_cwe["CWE-639"] == "confirmed"     # cross-tenant: carries tenant evidence
    assert all(f["target"].startswith("https://t/") for f in fs)


def test_public_endpoint_is_not_a_finding():
    # anonymous accesses a page but NO authed role differs -> build_matrix yields no gap ->
    # gaps_to_findings yields nothing. A public endpoint must never become an access-control bug.
    cells = [
        {"request": "/api/products", "role": "anonymous", "rank": 0, "status": 200, "body": "PUBLIC LIST"},
    ]
    result = authz.build_matrix(cells)
    assert AM.gaps_to_findings(result) == []


def test_missing_auth_is_a_lead_not_a_confirmed_high():
    # anon + an authed user get the SAME data — but identical data could be a legitimately PUBLIC
    # resource, so this is a LEAD needing data-comparison confirmation, NOT a confirmed High (CHAD #2).
    cells = [
        {"request": "/api/orders/1", "role": "anonymous", "rank": 0, "status": 200, "body": "ORDER#1 data"},
        {"request": "/api/orders/1", "role": "user_a", "rank": 1, "status": 200, "body": "ORDER#1 data"},
    ]
    result = authz.build_matrix(cells)
    fs = AM.gaps_to_findings(result, base_url="https://t")
    assert len(fs) == 1 and fs[0]["cwe"] == "CWE-306"
    assert fs[0]["confidence"] == "lead" and fs[0]["severity"] == "medium"
