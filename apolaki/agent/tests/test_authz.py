"""Tests for the Differential Authorization Engine (authz.build_matrix)."""
from __future__ import annotations

import authz


def test_bola_idor_detected():
    cells = [
        {"request": "GET /basket/1", "role": "userA", "rank": 1, "owner": "userA",
         "status": 200, "body": '{"id":1,"items":["x"]}'},
        {"request": "GET /basket/1", "role": "userB", "rank": 1, "owner": "userA",
         "status": 200, "body": '{"id":1,"items":["x"]}'},   # userB got userA's object
    ]
    r = authz.build_matrix(cells)
    assert any(g["type"] == "bola_idor" and "userB" in g["roles"] for g in r["gaps"])


def test_missing_authentication_detected():
    cells = [
        {"request": "GET /rest/user/me", "role": "anon", "rank": 0, "status": 200, "body": '{"email":"a@x"}'},
        {"request": "GET /rest/user/me", "role": "userA", "rank": 1, "status": 200, "body": '{"email":"a@x"}'},
    ]
    r = authz.build_matrix(cells)
    assert any(g["type"] == "missing_authentication" for g in r["gaps"])


def test_bfla_detected_on_privileged_route():
    cells = [
        {"request": "GET /admin/users", "role": "userA", "rank": 1, "status": 200, "body": '[{"u":"x"}]'},
        {"request": "GET /admin/users", "role": "admin", "rank": 2, "status": 200, "body": '[{"u":"x"}]'},
    ]
    r = authz.build_matrix(cells)
    assert any(g["type"] == "bfla" and "userA" in g["roles"] for g in r["gaps"])


def test_bfla_not_flagged_when_anonymous_can_access():
    # a public endpoint whose path merely LOOKS privileged (anonymous can reach it) must NOT be
    # reported as BFLA — it's missing_authentication. (Regression from a live Juice Shop run.)
    cells = [
        {"request": "GET /admin/stats", "role": "anon", "rank": 0, "status": 200, "body": "public stats"},
        {"request": "GET /admin/stats", "role": "userA", "rank": 1, "status": 200, "body": "public stats"},
    ]
    r = authz.build_matrix(cells)
    assert not any(g["type"] == "bfla" for g in r["gaps"])                    # not a privilege bug
    assert any(g["type"] == "missing_authentication" for g in r["gaps"])      # it's missing-auth


def test_cross_tenant_detected():
    cells = [
        {"request": "GET /doc/9", "role": "tAuser", "rank": 1, "owner": "tBuser", "tenant": "A",
         "status": 200, "body": "secret"},
        {"request": "GET /doc/9", "role": "tBuser", "rank": 1, "owner": "tBuser", "tenant": "B",
         "status": 200, "body": "secret"},
    ]
    r = authz.build_matrix(cells)
    assert any(g["type"] == "cross_tenant" for g in r["gaps"])


def test_proper_authz_no_gap():
    # owner accesses own object; the other role is correctly denied -> no gap
    cells = [
        {"request": "GET /basket/1", "role": "userA", "rank": 1, "owner": "userA", "status": 200, "body": '{"id":1}'},
        {"request": "GET /basket/1", "role": "userB", "rank": 1, "owner": "userA", "status": 403, "body": "Forbidden"},
    ]
    r = authz.build_matrix(cells)
    assert r["gaps"] == []


def test_matrix_shape():
    cells = [{"request": "GET /x", "role": "anon", "rank": 0, "status": 401, "body": "Unauthorized"}]
    r = authz.build_matrix(cells)
    assert r["matrix"]["GET /x"]["anon"]["access"] is False and r["gaps"] == []
