"""field_authz wired into the authz matrix (Codex #9 integration): build_matrix now emits
excessive_data_exposure gaps when a role's response body leaks sensitive/admin fields — distinct from BOLA."""
import json

import authz


def _cell(request, role, rank, body, owner=None, status=200):
    return {"request": request, "role": role, "rank": rank, "status": status,
            "body": json.dumps(body), "owner": owner}


def test_matrix_emits_excessive_data_exposure_gap():
    cells = [_cell("GET /me", "user", 1, {"id": 1, "name": "Bob", "is_admin": False, "password_hash": "x"},
                   owner="user")]
    res = authz.build_matrix(cells)
    ede = [g for g in res["gaps"] if g["type"] == "excessive_data_exposure"]
    assert ede and "is_admin" in ede[0]["exposed_fields"] and "password_hash" in ede[0]["exposed_fields"]


def test_no_gap_for_clean_body():
    cells = [_cell("GET /me", "user", 1, {"id": 1, "name": "Bob"}, owner="user")]
    res = authz.build_matrix(cells)
    assert not any(g["type"] == "excessive_data_exposure" for g in res["gaps"])


def test_lower_privileged_role_is_flagged_field_level():
    cells = [_cell("GET /o/1", "user", 1, {"id": 1, "role": "user", "is_admin": False}, owner="user"),
             _cell("GET /o/1", "admin", 2, {"id": 1, "role": "admin", "is_admin": True}, owner="admin")]
    res = authz.build_matrix(cells)
    ede = [g for g in res["gaps"] if g["type"] == "excessive_data_exposure" and g["roles"] == ["user"]]
    assert ede and "field-level authorization gap" in ede[0]["evidence"]


def test_non_json_body_is_ignored():
    cells = [{"request": "GET /x", "role": "user", "rank": 1, "status": 200,
              "body": "<html>ok</html>", "owner": "user"}]
    res = authz.build_matrix(cells)
    assert not any(g["type"] == "excessive_data_exposure" for g in res["gaps"])
