"""Identity-bootstrap pure helpers."""

from __future__ import annotations

from temporal.workflows.activities.identity_probe import default_identities, parse_login


def test_default_identities_are_two_distinct_standard_users():
    ids = default_identities("assessment-xyz", count=2)
    assert len(ids) == 2
    assert ids[0]["email"] != ids[1]["email"]
    assert all(i["privilege_label"] == "standard_user" for i in ids)
    # Deterministic per assessment.
    assert default_identities("assessment-xyz", count=2) == ids
    # Different assessment -> different credentials.
    assert default_identities("other", count=2) != ids


def test_parse_login_extracts_token_and_object_id():
    token, obj = parse_login({"authentication": {"token": "jwt-123", "bid": 7, "umail": "a@b"}})
    assert token == "jwt-123"
    assert obj == "7"

    none_token, none_obj = parse_login({})
    assert none_token is None and none_obj is None
