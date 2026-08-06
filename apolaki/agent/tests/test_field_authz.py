"""Field-level authorization / excessive-data-exposure diffing (Codex Tier-2 #9): distinct from BOLA;
same-role no finding; lower role receiving an admin/secret field is flagged; secrets redacted."""
import field_authz as F


def test_same_role_same_object_no_finding():
    resp = {"id": 1, "name": "Alice", "email": "a@x.com"}
    assert F.field_authz_diff(resp, resp, low_role="user", high_role="user") == []


def test_lower_role_receives_admin_only_field_is_flagged():
    low = {"id": 1, "name": "Bob", "is_admin": False, "role": "user"}
    high = {"id": 1, "name": "Bob", "is_admin": True, "role": "admin"}
    res = F.field_authz_diff(low, high, low_role="user", high_role="admin")
    fields = {r["field"] for r in res}
    assert "is_admin" in fields and "role" in fields
    assert all(r["family"] == "field_level_authorization" for r in res)
    # a hard admin marker for a non-admin low role is a finding
    assert any(r["confidence"] == "finding" for r in res)


def test_anonymous_public_resource_public_fields_no_bola():
    # only public fields -> nothing flagged, and it is NOT treated as BOLA
    pub = {"id": 42, "title": "Public post", "author": "someone"}
    assert F.excessive_data_exposure(pub, authenticated=False, own_resource=False) is None


def test_sensitive_debug_fields_are_excessive_data_exposure():
    resp = {"id": 1, "user": "x", "debug": {"sql": "SELECT * FROM users", "stack": "at handler:42"}}
    obs = F.excessive_data_exposure(resp)
    assert obs["family"] == "excessive_data_exposure" and obs["own_resource"] is True
    cats = {e["category"] for e in obs["exposed_fields"]}
    assert "debug" in cats


def test_secret_values_are_redacted():
    resp = {"id": 1, "password_hash": "verysecretbcrypthashvalue", "api_key": "sk_live_ABCDEFGH123456"}
    obs = F.excessive_data_exposure(resp)
    blob = str(obs)
    assert "verysecretbcrypthashvalue" not in blob and "sk_live_ABCDEFGH123456" not in blob
    assert obs["severity"] == "high"                      # secret present -> high
    # differential path redacts too
    res = F.field_authz_diff(resp, {}, low_role="user", high_role="admin")
    assert all("verysecretbcrypthashvalue" not in str(r) for r in res)


def test_excessive_exposure_is_distinct_from_bola():
    # own_resource True means field exposure is NOT cross-object access
    resp = {"id": 1, "ssn": "123-45-6789"}
    obs = F.excessive_data_exposure(resp, own_resource=True)
    assert obs["own_resource"] is True and "BOLA" in obs["note"]


def test_nested_fields_are_detected():
    resp = {"user": {"profile": {"is_admin": True}}}
    obs = F.excessive_data_exposure(resp)
    assert any(e["field"].endswith("is_admin") for e in obs["exposed_fields"])
