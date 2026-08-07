"""Read-only cross-user object IDOR/BOLA (general): ownership differential over per-user collections,
zero false-positive (public collections share ids -> nothing flagged)."""
import json

import read_object_idor as R


def test_extract_ids_handles_list_and_envelopes():
    assert R.extract_ids(json.dumps([{"id": 1}, {"id": 2}])) == {"1", "2"}
    assert R.extract_ids(json.dumps({"status": "ok", "data": [{"id": 7}, {"_id": "abc"}]})) == {"7", "abc"}
    assert R.extract_ids("not json") == set()


def test_owner_only_ids_is_the_differential():
    owner = json.dumps({"data": [{"id": 1}, {"id": 2}, {"id": 3}]})
    attacker = json.dumps({"data": [{"id": 3}]})           # attacker only legitimately sees 3
    assert R.owner_only_ids(owner, attacker) == ["1", "2"]  # 1,2 are provably owner-owned


def test_public_collection_yields_no_owner_only():
    both = json.dumps({"data": [{"id": 1}, {"id": 2}]})     # same ids for both = public/shared
    assert R.owner_only_ids(both, both) == []               # nothing to test -> zero false positive


def test_confirm_read_requires_2xx_and_id_in_body():
    assert R.confirm_read(200, json.dumps({"id": "1", "secret": "x"}), "1") is True
    assert R.confirm_read(401, json.dumps({"id": "1"}), "1") is False        # blocked
    assert R.confirm_read(200, json.dumps({"error": "not found"}), "1") is False  # 2xx but no object
    assert R.confirm_read(404, "", "1") is False


def test_finding_is_confirmed_bola():
    f = R.finding("/api/Addresss", "5", "user_a", "user_b", "http://app/api/Addresss/5")
    assert f["confidence"] == "confirmed" and f["family"] == "idor" and f["cwe"] == "CWE-639"
    assert "cross-user" in f["description"].lower()


def test_foreign_sensitive_read_confirms_cross_user_secret():
    body = json.dumps({"book_title": "b1", "owner": "alice", "secret": "TOPSECRET"})
    hit = R.foreign_sensitive_read(200, body, "bob")          # bob reading alice's secret
    assert hit and hit["owner"] == "alice" and "secret" in hit["sensitive_fields"]


def test_foreign_sensitive_read_zero_fp():
    own = json.dumps({"book_title": "b1", "owner": "bob", "secret": "x"})
    assert R.foreign_sensitive_read(200, own, "bob") is None   # reading your OWN object is not BOLA
    nosec = json.dumps({"book_title": "b1", "owner": "alice"})
    assert R.foreign_sensitive_read(200, nosec, "bob") is None # no sensitive field -> not flagged
    assert R.foreign_sensitive_read(401, json.dumps({"owner": "alice", "secret": "x"}), "bob") is None


def test_extract_ids_natural_key_fallback():
    assert R.extract_ids(json.dumps({"Books": [{"book_title": "t1"}, {"book_title": "t2"}]})) == {"t1", "t2"}
