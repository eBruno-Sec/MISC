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


def test_confirm_read_handles_numeric_detail_ids():
    """Defect #5 regression: a bare detail dict with a NUMERIC id (unquoted JSON) must confirm. The old
    ["\\b] char-class regex matched a quote/backspace, never a word boundary, so numeric ids were missed."""
    assert R.confirm_read(200, json.dumps({"id": 1, "secret": "x"}), "1") is True   # numeric id, bare dict
    assert R.confirm_read(200, {"id": 1, "secret": "x"}, "1") is True               # already-parsed dict
    assert R.confirm_read(200, json.dumps({"id": 12, "secret": "x"}), "1") is False  # 12 != 1, no substring FP
    assert R.confirm_read(200, json.dumps({"user_id": 1, "note": "hi"}), "1") is True  # id appears as a value


def test_finding_is_confirmed_bola():
    f = R.finding("/api/Addresss", "5", "user_a", "user_b", "http://app/api/Addresss/5")
    assert f["confidence"] == "confirmed" and f["family"] == "idor" and f["cwe"] == "CWE-639"
    assert "cross-user" in f["description"].lower()


def test_foreign_sensitive_read_confirms_cross_user_secret():
    body = json.dumps({"book_title": "b1", "owner": "alice", "secret": "TOPSECRET"})
    hit = R.foreign_sensitive_read(200, body, "bob")          # bob reading alice's secret (both name-scheme)
    assert hit and hit["owner"] == "alice" and "secret" in hit["sensitive_fields"]
    assert hit["confidence"] == "confirmed"                   # comparable schemes (name vs name) -> confirmed
    # accepts a SET/LIST of reader identifiers (email + username), not just a single string
    hit2 = R.foreign_sensitive_read(200, body, ["bob@x.com", "bob"])
    assert hit2 and hit2["confidence"] == "confirmed"


def test_foreign_sensitive_read_numeric_owner_email_reader_is_lead_not_confirmed():
    """Defect #4 regression (the zero-FP breaker): when the object's owner attribution is a NUMERIC id but
    the only reader identifiers we hold are email/username, we CANNOT prove the object is foreign — the old
    `owner != str(attacker_identity)` unconditionally CONFIRMED. Now it must be a LEAD, never a confirm."""
    body = json.dumps({"id": 9, "user_id": 2, "secret": "x"})
    hit = R.foreign_sensitive_read(200, body, ["bob@example.com", "bob"])   # no numeric id held for reader
    assert hit is not None and hit["confidence"] == "lead"                  # reported, but NOT confirmed
    # but if we DO hold the reader's numeric id, a DIFFERENT numeric owner is provably foreign -> confirmed
    hit2 = R.foreign_sensitive_read(200, body, ["bob@example.com", "5"])    # reader is #5, owner is #2
    assert hit2 and hit2["confidence"] == "confirmed"
    # and the reader's OWN numeric object is never flagged
    assert R.foreign_sensitive_read(200, body, ["2"]) is None


def test_foreign_sensitive_read_zero_fp():
    own = json.dumps({"book_title": "b1", "owner": "bob", "secret": "x"})
    assert R.foreign_sensitive_read(200, own, "bob") is None   # reading your OWN object is not BOLA
    nosec = json.dumps({"book_title": "b1", "owner": "alice"})
    assert R.foreign_sensitive_read(200, nosec, "bob") is None # no sensitive field -> not flagged
    assert R.foreign_sensitive_read(401, json.dumps({"owner": "alice", "secret": "x"}), "bob") is None


def test_foreign_finding_is_schema_complete():
    """Defect #6: BOLA findings must satisfy the canonical schema — reproduction_steps a LIST, plus impact."""
    for conf in ("confirmed", "lead"):
        hit = {"owner": "alice", "sensitive_fields": ["secret"], "confidence": conf}
        f = R.foreign_finding("/books/v1", "b1", hit, "bob", "http://app/books/v1/b1")
        assert isinstance(f["reproduction_steps"], list) and f["reproduction_steps"]
        assert f["impact"] and f["cwe"] == "CWE-639" and f["family"] == "idor"
        assert f["confidence"] == ("confirmed" if conf == "confirmed" else "lead")
        assert f["severity"] == ("high" if conf == "confirmed" else "medium")
    # the differential finding builder is schema-complete too
    df = R.finding("/api/Addresss", "5", "user_a", "user_b", "http://app/api/Addresss/5")
    assert isinstance(df["reproduction_steps"], list) and df["impact"]


def test_extract_ids_natural_key_fallback():
    assert R.extract_ids(json.dumps({"Books": [{"book_title": "t1"}, {"book_title": "t2"}]})) == {"t1", "t2"}
