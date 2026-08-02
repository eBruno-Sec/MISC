"""Create-object IDOR oracle: definitive ownership (we created it) -> confirmed cross-user access,
and only then. Pure; also checks the emitted finding satisfies the family proof gate (proof_schema)."""
from __future__ import annotations

import create_object_idor as C
import proof_schema as PS


def test_extract_id_from_json_uuid_and_location():
    assert C.extract_id(201, '{"id": 42, "name": "x"}') == "42"
    assert C.extract_id(201, '{"data": {"_id": "abc123"}}') == "abc123"
    u = "550e8400-e29b-41d4-a716-446655440000"
    assert C.extract_id(201, '{"uuid": "%s"}' % u) == u
    assert C.extract_id(201, "", location="/api/Addresss/7") == "7"
    assert C.extract_id(500, "internal error") == ""


def test_marker_is_unique():
    assert C.new_marker() != C.new_marker()
    assert C.new_marker().startswith("apolaki_idor_")


def test_confirmed_read_requires_marker_in_attacker_body():
    m = "apolaki_idor_deadbeef"
    v = C.verdict(marker=m, create_status=201, create_body='{"id": 9, "note": "%s"}' % m, object_id="9",
                  read_status=200, read_body='{"id": 9, "note": "%s"}' % m)
    assert v["created"] and v["confirmed_read"]
    # attacker sees a DIFFERENT object (no marker) -> not confirmed
    v2 = C.verdict(marker=m, create_status=201, create_body='{"id": 9, "note": "%s"}' % m, object_id="9",
                   read_status=200, read_body='{"id": 9, "note": "someone elses data"}')
    assert v2["created"] and not v2["confirmed_read"]


def test_confirmed_write_and_delete():
    m = "apolaki_idor_cafe"
    v = C.verdict(marker=m, create_status=201, create_body='{"id":"5","x":"%s"}' % m, object_id="5",
                  write_status=200, delete_status=200)
    assert v["confirmed_write"] and v["confirmed_delete"]


def test_not_created_when_marker_absent_or_error():
    v = C.verdict(marker="m", create_status=500, create_body="err", object_id="")
    assert not v["created"] and not v["confirmed_read"]


def test_attacker_denied_is_not_confirmed():
    m = "apolaki_idor_1234"
    v = C.verdict(marker=m, create_status=201, create_body='{"id":1,"n":"%s"}' % m, object_id="1",
                  read_status=403, read_body="Forbidden")
    assert v["created"] and not v["confirmed_read"]


def test_finding_from_verdict_passes_proof_gate():
    m = "apolaki_idor_777"
    v = C.verdict(marker=m, create_status=201, create_body='{"id":3,"n":"%s"}' % m, object_id="3",
                  read_status=200, read_body='{"id":3,"n":"%s"}' % m, delete_status=200)
    f = C.to_finding(v, target="http://h/api/Addresss/3", owner_role="user_a", attacker_role="user_b")
    assert f and f["confidence"] == "confirmed" and f["severity"] == "critical"
    ok, missing = PS.validate_confirmed(f)
    assert ok, missing            # a real created-object confirm must satisfy the family proof schema


def test_no_finding_when_nothing_confirmed():
    v = C.verdict(marker="m", create_status=201, create_body='{"id":1,"n":"m"}', object_id="1",
                  read_status=403, read_body="no")
    assert C.to_finding(v, "t", "user_a", "user_b") is None
