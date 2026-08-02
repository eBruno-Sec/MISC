"""Tamper-evident audit log: hash-chained append, secret redaction, and tamper DETECTION."""
from __future__ import annotations

import json

import audit


def test_records_chain_and_verify(tmp_path):
    log = audit.AuditLog(str(tmp_path / "audit.jsonl"))
    log.record("scan_launched", actor="operator", mission="m1", target="juice-shop")
    log.record("account_created", mission="m1", role="user_a")
    e3 = log.record("session_acquired", mission="m1", role="user_a")
    assert e3["prev"] != "0" * 64                        # links to the previous record
    ok, idx = log.verify_chain()
    assert ok and idx == -1                              # intact chain
    assert len(log.entries(mission="m1")) == 3
    assert len(log.entries(action="account_created")) == 1


def test_metadata_is_redacted(tmp_path):
    log = audit.AuditLog(str(tmp_path / "audit.jsonl"))
    log.record("credential_discovered", mission="m1", password="LEAK", identity_ref="vault://mission/m1/__scan__")
    row = log.entries()[0]
    assert row["meta"]["password"] == "<redacted>"       # secret scrubbed
    assert row["meta"]["identity_ref"] == "vault://mission/m1/__scan__"   # ref survives


def test_tampering_is_detected(tmp_path):
    p = tmp_path / "audit.jsonl"
    log = audit.AuditLog(str(p))
    log.record("a", mission="m1")
    log.record("b", mission="m1")
    log.record("c", mission="m1")
    assert log.verify_chain()[0] is True
    # tamper: rewrite the middle record's content, leaving its (now stale) hash
    rows = [json.loads(ln) for ln in p.read_text().splitlines() if ln.strip()]
    rows[1]["action"] = "MALICIOUSLY_CHANGED"
    p.write_text("\n".join(json.dumps(r) for r in rows) + "\n")
    ok, idx = audit.AuditLog(str(p)).verify_chain()
    assert ok is False and idx == 1                      # the exact tampered record is flagged


def test_truncation_is_detected(tmp_path):
    p = tmp_path / "audit.jsonl"
    log = audit.AuditLog(str(p))
    for a in ("a", "b", "c"):
        log.record(a, mission="m1")
    assert log.verify_chain()[0] is True
    # delete the LAST record: the surviving chain is internally valid, but the signed head checkpoint
    # remembers 3 records -> truncation is caught (the classic "delete the incriminating tail" attack).
    rows = [ln for ln in p.read_text().splitlines() if ln.strip()]
    p.write_text("\n".join(rows[:-1]) + "\n")
    ok, _ = audit.AuditLog(str(p)).verify_chain()
    assert ok is False


def test_checkpoint_deletion_is_detected(tmp_path):
    import os
    p = tmp_path / "audit.jsonl"
    log = audit.AuditLog(str(p))
    log.record("a", mission="m1")
    log.record("b", mission="m1")
    assert log.verify_chain()[0] is True
    # delete the checkpoint but leave the log records -> a legit log always has a checkpoint, so this
    # is flagged (partial defence — a full wipe of BOTH log and checkpoint still can't be detected).
    os.remove(str(p) + ".head")
    ok, idx = audit.AuditLog(str(p)).verify_chain()
    assert ok is False and idx == -3
