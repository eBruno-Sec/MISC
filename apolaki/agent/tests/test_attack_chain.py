"""Tests for the deterministic attack-chain memory (append-only, planner-annotating)."""
from __future__ import annotations

import attack_chain as AC


def test_record_and_summary(tmp_path):
    d = str(tmp_path)
    AC.record("http://t:3000/x", "sqli", "attempted", d=d)
    AC.record("http://t:3000", "sqli", "confirmed", d=d)      # same host key, better outcome wins
    AC.record("http://t:3000", "xxe", "failed", d=d)
    s = AC.summary("t:3000", d=d)
    assert s["sqli"] == "confirmed" and s["xxe"] == "failed"
    assert len(AC.load("t:3000", d=d)["steps"]) == 3          # append-only, nothing dropped


def test_target_key_normalizes():
    assert AC.target_key("http://juice-shop:3000/rest/x") == "juice-shop:3000"
    assert AC.target_key("juice-shop:3000") == "juice-shop:3000"


def test_learning_reliability_and_weight(tmp_path):
    import learning
    d = str(tmp_path)
    AC.record("t1", "sqli", "confirmed", d=d)
    AC.record("t2", "sqli", "confirmed", d=d)         # sqli confirms across 2 targets
    AC.record("t1", "xxe", "failed", d=d)
    AC.record("t2", "xxe", "failed", d=d)             # xxe never pans out
    rel = learning.reliability(d=d)
    assert rel["sqli"]["rate"] == 1.0 and rel["xxe"]["rate"] == 0.0
    assert learning.class_weight("sql_injection", rel, d=d) > 0     # canon match + reliable -> boost
    assert learning.class_weight("xxe", rel, d=d) < 0              # always failed -> penalty
    assert learning.class_weight("sqli", {"sqli": {"attempts": 1, "confirmed": 1, "rate": 1.0}}) == 0.0  # <2 attempts = no move


def test_annotate_plan_uses_prior_outcomes(tmp_path):
    d = str(tmp_path)
    AC.record("t:3000", "xxe", "failed", d=d)
    AC.record("t:3000", "sqli", "confirmed", d=d)
    plan = [{"id": "xxe_file_ssrf", "family": "xxe", "score": 50},
            {"id": "sqli_auth_bypass", "family": "sqli", "score": 40},
            {"id": "idor_bola_read", "family": "access_control", "score": 45}]
    p = AC.annotate_plan("t:3000", plan, d=d)
    by = {a["id"]: a for a in p}
    assert by["xxe_file_ssrf"]["prior"] == "previously failed" and by["xxe_file_ssrf"]["score"] == 30
    assert by["sqli_auth_bypass"]["prior"] == "already confirmed"          # sunk below everything
    assert p[0]["id"] == "idor_bola_read"                                  # untouched 45 now leads
