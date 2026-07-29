"""Tests for the Business-Logic Graph + logic-abuse test generator."""
from __future__ import annotations

import bizlogic


def test_logic_tests_cover_the_abuse_classes():
    tests = bizlogic.logic_tests(bizlogic.WORKFLOWS["checkout"])
    kinds = {t["kind"] for t in tests}
    assert "replay_double_execute" in kinds     # payment/coupon are non-idempotent + monetary
    assert "negative_or_limit_value" in kinds    # monetary steps
    assert "skip_prerequisite" in kinds          # payment depends_on set_address
    assert "bypass_mandatory" in kinds           # set_address/payment mandatory
    assert "replay_completed" in kinds           # checkout is terminal
    assert "out_of_order" in kinds
    for t in tests:                              # every test is actionable
        assert t["test"] and t["rationale"] and t["target"] and t["severity"]


def test_infer_workflows_from_routes():
    wfs = bizlogic.infer_workflows(["/basket", "/checkout", "/api/Cards",
                                    "/rest/deluxe-membership", "/redirect"])
    names = {w["name"] for w in wfs}
    assert any("Checkout" in n for n in names)
    assert any("Subscription" in n for n in names)     # deluxe-membership → subscription hint


def test_analyze_black_box_off_routes():
    r = bizlogic.analyze(["/basket", "/checkout", "/refund"])
    assert r["test_count"] > 0
    assert any("Checkout" in n for n in r["workflows_detected"])
    assert any("Refund" in n for n in r["workflows_detected"])


def test_graph_encodes_prerequisites():
    g = bizlogic.graph(bizlogic.WORKFLOWS["checkout"])
    assert len(g["nodes"]) == 5
    assert any(e["rel"] == "requires" and e["source"] == "set_address" and e["target"] == "payment"
               for e in g["edges"])
