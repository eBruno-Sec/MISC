"""Business-logic headline (#123): surface the workflows probed + abuse categories + outcomes as a
first-class capability, not buried in leads. Pure over the business_logic/race signals in the report."""
import report


def test_view_groups_workflows_and_categories():
    leads = [{"family": "business_logic", "title": "Business-logic hypothesis (Checkout / order placement) — replay_double_exec"},
             {"family": "business_logic", "title": "Business-logic hypothesis (Checkout / order placement) — negative_or_limit"},
             {"family": "race", "title": "Race condition (Coupon redemption) — double_apply"}]
    findings = [{"family": "business_logic", "confidence": "confirmed", "title": "Negative order total (Checkout) — negative_amount"}]
    v = report.business_logic_view(findings, leads)
    assert v["tested"] is True
    assert v["confirmed"] == 1 and v["hypotheses_to_verify"] == 3
    assert "Checkout / order placement" in v["workflows"] and "Coupon redemption" in v["workflows"]
    assert "replay_double_exec" in v["abuse_categories"] and "double_apply" in v["abuse_categories"]


def test_view_empty_when_no_business_logic_signal():
    v = report.business_logic_view([{"family": "sqli", "confidence": "confirmed"}],
                                   [{"family": "xss", "title": "reflected"}])
    assert v["tested"] is False and v["confirmed"] == 0 and v["hypotheses_to_verify"] == 0


def test_view_present_in_report_json():
    import json
    pkg = json.loads(report.findings_json(
        "p", [], {"in_scope": ["x"]},
        leads=[{"family": "business_logic", "title": "Business-logic hypothesis (Checkout) — skip_prerequisite"}]))
    assert "business_logic" in pkg and pkg["business_logic"]["tested"] is True
