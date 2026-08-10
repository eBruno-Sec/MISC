"""The proof gate must hold at every rendering surface, not just at the gate.

`proof_schema.demote_unproven` is deliberately non-destructive: it rewrites a weak finding's
`confidence` to "lead" and LEAVES THE ROW in the list. Every consumer therefore has to read that
field. `report.py` did not — the HTML card stamped a hardcoded CONFIRMED on every row and the
headline severity tally counted demoted rows — so the gate demoted a finding and the report
un-demoted it two calls later.

The second test here is the negative control for the fix's own first attempt: filtering inside the
shared `_counts()` also zeroed the LEADS tally, where every row is unproven by definition.
"""
import json

import proof_schema
import report


def _confirmed_finding():
    return {"title": "SQLi in id", "severity": "critical", "target": "https://t/i?id=1",
            "cwe": "CWE-89", "description": "d", "impact": "i"}


def _demoted_finding():
    """Exactly what demote_unproven produces: still in the list, confidence rewritten."""
    return {"title": "Unproven IDOR", "severity": "high", "target": "https://t/o/2",
            "cwe": "CWE-639", "description": "d", "impact": "i",
            "confidence": "lead", "tags": ["needs-confirmation", "proof-incomplete"],
            "proof_gap": ["ownership_evidence"]}


def test_is_confirmed_reads_the_field_demote_unproven_writes():
    assert proof_schema.is_confirmed(_confirmed_finding()) is True
    assert proof_schema.is_confirmed(_demoted_finding()) is False
    # A finding with no confidence key is confirmed by convention — most engines only set the field
    # when demoting. If this flipped, every ordinary finding would silently render as a lead.
    assert proof_schema.is_confirmed({"title": "x"}) is True
    for word in proof_schema.UNPROVEN_CONFIDENCE:
        assert proof_schema.is_confirmed({"confidence": word.upper()}) is False, word


def test_html_badge_is_read_from_the_finding_not_hardcoded():
    html = report.generate_html_report("P", [_confirmed_finding(), _demoted_finding()],
                                       {"in_scope": ["t"]})
    assert "CONFIRMED" in html, "a genuinely confirmed finding must still say CONFIRMED"
    assert "LEAD" in html, "a proof-gate demotion must be visible on the card"
    # The gap is named on the chip so a reader knows WHY it is not proven.
    assert "ownership_evidence" in html


def test_demoted_finding_does_not_inflate_the_headline_counts():
    only_demoted = report._confirmed_counts([_demoted_finding()])
    assert only_demoted == {}, "a demoted row must not appear in the confirmed severity tally"
    mixed = report._confirmed_counts([_confirmed_finding(), _demoted_finding()])
    assert mixed == {"critical": 1}


def test_leads_tally_stays_raw():
    """NEGATIVE CONTROL for the first attempt at the fix.

    Filtering inside the shared `_counts()` made `lead_counts` report zero of every severity,
    because every lead is unproven by definition. The two tallies are separate on purpose.
    """
    leads = [{"title": "Reflected value", "severity": "high", "confidence": "candidate"}]
    assert report._counts(leads) == {"high": 1}
    pkg = json.loads(report.findings_json("P", [_confirmed_finding(), _demoted_finding()],
                                          {"in_scope": ["t"]}, leads=leads))
    assert pkg["lead_counts"]["high"] == 1
    # ...while the findings tally in the same package excludes the demotion, matching `risk`.
    assert pkg["counts"] == {"critical": 1}


def test_risk_score_and_counts_agree_about_what_confirmed_means():
    """Two independent filters existed; they must not be able to disagree."""
    fs = [_confirmed_finding(), _demoted_finding()]
    assert sum(report._confirmed_counts(fs).values()) == 1
    # risk_score filters internally; a demoted high must not add its weight.
    assert report.risk_score(fs)["score"] == report.risk_score([_confirmed_finding()])["score"]


def test_severity_bars_survive_a_report_with_no_confirmed_findings():
    """The denominator is now sum(counts.values()); with zero confirmed rows that is 0, and the
    `or 1` guard is the only thing standing between this and a ZeroDivisionError."""
    html = report.generate_html_report("P", [_demoted_finding()], {"in_scope": ["t"]})
    assert "LEAD" in html and "<html" in html.lower()
