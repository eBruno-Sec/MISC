

# ── the proof gate must reach the headline number ─────────────────────────────
def test_a_demoted_lead_does_not_inflate_the_risk_score():
    """REGRESSION (Codex audit, batch 2 #10). proof_schema.demote_unproven is deliberately
    non-destructive: it rewrites a confirmed-but-unproven finding's confidence to "lead" and LEAVES IT IN
    the findings list. risk_score summed severity over every item handed to it, so exactly the findings
    the proof gate had just rejected went on contributing full weight to the headline number. Measured
    before the fix: one confirmed critical plus one demoted lead scored 80/Critical instead of
    40/High — an unproven finding doubling the reported risk."""
    import report as R
    crit = {"severity": "critical", "confidence": "confirmed"}
    lead = {"severity": "critical", "confidence": "lead"}
    assert R.risk_score([crit, lead])["score"] == R.risk_score([crit])["score"]
    assert R.risk_score([lead, lead])["score"] == 0
    assert R.risk_score([lead, lead])["label"] == "No Confirmed Risk"


def test_risk_score_still_counts_findings_with_no_confidence_field():
    """Absence of a confidence field means 'not demoted', not 'unproven' — most producers set it, but a
    finding that never had one must not be silently dropped from the score."""
    import report as R
    assert R.risk_score([{"severity": "high"}])["score"] > 0
