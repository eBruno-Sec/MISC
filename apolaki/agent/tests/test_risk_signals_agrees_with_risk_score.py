"""Q-015 - `risk_signals` was the unfiltered twin of `risk_score`, so one report contradicted itself.

MEASURED before the fix, one gate-demoted list through both functions:

    risk_score(gated)      -> {'score': 0, 'label': 'No Confirmed Risk'}
    risk_signals(gated)[0] -> {'label': 'Confirmed vulnerability load', 'pct': 25,
                               'basis': '1 confirmed finding(s), severity-weighted'}

Headline "No Confirmed Risk", executive dashboard "25% confirmed vulnerability load, 1 confirmed
finding" -- from the same input, in the same document. `proof_schema.demote_unproven` is deliberately
non-destructive: it rewrites the confidence to "lead" and leaves the row in the list, so a consumer
that does not filter is counting findings the proof gate rejected.

The invariant is stated as AGREEMENT rather than as a value, because the two numbers are the same
quantity and the defect was that they could disagree.
"""
import report


def _high(confidence):
    return {"title": "SQL injection in id", "severity": "high", "family": "sqli",
            "target": "http://x/?id=1", "confidence": confidence}


def _load(findings):
    sig = report.risk_signals(findings, [], {}, {}, [])
    return next(s for s in sig if s["label"] == "Confirmed vulnerability load")


def test_a_gate_demoted_finding_does_not_report_a_confirmed_load():
    """THE regression. A demoted row must not carry severity weight into the dashboard."""
    gated = [_high("lead")]
    assert report.risk_score(gated)["score"] == 0
    load = _load(gated)
    assert load["pct"] == 0, load
    assert "0 confirmed finding(s)" in load["basis"], load


def test_a_genuinely_confirmed_finding_still_scores_in_BOTH():
    """The negative control: the fix must not zero the signal, only the dishonest part of it. Without
    this, deleting the whole computation would pass the test above."""
    real = [_high("confirmed")]
    assert report.risk_score(real)["score"] > 0
    assert _load(real)["pct"] == report.risk_score(real)["score"]
    assert "1 confirmed finding(s)" in _load(real)["basis"]


def test_the_two_agree_on_every_mix_which_is_the_actual_invariant():
    """They compute the same quantity; the defect was that they could disagree. Asserted over mixed
    inputs so the agreement is a property, not a coincidence of one fixture."""
    for confs in (["confirmed"], ["lead"], ["confirmed", "lead"], ["candidate", "confirmed"],
                  ["lead", "candidate", "tentative"], ["confirmed", "confirmed"], []):
        fs = [_high(c) for c in confs]
        assert _load(fs)["pct"] == report.risk_score(fs)["score"], confs


def test_the_descriptive_signals_still_span_leads_deliberately():
    """Not everything should be filtered. 'Leads awaiting verification' and the exposure signal are
    descriptive by design and say so in their basis -- narrowing them would be a different bug."""
    sig = report.risk_signals([], [_high("lead")], {}, {}, [])
    leads = next(s for s in sig if s["label"] == "Leads awaiting verification")
    assert leads["pct"] > 0, "the lead signal must still see leads"
