"""A report may only claim a negative control that actually ran.

`proof_and_retest` built its control description from the finding's FAMILY alone and the report
rendered it present-indicative under "How this was confirmed (false-positive safety)". Measured
across 151 missions: 660 confirmed findings stored, 34 carry any control artifact, **626 (94.8%)
carried none and printed the claim anyway.**

Truth-first proof is the platform's whole differentiator. These tests make the claim structurally
dependent on the artifact, so it cannot drift back.
"""
import report


def _bare(fam="sqli"):
    """A finding exactly as 626 of the 660 stored ones look: no controls, no evidence."""
    return {"family": fam, "confidence": "confirmed", "target": "http://x/?id=1",
            "title": "SQL injection in id", "severity": "high"}


def _with_control(fam="sqli"):
    f = _bare(fam)
    f["negative_controls"] = [{"request": "GET /?id=1", "response_status": 200,
                               "note": "inert control did not reproduce the differential"}]
    return f


def test_control_ran_is_strict_about_what_counts():
    assert report.control_ran(_with_control()) is True
    assert report.control_ran(_bare()) is False
    # Empty containers and blank strings are not artifacts. A producer that writes `controls: []`
    # has recorded that it ran none, not that it ran some.
    for empty in ([], {}, "", "   ", None):
        assert report.control_ran({"family": "sqli", "negative_controls": empty}) is False, repr(empty)
    assert report.control_ran(None) is False and report.control_ran("nope") is False


def test_a_finding_with_no_control_does_not_assert_one():
    txt = report.proof_and_retest(_bare())["negative_control"]
    assert "NO NEGATIVE CONTROL WAS RECORDED" in txt
    # The contract is still shown -- a reviewer needs to know what WOULD settle it -- but as a
    # prescription, not as a report of something that happened.
    assert "would settle it" in txt and "run it before" in txt


def test_a_finding_with_a_real_control_still_states_it_plainly():
    """The negative control for the fix: don't destroy the honest case while fixing the dishonest one."""
    txt = report.proof_and_retest(_with_control())["negative_control"]
    assert "NO NEGATIVE CONTROL WAS RECORDED" not in txt
    assert txt.strip() and len(txt) > 20


def test_the_heading_tracks_the_artifact_in_html():
    bare = report.generate_html_report("P", [_bare()], {"in_scope": ["x"]})
    assert "NOT ESTABLISHED for this finding" in bare
    assert "How this was confirmed" not in bare, "the heading is a claim too"
    real = report.generate_html_report("P", [_with_control()], {"in_scope": ["x"]})
    assert "How this was confirmed" in real
    assert "NOT ESTABLISHED" not in real


def test_the_heading_tracks_the_artifact_in_markdown():
    bare = report.generate_report("P", [_bare()], {"in_scope": ["x"]})
    assert "False-positive safety: NOT ESTABLISHED" in bare
    assert "**How this was confirmed" not in bare
    real = report.generate_report("P", [_with_control()], {"in_scope": ["x"]})
    assert "**How this was confirmed" in real


def test_every_family_gets_the_honest_treatment_not_just_sqli():
    """The old text was keyed by family, so the bug had to be fixed for all of them at once."""
    for fam in ("sqli", "idor", "xss", "ssrf", "vulnerable_component", "open_redirect", ""):
        txt = report.proof_and_retest(_bare(fam))["negative_control"]
        assert "NO NEGATIVE CONTROL WAS RECORDED" in txt, fam
