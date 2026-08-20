"""Q-022 oracle 1: a finding WITH a recorded control must render the RECORDED VALUES, not a template.

Q-022's critical half -- a confirmation narrative on findings that never had a control -- is closed
and re-measured over the live corpus (1783 findings: 1064 not_recorded, 716 not_applicable, 3
recorded, 0 claiming a control they do not have). **Its oracle 1 was not.**

    "A finding with a recorded control renders the RECORDED values (url/status/length),
     and those values appear in the output."

The RECORDED branch was correctly GATED on the artifact (837b1f0, widened to the nested BIE location
by Q-071) and then printed `technique_model.proof_contract` keyed on FAMILY ALONE -- quoting nothing.
MEASURED on the stored BIE finding of mission 57cc3b49, whose three real controls are in the volume:

    heading: How this was confirmed (false-positive safety)
    text   : A negative-control request WITHOUT the trigger does NOT reproduce the confirming signal
             (differential measured over a stable baseline).

    label 'nonexistent'          md=False   html=False
    nonexistent.url              md=False   html=True     <- HTML only, from browser_evidence_html
    control.url                  md=False   html=True

So a MARKDOWN reader met a heading claiming a confirmation with **no record of anything underneath
it**, and an HTML reader got the values only from a separate table that the prose never referenced.
The gate was right and the sentence was still a template.

FIXTURES: the stored mission row (verbatim, same file `test_nested_negative_control.py` uses and for
the same reason) and the REAL top-level producer `ws_tool.cswsh_finding`. Nothing here is hand-shaped
-- the invented top-level fixture is precisely what let Q-071 ship inverted.
"""
from __future__ import annotations

import json
import os

import proof_schema
import report
import ws_tool

HERE = os.path.dirname(os.path.abspath(__file__))
_NO_CONTROL = "NO NEGATIVE CONTROL WAS RECORDED"


def _stored() -> list:
    with open(os.path.join(HERE, "findings_57cc3b49.json"), encoding="utf-8") as fh:
        doc = json.load(fh)
    assert "VERBATIM" in doc["_provenance"], "fixture lost its provenance -- it is no longer real data"
    return doc["findings"]


def _bie_finding() -> dict:
    fs = [f for f in _stored() if isinstance(f.get("browser_evidence"), dict)]
    assert len(fs) == 1, "expected exactly one BIE row in the stored mission, got %d" % len(fs)
    return fs[0]


def _no_control_finding() -> dict:
    fs = [f for f in _stored() if not isinstance(f.get("browser_evidence"), dict)]
    assert fs, "the stored mission no longer contains a control-free finding"
    return fs[0]


def _ws_finding() -> dict:
    """The OTHER real shape: a top-level LIST of {kind, description, result, rules_out}."""
    f = ws_tool.cswsh_finding(
        "ws://h/socket.io/?EIO=4&transport=websocket",
        {"verdict": "confirmed", "marker": "user_a@h", "authed_frame": '42["user",{"email":"user_a@h"}]'},
        "http://evil.example",
        "returned no frame within 5s (the socket is session-gated)")
    assert isinstance(f.get("negative_controls"), list) and f["negative_controls"]
    return f


# ── the fixture is real, and it really does carry values worth quoting ────────────────────────
def test_the_fixture_carries_a_real_artifact_with_the_values_oracle_1_names():
    nc = _bie_finding()["browser_evidence"]["negative_controls"]
    assert set(nc) == {"anon", "nonexistent", "control"}, sorted(nc)
    for label, probe in nc.items():
        assert probe["url"] and probe["status"] and probe["len"] > 0, (label, probe)


# ── oracle 1, in the projection ───────────────────────────────────────────────────────────────
def test_the_recorded_values_are_quoted_and_not_a_family_template():
    """FAILS BEFORE THE FIX: the text was `proof_contract("bola")` and contained no stored value."""
    f = _bie_finding()
    claim = report.negative_control_claim(f)
    assert claim["status"] == proof_schema.CONTROL_RECORDED
    txt = claim["text"]
    for label, probe in f["browser_evidence"]["negative_controls"].items():
        assert label in txt, "control %r is not named in the claim" % label
        assert str(probe["url"]) in txt and str(probe["status"]) in txt and str(probe["len"]) in txt, \
            "the RECORDED values of %r never reach the claim: %r" % (label, txt)


def test_the_contract_text_survives_but_is_labelled_as_the_requirement():
    """The prescription is still worth showing; what it may not do is stand in for the record.

    NEGATIVE CONTROL ON THE FIX: dropping the contract sentence would trade one defect for another
    (a reviewer could no longer tell what the control was supposed to establish), so both halves are
    asserted, and the record must come FIRST -- an indicative sentence read before any values is the
    Q-022 shape however true it happens to be.
    """
    txt = report.negative_control_claim(_bie_finding())["text"]
    assert "does NOT reproduce" in txt, "the technique contract was deleted rather than reframed"
    assert "contract requires" in txt
    assert txt.index("RECORDED for this finding") < txt.index("does NOT reproduce"), \
        "the template still leads and the record follows it"


def test_a_response_body_never_reaches_the_prose():
    """url/status/length is what oracle 1 asks for. A stored body in a sentence is unreadable, and
    these are real HTTP bodies -- the anon control's is a 972-byte HTML error page."""
    f = _bie_finding()
    txt = report.negative_control_claim(f)["text"]
    for label, probe in f["browser_evidence"]["negative_controls"].items():
        body = str(probe.get("body") or "")
        if len(body) > 40:
            assert body[:40] not in txt, "the %r control's response body leaked into the prose" % label
    assert len(txt) < 2000, "the claim is now longer than a paragraph: %d chars" % len(txt)


# ── oracle 1, END TO END: the values must appear in the ARTIFACT, in BOTH renderers ───────────
def test_the_values_reach_the_markdown_report_where_they_previously_never_appeared():
    """The half that was entirely missing: `browser_evidence_html` is HTML-only, so before this fix
    a markdown reader saw the confirmation heading with no record under it at all."""
    f = _bie_finding()
    md = report.generate_report("o1", [f], {"in_scope": [f.get("target", "")]})
    assert "How this was confirmed (false-positive safety)" in md
    for label, probe in f["browser_evidence"]["negative_controls"].items():
        assert label in md, "control %r never reaches the markdown report" % label
        assert str(probe["url"]) in md, "control %r's URL never reaches the markdown report" % label
        assert str(probe["len"]) in md


def test_the_values_reach_the_html_report_in_the_prose_and_not_only_in_the_table():
    f = _bie_finding()
    html = report.generate_html_report("o1", [f], {"in_scope": [f.get("target", "")]})
    assert "How this was confirmed (false-positive safety)" in html
    assert "NEGATIVE CONTROL RECORDED for this finding" in html
    assert _NO_CONTROL not in html
    # the table is the other half of the page and must still be there (Q-071's assertion, kept)
    for row in ("anonymous</td>", "implausible id</td>"):
        assert row in html, "the control table vanished: %r" % row


def test_the_poc_bundle_states_the_same_thing_as_the_report():
    """One projection, three surfaces. 837b1f0 gated the report and not the bundle, and they
    disagreed on the same finding until `negative_control_claim` became the single composer."""
    import poc_bundle
    c = poc_bundle.build(_bie_finding())["confirmation"]
    assert c["control_status"] == proof_schema.CONTROL_RECORDED
    assert c["negative_control"] == report.negative_control_claim(_bie_finding())["text"]
    assert "anon" in c["negative_control"]


# ── the other real producer shape, which records prose rather than an exchange ────────────────
def test_the_top_level_list_shape_is_quoted_too():
    """`ws_tool` and `mass_assign_tool` record `[{kind, description, result, rules_out}]`. Nothing of
    that shape has been STORED yet (0 of the corpus), which is exactly why an invented top-level
    fixture once passed while production was inverted -- so it is exercised through its producer."""
    f = _ws_finding()
    claim = report.negative_control_claim(f)
    assert claim["status"] == proof_schema.CONTROL_RECORDED
    kind = f["negative_controls"][0]["kind"]
    assert kind in claim["text"], "the recorded control's own words never reach the claim: %r" % claim["text"]
    assert _NO_CONTROL not in claim["text"]


# ── the mandatory negative controls: the other two statuses may not gain a fake record ────────
def test_a_finding_with_no_control_gains_no_quoted_values():
    """Q-022's standing requirement. A fix that renders values for everything is worse than the bug."""
    f = _no_control_finding()
    assert report.recorded_control_lines(f) == []
    claim = report.negative_control_claim(f)
    assert claim["status"] == proof_schema.CONTROL_NOT_RECORDED
    assert _NO_CONTROL in claim["text"]
    assert "NEGATIVE CONTROL RECORDED" not in claim["text"]


def test_an_empty_artifact_is_no_record_at_all():
    """`negative_controls: {}` is a producer recording that it ran NONE."""
    f = _bie_finding()
    f = dict(f, browser_evidence=dict(f["browser_evidence"], negative_controls={}))
    assert report.recorded_control_lines(f) == []
    assert report.negative_control_claim(f)["status"] == proof_schema.CONTROL_NOT_RECORDED


def test_the_line_builder_agrees_with_the_status_predicate_on_every_shape():
    """THE INVARIANT, and the reason the lines are read off the same artifact rather than re-scanned:
    quoted values and RECORDED must be the same fact, never two facts that can drift apart."""
    import codereview
    src = ('package a;\nimport javax.crypto.Cipher;\n'
           'public class B { public Cipher c() throws Exception { return Cipher.getInstance("DES"); } }\n')
    corpus = ([_bie_finding(), _no_control_finding(), _ws_finding(), {}, {"family": "sqli"},
               {"browser_evidence": {"negative_controls": {}}},
               {"browser_evidence": {"control": {"tag": "a"}}}]
              + codereview.review_java(src, "src/main/java/a/B.java")[:1])
    seen = set()
    for f in corpus:
        st = report.control_status(f)
        seen.add(st)
        assert bool(report.recorded_control_lines(f)) == (st == proof_schema.CONTROL_RECORDED), \
            "lines and status disagree on %r" % (str(f)[:120],)
    # non-vacuity: all three statuses are present, or the invariant was checked on one kind only
    assert seen == {proof_schema.CONTROL_RECORDED, proof_schema.CONTROL_NOT_RECORDED,
                    proof_schema.CONTROL_NOT_APPLICABLE}, seen


def test_a_source_derived_finding_is_still_not_applicable_and_quotes_nothing():
    import codereview
    fs = codereview.review_java(
        'package a;\nimport javax.crypto.Cipher;\n'
        'public class B { public Cipher c() throws Exception { return Cipher.getInstance("DES"); } }\n',
        "src/main/java/a/B.java")
    assert fs, "producer emitted nothing -- fixture is broken, not the contract"
    claim = report.negative_control_claim(fs[0])
    assert claim["status"] == proof_schema.CONTROL_NOT_APPLICABLE
    assert claim["text"].startswith("NOT APPLICABLE")
    assert "NEGATIVE CONTROL RECORDED" not in claim["text"]


def test_an_empty_ledger_renders_no_confirmation_claim_at_all():
    """A report built from nothing must not claim work was done -- the control whose absence let
    Q-084 survive, applied to this section."""
    for renderer in (report.generate_report, report.generate_html_report):
        doc = renderer("empty", [], {"in_scope": ["http://x/"]})
        assert "NEGATIVE CONTROL RECORDED" not in doc
        assert "How this was confirmed" not in doc
        assert _NO_CONTROL not in doc
