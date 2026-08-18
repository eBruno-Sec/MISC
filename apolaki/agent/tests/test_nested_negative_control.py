"""Q-071: the report printed "NO NEGATIVE CONTROL WAS RECORDED" on the only findings that had one.

`proof_schema.control_status` scans TOP-LEVEL keys. The only producer that has ever actually stored
a negative control is BIE, and it writes the artifact NESTED at `browser_evidence.negative_controls`.
So the report rendered a table of three real controls and, beside it, the sentence saying none was
recorded. The document contradicted itself on the page.

WHY THE OLD TEST DID NOT CATCH IT, which is the actual subject of this file. Its fixture
hand-wrote a top-level `negative_controls` list. That shape is emitted by two producers
(`mass_assign_tool`, `ws_tool`) but, measured over the live mission database, it has never been
stored: 1057 findings, 0 top-level controls, 3 nested ones, 0 reading RECORDED. The fixture was of a
shape that had never reached the report, so the suite stayed green while the feature was inverted in
production. Every fixture below is therefore either a VERBATIM stored finding or built by calling a
REAL producer -- nothing here is hand-shaped.

The measurement, the producer census and the decoy key are recorded in docs/handoff/controls.md.

FOUR THINGS MUST HOLD AT ONCE, and three of them are the reason a naive fix is worse than the bug:

    BIE finding, nested control          -> RECORDED           (the defect)
    stored finding with no control       -> NOT_RECORDED       (Q-022's mandatory negative control)
    BIE shape whose controls are EMPTY   -> NOT_RECORDED       (an empty dict is "no control ran")
    `browser_evidence.control` present   -> NOT_RECORDED       (that key is the withheld DOM element,
                                                                not a control -- the deep-scan decoy)
"""
from __future__ import annotations

import json
import os

import bie
import poc_bundle
import proof_schema
import report
import ws_tool

HERE = os.path.dirname(os.path.abspath(__file__))
_NO_CONTROL = "NO NEGATIVE CONTROL WAS RECORDED"


# ── fixtures: verbatim stored rows, or built by the real producer ─────────────────────────────
def _stored() -> list:
    """The VERBATIM findings rows of mission 57cc3b49, read read-only out of the live volume.

    Not hand-written and not trimmed -- see the file's own `_provenance`. Regenerating it from a
    later mission is fine; inventing a shape here is exactly the defect this file exists to catch.
    """
    with open(os.path.join(HERE, "findings_57cc3b49.json"), encoding="utf-8") as fh:
        doc = json.load(fh)
    assert "VERBATIM" in doc["_provenance"], "fixture lost its provenance -- it is no longer real data"
    return doc["findings"]


def _real_bie_finding() -> dict:
    """The stored BIE finding: three real negative controls, all nested. THE fixture of this ticket."""
    fs = [f for f in _stored() if isinstance(f.get("browser_evidence"), dict)]
    assert len(fs) == 1, "expected exactly one BIE row in the stored mission, got %d" % len(fs)
    f = fs[0]
    nc = f["browser_evidence"]["negative_controls"]
    assert set(nc) == {"anon", "nonexistent", "control"}, sorted(nc)
    return f


def _real_finding_without_any_control() -> dict:
    """A stored, CONFIRMED finding that genuinely ran no control -- also verbatim, not invented."""
    fs = [f for f in _stored() if not isinstance(f.get("browser_evidence"), dict)]
    assert fs, "the stored mission no longer contains a control-free finding"
    f = fs[0]
    assert not any(f.get(k) for k in proof_schema.CONTROL_KEYS)
    return f


def _bie_shape_with_no_control_recorded() -> dict:
    """Built by the REAL producer (`bie.finding_client_side_authz`) with no control probe returned.

    This is the decoy in its natural habitat: `browser_evidence.control` holds the DOM element the
    interface withheld -- non-empty, and named exactly like a `proof_schema.CONTROL_KEYS` entry --
    while `negative_controls` is empty because neither control probe ran. A fix that scans for any
    CONTROL_KEY at any depth reports this as RECORDED, which is a worse lie than the bug.
    """
    f = bie.finding_client_side_authz(
        {"tag": "a", "text": "Administration", "href": "/#/administration", "id": "admin-link",
         "visible": False, "disabled": False, "reason": "hidden", "probe_url": "http://h/rest/admin"},
        {"persona": {"url": "http://h/rest/admin", "status": 200, "len": 4096}},   # no anon, no shell
        {"verdict": "lead", "reason": "the control probes did not run"},
        persona="user_a")
    be = f["browser_evidence"]
    assert be["control"], "producer changed: the decoy key is gone, re-derive this test"
    assert be["negative_controls"] == {}, be["negative_controls"]
    return f


def _real_top_level_control_finding() -> dict:
    """The OTHER real shape: `ws_tool` writes its control TOP-LEVEL. Must keep reading RECORDED."""
    f = ws_tool.cswsh_finding(
        "ws://h/socket.io/?EIO=4&transport=websocket",
        {"verdict": "confirmed", "marker": "user_a@h", "authed_frame": '42["user",{"email":"user_a@h"}]'},
        "http://evil.example",
        "returned no frame within 5s (the socket is session-gated)")
    assert isinstance(f.get("negative_controls"), list) and f["negative_controls"]
    return f


# ── the defect ────────────────────────────────────────────────────────────────────────────────
def test_the_stored_control_is_nested_and_top_level_scanning_cannot_see_it():
    """The exact reason the shipped fix reported none: it looked in the wrong place. Pins the shape."""
    f = _real_bie_finding()
    assert not any(f.get(k) for k in proof_schema.CONTROL_KEYS), \
        "the stored finding has NO top-level control key -- that is the whole defect"
    assert f["browser_evidence"]["negative_controls"]["anon"]["status"] == 401
    assert f["browser_evidence"]["negative_controls"]["anon"]["len"] > 0


def test_report_reads_the_nested_control_the_only_producer_that_records_one_writes():
    """FAILS BEFORE THE FIX: three recorded controls, and the report said none was recorded."""
    f = _real_bie_finding()
    assert report.control_ran(f) is True
    claim = report.negative_control_claim(f)
    assert claim["status"] == proof_schema.CONTROL_RECORDED
    assert claim["heading"] == "How this was confirmed (false-positive safety)"
    assert _NO_CONTROL not in claim["text"]


def test_the_rendered_page_does_not_contradict_itself():
    """The defect as a READER meets it: the control table and the prose in one document.

    `browser_evidence_html` has always rendered the three controls. The prose beside it said none
    existed. Asserting both halves of the same page is what makes this a report defect and not a
    predicate defect.
    """
    f = _real_bie_finding()
    html = report.generate_html_report("q071", [f], {"in_scope": [f.get("target", "")]})
    # the control table, by the row labels `browser_evidence_html` writes (the dash is escaped, so
    # these are matched on their ASCII tails rather than on the entity)
    for row in ("anonymous</td>", "implausible id</td>"):
        assert row in html, "the control table is the other half of the page: missing %r" % row
    assert "How this was confirmed (false-positive safety)" in html
    assert _NO_CONTROL not in html

    md = report.generate_report("q071", [f], {"in_scope": [f.get("target", "")]})
    assert "How this was confirmed (false-positive safety)" in md
    assert _NO_CONTROL not in md


def test_the_poc_bundle_agrees_with_the_report():
    """One decision, every surface. The bundle reads `report.negative_control_claim`."""
    c = poc_bundle.build(_real_bie_finding())["confirmation"]
    assert c["control_status"] == proof_schema.CONTROL_RECORDED
    assert _NO_CONTROL not in c["negative_control"]


# ── the mandatory negative controls: a fix that reads RECORDED everywhere is worse than the bug ──
def test_a_stored_finding_with_no_control_still_reports_none():
    """Q-022's requirement, kept. The section's entire value is telling these two apart."""
    f = _real_finding_without_any_control()
    assert report.control_ran(f) is False
    claim = report.negative_control_claim(f)
    assert claim["status"] == proof_schema.CONTROL_NOT_RECORDED
    assert _NO_CONTROL in claim["text"]


def test_an_empty_nested_control_is_no_control_not_an_unknown_one():
    """`negative_controls: {}` is a producer recording that it ran NONE. Same strictness as top-level."""
    f = _real_bie_finding()
    f = dict(f, browser_evidence=dict(f["browser_evidence"], negative_controls={}))
    assert report.control_ran(f) is False
    claim = report.negative_control_claim(f)
    assert claim["status"] == proof_schema.CONTROL_NOT_RECORDED
    assert _NO_CONTROL in claim["text"]


def test_the_withheld_dom_element_is_not_a_negative_control():
    """The decoy. `browser_evidence.control` is the thing under test, not an experiment about it."""
    f = _bie_shape_with_no_control_recorded()
    assert report.control_ran(f) is False, \
        "a deep scan for CONTROL_KEYS counted the withheld DOM element as a control experiment"
    claim = report.negative_control_claim(f)
    assert claim["status"] == proof_schema.CONTROL_NOT_RECORDED
    assert _NO_CONTROL in claim["text"]


def test_a_bare_finding_and_a_non_dict_are_unchanged():
    """The 837b1f0 behaviour, byte-for-byte: nothing about the container lookup may relax it."""
    assert report.control_ran({}) is False
    assert report.control_ran(None) is False
    assert report.negative_control_claim({})["status"] == proof_schema.CONTROL_NOT_RECORDED
    assert report.negative_control_claim(None)["status"] == proof_schema.CONTROL_NOT_RECORDED
    assert report.control_ran({"browser_evidence": "not a dict"}) is False
    assert report.control_ran({"browser_evidence": {}}) is False
    assert report.control_ran({"browser_evidence": {"negative_controls": None}}) is False


# ── the shapes that already worked must keep working ──────────────────────────────────────────
def test_the_top_level_producer_shape_is_untouched():
    """`ws_tool` and `mass_assign_tool` write top-level. 0 stored so far -- and still correct."""
    f = _real_top_level_control_finding()
    assert report.control_ran(f) is True
    claim = report.negative_control_claim(f)
    assert claim["status"] == proof_schema.CONTROL_RECORDED
    assert _NO_CONTROL not in claim["text"]


def test_source_derived_findings_are_still_not_applicable():
    """The third value survives: a static call site has no request, so "not recorded" is also false."""
    import codereview
    fs = codereview.review_java(
        'package a;\nimport javax.crypto.Cipher;\n'
        'public class B { public Cipher c() throws Exception { return Cipher.getInstance("DES"); } }\n',
        "src/main/java/a/B.java")
    assert fs, "producer emitted nothing -- fixture is broken, not the contract"
    claim = report.negative_control_claim(fs[0])
    assert claim["status"] == proof_schema.CONTROL_NOT_APPLICABLE
    assert claim["text"].startswith("NOT APPLICABLE")
