"""The evidence contract is PER PROOF KIND. One shape assumed for everything is how the PoC bundle
came to demand a request differential of a static call site.

`837b1f0` stopped the report claiming a negative control that never ran. That defect was an
UNPROVEN claim: the experiment could have been run and was not. This file is about the harder one --
an INAPPLICABLE claim. For `Cipher.getInstance("DES")` at a known file and line there is no request,
no baseline and no mutation, so "a negative-control request ... does NOT reproduce the confirming
signal (differential measured over a stable baseline)" and "baseline + mutation request/response
retained for deterministic replay" describe an experiment that cannot exist even in principle. That
is a category error, not a missing measurement, and "not recorded" is the wrong answer to it too --
it says the experiment was available and skipped.

Three cases, and a reader holding only the JSON must be able to tell them apart:

    source-derived               -> control_status not_applicable, and the rule-level counter-example
    behavioural, control ran     -> UNCHANGED. Fixing the dishonest case must not touch the honest one.
    behavioural, no control ran  -> still says NO NEGATIVE CONTROL WAS RECORDED (the 837b1f0 behaviour)

The source fixtures are built by the REAL producer (`codereview.review_java`), never hand-written,
so a change to the producer's finding shape breaks these tests instead of silently bypassing them.
"""
from __future__ import annotations

import codereview
import poc_bundle
import proof_schema
import technique_model


_JAVA = '''package com.acme.billing;
import javax.crypto.Cipher;
public class Billing {
    public Cipher legacy() throws Exception { return Cipher.getInstance("DES"); }
}
'''
_SRC_PATH = "src/main/java/com/acme/billing/Billing.java"


def _source_finding() -> dict:
    """A real code-assisted finding: source-derived, static call site, no request and no response."""
    fs = codereview.review_java(_JAVA, _SRC_PATH)
    assert fs, "producer emitted nothing -- fixture is broken, not the contract"
    f = fs[0]
    assert f["provenance"] == "source-derived" and f["lane"] == "code-assisted"
    assert "request" not in f and "response" not in f
    return f


def _behavioural_bare() -> dict:
    """A DAST finding with no control artifact -- the 837b1f0 case, in the bundle this time."""
    return {"id": "b1", "family": "sqli", "confidence": "confirmed", "severity": "high",
            "target": "http://h/item?id=1", "title": "SQL injection in id",
            "evidence": "GET /item?id=1' -> 500, /item?id=1'' -> 200"}


def _behavioural_with_control() -> dict:
    f = _behavioural_bare()
    f["id"] = "b2"
    f["negative_controls"] = [{"request": "GET /item?id=1", "response_status": 200,
                               "note": "inert control did not reproduce the differential"}]
    return f


# ── the classifier: shared vocabulary, not a private copy ──────────────────────────────────────
def test_proof_kind_reads_the_lane_the_producer_stamped():
    assert proof_schema.proof_kind(_source_finding()) == proof_schema.SOURCE_DERIVED
    assert proof_schema.proof_kind(_behavioural_bare()) == proof_schema.BEHAVIOURAL
    # a finding that says nothing about its lane is behavioural -- that is what every HTTP probe emits
    assert proof_schema.proof_kind({}) == proof_schema.BEHAVIOURAL
    assert proof_schema.proof_kind(None) == proof_schema.BEHAVIOURAL


def test_control_status_is_three_valued_not_two():
    """The whole defect is a two-valued vocabulary (ran / did not run) asked a third question."""
    assert proof_schema.control_status(_source_finding()) == proof_schema.CONTROL_NOT_APPLICABLE
    assert proof_schema.control_status(_behavioural_bare()) == proof_schema.CONTROL_NOT_RECORDED
    assert proof_schema.control_status(_behavioural_with_control()) == proof_schema.CONTROL_RECORDED


def test_a_recorded_artifact_beats_the_lane_label():
    """A guard that reads a DECLARATION instead of a fact passes what it exists to catch.

    Deciding "not applicable" from the lane label alone would suppress a REAL artifact on a
    source-derived finding that a probe later confirmed. No producer emits that shape today, which
    is exactly when it is cheap to get right.
    """
    import report
    f = dict(_source_finding(),
             negative_controls=[{"request": "GET /pay?alg=AES", "note": "clean sibling rejected"}])
    assert proof_schema.control_status(f) == proof_schema.CONTROL_RECORDED
    assert report.control_ran(f) is True
    c = poc_bundle.build(f)["confirmation"]
    assert c["control_status"] == proof_schema.CONTROL_RECORDED
    assert not c["negative_control"].startswith("NOT APPLICABLE")
    # the call site is still evidence -- the two kinds of proof are additive, not exclusive
    assert poc_bundle.build(f)["source_evidence"]["line"] == f["line"]


# ── case 1: source-derived ─────────────────────────────────────────────────────────────────────
def test_source_finding_does_not_claim_a_request_negative_control():
    """THE DEFECT. The bundle promised a differential over a baseline for a static call site."""
    c = poc_bundle.build(_source_finding())["confirmation"]
    # the fabricated experiment goes first, so this test fails on the DEFECT before it fails on a
    # missing key -- a test that only fails because a new field is absent proves nothing
    nc = c["negative_control"]
    for banned in ("negative-control request", "stable baseline", "differential measured",
                   "A token signed with the wrong"):
        assert banned not in nc, banned
    reqs = " | ".join(c["evidence_requirements"])
    assert "Baseline + mutation request/response retained for deterministic replay." not in reqs
    assert nc.startswith("NOT APPLICABLE")
    # never the OTHER wrong answer either: "not recorded" says it could have been run
    assert "NO NEGATIVE CONTROL WAS RECORDED" not in nc
    assert "NOT APPLICABLE" in reqs
    assert c["proof_kind"] == proof_schema.SOURCE_DERIVED
    assert c["control_status"] == proof_schema.CONTROL_NOT_APPLICABLE


def test_source_finding_states_the_evidence_that_actually_exists():
    """Inapplicable is only half an answer. The call site IS the evidence; say what it is."""
    f = _source_finding()
    b = poc_bundle.build(f)
    se = b["source_evidence"]
    assert se["file"] == _SRC_PATH and se["line"] == f["line"]
    assert se["analysis"] == "static-call-site"
    assert "Cipher.getInstance" in se["call_site"] and "DES" in se["call_site"]
    assert se["rule"]["cwe"] == "CWE-327" and se["rule"]["family"] == "weak_crypto"
    assert se["rule"]["oracle"] == proof_schema.oracle_of(f)
    # the counter-example that would falsify the rule -- a real negative control, just not a request
    assert "AES/GCM" in se["counter_example"]
    assert "AES/GCM" in b["confirmation"]["counter_example"]
    assert "AES/GCM" in b["confirmation"]["negative_control"]
    assert se["runtime_observation"]


def test_source_finding_carries_its_lane_in_provenance():
    """A reader holding only the dossier must be able to tell a SAST row from a DAST row."""
    p = poc_bundle.build(_source_finding())["provenance"]
    assert p["lane"] == "code-assisted" and p["provenance"] == "source-derived"
    assert p["proof_kind"] == proof_schema.SOURCE_DERIVED
    assert poc_bundle.build(_behavioural_bare())["provenance"]["proof_kind"] == proof_schema.BEHAVIOURAL


def test_source_finding_reproduction_is_not_a_curl_to_a_file_path():
    """`_curl` fell back to `curl -i -sk <target>`, and for this lane the target is a file on disk."""
    b = poc_bundle.build(_source_finding())
    assert b["reproduction"]["curl"] == ""
    assert b["reproduction"]["open"] == "%s:%s" % (_SRC_PATH, _source_finding()["line"])
    assert b["reproduction"]["markdown"]          # the human-readable PoC still rides in


def test_a_source_finding_with_no_known_counter_example_says_so_instead_of_inventing_one():
    """The failure mode being fixed is fabrication. An unknown sibling must degrade, never guess."""
    f = dict(_source_finding(), family="some_future_sast_family", cwe="CWE-99999")
    c = poc_bundle.build(f)["confirmation"]
    assert c["control_status"] == proof_schema.CONTROL_NOT_APPLICABLE
    assert c.get("counter_example") is None
    assert "sibling" in c["negative_control"]     # the generic shape, named as generic
    assert "AES/GCM" not in c["negative_control"]


def test_a_producer_supplied_counter_example_beats_the_table():
    """The rule lives in codereview; the table here is a fallback, not the design (patch 6b)."""
    f = dict(_source_finding(), counter_example='Cipher.getInstance("ChaCha20-Poly1305")')
    c = poc_bundle.build(f)["confirmation"]
    assert c["counter_example"] == 'Cipher.getInstance("ChaCha20-Poly1305")'
    assert "ChaCha20-Poly1305" in c["negative_control"] and "AES/GCM" not in c["negative_control"]


# ── case 2: behavioural WITH a recorded control -- the negative control for this whole fix ─────
def test_behavioural_with_control_is_unchanged():
    """Do not break the honest case while fixing the dishonest one.

    Pinned to `technique_model.proof_contract`, the ORIGINAL source of truth, rather than to a copy
    of today's output -- a snapshot of the new behaviour would pass even if I had changed it.
    """
    f = _behavioural_with_control()
    contract = technique_model.proof_contract({"vuln_class": "sqli", "oracle": ""})
    c = poc_bundle.build(f)["confirmation"]
    assert c["negative_control"] == contract["negative_control"]
    assert c["evidence_requirements"] == contract["evidence_requirements"]
    assert c["safety"] == contract["safety"] and c["cleanup"] == contract["cleanup"]
    assert c["control_status"] == proof_schema.CONTROL_RECORDED
    assert "Baseline + mutation request/response retained for deterministic replay." in \
        " | ".join(c["evidence_requirements"])
    # and no source-only key leaked onto a behavioural bundle
    assert "source_evidence" not in poc_bundle.build(f)


# ── case 3: behavioural WITHOUT a recorded control -- the 837b1f0 behaviour, in the bundle ─────
def test_behavioural_without_control_says_so_in_the_bundle_too():
    """Session 2's REJECT: the report said NOT ESTABLISHED and the dossier asserted a control."""
    c = poc_bundle.build(_behavioural_bare())["confirmation"]
    nc = c["negative_control"]
    assert nc.startswith("NO NEGATIVE CONTROL WAS RECORDED")
    assert "would settle it" in nc and "run it before" in nc
    assert not nc.startswith("NOT APPLICABLE"), "an unrun experiment is not an impossible one"
    assert c["control_status"] == proof_schema.CONTROL_NOT_RECORDED


# ── every surface states ONE claim (breaker check 7) ───────────────────────────────────────────
def test_the_report_and_the_dossier_state_the_same_claim():
    """`837b1f0` gated the report and not the bundle, so the SAME finding read "NOT ESTABLISHED" in
    the report and "an inert control does NOT reproduce the differential" in its own dossier. One
    composer now, so they cannot drift apart again."""
    import report
    for f in (_source_finding(), _behavioural_bare(), _behavioural_with_control()):
        assert report.proof_and_retest(f)["negative_control"] == \
            poc_bundle.build(f)["confirmation"]["negative_control"]


def test_control_ran_keeps_its_exact_meaning():
    """The predicate `837b1f0` introduced is unchanged, including on the unseen finding class: a
    source-derived finding really does hold no REQUEST-based artifact."""
    import report
    assert report.control_ran(_behavioural_with_control()) is True
    assert report.control_ran(_behavioural_bare()) is False
    assert report.control_ran(_source_finding()) is False
    for empty in ([], {}, "", "   ", None):
        assert report.control_ran({"family": "sqli", "negative_controls": empty}) is False, repr(empty)
    assert report.control_ran(None) is False and report.control_ran("nope") is False


def test_the_rendered_heading_is_three_way_because_the_fact_is():
    """"NOT ESTABLISHED" over a source finding is false too -- its FP-safety IS established, by a
    counter-example rather than by a request. A two-valued heading over a three-valued fact has to
    be wrong somewhere."""
    import report
    scope = {"in_scope": ["x"]}
    src = report.generate_html_report("P", [_source_finding()], scope)
    assert "rule-level counter-example (no request applies)" in src
    assert "NOT ESTABLISHED" not in src and "How this was confirmed" not in src
    bare = report.generate_html_report("P", [_behavioural_bare()], scope)
    assert "NOT ESTABLISHED for this finding" in bare and "How this was confirmed" not in bare
    real = report.generate_html_report("P", [_behavioural_with_control()], scope)
    assert "How this was confirmed" in real and "NOT ESTABLISHED" not in real
    md = report.generate_report("P", [_source_finding()], scope)
    assert "**False-positive safety: rule-level counter-example (no request applies)**" in md
    assert "NOT ESTABLISHED" not in md


def test_the_three_cases_are_distinguishable_from_the_json_alone():
    """A reader who did not run the scan gets three different answers, not one shape for all."""
    got = {}
    for name, f in (("source", _source_finding()),
                    ("behavioural_control", _behavioural_with_control()),
                    ("behavioural_bare", _behavioural_bare())):
        c = poc_bundle.build(f)["confirmation"]
        got[name] = (c["proof_kind"], c["control_status"], c["negative_control"][:24])
    assert len(set(got.values())) == 3, got
    assert got["source"][:2] == (proof_schema.SOURCE_DERIVED, proof_schema.CONTROL_NOT_APPLICABLE)
    assert got["behavioural_control"][:2] == (proof_schema.BEHAVIOURAL, proof_schema.CONTROL_RECORDED)
    assert got["behavioural_bare"][:2] == (proof_schema.BEHAVIOURAL, proof_schema.CONTROL_NOT_RECORDED)
