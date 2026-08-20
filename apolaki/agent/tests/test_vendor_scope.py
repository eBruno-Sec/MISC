"""Q-083 — a finding in code the operator does not maintain is DEMOTED WITH EVIDENCE, never dropped,
and the same call in first-party code is still reported.

Mission `2fb87a3a` shipped a client a CONFIRMED medium against `webapp/js/jquery.min.js` at "line 2",
because the whole bundle is line 2. The defect is not that the finding is false — nobody has bound
that `Math.random()`'s use, so nobody knows. The defect is that the lane asserted a confidence it had
no basis for, at a location the operator cannot act on.

EVERY FIXTURE IN THIS FILE IS A REAL FILE, copied byte-for-byte out of a running lab container. Two of
them exist specifically to kill a lazier implementation:

  * `vendor_scope_testsuiteutils_js.txt` is OWASP's OWN first-party file and it opens with `/*!`.
    A rule that treats a bang-comment as a vendor banner swallows it. (`test_negative_control_bare_
    bang_banner_*`)
  * `vendor_scope_benchmarktest_java.txt` is `BenchmarkTest00023.java`, a SCORED weakrand case whose
    `new java.util.Random().nextFloat()` is the same weakness class as the jQuery row. It must stay
    `confirmed` or the OWASP Benchmark score silently drops — `owasp_bench._detected` credits a case
    only when confidence is outside `_UNPROVEN`, and `"lead"` is inside it.

The load-bearing test is `test_negative_control_first_party_weak_randomness_is_still_confirmed`: a
heuristic that silences the analyser on code that matters is strictly worse than the noise it removes.
"""
from __future__ import annotations

import os
import shutil
import tempfile

import pytest

import codeintel
import proof_schema

FIXTURES = os.path.dirname(os.path.abspath(__file__))

#: fixture file -> the REAL repository path the specimen was taken from. The path matters: the
#: classifier reads directory segments, so a specimen filed under the wrong name tests nothing.
SPECIMENS = {
    "vendor_scope_jquery_min_js.txt": "webapp/js/jquery.min.js",
    "vendor_scope_js_cookie_js.txt": "webapp/js/js.cookie.js",
    "vendor_scope_testsuiteutils_js.txt": "webapp/js/testsuiteutils.js",
    "vendor_scope_captcha_ts.txt": "routes/captcha.ts",
    "vendor_scope_insecurity_ts.txt": "lib/insecurity.ts",
    "vendor_scope_benchmarktest_java.txt":
        "java/org/owasp/benchmark/testcode/BenchmarkTest00023.java",
}

#: Code the operator maintains. `testsuiteutils.js` is in here on purpose — it is a hand-written
#: OWASP file that merely LOOKS like a bundle at byte 0.
FIRST_PARTY = ("webapp/js/testsuiteutils.js", "routes/captcha.ts", "lib/insecurity.ts",
               "java/org/owasp/benchmark/testcode/BenchmarkTest00023.java")
THIRD_PARTY = ("webapp/js/jquery.min.js", "webapp/js/js.cookie.js")


def _read(fixture: str) -> str:
    with open(os.path.join(FIXTURES, fixture), encoding="utf-8", errors="ignore") as fh:
        return fh.read()


def _text_for(rel: str) -> str:
    for fx, path in SPECIMENS.items():
        if path == rel:
            return _read(fx)
    raise KeyError(rel)


@pytest.fixture(scope="module")
def tree():
    """The six specimens laid out at their real paths, reviewed once through the real walk.

    Not a hand-built findings list: `review_source_tree` is the function the mission ran, and a test
    that calls the classifier directly would never notice the walk failing to apply it.
    """
    root = tempfile.mkdtemp(prefix="vendorscope_")
    try:
        for fx, rel in SPECIMENS.items():
            dst = os.path.join(root, rel)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.copyfile(os.path.join(FIXTURES, fx), dst)
        yield codeintel.review_source_tree(root)
    finally:
        shutil.rmtree(root, ignore_errors=True)


def _findings_in(tree: dict, rel: str) -> list:
    return [f for f in tree["findings"] if f["file"] == rel]


# ── the apparatus itself: if the walk did not read the specimens, every assertion below is vacuous ──

def test_positive_control_every_specimen_was_actually_reviewed(tree):
    """The zero-findings and not-classified assertions are only meaningful if the files were READ."""
    assert tree["error"] == ""
    assert sorted(tree["files"]) == sorted(SPECIMENS.values())
    assert tree["files_scanned"] == len(SPECIMENS) == 6
    # and the analyser actually produced results on this corpus, so "still reported" can be tested
    assert len(tree["findings"]) > 0


# ── classification: evidence, not extension, not guesswork ──

@pytest.mark.parametrize("rel", THIRD_PARTY)
def test_real_vendor_bundles_are_classified_with_quotable_evidence(rel):
    kind, evidence = codeintel.not_maintained_source(rel, _text_for(rel))
    assert kind == "third-party", rel
    # the evidence must QUOTE what was observed — a bare "looks vendored" cannot be overruled by a
    # reader, and a medium-reliability signal that shows no work is not reviewable
    assert evidence
    assert "licence banner" in evidence or "licence pragma" in evidence
    banner = _text_for(rel).split("*/", 1)[0]
    assert any(tok in evidence for tok in banner.split()[:4]), evidence


@pytest.mark.parametrize("rel", FIRST_PARTY)
def test_negative_control_first_party_files_are_never_classified(rel):
    """MANDATORY CONTROL. Code the operator maintains must never be marked not-maintained."""
    kind, evidence = codeintel.not_maintained_source(rel, _text_for(rel))
    assert kind == "", "first-party file misclassified as %r (%s): %s" % (kind, rel, evidence)


def test_negative_control_bare_bang_banner_is_not_a_licence_banner():
    """`/*! Test suite JavaScript util functions */` is OWASP's own first-party header.

    It is the reason the rule requires a licence claim AND a released-version token, and it is the
    single fixture most likely to be broken by "simplifying" the banner check.
    """
    rel = "webapp/js/testsuiteutils.js"
    text = _text_for(rel)
    assert text.startswith("/*!"), "fixture no longer exercises the bang-comment path"
    assert codeintel.not_maintained_source(rel, text) == ("", "")


def test_classification_does_not_depend_on_the_min_js_name():
    """MEASURED refutation of the obvious fix (handoff §3.2).

    Juice Shop's 35 bundles are `main.js` / `polyfills.js` / `chunk-<HASH>.js`; not one ends in
    `.min.js`. A filename rule is a heuristic for one 2015 naming convention, not for vendored code,
    so the same bytes under a modern bundler name must still classify.
    """
    jquery = _text_for("webapp/js/jquery.min.js")
    for alt in ("frontend/main.js", "frontend/chunk-BDIM6GZO.js", "assets/polyfills.js"):
        kind, evidence = codeintel.not_maintained_source(alt, jquery)
        assert kind == "third-party", "%s classified %r" % (alt, kind)
        assert "licence banner" in evidence


def test_dependency_directory_classifies_a_tree_rooted_inside_it():
    """`_SKIP_DIRS` only prunes BELOW the walk root. Point the lane at a tree that is itself inside
    `node_modules/` and the walk never sees the segment, so the classifier has to carry it."""
    text = _text_for("lib/insecurity.ts")          # first-party bytes, vendored location
    kind, evidence = codeintel.not_maintained_source("node_modules/left-pad/index.js", text)
    assert kind == "third-party"
    assert "node_modules" in evidence


# ── THE CONTROL THE TICKET TURNS ON ──

def test_negative_control_first_party_weak_randomness_is_still_confirmed(tree):
    """The same weakness class as the demoted jQuery row, in code the operator maintains, must be
    reported AND still be confirmed.

    `routes/captcha.ts` and `lib/insecurity.ts` call `Math.random()`; `BenchmarkTest00023.java` calls
    `new java.util.Random().nextFloat()`. All three are CWE-330 — exactly what was demoted in the
    bundle. If a heuristic cannot tell these apart from jQuery it has removed noise by removing the
    signal, which is a worse product than the one the ticket complains about.
    """
    for rel in FIRST_PARTY:
        fs = _findings_in(tree, rel)
        if rel == "webapp/js/testsuiteutils.js":
            continue                     # real file, genuinely contains no rule hit; see below
        assert fs, "first-party file went silent: %s" % rel
        for f in fs:
            assert not f.get("source_kind"), "%s demoted: %r" % (rel, f.get("source_kind"))
            assert proof_schema.is_confirmed(f), "%s:%s demoted to %r" % (
                rel, f.get("line"), f.get("confidence"))
            assert "not-maintained-source" not in (f.get("tags") or [])

    # named explicitly so a regression cannot be waved through as "the fixture never fired"
    assert {f["cwe"] for f in _findings_in(tree, "routes/captcha.ts")} == {"CWE-330"}
    assert "CWE-330" in {f["cwe"] for f in _findings_in(
        tree, "java/org/owasp/benchmark/testcode/BenchmarkTest00023.java")}


def test_benchmark_case_keeps_the_confidence_its_score_depends_on(tree):
    """IMMUTABILITY. `owasp_bench._detected` credits a case only when confidence is outside
    `_UNPROVEN`, and `"lead"` is inside it — so demoting a scored file silently drops the suite
    score. Measured end to end in docs/handoff/vendor_scope.md §4.3 (crypto/hash/weakrand all
    100.0%); this is the unit-level tripwire for the same property."""
    rel = "java/org/owasp/benchmark/testcode/BenchmarkTest00023.java"
    fs = _findings_in(tree, rel)
    assert fs, "the scored weakrand case produced no finding at all"
    assert rel not in tree["not_maintained_files"]
    for f in fs:
        assert proof_schema.is_confirmed(f)
    import owasp_bench
    assert not any((f.get("confidence") or "confirmed") in owasp_bench._UNPROVEN for f in fs)


# ── the demotion itself ──

def test_third_party_finding_is_demoted_and_NOT_dropped(tree):
    """Deleting the row would delete the only place the operator learns the tree ships jQuery 2.1.4,
    and would do it invisibly. A file wrongly marked here loses `confirmed` and keeps its row; a file
    wrongly excluded from the walk vanishes without trace. Those errors are not symmetric."""
    rel = "webapp/js/jquery.min.js"
    assert rel in tree["files"], "the bundle was dropped from the walk"
    fs = _findings_in(tree, rel)
    assert fs, "the finding was deleted rather than demoted"
    for f in fs:
        assert f["source_kind"] == "third-party"
        assert f["source_kind_evidence"]
        assert not proof_schema.is_confirmed(f)
        assert "third-party" in f["tags"] and "not-maintained-source" in f["tags"]
        # the operator is told WHY the line number is not actionable, not just that it is a lead
        assert any("third-party" in g for g in f["proof_gap"])


def test_demotion_uses_the_ONE_shared_unproven_vocabulary(tree):
    """The demotion is only real if every surface that renders, counts, scores or exports a finding
    agrees it is unproven. A private word here would leave the HTML report stamping CONFIRMED on a
    row this module believes it retracted — which is exactly how that bug happened before."""
    demoted = [f for f in tree["findings"] if f.get("source_kind")]
    assert demoted
    for f in demoted:
        assert f["confidence"] in proof_schema.UNPROVEN_CONFIDENCE
        assert not proof_schema.is_confirmed(f)


def test_severity_is_deliberately_left_alone(tree):
    """Severity describes the class's impact IF real; confidence describes whether this instance is
    proven. The ticket's complaint is the second one. Rewriting severity would assert something new
    about the bug rather than retract a claim about the proof."""
    rel = "webapp/js/jquery.min.js"
    demoted = _findings_in(tree, rel)
    first_party = _findings_in(tree, "routes/captcha.ts")
    assert demoted and first_party
    same_cwe = [f for f in first_party if f["cwe"] == demoted[0]["cwe"]]
    assert same_cwe, "no first-party finding of the same CWE to compare severity against"
    assert demoted[0].get("severity") == same_cwe[0].get("severity")


def test_summary_reports_the_split_rather_than_implying_it(tree):
    """A consumer that wants only maintained code can filter, and one that wants the dependency
    inventory has it without re-deriving the classification."""
    assert set(tree["not_maintained_files"]) == set(THIRD_PARTY)
    for rel, row in tree["not_maintained_files"].items():
        assert row["kind"] == "third-party" and row["evidence"]
    # counts are over DIFFERENT populations and are not meant to match: js.cookie.js is correctly
    # identified as a dependency and simply contains nothing the rules fire on
    assert tree["not_maintained_findings"] == len(
        [f for f in tree["findings"] if f.get("source_kind")])
    assert tree["not_maintained_findings"] < len(tree["not_maintained_files"]) + 1


# ══════════════════════════════════════════════════════════════════════════════════════════════
# THE SECOND WALK — `codeintel.review()`, the leads path behind GET /codereview
# ══════════════════════════════════════════════════════════════════════════════════════════════
# `review_source_tree` was fixed first. `review()` is a SEPARATE walk in the same module and it had
# the identical blind spot. MEASURED on DVWA pulled from `apolaki-dvwa-1` (handoff §6.1):
#
#     leads in NOT-MAINTAINED files : 14 of 57  (24.6%)
#     does the lead row say so?     : NO -- no marker key on any row
#
# 24.6%, against the 0.141% blast radius on the corpus that raised the ticket. Fixing one walk and
# not the other would have closed the ticket and left the larger hole open.
#
# Every fixture below is a REAL DVWA file. The pair that carries the section is
# `vendor_scope_dvwa_munge_php.txt` and `vendor_scope_dvwa_weakid_impossible_php.txt`: BOTH call
# `sha1()`, both fire the same `weak_crypto` rule, and one is vendored HTMLPurifier while the other
# is DVWA's own. A heuristic that cannot separate those two has not removed noise, it has removed
# the signal.

DVWA_SPECIMENS = {
    # third-party, proved by the DIRECTORY it sits in
    "vendor_scope_dvwa_munge_php.txt":
        "external/phpids/0.6/lib/IDS/vendors/htmlpurifier/HTMLPurifier/URIFilter/Munge.php",
    # third-party, proved by CONTENT ALONE at a path that looks entirely first-party: a verbatim
    # copy of js-sha256 v0.9.0 filed under DVWA's own `vulnerabilities/` challenge tree. No path or
    # filename rule reaches this file; the `@license` pragma in its header does.
    "vendor_scope_dvwa_jssha256_js.txt": "vulnerabilities/javascript/source/high_unobfuscated.js",
    # generated: the OBFUSCATED build of that same library, one 10417-char line
    "vendor_scope_dvwa_high_obfuscated_js.txt": "vulnerabilities/javascript/source/high.js",
    # FIRST PARTY, and the same `sha1()`/`weak_crypto` hit as Munge.php
    "vendor_scope_dvwa_weakid_impossible_php.txt": "vulnerabilities/weak_id/source/impossible.php",
}

DVWA_THIRD_PARTY = ("external/phpids/0.6/lib/IDS/vendors/htmlpurifier/HTMLPurifier/URIFilter/"
                    "Munge.php", "vulnerabilities/javascript/source/high_unobfuscated.js")
DVWA_FIRST_PARTY = ("vulnerabilities/weak_id/source/impossible.php",)


@pytest.fixture(scope="module")
def leads():
    """The four DVWA specimens at their real paths, run through the real `review()` walk."""
    root = tempfile.mkdtemp(prefix="vendorscope_leads_")
    try:
        for fx, rel in DVWA_SPECIMENS.items():
            dst = os.path.join(root, rel)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.copyfile(os.path.join(FIXTURES, fx), dst)
        yield codeintel.review(root)
    finally:
        shutil.rmtree(root, ignore_errors=True)


def _leads_in(leads: dict, rel: str) -> list:
    return [f for f in leads["findings"] if f["file"] == rel]


def test_positive_control_the_leads_walk_read_every_dvwa_specimen(leads):
    """Without this, every "not marked" and "still reported" assertion below is vacuous."""
    assert leads["files_scanned"] == len(DVWA_SPECIMENS) == 4
    assert leads["total"] > 0
    # named, so a regression cannot pass by the fixture silently going quiet
    assert _leads_in(leads, "external/phpids/0.6/lib/IDS/vendors/htmlpurifier/HTMLPurifier/"
                            "URIFilter/Munge.php"), "the vendored sha1() lead vanished"
    assert _leads_in(leads, "vulnerabilities/weak_id/source/impossible.php"), \
        "the first-party sha1() lead vanished"


@pytest.mark.parametrize("rel", DVWA_THIRD_PARTY)
def test_leads_walk_marks_a_vendored_lead_with_quotable_evidence(leads, rel):
    fs = _leads_in(leads, rel)
    assert fs, "no lead at all in %s" % rel
    for f in fs:
        assert f["source_kind"] == "third-party", rel
        assert f["source_kind_evidence"]
        assert "third-party" in f["tags"] and "not-maintained-source" in f["tags"]


def test_negative_control_same_sha1_in_first_party_code_is_still_reported_unmarked(leads):
    """THE MANDATORY CONTROL, on a matched pair of REAL files.

    `HTMLPurifier/URIFilter/Munge.php:49`  -> `sha1($this->secretKey . ':' . $string)`
    `vulnerabilities/weak_id/source/impossible.php:6` -> `sha1(mt_rand() . time() . "Impossible")`

    Same call, same `weak_crypto` rule, opposite ownership. The first must be marked and the second
    must not, and the second must still be REPORTED -- a heuristic that swallows first-party code is
    worse than the noise it removes.
    """
    for rel in DVWA_FIRST_PARTY:
        fs = _leads_in(leads, rel)
        assert fs, "first-party file went silent: %s" % rel
        for f in fs:
            assert not f.get("source_kind"), "%s marked %r" % (rel, f.get("source_kind"))
            assert "not-maintained-source" not in (f.get("tags") or [])
        assert rel not in leads["not_maintained_files"]

    # the pair really is a pair: both sides fire, and they fire the SAME rule
    vendored = _leads_in(leads, "external/phpids/0.6/lib/IDS/vendors/htmlpurifier/HTMLPurifier/"
                                "URIFilter/Munge.php")
    own = _leads_in(leads, "vulnerabilities/weak_id/source/impossible.php")
    assert {f["rule"] for f in vendored} & {f["rule"] for f in own} == {"weak_crypto"}


def test_leads_walk_classifies_on_evidence_not_on_the_path_it_sits_in(leads):
    """`vulnerabilities/javascript/source/high_unobfuscated.js` is js-sha256 v0.9.0 verbatim, under
    DVWA's own challenge tree. Every path-shaped rule -- `vendor/`, `node_modules/`, `external/`,
    `*.min.js` -- misses it. It is caught because the file SAYS what it is."""
    rel = "vulnerabilities/javascript/source/high_unobfuscated.js"
    assert not any(seg in rel for seg in codeintel._VENDOR_PATH_SEG)
    assert not codeintel._MINIFIED_NAME_RX.search(rel.rsplit("/", 1)[-1])
    row = leads["not_maintained_files"][rel]
    assert row["kind"] == "third-party"
    assert "@license" in row["evidence"], row["evidence"]


def test_the_inventory_covers_files_that_produced_no_lead(leads):
    """KILLS THE LAZY MUTANT. Classifying only lead-bearing files was the obvious way to keep the
    recon path cheap; measured, it loses 227 of DVWA's 239 dependency files (handoff §6.2).

    `vulnerabilities/javascript/source/high.js` is a real one-line 10417-char obfuscated bundle.
    `review()` skips lines over 600 chars, so it yields NO lead -- and it must still be inventoried,
    because "this tree ships an obfuscated copy of js-sha256" is the finding.
    """
    rel = "vulnerabilities/javascript/source/high.js"
    assert _leads_in(leads, rel) == [], "fixture no longer exercises the no-lead path"
    assert rel in leads["not_maintained_files"], "inventory only covers lead-bearing files"
    assert leads["not_maintained_files"][rel]["kind"] == "generated"
    assert "minified geometry" in leads["not_maintained_files"][rel]["evidence"]


def test_the_obfuscated_challenge_is_flagged_and_NOT_filtered_or_demoted(leads):
    """WHY THIS WALK MARKS INSTEAD OF FILTERING, found on a real tree.

    DVWA's `javascript` challenge IS the obfuscated `high.js`: attacking that client-side code is
    the exercise. A filter would have deleted the target, and a confidence demotion would have told
    the operator to look away from it. Marking costs no signal and adds the one fact worth having --
    the maintained source is the file next door.
    """
    rel = "vulnerabilities/javascript/source/high.js"
    assert rel in leads["not_maintained_files"]
    # the file was READ, not pruned from the walk
    assert leads["files_scanned"] == 4
    # and no lead anywhere in this walk was given a `confidence`: a review() row has no such key,
    # so writing one onto the marked subset alone would make its ABSENCE elsewhere mean something
    for f in leads["findings"]:
        assert "confidence" not in f, "the leads walk started asserting a confidence: %r" % f
        assert "proof_gap" not in f


def test_both_walks_speak_the_SAME_marker_vocabulary():
    """Two walks, one word for the same fact. A second private name for "this is a dependency" is
    how the original bug shipped, and `_tag_not_maintained` is the single place it is written."""
    tree_row, lead_row = {}, {}
    codeintel._mark_not_maintained(tree_row, "third-party", "evidence text")
    codeintel._tag_not_maintained(lead_row, "third-party", "evidence text")
    for key in ("source_kind", "source_kind_evidence", "tags"):
        assert tree_row[key] == lead_row[key], key
    # and the demotion is the ONLY thing the tree walk adds on top
    assert set(tree_row) - set(lead_row) == {"confidence", "proof_gap"}
    assert tree_row["confidence"] in proof_schema.UNPROVEN_CONFIDENCE
