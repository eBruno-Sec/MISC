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
