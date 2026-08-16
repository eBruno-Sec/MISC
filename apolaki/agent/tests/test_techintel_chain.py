"""Q-021C — the technology-intelligence CHAIN: a detected version must change what gets TESTED.

Before this ticket the chain stopped at `assess_component`: a version string was matched against a
table of ceilings and a finding was emitted. Nothing ever asked the target a question because of
what was detected. `fingerprint.py` states the rule this file enforces on the other end --
DETECTION IS NEVER A VULNERABILITY -- so the honest way to spend a detection is to spend it on a
TEST, and to let only the test's observation change the claim.

What is proven here:

  detected library + VERSION  ->  which applicability probes are in range   (the version decides)
  probe                       ->  reads the SERVED artifact for the CVE's own code
  presence control            ->  the artifact really contains the library, not merely its name
  verdict                     ->  CORROBORATED raises the RUNG, REFUTED removes the finding,
                                  INCONCLUSIVE changes nothing at all
  finding                     ->  evidence cites the version AND what was observed in the bytes

And what is NOT claimed: locating vulnerable code is not observing exploitation. A corroborated
probe must leave `confidence` and `component_status` exactly where `behaviour_proof_ok` put them.
That is pinned here too, because the failure this project keeps finding is a rung being skipped.
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import dependency_intel as dep


# ── artifact fixtures ────────────────────────────────────────────────────────────────────────
# Structurally faithful to the five artifacts measured live on the labs (mutillidae jquery 1.8.3,
# webgoat 2.1.4, webgoat 3.4.1, dvga 3.5.1, dvga bootstrap.bundle 4.5.3) and deliberately synthetic
# rather than copied bytes: what the probe reads is the SHAPE, and a synthetic fixture makes the
# shape the test is asserting on visible in the test.

_JQ_RUNTIME = 'k.fn.init=function(e,t){};k.fn=k.prototype={jquery:"x",constructor:k};'
_EXTEND_HEAD = "k.extend=k.fn.extend=function(){var e,t,n,r,i,o,a=arguments[0]||{},s=1;"
_MERGE_LOOP_VULNERABLE = "for(t in e)r=e[t],a!==r&&(a[t]=r);"
_MERGE_LOOP_PATCHED = 'for(t in e)r=e[t],"__proto__"!==t&&a!==r&&(a[t]=r);'
_SELFCLOSE_REWRITE = r"var je=/<(?!area|br|col|embed|hr|img|input|link|meta|param)(([a-z][^>]*)[^>]*)\/>/gi;"


def _jq(version, *, patched_proto=False, selfclosing=True, runtime=True, extend=True):
    """A served jQuery artifact with each CVE's code present or absent, independently."""
    parts = ["/*! jQuery JavaScript Library v%s */" % version]
    if runtime:
        parts.append(_JQ_RUNTIME)
    if extend:
        parts.append(_EXTEND_HEAD + (_MERGE_LOOP_PATCHED if patched_proto else _MERGE_LOOP_VULNERABLE))
    if selfclosing:
        parts.append(_SELFCLOSE_REWRITE)
    return "".join(parts)


#: The MEASURED false positive, reduced to its cause. Bootstrap 4.5.3's own dependency check names
#: a jQuery version in an error string; `LIB_SIGNATURES` reads that as a CONFIRMED jquery 1.9.1 and
#: (before this ticket) raised a medium finding against a file containing no jQuery.
#:
#: The error-string line is copied from the `evidence` field of the component record
#: `fingerprint_js_content` really emitted for
#: http://apolaki-dvga-1:5013/static/bootstrap/js/bootstrap.bundle.min.js, not composed here:
#:   "'s JavaScript requires at least jQuery v1.9.1 but less than v4.0.0\")}};l.jQueryDetect"
#: `test_the_bootstrap_fixture_reproduces_the_component_record_measured_live` pins that.
#:
#: The filler exists because the real artifact is 84,152 bytes and the refutation is an
#: absence-of-evidence argument that is only allowed to fire on an artifact big enough to have
#: carried the evidence (`_MIN_ARTIFACT_FOR_ABSENCE`). A fixture that skipped the bulk would have
#: tested a branch the real file never takes.
_BOOTSTRAP_BUNDLE = (
    "/*! Bootstrap v4.5.3 (https://getbootstrap.com/) */"
    '!function(t,e){"object"==typeof exports?e(exports,require("jquery")):e(t.bootstrap={},t.jQuery)}'
    '(this,function(t,e){var n=e.fn.jquery.split(" ")[0].split(".");'
    'if(n[0]<2&&n[1]<9)throw new Error("Bootstrap\'s JavaScript requires at least jQuery v1.9.1 '
    'but less than v4.0.0")});se.prototype.__proto__=ne;'
    + "".join("var _w%d=function(o){return o&&1===o.nodeType?o:null};" % i for i in range(60))
)
assert len(_BOOTSTRAP_BUNDLE) >= 2048, "fixture must be large enough to reach the absence branch"


def _first(comps, name):
    return next(c for c in comps if c["name"] == name)


# ── 1. the detection now decides what is tested ──────────────────────────────────────────────
def test_the_version_not_merely_the_library_selects_which_probes_run():
    """THE TICKET. A detected technology WITH A VERSION changes what gets tested.

    Same library, same served shape, three versions -> three different probe sets. Nothing about
    the artifact drives this; the version does.
    """
    def probes(v):
        c = dep.make_component("jquery", v, "js-content-banner", dep.CONFIRMED)
        return sorted(r["probe"] for r in dep.probe_applicability(c, _jq(v)))

    assert probes("3.3.1") == ["jquery-extend-proto-guard", "jquery-selfclosing-rewrite"]
    # 3.4.1 carries the __proto__ fix, so CVE-2019-11358's range no longer contains it and its
    # probe is not even asked. The self-closing rewrite is still in range.
    assert probes("3.4.1") == ["jquery-selfclosing-rewrite"]
    # 3.6.0 is outside every range this module has a probe for: nothing is tested, and that is the
    # correct amount of testing.
    assert probes("3.6.0") == []


def test_a_versionless_or_artifactless_component_is_never_probed():
    """NEGATIVE CONTROL. Empty is a real input. No version => no range => no probe; no artifact =>
    nothing to read. Neither may be silently treated as a verdict."""
    no_ver = dep.make_component("jquery", "", "js-content-banner", dep.CONFIRMED)
    assert dep.probe_applicability(no_ver, _jq("3.3.1")) == []
    ver = dep.make_component("jquery", "3.3.1", "script-filename", dep.HIGH)
    assert dep.probe_applicability(ver, "") == []
    assert dep.probe_applicability(ver, None) == []
    assert dep.probe_applicability(None, _jq("3.3.1")) == []
    # an unversioned component reaching the finding path still says nothing about applicability
    assert dep.applicability_records(ver) == [] and dep.refuted_cves(ver) == set()


# ── 2. the probe reads the served artifact ───────────────────────────────────────────────────
def test_the_probe_finds_the_cves_own_code_in_a_vulnerable_artifact():
    comps = dep.fingerprint_js_content(_jq("3.3.1"), "https://t/js/app.js")
    recs = {r["probe"]: r for r in _first(comps, "jquery")["applicability"]}
    proto = recs["jquery-extend-proto-guard"]
    assert proto["verdict"] == dep.CORROBORATED
    assert proto["reason"] == "vulnerable_code_present_in_served_artifact"
    assert proto["cves"] == ["CVE-2019-11358"]
    assert "__proto__" in proto["looked_for"] and "NO `__proto__` guard" in proto["observed"]
    rewrite = recs["jquery-selfclosing-rewrite"]
    assert rewrite["verdict"] == dep.CORROBORATED
    assert rewrite["cves"] == ["CVE-2020-11022", "CVE-2020-11023"]


def test_the_guard_is_searched_inside_extend_and_not_across_the_whole_file():
    """FALSE-NEGATIVE control, in the direction that HIDES a vulnerability. `__proto__` is an
    ordinary identifier: measured once in bootstrap.bundle.min.js, in its prototype-chain helper.
    A whole-file search for the guard would declare a genuinely unpatched jQuery patched as soon as
    any concatenated plugin carries its own `"__proto__"` check -- which bundled sanitizers commonly
    do, in exactly the quoted form the guard regex looks for.

    The mention is padded past `_JQ_EXTEND_WINDOW` on purpose: a mutant that widens the search to
    the whole file must be killed by this, and a fixture whose mention lands inside the window
    would let it survive (measured -- the first version of this test did exactly that)."""
    body = (_jq("3.3.1") + "\n/* bundled plugin */\n" + ("// pad\n" * 400) +
            'function clean(o){for(var k in o){if(k==="__proto__"){delete o[k];}}}')
    assert body.index('"__proto__"') - body.index("k.extend=") > dep._JQ_EXTEND_WINDOW
    comp = _first(dep.fingerprint_js_content(body, "https://t/js/bundle.js"), "jquery")
    proto = next(r for r in comp["applicability"] if r["probe"] == "jquery-extend-proto-guard")
    assert proto["verdict"] == dep.CORROBORATED
    assert "CVE-2019-11358" in [c for g in dep.assess_component(comp) for c in g["ids"]]


def test_a_backpatched_artifact_refutes_the_advisory_its_version_label_matched():
    """The FALSE POSITIVE a version table cannot see: a file still LABELLED 3.3.1 whose extend
    already carries the 3.4.0 `__proto__` guard (a distro backport, or an in-place patch that never
    renames the banner). The version says vulnerable; the bytes say patched."""
    body = _jq("3.3.1", patched_proto=True)
    comps = dep.fingerprint_js_content(body, "https://t/js/jquery.js")
    comp = _first(comps, "jquery")
    proto = next(r for r in comp["applicability"] if r["probe"] == "jquery-extend-proto-guard")
    assert proto["verdict"] == dep.REFUTED and proto["reason"] == "patched_in_served_artifact"
    assert "__proto__" in proto["evidence"]          # the patched line itself is quoted back
    # CVE-2019-11358's group is gone; the self-closing group is untouched because ITS code is
    # still there. A probe refutes exactly one advisory, never the component.
    ids = [g["ids"] for g in dep.assess_component(comp)]
    assert ids == [["CVE-2020-11022", "CVE-2020-11023"]]


def test_a_version_read_from_a_file_that_does_not_contain_the_library_is_refuted():
    """MEASURED on a live lab (dvga /static/bootstrap/js/bootstrap.bundle.min.js): Bootstrap's own
    dependency-check error string is read as jquery 1.9.1 at CONFIRMED, and raised
    `Potentially vulnerable component: jquery@1.9.1 (CVE-2020-11022, +2 more)` on a file with no
    jQuery in it. The presence control is what kills it."""
    comps = dep.fingerprint_js_content(_BOOTSTRAP_BUNDLE, "https://t/js/bootstrap.bundle.min.js")
    comp = _first(comps, "jquery")
    assert comp["version"] == "1.9.1" and comp["confidence"] == dep.CONFIRMED
    recs = comp["applicability"]
    assert recs and all(r["verdict"] == dep.REFUTED for r in recs)
    assert all(r["reason"] == "library_absent_from_artifact" for r in recs)
    assert dep.assess_component(comp) == []          # the finding is gone
    # NEGATIVE CONTROL on the same bytes: bootstrap's OWN version is detected and unaffected.
    assert _first(comps, "bootstrap")["version"] == "4.5.3"


def test_the_presence_control_needs_the_runtime_and_not_a_mention_of_the_name():
    """Why the presence control is an AND of two markers and why `.fn.jquery` is not one of them.

    Measured over six served artifacts: `.fn.jquery` is PRESENT in bootstrap.bundle.min.js (it reads
    the host page's jQuery version) and ABSENT from the minified jQuery 2.1.4 / 3.4.1 / 3.5.1 that
    three labs serve. Picking the obvious marker would have inverted this check on real bytes.
    """
    pad = "var _p=1;" * 400                                       # past _MIN_ARTIFACT_FOR_ABSENCE
    assert ".fn.jquery" in _BOOTSTRAP_BUNDLE                      # the trap is present in the fixture
    assert dep._library_present("jquery", _BOOTSTRAP_BUNDLE)[0] == dep._ABSENT
    assert dep._library_present("jquery", _jq("3.3.1"))[0] is True
    # both markers required: either one alone is not the library
    assert dep._library_present("jquery", 'k.fn.init=function(){};' + pad)[0] == dep._ABSENT
    assert dep._library_present("jquery", 'x={jquery:"3.3.1"};' + pad)[0] == dep._ABSENT
    # FAILS CLOSED: a library with no runtime marker can never be refuted by absence
    state, why = dep._library_present("lodash", "anything at all")
    assert state == dep._ABSENT and "no runtime marker" in why


def test_the_bootstrap_fixture_reproduces_the_component_record_measured_live():
    """The fixture is only worth anything if it produces the record the real bytes produced.

    MEASURED against http://apolaki-dvga-1:5013/static/bootstrap/js/bootstrap.bundle.min.js on
    unpatched HEAD:
        {"name": "jquery", "version": "1.9.1", "source": "js-content-banner",
         "confidence": "confirmed", "evidence": "'s JavaScript requires at least jQuery v1.9.1 ..."}
        assess: [CVE-2020-11022/11023, CVE-2019-11358]
        TITLE: Potentially vulnerable component: jquery@1.9.1 (CVE-2020-11022, +2 more)
    An invented fixture that merely LOOKED like this is how three defects shipped in one session
    elsewhere in this project, so the shape is asserted field by field.
    """
    jq = _first(dep.fingerprint_js_content(_BOOTSTRAP_BUNDLE, "https://t/js/bootstrap.bundle.min.js"),
                "jquery")
    assert jq["version"] == "1.9.1"
    assert jq["source"] == "js-content-banner" and jq["confidence"] == dep.CONFIRMED
    assert "requires at least jQuery v1.9.1" in jq["evidence"]
    # and the phantom really did reach a finding before the probes existed
    plain = dep.make_component("jquery", "1.9.1", "js-content-banner", dep.CONFIRMED)
    f = dep.vulnerable_component_finding(plain, dep.assess_component(plain))
    assert f["title"] == "Potentially vulnerable component: jquery@1.9.1 (CVE-2020-11022, +2 more)"
    assert f["severity"] == "medium"


def test_absence_is_only_a_refutation_when_there_was_room_for_the_evidence():
    """REGRESSION, caught by a test this lane does not own.

    `library_absent_from_artifact` is an absence-of-evidence argument. On 84kB of Bootstrap it is
    decisive; on a 55-byte body that is nothing but a version comment it proves nothing, and
    refuting there turns a short read into a FALSE NEGATIVE.

    The live victim: `retest.evaluate` re-fingerprints a replacement body and asks
    `assess_component` whether the new version is still in range. `test_q021a_sca_proof.py::
    test_retest_upgrade_that_is_still_in_range_stays_open` upgrades 3.4.0 -> 3.4.1 with the fixture
    body below -- still inside `<3.5.0`, so the finding must stay OPEN. Refuting on it reported
    CLOSED: a remediation lie.
    """
    stub = "/*! jQuery JavaScript Library v3.4.1 */ ;(function(){})();"
    assert len(stub) < dep._MIN_ARTIFACT_FOR_ABSENCE
    state, why = dep._library_present("jquery", stub)
    assert state == dep._TOO_SMALL and "too little" in why
    comp = _first(dep.fingerprint_js_content(stub, "https://t/assets/jquery-3.4.0.js"), "jquery")
    rec = comp["applicability"][0]
    assert rec["verdict"] == dep.INCONCLUSIVE
    assert rec["reason"] == "artifact_too_small_to_prove_absence"
    # INCONCLUSIVE drops nothing, so the still-in-range advisory survives and the retest stays open
    assert dep.refuted_cves(comp) == set()
    assert [g["ids"] for g in dep.assess_component(comp)] == [["CVE-2020-11022", "CVE-2020-11023"]]
    import retest
    finding = dep.vulnerable_component_finding(
        dep.make_component("jquery", "3.4.0", "js-content-banner", dep.CONFIRMED,
                           "jQuery JavaScript Library v3.4.0", "https://t/assets/jquery-3.4.0.js"),
        dep.assess_component(dep.make_component("jquery", "3.4.0", "js-content-banner",
                                                dep.CONFIRMED)))
    v = retest.evaluate(finding, 200, stub)
    assert v["verdict"] == "open" and "3.4.1" in v["detail"]


# ── 3. what a probe may and may not change ───────────────────────────────────────────────────
def test_no_applicability_record_leaves_assess_component_byte_identical():
    """NEGATIVE CONTROL, and the reason this change cannot move a benchmark number. Absent means
    NOT PROBED -- never `refuted`. Every component built without an artifact (script-filename,
    cdn-path, and every existing caller) is assessed exactly as before."""
    for src, conf in (("script-filename", dep.HIGH), ("cdn-path", dep.HIGH),
                      ("js-content-banner", dep.CONFIRMED)):
        c = dep.make_component("jquery", "3.3.1", src, conf)
        assert "applicability" not in c
        ids = [g["ids"] for g in dep.assess_component(c)]
        assert ids == [["CVE-2020-11022", "CVE-2020-11023"], ["CVE-2019-11358"]]
    # an explicitly EMPTY record list is the same statement, not a refutation
    c = dep.make_component("jquery", "3.3.1", "script-filename", dep.HIGH)
    c["applicability"] = []
    assert len(dep.assess_component(c)) == 2


def test_inconclusive_drops_nothing():
    """A split bundle: the library is here, the merge implementation is not. Undecidable -- and an
    undecidable probe must not become a false negative."""
    body = _jq("3.3.1", extend=False)
    comp = _first(dep.fingerprint_js_content(body, "https://t/js/chunk.js"), "jquery")
    proto = next(r for r in comp["applicability"] if r["probe"] == "jquery-extend-proto-guard")
    assert proto["verdict"] == dep.INCONCLUSIVE and proto["reason"] == "site_not_located"
    assert dep.refuted_cves(comp) == set()                       # inconclusive is NOT a refutation
    assert [g["ids"] for g in dep.assess_component(comp)] == [["CVE-2020-11022", "CVE-2020-11023"],
                                                              ["CVE-2019-11358"]]


def test_a_group_survives_unless_every_cve_in_it_was_refuted():
    """Conservative by construction: a partially-refuted range still ships."""
    c = dep.make_component("jquery", "3.3.1", "js-content-banner", dep.CONFIRMED)
    c["applicability"] = [{"probe": "p", "verdict": dep.REFUTED, "cves": ["CVE-2020-11022"],
                           "reason": "patched_in_served_artifact", "looked_for": "x",
                           "observed": "y", "control_observed": "z"}]
    assert [g["ids"] for g in dep.assess_component(c)] == [["CVE-2020-11022", "CVE-2020-11023"],
                                                           ["CVE-2019-11358"]]


def test_a_corroborated_probe_raises_the_rung_and_nothing_else():
    """THE HONESTY CONTROL. Locating the vulnerable code is not observing exploitation. Severity,
    `confidence` and `component_status` must be identical to the version-only finding; only
    `proof_state`, the evidence and the tag may move."""
    probed = _first(dep.fingerprint_js_content(_jq("3.3.1"), "https://t/js/app.js"), "jquery")
    plain = dep.make_component("jquery", "3.3.1", "js-content-banner", dep.CONFIRMED)
    f_probed = dep.vulnerable_component_finding(probed, dep.assess_component(probed))
    f_plain = dep.vulnerable_component_finding(plain, dep.assess_component(plain))
    for k in ("severity", "confidence", "component_status", "version_confidence", "family",
              "cwe", "cves", "proof_gap"):
        assert f_probed[k] == f_plain[k], k
    assert f_probed["confidence"] == "lead"
    assert f_probed["component_status"] == dep.POTENTIALLY_AFFECTED
    assert f_probed["proof_state"] == dep.APPLICABILITY_CONFIRMED
    assert f_plain["proof_state"] == dep.ADVISORY_MATCHED
    assert "applicability-confirmed" in f_probed["tags"]
    assert "applicability-confirmed" not in f_plain["tags"]
    assert "needs-confirmation" in f_probed["tags"]          # still a lead, still says so


def test_a_behaviour_proof_still_outranks_applicability():
    """The rungs above this one are unchanged. A real behaviour differential is the only thing that
    reaches ORACLE_CONFIRMED, with or without a probe."""
    probed = _first(dep.fingerprint_js_content(_jq("3.3.1"), "https://t/js/app.js"), "jquery")
    proof = {"cve": "CVE-2019-11358", "trigger": "t", "observed": "polluted",
             "control": "same request, trigger absent", "control_observed": "not polluted"}
    f = dep.vulnerable_component_finding(probed, dep.assess_component(probed), behaviour_proof=proof)
    assert f["confidence"] == "confirmed" and f["component_status"] == dep.AFFECTED
    assert f["proof_state"] == dep.ORACLE_CONFIRMED
    assert not f.get("proof_gap")


# ── 4. the chain is visible in the report ────────────────────────────────────────────────────
def test_the_finding_evidence_states_the_version_and_what_was_observed_in_the_bytes():
    """The report renders `evidence`. The chain has to be readable there or it did not happen for
    anyone but the code."""
    probed = _first(dep.fingerprint_js_content(_jq("3.3.1"), "https://t/js/app.js"), "jquery")
    f = dep.vulnerable_component_finding(probed, dep.assess_component(probed))
    ev = f["evidence"]
    assert "jquery@3.3.1" in ev                                  # the version
    assert "CVE-2019-11358" in ev                                # the advisory it matched
    assert "applicability probe jquery-extend-proto-guard" in ev  # the test that ran
    assert "OBSERVED" in ev and "__proto__" in ev                # what the bytes said
    assert "control -" in ev                                     # and the control that backed it
    assert "js/app.js" in f["target"]
    # the structured record travels too, so no consumer has to regex the prose
    assert [r["probe"] for r in f["applicability"]] == ["jquery-extend-proto-guard",
                                                        "jquery-selfclosing-rewrite"]
    assert any("Applicability:" in s for s in f["reproduction_steps"])
    assert "APPLICABILITY-confirmed only" in f["success_oracle"]
    assert "NOT observed" in f["impact"]                         # and still says what it did not do


def test_a_refuted_probe_is_recorded_on_the_finding_when_one_still_ships():
    """A refusal must never be an invisible drop. When one advisory is refuted and another is not,
    the surviving finding still carries the refusal."""
    comp = _first(dep.fingerprint_js_content(_jq("3.3.1", patched_proto=True), "https://t/j.js"),
                  "jquery")
    f = dep.vulnerable_component_finding(comp, dep.assess_component(comp))
    assert f["cves"] == ["CVE-2020-11022", "CVE-2020-11023"]     # 11358 dropped
    verdicts = {r["probe"]: r["verdict"] for r in f["applicability"]}
    assert verdicts["jquery-extend-proto-guard"] == dep.REFUTED  # ...and the reason travels
    assert verdicts["jquery-selfclosing-rewrite"] == dep.CORROBORATED


# ── 5. the tables cannot drift ───────────────────────────────────────────────────────────────
def test_every_probe_names_cve_ids_that_the_advisory_table_actually_has():
    """A near-miss identifier is worse than a missing one: `default_creds` vs
    `default_credentials` made four ASVS objectives unfailable. A probe whose CVE id is not in
    KNOWN_VULN can never be in range, so it would silently never run."""
    table = {str(c).upper() for _lib, _ceil, cves, _s, _sum in dep.KNOWN_VULN for c in cves}
    libs = {lib for lib, _c, _i, _s, _su in dep.KNOWN_VULN}
    for p in dep.APPLICABILITY_PROBES:
        assert p["library"] in libs, p["id"]
        assert p["library"] in dep._RUNTIME_MARKERS, p["id"]      # no probe without its control
        assert {str(c).upper() for c in p["cves"]} <= table, p["id"]
        # and it must actually be selectable for some version of that library
        assert any(dep._probe_in_range("0.0.1", p) for _ in (0,)), p["id"]


def test_probe_ids_are_unique_and_every_verdict_is_a_declared_constant():
    ids = [p["id"] for p in dep.APPLICABILITY_PROBES]
    assert len(ids) == len(set(ids))
    for body in (_jq("3.3.1"), _jq("3.3.1", patched_proto=True), _jq("3.3.1", extend=False),
                 _BOOTSTRAP_BUNDLE):
        comp = _first(dep.fingerprint_js_content(body, "https://t/x.js"), "jquery")
        for r in comp["applicability"]:
            assert r["verdict"] in dep.APPLICABILITY_VERDICTS
            for k in ("probe", "library", "version", "cves", "looked_for", "observed",
                      "reason", "control", "control_observed", "location"):
                assert k in r, k


def test_the_extend_window_covers_the_guard_in_an_unminified_build():
    """The window is a MEASURED bound, not a guess: the minified builds put the guard ~200 bytes
    past the site and the unminified source ~1.1kB past it (comments and whitespace). A window too
    small reports a patched file as vulnerable, which is the direction that produces a false
    positive, so it is pinned."""
    unminified = (
        "/*! jQuery JavaScript Library v3.3.1 */" + _JQ_RUNTIME +
        "jQuery.extend = jQuery.fn.extend = function() {\n" +
        "\t// handle a deep copy situation\n" * 40 +          # ~1.2kB of padding
        '\t\t\t\tif ( name === "__proto__" || target === copy ) {\n\t\t\t\t\tcontinue;\n\t\t\t\t}\n')
    assert 900 < unminified.index("__proto__") - unminified.index("jQuery.extend") < dep._JQ_EXTEND_WINDOW
    verdict, _obs, reason, _ev = dep._probe_jquery_extend_proto(unminified)
    assert verdict == dep.REFUTED and reason == "patched_in_served_artifact"


# ── 6. the composition rule lives in one place ───────────────────────────────────────────────
def test_the_scan_path_reconciles_a_stale_filename_against_the_served_body():
    """A tested guard that never ran where it mattered.

    `reconcile_components` was written to remove exactly this false positive and is covered by
    `test_q021a_sca_proof.py`. MEASURED on this tree: its only production caller was
    `retest.py:123`. `tools._run_js_review` hand-rolled the same composition WITHOUT reconciling,
    so the false positive shipped on every scan and was cleaned up only when someone retested.
    """
    url = "https://t/assets/jquery-3.4.0.js"          # the label an in-place patch never renames
    body = "/*! jQuery JavaScript Library v3.6.0 */"  # what is actually served, and patched
    raw = dep.fingerprint_js_content(body, url) + dep.fingerprint_url(url)
    assert {c["version"] for c in raw} == {"3.6.0", "3.4.0"}      # both readings really are produced
    assert any(dep.assess_component(c) for c in raw)              # and the stale one really does fire

    comps = dep.components_for_artifact(body, url)
    assert [(c["name"], c["version"], c["confidence"]) for c in comps] == \
        [("jquery", "3.6.0", dep.CONFIRMED)]
    assert [dep.assess_component(c) for c in comps] == [[]]       # no finding survives


def test_reconciling_the_scan_path_does_not_drop_a_consistent_or_unlabelled_artifact():
    """NEGATIVE CONTROL, against the two shapes every real lab artifact actually has.

    Measured live: webgoat serves `jquery-2.1.4.min.js` whose body ALSO says 2.1.4 (label and body
    agree), and `jquery.min.js` whose filename carries no version at all. Reconciliation must be a
    no-op on both, or it would delete true positives to remove a false one.
    """
    agree = dep.components_for_artifact("/*! jQuery v2.1.4 | (c) jQuery Foundation */" + _JQ_RUNTIME,
                                        "https://t/js/libs/jquery-2.1.4.min.js")
    assert [(c["name"], c["version"]) for c in agree] == [("jquery", "2.1.4")]
    assert dep.assess_component(agree[0])                         # still a finding, as it must be

    unlabelled = dep.components_for_artifact(_jq("3.4.1"), "https://t/js/libs/jquery.min.js")
    assert [(c["name"], c["version"]) for c in unlabelled] == [("jquery", "3.4.1")]
    assert dep.assess_component(unlabelled[0])

    # and the applicability records survive reconciliation -- they are the reason the finding is
    # more than a version match, so losing them here would silently undo Q-021C
    assert [r["probe"] for r in unlabelled[0]["applicability"]] == ["jquery-selfclosing-rewrite"]


def test_probe_helpers_tolerate_junk_records():
    """`applicability` arrives from persisted engagement state, so it must survive junk without
    crashing the assessment of a real component."""
    c = dep.make_component("jquery", "3.3.1", "js-content-banner", dep.CONFIRMED)
    c["applicability"] = ["not a dict", None, 42, {"verdict": dep.REFUTED}]
    assert dep.applicability_records(c) == [{"verdict": dep.REFUTED}]
    assert dep.refuted_cves(c) == set()                    # a record with no ids refutes nothing
    assert len(dep.assess_component(c)) == 2
    assert dep.corroborated_records(c) == []
