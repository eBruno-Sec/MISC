"""Q-021A — a version match is not an exploit.

`dependency_intel.vulnerable_component_finding` used to stamp `confidence="confirmed"` on a finding
whose own prose said exploitability "was NOT confirmed in this test". The machine-readable field
contradicted the human text beside it, and every consumer reads the field.

Root cause: `confidence` answered two different questions with one word — "are we sure the served
version is X?" and "are we sure this is exploitable?". These tests pin the split:

  version_confidence  -> how sure we are of the SERVED VERSION      (confirmed / high / low)
  component_status    -> whether the CVE's OWN BEHAVIOUR was seen   (affected / potentially_affected)
  confidence          -> the platform proof verdict; `confirmed` ONLY on a behaviour differential.

The oracle is a CVE-specific behaviour differential. The mandatory negative control is a
structurally identical request with the trigger ABSENT that must not reproduce the behaviour.
"""
import dependency_intel as dep


# a real, in-range component: angular 1.7.7 fingerprinted from an odd-separator filename (HIGH)
def _angular():
    return dep.fingerprint_url("https://t/js/angular_1-7-7.js")[0]


def _proof(cve="CVE-2023-26118", **kw):
    p = {"cve": cve,
         "trigger": "GET /?q={{7*7}} with ng-app in scope",
         "observed": "the response rendered 49 — the AngularJS expression was evaluated",
         "control": "GET /?q=7*7 (structurally identical, expression delimiters absent)",
         "control_observed": "the response rendered the literal 7*7 — no evaluation"}
    p.update(kw)
    return p


# ── the defect itself ─────────────────────────────────────────────────────────
def test_database_match_alone_is_never_confirmed():
    comp = _angular()
    vulns = dep.assess_component(comp)
    assert vulns, "fixture precondition: angular 1.7.7 must match a known-vulnerable range"
    f = dep.vulnerable_component_finding(comp, vulns)
    # the version is certain; the exploit is not. Two fields, two answers.
    assert f["version_confidence"] == dep.HIGH
    assert f["component_status"] == dep.POTENTIALLY_AFFECTED
    assert f["confidence"] != dep.CONFIRMED, "a version-range match must not be a confirmed finding"
    assert f["proof_gap"], "an unproven finding must name what is missing"
    # the machine-readable field and the prose must now AGREE
    assert "not confirmed" in f["impact"].lower() or "not an observed exploit" in f["impact"].lower()


def test_behaviour_differential_confirms():
    comp = _angular()
    vulns = dep.assess_component(comp)
    f = dep.vulnerable_component_finding(comp, vulns, behaviour_proof=_proof())
    assert f["confidence"] == dep.CONFIRMED
    assert f["component_status"] == dep.AFFECTED
    assert not f.get("proof_gap")
    assert "CVE-2023-26118" in f["evidence"] and "control" in f["evidence"].lower()


# ── negative controls (mandatory) ─────────────────────────────────────────────
def test_negative_control_trigger_absent_behaving_identically_does_not_confirm():
    """(a) A structurally identical request with the trigger absent must not confirm.
    If the control reproduces the same behaviour, the 'vulnerability' is just what the app does."""
    comp = _angular()
    vulns = dep.assess_component(comp)
    same = _proof(control_observed="the response rendered 49 — the AngularJS expression was evaluated")
    f = dep.vulnerable_component_finding(comp, vulns, behaviour_proof=same)
    assert f["confidence"] != dep.CONFIRMED
    assert "no_differential" in f["proof_gap"]


def test_low_version_confidence_can_never_be_affected_however_many_cves():
    """(c) CVE_ELIGIBLE is the single enforcement point: a guessed version carries no CVE, so it can
    never be AFFECTED — even if a feed hands back a hundred CVEs and a probe claims to have fired."""
    guessed = dep.make_component("angular", "1.7.7", "guess", dep.LOW)
    assert dep.assess_component(guessed) == []          # the ladder already refuses to assess it
    many = [{"ids": ["CVE-%d" % i for i in range(100)], "severity": "critical", "summary": "s"}]
    f = dep.vulnerable_component_finding(guessed, many, behaviour_proof=_proof(cve="CVE-0"))
    assert f["version_confidence"] == dep.LOW
    assert f["component_status"] == dep.POTENTIALLY_AFFECTED
    assert f["confidence"] != dep.CONFIRMED
    assert "version_confidence_too_low" in f["proof_gap"]


def test_grouped_range_a_proof_for_an_unmatched_cve_does_not_confirm():
    """FP risk — grouped CVE ranges. jQuery 3.4.0 matches the <3.5.0 group (CVE-2020-11022/11023) but
    NOT the <3.4.0 group (CVE-2019-11358). A probe naming the unmatched CVE must not confirm."""
    comp = dep.make_component("jquery", "3.4.0", "js-content-banner", dep.CONFIRMED, "jQuery v3.4.0")
    vulns = dep.assess_component(comp)
    ids = {c for v in vulns for c in v["ids"]}
    assert "CVE-2020-11022" in ids and "CVE-2019-11358" not in ids
    f = dep.vulnerable_component_finding(comp, vulns, behaviour_proof=_proof(cve="CVE-2019-11358"))
    assert f["confidence"] != dep.CONFIRMED
    assert "cve_not_in_matched_ranges" in f["proof_gap"]


def test_partial_proof_is_not_a_proof():
    comp = _angular()
    vulns = dep.assess_component(comp)
    for drop in ("trigger", "observed", "control", "control_observed"):
        p = _proof()
        p[drop] = ""
        f = dep.vulnerable_component_finding(comp, vulns, behaviour_proof=p)
        assert f["confidence"] != dep.CONFIRMED, "missing %s must not confirm" % drop
        assert drop in f["proof_gap"]


def test_behaviour_proof_ok_is_pure_and_reports_its_gaps():
    ok, gaps = dep.behaviour_proof_ok(None, ["CVE-1"])
    assert not ok and gaps == ["behaviour_probe_not_run"]
    ok, gaps = dep.behaviour_proof_ok(_proof(cve="CVE-2023-26118"), ["CVE-2023-26118"])
    assert ok and gaps == []


# ── slice 2: the proof gate must inspect SCA findings ────────────────────────
import proof_schema


def test_proof_gate_demotes_a_presence_only_sca_confirm():
    """The pre-Q-021A shape: family=vulnerable_component, confidence=confirmed, evidence naming only
    the served version. `demote_unproven` used to pass it straight through because
    `vulnerable_component` was absent from _DEFAULT_ENFORCE, so the false CONFIRMED reached the
    client report intact."""
    stale = {"title": "Vulnerable component: angular@1.7.7", "family": "vulnerable_component",
             "confidence": "confirmed", "severity": "medium",
             "evidence": "angular@1.7.7 from script-filename: https://t/js/angular_1-7-7.js",
             "impact": "Known-vulnerable dependency.",
             "reproduction_steps": ["Load the script", "Confirm the banner"]}
    out = proof_schema.demote_unproven([stale])
    assert out[0]["confidence"] == "lead"
    assert out[0]["proof_gap"] and "needs-confirmation" in out[0]["tags"]


def test_proof_gate_demotes_a_bare_cwe1104_confirm_with_no_family():
    only_cwe = {"title": "outdated lib", "cwe": "CWE-1104", "confidence": "confirmed",
                "evidence": "server banner reports nginx 1.14.0", "impact": "x",
                "reproduction_steps": ["curl -i https://t/"]}
    assert proof_schema.family_of(only_cwe) == "vulnerable_component"
    assert proof_schema.demote_unproven([only_cwe])[0]["confidence"] == "lead"


def test_proof_gate_does_not_demote_the_real_behaviour_confirmed_sca_finding():
    """NEGATIVE CONTROL for slice 2 — enforcing a new family must not create a false negative.
    The producer's own behaviour-differential output has to survive the gate untouched."""
    comp = _angular()
    f = dep.vulnerable_component_finding(comp, dep.assess_component(comp), behaviour_proof=_proof())
    assert f["confidence"] == "confirmed"
    ok, missing = proof_schema.validate_confirmed(f)
    assert ok, missing
    assert proof_schema.demote_unproven([f])[0]["confidence"] == "confirmed"


def test_proof_gate_still_ignores_families_outside_the_enforce_set():
    """NEGATIVE CONTROL — the deliberately narrow default is preserved for every other family; this
    slice widens it by exactly one entry, not to 'all'."""
    other = {"title": "weak random", "family": "weak_random", "confidence": "confirmed",
             "evidence": "short", "impact": ""}
    assert proof_schema.demote_unproven([other])[0]["confidence"] == "confirmed"
    assert "vulnerable_component" in proof_schema._DEFAULT_ENFORCE
    assert "weak_random" not in proof_schema._DEFAULT_ENFORCE


# ── slice 3: a patched component must CLOSE, not stay OPEN ───────────────────
import retest

_JQ_340 = "/*! jQuery JavaScript Library v3.4.0 */ ;(function(){})();"
_JQ_360 = "/*! jQuery JavaScript Library v3.6.0 */ ;(function(){})();"
_JQ_341 = "/*! jQuery JavaScript Library v3.4.1 */ ;(function(){})();"


def _jq_finding(url="https://t/assets/jquery-3.4.0.js"):
    comp = dep.make_component("jquery", "3.4.0", "js-content-banner", dep.CONFIRMED,
                              "jQuery JavaScript Library v3.4.0", url)
    return dep.vulnerable_component_finding(comp, dep.assess_component(comp))


def test_retest_uses_a_version_oracle_not_a_reachability_oracle():
    p = retest.plan(_jq_finding())
    assert p["retestable"] is True and p["oracle"] == "component_version"
    # the old mapping asked "is a file still served here", which any patched replacement answers yes to
    assert retest._GET_ORACLE["vulnerable_component"] != "reachable"


def test_retest_patched_component_closes():
    """(b) THE NEGATIVE CONTROL. A patched replacement still returns a non-empty 2xx from the same
    URL. Under the `reachable` oracle that was OPEN — telling a client their fix did not work, which
    is worse than missing the bug."""
    v = retest.evaluate(_jq_finding(), 200, _JQ_360)
    assert v["verdict"] == "closed", v
    assert "3.6.0" in v["detail"]


def test_retest_stale_bundle_filename_does_not_keep_a_fixed_finding_open():
    """FP risk — /assets/jquery-3.4.0.js now SERVING 3.6.0. The body states the truth; the path is
    only a label, and an in-place patch does not rename the file."""
    v = retest.evaluate(_jq_finding("https://t/assets/jquery-3.4.0.js"), 200, _JQ_360)
    assert v["verdict"] == "closed"


def test_retest_unpatched_component_stays_open():
    v = retest.evaluate(_jq_finding(), 200, _JQ_340)
    assert v["verdict"] == "open" and "3.4.0" in v["detail"]


def test_retest_upgrade_that_is_still_in_range_stays_open():
    """3.4.0 -> 3.4.1 leaves the <3.5.0 range unfixed. A version CHANGE is not a fix."""
    v = retest.evaluate(_jq_finding(), 200, _JQ_341)
    assert v["verdict"] == "open" and "3.4.1" in v["detail"]


def test_retest_component_no_longer_served_closes():
    assert retest.evaluate(_jq_finding(), 404, "")["verdict"] == "closed"


def test_retest_never_reports_open_from_the_filename_alone():
    """Filename spoofing / stale-label safety: if the replacement body states no version, the only
    evidence left is the unchanged path — which a patch in place never updates. Honest answer is
    INCONCLUSIVE; a false OPEN here is the remediation lie this slice exists to remove."""
    v = retest.evaluate(_jq_finding(), 200, "!function(){}();")   # minified, banner stripped
    assert v["verdict"] == "inconclusive"


def test_retest_without_structured_component_fields_is_inconclusive_not_open():
    """A finding persisted before Q-021A carries no component/component_version. It must degrade to
    an honest 'cannot tell', never back to the reachability answer."""
    legacy = {"family": "vulnerable_component", "target": "https://t/assets/jquery-3.4.0.js",
              "title": "Vulnerable component: jquery@3.4.0", "confidence": "lead"}
    assert retest.evaluate(legacy, 200, _JQ_340)["verdict"] == "inconclusive"
