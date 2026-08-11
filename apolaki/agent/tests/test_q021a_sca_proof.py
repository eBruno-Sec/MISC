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
