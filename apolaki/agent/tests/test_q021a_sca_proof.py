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


# ── slice 4: SCA findings carry structured CVEs, so KEV can match them ───────
import report


def test_sca_finding_emits_a_structured_cve_list():
    """KEV matching builds its blob from `cve` / `cves` / `evidence`. The SCA finding's CVE ids lived
    only in the title and description, so it silently missed KEV. The fix is a structured `cves`
    list from the PRODUCER — never a wider regex that scrapes titles."""
    comp = dep.make_component("jquery", "3.4.0", "js-content-banner", dep.CONFIRMED, "jQuery v3.4.0",
                              "https://t/a.js")
    f = dep.vulnerable_component_finding(comp, dep.assess_component(comp))
    assert isinstance(f["cves"], list)
    assert f["cves"] == ["CVE-2020-11022", "CVE-2020-11023"]
    # exactly the ids of the ranges this version MATCHED — 3.4.0 is not < 3.4.0
    assert "CVE-2019-11358" not in f["cves"]


def test_kev_section_matches_an_sca_finding_and_labels_its_status_honestly():
    comp = dep.make_component("jquery", "3.4.0", "js-content-banner", dep.CONFIRMED, "jQuery v3.4.0",
                              "https://t/a.js")
    f = dep.vulnerable_component_finding(comp, dep.assess_component(comp))
    html = report.generate_html_report("P", [f], {"in_scope": ["t"]}, kev_cves={"CVE-2020-11022"})
    assert "Known-Exploited in the Wild" in html and "CVE-2020-11022" in html
    # the row must not be presented as a confirmed finding — it is a potentially-affected lead
    assert "Confirmed finding</th>" not in html


def test_kev_does_not_scrape_cve_ids_out_of_a_title():
    """NEGATIVE CONTROL for slice 4 — the fix must be the producer emitting structure, NOT the
    consumer regexing prose. A CVE that appears only in a title stays unmatched."""
    title_only = {"title": "Something about CVE-2020-11022", "family": "misc", "severity": "low",
                  "confidence": "lead", "evidence": "no identifiers here", "target": "https://t/x"}
    html = report.generate_html_report("P", [title_only], {"in_scope": ["t"]},
                                       kev_cves={"CVE-2020-11022"})
    assert "Not identified in KEV" in html


def test_kev_stays_silent_when_the_sca_cve_is_not_in_the_catalog():
    comp = dep.make_component("jquery", "3.4.0", "js-content-banner", dep.CONFIRMED, "jQuery v3.4.0",
                              "https://t/a.js")
    f = dep.vulnerable_component_finding(comp, dep.assess_component(comp))
    html = report.generate_html_report("P", [f], {"in_scope": ["t"]}, kev_cves={"CVE-1999-0001"})
    assert "Not identified in KEV" in html


# ── slice 5: `success_oracle` vs `oracle` — one canonical key ────────────────
def test_oracle_of_reads_both_producer_spellings():
    """Measured platform-wide: 38 modules mention `success_oracle`, 87 sites write a plain `oracle`.
    `poc_bundle` read only `oracle`; `report.report_integrity_check` read only `success_oracle` — the
    two consumers disagreed with EACH OTHER. Neither spelling is dead, so neither is deleted: one
    canonical key (`success_oracle`), one reader, both producer spellings still accepted."""
    assert proof_schema.ORACLE_KEY == "success_oracle"
    assert proof_schema.oracle_of({"success_oracle": "canonical"}) == "canonical"
    assert proof_schema.oracle_of({"oracle": "legacy"}) == "legacy"
    assert proof_schema.oracle_of({"success_oracle": "canonical", "oracle": "legacy"}) == "canonical"
    assert proof_schema.oracle_of({}) == ""
    assert proof_schema.oracle_of(None) == ""


def test_the_proof_gate_normalises_the_oracle_key_at_one_chokepoint():
    """`db.get_findings_gated` -> `demote_unproven` is the documented single chokepoint every
    presenting consumer reads through. Normalise there, not in each consumer."""
    f = {"title": "t", "family": "xss", "confidence": "confirmed", "oracle": "the canary executed"}
    out = proof_schema.demote_unproven([f])[0]
    assert out["success_oracle"] == "the canary executed"
    assert out["oracle"] == "the canary executed"        # the legacy spelling still works
    assert f.get("success_oracle") is None                # non-destructive: the input is not mutated


def test_normalisation_never_overwrites_an_existing_success_oracle():
    """NEGATIVE CONTROL — the canonical key wins; a stale legacy `oracle` must not clobber it."""
    f = {"title": "t", "family": "xss", "confidence": "confirmed",
         "success_oracle": "canonical", "oracle": "stale"}
    assert proof_schema.demote_unproven([f])[0]["success_oracle"] == "canonical"


def test_poc_bundle_carries_the_oracle_of_a_success_oracle_producer():
    """poc_bundle read only `oracle`, so every family whose producer chose `success_oracle` reached
    the PoC bundle with an empty confirmation oracle."""
    import poc_bundle
    comp = _angular()
    f = dep.vulnerable_component_finding(comp, dep.assess_component(comp), behaviour_proof=_proof())
    f["id"] = "F1"
    assert f.get("oracle") is None and f["success_oracle"]     # the producer chose success_oracle
    b = poc_bundle.build(f)
    assert b["confirmation"]["oracle"] == f["success_oracle"]


def test_report_integrity_accepts_a_confirmed_finding_that_wrote_the_plain_oracle_key():
    f = {"title": "legacy-spelling finding", "family": "xss", "severity": "medium",
         "confidence": "confirmed", "evidence": "GET /x -> payload reflected unencoded",
         "impact": "script runs in the victim session",
         "reproduction_steps": ["GET /x?q=<payload>"],
         "oracle": "the injected canary executed in a real browser"}
    assert not any("success oracle" in i for i in report.report_integrity_check([f]))


def test_report_integrity_still_flags_a_confirmed_finding_with_no_oracle_at_all():
    """NEGATIVE CONTROL — accepting the second spelling must not neuter the check."""
    f = {"title": "no oracle anywhere", "family": "xss", "severity": "medium",
         "confidence": "confirmed", "evidence": "GET /x -> payload reflected unencoded",
         "impact": "script runs in the victim session",
         "reproduction_steps": ["GET /x?q=<payload>"]}
    assert any("success oracle" in i for i in report.report_integrity_check([f]))


# ── slice 6 (bonus): SARIF still un-demoted proof-gate-demoted rows ──────────
def test_sarif_downgrades_a_demoted_row_where_the_consumer_can_see_it():
    """707b3b9 / 5af0af8 fixed HTML, markdown, JSON and CSV. SARIF still emitted level=error and
    security-severity=9.5 for a row the proof gate had demoted, burying the demotion in
    `properties.confidence` — which GitHub code scanning and DefectDojo do not read. They read
    `level` and `security-severity`, so that is where the demotion has to appear."""
    import sarif_io
    demoted = {"title": "unproven idor", "family": "idor", "cwe": "CWE-639", "severity": "critical",
               "confidence": "lead", "target": "https://t/a", "proof_gap": ["impact"]}
    res = sarif_io.export_sarif([demoted])["runs"][0]["results"][0]
    assert res["level"] == "warning"
    assert res["properties"]["security-severity"] == "5.0"     # matches the level, not the claim
    # the original severity is preserved as data, not as an alarm level
    assert res["properties"]["claimed_severity"] == "critical"
    assert res["properties"]["confidence"] == "lead"


def test_sarif_leaves_a_confirmed_row_at_full_severity():
    """NEGATIVE CONTROL — the downgrade must key off the PROOF STATE, not off severity. A genuinely
    confirmed critical must still be error / 9.5."""
    import sarif_io
    proven = {"title": "confirmed idor", "family": "idor", "cwe": "CWE-639", "severity": "critical",
              "confidence": "confirmed", "target": "https://t/a"}
    res = sarif_io.export_sarif([proven])["runs"][0]["results"][0]
    assert res["level"] == "error" and res["properties"]["security-severity"] == "9.5"
    assert "claimed_severity" not in res["properties"]


def test_sarif_uses_the_shared_is_confirmed_definition():
    """A finding with NO confidence key at all is confirmed by convention (proof_schema.is_confirmed);
    SARIF must use that one definition rather than a fourth private copy."""
    import sarif_io
    no_key = {"title": "x", "family": "xss", "severity": "high", "target": "https://t/a"}
    assert sarif_io.export_sarif([no_key])["runs"][0]["results"][0]["level"] == "error"
    for word in ("candidate", "unconfirmed", "tentative"):
        row = {"title": "x", "family": "xss", "severity": "high", "confidence": word,
               "target": "https://t/a"}
        assert sarif_io.export_sarif([row])["runs"][0]["results"][0]["level"] == "warning", word


def test_sarif_never_downgrades_below_the_level_the_severity_already_earned():
    """A demoted LOW must not be promoted to warning by the demotion rule."""
    import sarif_io
    row = {"title": "x", "family": "xss", "severity": "low", "confidence": "lead",
           "target": "https://t/a"}
    res = sarif_io.export_sarif([row])["runs"][0]["results"][0]
    assert res["level"] == "note" and res["properties"]["security-severity"] == "3.0"
