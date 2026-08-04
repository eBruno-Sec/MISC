"""Adversarial regression tests for CHAD's final-audit defects (2026-08-03).

Each test feeds a DELIBERATELY BAD fixture and asserts the gate/logic catches it, plus a GOOD
fixture it must pass. These lock the eight false-claim classes CHAD found so they can never
silently return. Everything here is pure + deterministic (no network, no live mission)."""
from __future__ import annotations

import re

import report
import triage
import technique_advisor as ta
import dependency_intel as dep
import candidate_pipeline as cp
import proof_schema as ps


# ── Defect #1 — KEV must never be inferred from a CWE class ───────────────────
def test_kev_not_claimed_from_cwe_class():
    # a technique whose CWE class is in KEV but whose exact CVE is NOT known-exploited
    techs = [{"id": "t1", "vuln_class": "prototype_pollution", "cwe": ["CWE-1321"],
              "status": "proven", "confidence": {"score": 60}, "transferable": True}]
    recs = ta.recommend([{"family": "prototype_pollution", "cwe": "CWE-1321"}], techs,
                        kev_cwes={"CWE-1321"})
    reasons = " ".join(r for rec in recs for r in rec["reasons"]).lower()
    # the CWE intersection may still add context, but it must NOT be laundered into a
    # "known-exploited" claim (KEV is CVE-indexed).
    assert "known-exploited" not in reasons and "known exploited" not in reasons
    assert "contextual prior" in reasons or "represented in cisa kev" in reasons


def test_integrity_flags_kev_claim_without_exact_cve():
    bad = [{"title": "Angular", "family": "vulnerable_component", "confidence": "confirmed",
            "severity": "medium", "reproduction_steps": ["load it"], "success_oracle": "version match",
            "evidence": "This is known-exploited per CISA KEV.", "cve": "CVE-2023-26118"}]
    issues = report.report_integrity_check(bad, kev_cves={"CVE-2020-0001"})  # 26118 NOT in set
    assert any("known-exploited" in i.lower() for i in issues)
    # same finding, but the CVE really is in KEV -> no violation on that axis
    ok = report.report_integrity_check(bad, kev_cves={"CVE-2023-26118"})
    assert not any("known-exploited" in i.lower() for i in ok)


# ── Defect #2 — a credential proof must actually AUTHENTICATE ─────────────────
def _cred_finding(curl, steps):
    return {"title": "Confirmed working application credentials for 'carlos'",
            "family": "broken_auth", "cwe": "CWE-522", "confidence": "confirmed", "severity": "high",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N", "cvss_score": 8.2,
            "target": "https://x.test/login", "curl": curl, "reproduction_steps": steps,
            "success_oracle": "a session cookie/token is issued and an authed-only page loads as carlos"}


def test_integrity_flags_bare_get_credential_repro():
    bad = _cred_finding("curl -i -sS -k --path-as-is 'https://x.test/login'",
                        ["POST https://x.test/login with username='carlos' and password=<redacted>"])
    issues = report.report_integrity_check([bad])
    assert any("bare get" in i.lower() or "does not authenticate" in i.lower() for i in issues)


def test_integrity_passes_real_auth_credential_repro():
    good_curl = ("# 1) Authenticate\n"
                 "curl -i -sS -k -X POST 'https://x.test/login' \\\n"
                 "  -H 'Content-Type: application/x-www-form-urlencoded' \\\n"
                 "  --data 'username=carlos&password=<REDACTED_PASSWORD>'\n"
                 "# 2) Replay session\n"
                 "curl -i -sS -k -b 'session=<SESSION_COOKIE_FROM_STEP_1>' 'https://x.test/my-account'")
    good = _cred_finding(good_curl, ["POST /login with username + password=<REDACTED_PASSWORD>",
                                     "Success oracle: session issued; authed page loads as carlos"])
    assert report.report_integrity_check([good]) == []
    # and the report renders the real POST, not a GET
    assert report.finding_curl(good).startswith("# 1) Authenticate")
    assert "POST" in report.finding_curl(good) and "<REDACTED_PASSWORD>" in report.finding_curl(good)


# ── Defect #3 — no duplicated-host URLs ───────────────────────────────────────
def test_duplicated_host_detected_and_collapsed():
    bad = "https://ginandjuice.shop//ginandjuice.shop/resources/js/angular_1-7-7.js"
    assert report._netloc_repeats(bad) is True
    assert dep.canon_location(bad) == "https://ginandjuice.shop/resources/js/angular_1-7-7.js"
    # a clean URL is untouched and not flagged
    clean = "https://ginandjuice.shop/resources/js/angular_1-7-7.js"
    assert report._netloc_repeats(clean) is False
    assert dep.canon_location(clean) == clean


def test_protocol_relative_src_resolves_without_doubling():
    from urllib.parse import urljoin
    base = "https://ginandjuice.shop/"
    assert urljoin(base, "//ginandjuice.shop/resources/js/angular_1-7-7.js") == \
        "https://ginandjuice.shop/resources/js/angular_1-7-7.js"


def test_integrity_flags_finding_with_duplicated_host():
    bad = [{"title": "angular@1.7.7", "family": "vulnerable_component", "confidence": "confirmed",
            "severity": "medium", "reproduction_steps": ["load it"], "success_oracle": "version match",
            "target": "https://h.test//h.test/resources/js/angular.js"}]
    issues = report.report_integrity_check(bad)
    assert any("duplicated host" in i.lower() for i in issues)


def test_make_component_never_emits_doubled_host():
    c = dep.make_component("angular", "1.7.7", "script-filename", dep.HIGH,
                           location="https://h.test//h.test/resources/js/angular.js")
    assert not report._netloc_repeats(c["location"])


# ── Defect #4 — candidate rows must be self-consistent ────────────────────────
def test_integrity_flags_confirmed_with_no_validator():
    cv = {"counts": {"confirmed": 1}, "records": [
        {"candidate": "Technique to test — Broken Auth", "result": "confirmed",
         "validator": "", "oracle": "no validator implemented yet", "attempted": True}]}
    issues = report.report_integrity_check([], candidate_validation=cv)
    assert any("no validator" in i.lower() for i in issues)


def test_integrity_passes_deduplicated_candidate():
    cv = {"counts": {"confirmed": 1}, "records": [
        {"candidate": "Technique to test — Broken Auth", "result": "confirmed", "attempted": False,
         "deduplicated": True, "result_ref": "Confirmed working application credentials for 'carlos'",
         "validator": "deduplicated → primary finding",
         "oracle": "confirmed by finding 'Confirmed working application credentials for 'carlos'' via its success oracle: session issued"}]}
    assert report.report_integrity_check([], candidate_validation=cv) == []


# ── Defect #5 — IDOR/access-control leads are DEFERRED, not 'unsupported' ──────
def test_idor_lead_is_deferred_not_unsupported():
    fam = cp.canonical_family({"title": "Technique to test — Idor Bola Read", "family": "access_control"})
    assert fam in cp.PRIMARY_HANDLED  # owned by the two-user authz matrix, never 'unsupported'
    fam2 = cp.canonical_family({"title": "Idor Bola Read", "family": "idor"})
    assert fam2 in cp.PRIMARY_HANDLED


def test_integrity_flags_unreconciled_unsupported_debt():
    cv = {"counts": {"confirmed": 0, "unsupported": 0}, "records": [
        {"candidate": "weird lead", "result": "unsupported", "validator": "", "oracle": "no validator implemented yet"}]}
    issues = report.report_integrity_check([], candidate_validation=cv)
    assert any("unsupported" in i.lower() and "reconcil" in i.lower() for i in issues)


# ── Defect #6 — CVSS math + severity-band + chain wording ─────────────────────
def test_cvss_base_score_matches_known_vector():
    assert report.cvss31_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N") == 8.2
    assert report.cvss31_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == 9.8
    assert report.cvss31_base_score("CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N") == 2.6


def test_integrity_flags_score_vector_mismatch():
    bad = [{"title": "x", "family": "xss", "confidence": "confirmed", "severity": "medium",
            "reproduction_steps": ["r"], "success_oracle": "o",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N", "cvss_score": 2.0}]
    assert any("disagrees with its vector" in i.lower() for i in report.report_integrity_check(bad))


def test_integrity_flags_severity_band_mismatch():
    bad = [{"title": "x", "family": "xss", "confidence": "confirmed", "severity": "critical",
            "reproduction_steps": ["r"], "success_oracle": "o", "cvss_score": 4.5}]
    assert any("disagrees with cvss" in i.lower() for i in report.report_integrity_check(bad))


def test_integrity_flags_unverified_chain_that_claims_proof():
    bad_chains = [{"name": "c", "verified": False,
                   "narrative": "The SQLi proves this path and auto-executes the takeover."}]
    issues = report.report_integrity_check([], chains=bad_chains)
    assert any("overstates evidence" in i.lower() for i in issues)


# ── Defect #7 — dataflow chain wording says 'infers', never 'proves' ──────────
def test_dataflow_chain_says_infers_not_proves():
    findings = [{"title": "SQLi in id", "family": "sqli", "confidence": "confirmed",
                 "severity": "critical", "target": "https://h.test/item?id=1"}]
    chains = triage.build_chains(findings)
    flows = [c for c in chains if c.get("kind") == "dataflow"]
    for c in chains:
        assert "proves this path" not in (c.get("summary") or "").lower()
    if flows:
        assert "infers this path" in flows[0]["summary"].lower()


# ── Every chain carries a verified label (existing guarantee, kept) ───────────
def test_all_chains_labelled_verified():
    findings = [{"title": "SQLi", "family": "sqli", "confidence": "confirmed",
                 "severity": "critical", "target": "https://h.test/item?id=1"}]
    for c in triage.build_chains(findings):
        assert "verified" in c


# ── Defect #3 (re-run) — a doubled-host URL restored from prior-scan MEMORY is
#    sanitised at render time so the shipped report never prints it ────────────
def test_sanitize_finding_urls_collapses_memory_doubled_host():
    dirty = [{"title": "angular@1.7.7", "family": "vulnerable_component", "confidence": "confirmed",
              "severity": "medium", "reproduction_steps": ["load"], "success_oracle": "version",
              "target": "https://ginandjuice.shop//ginandjuice.shop/resources/js/angular_1-7-7.js",
              "evidence": "angular@1.7.7 from script-filename: https://ginandjuice.shop//ginandjuice.shop/resources/js/angular_1-7-7.js"}]
    clean = report.sanitize_finding_urls(dirty)[0]
    assert clean["target"] == "https://ginandjuice.shop/resources/js/angular_1-7-7.js"
    assert "shop//ginandjuice" not in clean["evidence"]
    # and the integrity gate is then clean on the sanitised finding
    assert not any("duplicated host" in i.lower() for i in report.report_integrity_check(clean and [clean]))


def test_collapse_dup_host_at_ingestion():
    import tools
    assert tools._collapse_dup_host("https://h.test//h.test/a.js") == "https://h.test/a.js"
    assert tools._collapse_dup_host("https://h.test/a.js") == "https://h.test/a.js"  # clean untouched


# ── Gate must NOT flag an HONEST disclaimer (negation/disclaimer awareness) ────
def test_gate_ignores_disclaimed_colocated_chain():
    honest = [{"name": "colo", "verified": False, "kind": "colocated",
               "narrative": "A + B",
               "summary": "4 confirmed findings are CO-LOCATED on host. This is NOT a proven attack path: "
                          "no data-flow, identity, or privilege transition between them was executed."}]
    assert report.report_integrity_check([], chains=honest) == []
    # the dataflow disclaimer ("infers", "does not auto-execute") is likewise fine
    df = [{"name": "df", "verified": False, "kind": "dataflow",
           "narrative": "SQLI -> data -> takeover",
           "summary": "Apolaki INFERS this path from co-present confirmed findings; it does NOT auto-execute the exploitation."}]
    assert report.report_integrity_check([], chains=df) == []


# ── A VERIFIED exposed credential (CWE-522) must NOT be demoted to a lead by the
#    access-control proof rule (it is exposed_credentials, not access control) ──
def _verified_credential():
    return {"title": "Confirmed working application credentials for 'carlos'", "severity": "high",
            "family": "broken_auth", "cwe": "CWE-522", "confidence": "confirmed",
            "impact": "An attacker logs in as carlos and gains full account access.",
            "evidence": ("Verified working: a login to https://x.test/login as 'carlos' (password redacted) "
                         "returned a valid authenticated session (session cookie/token issued)."),
            "reproduction_steps": ["POST /login with username=carlos and password=<REDACTED_PASSWORD>"]}


def test_cwe522_routes_to_exposed_credentials_not_access_control():
    assert ps.family_of(_verified_credential()) == "exposed_credentials"
    # ONLY CWE-522 escapes: a broken_auth AUTH-BYPASS finding still routes to access_control
    # (default-enforced) — the fix does not weaken access-control proof enforcement.
    assert ps.family_of({"family": "broken_auth", "cwe": "CWE-306"}) == "access_control"
    assert ps.family_of({"family": "access_control", "cwe": "CWE-285"}) == "access_control"
    # a family-less CWE-306 still falls back to missing_authentication
    assert ps.family_of({"cwe": "CWE-306"}) == "missing_authentication"


def test_verified_credential_survives_demotion():
    # default-enforced demotion must KEEP the verified credential confirmed (it was being wrongly
    # demoted to a lead while its evidence said "verified working" — a self-contradiction)
    out = ps.demote_unproven([_verified_credential()])
    assert out[0]["confidence"] == "confirmed"
    # even under FULL enforcement, the correct credential proof rule passes it
    out_all = ps.demote_unproven([_verified_credential()], enforce_families="all")
    assert out_all[0]["confidence"] == "confirmed"
    # but a proofless credential 'confirmed' is still demoted (guard intact)
    weak = dict(_verified_credential(), evidence="found a password somewhere")
    assert ps.demote_unproven([weak], enforce_families="all")[0]["confidence"] == "lead"
