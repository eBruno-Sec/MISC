"""Client-readiness gates from CHAD's final report review. These lock in: CVE-exact KEV (never
CWE-inferred), verified-vs-hypothetical attack chains, candidate/finding count reconciliation,
non-truncated responsive candidate table, and the report_integrity_check gate itself."""
from __future__ import annotations

import report


def _good_finding():
    return {"title": "Confirmed working application credentials for 'carlos'", "severity": "high",
            "family": "broken_auth", "confidence": "confirmed", "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
            "cvss_score": 8.2, "impact": "Attacker logs in as carlos.", "target": "https://t/login",
            "reproduction_steps": ["POST /login ...", "Success oracle: a session cookie is issued and an auth-only page loads."],
            "success_oracle": "session cookie issued + auth-only page loads"}


def test_integrity_check_clean_on_wellformed_report():
    assert report.report_integrity_check([_good_finding()], chains=[{"verified": False, "narrative": "x"}]) == []


def test_integrity_check_flags_high_without_cvss():
    f = _good_finding(); f["cvss_vector"] = ""; f["cvss_score"] = None
    issues = report.report_integrity_check([f])
    assert any("CVSS" in i for i in issues)


def test_integrity_check_flags_confirmed_without_oracle():
    f = _good_finding(); f["reproduction_steps"] = ["just curl it"]; f["success_oracle"] = ""
    assert any("success oracle" in i for i in report.report_integrity_check([f]))


def test_integrity_check_flags_unlabelled_chain_and_reused_impact():
    assert any("verified/hypothetical" in i for i in report.report_integrity_check([], chains=[{"narrative": "a->b"}]))
    a = _good_finding(); b = dict(_good_finding()); b["family"] = "sqli"  # same impact text, different family
    assert any("generic impact" in i for i in report.report_integrity_check([a, b]))


def test_kev_matches_exact_cve_only_never_cwe():
    # a finding whose CVE is in KEV -> KEV section names the exact CVE
    f = _good_finding(); f["cve"] = "CVE-2023-26118"; f["title"] = "Vulnerable component: angular@1.7.7"
    html = report.generate_html_report("P", [f], {"in_scope": ["x"]}, kev_cves={"CVE-2023-26118"})
    assert "CVE-2023-26118" in html and "Known-Exploited in the Wild" in html
    # a HIGH finding with only a CWE (no CVE) is NEVER KEV-listed -> explicit "Not identified in KEV"
    g = _good_finding()  # CWE-522, no CVE
    html2 = report.generate_html_report("P", [g], {"in_scope": ["x"]}, kev_cves={"CVE-2023-26118"})
    assert "Not identified in KEV" in html2


def test_attack_chains_labelled_and_reconciliation_rendered():
    from triage import build_chains
    findings = [{"id": "F1", "title": "CSTI", "family": "csti", "severity": "high", "target": "https://t/a", "confidence": "confirmed"},
                {"id": "F2", "title": "Prototype pollution", "family": "prototype_pollution", "severity": "high", "target": "https://t/b", "confidence": "confirmed"}]
    chains = build_chains(findings)
    assert chains and all("verified" in c for c in chains)          # every edge labelled
    assert all(c.get("verified") is False for c in chains)          # inference, not executed -> hypothesis
    # candidate-validation reconciliation is rendered (records -> unique findings, separate counts)
    cv = {"counts": {"confirmed": 7, "dismissed": 14, "blocked": 1, "unsupported": 0},
          "records": [{"candidate": "ng-app", "family": "csti", "validator": "run_dom_audit", "attempted": True,
                       "oracle": "angular arithmetic", "result": "confirmed", "evidence": "deduped"}]}
    html = report.generate_html_report("P", findings, {"in_scope": ["x"]}, candidate_validation=cv, chains=chains)
    assert "deduplicate into" in html          # reconciliation line rendered
    assert "cv-tbl" in html                    # responsive candidate table
    assert "PLAUSIBLE" in html                 # attack chains labelled hypothesis, not verified
