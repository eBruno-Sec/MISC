"""Report-integrity CVSS rules (Codex Tier-2 #6): accept a v3.1 OR v4 vector on a finding; reject a
CVSS vector/score attached to an attack CHAIN (CVSS scores atomic vulns only)."""
import report_integrity as RI

_V4 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"
_V31 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


def test_accepts_either_cvss_version_on_findings():
    assert RI.cvss_version_of({"severity": "critical", "cvss40_vector": _V4}) == "4.0"
    assert RI.cvss_version_of({"severity": "high", "cvss31_vector": _V31}) == "3.1"
    assert RI.cvss_version_of({"severity": "high", "cvss_vector": _V31}) == "3.1"
    assert RI.cvss_version_of({"severity": "high"}) is None
    assert RI.cvss_version_of({"cvss40_vector": "CVSS:4.0/AV:N"}) is None      # invalid v4 not accepted


def test_high_crit_findings_with_either_version_do_not_raise_integrity_errors():
    findings = [{"title": "SQLi", "severity": "critical", "confidence": "confirmed", "cvss40_vector": _V4},
                {"title": "XSS", "severity": "high", "confidence": "confirmed", "cvss31_vector": _V31}]
    r = RI.check_report_consistency(findings, [], risk={"label": "critical", "note": "scored"},
                                    counts={"critical": 1, "high": 1})
    assert not any(i["check"] == "chain-level-cvss" for i in r["issues"])


def test_chain_level_cvss_is_rejected():
    chains = [{"host": "app", "narrative": "SSRF->metadata", "cvss_vector": _V4}]
    viol = RI.chain_cvss_violations(chains)
    assert viol == ["app"]
    r = RI.check_report_consistency([], [], chains=chains)
    errs = [i for i in r["issues"] if i["check"] == "chain-level-cvss"]
    assert errs and r["ok"] is False


def test_clean_chain_without_cvss_is_fine():
    chains = [{"host": "app", "narrative": "SSRF->metadata", "severity": "high"}]
    assert RI.chain_cvss_violations(chains) == []
    r = RI.check_report_consistency([], [], chains=chains)
    assert not any(i["check"] == "chain-level-cvss" for i in r["issues"])
