"""Fix Now / Fix If / Strengthen remediation-priority layer (Hound-inspired), alongside CVSS/CWE."""
import remediation as R


def _f(**kw):
    return kw


def test_confirmed_high_is_fix_now():
    assert R.fix_priority(_f(family="sqli", severity="high", confidence="confirmed"))["tier"] == "fix_now"
    assert R.fix_priority(_f(family="idor", severity="critical", confidence="confirmed"))["tier"] == "fix_now"


def test_confirmed_high_with_precondition_is_fix_if():
    p = R.fix_priority(_f(family="idor", severity="high", confidence="confirmed", tags=["needs-confirmation"]))
    assert p["tier"] == "fix_if" and "precondition" in p["reason"]


def test_confirmed_medium_is_fix_if():
    assert R.fix_priority(_f(family="misconfig", severity="medium", confidence="confirmed"))["tier"] == "fix_if"


def test_unconfirmed_high_lead_is_fix_if():
    p = R.fix_priority(_f(family="xss", severity="high", confidence="lead"))
    assert p["tier"] == "fix_if" and "verify" in p["reason"]


def test_hardening_family_is_always_strengthen():
    # even a "high"-labelled cookie-flags/header issue is defense-in-depth, not an open door
    assert R.fix_priority(_f(family="cookie_flags", severity="high", confidence="confirmed"))["tier"] == "strengthen"
    assert R.fix_priority(_f(family="security_headers", severity="medium", confidence="confirmed"))["tier"] == "strengthen"


def test_confirmed_low_and_weak_lead_are_strengthen():
    assert R.fix_priority(_f(family="info_leak", severity="low", confidence="confirmed"))["tier"] == "strengthen"
    assert R.fix_priority(_f(family="attack_surface", severity="info", confidence="lead"))["tier"] == "strengthen"


def test_summary_counts_findings_and_leads():
    s = R.fix_priority_summary(
        findings=[_f(family="sqli", severity="high", confidence="confirmed"),
                  _f(family="misconfig", severity="medium", confidence="confirmed")],
        leads=[_f(family="xss", severity="high", confidence="lead")])
    assert s["counts"] == {"fix_now": 1, "fix_if": 2, "strengthen": 0}
    assert s["order"] == ["fix_now", "fix_if", "strengthen"]
