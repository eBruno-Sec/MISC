"""WAF inspection-window bypass engine (CWE-693). Confirms ONLY on the three-state differential: baseline OK,
raw signature blocked, padded signature not-blocked AND reflected. No WAF (never blocked) or a strong WAF
(still blocks the padded payload) yields nothing — no false positives."""
import blind_benchmark as bb
import waf_bypass_tool as wb
from report import cvss31_base_score


def test_pad_exceeds_window():
    p = wb.pad("<x>", size=8300, position="prefix")
    assert p.endswith("<x>") and p.count("A") >= 8300


def test_block_detection():
    assert wb.is_blocked(200, "ok", 403, "Request Blocked")            # block status
    assert wb.is_blocked(200, "welcome", 200, "Access Denied by WAF")  # block signature new to body
    assert not wb.is_blocked(200, "ok", 200, "ok")                     # normal
    assert not wb.is_blocked(403, "always 403", 403, "always 403")     # baseline already 403 -> not a NEW block


def test_confirms_only_on_full_differential():
    payload = "<script>alert(1)</script>"
    baseline = (200, "results for apolwafbase")
    raw = (403, "Request Blocked by WAF")                              # bare signature blocked
    padded = (200, "results for %s" % payload)                        # padded passes AND reflects
    assert wb.evaluate(baseline, raw, padded, payload)["confirmed"]
    # padded still blocked -> WAF has no window gap -> not confirmed
    assert not wb.evaluate(baseline, raw, (403, "Request Blocked by WAF"), payload)["confirmed"]
    # raw never blocked (no WAF) -> nothing to bypass
    assert not wb.evaluate(baseline, (200, "results for %s" % payload), padded, payload)["confirmed"]
    # padded passes but does NOT reflect -> can't prove it reached the app
    assert not wb.evaluate(baseline, raw, (200, "generic page"), payload)["confirmed"]


def test_finding_is_proof_with_consistent_cvss():
    f = wb.finding("https://x/s?q=1", "q", "xss", "padded payload reflected where raw was blocked")
    assert f["family"] == "waf_bypass" and f["cwe"] == "CWE-693" and bb._has_proof(f)
    assert abs(cvss31_base_score(f["cvss_vector"]) - f["cvss_score"]) < 0.05
