"""Q-106b — the Host-header oracle matched a substring where it claimed an authority.

Found by auditing the CRLF oracle's neighbours after Q-106 reported a false HIGH against a live
bug-bounty target. Same engine (`run_injection_probes`), same run, same two endpoints, same shape:
a substring test standing in for a structural one.

    if _EVIL_HOST in (location or "").lower():        # the old test

The finding says "the app trusts the Host header". That is only supported when the spoofed host is
the AUTHORITY the victim would be sent to. A Location that merely contains the string is something
else -- usually an open-redirect parameter, which has its own engine and its own finding.

NOT VERIFIED AGAINST THE LIVE TARGET. `linkpop.com` is in the operator's HackerOne scope but not in
mine, so the two MEDIUM findings from his run remain UNCONFIRMED either way. This fixes a defect
provable from the code; it does not settle whether his specific findings were true.
"""
import web_security as ws


EVIL = ws._EVIL_HOST


# ── the substring matches that were never host-header injection ───────────────

def test_an_open_redirect_parameter_is_not_host_header_injection():
    """The victim goes to legit.example. The evil host is cargo in a query parameter -- a different
    vulnerability class, with its own engine, and not evidence the app trusts the Host header."""
    loc = "https://legit.example/login?next=https%%3A%%2F%%2F%s" % EVIL
    assert ws.analyze_host_header("", loc) is None


def test_a_query_echo_is_not_host_header_injection():
    assert ws.analyze_host_header("", "https://legit.example/?ref=%s" % EVIL) is None


def test_a_relative_location_carries_no_host_at_all():
    """A relative Location cannot name an authority, so it can never prove this finding. The
    substring test matched this; the structural one cannot."""
    assert ws.analyze_host_header("", "/redir?to=%s" % EVIL) is None


def test_a_lookalike_host_does_not_match():
    """`bbh-evil.example.attacker.tld` contains the marker and is a DIFFERENT authority. Substring
    matching cannot tell the two apart; hostname comparison can."""
    assert ws.analyze_host_header("", "https://%s.attacker.tld/p" % EVIL) is None


# ── the half that keeps this an oracle rather than a deletion ─────────────────

def test_the_real_primitive_still_reports():
    """The spoofed host IS the authority the victim would be sent to. Without this, `return None`
    passes every test above."""
    got = ws.analyze_host_header("", "https://%s/reset?token=abc" % EVIL)
    assert got and got["severity"] == "MEDIUM", got


def test_a_port_or_scheme_does_not_defeat_it():
    for loc in ("http://%s/p" % EVIL, "https://%s:8443/p" % EVIL):
        assert ws.analyze_host_header("", loc), loc


def test_body_reflection_is_unchanged_and_still_LOW():
    """Deliberately still a substring test: it is already LOW, it claims only reflection rather than
    a redirect primitive, and HTML has no authority to parse."""
    got = ws.analyze_host_header("<a href='//%s/x'>" % EVIL, "")
    assert got and got["severity"] == "LOW", got


def test_a_clean_response_is_silent():
    assert ws.analyze_host_header("<html>ok</html>", "https://legit.example/home") is None
