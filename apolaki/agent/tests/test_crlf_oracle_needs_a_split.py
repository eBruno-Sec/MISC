"""Q-106 — the CRLF oracle reported a HIGH against a live bug-bounty target on an echo.

The operator's Shopify engagement produced two HIGH "CRLF / response-header injection" findings on
`linkpop.com`, an in-scope asset. He verified one by hand and it did not reproduce:

    curl -is 'https://linkpop.com/480cd2?fbclid=1%0D%0AX-bbhcrlf%3A+bbhcrlfpwned'
    Location: https://linkpop.com/480cd2/index.html?fbclid=1%0D%0AX-bbhcrlf:+bbhcrlfpwned

The marker sits INSIDE the Location value and `%0D%0A` is STILL PERCENT-ENCODED. The `%3A` decoded
to `:` while the newline did not -- the server refusing to decode a CRLF, which is the defence
working correctly. Nothing split.

The old oracle was `CRLF_MARKER in header_name OR "bbhcrlfpwned" in header_value`, justified in its
own docstring by "the marker cannot occur naturally". It can: our payload is in the request URL, and
any app that echoes that URL into a header hands the marker straight back.

A KEY match is the sound test -- a genuine split is parsed by the client as its own header. A VALUE
match now has to rule out the undecoded payload first.

Reporting this to a mature security team would have been a false claim of a header-injection
primitive, checkable by them in one command. That is worse than reporting nothing.
"""
import web_security as ws


PWNED = ws.CRLF_MARKER + "pwned"


# ── the field false positive ──────────────────────────────────────────────────

def test_the_echoed_location_from_the_live_target_is_not_a_finding():
    """Verbatim from the operator's own curl against linkpop.com."""
    headers = {"Location": "https://linkpop.com/480cd2/index.html"
                           "?fbclid=1%0D%0AX-bbhcrlf:+bbhcrlfpwned",
               "Content-Type": "text/html"}
    assert ws.analyze_crlf(headers) is None


def test_the_overlong_utf8_variant_echoes_the_same_way():
    """`build_crlf_probes` also sends %E5%98%8A%E5%98%8D, so its echo must be rejected too, or the
    fix only closes the one encoding we happened to observe."""
    headers = {"Location": "https://x.test/p?q=1%E5%98%8A%E5%98%8DX-bbhcrlf:+bbhcrlfpwned"}
    assert ws.analyze_crlf(headers) is None


# ── the half that keeps this an oracle rather than a deletion ─────────────────

def test_a_real_split_producing_its_own_header_is_still_HIGH():
    """A genuine split is parsed by the client as a separate header, so the marker becomes a KEY.
    Without this, `return None` would satisfy every other test in this file."""
    headers = {"Location": "https://x.test/", "X-bbhcrlf": "bbhcrlfpwned"}
    got = ws.analyze_crlf(headers)
    assert got and got["severity"] == "HIGH", got


def test_a_decoded_value_split_is_still_HIGH():
    """The Set-Cookie sink: the marker lands in another header's value with the CRLF actually
    DECODED. That is a real primitive and must survive the fix."""
    headers = {"Set-Cookie": "sid=1; path=/; X-bbhcrlf: bbhcrlfpwned"}
    got = ws.analyze_crlf(headers)
    assert got and got["severity"] == "HIGH", got


def test_a_clean_response_is_silent():
    assert ws.analyze_crlf({"Location": "https://x.test/", "Server": "nginx"}) is None
    assert ws.analyze_crlf({}) is None


# ── the discriminator itself ──────────────────────────────────────────────────

def test_the_same_value_differs_only_by_whether_the_crlf_decoded():
    """The whole fix in one assertion. Identical marker, identical header, identical position --
    the ONLY difference is whether the server decoded the newline. That is precisely the line
    between a defence that held and a primitive that exists."""
    encoded = {"Location": "https://x.test/p?q=1%0D%0AX-bbhcrlf:+" + PWNED}
    decoded = {"Location": "https://x.test/p?q=1", "X-bbhcrlf": PWNED}
    assert ws.analyze_crlf(encoded) is None
    assert ws.analyze_crlf(decoded) is not None
