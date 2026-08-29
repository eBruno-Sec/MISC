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


def test_the_double_encoded_echo_from_partners_shopify_is_not_a_finding():
    """ROUND TWO, and the one that killed the value branch. My first repair rejected a value hit
    only when the STILL-ENCODED CRLF was present, and partners.shopify.com returned it
    DOUBLE-encoded, so the check missed it:

        location: .../organizations?redirect_to=...itcat%3Dpartner_blog%250D%250AX-bbhcrlf%253A%2Bbbhcrlfpwned

    Chasing encodings is unwinnable -- there is always another layer."""
    headers = {"location": "https://partners.shopify.com/organizations?redirect_to=%2Fcurrent%2Fapps"
                           "%3Fitcat%3Dpartner_blog%250D%250AX-bbhcrlf%253A%2Bbbhcrlfpwned"}
    assert ws.analyze_crlf(headers) is None


def test_a_marker_in_any_header_value_is_never_a_finding():
    """THE DECISION. A real split is parsed BY THE CLIENT as a separate header, so the marker
    arrives as a KEY -- including the Set-Cookie sink, where `Set-Cookie: a=b\r\nX-bbhcrlf: pwned`
    reaches us as TWO parsed headers rather than one value. There is no mechanism by which a
    value-only match is real, and there were two field false positives and zero true positives.
    So the value branch is GONE, not tightened."""
    for hdr in ("location", "set-cookie", "x-anything"):
        assert ws.analyze_crlf({hdr: "sid=1; path=/; X-bbhcrlf: " + PWNED}) is None, hdr


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
