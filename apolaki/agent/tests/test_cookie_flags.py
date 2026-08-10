"""Cookie set without Secure (CWE-614), decided from the RAW Set-Cookie header only."""
import blind_benchmark as bb
import cookie_flags as cf


def test_missing_secure_confirms_and_present_secure_does_not():
    assert cf.evaluate(["SID=abc; Path=/; HttpOnly; SameSite=Strict"])["confirmed"]
    assert not cf.evaluate(["SID=abc; Path=/; Secure; HttpOnly"])["confirmed"]
    assert not cf.evaluate(["SID=abc; sEcUrE"])["confirmed"]        # attribute is case-insensitive


def test_httponly_without_secure_is_still_cwe_614():
    """HttpOnly protects against script access; it does nothing about plaintext transmission."""
    ev = cf.evaluate(["JSESSIONID=9F1; Path=/app; HttpOnly; SameSite=Lax"])
    assert ev["confirmed"] and ev["cookies"] == ["JSESSIONID"]
    assert ev["session_cookies"] == ["JSESSIONID"]


def test_secure_in_the_VALUE_is_not_the_attribute():
    """A cookie whose value contains the word secure is not a secure cookie."""
    assert cf.evaluate(["pref=secure; Path=/"])["confirmed"]
    assert cf.evaluate(["mode=very-secure-mode; Path=/"])["confirmed"]


def test_expires_comma_does_not_invent_a_second_cookie():
    """Set-Cookie legally contains a comma inside Expires. Naive splitting fabricates cookies."""
    joined = "SID=abc; Expires=Wed, 09 Jun 2027 10:18:14 GMT; Path=/"
    assert [c["name"] for c in map(cf.parse_cookie, cf.split_set_cookie(joined))] == ["SID"]
    ev = cf.evaluate(joined)
    assert ev["confirmed"] and ev["cookies"] == ["SID"]


def test_attributes_bind_to_the_correct_cookie_when_several_are_set():
    fields = ["a_tracking=1; Path=/; Secure", "SESSIONID=xyz; Path=/; HttpOnly"]
    ev = cf.evaluate(fields)
    assert ev["confirmed"] and ev["cookies"] == ["SESSIONID"]       # the Secure one is not reported
    joined = "a_tracking=1; Path=/; Secure, SESSIONID=xyz; Path=/; HttpOnly"
    assert cf.evaluate(joined)["cookies"] == ["SESSIONID"]


def test_nothing_is_invented_from_absent_or_unparseable_headers():
    """Negative controls. A default finding on every response would be worse than no check at all."""
    for bad in (None, "", [], ["   "], ["novalueatall"], ["; ; ;"]):
        assert not cf.evaluate(bad)["confirmed"], bad


def test_response_body_claims_are_ignored_entirely():
    """A real benchmark case prints 'secure flag ... false' in the body while the HEADER sets Secure.
    The verdict must follow the header. This is the exact deceptive case that defeats prose parsing."""
    assert not cf.evaluate(["SomeCookie=v; Path=/x; Secure; HttpOnly; SameSite=Strict"])["confirmed"]
    # ...and the inverse: body could claim "secure" while the header omits it.
    assert cf.evaluate(["SomeCookie=v; Path=/x; HttpOnly; SameSite=Strict"])["confirmed"]


def test_finding_is_proof_shaped_with_consistent_cvss():
    from report import cvss31_base_score
    ev = cf.evaluate(["JSESSIONID=9F1; HttpOnly"])
    f = cf.finding("https://t/x", ev["cookies"], ev["oracle"], session=True)
    assert f["family"] == "insecure_cookie" and f["cwe"] == "CWE-614" and bb._has_proof(f)
    assert abs(cvss31_base_score(f["cvss_vector"]) - f["cvss_score"]) < 0.05
    assert "raw Set-Cookie" in f["evidence"]
