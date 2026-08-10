"""Security value from a DISCLOSED non-cryptographic PRNG (CWE-330 + CWE-209).

Narrow by design: it reports what the application said about itself, never an inference from output
shape. Both gates must hold — a weak generator is named, AND it is tied to a security-relevant value.
"""
import prng_disclosure as pd
import blind_benchmark as bb


def test_weak_generator_with_security_context_confirms():
    ev = pd.evaluate("value remembered with cookie: rememberMe whose value is 61 "
                     "java.util.Random.nextFloat() executed")
    assert ev["confirmed"] and ev["api"] == "java.util.Random"
    assert "predictable" in ev["oracle"]
    assert pd.evaluate("session token issued; java.lang.Math.random() executed")["confirmed"]
    assert pd.evaluate("api_key generated via mt_rand()")["confirmed"]


def test_strong_generator_suppresses_the_finding():
    """The single most important control: naming SecureRandom must never be reported as weak."""
    for strong in ("java.security.SecureRandom.nextInt(int) executed",
                   "token minted with secrets.token_hex()",
                   "cookie set using crypto.randomBytes(32)",
                   "session id from os.urandom(16)",
                   "value from random.SystemRandom().randint(0, 9)"):
        assert not pd.evaluate("cookie session token " + strong)["confirmed"], strong


def test_weak_generator_without_security_meaning_is_not_a_vulnerability():
    """A predictable animation seed or cache-buster is not weak randomness."""
    ev = pd.evaluate("chart jitter seeded by java.util.Random.nextFloat() for display smoothing")
    assert not ev["confirmed"]
    assert "no security context" in (ev.get("note") or "")


def test_prose_and_ordinary_pages_confirm_nothing():
    """Negative controls. Any of these firing would make the detector noise on every site."""
    assert not pd.evaluate("")["confirmed"]
    assert not pd.evaluate("Our token generation uses secure random values.")["confirmed"]
    assert not pd.evaluate("<html><body>Random Facts About Cookies</body></html>")["confirmed"]
    assert not pd.evaluate("please randomize your password and rotate the session")["confirmed"]
    # a body too large to be a diagnostic page is not scanned at all
    assert not pd.evaluate("cookie java.util.Random.nextInt() " + ("x" * 500_000))["confirmed"]


def test_srand_is_not_mistaken_for_rand():
    assert pd.disclosed_generator("srand()") is None


def test_finding_is_proof_shaped_with_consistent_cvss():
    from report import cvss31_base_score
    ev = pd.evaluate("cookie rememberMe java.util.Random.nextFloat() executed")
    f = pd.finding("https://t/x", ev["api"], ev["oracle"])
    assert f["family"] == "weak_random" and f["cwe"] == "CWE-330" and bb._has_proof(f)
    assert abs(cvss31_base_score(f["cvss_vector"]) - f["cvss_score"]) < 0.05
    # the claim must stay modest: it rests on disclosure, not on cracking the generator
    assert "disclos" in f["evidence"].lower()
