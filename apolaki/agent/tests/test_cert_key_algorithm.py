"""Q-101 — a key size is meaningless without the algorithm it belongs to.

Found in the field, not in a lab: the operator's live Shopify run reported three HIGH "weak TLS
certificate key -- the public key is 256 bits, below the 2048-bit minimum" findings against
`partners.shopify.com`, `accounts.shopify.com` and `your-store.myshopify.com`. All three were ECDSA
P-256, which is roughly RSA-3072 equivalent, on hosts the same run recorded as negotiating TLSv1.3.

`_key_bits` already branched on RSA vs EC and returned a bare int; `analyze_certificate` compared that
int against `_MIN_RSA_BITS`. The discriminator was measured and dropped at the return edge -- the same
defect as `_cmd` discarding `proc.returncode` (Q-092) and `_http` discarding `status` (Q-093).

BOTH DIRECTIONS ARE ASSERTED HERE. A fix that stops flagging P-256 is indistinguishable from a fix
that deletes the check, and the second would be worse than the bug: it hides a genuinely weak key
instead of inventing a strong one. Every "does not fire" test below has a partner that fires.

No certificate fixtures: the defect is in the COMPARISON, and driving it through `analyze_certificate`
directly tests the thing that was broken without depending on what a CDN serves this week.
"""
import pytest

import transport_posture as tp


CERT = {"subject": ((("commonName", "example.test"),),),
        "issuer": ((("commonName", "Test CA"),),),
        "notBefore": "Jun  1 12:00:00 2020 GMT",
        "notAfter": "Jun  1 12:00:00 2099 GMT",
        "subjectAltName": (("DNS", "example.test"),)}


def _weak_key(**kw):
    return [i for i in tp.analyze_certificate(CERT, "example.test", **kw)
            if i["id"] == "cert_weak_key"]


# ── the field regression ──────────────────────────────────────────────────────

def test_ecdsa_p256_is_not_a_weak_key():
    """The exact finding the Shopify run produced three times. 256-bit EC is healthy."""
    assert _weak_key(key_bits=256, key_algo="ec") == []


@pytest.mark.parametrize("bits", [256, 384, 521])
def test_no_curve_in_real_use_is_flagged(bits):
    assert _weak_key(key_bits=bits, key_algo="ec") == []


# ── the half that keeps this a check rather than a deletion ───────────────────

def test_rsa_1024_is_still_weak():
    """The non-vacuity control. Without this, `return []` passes every other test in this file."""
    got = _weak_key(key_bits=1024, key_algo="rsa")
    assert len(got) == 1 and got[0]["severity"] == "high", got


def test_a_genuinely_weak_curve_is_still_weak():
    """P-192 is below the EC floor. The fix raised the question "which threshold", not "should there
    be one" -- an EC key can still be too small."""
    got = _weak_key(key_bits=192, key_algo="ec")
    assert len(got) == 1, got


def test_the_detail_names_the_algorithm_it_judged():
    """The old message said "256 bits, below the 2048-bit minimum" and never said against WHAT, so a
    reader could not see the category error. Naming it is what makes the next one visible."""
    detail = _weak_key(key_bits=1024, key_algo="rsa")[0]["detail"]
    assert "RSA" in detail and "2048" in detail, detail


# ── unknown is not weak ───────────────────────────────────────────────────────

def test_an_unidentified_algorithm_is_not_accused():
    """A finding is a claim. "I could not identify this key" is not evidence of a weak one, and a
    permissive default here is exactly how the original bug generalised to every curve."""
    assert _weak_key(key_bits=256, key_algo="") == []
    assert _weak_key(key_bits=256, key_algo="brand-new-pqc-scheme") == []


def test_ed25519_is_never_judged_on_size():
    """A fixed-size modern curve. Comparing it to a bit threshold is the same category error."""
    assert _weak_key(key_bits=256, key_algo="ed25519") == []


def test_a_caller_that_never_learned_to_pass_the_algorithm_reports_nothing():
    """The default is "" and not "rsa" deliberately. A falsy default that GUESSES rsa would rebuild
    the bug for any call site not yet updated, which is the failure mode this project has hit
    repeatedly. Silence from an un-updated caller is the safe direction."""
    assert _weak_key(key_bits=256) == []


# ── the producer must actually carry the type ─────────────────────────────────

def test_key_bits_returns_the_algorithm_beside_the_size():
    """`_key_bits` knew the algorithm all along and threw it away on the way out. The contract is a
    pair now, so the type cannot be lost between the two halves again."""
    got = tp._key_bits(b"not a certificate")
    assert isinstance(got, tuple) and len(got) == 2, got
    assert got == (0, ""), got


def test_probe_tls_declares_the_algorithm_field():
    """The transport probe must publish `key_algo`, or `findings_for` receives "" forever and the
    check silently never fires again -- a fix that looks like a fix and tests nothing."""
    import inspect
    src = inspect.getsource(tp.probe_tls)
    assert '"key_algo"' in src, "probe_tls must seed key_algo in its result dict"
