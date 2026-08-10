"""Session-token predictability analyzer (WAHH ch7, "Weaknesses in Token Generation"). Apolaki confirms JWT
forgery + base64-cookie SQLi, but had no check for the classic weak SESSION token: one that is sequential /
time-incrementing, or that DECODES to meaningful user/role data — both let an attacker predict or forge other
users' tokens and hijack sessions without credentials.

CONFIRMATION IS DETERMINISTIC + FP-SAFE: sample N fresh tokens (the caller fetches the session-issuing URL N
times with a clean client). A token is flagged ONLY when a numeric component forms an ARITHMETIC / bounded
sequence across the sample, or a decoding leaks structured user data. Genuinely random tokens produce neither
signal, so a CSPRNG token yields nothing. Pure logic here (decode + sequence detection + finding)."""
from __future__ import annotations

import base64
import re

_MEANINGFUL = re.compile(r"(?i)(user(name|id)?\s*[=:]|uid\s*[=:]|\brole\s*[=:]|;app=|is_?admin|\bgroup\s*[=:]|priv)")
_SESSIONISH = ("sess", "sid", "session", "token", "auth", "jsessionid", "phpsessid", "asp.net", "connect.sid")


def is_sessionish(name: str) -> bool:
    n = (name or "").lower()
    return any(s in n for s in _SESSIONISH)


def _decodings(tok: str) -> list:
    """The token plus plausible hex/base64 decodings (WAHH: tokens are often hex/Base64 over meaningful data)."""
    out, t = [tok], (tok or "").strip()
    if re.fullmatch(r"[0-9a-fA-F]+", t) and len(t) % 2 == 0 and len(t) <= 400:
        try:
            out.append(bytes.fromhex(t).decode("latin-1"))
        except Exception:
            pass
    try:
        d = base64.urlsafe_b64decode(t + "=" * (-len(t) % 4)).decode("latin-1")
        if sum(c.isprintable() for c in d) >= 0.7 * max(1, len(d)):
            out.append(d)
    except Exception:
        pass
    return out


def meaningful(tokens: list) -> str:
    for tok in tokens:
        for d in _decodings(tok):
            if _MEANINGFUL.search(d):
                return "the token decodes to structured user data ('%s' -> '%s')" % (str(tok)[:24], d[:60])
    return ""


def _numeric_component(tok: str):
    t = (tok or "").strip()
    if re.fullmatch(r"\d+", t):
        return int(t)
    if re.fullmatch(r"[0-9a-fA-F]+", t) and len(t) <= 16:
        try:
            return int(t, 16)
        except Exception:
            pass
    runs = re.findall(r"\d{2,}", t)
    return int(max(runs, key=len)) if runs else None


def sequential(tokens: list) -> str:
    nums = [n for n in (_numeric_component(t) for t in tokens) if n is not None]
    if len(nums) < 4:
        return ""
    deltas = [nums[i + 1] - nums[i] for i in range(len(nums) - 1)]
    if len(set(deltas)) == 1 and deltas[0] != 0:
        return "a numeric token component increments by a constant %d each issue (perfect arithmetic sequence)" % deltas[0]
    if all(0 < d <= 1000 for d in deltas) or all(-1000 <= d < 0 for d in deltas):
        return "a numeric token component moves monotonically in small bounded steps (%s...) — brute-forcible" % deltas[:5]
    return ""


def analyze(tokens: list):
    """(kind, evidence, cwe) or None. Meaningful decoding wins over a numeric sequence; neither = not flagged."""
    toks = [t for t in (tokens or []) if t]
    if len(toks) < 4:
        return None
    ev = meaningful(toks)
    if ev:
        return ("meaningful", ev, "CWE-384")
    ev = sequential(toks)
    if ev:
        return ("sequential/predictable", ev, "CWE-330")
    return None


def finding(url: str, kind: str, evidence: str, cwe: str, cookie_name: str) -> dict:
    return {
        "title": "Predictable session token (%s) in cookie '%s'" % (kind, cookie_name),
        "severity": "high", "family": "weak_session_token", "confidence": "confirmed", "target": url,
        "cwe": cwe, "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N", "cvss_score": 7.4,
        "evidence": ("Session tokens sampled from '%s' are predictable: %s. An attacker can extrapolate valid "
                     "tokens (or forge a meaningful one) and hijack other users' sessions." % (cookie_name, evidence)),
        "success_oracle": evidence,
        "reproduction_steps": [
            "Request %s repeatedly with no cookie; capture the fresh '%s' issued each time." % (url, cookie_name),
            "Observe the sampled tokens are %s." % kind,
            "Extrapolate the sequence (or forge a meaningful token) and replay it to ride another user's session."],
        "impact": "Session hijacking / account takeover with no credentials — predict or forge other users' tokens.",
        "remediation": ("Generate session tokens from a CSPRNG with >=128 bits of entropy; never encode meaningful "
                        "data (username/role) in the token; issue a fresh token on login and privilege change."),
        "tags": ["session", "predictable-token", cwe.lower()],
    }


# ── tokens carried in the RESPONSE BODY, not Set-Cookie ───────────────────────────────────────────────
# A cookie is not the only carrier. An API that answers {"access_token":"…"} or {"data":{"sessionId":"…"}}
# issues a session token the Set-Cookie scan never sees, so a perfectly sequential token was invisible and
# the endpoint was reported clean. The ANALYSER is unchanged — these samples join the same pipeline, and
# the harvested key name is kept verbatim so is_sessionish() judges it exactly as it judges a cookie name.
_TOKEN_KEY = re.compile(r"(?i)(token|session|sid|jwt|auth|apikey|api_key)")
_MAX_BODY = 400_000          # a body larger than this is not a login response; do not spend time parsing it
_MIN_TOK, _MAX_TOK = 8, 512  # below 8 chars it is a flag or a status, above 512 it is a document


def tokens_from_body(body: str, _depth: int = 6) -> dict:
    """Harvest token-shaped values from a JSON response body -> {key: value}.

    Keys are returned verbatim (dotted for nested objects) so the caller's sessionish test and the
    finding's cookie_name field both read naturally. Non-JSON bodies yield nothing rather than guessing:
    a regex over HTML would collect CSRF nonces and asset hashes and manufacture findings.
    """
    import json as _json
    text = str(body or "")
    if not text or len(text) > _MAX_BODY:
        return {}
    try:
        doc = _json.loads(text)
    except Exception:
        return {}
    out = {}

    def walk(node, path, depth):
        if depth <= 0:
            return
        if isinstance(node, dict):
            for k, v in node.items():
                key = "%s.%s" % (path, k) if path else str(k)
                if isinstance(v, str):
                    if _TOKEN_KEY.search(str(k)) and _MIN_TOK <= len(v) <= _MAX_TOK:
                        out[key] = v
                else:
                    walk(v, key, depth - 1)
        elif isinstance(node, list):
            for i, v in enumerate(node[:20]):
                walk(v, "%s[%d]" % (path, i), depth - 1)

    walk(doc, "", _depth)
    return out
