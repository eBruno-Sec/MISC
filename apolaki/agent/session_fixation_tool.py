"""Session-fixation analyzer (WAHH ch7/ch8, CWE-384 / WSTG-SESS-03). Apolaki samples token *predictability*
(session_token_tool) but never checked the other classic session flaw: an app that does NOT regenerate the
session identifier at the moment of authentication. If the token a client holds BEFORE login is still valid
and UNCHANGED AFTER a successful login, an attacker who plants a known token in a victim's browser (via a set
of vectors WAHH catalogs) rides the victim's authenticated session the instant they log in.

CONFIRMATION IS DETERMINISTIC + FP-SAFE. The caller drives ONE real client through the login boundary with a
KNOWN-GOOD credential (single value, never a brute-force) and hands this module (1) the session cookies the
client held pre-auth, (2) the cookies it holds post-auth, and (3) proof the login actually SUCCEEDED (the login
form is gone from the post-auth response). Fixation is flagged ONLY when a session-ish cookie present pre-auth
carries the SAME value post-auth AND the login succeeded — an app that rotates the token (new value) or issues
no pre-auth token sits clean and yields nothing. Pure logic here (compare + finding)."""
from __future__ import annotations

from session_token_tool import is_sessionish

_MIN_LEN = 6                                                 # ignore trivially short values (not a real token)


def analyze(pre: dict, post: dict, login_succeeded: bool):
    """(cookie_name, evidence) when a pre-auth session cookie is UNCHANGED after a SUCCESSFUL login; else None.
    pre/post: {cookie_name: value} the client held before / after authenticating."""
    if not login_succeeded:
        return None                                          # a failed login proves nothing about rotation
    for name, v1 in (pre or {}).items():
        if not is_sessionish(name) or not v1 or len(str(v1)) < _MIN_LEN:
            continue
        v2 = (post or {}).get(name)
        if v2 is not None and v2 == v1:
            return (name, "the session cookie '%s' the client held BEFORE login is byte-for-byte unchanged "
                          "AFTER a successful authentication (the identifier was not regenerated)" % name)
    return None


def finding(url: str, cookie_name: str, evidence: str) -> dict:
    return {
        "title": "Session fixation — session id not regenerated on login (cookie '%s')" % cookie_name,
        "severity": "high", "family": "session_fixation", "confidence": "confirmed", "target": url,
        "cwe": "CWE-384", "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N", "cvss_score": 6.8,
        "evidence": ("Authenticating at '%s' did not rotate the session identifier: %s. An attacker who fixes "
                     "this token in a victim's browser then waits for them to log in obtains a fully "
                     "authenticated session as that victim." % (url, evidence)),
        "success_oracle": evidence,
        "reproduction_steps": [
            "As a fresh client, request %s and record the session cookie '%s' issued pre-login." % (url, cookie_name),
            "Log in with valid credentials on that SAME client.",
            "Observe the '%s' value is unchanged after login — the app reused the pre-auth token instead of "
            "issuing a new one." % cookie_name],
        "impact": "Account takeover: fix a known session token in a victim's browser and inherit their session "
                  "the moment they authenticate — no credentials needed.",
        "remediation": ("Regenerate the session identifier on every privilege change, especially immediately "
                        "after successful login (and logout); invalidate the pre-auth session server-side."),
        "tags": ["session", "session-fixation", "cwe-384", "wstg-sess-03"],
    }
