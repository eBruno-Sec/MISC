"""Username-enumeration analyzer (WAHH ch6, "Attacking Authentication" — self-registration / login /
password-reset that leak whether an account exists). Apolaki proves auth *bypass* and weak *tokens* but had
no check for the classic pre-auth oracle: an app whose response to a WRONG password DIFFERS depending on
whether the username exists ("Invalid password" vs "No such user", a 200 vs 302, a materially different body).
That difference is a free membership oracle — an attacker harvests valid accounts before ever guessing a
password, which is exactly what feeds credential-stuffing and targeted phishing.

FP-SAFE BY A NOISE-FLOOR DIFFERENTIAL, NOT A RAW COMPARE. Login pages carry dynamic noise (CSRF tokens,
timestamps, nonces) so two identical requests already differ a little; and the submitted username is reflected
back, which differs trivially. So the engine (1) MASKS every submitted username out of each body before
comparing, and (2) measures the endpoint's OWN noise floor from TWO different non-existent usernames, then
flags enumeration ONLY when a KNOWN-existing account (our registered persona — ground truth, never a guess)
diverges from a non-existent one by MORE than that noise floor, or returns a different status. A well-built
login (identical "invalid credentials" for both) sits at the noise floor and yields nothing. Pure logic here
(mask + similarity + noise-floor decision + finding); the caller supplies the three real responses. NEVER a
password brute-force: every probe uses the SAME deliberately-wrong password; only the username varies, and the
'present' username is one we already created, so no credential is guessed."""
from __future__ import annotations

import difflib
import re
from urllib.parse import urljoin

_INPUT_RE = re.compile(r"<input\b[^>]*>", re.IGNORECASE)
_FORM_RE = re.compile(r"<form\b([^>]*)>(.*?)</form>", re.IGNORECASE | re.DOTALL)


def _attr(tag: str, name: str) -> str:
    m = (re.search(r'%s\s*=\s*"([^"]*)"' % name, tag, re.IGNORECASE)
         or re.search(r"%s\s*=\s*'([^']*)'" % name, tag, re.IGNORECASE)
         or re.search(r"%s\s*=\s*([^\s\"'>]+)" % name, tag, re.IGNORECASE))   # unquoted attribute value
    return m.group(1) if m else ""


def parse_login_form(html_text: str, base_url: str):
    """Return {action,user_field,pass_field,method} for the form that contains a password input (a login form),
    else None. The username field is the last text/email input BEFORE the password input (the real-world layout).
    Deterministic; no network. Lets the enumeration probe target the app's actual login form + field names."""
    for fm in _FORM_RE.finditer(html_text or ""):
        attrs, inner = fm.group(1), fm.group(2)
        inputs = _INPUT_RE.findall(inner)
        pw_idx = next((i for i, tag in enumerate(inputs) if _attr(tag, "type").lower() == "password"), None)
        if pw_idx is None:
            continue
        pass_field = _attr(inputs[pw_idx], "name") or "password"
        user_field = ""
        for tag in inputs[:pw_idx]:                         # last non-password text/email input above it
            if _attr(tag, "type").lower() in ("", "text", "email", "tel") and _attr(tag, "name"):
                user_field = _attr(tag, "name")
        action = _attr("<form %s>" % attrs, "action")
        method = (_attr("<form %s>" % attrs, "method") or "post").lower()
        return {"action": urljoin(base_url, action) if action else base_url,
                "user_field": user_field or "username", "pass_field": pass_field, "method": method}
    return None


# ── JSON login APIs ───────────────────────────────────────────────────────────────────────────────────
# A single-page app posts {"email":…,"password":…} to /api/login; there is no server-rendered <form>, so
# parse_login_form returns None and the engine used to answer "no login form here" and report nothing.
# That is a FALSE NEGATIVE indistinguishable from a hardened app: the differential was never attempted.
# The oracle below is unchanged — enumerable() still does the confirming — only the delivery changes.
_JSON_USER_FIELDS = ("username", "email", "user", "login", "userName")

# Statuses that mean the endpoint rejected our REQUEST SHAPE (or is not a login route at all) rather than
# rejecting the CREDENTIALS. 401/403 are the opposite: they prove the endpoint read our body and judged it.
_SHAPE_REJECT_STATUS = (400, 404, 405, 406, 409, 415, 422, 501)
_SHAPE_REJECT_TEXT = re.compile(
    r"(?i)(is required|required field|missing (?:required )?(?:field|parameter|property)|"
    r"must be provided|cannot be (?:null|blank|empty)|unexpected (?:field|property)|"
    r"invalid (?:request|payload|body|json)|malformed)")


def json_login_shapes() -> list:
    """Candidate JSON login body shapes, most common first. Returns (label, user_field, envelope)."""
    out = [("flat:%s" % uf, uf, "flat") for uf in _JSON_USER_FIELDS]
    out.append(("nested_user:email", "email", "user"))
    out.append(("nested_credentials:username", "username", "credentials"))
    return out


def json_login_body(shape, username: str, password: str) -> dict:
    _label, user_field, envelope = shape
    inner = {user_field: username, "password": password}
    return inner if envelope == "flat" else {envelope: inner}


def shape_rejected(status, body: str) -> bool:
    """True when the API refused the SHAPE, so this candidate proves nothing about the account.

    Deliberately conservative: an unrecognised status is treated as ACCEPTED, because the cost of wrongly
    accepting is one useless differential that finds nothing, while the cost of wrongly rejecting is
    abandoning a real login endpoint and reporting a clean bill of health for a vulnerable app.
    """
    try:
        code = int(status)
    except Exception:
        return True
    if code in _SHAPE_REJECT_STATUS:
        return True
    return bool(_SHAPE_REJECT_TEXT.search(str(body or "")[:2000]))

# margin the existing/absent divergence must EXCEED the absent/absent noise floor before we call it a leak
_MARGIN = 0.06
_AUTH_HINT = re.compile(r"(?i)(set-cookie|\bwelcome\b|dashboard|logout|sign\s*out|redirect|location:)")


def _norm(text: str) -> str:
    """Lowercase, collapse whitespace, and strip long hex/base64 runs (CSRF nonces) so the comparison sees the
    stable message shape, not per-request noise."""
    t = (text or "").lower()
    t = re.sub(r"[0-9a-f]{16,}", "#", t)                 # nonces / csrf tokens / session ids
    t = re.sub(r"\s+", " ", t)
    return t.strip()


def mask(body: str, usernames) -> str:
    """Remove every submitted username (case-insensitive) so a reflected echo can't masquerade as a real
    difference; then normalize. This is what makes the compare about the MESSAGE, not the input."""
    t = body or ""
    for u in usernames:
        if u:
            t = re.sub(re.escape(u), "@U@", t, flags=re.IGNORECASE)
    return _norm(t)


def similarity(a: str, b: str) -> float:
    return difflib.SequenceMatcher(None, a or "", b or "").ratio()


def looks_authenticated(resp: dict) -> bool:
    """A 'present' probe that actually LOGGED IN (session set / redirect to app) is not enumeration — it means
    the deliberately-wrong password was, by fluke, accepted, or the page always sets a session. Either way it
    is not a clean membership oracle, so we refuse to claim enumeration from it."""
    st = int(resp.get("status") or 0)
    hdrs = " ".join("%s: %s" % (k, v) for k, v in (resp.get("headers") or {}).items())
    return st in (301, 302, 303, 307, 308) or bool(_AUTH_HINT.search(hdrs))


def enumerable(absent1: dict, absent2: dict, present: dict, usernames) -> tuple | None:
    """(evidence, cwe) when the KNOWN-existing account diverges from a non-existent one beyond the endpoint's
    own noise floor; else None. `usernames` = every username submitted (masked out of all three bodies).
    absent1/absent2 = two DIFFERENT non-existent usernames (wrong pw); present = our registered account (wrong
    pw)."""
    if looks_authenticated(present):
        return None
    s_pres, s_abs = int(present.get("status") or 0), int(absent1.get("status") or 0)
    m_a1 = mask(absent1.get("body", ""), usernames)
    m_a2 = mask(absent2.get("body", ""), usernames)
    m_pr = mask(present.get("body", ""), usernames)

    # unambiguous: a different HTTP status for the existing account is a status-oracle
    if s_pres and s_abs and s_pres != s_abs:
        return ("the existing account returns HTTP %d while a non-existent one returns HTTP %d (status oracle)"
                % (s_pres, s_abs), "CWE-204")

    noise = similarity(m_a1, m_a2)                       # how alike two NON-existent responses are (the floor)
    signal = similarity(m_pr, m_a1)                      # how alike existing vs non-existent is
    if signal < noise - _MARGIN:
        # surface the phrase that differs, as proof it's a membership message
        diff = _distinct_phrase(m_pr, m_a1)
        return ("responses to an EXISTING vs a NON-EXISTENT account diverge (similarity %.2f) well beyond the "
                "endpoint's own noise floor (%.2f)%s — a membership oracle"
                % (signal, noise, (": e.g. \"%s\"" % diff) if diff else ""), "CWE-204")
    return None


def _distinct_phrase(present_body: str, absent_body: str) -> str:
    """A short chunk present in the existing-account response but not the non-existent one (the tell-tale
    'invalid password' vs 'no such user' wording), for human-readable proof."""
    sm = difflib.SequenceMatcher(None, absent_body, present_body)
    for tag, _i1, _i2, j1, j2 in sm.get_opcodes():
        if tag in ("replace", "insert"):
            frag = present_body[j1:j2].strip()
            if len(frag) >= 4:
                return frag[:60]
    return ""


def timing_enumerable(t_absent1: list, t_absent2: list, t_present: list, min_samples: int = 8):
    """(evidence) when a KNOWN account is DECISIVELY slower to authenticate than a non-existent one — the WAHH
    ch15 timing oracle (valid username ⇒ extra DB lookup + password hashing). FP-SAFE BY CONSERVATISM: timing is
    jitter-prone, so this confirms ONLY when the existing-vs-nonexistent median gap dwarfs BOTH the endpoint's own
    timing noise floor (measured from two NON-existent accounts) AND the present group's own spread, and clears a
    hard 50 ms absolute floor. Under network jitter the noise floor is large, the margin is unmet, and it yields
    nothing — the safe failure mode. Each sample is the SAME wrong password (timing measurement, not a guess)."""
    import statistics
    groups = [t_absent1 or [], t_absent2 or [], t_present or []]
    if any(len(g) < min_samples for g in groups):
        return None
    m_a1, m_a2, m_pr = (statistics.median(g) for g in groups)
    noise = abs(m_a1 - m_a2)                              # two non-existent accounts = the endpoint's own noise floor
    signal = m_pr - max(m_a1, m_a2)                       # existing account slower than BOTH non-existent
    spread = statistics.median([abs(x - m_pr) for x in t_present]) or 1e-6   # within-group jitter of the present group
    if signal > 0 and signal > max(3 * noise, 0.05) and signal > 4 * spread:
        return ("the existing account's median login time (%.0f ms) exceeds a non-existent one's (%.0f ms) by "
                "%.0f ms — far beyond the endpoint's own timing noise (%.0f ms) and the sample's spread"
                % (m_pr * 1000, max(m_a1, m_a2) * 1000, signal * 1000, noise * 1000))
    return None


def finding(url: str, evidence: str, cwe: str, present_username: str, field: str) -> dict:
    return {
        "title": "Username enumeration via login response discrepancy (%s)" % field,
        "severity": "medium", "family": "username_enumeration", "confidence": "confirmed", "target": url,
        "cwe": cwe, "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "cvss_score": 5.3,
        "evidence": ("The '%s' endpoint leaks account existence: %s. A known account and a random non-existent "
                     "one were each submitted with the SAME wrong password; only the username varied."
                     % (url, evidence)),
        "success_oracle": evidence,
        "reproduction_steps": [
            "POST %s with a random non-existent username and any wrong password; record the response." % url,
            "POST %s with a real account ('%s') and the SAME wrong password." % (url, present_username),
            "The two responses differ (status or message) purely because one account exists — the app confirms "
            "membership before authentication."],
        "impact": ("Pre-auth account harvesting: an attacker enumerates valid usernames/emails to seed "
                   "credential-stuffing and targeted phishing, and to confirm which accounts to attack."),
        "remediation": ("Return an identical, generic failure ('invalid username or password') with the same "
                        "status, body, and timing whether or not the account exists — on login, registration, "
                        "and password reset alike."),
        "tags": ["authentication", "username-enumeration", cwe.lower(), "wstg-idnt-04"],
    }


def timing_finding(url: str, evidence: str, present_username: str, field: str) -> dict:
    """A username-enumeration finding proven by a TIMING side channel (CWE-208) rather than response content —
    fires only when the content responses were identical, so it is the residual, harder-to-spot variant."""
    return {
        "title": "Username enumeration via login TIMING side channel (%s)" % field,
        "severity": "low", "family": "username_enumeration", "confidence": "confirmed", "target": url,
        "cwe": "CWE-208", "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N", "cvss_score": 3.7,
        "evidence": ("The '%s' endpoint returns identical content for valid and invalid usernames but leaks account "
                     "existence by RESPONSE TIME: %s. Each probe used the SAME wrong password; only the username "
                     "varied, and the timing gap dwarfs the endpoint's own measured noise floor." % (url, evidence)),
        "success_oracle": evidence,
        "reproduction_steps": [
            "POST %s many times with a random non-existent username + a fixed wrong password; record the median time." % url,
            "POST %s many times with a real account ('%s') + the SAME wrong password; record the median time." % (url, present_username),
            "The real account is decisively slower (valid username ⇒ extra DB lookup + password hashing) beyond the "
            "endpoint's own timing noise — a membership oracle with no content difference at all."],
        "impact": ("Pre-auth account harvesting even against a 'generic message' login — timing alone confirms which "
                   "usernames exist, seeding credential-stuffing and targeted phishing."),
        "remediation": ("Make authentication timing independent of account existence: always run the password-hash "
                        "comparison (against a dummy hash for unknown users) and return after a constant-time path."),
        "tags": ["authentication", "username-enumeration", "timing", "cwe-208", "wstg-idnt-04"],
    }
