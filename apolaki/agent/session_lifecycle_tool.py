"""Session-lifecycle invalidation analyzer (CWE-613 — WSTG-SESS-06 / -07 / -11).

WHAT WAS MISSING. `session_fixation_tool` answers one question — "was the identifier regenerated when
the session was CREATED?" — and nothing answered the mirror question: "is the identifier destroyed when
the session ENDS?" Logout that only clears the client's cookie, a password change that leaves every
other session live, and a declared expiry the server never enforces are all the same defect (CWE-613,
Insufficient Session Expiration) and all appear in essentially every commercial pentest report.

Worse, the platform had blinded itself to the endpoint the test needs: `tools._add_urls` DROPPED any
session-killing URL so no probe could log the scanner out. Dropping it also meant nothing remembered
where it was. It is now QUARANTINED instead — kept out of the probe surface, kept in a list only this
engine reads.

THE ORACLE, AND WHY IT IS TWO-SIDED.

    baseline   session cookie C reaches an authenticated marker            (must hold, or stop)
    control    a FRESHLY INVENTED cookie of the SAME NAME is REJECTED      (must hold, or stop)
    act        POST the app's own logout with C, and prove the app took it (must hold, or stop)
    probe      replay C against the SAME endpoint                          (confirmed iff still authed)
    re-control the invented cookie is STILL rejected after the logout      (must hold, or demote)

The control is not decoration. Without it, an endpoint that answers 200 to everyone reads as "still
authenticated" after logout and the engine confirms a bug on a healthy app. This project has been bitten
three times in one day by probing with an invented value and never measuring the baseline: baseline and
probe fail identically, and the engine reports a vulnerable field clean. Baseline first, always — here
the baseline is measured first and the control is measured TWICE, because the endpoint's behaviour is
allowed to change under us and a silent change would look exactly like the bug.

`logout_accepted` is the other honesty gate. A 200 from a logout endpoint is a DECLARATION; a cleared
Set-Cookie, a redirect to the login page, or a stated confirmation is a FACT. Without one of those facts
we cannot distinguish "the app ignored our logout" from "the app kept the session alive", so the verdict
is a lead, never a confirmation.

Pure: every function here decides over values the caller observed. All I/O lives in
`tools.ToolRegistry._run_session_lifecycle`.
"""
from __future__ import annotations

import re
import secrets

from urllib.parse import urljoin, urlparse

from session_token_tool import is_sessionish

# A session-ENDING route on the application's own surface. Deliberately the same vocabulary
# `tools._SESSION_KILL_RE` uses to keep such URLs OUT of the probe surface: one definition of
# "this endpoint ends a session", read by the guard that avoids it and by the engine that needs it.
LOGOUT_RE = re.compile(
    r"(?:^|/)(?:logout|log-?out|signout|sign-?out|log_?off|deauth)(?:[./?]|$)"
    r"|[?&](?:action|do|op|mode)=(?:logout|signout|log-?out)", re.I)

# Password-change routes, discovered on the surface rather than assumed.
PW_CHANGE_RE = re.compile(r"chang\w*[-_/]?password|password[-_/]?chang|new[-_/]?password|passwd", re.I)

# Ordered fallbacks, mirroring the existing `_login_candidates` / `_register_candidates` pattern: bounded
# ENDPOINT discovery on a target that exposes no link to the route. Never a payload or credential list.
_LOGOUT_PATHS = ("/logout", "/api/logout", "/rest/user/logout", "/auth/logout", "/api/auth/logout",
                 "/signout", "/sign-out", "/users/logout", "/session/logout", "/account/logout")
_PW_CHANGE_PATHS = ("/api/change-password", "/rest/user/change-password", "/change-password",
                    "/account/password", "/api/users/me/password", "/api/password", "/password/change")

# Response text that means "you are looking at the login wall", i.e. NOT an authenticated view.
_LOGGED_OUT_MARKERS = ("please log in", "please sign in", "login required", "not authenticated",
                       "unauthorized", "invalid token", "session expired", "invalid session")
# Byte-observable confirmations that a logout was actually PROCESSED by the server.
_LOGOUT_DONE_MARKERS = ("logged out", "log out successful", "signed out", "sign-out successful",
                        "session ended", "session terminated", "goodbye")


# ── endpoint discovery (bounded, surface-first) ───────────────────────────────────────────────

def _dedup(seq):
    seen, out = set(), []
    for x in seq:
        if x and x not in seen:
            seen.add(x)
            out.append(x)
    return out


def logout_candidates(base: str, quarantined=None, html: str = "", limit: int = 8) -> list:
    """Ordered logout-endpoint candidates for `base`. Pure.

    Surface-discovered first (the quarantine list `tools._add_urls` fills, then any anchor href in a page
    the engine itself fetched), then the bounded default path list. Same shape as the login/register
    candidate helpers already in the platform: endpoint discovery, never guessing a value."""
    b = (base or "").rstrip("/")
    host = urlparse(b).netloc
    cands = []
    for u in (quarantined or []):
        u = str(u)
        if LOGOUT_RE.search(urlparse(u).path or "") or LOGOUT_RE.search(u):
            if not host or urlparse(u).netloc == host:
                cands.append(u)
    for href in _hrefs(html):
        if LOGOUT_RE.search(href):
            cands.append(urljoin(b + "/", href))
    cands += [b + p for p in _LOGOUT_PATHS]
    return _dedup(cands)[:limit]


def password_change_candidates(base: str, surface=None, html: str = "", limit: int = 8) -> list:
    """Ordered change-password endpoint candidates for `base`. Pure. Same discipline as above."""
    b = (base or "").rstrip("/")
    host = urlparse(b).netloc
    cands = []
    for u in (surface or []):
        u = str(u)
        if PW_CHANGE_RE.search(urlparse(u).path or "") and (not host or urlparse(u).netloc == host):
            cands.append(u)
    for href in _hrefs(html):
        if PW_CHANGE_RE.search(href):
            cands.append(urljoin(b + "/", href))
    cands += [b + p for p in _PW_CHANGE_PATHS]
    return _dedup(cands)[:limit]


_HREF_RE = re.compile(r"""(?:href|action)\s*=\s*["']([^"'>\s]+)""", re.I)


def _hrefs(html: str) -> list:
    return _HREF_RE.findall(html or "")[:400]


def marker_candidates(base: str, surface=None, limit: int = 10) -> list:
    """Endpoints that plausibly render an AUTHENTICATED view, ordered. Pure.

    Same-host surface URLs that look account-scoped come first (they are the ones a session actually
    gates), then the base itself — an app that renders "signed in as X" on its own root is the common
    case and needs no special path."""
    b = (base or "").rstrip("/")
    host = urlparse(b).netloc
    hot = re.compile(r"/(me|profile|account|whoami|user|users|dashboard|session|home|basket|cart|orders?)\b", re.I)
    prefer, rest = [], []
    for u in (surface or []):
        u = str(u)
        if urlparse(u).scheme not in ("http", "https") or (host and urlparse(u).netloc != host):
            continue
        if LOGOUT_RE.search(urlparse(u).path or ""):
            continue                                  # never point the marker probe at a session killer
        (prefer if hot.search(urlparse(u).path or "") else rest).append(u.split("#")[0])
    return _dedup(prefer + [b + "/", b] + rest)[:limit]


# ── the negative control ──────────────────────────────────────────────────────────────────────

def parse_cookie_header(value: str) -> dict:
    """`"a=1; b=2"` -> `{"a": "1", "b": "2"}`. Pure."""
    out = {}
    for part in str(value or "").split(";"):
        k, _, v = part.strip().partition("=")
        if k:
            out[k.strip()] = v.strip()
    return out


def build_cookie_header(jar: dict) -> str:
    return "; ".join("%s=%s" % (k, v) for k, v in (jar or {}).items())


def session_credential_names(headers: dict) -> list:
    """The header/cookie names that actually carry this session's identity. Pure.

    Cookie names are returned bare (`sid`); a bearer token is returned as `Authorization`. Used both to
    build the negative control and to decide whether a logout response CLEARED the session."""
    names = []
    for k, v in (headers or {}).items():
        if str(k).lower() == "cookie":
            names += list(parse_cookie_header(v).keys())
        elif str(k).lower() == "authorization" and str(v).strip():
            names.append("Authorization")
    return names


def invented_headers(real: dict) -> dict:
    """The same session headers with every secret REPLACED by a freshly invented value of the same
    shape — the mandatory negative control. Pure; returns {} when there is nothing to invent."""
    out = {}
    for k, v in (real or {}).items():
        lk = str(k).lower()
        if lk == "cookie":
            jar = invented_cookies(parse_cookie_header(v))
            if jar:
                out[k] = build_cookie_header(jar)
        elif lk == "authorization":
            scheme, _, tok = str(v).partition(" ")
            if tok.strip():
                out[k] = "%s %s" % (scheme, list(invented_cookies({"t": tok.strip()}).values())[0])
        else:
            out[k] = v
    return out


def invented_cookies(real: dict) -> dict:
    """A freshly INVENTED cookie jar with the same NAMES and value SHAPES as the real session. Pure.

    Same names on purpose: a cookie the server has never heard of is a weaker control than a
    well-formed value for the exact name the server validates. The value is random, so it can only be
    accepted by an endpoint that is not really checking the session."""
    out = {}
    for name, val in (real or {}).items():
        v = str(val or "")
        n = max(8, min(len(v), 64))
        if re.fullmatch(r"[0-9a-fA-F]+", v) and v:
            out[name] = secrets.token_hex(max(4, n // 2))[:n]
        elif v.count(".") == 2:                        # JWT-shaped: keep the shape, invent every segment
            out[name] = ".".join(secrets.token_urlsafe(max(8, len(p) * 3 // 4))[:len(p) or 8]
                                 for p in v.split("."))
        else:
            out[name] = secrets.token_urlsafe(n)[:n]
    return out


# ── the discriminator: HOW we will tell "authenticated" from "not" at this endpoint ───────────

def build_discriminator(authed: dict, control: dict, identity_markers=None):
    """(discriminator, why) when this endpoint provably distinguishes our session from an invented one;
    (None, why_not) otherwise. Pure — the caller supplies two observed responses.

    `authed`  — the endpoint's response carrying the REAL session cookie.
    `control` — the same request carrying the freshly invented cookie (the mandatory negative control).
    `identity_markers` — OBSERVED values belonging to the account we created (email / username). Never
    an invented string: a marker we made up could not appear in either response, and the engine would
    silently degrade to "no marker endpoint" on a target that has one."""
    a_s, c_s = int(authed.get("status") or 0), int(control.get("status") or 0)
    a_b, c_b = str(authed.get("body") or ""), str(control.get("body") or "")
    if not (200 <= a_s < 300):
        return None, "the session did not reach this endpoint (status %d)" % a_s
    if _looks_logged_out(a_b):
        return None, "the authenticated response renders a login wall — the session is not in effect here"
    if not (200 <= c_s < 300):
        return ({"kind": "status", "authed_status": a_s, "control_status": c_s},
                "an invented cookie is rejected with HTTP %d where the real session gets HTTP %d"
                % (c_s, a_s))
    for m in (identity_markers or []):
        m = str(m or "")
        if len(m) >= 4 and m in a_b and m not in c_b:
            return ({"kind": "marker", "authed_status": a_s, "control_status": c_s, "marker": m},
                    "the response to the real session contains the account identifier %r, and the "
                    "identical request with an invented cookie does not" % m)
    if not _looks_logged_out(c_b):
        return None, ("the endpoint answers HTTP %d to an INVENTED cookie with no identity difference — "
                      "it is served anonymously, so it cannot witness session validity" % c_s)
    return ({"kind": "login_wall", "authed_status": a_s, "control_status": c_s},
            "an invented cookie is answered with a login wall where the real session is not")


def _looks_logged_out(body: str) -> bool:
    low = str(body or "").lower()[:20000]
    return any(m in low for m in _LOGGED_OUT_MARKERS)


def still_authenticated(resp: dict, disc: dict) -> bool:
    """Does this response still show the AUTHENTICATED view, judged by the discriminator that was proven
    to separate the real session from an invented one? Pure."""
    if not disc or not resp:
        return False
    status = int(resp.get("status") or 0)
    body = str(resp.get("body") or "")
    kind = disc.get("kind")
    if kind == "marker":
        return (200 <= status < 300) and disc.get("marker", "\x00") in body
    if kind == "status":
        return status == int(disc.get("authed_status") or 0)
    if kind == "login_wall":
        return (200 <= status < 300) and not _looks_logged_out(body)
    return False


# ── did the app actually PROCESS the state change we asked for? ───────────────────────────────

_CLEARED_RE = re.compile(r"(?:^|;\s*)(?:max-age\s*=\s*0|expires\s*=\s*thu,\s*01[ -]jan[ -]1970)", re.I)


def logout_accepted(status: int, headers: dict, body: str, cookie_names=None):
    """(accepted, evidence). Was the logout genuinely PROCESSED, on byte-observable grounds? Pure.

    A 2xx is a declaration. A cleared Set-Cookie for the session name, a redirect off to the login/root,
    or an explicit confirmation in the body are facts. Requiring one of the facts is what stops "the app
    ignored our logout request" from being reported as "the app failed to invalidate the session"."""
    st = int(status or 0)
    if not (200 <= st < 400):
        return False, "the logout endpoint answered HTTP %d — the request was not accepted" % st
    hdrs = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
    setc = hdrs.get("set-cookie", "")
    for name in (cookie_names or []):
        for piece in re.split(r",(?=[^;=]+=)", setc):
            if not piece.strip().lower().startswith(str(name).lower() + "="):
                continue
            val = piece.split("=", 1)[1].split(";")[0].strip()
            if val in ("", '""', "deleted", "null") or _CLEARED_RE.search(piece):
                return True, ("the logout response CLEARS the session cookie %r (Set-Cookie: %s)"
                              % (name, piece.strip()[:120]))
    loc = hdrs.get("location", "")
    if 300 <= st < 400 and loc:
        return True, "the logout responded HTTP %d redirecting to %s" % (st, loc[:120])
    low = str(body or "").lower()[:8000]
    for m in _LOGOUT_DONE_MARKERS + _LOGGED_OUT_MARKERS:
        if m in low:
            return True, "the logout response states the session ended (%r) with HTTP %d" % (m, st)
    return False, ("the logout answered HTTP %d but did not clear the session cookie, redirect, or "
                   "state that the session ended — we cannot prove the app processed it" % st)


def password_change_accepted(old_login_status: int, new_login_status: int):
    """(accepted, evidence). The credential rotation is proven by the app's OWN login endpoint: the OLD
    password must now be refused and the NEW one accepted. Two known values, no iteration. Pure."""
    old_ok = 200 <= int(old_login_status or 0) < 300
    new_ok = 200 <= int(new_login_status or 0) < 300
    if new_ok and not old_ok:
        return True, ("the credential really rotated: re-login with the OLD password now returns HTTP %d "
                      "and the NEW password returns HTTP %d" % (old_login_status, new_login_status))
    return False, ("credential rotation unproven (old-password login HTTP %s, new-password login HTTP %s)"
                   % (old_login_status, new_login_status))


def declared_lifetime(set_cookie: str, cookie_names=None):
    """Seconds the server DECLARED this session cookie should live (Max-Age), or None. Pure.

    Only Max-Age is read: it is a relative integer, so it needs no clock agreement with the target, and
    an `Expires` date would make the check depend on the target's clock being right."""
    for piece in re.split(r",(?=[^;=]+=)", str(set_cookie or "")):
        head = piece.strip().split("=", 1)[0].strip().lower()
        if cookie_names and head not in {str(n).lower() for n in cookie_names}:
            continue
        if not cookie_names and not is_sessionish(head):
            continue
        m = re.search(r"max-age\s*=\s*(\d{1,9})", piece, re.I)
        if m:
            return int(m.group(1))
    return None


# ── findings ──────────────────────────────────────────────────────────────────────────────────

_BASE_TAGS = ["session", "session-lifecycle", "cwe-613"]

# ONE vector for the whole class, because the exploited impact really is the same in all three variants:
# whoever replays the token holds the entire account session. The variants differ in how the window opens,
# not in what it grants, and inventing a lower C/I for the weaker-looking one would be scoring the
# LIKELIHOOD in the impact metrics.
#   AC:H  the attacker must already hold a token the app was supposed to have retired — a condition
#         outside their control, and the same call `session_fixation_tool` makes.
#   UI:R  the user has to have signed out / rotated / gone idle for the retired token to exist at all.
# `report.check_report_honesty` recomputes this from the vector and rejects a score that disagrees with
# it by more than 0.5, so these two constants must be kept together. test_session_lifecycle pins them.
_CVSS_VECTOR = "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N"
_CVSS_SCORE = 6.8       # CVSS v3.1 base for the vector above; band = medium


def _finding(title, family, wstg, target, evidence, oracle, steps, impact, remediation,
             severity="medium", confidence="confirmed", extra_tags=(), cvss_rationale=""):
    f = {
        "title": title, "severity": severity, "family": family, "confidence": confidence,
        "target": target, "cwe": "CWE-613",
        "cvss_vector": _CVSS_VECTOR, "cvss_score": _CVSS_SCORE,
        "evidence": evidence, "success_oracle": oracle, "reproduction_steps": list(steps),
        "impact": impact, "remediation": remediation,
        "tags": _BASE_TAGS + [str(wstg).lower()] + list(extra_tags),
        "wstg": wstg,
    }
    if cvss_rationale:
        f["cvss_rationale"] = cvss_rationale
    return f


def logout_finding(marker_url: str, logout_url: str, disc: dict, control_evidence: str,
                   accept_evidence: str, replay_status: int, recheck_evidence: str) -> dict:
    ev = ("Session lifecycle at %s: a session Apolaki created reached the authenticated view (HTTP %s). "
          "NEGATIVE CONTROL — the identical request carrying a freshly invented cookie of the same name "
          "was rejected: %s. %s. Replaying the ORIGINAL cookie afterwards STILL returned the "
          "authenticated view (HTTP %d), so the server never destroyed the session. Post-logout control "
          "re-check: %s."
          % (marker_url, disc.get("authed_status"), control_evidence, accept_evidence,
             replay_status, recheck_evidence))
    return _finding(
        "Session not invalidated on logout — the token still works after signing out",
        "session_lifecycle", "WSTG-SESS-06", marker_url, ev,
        "the pre-logout session cookie still returns the authenticated view after a processed logout",
        ["Create an account (or log in) and record the session cookie the app issues.",
         "GET %s with that cookie and note the authenticated response." % marker_url,
         "Repeat the same GET with a random value for the same cookie name — it must be rejected.",
         "Send the application's own logout at %s with the real cookie." % logout_url,
         "Replay the original cookie against %s: it still returns the authenticated view." % marker_url],
        "Logout is cosmetic. A token captured from a log, a proxy, a shared machine's browser or a "
        "backup remains usable indefinitely after the user believes they have signed out, so revoking "
        "access is impossible without changing the underlying credential.",
        "Destroy session state SERVER-SIDE on logout (delete the record / revoke the token id) rather "
        "than only clearing the client cookie; for stateless tokens keep a revocation list until expiry.",
        severity="medium", extra_tags=["logout", "cwe-613-logout"])


def password_change_finding(marker_url: str, change_url: str, disc: dict, control_evidence: str,
                            accept_evidence: str, replay_status: int, recheck_evidence: str) -> dict:
    ev = ("Concurrent-session handling at %s: two sessions were opened for one account Apolaki created. "
          "NEGATIVE CONTROL — an invented cookie of the same name was rejected: %s. The password was then "
          "changed through the application's own endpoint %s, and %s. Replaying the OTHER session's "
          "original cookie STILL returned the authenticated view (HTTP %d). Post-change control re-check: %s."
          % (marker_url, control_evidence, change_url, accept_evidence, replay_status, recheck_evidence))
    return _finding(
        "Sessions survive a password change — other sessions are not terminated on credential rotation",
        "session_lifecycle", "WSTG-SESS-11", marker_url, ev,
        "a session opened before the password change still returns the authenticated view after it",
        ["Create an account and open TWO sessions for it (log in twice).",
         "Confirm both cookies reach the authenticated view at %s." % marker_url,
         "Change the password from the first session via %s." % change_url,
         "Verify the rotation: the old password is now refused and the new one accepted at login.",
         "Replay the SECOND session's original cookie — it still returns the authenticated view."],
        "Changing the password is the standard response to a suspected compromise, and here it does not "
        "evict the attacker: an intruder holding a stolen session keeps access after the victim has "
        "rotated the only credential they control.",
        "Terminate every other session for the principal when its credential changes (bump a per-user "
        "session epoch / token version and reject anything issued before it).",
        severity="medium", extra_tags=["password-change", "concurrent-sessions"])


def timeout_finding(marker_url: str, declared: int, waited: int, disc: dict, control_evidence: str,
                    replay_status: int, recheck_evidence: str) -> dict:
    ev = ("Session expiry at %s: the server DECLARED a lifetime of %ds for its session cookie "
          "(Set-Cookie Max-Age). NEGATIVE CONTROL — an invented cookie of the same name was rejected: %s. "
          "After waiting %ds with no activity, replaying the original cookie STILL returned the "
          "authenticated view (HTTP %d) — the declared expiry is advisory to the browser and is not "
          "enforced server-side. Post-wait control re-check: %s."
          % (marker_url, declared, control_evidence, waited, replay_status, recheck_evidence))
    return _finding(
        "Declared session expiry is not enforced server-side (session outlives its stated lifetime)",
        "session_lifecycle", "WSTG-SESS-07", marker_url, ev,
        "the session cookie is still accepted after the lifetime the server itself declared has elapsed",
        ["Create an account and record the Set-Cookie the app issues, including its Max-Age.",
         "Confirm the cookie reaches the authenticated view at %s." % marker_url,
         "Confirm a random value for the same cookie name is rejected there.",
         "Wait until the declared Max-Age has elapsed, sending nothing.",
         "Replay the original cookie — it is still accepted."],
        "The expiry a user (or an auditor) is shown is fiction. A token lifted from a browser, cache or "
        "log stays valid long past the window the application claims to enforce.",
        "Enforce absolute and idle lifetimes on the SERVER side and reject an expired session id, "
        "instead of relying on the cookie attribute the client is free to ignore.",
        severity="low", extra_tags=["timeout", "expiry"],
        cvss_rationale=(
            "Reported LOW against a medium base score, deliberately. The base vector scores what an "
            "attacker gets once they replay the token — the whole session, same as the logout variant. "
            "What differs here is that nobody ever asked for the session to end: no user signed out and "
            "no credential rotated, so the only extra exposure is the gap between the lifetime the "
            "server advertises and the one it enforces. Reporting that at the base band would rank a "
            "declared-versus-enforced mismatch alongside a logout that does nothing."))


def inconclusive(reason: str) -> str:
    """One-line, honest note for a run that could not reach a verdict. Never a finding."""
    return "session-lifecycle: %s" % reason
