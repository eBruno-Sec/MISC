"""
CSRF detection: state-changing form / SameSite analysis.

From Bug Bounty Bootcamp (Li, Ch 9). Black-box CSRF hunting is: (1) spot
state-changing actions, (2) check for missing CSRF protection (no token AND weak
SameSite), accounting for the nuances the chapter stresses:

  - SameSite=Lax is the modern browser default, so a token-less POST form is only
    exploitable when the session cookie is SameSite=None (or a non-default
    browser). We grade accordingly instead of crying "CSRF" on every POST form.
  - A GET request that changes state is exploitable even under SameSite=Lax
    (top-level navigation sends the cookie), so a sensitive GET form is graded
    higher.

Pure/deterministic; tools._run_csrf fetches the page and its Set-Cookie and runs
this. No state-changing requests are sent (safe, non-destructive).
"""
from __future__ import annotations

import re
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse

# input/param names that indicate an anti-CSRF token
TOKEN_NAME = re.compile(
    r"csrf|xsrf|_token\b|authenticity_token|anti.?forgery|__requestverificationtoken|nonce|\bstate\b",
    re.I)
# action paths whose change is security-sensitive (higher impact)
SENSITIVE_ACTION = re.compile(
    r"password|passwd|email|e-mail|account|settings|profile|role|admin|payment|billing|"
    r"transfer|withdraw|delete|remove|address|phone|2fa|mfa|api[_-]?key|token|grant|invite",
    re.I)


class _FormParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.forms = []
        self._cur = None

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "form":
            self._cur = {"method": a.get("method", "get").lower(), "action": a.get("action", ""),
                         "inputs": []}
        elif tag in ("input", "textarea", "select", "button") and self._cur is not None:
            if a.get("name"):
                self._cur["inputs"].append({"name": a["name"], "type": a.get("type", "text").lower()})

    def handle_endtag(self, tag):
        if tag == "form" and self._cur is not None:
            self.forms.append(self._cur)
            self._cur = None


def parse_forms(html: str, base_url: str = "") -> list:
    p = _FormParser()
    try:
        p.feed(html or "")
    except Exception:
        pass
    out = []
    for f in p.forms:
        has_token = any(TOKEN_NAME.search(i["name"]) for i in f["inputs"])
        action = urljoin(base_url, f["action"]) if base_url else f["action"]
        out.append({"method": f["method"].upper() or "GET", "action": action or base_url,
                    "inputs": [i["name"] for i in f["inputs"]], "has_token": has_token})
    return out


def parse_samesite(set_cookie: str) -> str:
    """Return the weakest SameSite seen on a session-ish cookie: 'none' | 'lax' |
    'strict' | '' (absent). '' means the app did not set it (browser default Lax
    applies, but non-default browsers are unprotected)."""
    if not set_cookie:
        return ""
    sess = re.search(r"(?i)(sess|sid|auth|token|jwt|login|phpsessid|jsessionid|asp\.net)[^;]*;?(.*)",
                     set_cookie)
    scope = set_cookie if not sess else set_cookie
    m = re.search(r"(?i)samesite\s*=\s*(strict|lax|none)", scope)
    return m.group(1).lower() if m else ""


def analyze(forms: list, set_cookie: str, page_url: str) -> list:
    samesite = parse_samesite(set_cookie)
    findings = []
    for f in forms:
        method = f["method"]
        action = f["action"] or page_url
        sensitive = bool(SENSITIVE_ACTION.search(action) or
                         any(SENSITIVE_ACTION.search(n) for n in f["inputs"]))

        # GET that changes sensitive state — exploitable even under SameSite=Lax
        if method == "GET" and sensitive:
            findings.append(_finding(
                "CSRF via state-changing GET request", "medium", action,
                "A sensitive action is reachable by GET; top-level navigation sends the session cookie even "
                "under the SameSite=Lax browser default, so a simple <img>/link CSRF works.",
                ["Craft <img src='" + action + "?...'>", "Load it while authenticated", "Confirm the action ran"],
                samesite))
            continue

        if method in ("POST", "PUT", "PATCH", "DELETE") and not f["has_token"]:
            if samesite in ("", "none"):
                sev = "high" if sensitive and samesite == "none" else ("medium" if sensitive else "low")
                note = ("session cookie is SameSite=None — classic cross-site form CSRF works in all browsers"
                        if samesite == "none" else
                        "app did not set SameSite (default Lax protects Chrome, but Firefox/Safari without the "
                        "default and any SameSite=None path remain exploitable)")
                findings.append(_finding(
                    f"Missing CSRF token on {method} form", sev, action,
                    f"The {method} form has no anti-CSRF token field and {note}.",
                    [f"Build an auto-submitting {method} form to {action}",
                     "Load it in an authenticated victim browser", "Confirm the state change"],
                    samesite))
            # SameSite Strict/Lax with a non-sensitive action -> browser default covers it; stay quiet
    return findings


def _finding(title, severity, action, desc, steps, samesite):
    return {
        "title": title, "severity": severity, "target": action,
        "description": desc + f" (observed SameSite: {samesite or 'not set'}).",
        "impact": "Force authenticated victims to perform state-changing actions (password/email change, "
                  "transfers, account takeover).",
        "reproduction_steps": steps, "cwe": "CWE-352", "family": "csrf",
        "tags": ["csrf", "access-control"], "confidence": "candidate",
    }
