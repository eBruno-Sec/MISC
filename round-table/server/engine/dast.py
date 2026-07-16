"""
Headless-browser DAST (opt-in) — the client-side confirmation layer.

An HTTP recon tool (curl/httpx) cannot see vulnerabilities that only exist once
JavaScript runs: DOM-based XSS, and client-side template injection (CSTI) such as
AngularJS evaluating {{7*7}} in the browser. This module renders candidate URLs
in real Chromium (via Playwright) and CONFIRMS execution:

  - CSTI  : inject rtc{{7*7}}rtc; if the rendered DOM contains rtc49rtc, a template
            engine evaluated it client-side.
  - XSS   : inject a benign sentinel payload whose only effect is to call a hook
            (window.__rt / alert override); if the hook fires, script executed.

Benign only — the payloads set an in-page flag; they never exfiltrate data or
navigate away. Round Table proves the vuln and hands the operator the confirmed
finding + weaponization guidance; it does not weaponize. Runs authenticated when
the mission supplies a session. Off unless the mission opts in.
"""
from __future__ import annotations

import time
from urllib.parse import urlparse, quote

from ..core import runconfig

# tuning (kept small so the browser phase stays bounded)
MAX_NAV = 60            # hard cap on page loads
TIME_BUDGET_S = 150     # overall wall-clock budget for the phase
NAV_TIMEOUT_MS = 9000
PARAM_NAMES = ["searchTerm", "search", "q", "query", "s", "keyword", "name", "redirect", "returnUrl", "id"]
INTERESTING = ("search", "catalog", "blog", "query", "find", "filter", "product", "result", "redirect", "return")

# CSTI: unique wrappers make an evaluated result unambiguous (no bare "49" FP).
CSTI_VALUE = "rtc{{7*7}}rtc rtd${7*7}rtd rtf#{7*7}rtf"
CSTI_HITS = {"rtc49rtc": "{{7*7}}", "rtd49rtd": "${7*7}", "rtf49rtf": "#{7*7}"}

# XSS sentinels — inline handlers that call the in-page hook window.__rt(tag).
XSS_PAYLOADS = [
    '"><img src=x onerror=__rt(\'img\')>',
    "<svg onload=__rt('svg')>",
    "'><svg onload=__rt('sqsvg')>",
    "javascript:__rt('uri')",
]

INIT_SCRIPT = """
window.__rtHits = [];
window.__rt = function (t) { try { window.__rtHits.push(String(t)); } catch (e) {} return 1; };
['alert','confirm','prompt'].forEach(function (fn) {
  try { window[fn] = function () { window.__rtHits.push(fn); return true; }; } catch (e) {}
});
"""


def _finding(**kw):
    from ..core.detectors import _finding as f
    return f(**kw)


def _candidate_urls(recon: dict, base: str) -> list[str]:
    """base + a few 'interesting' discovered/JS endpoints on this host."""
    host = urlparse(base).hostname or ""
    out, seen = [base], {base}
    pools = []
    for _b, paths in (recon.get("dir_bust") or {}).items():
        for p in paths or []:
            pools.append(p.get("url") if isinstance(p, dict) else str(p))
    for ep in recon.get("js_endpoints") or []:
        pools.append(base + ep if str(ep).startswith("/") else str(ep))
    for u in pools:
        if not u or (urlparse(u).hostname or "") != host:
            continue
        if any(k in u.lower() for k in INTERESTING) and u not in seen:
            seen.add(u)
            out.append(u.split("#")[0])
        if len(out) >= 5:
            break
    return out


def _with_param(url: str, param: str, value: str) -> str:
    sep = "&" if "?" in url else "?"
    return f"{url}{sep}{param}={quote(value)}"


def run_dast(recon: dict, config: dict, log) -> list[dict]:
    try:
        from playwright.sync_api import sync_playwright
    except Exception:
        log("headless DAST unavailable (playwright not installed) — skipping", "warn", "dast")
        return []

    bases = []
    for h in (recon.get("live_hosts") or [])[:3]:
        u = (h.get("url") or "").rstrip("/")
        if u:
            bases.append(u)
    if not bases:
        return []

    auth_hdrs = runconfig.auth_headers(config)
    extra_headers, cookie_header = {}, ""
    for h in auth_hdrs:
        name, _, val = h.partition(":")
        if name.strip().lower() == "cookie":
            cookie_header = val.strip()
        else:
            extra_headers[name.strip()] = val.strip()

    findings: list[dict] = []
    nav = 0
    deadline = time.time() + TIME_BUDGET_S
    log(f"── Headless DAST (real Chromium) on {len(bases)} host(s) ──", "hdr", "dast")
    if auth_hdrs:
        log("headless DAST running authenticated (session attached to the browser)", "info", "dast")

    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(args=["--no-sandbox", "--disable-dev-shm-usage"])
            ctx = browser.new_context(ignore_https_errors=True,
                                      extra_http_headers=extra_headers or None)
            ctx.add_init_script(INIT_SCRIPT)
            if cookie_header:
                cookies = []
                for pair in cookie_header.split(";"):
                    if "=" in pair:
                        n, v = pair.split("=", 1)
                        cookies.append({"name": n.strip(), "value": v.strip(), "url": bases[0]})
                if cookies:
                    try:
                        ctx.add_cookies(cookies)
                    except Exception:
                        pass
            page = ctx.new_page()
            page.set_default_timeout(NAV_TIMEOUT_MS)

            def visit(url: str) -> str:
                nonlocal nav
                nav += 1
                try:
                    page.goto(url, wait_until="networkidle", timeout=NAV_TIMEOUT_MS)
                except Exception:
                    try:
                        page.goto(url, wait_until="domcontentloaded", timeout=NAV_TIMEOUT_MS)
                    except Exception:
                        return ""
                page.wait_for_timeout(350)  # let client-side frameworks render
                try:
                    return page.content()
                except Exception:
                    return ""

            def hits() -> list:
                try:
                    return page.evaluate("window.__rtHits || []") or []
                except Exception:
                    return []

            for base in bases:
                got_csti = got_xss = False
                for url in _candidate_urls(recon, base):
                    for param in PARAM_NAMES:
                        if nav >= MAX_NAV or time.time() > deadline:
                            break
                        if got_csti and got_xss:
                            break
                        # ── CSTI probe ──
                        if not got_csti:
                            html = visit(_with_param(url, param, CSTI_VALUE))
                            fired = next((v for k, v in CSTI_HITS.items() if k in html), None)
                            if fired:
                                got_csti = True
                                surf = _with_param(url, param, "{{7*7}}")
                                fw = urlparse(base).hostname
                                findings.append(_finding(
                                    key="dast-csti", title="Client-side template injection (CSTI) — CONFIRMED in browser",
                                    category="Injection", severity="HIGH", surface=surf, confidence=93,
                                    evidence=f"Chromium rendered {fired} injected via ?{param}= as 49 in the DOM — a template engine evaluated it client-side.",
                                    what="User input is evaluated by a client-side template engine (AngularJS/Vue/etc.). "
                                         "This is CSTI → XSS: escalate the expression to run arbitrary JavaScript.",
                                    how=[f"Reproduce: open {surf} and confirm the page renders 49.",
                                         "Escalate with the sandbox-escape payload below (AngularJS >=1.6 has no sandbox).",
                                         "Confirm arbitrary JS (alert(document.domain)); report CSTI → XSS."],
                                    payloads=["{{7*7}}",
                                              "{{constructor.constructor('alert(document.domain)')()}}",
                                              "{{$eval.constructor('alert(1)')()}}"],
                                    tools=["browser", "Burp Suite"],
                                    references=[{"title": "PortSwigger · Client-side template injection",
                                                 "url": "https://portswigger.net/research/evading-defences-using-angularjs-script-gadgets"}],
                                    remediation={"summary": "Never render untrusted input inside a client-side template expression; migrate off AngularJS 1.x.", "fixes": []},
                                    tags=["csti", "xss", "confirmed", "dast", "exploit-guidance"],
                                ))
                                log(f"CONFIRMED (DAST): CSTI via ?{param}= on {url}", "ok", "dast")
                        # ── XSS probe ──
                        if not got_xss and nav < MAX_NAV and time.time() <= deadline:
                            for pl in XSS_PAYLOADS:
                                visit(_with_param(url, param, pl))
                                fired = hits()
                                # also probe DOM-sink via the URL fragment
                                if not fired:
                                    visit(f"{url}#{quote(pl)}")
                                    fired = hits()
                                if fired:
                                    got_xss = True
                                    surf = _with_param(url, param, "<payload>")
                                    findings.append(_finding(
                                        key="dast-xss", title="Cross-site scripting (XSS) — CONFIRMED executing in browser",
                                        category="Injection", severity="HIGH", surface=surf, confidence=92,
                                        evidence=f"A benign sentinel payload executed in Chromium (hook fired: {', '.join(sorted(set(fired)))[:60]}) via ?{param}= / URL fragment.",
                                        what="Injected markup executes as script in a real browser — reflected or DOM-based XSS. "
                                             "Round Table used a harmless flag-setting payload; weaponize manually.",
                                        how=["Reproduce with the payload below in a browser and confirm it runs.",
                                             "Determine the context (HTML/attr/JS/DOM sink) and pick the matching break-out.",
                                             "Report with impact (session theft, account actions) — do not pivot beyond PoC."],
                                        payloads=['"><img src=x onerror=alert(document.domain)>',
                                                  "<svg onload=alert(document.domain)>"],
                                        tools=["browser", "Burp Suite"],
                                        references=[{"title": "PortSwigger · XSS", "url": "https://portswigger.net/web-security/cross-site-scripting"}],
                                        remediation={"summary": "Context-encode all output; add a strict CSP; avoid dangerous DOM sinks (innerHTML, document.write).", "fixes": []},
                                        tags=["xss", "dom", "confirmed", "dast", "exploit-guidance"],
                                    ))
                                    log(f"CONFIRMED (DAST): XSS via ?{param}= on {url}", "ok", "dast")
                                    break
                                if nav >= MAX_NAV or time.time() > deadline:
                                    break
                    if nav >= MAX_NAV or time.time() > deadline:
                        break
            try:
                ctx.close(); browser.close()
            except Exception:
                pass
    except Exception as e:
        log(f"headless DAST error: {type(e).__name__}: {e}", "warn", "dast")

    log(f"headless DAST: {len(findings)} confirmed client-side issue(s) in {nav} page load(s)", "ok", "dast")
    return findings
