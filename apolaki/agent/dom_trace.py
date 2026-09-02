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


_REDIRECTISH = ("back", "url", "return", "returnurl", "returnto", "next", "goto", "dest",
                "destination", "redirect", "redir", "continue", "callback", "to", "link", "out",
                # request-override-ish names too: a client-side fetch/XHR target is almost always a
                # URL-shaped parameter, so gate the (costly) attacker-host render on these names + reflection
                "endpoint", "api", "src", "uri", "path", "load", "fetch", "resource", "feed",
                "host", "target", "data", "json", "proxy", "file", "u", "domain", "origin")

# THE DOM SINK SCAN. `tools._run_dom_trace` evaluates this in the rendered page with the canary as its
# argument and merges the result into the runtime signals.
#
# THIS CONSTANT WAS MISSING AND THE CALL SITE STILL REFERENCED IT. The evaluate is wrapped in a bare
# `except Exception: pass`, so `AttributeError: module 'dom_trace' has no attribute 'DOM_SCAN_JS'` was
# swallowed on EVERY render: in_href / in_src / in_attr / in_text were never populated, which silently
# retired dom_link_manipulation and dom_data_manipulation entirely — and, because the XSS pass only runs
# where the canary `reflected`, it also stopped every DOM-XSS payload render from ever firing. A dead
# `_TRACE_JS` (the older browser_engine flow, referenced by nothing) sat next to it carrying the same
# logic, which is how the mismatch survived: the code LOOKED present.
DOM_SCAN_JS = r"""(c) => {
  const o = { in_href:"", in_src:"", in_attr:"", in_text:false };
  for (const e of document.querySelectorAll("a[href],area[href],link[href],base[href],form[action]")) {
    const h = e.getAttribute("href") || e.getAttribute("action") || "";
    if (h.indexOf(c) >= 0) { o.in_href = e.tagName+":"+h.slice(0,140); break; } }
  for (const e of document.querySelectorAll("[src]")) {
    const s = e.getAttribute("src") || "";
    if (s.indexOf(c) >= 0) { o.in_src = e.tagName+":"+s.slice(0,140); break; } }
  for (const e of document.querySelectorAll("*")) {
    let hit=false; const at=e.attributes||[];
    for (let i=0;i<at.length;i++){ const a=at[i];
      if (a.name!=="value" && a.value && a.value.indexOf(c)>=0){ o.in_attr=e.tagName+"@"+a.name; hit=true; break; } }
    if(hit) break; }
  try { o.in_text = !!(document.body && document.body.innerHTML.indexOf(c) >= 0); } catch(e){}
  return o;
}"""



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


# ── client-side SOURCES ─────────────────────────────────────────────────────────────────────────
# THE FRAGMENT IS NOT A QUERY PARAMETER, AND THAT IS THE WHOLE POINT. Everything after '#' is never
# transmitted to the server, so no server-side reflection test can observe it and no proxy log records
# it — a fragment-sourced DOM bug is invisible to every engine that reasons about request/response
# pairs. It is only reachable by rendering the page and watching the sink, which is exactly what this
# module does. SPA routers, deparam-style hash parsers and "#!"-style navigation all read it.
#
# Two shapes, because applications parse the hash two different ways:
#   fragment      #name=value  — the hash parsed as a query string (deparam / router query)
#   fragment_raw  #value       — the whole hash consumed as one value (router path, anchor target)
SOURCES = ("query", "fragment", "fragment_raw")


def set_fragment(url: str, name: str, value: str) -> str:
    """Put `name=value` in the URL fragment, preserving any existing fragment pairs. Pure."""
    p = urlparse(url)
    pairs = parse_qsl(p.fragment, keep_blank_values=True)
    if any(k == name for k, _ in pairs):
        pairs = [(k, value if k == name else v) for k, v in pairs]
    else:
        pairs.append((name, value))
    return urlunparse(p._replace(fragment=urlencode(pairs, doseq=True)))


def set_raw_fragment(url: str, value: str) -> str:
    """Replace the whole fragment with `value`. Pure."""
    return urlunparse(urlparse(url)._replace(fragment=str(value)))


def fragment_route_params(url: str) -> list:
    """Parameter names carried INSIDE a hash route, e.g. `#/search?q=x` -> ["q"]. Pure.

    Q-153. A hash-routed SPA keeps its parameters in the FRAGMENT'S OWN query string, and the
    fragment is never sent to the server -- so no request/response engine can see them and neither
    could this one. MEASURED on juice-shop, whose DOM XSS lives at `#/search?q=`: all three
    existing sources miss it, and two of them actively destroy the route.
    """
    frag = urlparse(url).fragment
    if "?" not in frag:
        return []
    return [k for k, _ in parse_qsl(frag.split("?", 1)[1], keep_blank_values=True) if k]


def set_fragment_param(url: str, name: str, value: str) -> str:
    """Set `name=value` inside the fragment's own query string, KEEPING the hash route. Pure.

    `set_fragment` treats the whole fragment as a query string, so on `#/search?q=test` it
    percent-encodes the route into a parameter NAME (`#%2Fsearch%3Fq=test&q=...`) and the app
    routes nowhere. `set_raw_fragment` replaces the route outright. Both leave the payload
    somewhere the application never reads.
    """
    p = urlparse(url)
    route, _, q = p.fragment.partition("?")
    pairs = parse_qsl(q, keep_blank_values=True)
    if any(k == name for k, _ in pairs):
        pairs = [(k, value if k == name else v) for k, v in pairs]
    else:
        pairs.append((name, value))
    return urlunparse(p._replace(fragment=route + "?" + urlencode(pairs, doseq=True)))


def probe_url(url: str, param: str, value: str, source: str = "query") -> str:
    """Build the probe URL for one client-side source. Pure.

    Centralised so a finding's `target` and reproduction steps describe the source that was ACTUALLY
    injected. Rebuilding the URL as a query parameter after probing the fragment would hand the reader
    steps that cannot reproduce the bug."""
    if source == "fragment":
        return set_fragment(url, param, value)
    if source == "fragment_raw":
        return set_raw_fragment(url, value)
    if source == "fragment_route":
        return set_fragment_param(url, param, value)
    return set_param(url, param, value)


_SOURCE_PHRASE = {"query": "query parameter '%s'", "fragment": "URL fragment '#%s='",
                  "fragment_raw": "URL fragment",
                  "fragment_route": "hash-route parameter '%s' (inside the fragment, never sent "
                                    "to the server)"}


def source_phrase(source: str, param: str) -> str:
    """Human wording for the injected source, for evidence lines. Pure."""
    fmt = _SOURCE_PHRASE.get(source, _SOURCE_PHRASE["query"])
    return fmt % param if "%s" in fmt else fmt



def is_evil_host(u: str) -> bool:
    try:
        return bool(re.match(r"^evilc[0-9a-z]+\.example$", urlparse(u).hostname or "", re.I))
    except Exception:
        return False


def classify(url: str, param: str, canary: str, sig: dict, source: str = "query") -> list:
    """PURE: given the collected runtime signals for one SOURCE, return the confirmed-family hits.
    sig = {executed, redirect, in_href, in_src, in_attr, in_text}. Most-severe first.

    `source` defaults to "query" so existing callers are unchanged; it selects how the probe URL is
    rebuilt and how the evidence names the injection point."""
    hits, s = [], sig or {}
    here = probe_url(url, param, canary, source)
    where_from = source_phrase(source, param)
    if s.get("executed"):
        hits.append({"family": "dom_xss", "param": param, "source": source,
                     "target": s.get("xss_target") or here,
                     "canary": canary, "evidence": "browser executed alert(%s) via %s (%s)" % (canary, where_from, s.get("xss_payload", "breakout"))})
    if (s.get("redirect") or "").strip():
        hits.append({"family": "open_redirect", "param": param, "source": source,
                     "target": s.get("redir_target") or here,
                     "canary": canary, "evidence": "navigation to attacker host from %s: %s" % (where_from, s["redirect"])})
    if (s.get("req_override") or "").strip():
        hits.append({"family": "request_url_override", "param": param, "source": source,
                     "target": s.get("reqov_target") or here,
                     "canary": canary, "evidence": "%s overrides a client-side fetch/XHR request target at runtime: %s" % (where_from, str(s["req_override"])[:120])})
    # ── Q-128: PRESENCE IN THE DOM IS NOT A DOM FLOW ──────────────────────────────────────────────
    #
    # The two families below fire on the canary merely BEING somewhere in the rendered page. That is
    # only evidence of a client-side sink if client-side code put it there. When the SERVER already
    # emitted it, the browser is showing us the application's own HTML and nothing was traced.
    #
    # MEASURED on a stock WordPress lab: 314 of 322 findings were these two families, and the canary
    # was in the RAW response every time -- WordPress echoes the request URI into its comment-reply
    # link:
    #
    #     <a id="cancel-comment-reply-link" href="/?p=1&#038;lang=domtr7168079a#respond">
    #
    # No JavaScript was involved. Every one of those 314 claimed CWE-79 at MEDIUM.
    #
    # THE THREE FAMILIES ABOVE ARE DELIBERATELY NOT GATED. `executed`, `redirect` and `req_override`
    # are BEHAVIOURS the browser performed -- a dialog fired, a navigation happened, a fetch went to
    # the attacker host. Server-side reflection that also executes is still DOM XSS, and suppressing
    # it here would trade a false-positive flood for a missed real bug, which is the wrong trade.
    # Q-129, the second half of the same rule and found by the same lab. A navigation that never
    # CONNECTED still leaves a rendered document: the browser's own error page, which displays the
    # requested URL -- and the canary is in that URL. MEASURED: three findings against
    # `https://wpreach/...` where the lab has no TLS listener (curl reports 000, no connection).
    # `server_reflected` was False because there was no server response to reflect anything, so the
    # gate above passed it. No page means no sink and no verdict, the same rule as Q-126's "an
    # oracle that cannot say what it sent cannot say what came back".
    #
    # `navigated` absent is treated as TRUE so every existing caller and fixture is unchanged; only
    # a producer that explicitly reports a failed navigation suppresses these.
    _loaded = s.get("navigated", True)
    if _loaded and not s.get("server_reflected"):
        if s.get("in_href") or s.get("in_src"):
            sink = s.get("in_href") or s.get("in_src")
            hits.append({"family": "dom_link_manipulation", "param": param, "source": source, "target": here,
                         "canary": canary, "evidence": "%s controls a link/resource URL at runtime (%s)" % (where_from, str(sink)[:120])})
        if s.get("in_attr") or s.get("in_text"):
            where = s.get("in_attr") or "DOM text"
            hits.append({"family": "dom_data_manipulation", "param": param, "source": source, "target": here,
                         "canary": canary, "evidence": "%s reflects into rendered DOM content at runtime (%s)" % (where_from, where)})
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


# NOTE (#125): a synchronous `trace_param` used to live here — a source-to-sink tracer that duplicated
# what `tools._run_dom_trace` implements asynchronously. It had no caller anywhere in the codebase, and a
# superseded duplicate sitting beside the live engine is a trap: it emits the same families, so calling
# the wrong one would look like it worked. The async path in tools.py is the engine; this module keeps the
# shared pure helpers (`classify`, `finding`, `set_param`, `params_of`) that it uses.


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
    src = hit.get("source") or "query"
    # Name the source in the title only when it is NOT the ordinary query parameter, so existing
    # query-sourced titles are unchanged while a fragment-sourced bug is never mistaken for one a
    # server-side retest could reproduce.
    where = "" if src == "query" else " (via the URL fragment)"
    return {
        "title": "%s in '%s'%s" % (_TITLE.get(fam, fam), hit["param"], where),
        "severity": ("medium" if (score or 0) >= 4 else "low"),
        "family": fam, "confidence": "confirmed", "target": hit["target"], "source": src,
        "cwe": _CWE.get(fam, "CWE-79"), "cvss_vector": vec, "cvss_score": score,
        "evidence": hit["evidence"],
        "success_oracle": "a unique per-request canary reached the DOM sink at runtime in a real browser "
                          "(source→sink confirmed live), with vendor-library-only reflections self-dismissed.",
        "reproduction_steps": ["Load %s in a browser" % hit["target"],
                               "Observe the attacker-controlled canary reach the DOM sink / execute"]
        + ([] if src == "query" else
           ["NOTE: the payload is in the URL FRAGMENT, which the browser never sends to the server — "
            "this cannot be reproduced from a server-side request log or by replaying the request."]),
        "impact": {"dom_xss": "Arbitrary script executes in the victim's browser (session/credential theft).",
                   "open_redirect": "The app redirects victims to an attacker-controlled host (phishing/token leak).",
                   "request_url_override": "Attacker controls the URL the page fetches at runtime (client-side request forgery): "
                                           "exfiltration to an attacker host, SSRF-style reach to internal endpoints, or token leakage via the outbound request.",
                   "dom_link_manipulation": "Attacker controls a link/resource URL the page requests or a victim clicks.",
                   "dom_data_manipulation": "Attacker controls rendered DOM content/attributes (UI redress, data spoofing)."}.get(fam, ""),
        "tags": ["dom", "runtime-canary", fam],
    }
