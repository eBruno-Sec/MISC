"""General parameter discovery (arjun-style, target-derived): many injection points live on parameters
that are never linked — an app reads `?redirect=` or `?url=` that no crawl edge exposes, so the reflected/
DOM/request-override probes never test them. Two general, non-lab-specific sources of candidate names:

  1. JS SOURCE harvest — the client code tells us which params it reads: searchParams.get('x'),
     getParameterByName('x'), params['x'], a `[?&]x=` literal. These are the exact source params for
     DOM-XSS / client-side request-forgery, and they often do NOT reflect in the HTML.
  2. A framework-level WORDLIST of common reflected/effective param names, confirmed by a single BATCHED
     reflection probe (one request carries a unique canary per name; whichever canaries come back name a
     live reflecting param).

Pure logic here (name extraction + probe-URL construction + reflection read); the HTTP lives in tools."""
from __future__ import annotations

import re
from urllib.parse import urlparse, urlunparse, parse_qsl, urlencode

# common param names an app reads for reflection / redirect / template / client-side fetch. A TECHNIQUE
# wordlist (documented, cross-target), unioned with target-harvested names — never a lab's answer key.
PARAM_WORDLIST = (
    "q", "s", "search", "query", "searchTerm", "searchTerms", "keyword", "term", "id", "page",
    "category", "name", "message", "msg", "error", "redirect", "redirectUrl", "returnUrl", "return",
    "url", "next", "goto", "dest", "destination", "ref", "referrer", "callback", "lang", "view",
    "tab", "sort", "filter", "type", "mode", "content", "text", "title", "user", "username",
    "email", "comment", "postId", "productId", "path", "file", "endpoint", "api", "src", "to",
)

# JS patterns that reveal a param the CLIENT reads (the real DOM-XSS / request-override source params).
# The generic `.get/.has('name')` catches URLSearchParams aliased to a short var (p.get('redirect')); a few
# non-param names it also matches (map/store .get) are harmless — every candidate is gated by a cheap
# reflection probe before any expensive render.
_JS_PARAM_PATTERNS = (
    r"""getParameterByName\(\s*['"]([A-Za-z_][\w-]{0,39})['"]""",
    r"""(?:getQueryParam|getParam|param|qs)\(\s*['"]([A-Za-z_][\w-]{0,39})['"]""",
    r"""\.(?:get|getAll|has)\(\s*['"]([A-Za-z_][\w-]{0,39})['"]""",
    r"""params\[\s*['"]([A-Za-z_][\w-]{0,39})['"]\s*\]""",
    r"""[?&]([A-Za-z_][\w-]{0,39})=""",
)


def harvest_js_params(js_text: str, cap: int = 20) -> list:
    """Extract candidate parameter names the client-side code reads from the URL. Pure + bounded."""
    js = js_text or ""
    out, seen = [], set()
    for pat in _JS_PARAM_PATTERNS:
        for m in re.finditer(pat, js):
            n = m.group(1)
            low = n.lower()
            if low in seen or low in ("http", "https", "www"):
                continue
            seen.add(low); out.append(n)
            if len(out) >= cap:
                return out
    return out


def _token(i: int) -> str:
    # a canary unlikely to occur naturally; the index keeps each param's token unique
    return "zqp%03dqz" % i


def probe_url(url: str, names) -> tuple:
    """Build ONE probe URL that assigns a unique canary to each candidate param (batched discovery), and
    the {name: token} map. Existing query params are preserved; candidate names are added/overwritten."""
    p = urlparse(url)
    existing = [(k, v) for k, v in parse_qsl(p.query, keep_blank_values=True)]
    tokens, cand = {}, []
    for i, n in enumerate(list(dict.fromkeys(names))):
        t = _token(i)
        tokens[n] = t
        cand.append((n, t))
    have = {k for k, _ in existing}
    merged = existing + [(n, t) for n, t in cand if n not in have]
    return urlunparse(p._replace(query=urlencode(merged, doseq=True))), tokens


def reflected(body: str, tokens: dict) -> list:
    """Which candidate params' canaries came back in the response — those are live reflecting params."""
    b = body or ""
    return [n for n, t in (tokens or {}).items() if t in b]


def discover(url: str, js_sources=None, body=None, wordlist=None, cap: int = 24) -> dict:
    """Combine the two general sources into a candidate list + the reflection probe plan. Pure: the caller
    fetches probe_plan['probe_url'] and calls reflected(resp, probe_plan['tokens']).
    Returns {existing, js_params, wordlist, candidates, probe}."""
    existing = [k for k, _ in parse_qsl(urlparse(url).query, keep_blank_values=True) if k]
    js_params = []
    for src in (js_sources or []):
        for n in harvest_js_params(src):
            if n not in js_params:
                js_params.append(n)
    if body:
        for n in harvest_js_params(body):
            if n not in js_params:
                js_params.append(n)
    wl = list(wordlist or PARAM_WORDLIST)
    # candidate order: existing first, then JS-harvested (precise, target-derived), then wordlist
    candidates, seen = [], set()
    for n in existing + js_params + wl:
        if n and n.lower() not in seen:
            seen.add(n.lower()); candidates.append(n)
        if len(candidates) >= cap:
            break
    pu, tokens = probe_url(url, [c for c in candidates if c not in existing])
    return {"existing": existing, "js_params": js_params, "candidates": candidates,
            "probe": {"probe_url": pu, "tokens": tokens}}
