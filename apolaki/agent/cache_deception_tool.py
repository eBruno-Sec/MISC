"""Web Cache Deception engine (CWE-525), distilled from the OWASP WSTG / PortSwigger material in the
RedCyber corpus ("Path confusion: web cache deception"). Different from cache POISONING (unkeyed headers,
already covered): here the attacker lures a victim to a path-confused URL like `/account/nonexistent.css`.
The APP ignores the fake static suffix and serves the victim's PRIVATE `/account` page, while the CDN/cache
sees a `.css`/`.js` extension and caches the response under that public URL — so the attacker then fetches
the same URL unauthenticated and reads the victim's cached private data.

CONFIRMATION IS A THREE-WAY DIFFERENTIAL, FP-SAFE + NON-DESTRUCTIVE. We only ever cache the TESTER's OWN
page (self-inflicted), and confirm ONLY when an UNAUTHENTICATED fetch of the path-confused URL returns
tokens that are private to the authenticated page (present when logged in, absent when logged out). A target
with no cache simply returns the login page to the anon fetch -> no private token -> not confirmed.

Pure logic here (variants + private-token diff + cacheability + finding); the HTTP transport lives in tools.
"""
from __future__ import annotations

import re

# Static-looking suffixes a CDN commonly caches by extension, appended so the ORIGIN still routes to the
# base handler (path confusion) but the CACHE keys it as a cacheable static asset.
_EXTS = (".css", ".js", ".jpg", ".png", ".ico")


def deception_variants(url: str, token: str) -> list:
    """Path-confusion URLs for `url`, each carrying a unique random segment so we never collide with a real
    asset and each cache entry is ours alone. Covers the append, path-parameter, and encoded-slash forms."""
    base = url.split("?", 1)[0].split("#", 1)[0].rstrip("/")
    seg = "wcd%s" % token
    out = []
    for ext in _EXTS[:3]:
        out.append("%s/%s%s" % (base, seg, ext))          # /account/wcdXXXX.css  (classic append)
    out.append("%s;%s%s" % (base, seg, _EXTS[0]))          # /account;wcdXXXX.css  (path parameter)
    out.append("%s%%2f%s%s" % (base, seg, _EXTS[1]))       # /account%2fwcdXXXX.js (encoded slash)
    return out


_WORD = re.compile(r"[A-Za-z0-9_@.\-]{6,64}")
# generic chrome that differs between logged-in/out but is NOT sensitive user data — excluded from markers.
_STOP = {"logout", "sign-out", "signout", "content-length", "text/html"}


def private_tokens(authed_body: str, anon_body: str, limit: int = 40) -> list:
    """Tokens that appear in the AUTHENTICATED page but NOT in the anonymous page — the private signal
    (username, email, api tokens, CSRF value, order ids). If empty, the page is not auth-differentiated and
    web cache deception has nothing to leak, so the caller skips it."""
    anon = set(_WORD.findall(anon_body or ""))
    out, seen = [], set()
    for m in _WORD.findall(authed_body or ""):
        if m in anon or m.lower() in _STOP or m in seen:
            continue
        seen.add(m)
        out.append(m)
        if len(out) >= limit:
            break
    return out


def looks_cacheable(headers: dict) -> bool:
    """The response advertises itself as (or shows signs of being) cached under this URL."""
    h = {str(k).lower(): str(v).lower() for k, v in (headers or {}).items()}
    cc = h.get("cache-control", "")
    if "no-store" in cc or "private" in cc:
        return False
    if "public" in cc or re.search(r"max-age=([1-9]\d*)", cc):
        return True
    # explicit cache hit / age markers from a CDN
    return ("age" in h) or ("hit" in h.get("x-cache", "")) or ("hit" in h.get("cf-cache-status", "")) \
        or ("hit" in h.get("x-cache-status", ""))


def leaked_tokens(anon_variant_body: str, private: list) -> list:
    """Private tokens that showed up in the UNAUTHENTICATED fetch of the path-confused URL — the proof."""
    body = anon_variant_body or ""
    return [t for t in private if t in body][:5]


def finding(base_url: str, variant_url: str, leaked: list, cacheable: bool) -> dict:
    ev = ("An unauthenticated request to the path-confused URL returned data private to the authenticated "
          "page (e.g. %s). The origin served the private page for the fake static suffix and the cache "
          "stored it under the public URL." % ", ".join("'%s'" % x for x in leaked[:3]))
    return {
        "title": "Web cache deception — private page cached under a static-looking URL",
        "severity": "high", "family": "cache_deception", "confidence": "confirmed", "target": base_url,
        "cwe": "CWE-525", "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:N/A:N", "cvss_score": 6.8,
        "evidence": ev + ("" if cacheable else " (response cache headers were not explicit, but the anon fetch "
                          "still served the private body — a cache is present.)"),
        "success_oracle": ("an anonymous GET of %s returned tokens private to the authenticated page — the "
                           "victim's private data is retrievable from the cache without their session" % variant_url),
        "reproduction_steps": [
            "As the victim, load %s (a path-confused URL that the origin routes to the private page)." % variant_url,
            "The CDN/cache stores the private response under that public, static-looking URL.",
            "As an anonymous attacker, GET %s and read the victim's cached private data." % variant_url],
        "impact": ("An attacker who lures a logged-in victim to the crafted URL can then read that victim's "
                   "private page (account details, tokens, PII) straight from the shared cache."),
        "remediation": ("Make the cache key on the FULL normalized path and the content-type the origin "
                        "actually returned (not the URL extension); set Cache-Control: private/no-store on "
                        "authenticated responses; reject unknown static suffixes on dynamic routes."),
        "tags": ["cache", "web-cache-deception", "cwe-525"],
    }
