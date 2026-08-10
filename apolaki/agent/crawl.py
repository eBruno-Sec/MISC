"""
Authenticated recursive-crawl helpers (CHAD capability D).

The frontier-selection logic is factored out as a PURE function so the per-persona BFS is
unit-testable without a live target: given the URLs discovered at one depth, pick the next depth's
frontier — new, same-origin, non-asset links, bounded. The live fetching (authenticated GET as each
persona, SPA/XHR capture, session refresh) runs in the agent using this to choose what to visit next.
"""
from __future__ import annotations

import html
import re
from urllib.parse import urlparse

# Static assets carry no new authenticated surface — never spend a crawl budget on them.
_ASSET = re.compile(r"\.(?:png|jpe?g|gif|svg|ico|css|js|mjs|woff2?|ttf|eot|map|pdf|zip|gz|mp4|webm|webp|avif)(?:\?|#|$)", re.I)


def same_origin(u: str, base: str) -> bool:
    try:
        pu, pb = urlparse(u), urlparse(base)
    except Exception:
        return False
    return pu.scheme in ("http", "https") and bool(pu.netloc) and pu.netloc == pb.netloc


_FORM_RE = re.compile(r"<form\b[^>]*>(.*?)</form>", re.I | re.S)
_ACTION_RE = re.compile(r"""\baction\s*=\s*["']?([^"'\s>]+)""", re.I)
_METHOD_RE = re.compile(r"""\bmethod\s*=\s*["']?([a-zA-Z]+)""", re.I)
_FIELD_RE = re.compile(r"""<(?:input|textarea|select)\b[^>]*\bname\s*=\s*["']?([^"'\s>]+)""", re.I)
# Bounded on purpose: an unbounded [^>]* inside a repeated group is how a parser becomes a ReDoS target on
# hostile markup. 2000 chars is far past any real form control.
_TAG_RE = re.compile(r"<(?:input|textarea|select)\b[^>]{0,2000}?>", re.I)


def _tag_attr(tag: str, name: str) -> str:
    """One attribute off a single tag, quoted or bare. Entity-decoded, because a serialized blob parked in
    a value attribute arrives HTML-escaped (a:1:{s:4:&quot;x&quot;;}) and must be compared as its real bytes."""
    for pat in (r'\b%s\s*=\s*"([^"]*)"', r"\b%s\s*=\s*'([^']*)'", r"\b%s\s*=\s*([^\s>]+)"):
        m = re.search(pat % re.escape(name), tag, re.I)
        if m:
            return html.unescape(m.group(1))
    return ""


def extract_forms(html: str, base: str) -> list:
    """Parse HTML forms into {action(absolute), method, fields[]} — the authenticated crawl's form
    discovery (CHAD capability D). Deterministic, dependency-free (regex, not a live browser). An
    empty/missing action resolves to `base`. Fields are input/textarea/select names. Pure + testable."""
    from urllib.parse import urljoin
    out = []
    for m in _FORM_RE.finditer(html or ""):
        head = (html[m.start():m.start() + 400])
        inner = m.group(1) or ""
        am = _ACTION_RE.search(head)
        action = urljoin(base, am.group(1)) if am and am.group(1) else base
        mm = _METHOD_RE.search(head)
        method = (mm.group(1).upper() if mm else "GET")
        # `fields` stays a de-duplicated list of NAMES (unchanged for existing consumers). `inputs` adds
        # the default VALUE and type, which the name-only scan threw away — and a serialized object parked
        # in a hidden field is exactly a value: <input type=hidden name=prefs value="a:1:{...}">. Without
        # it, insecure_deser can never see the most common real-world carrier.
        fields, inputs = [], []
        for tm in _TAG_RE.finditer(inner):
            tag = tm.group(0)
            nm = _tag_attr(tag, "name")
            if not nm:
                continue
            if nm not in fields:
                fields.append(nm)
            inputs.append({"name": nm, "value": _tag_attr(tag, "value"),
                           "type": _tag_attr(tag, "type").lower()})
        out.append({"action": action, "method": method, "fields": fields, "inputs": inputs})
    return out


def bfs_frontier(candidates, base: str, seen, limit: int = 40) -> list:
    """The next-depth frontier: from `candidates`, keep URLs that are new (not in `seen`), same-origin
    as `base`, and not static assets — de-duplicated and capped at `limit`. Deterministic order (first
    occurrence) so a re-run visits the same frontier."""
    seen = set(seen or [])
    out, picked = [], set()
    for u in candidates or []:
        u = str(u)
        if u in seen or u in picked or not same_origin(u, base) or _ASSET.search(u):
            continue
        picked.add(u)
        out.append(u)
        if len(out) >= limit:
            break
    return out


# ── robots.txt / sitemap.xml: the two highest-yield free surface sources ──────────────────────────────
# A general scan never fetched either (they appeared only in a NOISE exclusion list, and in the Natas
# CTF solver). robots.txt is a list of paths the owner wants hidden -- admin panels, backups, staging
# consoles -- published by the owner. sitemap.xml is an enumerated index of the site. Reading them is
# passive, cheap, and standard practice for every mature scanner.
_ROBOTS_PATH = re.compile(r"(?im)^\s*(?:dis)?allow\s*:\s*(\S+)")
_ROBOTS_SITEMAP = re.compile(r"(?im)^\s*sitemap\s*:\s*(\S+)")
_SITEMAP_LOC = re.compile(r"(?is)<loc>\s*([^<\s]+)\s*</loc>")
_MAX_DOC = 2_000_000


def parse_robots(text: str, base: str, limit: int = 200) -> dict:
    """{'urls': [...], 'sitemaps': [...]} from robots.txt.

    BOTH Allow and Disallow are harvested. A Disallow is not an instruction we are obeying here -- it is
    the owner telling us where the interesting paths are, which is exactly the recon value. A wildcard
    pattern (`/admin/*`) is reduced to its literal prefix; a bare `/` is skipped because it names the
    whole site and adds nothing.
    """
    from urllib.parse import urljoin
    out, maps = [], []
    t = str(text or "")[:_MAX_DOC]
    for m in _ROBOTS_PATH.finditer(t):
        p = m.group(1).split("*")[0].split("$")[0].strip()
        if not p or p == "/":
            continue
        u = urljoin(base, p)
        if u.startswith(("http://", "https://")) and u not in out:
            out.append(u)
        if len(out) >= limit:
            break
    for m in _ROBOTS_SITEMAP.finditer(t):
        s = urljoin(base, m.group(1).strip())
        if s.startswith(("http://", "https://")) and s not in maps:
            maps.append(s)
    return {"urls": out, "sitemaps": maps}


def parse_sitemap(xml: str, base: str, limit: int = 500) -> dict:
    """{'urls': [...], 'sitemaps': [...]} from a sitemap or sitemap-index document.

    A <loc> inside <sitemapindex> points at another sitemap; inside <urlset> it is a page. Both appear
    as <loc>, so they are separated by suffix rather than by trusting the wrapper element, which lets a
    malformed document still yield useful URLs.
    """
    from urllib.parse import urljoin
    urls, maps = [], []
    t = str(xml or "")[:_MAX_DOC]
    for m in _SITEMAP_LOC.finditer(t):
        u = urljoin(base, html.unescape(m.group(1).strip()))
        if not u.startswith(("http://", "https://")):
            continue
        target = maps if u.lower().endswith((".xml", ".xml.gz")) else urls
        if u not in target:
            target.append(u)
        if len(urls) >= limit:
            break
    return {"urls": urls, "sitemaps": maps}
