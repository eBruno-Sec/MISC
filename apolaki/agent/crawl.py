"""
Authenticated recursive-crawl helpers (CHAD capability D).

The frontier-selection logic is factored out as a PURE function so the per-persona BFS is
unit-testable without a live target: given the URLs discovered at one depth, pick the next depth's
frontier — new, same-origin, non-asset links, bounded. The live fetching (authenticated GET as each
persona, SPA/XHR capture, session refresh) runs in the agent using this to choose what to visit next.
"""
from __future__ import annotations

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
        fields = []
        for fm in _FIELD_RE.finditer(inner):
            if fm.group(1) not in fields:
                fields.append(fm.group(1))
        out.append({"action": action, "method": method, "fields": fields})
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
