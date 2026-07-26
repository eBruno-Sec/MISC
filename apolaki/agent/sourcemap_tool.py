"""
Source-map discovery + analysis.

A JavaScript source map (`*.js.map`) often ships the ORIGINAL, pre-minification source
in its `sourcesContent`, plus the original file tree in `sources`. That is a goldmine:
hidden routes, internal API endpoints, feature flags, dev-only components, and hardcoded
secrets that the minified bundle hides. This module is pure: it builds candidate map
URLs, parses a fetched map, and analyses the reconstructed source. The scope-guarded
network fetch lives in tools._run_sourcemap; findings stay truth-first (secrets/flags are
leads until a human verifies them).
"""
from __future__ import annotations

import json
import re

# `//# sourceMappingURL=main.js.map` (or the older //@) at the end of a bundle.
_SM_URL = re.compile(r"//[#@]\s*sourceMappingURL=([^\s'\"]+)")
# Feature-flag shaped identifiers in reconstructed source.
_FLAG = re.compile(
    r"""(?xi)
    (?:feature[_-]?flags?|isEnabled|isFeatureEnabled|toggles?|launchdarkly|
       unleash|split[_-]?io|process\.env\.(?:FEATURE|FLAG|ENABLE)_[A-Z0-9_]+)
    """)
# Client-side route tables (Angular/React/Vue routers list paths as string literals).
_ROUTE = re.compile(r"""['"`](/[A-Za-z0-9_\-/:]{1,60})['"`]\s*[,:]?\s*(?:component|element|loadChildren|redirectTo|name)""")


def candidate_map_urls(js_url: str, body: str = "") -> list:
    """Map URLs to try for a JS bundle: an explicit sourceMappingURL comment (resolved
    against the bundle) first, then the conventional `<bundle>.map`."""
    out, seen = [], set()

    def add(u):
        if u and u not in seen:
            seen.add(u)
            out.append(u)

    m = _SM_URL.search(body or "")
    if m:
        ref = m.group(1).strip()
        if ref.startswith(("http://", "https://")):
            add(ref)
        elif ref.startswith("//"):
            add((js_url.split(":", 1)[0] or "https") + ":" + ref)
        elif ref.startswith("/"):
            mm = re.match(r"(https?://[^/]+)", js_url or "")
            if mm:
                add(mm.group(1) + ref)
        elif not ref.startswith("data:"):
            add(re.sub(r"/[^/]*$", "/" + ref, js_url))
    add((js_url or "") + ".map")
    return out


def parse(text: str) -> dict:
    """Parse a source-map JSON blob into {'sources': [...paths], 'content': str}.
    Returns empty on anything that is not a valid source map."""
    try:
        d = json.loads(text)
    except Exception:
        return {"sources": [], "content": ""}
    if not isinstance(d, dict) or "version" not in d or "mappings" not in d:
        return {"sources": [], "content": ""}
    sources = [s for s in (d.get("sources") or []) if isinstance(s, str)]
    contents = [c for c in (d.get("sourcesContent") or []) if isinstance(c, str)]
    return {"sources": sources, "content": "\n".join(contents)}


def _own_sources(sources: list) -> list:
    """The application's OWN source files — drop third-party/framework noise so the
    'hidden routes/files' list is the target's code, not node_modules."""
    out = []
    for s in sources or []:
        low = s.lower()
        # drop third-party/vendor code only — NOT the normal `webpack:///` app prefix,
        # which every application source also carries.
        if "node_modules" in low or "/vendor/" in low or "/bower_components/" in low:
            continue
        out.append(s)
    return out


def analyze(sm: dict) -> dict:
    """Mine a parsed source map. Reuses the codereview scanner for secrets / sinks /
    endpoints so results are consistent with the rest of Apolaki. Returns
    {'sources','routes','feature_flags','endpoints','secrets','comments'}."""
    import codereview as cr
    content = sm.get("content") or ""
    own = _own_sources(sm.get("sources") or [])
    routes = sorted({m.group(1) for m in _ROUTE.finditer(content)})
    flags = sorted({m.group(0) for m in _FLAG.finditer(content)})
    rev = cr.review(content, "source-map") if content else {"findings": [], "endpoints": []}
    return {
        "sources": own[:200],
        "routes": routes[:100],
        "feature_flags": flags[:60],
        "endpoints": (rev.get("endpoints") or [])[:200],
        "secrets": [f for f in (rev.get("findings") or []) if "secret" in (f.get("family", "") + f.get("title", "")).lower()][:40],
        "comments": [f for f in (rev.get("findings") or []) if "comment" in (f.get("title", "")).lower()][:40],
    }
