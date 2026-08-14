"""
Tech-stack fingerprinting from a single HTTP response.

From Bug Bounty Bootcamp (Li, Ch 5). Identifies server software/versions,
languages, frameworks, and CMSs from response headers, Set-Cookie names, and
HTML/JS signatures — binary-free (a native complement to whatweb, which needs a
binary). The result feeds the guidance engine (tech -> targeted tests) and flags
precise version banners as a low-severity disclosure with a CVE-lookup pointer.

Pure/deterministic; unit-tested. tools._run_fingerprint does the one GET.
"""
from __future__ import annotations

import re
from urllib.parse import urlparse

# ── header value -> technology ───────────────────────────────────
_SERVER_VER = re.compile(r"([A-Za-z][\w\-]*)/([\d.]+)")

# Hoisted out of _from_headers so the admissible-product set below can be DERIVED from the same
# table the detector uses. Two hand-maintained lists of the same products is how a gate drifts out
# of step with its detector.
_HEADER_TECH = (
    ("x-generator", "", "cms"), ("x-drupal-cache", "Drupal", "cms"),
    ("x-drupal-dynamic-cache", "Drupal", "cms"), ("x-aspnet-version", "ASP.NET", "framework"),
    ("x-aspnetmvc-version", "ASP.NET MVC", "framework"), ("x-shopify-stage", "Shopify", "cms"),
    ("x-vercel-id", "Vercel", "hosting"), ("x-served-by", "", "cdn"),
    ("x-shopid", "Shopify", "cms"), ("x-turbo-charged-by", "LiteSpeed", "server"),
)


def _hdr_display(hdr: str) -> str:
    """`x-powered-by` -> `X-Powered-By`, so recorded evidence quotes the header the way an operator
    will see it in a proxy log."""
    return "-".join(p.capitalize() for p in str(hdr or "").split("-"))


def _from_headers(h: dict) -> list:
    out = []
    server = h.get("server", "")
    if server:
        m = _SERVER_VER.search(server)
        out.append({"name": m.group(1) if m else server, "version": m.group(2) if m else "",
                    "source": "Server header", "category": "server",
                    "evidence": "Server: " + server})
    xp = h.get("x-powered-by", "")
    if xp:
        m = _SERVER_VER.search(xp)
        out.append({"name": m.group(1) if m else xp, "version": m.group(2) if m else "",
                    "source": "X-Powered-By", "category": "language",
                    "evidence": "X-Powered-By: " + xp})
    for hdr, name, cat in _HEADER_TECH:
        v = h.get(hdr, "")
        if v:
            nm = name or v
            mm = _SERVER_VER.search(v)
            out.append({"name": nm if not mm else mm.group(1), "version": mm.group(2) if mm else "",
                        "source": hdr, "category": cat,
                        "evidence": "%s: %s" % (_hdr_display(hdr), v)})
    return out


# ── Set-Cookie name -> technology ────────────────────────────────
_COOKIE_TECH = [
    (re.compile(r"\bPHPSESSID\b", re.I), "PHP", "language"),
    (re.compile(r"\bJSESSIONID\b", re.I), "Java/JSP", "language"),
    (re.compile(r"ASP\.NET_SessionId|\.ASPXAUTH", re.I), "ASP.NET", "framework"),
    (re.compile(r"\blaravel_session\b|XSRF-TOKEN", re.I), "Laravel", "framework"),
    (re.compile(r"\bconnect\.sid\b", re.I), "Express/Node.js", "framework"),
    (re.compile(r"\bcsrftoken\b|\bsessionid\b.*django", re.I), "Django", "framework"),
    (re.compile(r"\b_rails_session\b|\b_session_id\b", re.I), "Ruby on Rails", "framework"),
    (re.compile(r"wordpress_|wp-settings|wordpress_logged_in", re.I), "WordPress", "cms"),
    (re.compile(r"\bci_session\b", re.I), "CodeIgniter", "framework"),
]


def _from_cookies(set_cookie: str) -> list:
    out = []
    for rx, name, cat in _COOKIE_TECH:
        m = rx.search(set_cookie or "")
        if m:
            # ONLY the matched cookie NAME goes into evidence. The header also carries the cookie
            # VALUE, which on a Set-Cookie is a live session token -- evidence is quoted into
            # reports and stored across missions, so it must never carry one.
            out.append({"name": name, "version": "", "source": "Set-Cookie", "category": cat,
                        "evidence": "Set-Cookie: " + m.group(0)})
    return out


# ── HTML / JS body signatures ────────────────────────────────────
_META_GEN = re.compile(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', re.I)
_POWERED = re.compile(r"(?:powered by|built with|running)\s+([A-Za-z][\w .\-]{2,30})", re.I)
_JS_LIB = [
    (re.compile(r"jquery[-.](\d+\.\d+(?:\.\d+)?)", re.I), "jQuery", "js-lib"),
    (re.compile(r"bootstrap[-.](\d+\.\d+(?:\.\d+)?)", re.I), "Bootstrap", "js-lib"),
    (re.compile(r"angular[.-](\d+\.\d+(?:\.\d+)?)", re.I), "AngularJS", "js-lib"),
    (re.compile(r"vue(?:@|[.-])(\d+\.\d+(?:\.\d+)?)", re.I), "Vue.js", "js-lib"),
    (re.compile(r"react(?:-dom)?[.@-](\d+\.\d+(?:\.\d+)?)", re.I), "React", "js-lib"),
]
_BODY_SIG = [
    (re.compile(r"wp-content|wp-includes|/wp-json", re.I), "WordPress", "cms"),
    (re.compile(r"Drupal\.settings|/sites/(?:all|default)/", re.I), "Drupal", "cms"),
    (re.compile(r"/media/jui/|Joomla!|/templates/system/", re.I), "Joomla", "cms"),
    (re.compile(r"__NEXT_DATA__|/_next/static", re.I), "Next.js", "framework"),
    (re.compile(r"__NUXT__|/_nuxt/", re.I), "Nuxt.js", "framework"),
    (re.compile(r"ng-version=|ng-app\b", re.I), "Angular", "framework"),
    (re.compile(r"data-reactroot|react(?:-dom)?\.production", re.I), "React", "js-lib"),
    (re.compile(r"csrf-param.+authenticity_token", re.I | re.S), "Ruby on Rails", "framework"),
    (re.compile(r"cdn\.shopify\.com|Shopify\.theme", re.I), "Shopify", "cms"),
    (re.compile(r"static\.wixstatic\.com|X-Wix-", re.I), "Wix", "cms"),
]


def _from_body(body: str) -> list:
    out = []
    m = _META_GEN.search(body or "")
    if m:
        gen = m.group(1)
        vm = _SERVER_VER.search(gen) or re.search(r"([A-Za-z][\w ]+?)\s+([\d.]+)", gen)
        out.append({"name": vm.group(1).strip() if vm else gen, "version": vm.group(2) if vm else "",
                    "source": "meta generator", "category": "cms",
                    "evidence": '<meta name="generator" content="%s">' % gen[:120]})
    for rx, name, cat in _BODY_SIG:
        mm = rx.search(body or "")
        if mm:
            out.append({"name": name, "version": "", "source": "HTML signature", "category": cat,
                        "evidence": mm.group(0)[:120]})
    for rx, name, cat in _JS_LIB:
        mm = rx.search(body or "")
        if mm:
            out.append({"name": name, "version": mm.group(1), "source": "script src", "category": cat,
                        "evidence": mm.group(0)[:120]})
    for m in list(_POWERED.finditer(body or ""))[:3]:
        out.append({"name": m.group(1).strip(), "version": "", "source": "powered-by text",
                    "category": "generic", "evidence": m.group(0)[:120]})
    return out


# The four keys `fingerprint()` has always returned. Evidence is computed at the point of match
# (above) for the FACT path, and stripped here so the DISPLAY path -- `live_hosts[i]["tech"]`, the
# report's delta section, `version_disclosures` -- keeps a byte-identical shape.
_PUBLIC_KEYS = ("name", "version", "source", "category")


def _dedup(techs: list) -> list:
    # names that appear with a version anywhere — drop their versionless dupes
    versioned = {t["name"].lower() for t in techs if t.get("version")}
    seen, out = set(), []
    for t in techs:
        name = t["name"].lower()
        if not t.get("version") and name in versioned:
            continue
        key = (name, t.get("version", ""))
        if key in seen:
            continue
        seen.add(key)
        out.append(t)
    return out


def detect(headers: dict, set_cookie: str, body: str) -> list:
    """Every detection with its EVIDENCE — the byte that proved it. Internal; `fingerprint()` is the
    stable four-key public shape and `tech_facts()` is the persistable one."""
    h = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
    techs = _from_headers(h) + _from_cookies(set_cookie or h.get("set-cookie", "")) + _from_body(body or "")
    return _dedup([t for t in techs if t.get("name")])


def public_view(records: list) -> list:
    """`detect()` records projected onto the four keys `fingerprint()` has always returned. Exposed
    so a caller that needs BOTH the display list and the evidence-carrying records can run the
    detection once, without a second copy of the key tuple drifting out of step with this one."""
    return [{k: t.get(k, "") for k in _PUBLIC_KEYS} for t in (records or [])]


def fingerprint(headers: dict, set_cookie: str, body: str) -> list:
    """Return a deduped list of {name, version, source, category} technologies."""
    return public_view(detect(headers, set_cookie, body))


def version_disclosures(techs: list) -> list:
    """Techs that leak a precise version — worth a CVE lookup (low-sev finding)."""
    return [t for t in techs if t.get("version")]


# ══════════════════════════════════════════════════════════════════════════════════════════════
# Q-021B — from a display string to a persistable TechnologyFact
# ══════════════════════════════════════════════════════════════════════════════════════════════
# The version was computed here and dropped one line later in tools._run_fingerprint, which kept
# `[t["name"] for t in techs]`. Everything below exists so it survives instead — WITH the evidence
# that proved it, an honest statement of how sure we are, and a refusal path that is recorded
# rather than silent.
#
# DETECTION IS NEVER A VULNERABILITY. A fact here is an observation, and `dependency_intel`'s
# CONFIRMED/HIGH/LOW ladder (with CVE_ELIGIBLE excluding LOW) decides what may be done with it.

#: Detection source -> the detector that produced it, so a rejection can name its own author.
_DETECTOR = {
    "Server header": "fingerprint.headers", "X-Powered-By": "fingerprint.headers",
    "Set-Cookie": "fingerprint.cookies", "meta generator": "fingerprint.body.meta",
    "HTML signature": "fingerprint.body.signature", "script src": "fingerprint.body.script",
    "powered-by text": "fingerprint.body.prose",
}

#: Sources that are FREE PROSE rather than a structured field. `powered by X` is the weakest signal
#: the detector has, and it is the one that produced every measured garbage name, so X must be a
#: product one of the detection tables already knows. This also removes the need for a separate
#: "was this truncated at the regex bound?" check: a truncated fragment is never a known product.
_FREE_TEXT_SOURCES = frozenset({"powered-by text"})

_MAX_NAME_LEN = 40
_MAX_NAME_TOKENS = 3          # "Ruby on Rails" is the longest real product name any table emits

#: A leading article/preposition/pronoun is the signature of a captured sentence, not a product.
_STOPWORD_START = frozenset({
    "a", "an", "the", "in", "on", "at", "by", "with", "from", "our", "your", "their", "this",
    "that", "these", "those", "it", "its", "is", "are", "was", "were", "be", "and", "or", "for",
    "to", "of", "as", "we", "you", "i", "they", "he", "she", "not", "no", "all", "some", "more",
    "up", "out", "over", "under", "via", "using", "used", "just", "only", "now", "here", "there",
})

#: Product identities: letters/digits in runs, joined by a single space, dot, dash, underscore,
#: slash or plus. Admits nginx, PHP, ASP.NET, Microsoft-IIS, Express/Node.js, Next.js, Ruby on
#: Rails; refuses anything with a comma, a trailing separator, or a leading digit.
_NAME_SHAPE = re.compile(r"^[A-Za-z][A-Za-z0-9]*(?:[ ._/+-][A-Za-z0-9]+)*$")


def _known_products() -> frozenset:
    """The product names the detection tables themselves can emit, plus the servers/languages the
    `Server:`/`X-Powered-By` regex yields. DERIVED from the tables above so it cannot drift."""
    names = {n for _, n, _ in _COOKIE_TECH} | {n for _, n, _ in _JS_LIB} | {n for _, n, _ in _BODY_SIG}
    names |= {n for _, n, _ in _HEADER_TECH if n}
    # Products no table names because the header regex extracts them from a version banner.
    names |= {"Apache", "nginx", "openresty", "IIS", "Microsoft-IIS", "Tomcat", "Jetty", "Caddy",
              "gunicorn", "Werkzeug", "Kestrel", "Envoy", "Traefik", "HAProxy", "Varnish",
              "cloudflare", "LiteSpeed", "PHP", "Python", "Perl", "Node.js"}
    return frozenset(n.lower() for n in names)


_KNOWN_PRODUCTS = _known_products()


def name_rejection(name, source="") -> str:
    """Why this detected string may NOT be persisted as a product identity — "" when it may.

    Returns a REASON rather than a bool on purpose: a refusal that cannot say why is the same
    invisible drop this ticket exists to remove.
    """
    n = str(name or "").strip()
    src = str(source or "").strip()
    if not n:
        return "empty"
    if len(n) > _MAX_NAME_LEN:
        return "too_long"
    if n.endswith("."):
        # `nothing on.` / `in safety mode.` — sentence punctuation, never a product name. Note a
        # trailing dot is distinct from an interior one: `Next.js` and `ASP.NET` are admitted.
        return "trailing_sentence_punctuation"
    toks = n.split()
    if toks[0].lower() in _STOPWORD_START:
        return "prose_leading_stopword"
    if len(toks) > _MAX_NAME_TOKENS:
        return "too_many_tokens"
    if not _NAME_SHAPE.match(n):
        return "bad_shape"
    if src in _FREE_TEXT_SOURCES and n.lower() not in _KNOWN_PRODUCTS:
        return "prose_not_a_known_product"
    return ""


def tech_facts(headers: dict, set_cookie: str, body: str, *, url: str = "",
               authenticated: bool = False, host: str = "", now=None, techs=None):
    """(facts, rejected) — detections as persistable TechnologyFacts, plus every refusal with a
    reason and the detector that produced it.

    `techs` lets a caller that already ran `detect()` reuse it instead of paying for a second pass.
    """
    import dependency_intel as _di
    records = techs if techs is not None else detect(headers, set_cookie, body)
    h = host or (urlparse(url).netloc if url else "")
    facts, rejected = [], []
    for t in records:
        name, src = t.get("name", ""), t.get("source", "")
        detector = _DETECTOR.get(src, "fingerprint.headers" if src.startswith("x-") else "fingerprint")
        why = name_rejection(name, src)
        if why:
            rejected.append({"name": str(name)[:120], "source": src, "detector": detector,
                             "reason": why, "location": url, "host": h,
                             "evidence": str(t.get("evidence", ""))[:200]})
            continue
        facts.append(_di.make_tech_fact(
            name, version=t.get("version", ""), source=src, detector=detector,
            category=t.get("category", ""), evidence=t.get("evidence", ""),
            location=url, host=h, authenticated=authenticated, now=now))
    return _di.merge_tech_facts(facts), rejected


#: Bound on the recorded refusals, same discipline as tools._swallow — a pathological body must not
#: grow engagement state without limit.
MAX_REJECTIONS = 200


def record_facts(recon: dict, url: str, headers: dict, set_cookie: str, body: str, *,
                 authenticated: bool = False, now=None, techs=None):
    """PERSIST the technology facts for one response into `recon`. Returns (facts, rejected).

    This is the step that was missing. It mutates `recon` rather than returning only — a return
    value is precisely what `_run_fingerprint` threw away. `recon["technology"]` accumulates facts
    deduped by IDENTITY (host + vendor + product + component), so re-fingerprinting a host extends
    `last_seen` instead of appending a duplicate; `recon["technology_rejected"]` accumulates the
    refusals so a real zero stays distinguishable from a detector that quietly dropped everything.

    `recon["live_hosts"][i]["tech"]` is deliberately NOT touched: that display list is the caller's
    business and the report's delta section reads its exact current shape.
    """
    import dependency_intel as _di
    facts, rejected = tech_facts(headers, set_cookie, body, url=url, authenticated=authenticated,
                                 now=now, techs=techs)
    recon["technology"] = _di.merge_tech_facts(list(recon.get("technology") or []) + facts)
    seen = {(r.get("name"), r.get("source"), r.get("reason"))
            for r in (recon.get("technology_rejected") or [])}
    out = list(recon.get("technology_rejected") or [])
    for r in rejected:
        k = (r["name"], r["source"], r["reason"])
        if k in seen or len(out) >= MAX_REJECTIONS:
            continue
        seen.add(k)
        out.append(r)
    recon["technology_rejected"] = out
    return facts, rejected
