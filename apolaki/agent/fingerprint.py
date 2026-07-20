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

# ── header value -> technology ───────────────────────────────────
_SERVER_VER = re.compile(r"([A-Za-z][\w\-]*)/([\d.]+)")


def _from_headers(h: dict) -> list:
    out = []
    server = h.get("server", "")
    if server:
        m = _SERVER_VER.search(server)
        out.append({"name": m.group(1) if m else server, "version": m.group(2) if m else "",
                    "source": "Server header", "category": "server"})
    xp = h.get("x-powered-by", "")
    if xp:
        m = _SERVER_VER.search(xp)
        out.append({"name": m.group(1) if m else xp, "version": m.group(2) if m else "",
                    "source": "X-Powered-By", "category": "language"})
    for hdr, name, cat in (
        ("x-generator", "", "cms"), ("x-drupal-cache", "Drupal", "cms"),
        ("x-drupal-dynamic-cache", "Drupal", "cms"), ("x-aspnet-version", "ASP.NET", "framework"),
        ("x-aspnetmvc-version", "ASP.NET MVC", "framework"), ("x-shopify-stage", "Shopify", "cms"),
        ("x-vercel-id", "Vercel", "hosting"), ("x-served-by", "", "cdn"),
        ("x-shopid", "Shopify", "cms"), ("x-turbo-charged-by", "LiteSpeed", "server")):
        v = h.get(hdr, "")
        if v:
            nm = name or v
            mm = _SERVER_VER.search(v)
            out.append({"name": nm if not mm else mm.group(1), "version": mm.group(2) if mm else "",
                        "source": hdr, "category": cat})
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
        if rx.search(set_cookie or ""):
            out.append({"name": name, "version": "", "source": "Set-Cookie", "category": cat})
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
                    "source": "meta generator", "category": "cms"})
    for rx, name, cat in _BODY_SIG:
        if rx.search(body or ""):
            out.append({"name": name, "version": "", "source": "HTML signature", "category": cat})
    for rx, name, cat in _JS_LIB:
        mm = rx.search(body or "")
        if mm:
            out.append({"name": name, "version": mm.group(1), "source": "script src", "category": cat})
    for m in list(_POWERED.finditer(body or ""))[:3]:
        out.append({"name": m.group(1).strip(), "version": "", "source": "powered-by text", "category": "generic"})
    return out


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


def fingerprint(headers: dict, set_cookie: str, body: str) -> list:
    """Return a deduped list of {name, version, source, category} technologies."""
    h = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
    techs = _from_headers(h) + _from_cookies(set_cookie or h.get("set-cookie", "")) + _from_body(body or "")
    return _dedup([t for t in techs if t.get("name")])


def version_disclosures(techs: list) -> list:
    """Techs that leak a precise version — worth a CVE lookup (low-sev finding)."""
    return [t for t in techs if t.get("version")]
