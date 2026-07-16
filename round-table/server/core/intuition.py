"""
INTUITION engine — the tool's "gut feeling".

Between CONFIRMED (detectors) and generic advisory sits a hunter's intuition:
patterns that *smell* vulnerable even without proof. This engine mines the app's
JavaScript bundle for real (often unlinked) endpoints, then reasons over every
discovered endpoint/param/signal to emit low-confidence HUNCHES — each labelled
INFO / "Hunch" so it can never be mistaken for a confirmed finding — with a plain
explanation of *why* it caught the tool's eye and exact manual steps to test it.

Rule-based (always on) + optional AI hunches when a key is configured.
"""
from __future__ import annotations

import hashlib
import re
import ssl
import urllib.request
from typing import Any
from urllib.parse import urlparse

_CTX = ssl.create_default_context()
_CTX.check_hostname = False
_CTX.verify_mode = ssl.CERT_NONE


def _gid(*p):
    return "intu_" + hashlib.sha1("|".join(p).encode()).hexdigest()[:9]


def _hunch(*, key, title, surface, why, what, how, tags=None, payloads=None,
           tools=None, refs=None, confidence=30):
    return {
        "id": _gid(key, surface),
        "key": f"intuition-{key}",
        "title": f"Hunch: {title}",
        "category": "Intuition",
        "wstg": "",
        "severity": "INFO",
        "confidence": confidence,
        "confidence_label": "Hunch",
        "hunch": True,
        "surface": surface,
        "evidence": why,                       # the "why I flagged this"
        "what_to_test": what,
        "how_to_test": how,
        "payloads": payloads or [],
        "tools": tools or ["Burp Suite", "curl"],
        "curl_steps": [],
        "references": refs or [],
        "tags": ["intuition"] + (tags or []),
        "remediation": None,
    }


# ── mine endpoints/routes from the JS bundle (the "realization" source) ─────
def _fetch(url, timeout=8):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "RoundTable/2 intuition"})
        with urllib.request.urlopen(req, timeout=timeout, context=_CTX) as r:
            return r.status, r.read(4_000_000).decode("utf-8", "ignore")
    except Exception:
        return None, ""


def extract_js_endpoints(base: str) -> list[str]:
    base = base.rstrip("/")
    st, idx = _fetch(base)
    if not idx:
        return []
    scripts = re.findall(r'(?:src|href)="([^"]+\.js)"', idx)[:6]
    eps: set[str] = set()
    for s in scripts:
        url = s if s.startswith("http") else base + "/" + s.lstrip("/")
        _, js = _fetch(url)
        if not js:
            continue
        for m in re.findall(r'["\'`](/(?:rest|api)/[A-Za-z0-9_\-/{}:.]+)["\'`]', js):
            eps.add(m.split("{")[0].rstrip("/"))
        for m in re.findall(r'path\s*:\s*["\']([A-Za-z0-9_\-/]+)["\']', js):
            if m and m not in ("", "/"):
                eps.add("/#/" + m.lstrip("/"))
    # de-dupe, cap
    return sorted(eps)[:60]


# ── hunch rules: (regex over endpoint, type, title, why, what, steps, tags) ──
RULES = [
    (r"(?:^|/)(?:user|users|order|orders|basket|baskets|product|products|review|reviews|"
     r"feedback|complaint|card|address|wallet|memory|quantity)s?/?(?:\{?\w*id\}?|\d+)?",
     "idor", "IDOR / BOLA on object reference",
     "The endpoint names an object collection (often keyed by a numeric/predictable id). Object-level authorization is the most-missed control.",
     "Whether you can read/modify another user's object by changing the id.",
     ["Authenticate as user A, capture the request.",
      "Replay it as user B (or with no token) and change the id.",
      "Diff the responses; any cross-user read/write is IDOR/BOLA."],
     ["idor", "access-control"]),
    (r"(?:login|register|signup|reset|forgot|password|change-password|2fa|otp|totp|authentication)",
     "auth", "Authentication-flow weakness",
     "Auth endpoints attract user enumeration, reset-token/host poisoning, weak lockout, and security-question OSINT.",
     "User enumeration, password-reset poisoning, missing rate-limit, guessable security answers.",
     ["Compare responses/timing for valid vs invalid users (enumeration).",
      "Trigger a reset with a spoofed Host / X-Forwarded-Host and inspect the email link.",
      "Check for lockout after N attempts."],
     ["auth"]),
    (r"(?:upload|import|file|files|image|images|avatar|attachment|profileImage)",
     "upload", "File-upload abuse surface",
     "Upload/import endpoints often mishandle type/size, and image parsers open SVG-XSS, XXE, path-traversal, and image-SSRF.",
     "Extension/content-type bypass, oversized files, SVG with script, XXE via image metadata, traversal in filename.",
     ["Upload a benign file, then vary extension/content-type/size.",
      "Try an SVG containing <script>, and a filename with ../ traversal.",
      "If it processes images/URLs, test image-SSRF."],
     ["upload"]),
    (r"(?:coupon|discount|voucher|reward|deluxe|membership|premium|price|amount|total|balance|points|wallet|payment|checkout|deliver)",
     "logic", "Business-logic / price-trust surface",
     "Money/entitlement fields are where client-trusted values, negative/overflow quantities, and coupon abuse live — invisible to signature scanners.",
     "Negative or huge quantities, client-set prices, stacked/expired coupons, entitlement without payment.",
     ["Intercept the request and set price/quantity to negative, zero, or huge values.",
      "Replay an expired/known coupon; try stacking.",
      "Attempt to obtain a paid tier without a completed payment step."],
     ["business-logic"]),
    (r"(?:search|products/search|query|find|filter)",
     "injection", "Injection + reflected-XSS surface",
     "Search/query endpoints frequently build SQL/NoSQL strings and reflect input into responses.",
     "SQLi/NoSQLi via the query term, and reflected/stored XSS where the term is echoed.",
     ["Send a single quote / NoSQL operator and watch for errors or altered result sets.",
      "Inject a unique marker and check if it reflects unencoded."],
     ["sqli", "xss"]),
    (r"(?:redirect|url|goto|next|return|to|track|dest|continue|callback)",
     "redirect", "Open-redirect / SSRF surface",
     "Parameters that carry a URL tend to redirect or fetch server-side without validation.",
     "Open redirect (client-side) or SSRF (server fetches the URL).",
     ["Set the value to an external domain and follow the response.",
      "Point it at a Collaborator/OAST host and watch for a server-side callback."],
     ["redirect", "ssrf"]),
    (r"(?:admin|administration|config|configuration|debug|internal|actuator|metrics|api-docs|swagger|graphql|console|b2b)",
     "exposure", "Sensitive/admin surface exposure",
     "Admin, config, debug, and machine interfaces are often reachable without proper authorization.",
     "Unauthenticated access to admin/config/debug data or functionality.",
     ["Request the endpoint unauthenticated and as a low-priv user.",
      "For /b2b or XML endpoints, test XXE; for GraphQL, test introspection."],
     ["access-control", "config"]),
    (r"(?:token|jwt|refresh|session|whoami|authentication-details)",
     "jwt", "Token / session handling surface",
     "Endpoints that mint or read tokens invite alg-confusion, weak secrets, and session-fixation.",
     "JWT alg:none / RSA→HMAC confusion, weak signing secret, non-expiring or fixable sessions.",
     ["Decode the token; try re-signing with alg:none.",
      "Attempt HS256 signed with the app's public key (RSA confusion)."],
     ["jwt", "auth"]),
]


def _reflects(recon: dict) -> bool:
    http = recon.get("http") or {}
    return bool(http.get("ok"))  # placeholder; real reflection tested in detectors


def build_intuition(recon: dict, config: dict = None) -> list[dict]:
    out: list[dict] = []
    seen: set[str] = set()

    # candidate surfaces: live-host bases, discovered paths, and JS-mined endpoints
    bases = [(h.get("url") or "").rstrip("/") for h in (recon.get("live_hosts") or []) if h.get("url")]
    endpoints: list[str] = []
    for base in bases[:2]:
        for ep in extract_js_endpoints(base):
            endpoints.append(base + ep if ep.startswith("/") else ep)
        recon.setdefault("js_endpoints", []).extend(extract_js_endpoints(base))
    for b, paths in (recon.get("dir_bust") or {}).items():
        for p in paths or []:
            u = p.get("url") if isinstance(p, dict) else str(p)
            if u:
                endpoints.append(u)

    for ep in endpoints:
        path = urlparse(ep).path.lower() + "?" + (urlparse(ep).query.lower())
        for rx, typ, title, why, what, how, tags in RULES:
            if re.search(rx, path):
                key = f"{typ}"
                dedupe = typ + "|" + (urlparse(ep).path or "/").lower()
                if dedupe in seen:
                    continue
                seen.add(dedupe)
                out.append(_hunch(key=key, title=title, surface=ep, why=why + f"  (matched pattern in {urlparse(ep).path})",
                                  what=what, how=how, tags=tags))
                break  # one hunch per endpoint

    # signal-based hunches (not endpoint-specific)
    http = recon.get("http") or {}
    cookie = (http.get("headers") or {}).get("set-cookie", "") if http.get("ok") else ""
    if cookie and "samesite" not in cookie.lower():
        base = (bases[0] if bases else f"https://{recon.get('target','')}")
        out.append(_hunch(key="csrf", title="CSRF likely on state-changing actions",
                          surface=base, confidence=28,
                          why="A session cookie is set without SameSite; cross-site state-changing requests may ride the session.",
                          what="CSRF on any POST/PUT/DELETE that lacks an anti-CSRF token.",
                          how=["Build an attacker-page auto-submitting form to a state-changing endpoint.",
                               "Confirm the action executes using only the victim's cookie."],
                          tags=["csrf"]))

    # optional AI hunches
    if config and __import__("os").getenv("AI_API_KEY"):
        try:
            out.extend(_ai_hunches(recon, endpoints[:30]))
        except Exception:
            pass

    # cap + return (INFO severity → these sort below real findings)
    return out[:30]


def _ai_hunches(recon: dict, endpoints: list[str]) -> list[dict]:
    import asyncio
    import json as _json

    from . import ai_client

    target = recon.get("target", "")
    live = [h.get("url") for h in recon.get("live_hosts", [])[:8] if h.get("url")]
    prompt = (
        "You are a veteran bug-bounty hunter reviewing recon for an AUTHORIZED target. "
        "Based ONLY on the endpoints/signals below, list up to 6 ENDPOINTS that intuitively "
        "look vulnerable, each with the vuln class you suspect, one sentence WHY, and 2-3 manual "
        "test steps. Do not claim anything is confirmed. Reply ONLY as compact JSON:\n"
        '{"hunches":[{"endpoint":"...","suspect":"IDOR|SQLi|XSS|SSRF|logic|auth|upload|xxe|jwt",'
        '"why":"...","steps":["...","..."]}]}\n\n'
        f"TARGET: {target}\nLIVE: {_json.dumps(live)}\nENDPOINTS: {_json.dumps(endpoints)}"
    )
    try:
        txt = asyncio.run(ai_client.complete(prompt, max_tokens=800,
                          system="Return only valid JSON. These are speculative hunches, never claims of confirmation."))
    except Exception:
        return []
    if not txt:
        return []
    m = re.search(r"\{.*\}", txt, re.DOTALL)
    if not m:
        return []
    try:
        data = _json.loads(m.group(0))
    except Exception:
        return []
    res = []
    for h in (data.get("hunches") or [])[:6]:
        ep = str(h.get("endpoint", "")).strip()
        if not ep:
            continue
        res.append(_hunch(key="ai-" + str(h.get("suspect", "lead")).lower(),
                          title=f"AI hunch — possible {h.get('suspect','issue')}",
                          surface=ep, confidence=32,
                          why="AI reasoning: " + str(h.get("why", ""))[:220],
                          what=f"Possible {h.get('suspect','vulnerability')} at this endpoint (speculative).",
                          how=[str(s) for s in (h.get("steps") or [])][:4] or ["Test manually per the suspected class."],
                          tags=["ai"]))
    return res
