"""
Native out-of-band (OOB) interaction collaborator.

Blind vulnerabilities (blind SSRF, blind XXE, some deserialization/RCE) reflect
nothing in the HTTP response — the only proof is the server reaching out to an
attacker-controlled endpoint. Burp Collaborator / interactsh do this externally;
this is a built-in equivalent that rides the agent's own FastAPI app, so the
single-container platform can confirm blind bugs on targets that can reach it
(localhost/CI/internal, or any host when the operator exposes the agent and sets
BBH_OOB_BASE to its public URL).

Flow: a tool calls new_token(), injects probe_url(token) into the target, then
polls hits(token). The FastAPI catch-all /oob route (main.py) calls record() for
any inbound request, keyed by the token in the path or the leftmost Host label.
Correlation is in-process (same interpreter as the tools), so no external service
is required.

The token/URL/correlation logic here is pure and unit-tested; only the inbound
HTTP route and the tool transport touch the network.
"""
from __future__ import annotations

import os
import threading
import time

_LOCK = threading.Lock()
_HITS: dict = {}          # token -> [ {time, source_ip, method, path, host, ua} ]
_MAX_TOKENS = 500          # bound memory: evict oldest tokens past this


def enabled() -> bool:
    """Native OOB is active only when the operator has published a base URL."""
    return bool(base())


def base() -> str:
    return os.getenv("BBH_OOB_BASE", "").strip().rstrip("/")


def domain() -> str:
    """Optional wildcard-DNS domain for subdomain-form probes (DNS-triggerable)."""
    return os.getenv("BBH_OOB_DOMAIN", "").strip().strip(".")


def new_token() -> str:
    return os.urandom(6).hex()


def probe_url(token: str, base_url: str = "") -> str:
    """The URL to inject. Subdomain form (DNS-triggerable) when a wildcard domain
    is configured, else a path form on the agent's base URL."""
    dom = domain()
    if dom:
        return f"http://{token}.{dom}/"
    b = (base_url or base()).rstrip("/")
    return f"{b}/oob/{token}"


def token_from_request(path: str, host: str) -> str:
    """Extract the correlation token from an inbound OOB request.

    Path form: /oob/<token>[/...]. Subdomain form: <token>.<oob-domain>."""
    p = (path or "").lstrip("/")
    if p.startswith("oob/"):
        seg = p[len("oob/"):].split("/", 1)[0].split("?", 1)[0]
        if seg:
            return seg
    dom = domain()
    h = (host or "").split(":")[0]
    if dom and h.endswith("." + dom):
        return h[: -(len(dom) + 1)].split(".")[-1]
    return ""


def record(token: str, meta: dict) -> bool:
    """Log an inbound interaction for a token. Returns True if the token is known
    (i.e. one a tool registered) — unknown tokens are still logged so nothing is
    silently dropped, but callers can tell a correlated hit from noise."""
    if not token:
        return False
    with _LOCK:
        known = token in _HITS
        _HITS.setdefault(token, []).append({"time": time.time(), **meta})
        if len(_HITS) > _MAX_TOKENS:
            oldest = min(_HITS, key=lambda k: _HITS[k][0]["time"] if _HITS[k] else 0)
            _HITS.pop(oldest, None)
        return known


def register(token: str) -> None:
    """Pre-register a token so an interaction is recognized as correlated."""
    with _LOCK:
        _HITS.setdefault(token, [])


def hits(token: str) -> list:
    with _LOCK:
        return list(_HITS.get(token, []))


def clear(token: str) -> None:
    with _LOCK:
        _HITS.pop(token, None)


def oob_finding(url: str, param: str, probe: str, interactions: list) -> dict:
    first = interactions[0] if interactions else {}
    src = first.get("source_ip", "?")
    proto = first.get("method", "HTTP")
    return {
        "title": f"Blind SSRF confirmed via OOB interaction ('{param}')",
        "severity": "high", "target": url,
        "description": (f"After injecting an out-of-band probe into '{param}', the target's server made an inbound "
                        f"request to the collaborator ({proto} from {src}). Nothing was reflected in the response, so "
                        "this is a confirmed blind SSRF proven by the server-side callback."),
        "impact": ("Reach internal-only services and cloud metadata from the server's network position; escalate to "
                   "credential theft / internal pivoting."),
        "reproduction_steps": [f"Set '{param}' to the collaborator URL {probe}",
                               f"Observe an inbound {proto} interaction at the collaborator from {src}",
                               "Repoint the probe at 169.254.169.254 / internal hosts to assess impact"],
        "evidence": f"OOB interaction from {src} ({proto}) on {probe}",
        "cwe": "CWE-918", "family": "ssrf", "tags": ["ssrf", "blind", "oob"], "confidence": "confirmed",
    }
