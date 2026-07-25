"""Safe-recon planning (pure, no I/O, no Temporal).

Separated from the activity so the scope-fencing and probe planning are
unit-testable without a worker, a target, or temporalio. The activity
(recon_activities.py) performs the actual HTTP and evidence capture.
"""

from __future__ import annotations

from urllib.parse import urlparse

from policy.scope_firewall import ScopeFirewall

# A small, read-only (R1) probe set. GET-only; presence-confirming, never
# mutating. The IDOR module establishes the login/basket flow directly in M4;
# recon's job is to prove safe, scope-fenced enumeration and record endpoints.
DEFAULT_PROBE_PATHS: list[str] = [
    "/",
    "/rest/products/search?q=",
    "/api/Products",
    "/api/Users",
    "/rest/user/whoami",
    "/rest/user/login",
    "/rest/basket/1",
]


def derive_base_url(targets: list[dict], scheme_default: str = "http") -> str | None:
    """Pick the first included target and build a concrete base URL. A bare
    host:port with no scheme defaults to http (lab targets like juice-shop:3000)."""
    for t in targets:
        if t.get("disposition", "include") != "include":
            continue
        value = (t.get("value") or "").strip()
        if not value:
            continue
        if "://" in value:
            return value.rstrip("/")
        return f"{scheme_default}://{value}".rstrip("/")
    return None


def plan_probes(base_url: str, probe_paths: list[str], firewall: ScopeFirewall) -> list[str]:
    """Return the absolute URLs that are in scope. Every URL is scope-validated;
    out-of-scope probes are dropped (fail-closed)."""
    host_port = urlparse(base_url).netloc
    urls: list[str] = []
    for path in probe_paths:
        url = base_url + path
        # Scope-check both the concrete URL and its host:port authority.
        if firewall.validate(url).allowed or firewall.validate(host_port).allowed:
            urls.append(url)
    return urls


def endpoint_from_url(url: str) -> tuple[str, str]:
    """(host, path_template) for an observed endpoint."""
    p = urlparse(url)
    return p.netloc, (p.path or "/")
