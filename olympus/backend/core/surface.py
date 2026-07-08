"""Attack-surface inventory.

Turns the flat list of discovered URLs (crawl + archive + param mining) into a
deduplicated endpoint / parameter catalog the analyst can browse and pivot from
into the workbench (fuzz a param) or access-check (test an endpoint per role).
Pure and deterministic — no network, no AI.
"""
from urllib.parse import urlparse, parse_qsl


def build_inventory(urls, cap: int = 1000) -> list:
    """Group URLs by (host, path); union the query params seen for each.

    Returns a list of {host, path, params[], parameterized, example}, in first-seen
    order, capped at `cap` distinct endpoints."""
    by_key = {}
    order = []
    for u in urls or []:
        if not isinstance(u, str) or not u:
            continue
        try:
            p = urlparse(u)
        except Exception:
            continue
        if not p.netloc:
            continue
        path = p.path or "/"
        key = (p.netloc, path)
        params = [k for k, _ in parse_qsl(p.query, keep_blank_values=True)]
        if key not in by_key:
            by_key[key] = {"host": p.netloc, "path": path, "params": set(), "example": u}
            order.append(key)
        by_key[key]["params"].update(params)
        # Prefer an example URL that actually carries parameters.
        if params and "?" not in by_key[key]["example"]:
            by_key[key]["example"] = u

    out = []
    for key in order[:cap]:
        e = by_key[key]
        out.append({
            "host": e["host"],
            "path": e["path"],
            "params": sorted(e["params"]),
            "parameterized": bool(e["params"]),
            "example": e["example"],
        })
    return out
