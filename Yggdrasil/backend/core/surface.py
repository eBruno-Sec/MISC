"""Attack-surface inventory.

Turns the flat list of discovered URLs (crawl + archive + param mining) into a
deduplicated endpoint / parameter catalog the analyst can browse and pivot from
into the workbench (fuzz a param) or access-check (test an endpoint per role).
Pure and deterministic — no network, no AI.
"""
import re
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


def endpoints_from_openapi(spec, base_url: str) -> list:
    """Extract testable endpoint URLs (with query params) from an OpenAPI 3 or
    Swagger 2 spec, anchored to base_url's host.

    Scope-safe: only the base *path* is borrowed from the spec's `servers`/
    `basePath` — the host is always base_url, never a foreign host the spec may
    declare. Path templates ({id}) become `1`; declared query params become
    `?name=test` so the injection probes have something to attack."""
    if not isinstance(spec, dict) or not isinstance(spec.get("paths"), dict):
        return []
    base = base_url.rstrip("/")

    bp = ""
    servers = spec.get("servers")
    if isinstance(servers, list) and servers and isinstance(servers[0], dict):
        u = servers[0].get("url", "") or ""
        bp = urlparse(u).path if u.startswith("http") else (u if u.startswith("/") else "")
    if not bp:
        bp = spec.get("basePath", "") or ""
    root = (base + bp).rstrip("/")

    out = []
    for path, methods in spec["paths"].items():
        if not isinstance(methods, dict):
            continue
        qparams, testable = set(), False
        for m, op in methods.items():
            if m.lower() not in ("get", "post", "put", "delete", "patch"):
                continue
            testable = True
            if isinstance(op, dict):
                for p in (op.get("parameters") or []):
                    if isinstance(p, dict) and p.get("in") == "query" and p.get("name"):
                        qparams.add(str(p["name"]))
        if not testable:
            continue
        concrete = re.sub(r"\{[^}]+\}", "1", str(path))
        full = root + "/" + concrete.lstrip("/")
        if qparams:
            full += ("&" if "?" in full else "?") + "&".join(f"{n}=test" for n in sorted(qparams))
        out.append(full)
    return list(dict.fromkeys(out))
