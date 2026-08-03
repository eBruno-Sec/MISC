"""
Cross-session memory — reuse prior-mission intel on the same target.

An EvoGraph-lite. Each mission writes a compact SNAPSHOT of the attack surface it
discovered (hosts, subdomains, endpoints, tech, confirmed findings) keyed by a
stable TARGET KEY derived from scope — not the mission id — so successive
missions on the same program accumulate. A follow-up mission can then:

  • warm-start   — seed known live hosts / subdomains so recon skips cold ground
  • diff         — show what changed since the last scan ("new endpoint",
                   "finding gone", "new subdomain")

Pure and deterministic: no AI, no network. Guardrails live upstream — only
in-scope assets are ever seeded back, and secrets never enter a snapshot (we
persist hosts/paths/finding metadata, never headers or bodies).
"""
from __future__ import annotations

from urllib.parse import urlparse

import surface as surface_mod


def _host(v: str) -> str:
    v = (v or "").strip().lower().lstrip("*.")
    if "://" in v:
        v = urlparse(v).netloc
    return v.split("/")[0].split(":")[0]


def _host_of(url: str) -> str:
    try:
        return (urlparse(url).netloc or "").split(":")[0]
    except Exception:
        return ""


def _root(host: str) -> str:
    parts = (host or "").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def _port(v: str) -> str:
    """Non-default port from a scope entry / base URL, or '' (80/443 = default)."""
    v = (v or "").strip().lower()
    netloc = urlparse(v).netloc if "://" in v else v.split("/")[0]
    if ":" in netloc:
        p = netloc.rsplit(":", 1)[1]
        if p.isdigit() and p not in ("80", "443"):
            return p
    return ""


def _root_port(v: str) -> str:
    """Registrable root plus a non-default :port, so different apps on the SAME host
    but different ports (e.g. a local lab on :42000 / :42001 / :42002) map to
    DISTINCT memory buckets instead of colliding."""
    root = _root(_host(v))
    port = _port(v)
    return f"{root}:{port}" if (root and port) else root


def target_key(scope) -> str:
    """Stable per-program key from the in-scope registrable domains — now port-aware.

    Prefers the scope's base URLs (which carry scheme+port) so two apps on the same
    host but different ports don't share a memory bucket; falls back to in_scope.
    Independent of mission id, ordering, wildcards and scheme; still groups
    subdomains of the same registrable domain."""
    if isinstance(scope, dict):
        ins = scope.get("bases") or scope.get("in_scope")
    else:
        ins = scope
    keys = sorted({_root_port(x) for x in (ins or []) if _host(x)})
    return "|".join(keys) or "unknown"


def finding_fp(f: dict) -> str:
    """Deterministic fingerprint for diffing findings across runs — the vuln
    CLASS at a LOCATION, deliberately independent of severity/confidence/wording
    so a re-run recognises the same issue."""
    tgt = f.get("target") or f.get("surface") or ""
    host = _host_of(tgt)
    path = (urlparse(tgt).path or "/") if tgt else ""
    cls = (f.get("category") or f.get("cwe") or f.get("wstg") or "").strip().lower()
    if not cls:
        cls = (f.get("title") or "").strip().lower()[:40]
    return f"{cls}|{host}{path}"


def snapshot(recon: dict = None, urls: list = None, findings: list = None) -> dict:
    """Compact, serialisable view of what a mission discovered — the unit stored
    in memory and diffed against. Deterministic (sorted, deduped)."""
    recon = recon or {}
    urls = urls or []
    findings = findings or []

    hosts = set()
    tech = set()
    for h in (recon.get("live_hosts") or []):
        host = _host_of(h.get("url") or "") or _host(h.get("url") or "")
        if host:
            hosts.add(host)
        for t in (h.get("tech") or []):
            if t:
                tech.add(str(t))
    import dns_recon
    # Never PERSIST DNS/parsing artifacts (SOA-RNAME hosts) into the target's warm-start memory,
    # so a later scan does not re-seed junk targets from a prior run's snapshot.
    subs = {s for s in (recon.get("subdomains") or []) if s and not dns_recon.is_junk_host(s)}
    for u in urls:
        hh = _host_of(u)
        if hh:
            hosts.add(hh)

    inv = surface_mod.build_inventory(urls)
    # Keep the param NAMES on the stored endpoint (not values) so a future
    # warm-start re-seeds a PARAMETERIZED endpoint. Without this the seed is
    # host/path only, the endpoint looks param-free, and the deterministic
    # planner never re-probes it — which silently drops still-present findings
    # on any re-scan. Names only keeps memory compact and the diff stable.
    endpoints = sorted({
        f"{e['host']}{e['path']}" + ("?" + "&".join(e["params"]) if e.get("params") else "")
        for e in inv
    })

    finds = []
    seen_fp = set()
    for f in findings:
        fp = finding_fp(f)
        if fp in seen_fp:
            continue
        seen_fp.add(fp)
        finds.append({
            "fp": fp,
            "title": f.get("title", "Finding"),
            "severity": (f.get("severity") or "info").lower(),
            "target": f.get("target") or f.get("surface") or "",
        })

    return {
        "hosts": sorted(hosts),
        "subdomains": sorted(subs),
        "endpoints": endpoints,
        "tech": sorted(tech),
        "findings": finds,
        "counts": {"hosts": len(hosts), "subdomains": len(subs),
                   "endpoints": len(endpoints), "findings": len(finds)},
    }


def asset_pairs(snap: dict) -> list:
    """(kind, value) tuples for the persistent asset store — the accumulated
    facts a future mission warm-starts from."""
    snap = snap or {}
    out = []
    for kind in ("hosts", "subdomains", "endpoints", "tech"):
        for v in (snap.get(kind) or []):
            out.append((kind, v))
    return out


def diff(prev: dict, curr: dict) -> dict:
    """What changed between two snapshots — added/removed per asset kind, and
    findings compared by fingerprint (new vs resolved)."""
    prev = prev or {}
    curr = curr or {}

    def d(k):
        a, b = set(prev.get(k) or []), set(curr.get(k) or [])
        return {"added": sorted(b - a), "removed": sorted(a - b)}

    pf = {f["fp"]: f for f in (prev.get("findings") or []) if f.get("fp")}
    cf = {f["fp"]: f for f in (curr.get("findings") or []) if f.get("fp")}
    new_f = [cf[k] for k in cf if k not in pf]
    gone_f = [pf[k] for k in pf if k not in cf]

    return {
        "has_prior": bool(prev),
        "hosts": d("hosts"),
        "subdomains": d("subdomains"),
        "endpoints": d("endpoints"),
        "tech": d("tech"),
        "findings": {"added": new_f, "removed": gone_f},
    }
