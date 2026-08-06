"""API inventory drift + version governance (Codex cross-check Tier-2 #10).

Apolaki imports OpenAPI and crawls routes; this adds the COMPARISON model the API books keep circling back
to: runtime endpoints vs documented (OpenAPI) vs archived/passive vs code-discovered. It surfaces drift —
undocumented live endpoints, documented-but-dead endpoints, deprecated versions still exposed, response
schema drift, and third-party dependency APIs. Almost everything here is an OBSERVATION / lead, not a
vulnerability. Off-scope archived endpoints are never imported as live. Pure + offline.
"""
from __future__ import annotations

import re
from urllib.parse import urlsplit

_VER_RX = re.compile(r"(?i)/(v\d+|beta|legacy|alpha|preview|deprecated|v\d+\.\d+)(?=/|$)")
_DEPRECATED = {"beta", "legacy", "alpha", "preview", "deprecated", "v0", "v1"}


def _path(ep) -> str:
    """Normalize an endpoint (string URL/path or {method,path}/{url}) to a lowercased path w/o query/slash."""
    if isinstance(ep, dict):
        raw = ep.get("path") or ep.get("url") or ep.get("endpoint") or ""
    else:
        raw = str(ep or "")
    sp = urlsplit(raw)
    p = sp.path if sp.scheme or sp.netloc else raw.split("?", 1)[0].split("#", 1)[0]
    p = "/" + p.strip().strip("/").lower()
    return p if p != "/" else "/"


def _set(eps) -> set:
    return {_path(e) for e in (eps or []) if _path(e)}


def _version_of(path: str):
    m = _VER_RX.search(path or "")
    return m.group(1).lower() if m else None


def _base_of(path: str) -> str:
    return re.sub(r"/{2,}", "/", _VER_RX.sub("/", path or "", count=1)) or "/"


def _obs(otype: str, endpoint: str, note: str, confidence: str = "observation") -> dict:
    return {"type": otype, "endpoint": endpoint, "confidence": confidence, "family": "api_inventory",
            "note": note}


def reconcile(runtime=None, documented=None, *, archived=None, code=None, in_scope=None) -> list:
    """Compare endpoint sources and return drift observations (never vulns). `in_scope(path)` filters archived
    endpoints so an off-scope archived path is never imported as a live/runtime endpoint."""
    rt = _set(runtime)
    doc = _set(documented)
    arch = {p for p in _set(archived) if in_scope is None or in_scope(p)}   # off-scope archived dropped
    src = _set(code)
    out = []

    for p in sorted(rt - doc):
        out.append(_obs("undocumented_runtime_endpoint", p,
                        "Seen live but absent from the API spec — inventory drift; document or remove."))
    for p in sorted(doc - rt):
        out.append(_obs("documented_dead_endpoint", p,
                        "In the spec but never observed/reachable — a coverage gap, not a vulnerability.",
                        confidence="coverage_gap"))
    for p in sorted(rt | arch | src):
        v = _version_of(p)
        if v and v in _DEPRECATED:
            out.append(_obs("deprecated_version_exposed", p,
                            "Deprecated/old API version still exposed (%s) — review for retirement." % v,
                            confidence="lead"))

    # version coexistence: same base path served under 2+ versions
    versions: dict = {}
    for p in sorted(rt | arch | src | doc):
        v = _version_of(p)
        if v:
            versions.setdefault(_base_of(p), set()).add(v)
    for base, vers in sorted(versions.items()):
        if len(vers) > 1:
            out.append(_obs("multiple_versions_exposed", base,
                            "Multiple API versions coexist (%s) — versioning/deprecation governance review."
                            % ", ".join(sorted(vers)), confidence="observation"))
    return out


def schema_drift(observed_fields, spec_fields, endpoint: str = "") -> dict:
    """Response fields that differ from the spec. Extra fields (in response, not spec) are the interesting
    drift; missing fields are noted too. Observation, not a vuln. Returns None when the response matches."""
    obs = {str(f).lower() for f in (observed_fields or [])}
    spec = {str(f).lower() for f in (spec_fields or [])}
    extra, missing = sorted(obs - spec), sorted(spec - obs)
    if not extra and not missing:
        return None
    return {"type": "schema_drift", "endpoint": endpoint, "family": "api_inventory",
            "confidence": "observation", "extra_fields": extra, "missing_fields": missing,
            "note": "Response schema differs from the spec — review for undocumented/removed fields."}


def third_party_dependency_apis(outbound_urls, target_hosts) -> list:
    """Outbound API/webhook hosts that are NOT the target — each needs a trust-boundary review. Observation."""
    hosts = {str(h).lower() for h in (target_hosts or [])}
    seen, out = set(), []
    for u in (outbound_urls or []):
        host = (urlsplit(str(u)).netloc or "").lower().split(":")[0]
        if not host or host in hosts or host in seen:
            continue
        seen.add(host)
        out.append(_obs("third_party_dependency_api", host,
                        "Outbound API/webhook dependency — review the trust boundary + data shared.",
                        confidence="observation"))
    return out
