"""
Authorization-matrix orchestration — the request set to replay and the finding mapping.

The differential ANALYSIS lives in authz.build_matrix (pure, per-cell). This module supplies the
two pieces around it the scan needs, both pure + testable:

  candidate_operations(urls)  -> object-bearing operations to replay across personas
  gaps_to_findings(result)    -> Apolaki findings from build_matrix's gaps

The network replay + the ownership-proven horizontal-read oracle live in the ToolRegistry async
driver (_run_authz_matrix); this module keeps the decisions deterministic and unit-testable.
"""
from __future__ import annotations

import re
from urllib.parse import urlparse

# an object-bearing path segment: .../<name>/<id> where id is numeric, a long hex, or a uuid.
_OBJ_RX = re.compile(r"/([A-Za-z][\w.-]*)/(\d+|[0-9a-fA-F]{8,}|[0-9a-fA-F-]{36})(?=/|$|\?)")

# gap type -> (title, default severity, family, cwe, tags)
_GAP_META = {
    "missing_authentication": (
        "Broken access control — endpoint reachable with no authentication",
        "high", "access_control", "CWE-306", ["access-control", "authentication"]),
    "bola_idor": (
        "IDOR / BOLA — cross-user object access confirmed",
        "high", "idor", "CWE-639", ["idor", "bola", "access-control"]),
    "bfla": (
        "Broken function-level authorization — privileged function reached by a normal user",
        "high", "access_control", "CWE-285", ["bfla", "access-control", "privilege"]),
    "cross_tenant": (
        "Cross-tenant access — one tenant received another tenant's data",
        "critical", "access_control", "CWE-639", ["cross-tenant", "access-control", "isolation"]),
}

_REMEDIATION = {
    "missing_authentication": "Require an authenticated session on this endpoint; deny anonymous access.",
    "bola_idor": "Enforce object-level authorization: check the session owns the requested object id server-side.",
    "bfla": "Enforce function-level authorization: verify the caller's role before running privileged actions.",
    "cross_tenant": "Scope every query by tenant; never resolve an object id across tenant boundaries.",
}


def is_object_path(path: str) -> bool:
    return bool(_OBJ_RX.search(path or ""))


def object_key(path: str) -> str:
    m = _OBJ_RX.search(path or "")
    return m.group(1) if m else ""


def _shape(path: str) -> str:
    """Normalize the object id in a path to {id} so /orders/1 and /orders/2 dedup to one endpoint
    shape (same authorization logic — one representative object is enough to test the endpoint)."""
    m = _OBJ_RX.search(path or "")
    if not m:
        return path or "/"
    return path[:m.start(2)] + "{id}" + path[m.end(2):]


def candidate_operations(urls, max_ops: int = 25) -> list:
    """From discovered URLs, pick object-bearing operations to replay across personas. Returns
    [{request, method, path, object_key}], deduped by endpoint SHAPE (id normalized) so two ids of
    the same endpoint collapse to one. GET-only here — the read differential; write/vertical are
    separate bounded oracles in the driver."""
    ops, seen = [], set()
    for u in urls or []:
        p = urlparse(str(u))
        path = p.path or "/"
        if not is_object_path(path):
            continue
        shape = _shape(path)
        if shape in seen:
            continue
        seen.add(shape)
        full = path + (("?" + p.query) if p.query else "")
        ops.append({"request": path, "method": "GET", "path": full, "object_key": object_key(path)})
        if len(ops) >= max_ops:
            break
    return ops


# These gap TYPES are heuristic SIGNALS, not proof, so they are emitted as LEADS (truth-first):
#  - missing_authentication: the anon-reachable object may be a legitimately PUBLIC resource; build_matrix
#    does not compare the returned data, so a public catalog would otherwise become a false High.
#  - bfla: a privileged-LOOKING path reached by a user may just be the user's OWN resource (/settings,
#    /users/<self>) — confirming needs a proven privileged control persona + a denied-action proof.
# bola_idor / cross_tenant carry ownership/tenant evidence, so they stay confirmed. (The driver's
# own-object-differential IDOR path is separate and emits its own confirmed/lead finding.)
_GAP_CONFIDENCE = {"missing_authentication": "lead", "bfla": "lead",
                   "bola_idor": "confirmed", "cross_tenant": "confirmed"}


def _describe(gap: dict) -> str:
    t = gap.get("type")
    roles = ", ".join(gap.get("roles", []) or [])
    base = {
        "missing_authentication": ("An object endpoint returned data to an UNAUTHENTICATED request. This is a "
                                   "SIGNAL, not proof — confirm it is not a legitimately public resource by "
                                   "comparing the anonymous response to a per-user one."),
        "bola_idor": "A user received an object owned by a different user — object-level authorization is missing.",
        "bfla": ("A privileged-LOOKING path was reached by a non-privileged authenticated role. This is a "
                 "SIGNAL — confirm with a PROVEN privileged persona that it is actually a privileged function "
                 "(not the user's own resource, e.g. /settings or /users/<self>)."),
        "cross_tenant": "A user in one tenant received data belonging to another tenant.",
    }.get(t, "Authorization gap detected by the differential matrix.")
    return f"{base} Roles involved: {roles}." if roles else base


def gaps_to_findings(matrix_result: dict, base_url: str = "") -> list:
    """Map build_matrix gaps to Apolaki finding dicts. missing_authentication and bfla are emitted as
    LEADS (heuristic signals — see _GAP_CONFIDENCE); only ownership/tenant-evidenced gaps are confirmed.
    This avoids marking a public catalog or a user's own resource as a High access-control finding."""
    findings = []
    for g in (matrix_result or {}).get("gaps", []) or []:
        meta = _GAP_META.get(g.get("type"))
        if not meta:
            continue
        title, sev, family, cwe, tags = meta
        req = g.get("request", "") or ""
        if req.startswith("http"):
            target = req
        elif base_url:
            target = base_url.rstrip("/") + "/" + req.lstrip("/")
        else:
            target = req
        conf = _GAP_CONFIDENCE.get(g.get("type"), "lead")
        findings.append({
            "title": ("Possible " + title) if conf == "lead" else title,
            "severity": "medium" if conf == "lead" else g.get("severity", sev),
            "family": family,
            "confidence": conf,
            "cwe": cwe,
            "target": target,
            "tags": tags + (["needs-confirmation"] if conf == "lead" else []),
            "description": _describe(g),
            "evidence": g.get("evidence", ""),
            "remediation": _REMEDIATION.get(g.get("type"), ""),
        })
    return findings
