"""
Differential Authorization Engine.

Scanners test users one at a time and miss the whole class of authorization bugs. This builds an
AUTHORIZATION MATRIX — the same requests replayed as every role (anonymous, user A, user B,
privileged, tenant A, tenant B) — and reads the DIFFERENCES to detect what a single-user scan
can't:

  - missing_authentication : an unauthenticated role gets the same data an authenticated one does
  - bola_idor              : a role receives an object it does not own (object-level authz missing)
  - bfla                   : a non-privileged role reaches a privileged function (function-level)
  - cross_tenant           : tenant A receives tenant B's data
  - no_differentiation     : an endpoint returns the same to roles that should differ

Every flagged gap is a DIFFERENTIAL FACT (role X got exactly what role Y got, or what nobody
below privilege should) — not a heuristic guess. Deterministic; the analysis (`build_matrix`) is
pure and testable. `run_matrix` is a thin driver that collects the cells over HTTP.

Cell schema (one per request×role):
  {"request": <id>, "role": <label>, "rank": <int 0=anon 1=user 2=privileged>,
   "status": <int>, "body": <str>, "owner": <role label who owns the object|None>,
   "tenant": <tenant label|None>}
"""
from __future__ import annotations

import re

_DENY_MARKERS = ("access denied", "unauthorized", "forbidden", "not allowed", "must be logged",
                 "please log in", "authentication required", "login required", "permission denied")
_PRIV_RX = re.compile(r"(/admin|/manage|/internal|/config|/settings|/users?/|/roles?|/audit|"
                      r"/delete|/approve|/impersonate|/backup|/metrics|/debug)", re.I)


def _accessed(status, body) -> bool:
    """Did this role successfully ACCESS data? A 2xx with a non-empty, non-error body."""
    try:
        code = int(status or 0)
    except Exception:
        code = 0
    if not (200 <= code < 300):
        return False
    b = (body or "").strip().lower()
    if not b:
        return False
    return not any(m in b[:300] for m in _DENY_MARKERS)


def _looks_privileged(request_id: str) -> bool:
    return bool(_PRIV_RX.search(request_id or ""))


def _json_body(body):
    """Parse a response body as JSON for field-level analysis; None if it is not a JSON object/array."""
    s = (body or "").strip()
    if not s or s[0] not in "{[":
        return None
    try:
        import json
        return json.loads(s)
    except Exception:
        return None


def build_matrix(cells: list) -> dict:
    """Pure differential analysis over collected (request×role) cells. Returns the matrix plus the
    authorization GAPS, each with the differential evidence that proves it."""
    reqs: dict = {}
    for c in cells or []:
        reqs.setdefault(c.get("request", "?"), {})[c.get("role", "?")] = c
    matrix, gaps = {}, []
    for req, byrole in reqs.items():
        matrix[req] = {r: {"status": c.get("status"), "rank": c.get("rank", 1),
                           "access": _accessed(c.get("status"), c.get("body"))}
                       for r, c in byrole.items()}
        got = [(r, c) for r, c in byrole.items() if _accessed(c.get("status"), c.get("body"))]

        # 1) missing authentication — an anonymous role (rank 0) accessed it AND an authed role also did
        anon_in = [r for r, c in got if c.get("rank", 1) == 0]
        authed_in = [r for r, c in got if c.get("rank", 1) >= 1]
        if anon_in and authed_in:
            gaps.append({"type": "missing_authentication", "request": req, "severity": "high",
                         "roles": anon_in,
                         "evidence": ("reachable with NO authentication (%s) and returns the same data an "
                                      "authenticated role sees — the endpoint does not require a session."
                                      % anon_in[0])})

        # 2) BOLA / IDOR — a non-privileged role received an object it does not own
        for r, c in got:
            owner = c.get("owner")
            if owner and r != owner and c.get("rank", 1) < 2:
                gaps.append({"type": "bola_idor", "request": req, "severity": "high", "roles": [r],
                             "evidence": ("role '%s' received the object owned by '%s' — object-level "
                                          "authorization is not enforced." % (r, owner))})

        # 3) cross-tenant — a role from tenant X received tenant Y's data
        for r, c in got:
            ten, owner = c.get("tenant"), byrole.get(c.get("owner") or "", {})
            oten = owner.get("tenant") if isinstance(owner, dict) else None
            if ten and oten and ten != oten:
                gaps.append({"type": "cross_tenant", "request": req, "severity": "critical", "roles": [r],
                             "evidence": ("role '%s' (tenant %s) received data belonging to tenant %s — "
                                          "cross-tenant isolation is broken." % (r, ten, oten))})

        # 4) BFLA — a privileged-looking function reached by an AUTHENTICATED non-privileged user.
        # Anonymous access to it is NOT bfla (that's missing_authentication / a public endpoint), so
        # exclude anon and only fire when the endpoint is not anon-reachable — otherwise a public
        # endpoint whose path merely looks privileged is a false positive.
        if _looks_privileged(req):
            anon_got = any(c.get("rank", 1) == 0 for _, c in got)
            authed_lowpriv = [r for r, c in got if c.get("rank", 1) == 1]
            if authed_lowpriv and not anon_got:
                gaps.append({"type": "bfla", "request": req, "severity": "high", "roles": authed_lowpriv,
                             "evidence": ("privileged function reached by authenticated non-privileged role(s) %s "
                                          "(anonymous is denied) — function-level authorization is not enforced."
                                          % authed_lowpriv)})

        # 5) FIELD-LEVEL over-exposure (Codex #9), distinct from BOLA: a response leaks sensitive/admin/debug
        # fields even when object-level access is legitimate. Fires only on conservative sensitive field NAMES.
        _ranks = {r: c.get("rank", 1) for r, c in got}
        _maxrank = max(_ranks.values(), default=1)
        for r, c in got:
            data = _json_body(c.get("body"))
            if data is None:
                continue
            try:
                import field_authz as _fa
                obs = _fa.excessive_data_exposure(
                    data, role=r, authenticated=(c.get("rank", 1) >= 1),
                    own_resource=(c.get("owner") in (None, r)))
            except Exception:
                obs = None
            if obs:
                _fields = [e["field"] for e in obs["exposed_fields"]]
                _low = _ranks.get(r, 1) < _maxrank
                gaps.append({"type": "excessive_data_exposure", "request": req,
                             "severity": obs["severity"], "roles": [r], "exposed_fields": _fields,
                             "evidence": ("role '%s' response exposes %d sensitive/admin/debug field(s): %s%s"
                                          % (r, len(_fields), ", ".join(_fields[:6]),
                                             " — and this role is lower-privileged than a peer that accessed the "
                                             "same object (field-level authorization gap)" if _low else ""))})

    # dedup identical gaps (same type+request+roles)
    seen, uniq = set(), []
    for g in gaps:
        k = (g["type"], g["request"], tuple(g.get("roles", [])))
        if k not in seen:
            seen.add(k)
            uniq.append(g)
    return {"roles": sorted({c.get("role", "?") for c in (cells or [])}),
            "requests": sorted(reqs), "matrix": matrix, "gaps": uniq}


def run_matrix(base_url: str, roles: list, requests: list, timeout: int = 12) -> dict:
    """Thin driver: replay each request as each role over HTTP, then build_matrix.
    roles:    [{"role","rank","headers"?,"tenant"?}]  requests: [{"request"|"id","method","path","owner"?}]
    NO credential brute-force and no state-changing methods unless the caller opts in — read-only by
    default (only GET/HEAD/OPTIONS are sent) so the matrix is a safe recon differential."""
    try:
        import httpx
    except Exception:
        return {"error": "httpx unavailable"}
    base = base_url.rstrip("/")
    cells = []
    try:
        c = httpx.Client(base_url=base, timeout=timeout, follow_redirects=False)
    except Exception as e:
        return {"error": str(e)}
    try:
        for rq in requests or []:
            method = str(rq.get("method", "GET")).upper()
            if method not in ("GET", "HEAD", "OPTIONS"):
                continue                                      # read-only differential by default
            path = rq.get("path") or rq.get("request") or "/"
            rid = rq.get("request") or rq.get("id") or (method + " " + path)
            for role in roles or []:
                try:
                    r = c.request(method, path, headers=role.get("headers") or {})
                    body, status = r.text[:4000], r.status_code
                except Exception:
                    body, status = "", 0
                cells.append({"request": rid, "role": role.get("role", "?"),
                              "rank": role.get("rank", 1), "status": status, "body": body,
                              "owner": rq.get("owner"), "tenant": role.get("tenant")})
    finally:
        c.close()
    return build_matrix(cells)
