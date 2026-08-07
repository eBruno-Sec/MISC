"""Central finding write-gate — the ONE chokepoint every persisted finding passes through (db.add_finding).

The review found three invariants bypassable at scattered write sites (deterministic tools, the model's
store_finding, and the API add/update paths each wrote findings their own way). They are now enforced in a
single place so no producer can route around them:

  * SCHEMA (#6): `normalize` coerces a finding to the canonical schema — reproduction_steps is ALWAYS a
    LIST (a producer that emitted a numbered string no longer breaks SARIF export / report / retest), and
    a couple of always-present fields get safe defaults.
  * SCOPE  (#8): `off_scope` rejects a finding whose target host is provably OUTSIDE the mission scope, so
    an off-scope finding can never be written — uniformly, from any producer. Fail-OPEN when scope is
    absent or the target has no parseable host (we only block what we can PROVE is out of scope).
  * TRUTH  (#7): `is_lead` flags a finding whose confidence is a LEAD so the DB layer routes it to the
    mission's leads list instead of the confirmed-findings table — a lead can never masquerade as a
    confirmed finding, even if a producer appended it to a findings list.

Pure decision helpers (except `off_scope`, which builds a throwaway ScopeEngine). No DB, no I/O.
"""
from __future__ import annotations

import re
from urllib.parse import urlparse

# confidence values that mean "not proven" — normalized (lower, '-'→'_') before compare
_LEAD_CONF = {"lead", "needs_confirmation", "unconfirmed", "tentative", "possible", "suspected"}


def _conf(finding) -> str:
    return str((finding or {}).get("confidence") or "").strip().lower().replace("-", "_")


def is_lead(finding) -> bool:
    """True when the finding is an UNPROVEN lead (must NOT be persisted as a confirmed finding, #7).
    A missing/blank confidence is treated as confirmed (the historical default) — only an explicit
    lead-like confidence reroutes, to keep the blast radius on existing producers minimal."""
    return _conf(finding) in _LEAD_CONF


def normalize(finding) -> dict:
    """Return a NEW dict coerced to the canonical finding schema (#6). The load-bearing fix is
    reproduction_steps → LIST (SARIF/report/retest all index it as a list); everything else is a
    conservative default that never overwrites a value a producer already set."""
    f = dict(finding or {})
    rs = f.get("reproduction_steps")
    if rs in (None, "", [], {}):
        f["reproduction_steps"] = []
    elif isinstance(rs, list):
        f["reproduction_steps"] = [str(x).strip() for x in rs if str(x).strip()]
    elif isinstance(rs, str):
        # split a numbered / newline / semicolon string ("1) a 2) b" | "a;\nb") into discrete steps
        parts = [p.strip() for p in re.split(r"\s*(?:\n|;|(?:^|\s)\d+[\).]\s)", rs) if p and p.strip()]
        f["reproduction_steps"] = parts or [rs.strip()]
    else:
        f["reproduction_steps"] = [str(rs)]
    f.setdefault("severity", "info")
    f.setdefault("confidence", "confirmed")
    # tags must be a list if present (export iterates it)
    if f.get("tags") is not None and not isinstance(f["tags"], list):
        f["tags"] = [str(f["tags"])]
    return f


def _host_of(target) -> str:
    t = (target or "").strip()
    if not t:
        return ""
    if "://" not in t:
        t = "//" + t
    try:
        return (urlparse(t).hostname or "").lower()
    except Exception:
        return ""


def off_scope(finding, scope: dict) -> bool:
    """True ONLY when the finding's target is PROVABLY outside the mission scope (#8). Fail-open:
    returns False (admit) when scope is empty / has no in_scope, when the finding has no target, or
    when the target has no parseable host — we block only what we can prove is out of scope, so a
    legitimate finding with a placeholder/non-URL target is never silently dropped."""
    scope = scope or {}
    in_scope = scope.get("in_scope") or []
    if not in_scope:
        return False                                   # no scope configured -> nothing to enforce
    target = (finding or {}).get("target") or (finding or {}).get("url") or ""
    t = str(target).strip().lower()
    # The web ScopeEngine governs WEB/API targets only. A finding whose target is NOT an http(s) URL —
    # a cloud-posture label ("fw-web"), a network host:port, a service/OT identifier — lives in its own
    # authorization namespace (the cloud token, the service-pack scope) and is NOT subject to the web
    # scope; never reject it here (that would silently drop legitimate cloud/network findings).
    if not (t.startswith("http://") or t.startswith("https://")):
        return False
    if not _host_of(target):
        return False                                   # no host to judge -> admit (fail-open)
    try:
        import scope as _scope
        eng = _scope.ScopeEngine()
        # rebuild from `bases` when present (they carry scheme:host:port/path so port/path pinning is
        # preserved); fall back to the bare in_scope hosts.
        eng.load_manual(scope.get("bases") or in_scope, scope.get("out_of_scope") or [],
                        scope.get("program") or "Program")
        ok, _reason = eng.validate(target)
        return not ok
    except Exception:
        return False                                   # scope engine unavailable -> do not block
