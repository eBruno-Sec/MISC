"""Central finding write-gate — the ONE chokepoint every persisted finding passes through (db.add_finding).

The review found three invariants bypassable at scattered write sites (deterministic tools, the model's
store_finding, and the API add/update paths each wrote findings their own way). They are now enforced in a
single place so no producer can route around them:

  * SCHEMA (#6): `normalize` coerces a finding to the canonical schema — reproduction_steps is ALWAYS a
    LIST (a producer that emitted a numbered string no longer breaks SARIF export / report / retest), and
    a couple of always-present fields get safe defaults.
  * SCOPE  (#8): `off_scope` rejects a finding whose target CANNOT BE PROVED to be inside the mission
    scope, so an off-scope finding can never be written — uniformly, from any producer. Q-099: this one
    fails CLOSED. An unbuildable boundary or an http(s) target with no parseable host is a REFUSAL, not
    an admission; see `off_scope` for why this gate's direction is the opposite of an engine's. Two
    arms still admit and neither is a fail-open: a mission that declares no scope, and a target that is
    not an http(s) URL (cloud / network findings answer to their own authorization namespace).
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


def _boundary(scope: dict) -> tuple:
    """`(ScopeEngine, "")` for a scope that states an enforceable boundary, `(None, reason)` for one
    that does not, `(None, "")` for a mission that declares no boundary at all.

    Rebuilt from `bases` when present (they carry scheme:host:port/path, so port and path pinning
    survive); falls back to the bare `in_scope` hosts. Delegates to `scope.build_boundary` so the
    write gate, the mission record and the request guards answer from ONE evaluation."""
    scope = scope or {}
    in_scope = scope.get("in_scope") or []
    if not in_scope:
        return None, ""                                # nothing declared — a different question
    import scope as _scope
    return _scope.build_boundary(scope.get("bases") or in_scope, scope.get("out_of_scope") or [],
                                 scope.get("program") or "Program")


def scope_refusal(scope: dict) -> str:
    """Non-empty when this mission's declared scope CANNOT be built into an enforceable boundary —
    the reason, in a sentence naming the entry to fix. `""` when it can, and `""` when the mission
    declares no scope at all (that is the separate `not in_scope` state below, unchanged by Q-099).

    Exists because `off_scope` answers with a bare `True`, which is the right answer and a useless
    one to whoever has to fix the mission. Every operator-facing surface reads this."""
    return _boundary(scope)[1]


def off_scope(finding, scope: dict) -> bool:
    """True when the finding's target CANNOT BE PROVED to be inside the mission scope (#8).

    Q-099 REVERSED THE DIRECTION OF TWO ARMS, deliberately. Both used to admit, both with a comment
    saying so on purpose, and both fired exactly where scope is least trustworthy:

        no parseable host on an http(s) target   -> was admit, now REFUSE
        the boundary could not be built at all   -> was admit, now REFUSE

    The second was the live one. Q-096 made `load_manual` RAISE on a scope made entirely of regex
    patterns (the real 2026-08-24 Shopify engagement), and `ScopeEngine.to_dict` puts patterns into
    `in_scope`, so such a mission sails past the `not in_scope` arm and every finding it produced was
    admitted. MEASURED before this change: a mission with an unbuildable boundary published all 7 of
    7 findings, `http://evil.example.com/p` among them.

    WHY THIS GATE, AND ONLY THIS KIND OF GATE, FAILS CLOSED. An engine failing closed loses a
    finding; a SCOPE gate failing open puts an out-of-scope finding into a report submitted to a bug
    bounty program — a program-rules violation and a reputational hit, not a missed bug. The
    discipline is already written at `main.py:3081`: an exception while BUILDING the boundary can
    only mean the boundary is unknown, and **unknown is not permission**. Note the shape of the
    refusal: with no boundary, the operator's OWN asset is refused too. That is not over-blocking,
    it is what "unknown" means — the statement is about the boundary, never about the target.

    The two arms that still ADMIT are unchanged and are not fail-opens:
      * no scope declared — a different question, and `EngageRequest` requires `in_scope`, so no
        mission created by the product reaches it;
      * a non-http(s) target — a cloud-posture label ("fw-web"), a network host:port, a service/OT
        identifier. These live in their own authorization namespace (the cloud token, the
        service-pack scope) and the WEB ScopeEngine has no jurisdiction over them, so its failure to
        build says nothing about them. Refusing them here would silently drop legitimate
        cloud/network findings for an unrelated reason.
    """
    scope = scope or {}
    in_scope = scope.get("in_scope") or []
    if not in_scope:
        return False                                   # no scope configured -> nothing to enforce
    target = (finding or {}).get("target") or (finding or {}).get("url") or ""
    t = str(target).strip().lower()
    if not (t.startswith("http://") or t.startswith("https://")):
        return False                                   # non-web target: not this scope's namespace
    if not _host_of(target):
        return True                                    # Q-099: no host to judge -> cannot prove in scope
    eng, refusal = _boundary(scope)
    if refusal or eng is None:
        return True                                    # Q-099: no enforceable boundary -> refuse
    try:
        ok, _reason = eng.validate(target)
    except Exception:
        # The boundary built, then could not answer for this target. Same sentence: a predicate that
        # cannot evaluate has not said yes.
        return True
    return not ok
