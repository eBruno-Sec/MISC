"""
Function-level authorization testing (BFLA) + side-channel BOLA oracle.

From Hacking APIs (Ball, Ch 10). Complements the cross-role access-check (BOLA)
and the IDOR neighbor probes already in BBH:
  - BFLA: send multiple HTTP methods (incl. write methods and admin paths) with a
    token that SHOULD NOT be authorized; any 2xx is a candidate broken
    function-level authorization / privilege escalation.
  - Side-channel BOLA: a nonexistent resource vs an existing-but-unauthorized one
    returning distinguishable status/length is an existence/enumeration oracle.

DELETE is excluded by default (the book's warning: never DELETE-fuzz live data).
Analysis is pure/deterministic; the network lives in tools._run_bfla.
"""
from __future__ import annotations

import re
from urllib.parse import urlparse

WRITE_METHODS = ("POST", "PUT", "PATCH", "DELETE")
SAFE_SWEEP = ("GET", "POST", "PUT", "PATCH")          # DELETE opt-in only
ADMIN_HINT = re.compile(r"/(admin|manage|management|internal|console|superuser|root)(/|$)", re.I)


def is_admin_path(url: str) -> bool:
    return bool(ADMIN_HINT.search(urlparse(url).path or ""))


def _ok(status: int) -> bool:
    return 200 <= (status or 0) < 300


def analyze_methods(url: str, method_results: dict, anon_results: dict = None) -> list:
    """Flag methods the test token reached that it likely should not have.

    method_results / anon_results: {METHOD: {"status": int, "length": int}}.
    A write method or an admin-path GET returning 2xx for the test token — and
    NOT already public (anon 2xx) — is a BFLA candidate."""
    anon_results = anon_results or {}
    admin = is_admin_path(url)
    findings = []
    for m, r in method_results.items():
        if not _ok(r.get("status")):
            continue
        if _ok((anon_results.get(m) or {}).get("status")):
            continue  # already public — not an authz gap for this token
        if m in WRITE_METHODS:
            findings.append({
                "title": f"Broken function-level authorization ({m})",
                "severity": "high", "target": url,
                "description": (f"A {m} request succeeded (HTTP {r.get('status')}) with a token that should not be "
                                "authorized for this action."),
                "impact": "Unauthorized state change / privilege escalation (BFLA).",
                "reproduction_steps": [f"Send {m} {url} with a lower-privileged / other-user token",
                                       f"Observe HTTP {r.get('status')}", "Confirm the token lacks this permission"],
                "cwe": "CWE-285", "family": "bfla", "tags": ["bfla", "access-control"],
                "confidence": "candidate"})
        elif admin and m == "GET":
            findings.append({
                "title": "Admin endpoint reachable by non-admin token",
                "severity": "high", "target": url,
                "description": f"An admin-path GET returned HTTP {r.get('status')} with a non-admin token.",
                "impact": "Privilege escalation / sensitive admin data exposure (BFLA).",
                "reproduction_steps": [f"GET {url} with a low-privileged token",
                                       f"Observe HTTP {r.get('status')}"],
                "cwe": "CWE-285", "family": "bfla", "tags": ["bfla", "access-control"],
                "confidence": "candidate"})
    return findings


def analyze_side_channel(nonexistent: dict, target: dict) -> list:
    """Existence oracle: a nonexistent resource and an existing-but-unauthorized
    one returning distinguishable responses lets an attacker enumerate resources."""
    ns = (nonexistent or {}).get("status", 0)
    ts = (target or {}).get("status", 0)
    nl = (nonexistent or {}).get("length", 0) or 0
    tl = (target or {}).get("length", 0) or 0
    distinguishable = False
    reason = ""
    if ns == 404 and ts != 404 and ts in (200, 401, 403, 405):
        distinguishable = True
        reason = f"nonexistent -> 404, existing-unauthorized -> {ts}"
    elif ns == ts and abs(tl - nl) > 40 and ts in (401, 403, 405):
        distinguishable = True
        reason = f"same status {ts} but response length differs ({nl} vs {tl})"
    if not distinguishable:
        return []
    return [{
        "title": "Side-channel BOLA (resource existence oracle)",
        "severity": "low", "target": "resource-id",
        "description": f"Existing vs nonexistent resources are distinguishable: {reason}. "
                       "IDs (usernames, accounts, phone numbers) can be enumerated even without direct access.",
        "impact": "Enumerate valid resource identifiers to fuel BOLA / brute-force.",
        "reproduction_steps": ["Request a random nonexistent id and an existing id",
                               "Compare status/length to build an oracle"],
        "cwe": "CWE-204", "family": "bola", "tags": ["bola", "access-control"],
        "confidence": "candidate"}]
