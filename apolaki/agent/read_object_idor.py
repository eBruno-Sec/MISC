"""Read-only cross-user object IDOR / BOLA (general, target-agnostic).

Complements create-object IDOR (which creates a marked object). This confirms BOLA on PRE-EXISTING /
auto-created objects (addresses, orders, complaints, per-user records) with an ownership DIFFERENTIAL, so it
needs no writes:

  1. Owner and attacker each GET a per-user collection (e.g. /api/Addresss).
  2. An object id in the OWNER's listing but NOT the attacker's is provably OWNER-OWNED (a per-user resource
     the attacker cannot legitimately see).
  3. If the attacker can then GET that id at /collection/{id} and the response actually carries that object,
     it is a CONFIRMED cross-user read — definitive, zero false-positive (public collections share ids across
     users, so owner_only is empty and nothing is flagged).

Pure decision layer — the live HTTP (owner list, attacker list, attacker read) runs in the tool that imports
this. Fully unit-testable.
"""
from __future__ import annotations

import json
import re

_ID_KEYS = ("id", "_id", "uuid", "ID")


def _items(body):
    """The list of objects from a collection response: a bare list, or {data:[...]} / {result:[...]} / a
    {status, data:[...]} envelope."""
    try:
        obj = json.loads(body or "")
    except Exception:
        return []
    if isinstance(obj, list):
        return [o for o in obj if isinstance(o, dict)]
    if isinstance(obj, dict):
        for wrap in ("data", "result", "items", "rows"):
            v = obj.get(wrap)
            if isinstance(v, list):
                return [o for o in v if isinstance(o, dict)]
    return []


def extract_ids(body) -> set:
    """Every object id in a collection response (as strings)."""
    out = set()
    for o in _items(body):
        for k in _ID_KEYS:
            if o.get(k) not in (None, "", []):
                out.add(str(o[k]))
                break
    return out


def owner_only_ids(owner_body, attacker_body) -> list:
    """Object ids the OWNER sees but the ATTACKER does not — provably owner-owned on a per-user resource.
    Empty for a public/shared collection (owner and attacker see the same ids) => nothing to test."""
    return sorted(extract_ids(owner_body) - extract_ids(attacker_body))


def _2xx(status) -> bool:
    try:
        return 200 <= int(status) < 300
    except Exception:
        return False


def confirm_read(attacker_status, attacker_body, object_id) -> bool:
    """A confirmed cross-user read: the attacker got a 2xx AND the response actually carries the target
    object id (proof it returned OWNER's object, not an empty/blocked page)."""
    if not _2xx(attacker_status):
        return False
    oid = str(object_id)
    # the id must appear as an actual value in the attacker's response body
    if re.search(r'["\b]' + re.escape(oid) + r'["\b]', attacker_body or ""):
        return True
    return oid in extract_ids(attacker_body)


def finding(collection_path: str, object_id: str, owner_role: str, attacker_role: str, target: str) -> dict:
    return {
        "title": "Broken object-level authorization (cross-user read)",
        "family": "idor", "confidence": "confirmed", "severity": "high", "cwe": "CWE-639",
        "owasp": "A01:2021", "target": target,
        "tags": ["idor", "bola", "access-control", "read", "differential"],
        "description": ("Persona '%s' read object id %s at %s — an object that only owner persona '%s' has in "
                        "their own listing. The response carried the object, proving a cross-user read "
                        "(broken object-level authorization)." % (attacker_role, object_id, collection_path,
                                                                  owner_role)),
        "evidence": "owner-only id %s at %s readable by a different authenticated user" % (object_id, collection_path),
        "false_positive_check": ("owner_only ids are provably absent from the attacker's own listing, and the "
                                 "attacker's 2xx response carried the target id — no similarity guessing."),
        "remediation": "Enforce per-request object-ownership checks server-side; do not authorize by id alone.",
    }
