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
# natural keys many APIs use instead of a numeric id (the read path is /collection/{this})
_NAT_KEYS = ("book_title", "title", "slug", "name", "username", "handle", "key", "code")


def _obj_id(o: dict):
    for k in _ID_KEYS:
        if o.get(k) not in (None, "", []):
            return str(o[k])
    for k in o:
        if str(k).lower() in _NAT_KEYS and o.get(k) not in (None, "", []):
            return str(o[k])
    return None


def _items(body):
    """The list of objects from a collection response: a bare list, or {data:[...]} / {result:[...]} / a
    {status, data:[...]} envelope."""
    try:
        obj = json.loads(body or "")
    except Exception:
        return []
    # general envelope unwrap: a bare list, or ANY dict value that is a list of objects (data/Books/results/…)
    if isinstance(obj, list):
        return [o for o in obj if isinstance(o, dict)]
    if isinstance(obj, dict):
        for v in obj.values():
            if isinstance(v, list) and any(isinstance(o, dict) for o in v):
                return [o for o in v if isinstance(o, dict)]
    return []


def extract_ids(body) -> set:
    """Every object id in a collection response (as strings)."""
    out = set()
    for o in _items(body):
        oid = _obj_id(o)
        if oid is not None:
            out.add(oid)
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


# owner-attribution fields (who a returned object belongs to) + sensitive fields a shared listing should hide
_OWNER_FIELDS = ("owner", "user", "username", "userid", "user_id", "created_by", "author", "account", "email")
_SENSITIVE = ("secret", "password", "passwd", "token", "api_key", "apikey", "private_key", "privatekey",
              "ssn", "credit_card", "creditcard", "card_number", "cardnumber", "cvv", "pin", "salary",
              "dob", "security_answer", "securityanswer", "reset_token")


def _norm(k) -> str:
    return str(k).lower().replace("-", "_")


def _one_object(body):
    """The single object from a detail response (bare dict, or the first object in an envelope)."""
    try:
        obj = json.loads(body or "")
    except Exception:
        return {}
    if isinstance(obj, dict):
        # a detail wrapped in an envelope? unwrap the first list-of-objects, else use the dict itself
        lst = _items(body)
        if lst and not any(_norm(k) in _SENSITIVE for k in obj):
            return lst[0]
        return obj
    lst = _items(body)
    return lst[0] if lst else {}


def foreign_sensitive_read(status, detail_body, attacker_identity):
    """Confirmed cross-user SENSITIVE read (fits shared-listing APIs like VAmPI): attacker got a 2xx, the
    object is attributed to a DIFFERENT user, and the detail carries a sensitive field the shared listing did
    not expose. Returns {owner, sensitive_fields} or None. Zero-FP: requires foreign owner AND a secret."""
    if not _2xx(status):
        return None
    obj = _one_object(detail_body)
    if not isinstance(obj, dict) or not obj:
        return None
    owner = None
    for k, v in obj.items():
        if _norm(k) in _OWNER_FIELDS and v not in (None, ""):
            owner = str(v)
            break
    sens = [k for k in obj if _norm(k) in _SENSITIVE]
    if sens and owner is not None and owner != str(attacker_identity):
        return {"owner": owner, "sensitive_fields": sens}
    return None


def foreign_finding(collection_path: str, object_id: str, hit: dict, attacker_role: str, target: str) -> dict:
    return {
        "title": "Broken object-level authorization — cross-user sensitive data read",
        "family": "idor", "confidence": "confirmed", "severity": "high", "cwe": "CWE-639",
        "owasp": "A01:2021", "target": target,
        "tags": ["idor", "bola", "access-control", "read", "excessive-data-exposure"],
        "description": ("Persona '%s' read object %s at %s: the detail belongs to a DIFFERENT user (%s) and "
                        "leaked sensitive field(s) %s that the shared listing did not expose — a confirmed "
                        "cross-user read of another user's sensitive data." % (attacker_role, object_id,
                        collection_path, hit.get("owner"), ", ".join(hit.get("sensitive_fields") or []))),
        "evidence": "foreign owner=%s, leaked fields=%s" % (hit.get("owner"), hit.get("sensitive_fields")),
        "false_positive_check": ("confirmed only when the object is attributed to a user other than the reader "
                                 "AND the detail carries a sensitive field — no guessing."),
        "remediation": "Enforce per-request object-ownership on the detail endpoint; never authorize by id alone.",
    }


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
