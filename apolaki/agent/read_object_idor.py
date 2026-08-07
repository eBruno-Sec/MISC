"""Read-only cross-user object IDOR / BOLA (general, target-agnostic).

Complements create-object IDOR (which creates a marked object). This confirms BOLA on PRE-EXISTING /
auto-created objects (addresses, orders, complaints, per-user records) two ways, both zero-false-positive:

  A) OWNERSHIP DIFFERENTIAL (per-user listings): an object id in the OWNER's listing but NOT the attacker's
     is provably owner-owned; if the attacker can then GET it and the response carries that id, it's a
     confirmed cross-user read.
  B) OWNER-ATTRIBUTION (shared listings, e.g. VAmPI): a detail attributed to a DIFFERENT principal that leaks
     a sensitive field the listing hid is a confirmed cross-user read — but ONLY when the owner is a principal
     we can actually compare against the reader's known identifiers (same scheme: email/name/numeric). If the
     owner uses a scheme we don't hold for the attacker, we CANNOT prove it's foreign and emit a LEAD, never a
     false confirm.

Pure decision layer — the live HTTP runs in the tool that imports this. Fully unit-testable.
"""
from __future__ import annotations

import json
import re

_ID_KEYS = ("id", "_id", "uuid", "ID")
# natural keys many APIs use instead of a numeric id (the read path is /collection/{this})
_NAT_KEYS = ("book_title", "title", "slug", "name", "username", "handle", "key", "code")


def _parse(body):
    """Return a parsed JSON object from `body` whether it is a JSON string or already a dict/list."""
    if isinstance(body, (dict, list)):
        return body
    try:
        return json.loads(body or "")
    except Exception:
        return None


def _obj_id(o: dict):
    for k in _ID_KEYS:
        if o.get(k) not in (None, "", []):
            return str(o[k])
    for k in o:
        if str(k).lower() in _NAT_KEYS and o.get(k) not in (None, "", []):
            return str(o[k])
    return None


def _items(body):
    """The list of objects from a collection response: a bare list, or ANY dict value that is a list of
    objects (data/Books/results/… — no hardcoded key). Accepts a JSON string or a parsed dict/list."""
    obj = _parse(body)
    if isinstance(obj, list):
        return [o for o in obj if isinstance(o, dict)]
    if isinstance(obj, dict):
        for v in obj.values():
            if isinstance(v, list) and any(isinstance(o, dict) for o in v):
                return [o for o in v if isinstance(o, dict)]
    return []


def _one_object(body):
    """The single object from a DETAIL response: a bare dict, or the first object in an envelope. Accepts a
    JSON string or a parsed dict/list (fixes numeric bare-detail-dict handling)."""
    obj = _parse(body)
    if isinstance(obj, dict):
        # a detail wrapped in an envelope? unwrap the first list-of-objects, else use the dict itself
        lst = _items(obj)
        if lst and not any(_norm(k) in _SENSITIVE for k in obj):
            return lst[0]
        return obj
    if isinstance(obj, list):
        return obj[0] if obj and isinstance(obj[0], dict) else {}
    return {}


def extract_ids(body) -> set:
    """Every object id in a response (as strings). Handles collection lists/envelopes AND a bare detail dict
    (so a numeric detail id like {"id": 1} is picked up)."""
    out = set()
    items = _items(body)
    if not items:
        one = _one_object(body)
        if one:
            items = [one]
    for o in items:
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
    """A confirmed cross-user read: the attacker got a 2xx AND the response actually carries the target object
    id — proof it returned OWNER's object. Handles NUMERIC ids (bare, unquoted JSON) and string ids, and a
    bare detail dict (not just list/envelope)."""
    if not _2xx(attacker_status):
        return False
    oid = str(object_id)
    obj = _one_object(attacker_body)
    if isinstance(obj, dict) and obj:
        if _obj_id(obj) == oid:                       # the detail object's own id matches the target
            return True
        if any(str(v) == oid for v in obj.values()):  # the id appears as a real value
            return True
    if oid in extract_ids(attacker_body):
        return True
    # last resort: the id appears as a standalone JSON token (quoted string OR bare number), not a substring
    text = attacker_body if isinstance(attacker_body, str) else json.dumps(attacker_body, default=str)
    return bool(re.search(r'(?<![\w.\-])' + re.escape(oid) + r'(?![\w.\-])', text or ""))


# owner-attribution fields (who a returned object belongs to) + sensitive fields a shared listing should hide
_OWNER_FIELDS = ("owner", "user", "username", "userid", "user_id", "created_by", "author", "account", "email")
_SENSITIVE = ("secret", "password", "passwd", "token", "api_key", "apikey", "private_key", "privatekey",
              "ssn", "credit_card", "creditcard", "card_number", "cardnumber", "cvv", "pin", "salary",
              "dob", "security_answer", "securityanswer", "reset_token")


def _norm(k) -> str:
    return str(k).lower().replace("-", "_")


def _scheme(v) -> str:
    """The identifier scheme of a value: email / numeric / name — so we only compare like with like."""
    s = str(v)
    if "@" in s:
        return "email"
    if s.isdigit():
        return "numeric"
    return "name"


def _identity_set(attacker_identity) -> set:
    """Accept a single identifier or an iterable of them (email, username, numeric id, whoami…)."""
    if attacker_identity is None:
        return set()
    if isinstance(attacker_identity, str):
        return {attacker_identity} if attacker_identity else set()
    return {str(x) for x in attacker_identity if str(x) != ""}


def foreign_sensitive_read(status, detail_body, attacker_identity):
    """Cross-user SENSITIVE read (shared-listing APIs). `attacker_identity` is the reader's own identifier(s)
    (a string or an iterable of email/username/numeric-id). Returns {owner, sensitive_fields, confidence} or
    None. confidence is:
      * 'confirmed' — owner is a DIFFERENT principal we can compare (owner's scheme matches a reader id we
        hold), so it is provably foreign;
      * 'lead' — owner is not one of our ids but uses a scheme we DON'T hold for the reader (e.g. a numeric
        owner id when we only know the reader's email) so we cannot prove it is foreign — never a confirm.
    None when the object is the reader's own, or carries no sensitive field, or is not a 2xx. (Fixes the
    numeric-owner-vs-email false positive.)"""
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
    if not sens or owner is None:
        return None
    ids = _identity_set(attacker_identity)
    if owner in ids:
        return None                                   # the reader's OWN object — not BOLA
    comparable = any(_scheme(i) == _scheme(owner) for i in ids)
    return {"owner": owner, "sensitive_fields": sens,
            "confidence": "confirmed" if comparable else "lead"}


# ── canonical-schema-complete finding builders (list repro + impact + all required fields) ──
def foreign_finding(collection_path: str, object_id: str, hit: dict, attacker_role: str, target: str) -> dict:
    confirmed = (hit or {}).get("confidence", "confirmed") == "confirmed"
    return {
        "title": "Broken object-level authorization — cross-user sensitive data read",
        "family": "idor", "confidence": "confirmed" if confirmed else "lead",
        "severity": "high" if confirmed else "medium", "cwe": "CWE-639", "owasp": "A01:2021", "target": target,
        "tags": ["idor", "bola", "access-control", "read", "excessive-data-exposure"]
                + ([] if confirmed else ["needs-confirmation"]),
        "description": ("Persona '%s' read object %s at %s: the detail is attributed to a different user (%s) "
                        "and leaked sensitive field(s) %s that the shared listing did not expose%s."
                        % (attacker_role, object_id, target, (hit or {}).get("owner"),
                           ", ".join((hit or {}).get("sensitive_fields") or []),
                           "" if confirmed else " (owner attribution could not be normalized to a comparable "
                           "scheme — reported as a LEAD, not a confirmed finding)")),
        "reproduction_steps": [
            "Authenticate as two separate users (the reader and a victim).",
            "As the reader, GET the object detail at %s (an object owned by the victim)." % target,
            "Observe the response returns the victim's object including sensitive field(s): %s."
            % ", ".join((hit or {}).get("sensitive_fields") or []),
        ],
        "impact": ("Any authenticated user can read another user's sensitive data by object id — cross-user "
                   "information disclosure, mass exfiltration by walking ids."),
        "evidence": "foreign owner=%s, leaked fields=%s" % ((hit or {}).get("owner"),
                                                            (hit or {}).get("sensitive_fields")),
        "false_positive_check": ("confirmed only when the object is attributed to a principal of a scheme we "
                                 "hold for the reader and it differs — otherwise a lead, never a false confirm."),
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
        "reproduction_steps": [
            "Authenticate as two separate users (owner '%s' and attacker '%s')." % (owner_role, attacker_role),
            "As the owner, list the collection %s and note an object id absent from the attacker's own list."
            % collection_path,
            "As the attacker, GET %s and observe the owner's object is returned." % target,
        ],
        "impact": ("Any authenticated user can read another user's object by id — cross-user data disclosure "
                   "and bulk exfiltration by walking ids."),
        "evidence": "owner-only id %s at %s readable by a different authenticated user" % (object_id, collection_path),
        "false_positive_check": ("owner_only ids are provably absent from the attacker's own listing, and the "
                                 "attacker's 2xx response carried the target id — no similarity guessing."),
        "remediation": "Enforce per-request object-ownership checks server-side; do not authorize by id alone.",
    }
