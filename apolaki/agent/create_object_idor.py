"""
Create-object IDOR/BOLA confirmation (CHAD re-audit C) — pure oracle.

The strongest IDOR proof does not rely on similarity heuristics: the victim persona CREATES a
uniquely-owned object (carrying a random marker we chose), then the attacker persona tries to
read / update / delete it by id. Because WE created the object as the victim, ownership is
DEFINITIVE — no "maybe it's a shared resource" ambiguity. A cross-persona hit on that exact
object is a confirmed access-control break.

This module is the pure decision layer: extract the created object's id, and judge each
attacker action against the marker + status. The live HTTP (create as owner, act as attacker,
clean up) runs in the tool that imports this. No network here → fully unit-testable.

ID shapes handled: numeric ids, UUIDs, string ids, and ids embedded in a Location header or a
JSON body under common keys (id, _id, uuid, ...) or a REST resource path.
"""
from __future__ import annotations

import json
import re

_ID_KEYS = ("id", "_id", "uuid", "objectId", "object_id", "pk", "key")
_UUID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I)


def new_marker() -> str:
    """A unique, greppable marker to stamp into the created object so we can PROVE the attacker read
    OUR object, not merely 'an' object. Also makes created test data easy to identify + clean up."""
    import secrets
    return "apolaki_idor_%s" % secrets.token_hex(6)


def extract_id(status, body: str, location: str = "") -> str:
    """Best-effort id of a just-created object, from a Location header, a JSON body (common id keys,
    else the first UUID / integer), or an empty string when none is found."""
    if location:
        m = re.search(r"/([A-Za-z0-9_-]{1,64})/?$", location.strip())
        if m:
            return m.group(1)
    try:
        obj = json.loads(body or "")
        # unwrap common {data: {...}} / {result: {...}} envelopes
        for wrap in ("data", "result", "object"):
            if isinstance(obj, dict) and isinstance(obj.get(wrap), dict):
                obj = obj[wrap]
        if isinstance(obj, dict):
            for k in _ID_KEYS:
                if obj.get(k) not in (None, "", []):
                    return str(obj[k])
    except Exception:
        pass
    m = _UUID_RE.search(body or "")
    if m:
        return m.group(0)
    m = re.search(r'"(?:id|_id)"\s*:\s*"?(\d+)', body or "")
    return m.group(1) if m else ""


def _accessed(status) -> bool:
    """A status that means the server served the resource (not an auth/again-missing wall)."""
    try:
        s = int(status)
    except Exception:
        return False
    return 200 <= s < 300


def verdict(*, marker: str, create_status, create_body: str, object_id: str,
            read_status=None, read_body: str = "", write_status=None,
            delete_status=None) -> dict:
    """Judge the create-object IDOR attempt. `created` requires a 2xx create carrying OUR marker +
    an id. A confirmed READ requires the attacker's response to contain the exact marker (proof it is
    OUR object). Confirmed WRITE/DELETE require the attacker action to be ACCEPTED (2xx) on our object.
    Returns {created, confirmed_read, confirmed_write, confirmed_delete, evidence}."""
    created = _accessed(create_status) and bool(object_id) and (marker in (create_body or ""))
    out = {"created": created, "object_id": object_id,
           "confirmed_read": False, "confirmed_write": False, "confirmed_delete": False, "evidence": ""}
    if not created:
        out["evidence"] = "object not created as owner (status=%s, id=%s, marker_present=%s)" % (
            create_status, object_id, marker in (create_body or ""))
        return out
    ev = []
    if read_status is not None and _accessed(read_status) and marker in (read_body or ""):
        out["confirmed_read"] = True
        ev.append("attacker READ object %s -> %s and it carried OUR marker %s (owner-created)"
                  % (object_id, read_status, marker))
    if write_status is not None and _accessed(write_status):
        out["confirmed_write"] = True
        ev.append("attacker WROTE object %s -> %s (owner-created object mutated cross-user)" % (object_id, write_status))
    if delete_status is not None and _accessed(delete_status):
        out["confirmed_delete"] = True
        ev.append("attacker DELETED object %s -> %s (owner-created object removed cross-user)" % (object_id, delete_status))
    out["evidence"] = "; ".join(ev) if ev else ("attacker could not access owner-created object %s" % object_id)
    return out


def to_finding(v: dict, target: str, owner_role: str, attacker_role: str) -> dict:
    """Build a CONFIRMED access-control finding from a positive verdict (ownership is definitive:
    the object was created by the owner with our marker). Returns None if nothing was confirmed."""
    if not (v.get("confirmed_read") or v.get("confirmed_write") or v.get("confirmed_delete")):
        return None
    ops = [k.split("_", 1)[1] for k in ("confirmed_read", "confirmed_write", "confirmed_delete") if v.get(k)]
    sev = "critical" if (v.get("confirmed_write") or v.get("confirmed_delete")) else "high"
    return {
        "title": "IDOR / BOLA confirmed via owned-object creation (%s)" % "+".join(ops),
        "severity": sev, "family": "idor", "confidence": "confirmed", "cwe": "CWE-639", "target": target,
        "tags": ["idor", "bola", "access-control", "created-object-proof"] + ops,
        "description": ("Persona '%s' created a uniquely-owned object; persona '%s' then %s it by id. "
                        "Ownership is definitive (we created it with a private marker), so this is a "
                        "confirmed cross-user access-control break." % (owner_role, attacker_role, "/".join(ops))),
        "impact": "Any user can access/modify other users' objects by id — bulk exfiltration or tampering by walking ids.",
        "evidence": "created object %s as '%s'; %s" % (v.get("object_id"), owner_role, v.get("evidence")),
        "reproduction_steps": ("1) log in as two users; 2) as owner POST the create endpoint with a marker; "
                               "3) as attacker GET/PUT/DELETE the returned id; 4) observe the marker / accepted write."),
        "remediation": "Enforce object-level authorization on every read/write: verify the session owns the id server-side.",
    }
