"""Field-level authorization + excessive-data-exposure diffing (Codex cross-check Tier-2 #9).

Apolaki has strong IDOR/BOLA/BFLA (object-level) foundations. This adds the SEPARATE, high-value check the
API books emphasize: object-PROPERTY authorization. Sometimes a persona reads the CORRECT object but the
response leaks fields it should never see (admin flags, role/permissions, payment/PII, backend-only or debug
fields). That is not BOLA — it is field-level over-exposure.

RAILS:
  * Distinct from BOLA: own-resource field exposure is NOT cross-object access.
  * Unauthenticated access is treated separately from field-level authz.
  * A differential across two personas is 'lead' unless there is a clear role expectation / hard admin
    marker, in which case it is a 'finding'. Conservative sensitive-field markers only.
  * Raw secret VALUES are redacted — only field NAMES + redacted evidence leave.
Pure + offline (operates on already-fetched JSON responses).
"""
from __future__ import annotations

# hard markers a normal user should generally never receive
_ADMIN_ONLY = {"is_admin", "isadmin", "role", "roles", "permissions", "perms", "tenant_id", "tenantid",
               "cost_price", "costprice", "internal", "is_staff", "account_type"}
# backend/debug fields that should not be in a normal API response
_DEBUG = {"debug", "stack", "stacktrace", "stack_trace", "trace", "sql", "query", "_raw", "backtrace"}
# secret/PII field names whose mere presence in a response is exposure
_SECRET = {"password", "password_hash", "passwordhash", "reset_token", "resettoken", "mfa_secret",
           "mfasecret", "api_key", "apikey", "secret", "private_key", "privatekey", "ssn",
           "credit_card", "creditcard", "card_number", "cardnumber", "cvv", "token"}
SENSITIVE_FIELDS = _ADMIN_ONLY | _DEBUG | _SECRET


def _norm(k: str) -> str:
    return str(k or "").strip().lower().replace("-", "_")


def _redact(v) -> str:
    s = str(v)
    return s if len(s) <= 8 else "%s…%s" % (s[:2], s[-2:])


def field_paths(obj, prefix: str = "") -> list:
    """Recursively collect (dotted_path, key, value) for every leaf/dict key in a JSON-like object."""
    out = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            path = "%s.%s" % (prefix, k) if prefix else str(k)
            out.append((path, _norm(k), v))
            out.extend(field_paths(v, path))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            out.extend(field_paths(v, "%s[%d]" % (prefix, i)))
    return out


def _classify(key: str) -> str:
    if key in _SECRET:
        return "secret"
    if key in _ADMIN_ONLY:
        return "admin_only"
    if key in _DEBUG:
        return "debug"
    return ""


def excessive_data_exposure(response, *, role: str = "user", authenticated: bool = True,
                            own_resource: bool = True) -> dict:
    """Flag a SINGLE response that carries sensitive/admin/debug/secret fields (excessive data exposure).
    Distinct from BOLA (own_resource=True => not cross-object). Returns None if nothing sensitive is present.
    Raw values are redacted; only field names + redacted evidence are reported."""
    exposed = []
    for path, key, val in field_paths(response):
        cls = _classify(key)
        if cls:
            exposed.append({"field": path, "category": cls, "evidence": _redact(val)})
    if not exposed:
        return None
    has_secret = any(e["category"] == "secret" for e in exposed)
    return {
        "family": "excessive_data_exposure",
        "confidence": "lead", "authenticated": bool(authenticated), "own_resource": bool(own_resource),
        "severity": "high" if has_secret else "medium",
        "exposed_fields": exposed, "role": role,
        "note": ("Response exposes sensitive/admin/debug fields — excessive data exposure. This is a "
                 "field-level exposure, NOT cross-object BOLA; confirm the field should be hidden for this role."),
    }


def field_authz_diff(low_response, high_response, *, low_role: str = "user", high_role: str = "admin") -> list:
    """Differential field-level authorization across two personas on the SAME object. Flags sensitive/admin
    fields the LOWER-privileged persona receives. Same role => no differential (returns []). A hard admin/
    secret marker for a non-admin low role is a 'finding'; otherwise a 'lead'. Redacted evidence only."""
    if _norm(low_role) == _norm(high_role):
        return []                                           # cannot establish a privilege differential
    low_non_admin = _norm(low_role) not in ("admin", "administrator", "superadmin", "root", "staff")
    out = []
    for path, key, val in field_paths(low_response):
        cls = _classify(key)
        if not cls:
            continue
        hard = cls in ("admin_only", "secret")
        out.append({
            "family": "field_level_authorization", "field": path, "category": cls,
            "exposed_to_role": low_role, "should_be_role": high_role,
            "confidence": "finding" if (hard and low_non_admin) else "lead",
            "evidence": _redact(val),
            "note": ("Lower-privileged persona '%s' receives a %s field that should be restricted to '%s'."
                     % (low_role, cls, high_role)),
        })
    return out
