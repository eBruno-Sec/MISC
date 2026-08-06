"""Durable, idempotent action envelope (Codex cross-check Tier-3 #11).

The RedCyber/ArsGoatia architecture material pushes durable, resumable, replay-safe orchestration. The
minimum useful slice (short of installing Temporal): an ENVELOPE every side-effecting tool carries and that
is checked immediately before any side effect.

Guarantees:
  * Deterministic idempotency_key from (mission, tool, input_hash, scope_hash) — retries reuse the same key.
  * An approval is bound to a specific input+scope: if either CHANGES, the prior approval is invalidated.
  * An INTRUSIVE action without a valid approval is rejected before it can run.
  * Raw secrets (Authorization / Cookie / tokens / passwords) NEVER enter the envelope — only hashes of
    secret-stripped input/scope are stored.
  * Failed/cancelled actions keep a visible status (never silently dropped).
Pure + offline.
"""
from __future__ import annotations

import hashlib
import json
import time
import uuid

PERMISSIONS = ("PASSIVE", "ACTIVE", "INTRUSIVE")
STATUSES = ("created", "approved", "executed", "failed", "cancelled", "rejected")
_SECRET_KEYS = ("authorization", "cookie", "set-cookie", "token", "password", "passwd", "secret",
                "api_key", "apikey", "x-api-key", "bearer", "session", "csrf")


def _strip_secrets(obj):
    """Recursively drop any key whose name looks secret — so no raw credential can enter the envelope."""
    if isinstance(obj, dict):
        return {k: _strip_secrets(v) for k, v in obj.items()
                if not any(tok in str(k).lower() for tok in _SECRET_KEYS)}
    if isinstance(obj, list):
        return [_strip_secrets(v) for v in obj]
    return obj


def _hash(obj) -> str:
    canon = json.dumps(_strip_secrets(obj), sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canon.encode("utf-8", "replace")).hexdigest()[:16]


def idempotency_key(mission_id: str, tool: str, input_hash: str, scope_hash: str) -> str:
    return hashlib.sha256(("%s|%s|%s|%s" % (mission_id, tool, input_hash, scope_hash))
                          .encode("utf-8")).hexdigest()[:16]


def make_envelope(mission_id: str, tool: str, inputs, scope, *, permission: str = "ACTIVE",
                  requires_approval: bool = None, approval_id: str = None) -> dict:
    """Mint an action envelope. INTRUSIVE defaults to requires_approval=True. Stores ONLY hashes of
    secret-stripped input/scope — never raw inputs."""
    perm = str(permission or "ACTIVE").upper()
    if perm not in PERMISSIONS:
        perm = "ACTIVE"
    ih, sh = _hash(inputs), _hash(scope)
    ra = requires_approval if requires_approval is not None else (perm == "INTRUSIVE")
    return {
        "mission_id": mission_id, "action_id": uuid.uuid4().hex[:12], "tool": tool,
        "permission": perm, "scope_hash": sh, "input_hash": ih,
        "requires_approval": bool(ra), "approval_id": approval_id,
        "idempotency_key": idempotency_key(mission_id, tool, ih, sh),
        "status": "created", "created_at": _now(),
    }


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def authorize(envelope: dict, approval_id: str = None) -> dict:
    """Attach an approval. An INTRUSIVE / requires_approval envelope without an approval id stays rejected."""
    env = dict(envelope or {})
    if env.get("requires_approval") and not approval_id:
        env["status"] = "rejected"
        return {"allowed": False, "reason": "action requires approval (none supplied)", "envelope": env}
    if approval_id:
        env["approval_id"] = str(approval_id)
        env["status"] = "approved"
    return {"allowed": True, "reason": "authorized", "envelope": env}


def validate_before_execute(envelope: dict, current_scope, current_inputs, approval_id: str = None) -> dict:
    """The check every side-effecting tool runs immediately before the side effect. Rejects when scope or
    input changed since the envelope was minted (prior approval invalidated), or when an approval is required
    but absent."""
    env = envelope or {}
    if _hash(current_scope) != env.get("scope_hash"):
        return {"allowed": False, "reason": "scope changed since approval — prior approval invalidated"}
    if _hash(current_inputs) != env.get("input_hash"):
        return {"allowed": False, "reason": "input changed since approval — prior approval invalidated"}
    if env.get("requires_approval") and not (approval_id or env.get("approval_id")):
        return {"allowed": False, "reason": "intrusive/approval-required action has no valid approval"}
    return {"allowed": True, "reason": "envelope valid; scope + input unchanged"}


def mark(envelope: dict, status: str) -> dict:
    """Transition status (executed/failed/cancelled) — failed/cancelled remain visible, never dropped."""
    env = dict(envelope or {})
    env["status"] = status if status in STATUSES else env.get("status", "created")
    env["updated_at"] = _now()
    return env
