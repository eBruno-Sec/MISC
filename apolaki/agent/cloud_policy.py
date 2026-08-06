"""First-class cloud provider-policy / authorization gate (Codex cross-check Tier-1 #4).

The cloud books' key point ordinary scanners miss: cloud scope is EXECUTABLE POLICY. Subscription/account/
project ownership, allowed regions, allowed actions, and provider-notification requirements gate what a cloud
test may do — a mis-scoped test can hit another customer or provider-owned surface. Apolaki already has
cloud_intel/cloud_iam; this adds the POLICY OBJECT that gates cloud actions BEFORE they run.

Design that respects the existing authorized Linode read-only flow (operator put a READ-ONLY token in scope =
authorization for read-only inventory) while genuinely hardening everything else:

  * DEFAULT policy permits ONLY read-only inventory actions and default-DENIES every mutating/active action.
    So a live read-only posture keeps working, but any write / active-probe / destructive / brute action is
    blocked unless an EXPLICIT policy (env APOLAKI_CLOUD_POLICY -> JSON, or a mission-supplied dict) grants it.
  * PROHIBITED wins over allowed. Provider-notification-required blocks until status == "provided". Actions in
    requires_approval are blocked unless an approval id is supplied. Provider/region scope is enforced.

This module NEVER makes a cloud call — it only decides allow/deny. cloud_iam.collect() consults it.
"""
from __future__ import annotations

import json
import os

READ_ONLY_ACTIONS = ("read_inventory", "read_iam", "read_storage_acl", "read_config", "list")

DEFAULT_POLICY = {
    "provider": "any",
    "tenant_id": "", "subscription_ids": [], "account_ids": [], "project_ids": [],
    "regions": [],                                   # empty => region scoping not enforced
    "authorized_services": [],
    "allowed_actions": list(READ_ONLY_ACTIONS),
    "requires_approval": ["active_probe", "write_validation"],
    "prohibited_actions": ["destructive_write", "write", "delete", "dos", "credential_bruteforce"],
    "provider_notification": {"required": False, "status": "not_required"},
    "source": "apolaki_default_readonly",
}


def _norm(v) -> set:
    return {str(x).strip().lower() for x in (v or []) if str(x).strip()}


def load_policy_file(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def effective_policy(provider: str = None) -> dict:
    """The policy in force. An explicit policy at env APOLAKI_CLOUD_POLICY (a JSON file) wins — it may be a
    single policy object or a {provider: policy} map. Otherwise the read-only default (mutating actions
    default-denied). Never raises; a broken policy file falls back to the safe default."""
    path = os.environ.get("APOLAKI_CLOUD_POLICY", "").strip()
    if path and os.path.exists(path):
        try:
            data = load_policy_file(path)
            if isinstance(data, dict) and "allowed_actions" not in data and provider:
                # a {provider: policy} map
                pol = data.get((provider or "").lower()) or data.get("any")
                if isinstance(pol, dict):
                    return pol
            if isinstance(data, dict) and "allowed_actions" in data:
                return data
        except Exception:
            pass
    return dict(DEFAULT_POLICY)


def _decision(allowed: bool, action: str, provider: str, reason: str, **extra) -> dict:
    d = {"allowed": bool(allowed), "action": action, "provider": provider, "reason": reason,
         "requires_approval": False}
    d.update(extra)
    return d


def gate(provider: str, action: str, *, policy: dict = None, region: str = None, approval: str = None) -> dict:
    """Decide whether `action` on `provider` is authorized. Returns a decision dict {allowed, reason, action,
    provider, requires_approval, ...}. Precedence: provider scope -> region scope -> PROHIBITED (wins) ->
    notification-required -> requires-approval -> allowed -> default-DENY."""
    pol = policy or effective_policy(provider)
    prov = (provider or "").strip().lower()
    act = (action or "").strip().lower()
    pol_prov = str(pol.get("provider") or "any").strip().lower()
    src = pol.get("source") or "explicit"

    if pol_prov not in ("any", prov):
        return _decision(False, act, prov, "policy authorizes provider '%s', not '%s'" % (pol_prov, prov),
                         policy_source=src)

    regions = _norm(pol.get("regions"))
    if region and regions and str(region).strip().lower() not in regions:
        return _decision(False, act, prov, "region '%s' is not in the authorized regions" % region,
                         policy_source=src)

    if act in _norm(pol.get("prohibited_actions")):
        return _decision(False, act, prov, "action '%s' is PROHIBITED by policy" % act, policy_source=src)

    notif = pol.get("provider_notification") or {}
    if notif.get("required") and str(notif.get("status") or "").lower() != "provided":
        return _decision(False, act, prov, "provider notification is required but not provided",
                         policy_source=src)

    if act in _norm(pol.get("requires_approval")):
        if not approval:
            return _decision(False, act, prov, "action '%s' requires approval (none supplied)" % act,
                             requires_approval=True, policy_source=src)
        return _decision(True, act, prov, "approved: %s" % approval, requires_approval=True,
                         approval_id=str(approval), policy_source=src)

    if act in _norm(pol.get("allowed_actions")):
        return _decision(True, act, prov, "action '%s' is allowed by policy" % act, policy_source=src)

    return _decision(False, act, prov, "action '%s' is not in allowed_actions (default-deny)" % act,
                     policy_source=src)


def summary(provider: str = None) -> dict:
    """Inspectable view of the effective policy for a provider (for the /cloud/policy endpoint)."""
    pol = effective_policy(provider)
    return {"provider_scope": pol.get("provider", "any"), "source": pol.get("source", "explicit"),
            "allowed_actions": pol.get("allowed_actions", []),
            "requires_approval": pol.get("requires_approval", []),
            "prohibited_actions": pol.get("prohibited_actions", []),
            "regions": pol.get("regions", []),
            "provider_notification": pol.get("provider_notification", {}),
            "note": ("Default read-only policy in force — only read-only inventory is permitted; every "
                     "mutating/active/destructive cloud action is default-denied until an explicit policy "
                     "(APOLAKI_CLOUD_POLICY) grants it." if pol.get("source") == "apolaki_default_readonly"
                     else "Explicit operator cloud policy in force.")}
