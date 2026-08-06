"""Active Directory / Windows frontier — MODELED read-only before exploited (Codex cross-check Tier-3 #13).

The AD/Kerberos/ADCS material is high-impact but most of it needs a real authorized domain (a DC, credentials,
an IdP). Apolaki should NOT pretend to cover that from black-box context. The correct upgrade is to MODEL the
frontier and add read-only inventory where safe — and keep everything beyond read-only BLOCKED until an
authorized lab exists.

Already present in Apolaki (read-only): LDAP anonymous read, LDAP injection, SMB null session, SMB signing
audit, RDP NLA audit. This module adds the read-only CONTEXT model (domain/forest/DC/naming-context/SPN
inventory/CA presence/SMB-relay risk observation) and the honest capability gate.
Pure + offline.
"""
from __future__ import annotations

# capabilities Apolaki may perform read-only right now
READONLY_CAPS = {"ldap_read", "smb_enum", "spn_inventory", "ca_presence", "naming_context_enum",
                 "smb_relay_risk_observation", "rdp_nla_audit", "domain_model"}
# authenticated AD attacks that stay BLOCKED until an authorized DC lab exists
BLOCKED_UNTIL_LAB = {"kerberoast", "asreproast", "dcsync", "ntlm_relay", "pass_the_hash",
                     "golden_ticket", "silver_ticket", "adcs_esc1", "adcs_esc8", "sccm_takeover",
                     "wsus_abuse", "exchange_privesc", "unconstrained_delegation_abuse"}


def model_domain(facts: dict) -> dict:
    """Build a read-only AD domain model from LDAP/SMB facts. Forest defaults to the domain; nothing here is
    an attack — it is inventory the planner can reason over."""
    f = facts or {}
    domain = str(f.get("domain") or "").lower()
    return {
        "domain": domain, "forest": str(f.get("forest") or domain).lower(),
        "domain_controllers": list(f.get("dcs") or f.get("domain_controllers") or []),
        "naming_contexts": list(f.get("naming_contexts") or []),
        "functional_level": f.get("functional_level"),
        "source": "ldap_readonly", "kind": "ad_domain_model",
    }


def spn_inventory(ldap_entries: list) -> dict:
    """Collect servicePrincipalName values as INVENTORY (not Kerberoasting). SPN presence is a fact; extracting
    or cracking service tickets is BLOCKED until a lab."""
    spns, accounts = [], []
    for e in ldap_entries or []:
        sp = (e or {}).get("servicePrincipalName") or (e or {}).get("spn")
        vals = sp if isinstance(sp, list) else ([sp] if sp else [])
        if vals:
            accounts.append((e or {}).get("sAMAccountName") or (e or {}).get("cn") or (e or {}).get("name"))
            for v in vals:
                if v and v not in spns:
                    spns.append(v)
    return {"kind": "spn_inventory", "spns": spns, "accounts_with_spn": [a for a in accounts if a],
            "confidence": "observation",
            "note": "SPN inventory only — Kerberoasting (service-ticket extraction) is blocked until a lab."}


def smb_relay_risk(smb_signing_required) -> dict:
    """SMB signing NOT required => NTLM-relay risk OBSERVATION (not an executed relay)."""
    if smb_signing_required:
        return None
    return {"kind": "smb_relay_risk", "confidence": "observation", "family": "ad_context",
            "note": "SMB signing not required — NTLM relay is a RISK to review; relaying itself is blocked "
                    "until an authorized lab exists."}


def ca_presence(ldap_entries: list) -> dict:
    """Detect an ADCS Certificate Authority from LDAP objects (pKIEnrollmentService / Enrollment Services).
    Presence is inventory; ADCS ESC abuse is blocked until a lab."""
    cas = []
    for e in ldap_entries or []:
        oc = " ".join(str(x) for x in ((e or {}).get("objectClass") or [])).lower()
        cn = str((e or {}).get("cn") or (e or {}).get("name") or "")
        if "pkienrollmentservice" in oc or "enrollment service" in cn.lower():
            if cn and cn not in cas:
                cas.append(cn)
    if not cas:
        return None
    return {"kind": "ca_presence", "certificate_authorities": cas, "confidence": "observation",
            "note": "ADCS CA present — certificate-template (ESC) assessment is blocked until a lab."}


def is_capability_allowed(capability: str):
    """Gate an AD capability. Read-only inventory is allowed; authenticated AD attacks are blocked until an
    authorized DC lab exists. Returns (allowed: bool, reason: str)."""
    cap = (capability or "").strip().lower()
    if cap in READONLY_CAPS:
        return True, "read-only AD inventory — allowed"
    if cap in BLOCKED_UNTIL_LAB:
        return False, "authenticated AD attack — BLOCKED until an authorized domain-controller lab exists"
    return False, "unknown AD capability — blocked by default"


def frontier() -> dict:
    """Honest map of what is read-only-present vs environment-gated (blocked until a lab)."""
    return {"present_readonly": sorted(READONLY_CAPS), "blocked_until_lab": sorted(BLOCKED_UNTIL_LAB),
            "note": "AD frontier is modeled read-only; everything beyond inventory is gated on an authorized "
                    "domain-controller lab (never run from black-box context)."}
