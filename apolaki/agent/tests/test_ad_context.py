"""AD frontier modeled read-only (Codex Tier-3 #13): domain model + SPN/CA inventory + SMB-relay risk are
read-only observations; authenticated AD attacks (Kerberoast/ADCS/DCSync/...) stay BLOCKED until a lab."""
import ad_context as A


def test_model_domain_from_readonly_facts():
    m = A.model_domain({"domain": "CORP.LOCAL", "dcs": ["dc1.corp.local"],
                        "naming_contexts": ["DC=corp,DC=local"]})
    assert m["domain"] == "corp.local" and m["forest"] == "corp.local"
    assert m["domain_controllers"] == ["dc1.corp.local"] and m["source"] == "ldap_readonly"


def test_spn_inventory_is_observation_not_kerberoast():
    entries = [{"sAMAccountName": "svc-sql", "servicePrincipalName": ["MSSQLSvc/db.corp.local:1433"]},
               {"sAMAccountName": "user1"}]
    inv = A.spn_inventory(entries)
    assert inv["spns"] == ["MSSQLSvc/db.corp.local:1433"] and inv["accounts_with_spn"] == ["svc-sql"]
    assert inv["confidence"] == "observation" and "blocked" in inv["note"].lower()


def test_smb_signing_disabled_is_relay_risk_observation():
    assert A.smb_relay_risk(smb_signing_required=True) is None
    r = A.smb_relay_risk(smb_signing_required=False)
    assert r["kind"] == "smb_relay_risk" and r["confidence"] == "observation"


def test_adcs_ca_presence_detected():
    entries = [{"cn": "CORP-CA", "objectClass": ["top", "pKIEnrollmentService"]},
               {"cn": "Users", "objectClass": ["container"]}]
    ca = A.ca_presence(entries)
    assert ca["certificate_authorities"] == ["CORP-CA"] and ca["confidence"] == "observation"
    assert A.ca_presence([{"cn": "Users", "objectClass": ["container"]}]) is None


def test_authenticated_ad_attacks_blocked_until_lab():
    for cap in ("kerberoast", "asreproast", "dcsync", "adcs_esc1", "ntlm_relay"):
        allowed, reason = A.is_capability_allowed(cap)
        assert allowed is False and "lab" in reason.lower()


def test_readonly_inventory_capabilities_allowed():
    for cap in ("ldap_read", "smb_enum", "spn_inventory", "ca_presence"):
        allowed, _ = A.is_capability_allowed(cap)
        assert allowed is True
    assert A.is_capability_allowed("totally_unknown")[0] is False


def test_frontier_separates_present_from_gated():
    fr = A.frontier()
    assert "kerberoast" in fr["blocked_until_lab"] and "ldap_read" in fr["present_readonly"]
    assert set(fr["present_readonly"]).isdisjoint(fr["blocked_until_lab"])
