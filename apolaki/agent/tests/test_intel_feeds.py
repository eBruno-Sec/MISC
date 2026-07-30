"""Tests for the deterministic offensive intel feeds (Phase 0): pure parsers + enrichment, no network."""
from __future__ import annotations

import json

import intel_feeds

_KEV = json.dumps({
    "catalogVersion": "2026.07.29", "count": 3,
    "vulnerabilities": [
        {"cveID": "CVE-2014-6271", "vendorProject": "GNU", "product": "Bash", "dateAdded": "2021-11-03",
         "knownRansomwareCampaignUse": "Known", "cwes": ["CWE-78"]},
        {"cveID": "CVE-2016-2386", "vendorProject": "SAP", "product": "NetWeaver", "dateAdded": "2022-01-01",
         "knownRansomwareCampaignUse": "Unknown", "cwes": ["CWE-89"]},
        {"cveID": "CVE-2020-0001", "vendorProject": "x", "product": "y", "dateAdded": "2020-01-01",
         "knownRansomwareCampaignUse": "Unknown"},   # no cwes -> excluded from by_cwe
    ],
})

_CAPEC = json.dumps({"objects": [
    {"type": "attack-pattern", "name": "SQL Injection",
     "external_references": [{"source_name": "capec", "external_id": "CAPEC-66"},
                             {"source_name": "cwe", "external_id": "CWE-89"}],
     "x_capec_typical_severity": "High", "x_capec_likelihood_of_attack": "High"},
    {"type": "attack-pattern", "name": "Deprecated one", "x_capec_status": "Deprecated",
     "external_references": [{"source_name": "capec", "external_id": "CAPEC-999"},
                             {"source_name": "cwe", "external_id": "CWE-89"}]},
    {"type": "identity", "name": "not an attack pattern"},
]})

_ATTACK = json.dumps({"objects": [
    {"type": "attack-pattern", "name": "Exploit Public-Facing Application",
     "external_references": [{"source_name": "mitre-attack", "external_id": "T1190"}],
     "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "initial-access"}]},
    {"type": "attack-pattern", "name": "revoked", "revoked": True,
     "external_references": [{"source_name": "mitre-attack", "external_id": "T9999"}]},
]})


def test_parse_kev():
    k = intel_feeds.parse_kev(_KEV)
    assert k["catalog_version"] == "2026.07.29"
    assert k["cwes"]["CWE-78"] == ["CVE-2014-6271"]
    assert k["cwes"]["CWE-89"] == ["CVE-2016-2386"]
    assert "CVE-2020-0001" not in [c for cs in k["cwes"].values() for c in cs]   # no-cwe entry not mapped
    assert k["cves_meta"]["CVE-2014-6271"]["ransomware"] is True
    assert k["cves_meta"]["CVE-2016-2386"]["ransomware"] is False


def test_parse_capec_skips_deprecated():
    c = intel_feeds.parse_capec(_CAPEC)
    assert "CAPEC-66" in c["patterns"] and "CAPEC-999" not in c["patterns"]
    assert c["patterns"]["CAPEC-66"]["severity"] == "High"
    assert c["cwes"]["CWE-89"] == ["CAPEC-66"]


def test_parse_attack_skips_revoked():
    a = intel_feeds.parse_attack(_ATTACK)
    assert "T1190" in a["techniques"] and "T9999" not in a["techniques"]
    assert a["techniques"]["T1190"]["tactics"] == ["initial-access"]


def test_enrich_flags_known_exploited_and_capec():
    snaps = {"kev": intel_feeds.parse_kev(_KEV), "capec": intel_feeds.parse_capec(_CAPEC)}
    techs = [{"id": "sqli", "cwe": "CWE-89"}, {"id": "cmdi", "cwe": "CWE-78"}, {"id": "logic", "cwe": "CWE-840"}]
    enr = intel_feeds.enrich_techniques(techs, snaps)
    assert enr["sqli"]["known_exploited"] is True and enr["sqli"]["kev_cves"] == ["CVE-2016-2386"]
    assert [c["id"] for c in enr["sqli"]["capec"]] == ["CAPEC-66"]
    assert enr["cmdi"]["known_exploited"] is True and enr["cmdi"]["kev_ransomware"] is True
    assert enr["logic"]["known_exploited"] is False and enr["logic"]["capec"] == []   # unmapped CWE stays clean


def test_enrich_degrades_without_snapshots():
    enr = intel_feeds.enrich_techniques([{"id": "sqli", "cwe": "CWE-89"}], {})
    assert enr["sqli"]["known_exploited"] is False and enr["sqli"]["capec"] == []


def test_norm_cwe():
    assert intel_feeds._norm_cwe("cwe-89") == "CWE-89"
    assert intel_feeds._norm_cwe("89") == "CWE-89"
    assert intel_feeds._norm_cwe("CWE-89 ") == "CWE-89"
    assert intel_feeds._norm_cwe("garbage") == "" and intel_feeds._norm_cwe(None) == ""
