"""Evidence dossier (#123): poc_bundle now composes standards (CWE/OWASP/CAPEC + ASVS + WSTG), the attack
path (enables + chains), and fix priority — the unified per-finding proof, from existing primitives."""
import poc_bundle as PB


_IDOR = {"id": "F1", "title": "BOLA read", "family": "idor", "severity": "high", "confidence": "confirmed",
         "cwe": "CWE-639", "owasp": "A01:2021", "target": "http://app/api/orders/2",
         "evidence": "user_b read user_a order", "oracle": "ownership differential",
         "reproduction_steps": ["login as two users", "read the other's order"], "remediation": "check ownership"}


def test_standards_maps_asvs_and_carries_cwe():
    s = PB.standards(_IDOR)
    assert s["cwe"] == "CWE-639" and s["owasp"] == "A01:2021"
    cids = {a["cid"] for a in s.get("asvs", [])}
    # the #11 umbrella fix means an idor violates BOTH the specific and the umbrella access-control objective
    assert "ATHZ-01" in cids and "ATHZ-00" in cids
    assert all(a.get("requirement") for a in s["asvs"])       # each ASVS objective carries its requirement text


def test_attack_path_enables_and_chains():
    ap = PB.attack_path(_IDOR, chains=[{"title": "IDOR -> account takeover", "steps": ["read order 2"]}])
    assert "other users" in ap["enables"]
    assert ap["in_chains"] == ["IDOR -> account takeover"]     # the chain referencing this family is attached
    # no chains -> still returns the class-level escalation, empty chain list
    assert PB.attack_path(_IDOR, chains=[])["in_chains"] == []


def test_build_is_a_complete_dossier():
    b = PB.build(_IDOR, exchanges=[], target="http://app")
    # the unified dossier carries every moat primitive
    for k in ("finding", "reproduction", "confirmation", "impact", "attack_path", "standards",
              "retest", "fix_priority", "remediation", "provenance"):
        assert k in b, "dossier missing %s" % k
    assert b["confirmation"]["negative_control"]              # the FP-safety proof is present
    assert b["fix_priority"]["tier"] == "fix_now"             # confirmed high -> Fix Now
    assert b["standards"]["cwe"] == "CWE-639"


def test_build_all_only_confirmed_and_threads_chains():
    findings = [_IDOR, {"id": "L1", "family": "xss", "confidence": "lead", "severity": "high"}]
    bundles = PB.build_all(findings, chains=[{"title": "chain X"}])
    assert len(bundles) == 1 and bundles[0]["finding"]["id"] == "F1"   # the lead is excluded
