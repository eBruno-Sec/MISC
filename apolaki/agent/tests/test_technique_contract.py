"""Executable-knowledge proof contract (#115, Nuclei-style).

Every technique carries an EXPLICIT false-positive-safety negative control + evidence obligations,
machine-checkable instead of buried in engine code. Proven techniques must declare a real contract.
This guard is what keeps 'we have an oracle' honest: a new technique that ships without a declared
differential + evidence requirements fails here.
"""
import techniques as T
import technique_model as TM


def test_every_technique_record_carries_a_contract():
    for tid, rec in T.TECHNIQUES.items():
        assert rec.get("negative_control"), "%s: empty negative_control" % tid
        ev = rec.get("evidence_requirements")
        assert isinstance(ev, list) and ev, "%s: no evidence_requirements" % tid
        assert rec.get("safety") in ("active-safe", "operator-gated", "passive-readonly"), tid
        assert rec.get("replayable") is True, tid
        assert rec.get("cleanup"), tid


def test_proven_techniques_declare_real_proof_obligations():
    proven = [r for r in T.TECHNIQUES.values() if r.get("validated_on")]
    assert len(proven) >= 30
    for r in proven:
        assert len(r["negative_control"]) > 20, r["id"]          # a real differential, not a stub
        assert len(r["evidence_requirements"]) >= 2, r["id"]     # oracle + negative control + replay


def test_contract_derivation_is_class_specific_and_overridable():
    sqli = T.get("sqli_auth_bypass")
    assert "SQL" in sqli["negative_control"]
    idor = T.get("idor_bola_read")
    assert "owner" in idor["negative_control"].lower() or "denied" in idor["negative_control"].lower()
    # an explicit per-record value overrides the derivation (precise authoring stays possible)
    c = TM.proof_contract({"vuln_class": "sql_injection", "oracle": "x",
                           "negative_control": "CUSTOM", "evidence_requirements": ["only this"]})
    assert c["negative_control"] == "CUSTOM" and c["evidence_requirements"] == ["only this"]
    # beyond-web read-only classes get a read-only-flavoured control (never a write)
    net = TM.proof_contract({"vuln_class": "network_service", "permission": "ACTIVE", "oracle": "banner"})
    assert "read-only" in net["negative_control"].lower() or "configuration" in net["negative_control"].lower()
    # ICS/OT contract is explicitly read-only, no write ever
    ics = TM.proof_contract({"vuln_class": "ics_ot", "oracle": "unauth read"})
    assert "read-only" in ics["negative_control"].lower() and "write" in ics["negative_control"].lower()


def test_from_registry_surfaces_the_contract_on_the_canonical_model():
    assert "negative_control" in TM.FIELDS and "evidence_requirements" in TM.FIELDS
    t = TM.from_registry(T.get("ssrf"))
    assert t["negative_control"] and t["evidence_requirements"]
    # ssrf evidence obligations name the out-of-band correlation token (family-specific)
    assert any("correlation" in e.lower() or "out-of-band" in e.lower() for e in t["evidence_requirements"])
    # schema round-trip stays valid with the new list field
    assert TM.validate(t) == []
