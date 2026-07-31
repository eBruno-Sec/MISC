"""Phase 1: first-class Technique model + store lifecycle + extractor. Pure, deterministic, no network."""
from __future__ import annotations

import technique_model as TM
import technique_store as TS
import intel_extractor as EX


# ---------------------------------------------------------------------------- model
def test_from_registry_projects_canonical_shape():
    rec = {"id": "sqli_auth_bypass", "vuln_class": "sqli", "cwe": "CWE-89", "owasp": "A03:2021",
           "mitre": "T1190", "detect": "error-based probe", "oracle": "boolean diff",
           "summary": "auth bypass via SQLi", "validated_on": ["juiceshop", "dvwa"],
           "maps_to": {"juiceshop": ["Login Admin"]}, "transferable": True, "permission": "auto"}
    t = TM.from_registry(rec, try_it="POST /login ' or 1=1--", known_exploited=True, kev_cves=["CVE-2016-2386"])
    assert t["status"] == "proven" and t["cwe"] == ["CWE-89"] and t["attack"] == ["T1190"]
    assert t["evidence"][0]["lab"] == "juiceshop" and t["payloads"][0]["payload"].startswith("POST")
    assert set(t.keys()) >= set(TM.FIELDS)                       # full canonical shape
    assert t["confidence"]["tier"] == "high"                    # proven + 2 labs + KEV -> high


def test_confidence_is_deterministic_and_explainable():
    rec = {"id": "x", "cwe": "CWE-1", "validated_on": []}
    a = TM.from_registry(rec)
    b = TM.from_registry(rec)
    assert a["confidence"] == b["confidence"]                   # deterministic
    names = [f["name"] for f in a["confidence"]["factors"]]
    assert any(n.startswith("status:") for n in names)          # every point attributed to a factor


def test_from_capec_builds_catalogued_candidate():
    pat = {"name": "SQL Injection", "cwes": ["CWE-89"], "severity": "High", "likelihood": "High",
           "abstraction": "Standard", "attack": ["T1190"], "prerequisites": ["a database is used"],
           "parents": ["CAPEC-248"], "children": []}
    t = TM.from_capec("CAPEC-66", pat)
    assert t["id"] == "capec_66" and t["status"] == "catalogued"
    assert t["cwe"] == ["CWE-89"] and t["preconditions"] == ["a database is used"]
    assert t["parents"] == ["capec_248"] and "severity:High" in t["tags"]
    assert not TM.validate(t)


# ---------------------------------------------------------------------------- store lifecycle
def test_upsert_creates_then_versions_on_change():
    store = {"techniques": {}}
    t = TM.from_capec("CAPEC-66", {"name": "SQLi", "cwes": ["CWE-89"]})
    assert TS.upsert(store, t) == "created"
    assert TS.upsert(store, t) == "unchanged"                   # idempotent
    t2 = dict(t)
    t2["preconditions"] = ["new precondition"]
    assert TS.upsert(store, t2) == "updated"
    cur = TS.get(store, "capec_66")
    assert cur["version"] == 2 and [h["action"] for h in cur["version_history"]] == ["created", "updated"]


def test_transition_and_merge_never_delete():
    store = {"techniques": {}}
    TS.upsert(store, TM.from_capec("CAPEC-66", {"name": "SQLi", "cwes": ["CWE-89"]}))
    TS.upsert(store, TM.from_capec("CAPEC-7", {"name": "Blind SQLi", "cwes": ["CWE-89"]}))
    TS.transition(store, "capec_66", "experimental", by="erwin", note="promoted")
    assert TS.get(store, "capec_66")["status"] == "experimental"
    assert [h["action"] for h in TS.get(store, "capec_66")["version_history"]][-1] == "experimental"
    TS.merge(store, "capec_66", "capec_7", by="erwin")
    assert TS.get(store, "capec_7")["status"] == "superseded"    # dropped one kept, not deleted
    assert TS.get(store, "capec_7")["superseded_by"] == "capec_66"


def test_dedup_key_is_deterministic():
    assert TS.dedup_key({"capec": ["CAPEC-9", "CAPEC-1"]}) == "capec:CAPEC-1"
    assert TS.dedup_key({"cwe": ["CWE-89"], "name": "SQL Injection"}) == "cwe:CWE-89|name:sql injection"


# ---------------------------------------------------------------------------- extractor
def test_run_capec_extraction_populates_store():
    feeds = {"capec": {"patterns": {
        "CAPEC-66": {"name": "SQLi", "cwes": ["CWE-89"], "prerequisites": ["db used"]},
        "CAPEC-63": {"name": "XSS", "cwes": ["CWE-79"]}}}}
    store = {"techniques": {}}
    res = EX.run_capec_extraction(feeds, store)
    assert res["created"] == 2 and res["total"] == 2
    assert TS.get(store, "capec_66")["status"] == "catalogued"


def test_preprocess_pulls_identifiers():
    pre = EX.preprocess("Affects Foo 2.1.0. See CVE-2021-1675 and CVE-2016-2386 (CWE-89, CAPEC-66).")
    assert pre["cves"] == ["CVE-2016-2386", "CVE-2021-1675"]
    assert pre["cwes"] == ["CWE-89"] and pre["capec"] == ["CAPEC-66"] and "2.1.0" in pre["versions"]


def test_extract_prose_degrades_without_llm(monkeypatch):
    for v in ("AI_API_KEY", "OPENROUTER_API_KEY", "ANTHROPIC_API_KEY", "AI_BASE_URL"):
        monkeypatch.delenv(v, raising=False)
    monkeypatch.setenv("AI_BASE_URL", "")                       # force no base_url too
    t = EX.extract_prose("A path traversal in CVE-2021-1675 via CWE-22.", source="advisory", ref="CVE-2021-1675")
    assert t["status"] == "pending_review"                     # LLM-lane output always needs review
    assert "no-llm:structure-only" in t["tags"]                # honest degrade label
    assert t["cwe"] == ["CWE-22"] and t["provenance"][0]["cves"] == ["CVE-2021-1675"]   # deterministic pre still works
