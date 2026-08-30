"""Phase 1: first-class Technique model + store lifecycle + extractor. Pure, deterministic, no network."""
from __future__ import annotations

import technique_model as TM
import technique_store as TS
import intel_extractor as EX
import technique_advisor as ADV


# ---------------------------------------------------------------------------- model
def test_from_registry_projects_canonical_shape(monkeypatch):
    """Q-088: `status` used to be `"proven" if validated_on else "catalogued"` -- true for ANY
    non-empty validated_on, which is the exact bug test_validated_on.py's negative control pins
    (two invented lab ids used to earn "proven" the same way). `from_registry` now defers to
    techniques.technique_status(), the shared predicate, which only says "proven" once a liveness
    RUN has confirmed the id -- "sqli_auth_bypass" (this test's id) is a real registry entry but is
    not in the current liveness ledger, so it is honestly "unverified" today, same as most of the
    registry (see test_technique_status_is_the_fixed_rule_and_still_holds in test_validated_on.py).
    Pinning this unit test to whatever the live liveness_baseline.json happens to contain would make
    it flake against future liveness runs, so instead it monkeypatches
    techniques._liveness_verified() to deterministically vouch for this one id -- exercising the
    real from_registry -> techniques.technique_status wiring, not a mock of it."""
    import techniques as T
    monkeypatch.setattr(T, "_liveness_verified", lambda: {"sqli_auth_bypass"})
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


def test_dedup_suggestions_pairs_similar_candidates():
    store = {"techniques": {
        "a": {"id": "a", "name": "SQL Injection in login", "summary": "sql injection login bypass",
              "cwe": ["CWE-89"], "status": "catalogued", "confidence": {"score": 30}},
        "b": {"id": "b", "name": "SQL Injection login", "summary": "sql injection login",
              "cwe": ["CWE-89"], "status": "catalogued", "confidence": {"score": 22}},
        "c": {"id": "c", "name": "XSS reflected", "summary": "reflected xss",
              "cwe": ["CWE-79"], "status": "catalogued", "confidence": {"score": 20}}}}
    s = TS.dedup_suggestions(store, threshold=0.4)
    assert any({x["a"], x["b"]} == {"a", "b"} for x in s)      # same CWE + similar names -> suggested
    assert not any("c" in (x["a"], x["b"]) for x in s)         # different CWE -> never paired


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


def test_advisor_ranks_by_relevance_kev_and_confidence():
    sqli = TM.from_registry({"id": "sqli_auth_bypass", "vuln_class": "sqli", "cwe": "CWE-89",
                             "validated_on": ["juiceshop"]}, try_it="' or 1=1--")
    xss = TM.from_registry({"id": "reflected_xss", "vuln_class": "xss", "cwe": "CWE-79", "validated_on": []})
    ssrf = TM.from_registry({"id": "ssrf", "vuln_class": "ssrf", "cwe": "CWE-918", "validated_on": []})
    findings = [{"family": "sqli", "cwe": "CWE-89", "title": "SQLi in login"}]
    recs = ADV.recommend(findings, [sqli, xss, ssrf], kev_cwes={"CWE-89"}, top=3)
    assert recs[0]["technique"]["id"] == "sqli_auth_bypass"          # matches a confirmed finding -> top
    assert any("confirmed sqli" in r for r in recs[0]["reasons"])
    assert any("KEV" in r for r in recs[0]["reasons"])              # CWE-89 in KEV boosts it
    leads = ADV.as_leads(recs[:1], "http://t")
    assert leads[0]["tags"][0] == "technique-advisor" and "kev" in leads[0]["tags"]
    assert leads[0]["reproduction_steps"]                          # carries a concrete payload/discovery step


def test_advisor_uses_gathered_intel_signals():
    # orchestration: with NO confirmed findings, a signal derived from gathered intel (e.g. recon found
    # object-ids -> access_control) still steers the advisor toward the matching technique.
    ssrf = TM.from_registry({"id": "ssrf", "vuln_class": "ssrf", "cwe": "CWE-918", "validated_on": []})
    xss = TM.from_registry({"id": "xss", "vuln_class": "xss", "cwe": "CWE-79", "validated_on": []})
    recs = ADV.recommend([], [ssrf, xss], signals={"ssrf"}, top=2)
    assert recs[0]["technique"]["id"] == "ssrf"
    assert any("gathered-intel signal" in r for r in recs[0]["reasons"])


def test_advisor_skips_rejected_and_deprecated():
    ok = TM.from_registry({"id": "a", "vuln_class": "sqli", "cwe": "CWE-89", "validated_on": []})
    dead = TM.from_registry({"id": "b", "vuln_class": "xss", "cwe": "CWE-79", "validated_on": []})
    dead["status"] = "deprecated"
    recs = ADV.recommend([], [ok, dead], top=5)
    assert [r["technique"]["id"] for r in recs] == ["a"]            # deprecated is never recommended


def test_extract_prose_degrades_without_llm(monkeypatch):
    for v in ("AI_API_KEY", "OPENROUTER_API_KEY", "ANTHROPIC_API_KEY", "AI_BASE_URL"):
        monkeypatch.delenv(v, raising=False)
    monkeypatch.setenv("AI_BASE_URL", "")                       # force no base_url too
    t = EX.extract_prose("A path traversal in CVE-2021-1675 via CWE-22.", source="advisory", ref="CVE-2021-1675")
    assert t["status"] == "pending_review"                     # LLM-lane output always needs review
    assert "no-llm:structure-only" in t["tags"]                # honest degrade label
    assert t["cwe"] == ["CWE-22"] and t["provenance"][0]["cves"] == ["CVE-2021-1675"]   # deterministic pre still works
