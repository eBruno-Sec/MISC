"""LDAP anonymous-read audit (AD/directory pentest, CWE-306). Confirms only when an anonymous bind can read
naming-context ENTRIES; a bind failure, an error, or a RootDSE-only result (subtree returned nothing on a
hardened server) all yield nothing (no FP). User objects escalate to high; structure-only is medium."""
import blind_benchmark as bb
import ldap_enum_tool as le


def test_bind_failure_not_flagged():
    assert le.analyze({"bound": False}) is None
    assert le.analyze({"error": "connection refused"}) is None


def test_anonymous_bound_but_empty_subtree_not_flagged():
    # hardened: anon bind allowed (RootDSE), but the naming-context subtree returned nothing -> NOT a finding
    assert le.analyze({"bound": True, "naming_contexts": ["dc=x"], "entries": [], "user_dns": []}) is None


def test_structure_read_is_medium():
    res = {"bound": True, "naming_contexts": ["dc=designworld,dc=local"],
           "entries": ["dc=designworld,dc=local", "ou=groups,dc=designworld,dc=local"], "user_dns": []}
    out = le.analyze(res)
    assert out and out[0] == "medium"


def test_user_objects_read_is_high():
    res = {"bound": True, "naming_contexts": ["dc=designworld,dc=local"],
           "entries": ["dc=designworld,dc=local", "uid=jdoe,dc=designworld,dc=local"],
           "user_dns": ["uid=jdoe,dc=designworld,dc=local"]}
    out = le.analyze(res)
    assert out and out[0] == "high" and "user object" in out[1]


def test_finding_is_proof_with_cvss():
    from report import cvss31_base_score
    res = {"bound": True, "naming_contexts": ["dc=designworld,dc=local"],
           "entries": ["uid=jdoe,dc=designworld,dc=local"], "user_dns": ["uid=jdoe,dc=designworld,dc=local"]}
    sev, ev = le.analyze(res)
    f = le.finding("10.0.0.2", 389, res, sev, ev)
    assert f["family"] == "ldap_anonymous_read" and f["cwe"] == "CWE-306" and bb._has_proof(f)
    assert abs(cvss31_base_score(f["cvss_vector"]) - f["cvss_score"]) < 0.05
