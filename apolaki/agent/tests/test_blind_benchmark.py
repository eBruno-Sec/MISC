"""Blind benchmark harness (CHAD final mandate): the answer key is blocked from the scanner, parsed
generically post-seal, matched by path+family+proof, and the two artifacts' ordering proves no
influence. These lock the anti-cheat guarantees and the parser."""
from __future__ import annotations

import blind_benchmark as bb
import scope as scope_mod


# ── the answer key is blocked from the scanner everywhere scope is checked ─────
def test_is_answer_key_matches_regardless_of_host_scheme_query():
    for u in ("https://ginandjuice.shop/vulnerabilities",
              "http://any.host/vulnerabilities?x=1",
              "https://x/vulnerabilities/"):
        assert bb.is_answer_key(u), u
    # EXACT match only: sub-paths are legitimate app surface (e.g. DVWA's /vulnerabilities/sqli/)
    for u in ("https://ginandjuice.shop/catalog", "https://x/vuln", "https://x/blog",
              "http://host.local/vulnerabilities/sqli/", "https://x/vulnerabilities/detail"):
        assert not bb.is_answer_key(u), u


def test_scope_validate_blocks_answer_key():
    sc = scope_mod.ScopeEngine()
    sc.load_manual(["ginandjuice.shop"], [], "gnj")
    ok_catalog, _ = sc.validate("https://ginandjuice.shop/catalog")
    ok_key, reason = sc.validate("https://ginandjuice.shop/vulnerabilities")
    assert ok_catalog is True                     # normal in-scope target allowed
    assert ok_key is False and "BLIND BENCHMARK" in reason   # answer key hard-blocked


# ── generic parsing of an obfuscated published-vulnerabilities table ──────────
_FIXTURE = (
    "<table><tr><th>Path</th><th>Difficulties</th><th>Technologies</th><th>Vulnerabilities</th></tr>"
    "<tr><td>/​b​l​o​g</td><td>Client-side prototype pollution "
    "Client-side template injection Cross-site scripting (DOM-based)</td><td>JavaScript</td>"
    "<td>Open redirection (DOM-based)</td></tr>"
    "<tr><td>/​c​a​t​a​l​o​g</td>"
    "<td>SQL injection Base64-encoded data in parameter Cross-site scripting (reflected)</td>"
    "<td>PostgreSQL</td><td>HTTP response header injection</td></tr></table>"
)


def test_parse_answer_key_deobfuscates_and_extracts_families():
    E = bb.parse_answer_key(_FIXTURE)
    fams = {e["family"] for e in E}
    paths = {e["path"] for e in E}
    assert "/blog" in paths and "/catalog" in paths        # zero-width separators stripped
    assert {"prototype_pollution", "csti", "dom_xss", "open_redirect"} <= fams
    assert {"sqli", "base64_param", "reflected_xss", "header_injection"} <= fams
    # every entry is a (path, family) with a benchmark id and a context
    for e in E:
        assert e["path"].startswith("/") and e["family"] and e["benchmark_id"] and "context" in e


# ── matching is path + family + PROOF, never title ────────────────────────────
def _finding(fam, path, confirmed=True, oracle="canary fired at runtime"):
    return {"family": fam, "target": "https://t" + path, "confidence": "confirmed" if confirmed else "candidate",
            "success_oracle": oracle if confirmed else "", "title": "x"}


def test_match_requires_family_path_and_proof():
    expected = [{"benchmark_id": "bm-1", "path": "/catalog", "family": "sqli", "context": "sql"}]
    # right family+path but NO proof -> discovered-unconfirmed, not a true positive
    m1 = bb.match(expected, [], candidates=[_finding("sqli", "/catalog", confirmed=False)])
    assert len(m1["true_positives"]) == 0 and len(m1["discovered_unconfirmed"]) == 1
    # confirmed with proof on the right path+family -> true positive
    m2 = bb.match(expected, [_finding("sql_injection", "/catalog")], candidates=[])
    assert len(m2["true_positives"]) == 1 and len(m2["missed"]) == 0
    # confirmed but WRONG path -> missed (family alone is not enough for a path-level TP)
    m3 = bb.match(expected, [_finding("sqli", "/login")], candidates=[])
    assert len(m3["true_positives"]) == 0 and len(m3["missed"]) == 1


def test_score_reports_full_breakdown():
    expected = [{"benchmark_id": "bm-%d" % i, "path": p, "family": f, "context": ""}
                for i, (p, f) in enumerate([("/catalog", "sqli"), ("/blog", "dom_xss"), ("/login", "reflected_xss")])]
    m = bb.match(expected, [_finding("sqli", "/catalog")], candidates=[_finding("dom_xss", "/blog", confirmed=False)])
    s = bb.score(expected, m, candidates=[1, 2, 3], validations={"executed": 5, "unsupported": 1})
    assert s["expected_instances"] == 3
    assert s["confirmed_true_positives"] == 1
    assert s["missed_vulnerabilities"] == 1          # /login reflected_xss neither confirmed nor discovered
    assert s["family_level_recall"] == round(100 / 3, 1)
    assert s["discovery_family_recall"] == round(200 / 3, 1)   # sqli confirmed + dom_xss discovered
    for k in ("path_level_recall", "precision", "unsupported_coverage_rate", "executed_validations"):
        assert k in s


# ── the two artifacts' ordering proves the key did not influence discovery ────
def test_artifacts_are_hashed_and_ordered():
    findings = [_finding("sqli", "/catalog")]
    blind = bb.blind_artifact("sid1", "t.host", findings, findings, {"executed": 1}, "rev")
    assert blind["answer_key_read"] is False and len(blind["content_hash"]) == 64
    expected = [{"benchmark_id": "bm-1", "path": "/catalog", "family": "sqli", "context": ""}]
    m = bb.match(expected, findings, [])
    s = bb.score(expected, m, findings)
    comp = bb.comparison_artifact(blind, expected, m, s, "keysha", "https://t.host/vulnerabilities")
    assert comp["blind_artifact_hash"] == blind["content_hash"]     # comparison is BOUND to the seal
    assert comp["ordering_ok"] is True                              # fetched after sealed
    assert comp["hash_algo"] == "sha256"


def test_finding_family_canonicalizes_across_emitters():
    assert bb.finding_family({"family": "sql_injection"}) == "sqli"
    assert bb.finding_family({"family": "dom_xss"}) == "dom_xss"
    assert bb.finding_family({"cwe": "CWE-601"}) == "open_redirect"
    assert bb.finding_family({"title": "Client-side template injection (CSTI, via search)"}) == "csti"


def test_out_of_key_scope_is_not_counted_as_a_false_positive():
    """The wrong-ruler guard. A published vulnerability list enumerates injectable defects; it does not
    list missing HSTS or a vulnerable dependency. Scoring those as false positives punishes the scanner
    for being more thorough than the ruler — measured live on ginandjuice, where 6 of 10 'false
    positives' were true transport-posture findings."""
    import blind_benchmark as bb
    expected = [{"family": "sqli", "path": "/catalog", "method": "GET", "benchmark_id": "bm-1"}]
    conf = [
        {"title": "SQL injection in id", "family": "sqli", "target": "https://t/catalog",
         "confidence": "confirmed", "evidence": "GET -> payload reflected in SQL error"},
        # same family the key enumerates, but a path the key never lists -> a real precision miss
        {"title": "SQL injection in q", "family": "sqli", "target": "https://t/other",
         "confidence": "confirmed", "evidence": "GET -> payload reflected in SQL error"},
        # families the key never enumerates at all -> out of key scope, not wrong
        {"title": "HSTS not enabled", "family": "security_misconfig", "target": "https://t/",
         "confidence": "confirmed", "evidence": "GET -> payload reflected in SQL error"},
        {"title": "Vulnerable component angular", "family": "vulnerable_component",
         "target": "https://t/a.js", "confidence": "confirmed", "evidence": "GET -> payload reflected in SQL error"},
    ]
    m = bb.match(expected, conf, conf)
    fams = {x["family"] for x in m["false_positives"]}
    oos = {x["family"] for x in m["out_of_key_scope"]}
    assert fams == {"sqli"}, m["false_positives"]
    assert oos == {"security_misconfig", "vulnerable_component"}, m["out_of_key_scope"]

    s = bb.score(expected, m, candidates=conf)
    assert s["false_positives"] == 1 and s["out_of_key_scope"] == 2
    # precision reflects only families the ruler actually measures: 1 TP / (1 TP + 1 FP)
    assert s["precision"] == 50.0
