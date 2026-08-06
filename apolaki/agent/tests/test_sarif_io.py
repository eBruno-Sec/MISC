"""SARIF 2.1.0 boundary (Codex Tier-1 #2): import -> CANDIDATE (never confirmed), export atomic findings
only, CWE from rule tags, order-stable fingerprints, suppression preserved-not-trusted, secrets redacted."""
import sarif_io as S


def _sample_sarif(uri="src/db.py", line=42, rule="sql-injection", tags=("external/cwe/cwe-89",)):
    return {
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "semgrep", "rules": [
                {"id": rule, "name": "SQL injection", "properties": {"tags": list(tags)}}]}},
            "results": [{
                "ruleId": rule, "level": "error", "message": {"text": "Tainted input reaches SQL sink"},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri},
                                                    "region": {"startLine": line}}}],
                "codeFlows": [{"threadFlows": [{"locations": [
                    {"location": {"physicalLocation": {"artifactLocation": {"uri": "src/handler.py"},
                                                       "region": {"startLine": 10}}}},
                    {"location": {"physicalLocation": {"artifactLocation": {"uri": uri},
                                                       "region": {"startLine": line}}}}]}]}],
                "partialFingerprints": {"semgrep/v1": "abc123"},
            }],
        }],
    }


def test_import_maps_to_candidate_not_confirmed():
    cands = S.import_sarif(_sample_sarif())
    assert len(cands) == 1
    c = cands[0]
    assert c["confidence"] == "candidate" and c["requires_runtime_validation"] is True
    assert c["source"] == "sarif" and c["producer"] == "semgrep"
    assert c["cwe"] == "CWE-89"
    assert c["location"] == {"uri": "src/db.py", "start_line": 42}
    assert c["producer_fingerprint"] == "abc123"
    assert c["code_flow"][-1]["uri"] == "src/db.py"          # sink is the last flow step


def test_cwe_extraction_from_rule_tags():
    assert S.import_sarif(_sample_sarif(tags=("CWE-79",)))[0]["cwe"] == "CWE-79"
    assert S.import_sarif(_sample_sarif(tags=("external/cwe/cwe-611",)))[0]["cwe"] == "CWE-611"
    assert S.import_sarif(_sample_sarif(tags=("security",)))[0]["cwe"] == ""   # no fake CWE


def test_export_emits_valid_sarif_structure():
    findings = [{"id": "F1", "title": "SQL injection in /login", "family": "sqli",
                 "cwe": "CWE-89", "severity": "critical", "confidence": "confirmed",
                 "target": "http://app/login?u=1"}]
    doc = S.export_sarif(findings)
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "Apolaki"
    res = run["results"][0]
    assert res["ruleId"] == "sqli" and res["level"] == "error"
    assert res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"].startswith("http://app/login")
    assert res["properties"]["security-severity"] == "9.5" and res["properties"]["atomic"] is True
    assert S.FP_KEY in res["partialFingerprints"]
    # rule carries the CWE tag
    assert any("cwe-89" in t for t in run["tool"]["driver"]["rules"][0]["properties"]["tags"])


def test_fingerprints_stable_across_order():
    a = S.apolaki_fingerprint("sqli", "CWE-89", "http://app/login?u=1")
    b = S.apolaki_fingerprint("sqli", "CWE-89", "http://app/login?u=2")   # query differs -> same key
    c = S.apolaki_fingerprint("sqli", "cwe-89", "http://APP/login/")      # case/trailing slash -> same key
    assert a == b == c
    # import order does not change per-result fingerprints
    d1 = _sample_sarif(uri="a.py"); d2 = _sample_sarif(uri="b.py")
    merged1 = {"runs": d1["runs"] + d2["runs"]}
    merged2 = {"runs": d2["runs"] + d1["runs"]}
    fps1 = sorted(c["apolaki_fingerprint"] for c in S.import_sarif(merged1))
    fps2 = sorted(c["apolaki_fingerprint"] for c in S.import_sarif(merged2))
    assert fps1 == fps2


def test_suppression_preserved_not_trusted():
    doc = _sample_sarif()
    doc["runs"][0]["results"][0]["suppressions"] = [{"kind": "inSource", "justification": "false positive"}]
    c = S.import_sarif(doc)[0]
    # preserved as EXTERNAL metadata, and the candidate still requires runtime validation regardless
    assert c["external_suppression"]["suppressed"] is True
    assert c["external_suppression"]["raw"][0]["kind"] == "inSource"
    assert c["requires_runtime_validation"] is True
    assert c["confidence"] == "candidate"


def test_secret_snippets_are_redacted():
    doc = _sample_sarif()
    doc["runs"][0]["results"][0]["message"]["text"] = 'aws_secret_key = "AKIAIOSFODNN7EXAMPLE" leaked here'
    c = S.import_sarif(doc)[0]
    assert "AKIAIOSFODNN7EXAMPLE" not in c["title"]
    # export redacts too
    doc2 = S.export_sarif([{"id": "F", "title": "leak", "family": "exposure",
                            "description": 'token ghp_' + "a" * 36, "severity": "high", "target": "http://x"}])
    assert "ghp_" + "a" * 36 not in doc2["runs"][0]["results"][0]["message"]["text"]


def test_malformed_input_is_safe():
    assert S.import_sarif(None) == []
    assert S.import_sarif({}) == []
    assert S.import_sarif({"runs": [{}]}) == []
    assert S.export_sarif([])["runs"][0]["results"] == []


def test_roundtrip_export_then_import():
    findings = [{"id": "F1", "title": "XSS", "family": "xss", "cwe": "CWE-79",
                 "severity": "medium", "target": "http://app/q?x=1"}]
    doc = S.export_sarif(findings)
    back = S.import_sarif(doc)
    assert len(back) == 1 and back[0]["cwe"] == "CWE-79"
    assert back[0]["confidence"] == "candidate"          # re-import is a candidate again, not confirmed
