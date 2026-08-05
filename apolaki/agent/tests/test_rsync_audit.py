"""rsync anonymous-module audit (infra pentest, CWE-306). Confirms only when an anonymous '#list' returns
modules; a daemon that lists nothing, an @ERROR, or a non-rsync service yields nothing."""
import blind_benchmark as bb
import rsync_audit_tool as rs


def test_parse_modules_skips_protocol_lines():
    resp = "data\tData share\nbackups\tNightly backups\n@RSYNCD: EXIT\n"
    assert rs.parse_modules(resp) == ["data", "backups"]
    assert rs.parse_modules("@RSYNCD: AUTHREQD abc\n@RSYNCD: EXIT\n") == []
    assert rs.parse_modules("@ERROR: access denied\n") == []


def test_analyze_confirms_modules():
    out = rs.analyze({"rsync_version": "@RSYNCD: 31.0", "modules": ["data", "backups"]})
    assert out and "2 rsync module" in out[0]
    assert rs.analyze({"modules": []}) is None
    assert rs.analyze({"error": "not an rsync daemon"}) is None


def test_finding_is_proof_with_cvss():
    from report import cvss31_base_score
    res = {"rsync_version": "@RSYNCD: 31.0", "modules": ["backups"]}
    (ev,) = rs.analyze(res)
    f = rs.finding("10.0.0.8", 873, ev, res)
    assert f["family"] == "rsync_anon" and f["cwe"] == "CWE-306" and bb._has_proof(f)
    assert abs(cvss31_base_score(f["cvss_vector"]) - f["cvss_score"]) < 0.05
