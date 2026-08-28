import json

import pytest
from fastapi.testclient import TestClient

import codeintel
import db
import main
import proof_schema


@pytest.fixture
def api(tmp_path, monkeypatch):
    monkeypatch.delenv("APOLAKI_API_TOKEN", raising=False)
    db.init(str(tmp_path / "apolaki.db"))
    main.sessions.clear()
    client = TestClient(main.app)
    try:
        yield client
    finally:
        client.close()
        main.sessions.clear()


def _engage(client, source_root=None):
    payload = {
        "program_name": "SAST production fixture",
        "in_scope": ["fixture.invalid"],
        "mode": "passive",
        "strategy": "deterministic",
    }
    if source_root is not None:
        payload["source_root"] = str(source_root)
    response = client.post("/engage", json=payload)
    assert response.status_code == 200, response.text
    return response.json()


def _source_tree(root):
    root.mkdir()
    (root / "Legacy.java").write_text(
        """import javax.crypto.Cipher;
class Legacy {
    Cipher weak() throws Exception { return Cipher.getInstance(\"DES\"); }
    Cipher clean() throws Exception { return Cipher.getInstance(\"AES/GCM/NoPadding\"); }
}
""",
        encoding="utf-8",
    )
    (root / "legacy.py").write_text(
        """from Crypto.Cipher import AES, DES

def weak(key):
    return DES.new(key, DES.MODE_ECB)

def clean(key, nonce):
    return AES.new(key, AES.MODE_GCM, nonce=nonce)
""",
        encoding="utf-8",
    )
    return root


# `id` and `observed_at` are both assigned BY STORAGE, not by the analyzer, so neither can appear in
# a comparison against what the analyzer produced. Q-102 added `observed_at` at read time (the row's
# own `created_at`, which `get_findings` had been sorting on and discarding); this helper already
# existed to drop exactly this category of storage-assigned metadata.
_STORAGE_ASSIGNED = {"id", "observed_at"}


def _without_ids(findings):
    return [{k: v for k, v in finding.items() if k not in _STORAGE_ASSIGNED} for finding in findings]


def test_real_mission_persists_exact_source_tree_findings_and_reports_the_lane(api, tmp_path):
    source_root = _source_tree(tmp_path / "src")
    analyzer = codeintel.review_source_tree(str(source_root))
    assert analyzer["files_scanned"] == 2
    assert len(analyzer["findings"]) == 2

    engaged = _engage(api, source_root)
    sid = engaged["session_id"]
    state = engaged["source_review"]
    assert state == {
        "status": "complete",
        "lane": "code-assisted",
        "label": "code-assisted (SAST)",
        "provenance": "source-derived",
        "source_root": str(source_root),
        "files_scanned": 2,
        "findings": 2,
        "stored_findings": 2,
        "rejected_findings": 0,
        "error": "",
    }

    persisted = db.get_findings(sid)
    assert _without_ids(persisted) == analyzer["findings"]
    assert all(proof_schema.proof_kind(f) == proof_schema.SOURCE_DERIVED for f in persisted)
    assert all(proof_schema.control_status(f) == proof_schema.CONTROL_NOT_APPLICABLE for f in persisted)

    mission = api.get(f"/missions/{sid}")
    assert mission.status_code == 200
    assert mission.json()["source_review"] == state

    report = api.get(f"/report/{sid}")
    assert report.status_code == 200
    body = report.json()
    assert _without_ids(body["findings"]) == proof_schema.demote_unproven(analyzer["findings"])
    assert "code-assisted (SAST)" in body["markdown"]
    assert "source-derived (static call-site)" in body["markdown"]

    json_report = api.get(f"/report/{sid}/json")
    assert json_report.status_code == 200
    exported = json.loads(json_report.text)
    assert all(f["lane"] == "code-assisted" for f in exported["findings"])
    assert all(f["provenance"] == "source-derived" for f in exported["findings"])
    assert any(t["tool"] == "codeintel.review_source_tree" and
               "code-assisted (SAST)" in t["note"]
               for t in exported["tool_ledger"]["tools"])


def test_source_tree_output_cannot_bypass_into_a_dast_finding(api, tmp_path, monkeypatch):
    source_root = _source_tree(tmp_path / "src")
    fake = {
        "lane": "code-assisted",
        "provenance": "source-derived",
        "root": str(source_root),
        "error": "",
        "files_scanned": 1,
        "files": ["Legacy.java"],
        "properties_resolved": 0,
        "findings": [{
            "title": "Analyzer marker bypass",
            "severity": "critical",
            "confidence": "confirmed",
            "family": "sqli",
            "cwe": "CWE-89",
            "target": "Legacy.java",
            "evidence": "text that must never become a DAST confirmation",
            "oracle": "none",
        }],
        "by_cwe": {"CWE-89": 1},
        "by_file": {"Legacy.java": ["CWE-89"]},
    }
    monkeypatch.setattr(codeintel, "review_source_tree", lambda root: fake)

    engaged = _engage(api, source_root)
    sid = engaged["session_id"]
    state = engaged["source_review"]
    assert state["status"] == "error"
    assert state["stored_findings"] == 0
    assert state["rejected_findings"] == 1
    assert "source-derived markers" in state["error"]
    assert db.get_findings(sid) == []
    assert api.get(f"/report/{sid}").json()["findings"] == []


def test_no_source_is_not_run_and_never_presented_as_a_clean_scan(api):
    engaged = _engage(api)
    state = engaged["source_review"]
    assert state["status"] == "not_run"
    assert state["error"] == "no source provided"
    assert state["files_scanned"] == 0
    assert state["findings"] == 0
    assert "clean" not in json.dumps(state).lower()

    archived = api.get(f"/missions/{engaged['session_id']}").json()["source_review"]
    assert archived == state

    report = api.get(f"/report/{engaged['session_id']}").json()
    assert "code-assisted (SAST)" in report["markdown"]
    assert "no source provided" in report["markdown"]
    exported = json.loads(api.get(f"/report/{engaged['session_id']}/json").text)
    source_tools = [t for t in exported["tool_ledger"]["tools"]
                    if t["tool"] == "codeintel.review_source_tree"]
    assert len(source_tools) == 1
    source_tool = source_tools[0]
    assert source_tool["status"] == "skipped"
    assert source_tool["calls"] == 0
    assert source_tool["findings"] == 0
    assert "no source provided" in source_tool["note"]


def test_invalid_source_path_is_an_environment_error_not_a_clean_scan(api, tmp_path):
    missing = tmp_path / "missing"
    engaged = _engage(api, missing)
    state = engaged["source_review"]
    assert state["status"] == "error"
    assert state["stored_findings"] == 0
    assert state["error"].startswith("no source provided: not a directory:")
    assert "clean" not in json.dumps(state).lower()


def test_legacy_codereview_keeps_using_the_general_review_route(api, monkeypatch):
    sentinel = {"error": "", "findings": [{"kind": "legacy-route"}], "scanned": 7}
    calls = []

    def legacy(path):
        calls.append(path)
        return sentinel

    def source_tree(_path):
        raise AssertionError("legacy /codereview routed into the code-assisted benchmark lane")

    monkeypatch.setattr(codeintel, "review", legacy)
    monkeypatch.setattr(codeintel, "review_source_tree", source_tree)
    response = api.get("/codereview", params={"path": "/non-java-python/tree"})
    assert response.status_code == 200
    assert response.content == json.dumps(sentinel, separators=(",", ":")).encode()
    assert calls == ["/non-java-python/tree"]
