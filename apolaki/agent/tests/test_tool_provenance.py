"""Tool-execution provenance + parser versioning (Codex Tier-3 #14): every field recorded, stable argv hash,
secrets redacted, output/scope/input hashed, parser version captured."""
import json

import tool_provenance as TP


def test_record_has_all_provenance_fields():
    r = TP.record("nmap", ["nmap", "-sV", "10.0.0.1"], binary_path="/usr/bin/nmap",
                  binary_version="7.94", timeout=120, exit_code=0, parser_version="nmap_xml/v3",
                  inputs={"target": "10.0.0.1"}, output="<nmaprun>...</nmaprun>",
                  scope={"hosts": ["10.0.0.1"]}, permission="ACTIVE")
    for k in ("tool", "binary_path", "binary_version", "argv_hash", "timeout", "exit_code",
              "parser_version", "input_hash", "output_artifact_hash", "scope_hash", "permission",
              "approval_id", "recorded_at"):
        assert k in r
    assert r["binary_version"] == "7.94" and r["parser_version"] == "nmap_xml/v3"
    assert r["exit_code"] == 0 and r["permission"] == "ACTIVE"


def test_argv_hash_is_stable_and_distinguishing():
    a = TP.argv_hash(["nmap", "-sV", "10.0.0.1"])
    b = TP.argv_hash(["nmap", "-sV", "10.0.0.1"])
    c = TP.argv_hash(["nmap", "-sV", "10.0.0.2"])
    assert a == b and a != c


def test_secrets_in_argv_are_redacted():
    r = TP.record("curl", ["curl", "-H", "Authorization: Bearer SUPERSECRETTOKEN", "http://app"])
    blob = json.dumps(r)
    assert "SUPERSECRETTOKEN" not in blob
    assert any("redacted" in a for a in r["argv_redacted"])


def test_secrets_in_inputs_do_not_enter_record():
    r = TP.record("tool", ["tool"], inputs={"url": "http://app", "authorization": "Bearer LEAK"})
    assert "LEAK" not in json.dumps(r) and r["input_hash"] is not None


def test_output_and_scope_hashed_not_stored_raw():
    r = TP.record("tool", ["tool"], output="raw-tool-output-blob", scope={"h": ["x"]})
    assert r["output_artifact_hash"] and "raw-tool-output-blob" not in json.dumps(r)
    assert r["scope_hash"]


def test_missing_optionals_are_none_not_crash():
    r = TP.record("tool", ["tool"])
    assert r["input_hash"] is None and r["output_artifact_hash"] is None and r["scope_hash"] is None
