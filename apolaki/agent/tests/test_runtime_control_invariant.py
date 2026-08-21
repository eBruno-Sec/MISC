"""I-4: behavioural confirmations retain the control that ruled out a benign result.

The control belongs on the finding emitted by the oracle.  A report/proof consumer must
not infer one later from a family name or from a confident-sounding description.
"""

import asyncio

import pytest

import exposure_tool as exposure
import header_trust_tool as header_trust
import proof_schema
import sqli_tool as sqli
import xss_tool as xss
from tools import ToolRegistry, _mark_source_derived, _not_found_control


def _sqli_findings():
    return {
        "error": sqli.error_finding(
            "https://target.test/items?id=1", "id", "'",
            [{"dbms": "SQLite", "pattern": "SQLITE_ERROR"}],
        ),
        "quote_recovery": sqli.quote_recovery_finding(
            "https://target.test/items?id=1", "id", 200, 500, 200,
        ),
        "boolean": sqli.boolean_finding(
            "https://target.test/items?id=1", "id",
            {"ctx": "numeric", "true": "1 AND 1=1", "false": "1 AND 1=2"},
        ),
        "auth_bypass": sqli.auth_bypass_finding(
            "https://target.test/login", "email", "' OR 1=1--",
            "session/JWT token issued for an invalid credential",
        ),
        "union": sqli.union_finding(
            "https://target.test/items?id=1", "id", 3, "'", ["users"],
            ["user@example.test:0123456789abcdef"],
        ),
        "time": sqli.time_finding(
            "https://target.test/items?id=1", "id",
            {"dbms": "MySQL", "payload": "1 AND SLEEP(5)",
             "control": "1 AND SLEEP(0)"},
            0.12, 5.21, 5,
        ),
        "structural": sqli.structural_finding(
            "https://target.test/items?sort=name", "sort",
            [{"dbms": "SQLite", "pattern": "no such table"}],
        ),
    }


def _assert_sqli_controls(findings):
    assert set(findings) == {
        "error", "quote_recovery", "boolean", "auth_bypass", "union", "time", "structural",
    }
    for name, finding in findings.items():
        assert finding["confidence"] == "confirmed", name
        assert proof_schema.control_status(finding) == proof_schema.CONTROL_RECORDED, name
        controls = finding.get("negative_controls")
        assert isinstance(controls, list) and controls, name
        assert all(isinstance(control, dict) and control.get("kind") for control in controls), name


def test_every_sqli_confirmation_carries_its_executed_negative_control():
    _assert_sqli_controls(_sqli_findings())


def test_sqli_control_artifacts_quote_the_observation_that_was_run():
    findings = _sqli_findings()
    quote = findings["quote_recovery"]["negative_controls"]
    assert quote[0]["status"] == 200
    assert quote[1]["status"] == 200
    assert quote[1]["payload_suffix"] == "''"

    boolean = findings["boolean"]["negative_controls"]
    assert boolean[0]["payload"] == "1 AND 1=2"
    assert "diverged" in boolean[0]["result"]

    timing = findings["time"]["negative_controls"]
    assert timing == [{
        "kind": "zero-delay-control",
        "payload": "1 AND SLEEP(0)",
        "elapsed_seconds": 0.12,
        "result": "control stayed below the injected 5s delay",
    }]


def test_clean_sqli_twins_do_not_reach_a_confirmed_builder():
    assert sqli.error_signatures("normal page", "normal page") == []
    assert not sqli.quote_break_recovers(200, 200, 200)
    assert not sqli.analyze_boolean(
        "same", "same", "same", baseline_samples=["same", "same"]
    )
    assert not sqli.auth_bypass_confirmed(401, "denied", 401, "denied")
    confirmed, hits = sqli.structural_confirmed("normal", "normal", "normal")
    assert not confirmed and hits == []


def test_no_consumer_backfills_a_missing_runtime_control():
    bare = {
        "title": "synthetic confirmed runtime finding",
        "confidence": "confirmed",
        "family": "sqli",
        "evidence": "payload changed the target",
    }
    assert proof_schema.control_status(bare) == proof_schema.CONTROL_NOT_RECORDED
    assert "negative_controls" not in bare


def _assert_union_baseline_blocks():
    calls = []

    async def get(_client, target):
        calls.append(target)
        raise AssertionError("no UNION probe may run when its marker is already in the baseline")

    got = asyncio.run(ToolRegistry._sqli_union(
        object(), None, get, "https://target.test/items?id=1", "id", "1",
        "ordinary page already containing " + sqli.UNION_MARK,
    ))
    assert got is None
    assert calls == []


def test_union_marker_must_be_absent_from_the_real_baseline():
    _assert_union_baseline_blocks()


def test_semantic_mutant_dropping_control_artifacts_is_killed(monkeypatch):
    original = sqli._base

    def drops_artifact(*args, **kwargs):
        finding = original(*args, **kwargs)
        finding.pop("negative_controls", None)
        return finding

    monkeypatch.setattr(sqli, "_base", drops_artifact)
    with pytest.raises(AssertionError, match="error"):
        _assert_sqli_controls(_sqli_findings())


def test_semantic_mutant_bypassing_union_baseline_is_killed(monkeypatch):
    monkeypatch.setattr(sqli, "union_hit", lambda _body: False)
    with pytest.raises(AssertionError, match="no UNION probe may run"):
        _assert_union_baseline_blocks()


def test_exposure_emitter_retains_the_not_found_twin():
    check = {
        "name": "Environment file exposed", "path": ".env", "severity": "high",
        "family": "config_exposure", "sig": [r"DB_PASSWORD="],
    }
    finding = exposure.classify(
        check, 200, "DB_PASSWORD=secret", "text/plain", "ordinary not-found page",
    )
    assert finding is not None
    assert proof_schema.control_status(finding) == proof_schema.CONTROL_RECORDED
    assert finding["negative_controls"][0]["kind"] == "not-found-baseline"
    assert finding["negative_controls"][0]["response_length"] == len("ordinary not-found page")


def test_null_byte_harvest_retains_the_plain_path_refusal():
    finding = exposure.harvest_finding(
        "https://target.test/files/secret.bak%2500.md", "files/secret.bak", True,
        "confidential password=secret",
    )
    assert proof_schema.control_status(finding) == proof_schema.CONTROL_RECORDED
    assert finding["negative_controls"][0]["kind"] == "plain-path-refusal"


def test_direct_harvest_retains_the_random_not_found_twin():
    control = {
        "kind": "not-found-baseline", "status": 404, "response_length": 18,
        "result": "random sibling did not return sensitive content",
    }
    finding = exposure.harvest_finding(
        "https://target.test/files/secret.bak", "files/secret.bak", False,
        "confidential password=secret", negative_control=control,
    )
    assert proof_schema.control_status(finding) == proof_schema.CONTROL_RECORDED
    assert finding["negative_controls"] == [control]


def test_reflected_xss_retains_the_harmless_canary_control():
    finding = xss.reflection_finding(
        "https://target.test/search?q=hello", "q", "html",
        evidence='...<bbh-xss-marker data-x="1">...',
    )
    assert finding["confidence"] == "confirmed"
    assert proof_schema.control_status(finding) == proof_schema.CONTROL_RECORDED
    assert finding["negative_controls"][0]["payload"] == xss.CANARY


def test_header_trust_retains_both_denial_controls():
    probes = {
        "baseline": {"status": 403, "body": "denied"},
        "with_header": {"status": 200, "body": "private account"},
        "value_control": {"status": 403, "body": "denied"},
    }
    finding = header_trust.finding_header_trust(
        "https://target.test/admin", "X-Forwarded-For", "127.0.0.1", "loopback trusted",
        probes, {"verdict": "confirmed", "reason": "only the valid value granted access"},
    )
    assert proof_schema.control_status(finding) == proof_schema.CONTROL_RECORDED
    kinds = {item["kind"] for item in finding["negative_controls"]}
    assert kinds == {"header-absent", "implausible-header-value"}

    override = header_trust.finding_url_override(
        "https://target.test", "/admin", "X-Rewrite-URL",
        {"direct": {"status": 403, "body": "denied"},
         "permitted": {"status": 200, "body": "home"},
         "overridden": {"status": 200, "body": "private account"}},
        {"verdict": "confirmed", "reason": "override served the denied resource"},
    )
    assert proof_schema.control_status(override) == proof_schema.CONTROL_RECORDED
    assert {item["kind"] for item in override["negative_controls"]} == {
        "direct-denied-path", "permitted-path-body",
    }


def test_random_not_found_control_requires_an_observation_that_ran():
    assert _not_found_control({"status": 404, "body": "missing"}) == {
        "kind": "not-found-baseline", "status": 404, "response_length": 7,
        "result": "the randomized missing-path response did not match the reported sensitive resource",
    }
    assert _not_found_control({"status": 0, "body": ""}) is None
    assert _not_found_control({"status": 404, "body": "", "error": "timeout"}) is None


def test_js_review_confirmation_is_typed_as_source_derived_before_emission():
    finding = {
        "title": "Credential exposed in a source comment", "confidence": "confirmed",
        "family": "sensitive_exposure", "evidence": "source line 7",
    }
    assert _mark_source_derived([finding]) == [finding]
    assert proof_schema.proof_kind(finding) == proof_schema.SOURCE_DERIVED
    assert proof_schema.control_status(finding) == proof_schema.CONTROL_NOT_APPLICABLE


def test_source_marker_leaves_nonconfirmed_review_output_unchanged():
    candidate = {"confidence": "candidate", "family": "sensitive_exposure"}
    _mark_source_derived([candidate, "raw review note"])
    assert "provenance" not in candidate


def test_semantic_mutant_dropping_exposure_control_is_killed():
    check = {
        "name": "Environment file exposed", "path": ".env", "severity": "high",
        "family": "config_exposure", "sig": [r"DB_PASSWORD="],
    }
    mutant = exposure.classify(
        check, 200, "DB_PASSWORD=secret", "text/plain", "ordinary not-found page",
    )
    mutant.pop("negative_controls")
    with pytest.raises(AssertionError, match="recorded"):
        assert proof_schema.control_status(mutant) == proof_schema.CONTROL_RECORDED


def test_semantic_mutant_dropping_source_provenance_is_killed():
    mutant = {"title": "source secret", "confidence": "confirmed", "family": "sensitive_exposure"}
    _mark_source_derived([mutant])
    for key in ("provenance", "lane", "analysis"):
        mutant.pop(key)
    with pytest.raises(AssertionError, match="source-derived"):
        assert proof_schema.proof_kind(mutant) == proof_schema.SOURCE_DERIVED
