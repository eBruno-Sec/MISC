"""I-4: behavioural confirmations retain the control that ruled out a benign result.

The control belongs on the finding emitted by the oracle.  A report/proof consumer must
not infer one later from a family name or from a confident-sounding description.
"""

import asyncio

import pytest

import proof_schema
import sqli_tool as sqli
from tools import ToolRegistry


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
