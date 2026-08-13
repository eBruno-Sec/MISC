from __future__ import annotations

import pytest

from tier3 import gate
from tier3.runner import ERROR, FAIL, NOT_RUN, PASS, SKIPPED


def _entry(control_id, status=PASS, vulnerability_class="sqli"):
    return {"control_id": control_id, "status": status,
            "vulnerability_class": vulnerability_class}


def _artifact(*entries, environment_failures=None, semantic="sha"):
    return {"git_sha": "abc", "semantic_sha256": semantic,
            "per_entry": list(entries),
            "environment_failures": list(environment_failures or [])}


def test_identical_run_passes_but_a_known_skip_is_never_counted():
    baseline = _artifact(_entry("live"), _entry("known-gap", SKIPPED))
    current = _artifact(_entry("live"), _entry("known-gap", SKIPPED))
    result = gate.evaluate(current, baseline)
    assert result["ok"] is True
    assert result["current_pass"] == ["live"]
    assert result["known_gaps"] == ["known-gap"]
    assert result["summary"]["current_passing"] == 1


@pytest.mark.parametrize("status", [SKIPPED, FAIL, ERROR, NOT_RUN])
def test_a_previously_passing_control_regresses_on_every_nonpass(status):
    result = gate.evaluate(_artifact(_entry("live", status)), _artifact(_entry("live", PASS)))
    assert result["ok"] is False
    assert result["regressions"] == [{
        "control_id": "live",
        "vulnerability_class": "sqli",
        "baseline_status": PASS,
        "current_status": status,
        "baseline_required": True,
        "regression": True,
    }]


def test_removing_a_previously_passing_node_is_not_run_and_regresses():
    result = gate.evaluate(_artifact(), _artifact(_entry("removed")))
    assert result["ok"] is False
    assert result["regressions"][0]["current_status"] == NOT_RUN
    assert result["class_regressions"] == ["sqli"]


def test_losing_one_control_fails_even_when_the_class_still_has_another():
    baseline = _artifact(_entry("a"), _entry("b"))
    current = _artifact(_entry("a", SKIPPED), _entry("b"))
    result = gate.evaluate(current, baseline)
    assert result["ok"] is False
    assert [r["control_id"] for r in result["regressions"]] == ["a"]
    assert result["class_regressions"] == []


def test_a_new_passing_control_tightens_the_candidate_baseline():
    baseline = _artifact(_entry("old"))
    current = _artifact(_entry("old"), _entry("new", vulnerability_class="xss"))
    result = gate.evaluate(current, baseline)
    assert result["ok"] is True
    assert result["gained"] == ["new"]
    assert result["candidate_baseline_pass"] == ["new", "old"]


@pytest.mark.parametrize("status", [FAIL, ERROR, NOT_RUN])
def test_a_new_broken_control_is_fatal_not_a_gain(status):
    result = gate.evaluate(_artifact(_entry("old"), _entry("broken", status)),
                           _artifact(_entry("old")))
    assert result["ok"] is False
    assert result["fatal_statuses"] == ["broken"]
    assert "broken" not in result["candidate_baseline_pass"]


def test_environment_failure_fails_even_without_a_control_regression():
    artifact = _artifact(_entry("old"), environment_failures=[{"kind": "container", "detail": "down"}])
    result = gate.evaluate(artifact, _artifact(_entry("old")))
    assert result["ok"] is False
    assert result["environment_failures"][0]["kind"] == "container"


def test_duplicate_ids_or_unknown_statuses_make_the_gate_error():
    with pytest.raises(ValueError, match="duplicate"):
        gate.evaluate(_artifact(_entry("same"), _entry("same")), _artifact())
    with pytest.raises(ValueError, match="invalid status"):
        gate.evaluate(_artifact(_entry("x", "MAYBE")), _artifact())


def test_semantic_digest_ignores_timestamp_but_changes_with_outcome():
    baseline = _artifact(_entry("old"))
    first = gate.evaluate(_artifact(_entry("old")), baseline)
    second = gate.evaluate(_artifact(_entry("old")), baseline)
    changed = gate.evaluate(_artifact(_entry("old", SKIPPED)), baseline)
    assert first["semantic_sha256"] == second["semantic_sha256"]
    assert first["semantic_sha256"] != changed["semantic_sha256"]
