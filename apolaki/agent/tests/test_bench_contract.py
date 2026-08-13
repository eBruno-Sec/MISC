from __future__ import annotations

import json

import pytest

import bench_contract as bc
import owasp_bench


def _case(case_id, category="sqli", families=(), conf=None, status=bc.MEASURED,
          evidence=None):
    return {
        "case_id": case_id,
        "category": category,
        "measurement_status": status,
        "families": list(families),
        "conf": list(conf) if conf is not None else ["confirmed"] * len(families),
        "raw_evidence": evidence if evidence is not None else {"request": case_id, "response": "recorded"},
    }


def test_result_vocabulary_is_explicit_and_skipped_is_not_a_result():
    assert bc.RESULT_VOCABULARY == {
        bc.PASS, bc.FAIL, bc.FP, bc.FN, bc.UNSUPPORTED, bc.INCONCLUSIVE,
        bc.ENVIRONMENT_FAILURE,
    }
    assert "SKIPPED" not in bc.RESULT_VOCABULARY


def test_checkpoint_fsyncs_each_case_and_resumes_without_repeating_it(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(bc.os, "fsync", lambda fd: calls.append(fd))
    path = tmp_path / "run.jsonl"
    checkpoint = bc.CaseCheckpoint(path)
    first = _case("C1")
    assert checkpoint.append(first) is True
    assert calls, "a written case must reach fsync before it is considered complete"
    resumed = bc.CaseCheckpoint(path)
    assert resumed.completed_ids == {"C1"}
    assert resumed.pending(["C1", "C2"]) == ["C2"]
    assert resumed.append(dict(first)) is False
    assert bc.load_checkpoint(path)[0]["raw_evidence"] == first["raw_evidence"]


def test_checkpoint_recovers_only_a_truncated_final_row(tmp_path):
    path = tmp_path / "run.jsonl"
    row = _case("C1")
    path.write_bytes((json.dumps(row) + "\n{partial").encode("utf8"))
    checkpoint = bc.CaseCheckpoint(path)
    assert checkpoint.completed_ids == {"C1"}
    assert checkpoint.append(_case("C2")) is True
    assert [r["case_id"] for r in bc.load_checkpoint(path)] == ["C1", "C2"]


def test_checkpoint_resume_separates_a_valid_final_row_without_newline(tmp_path):
    path = tmp_path / "run.jsonl"
    path.write_text(json.dumps(_case("C1")), encoding="utf8")
    checkpoint = bc.CaseCheckpoint(path)
    assert checkpoint.append(_case("C2")) is True
    assert [r["case_id"] for r in bc.load_checkpoint(path)] == ["C1", "C2"]


def test_checkpoint_rejects_corrupt_middle_rows_and_conflicting_duplicates(tmp_path):
    path = tmp_path / "bad.jsonl"
    path.write_text(json.dumps(_case("C1")) + "\nnot-json\n" + json.dumps(_case("C2")) + "\n",
                    encoding="utf8")
    with pytest.raises(bc.CheckpointCorruption, match="row 2"):
        bc.CaseCheckpoint(path)
    good = bc.CaseCheckpoint(tmp_path / "good.jsonl")
    good.append(_case("C1"))
    with pytest.raises(bc.CheckpointCorruption, match="conflicting result"):
        good.append(_case("C1", families=["sqli"]))


def test_raw_evidence_is_mandatory_even_for_a_non_detection():
    row = _case("C1")
    del row["raw_evidence"]
    with pytest.raises(bc.ContractError, match="raw_evidence"):
        bc.validate_case_result(row)


def test_key_loader_runs_only_after_an_unchanged_artifact_is_sealed(tmp_path):
    run = tmp_path / "run.jsonl"
    run.write_text(json.dumps(_case("C1")) + "\n", encoding="utf8")
    key = tmp_path / "key.csv"
    key.write_text("C1,sqli,true\n", encoding="ascii")
    called = []
    seal = bc.seal_run(run, git_sha="abc")
    loaded, receipt = bc.load_key_after_seal(
        seal, key, lambda path: called.append(path) or {"C1": ("sqli", True)})
    assert called == [str(key.resolve())] and loaded["C1"][1] is True
    assert receipt["ordering_ok"] is True and receipt["run_seal"]["sha256"] == seal.sha256


def test_tampering_after_seal_blocks_the_key_loader(tmp_path):
    run = tmp_path / "run.jsonl"
    run.write_text("original\n", encoding="ascii")
    key = tmp_path / "key.csv"
    key.write_text("secret", encoding="ascii")
    seal = bc.seal_run(run)
    run.write_text("changed\n", encoding="ascii")
    called = []
    with pytest.raises(bc.SealError, match="changed after"):
        bc.load_key_after_seal(seal, key, lambda path: called.append(path))
    assert called == [], "ground truth must remain unread when the blind artifact no longer matches"


def test_b1_scoring_keeps_official_and_product_false_positives_separate():
    key = {"V": ("securecookie", True), "C": ("securecookie", False)}
    results = [
        _case("V", "securecookie", ["insecure_cookie"]),
        _case("C", "securecookie", ["path_traversal"]),
    ]
    score = bc.score_b1(results, key, {"securecookie": {"insecure_cookie"}})
    assert score["publishable"] is True and score["denominator"] == 2
    assert score["official"]["overall"] == {
        "tp": 1, "tn": 1, "fp": 0, "fn": 0, "denominator": 2,
        "precision": 1.0, "recall": 1.0, "f1": 1.0, "fpr": 0.0, "fnr": 0.0,
    }
    assert score["product"]["overall"]["fp"] == 1
    assert score["product"]["overall"]["fpr"] == 1.0
    assert score["cross_family_fp"] == 1
    by_id = {row["case_id"]: row for row in score["per_case"]}
    assert by_id["C"]["raw_evidence"] == results[1]["raw_evidence"]


def test_leads_and_empty_family_rows_cannot_invent_a_product_false_positive():
    key = {"C1": ("securecookie", False), "C2": ("securecookie", False)}
    results = [
        _case("C1", "securecookie", ["path_traversal"], ["lead"]),
        _case("C2", "securecookie", [], ["confirmed"]),
    ]
    score = bc.score_b1(results, key, {"securecookie": {"insecure_cookie"}})
    assert score["product"]["overall"]["fp"] == 0
    assert score["product"]["overall"]["tn"] == 2


def test_an_unresolved_b1_case_keeps_the_denominator_but_blocks_accuracy_claims():
    key = {"V": ("sqli", True), "C": ("sqli", False)}
    results = [_case("V", families=["sqli"]),
               _case("C", status=bc.ENVIRONMENT_FAILURE, evidence={"error": "lab down"})]
    score = bc.score_b1(results, key, {"sqli": {"sqli"}})
    assert score["denominator"] == 2 and score["measured"] == 1
    assert score["publishable"] is False
    assert score["official"] is None and score["product"] is None
    assert score["unresolved"][0]["result"] == bc.ENVIRONMENT_FAILURE


def test_score_is_independent_of_case_order():
    key = {"A": ("sqli", True), "B": ("sqli", False)}
    rows = [_case("A", families=["sqli"]), _case("B")]
    assert bc.score_b1(rows, key, {"sqli": {"sqli"}}) == bc.score_b1(
        list(reversed(rows)), key, {"sqli": {"sqli"}})


def test_unmodified_owasp_adapter_meets_the_measured_conformance_floor(tmp_path):
    rows = {row["clause"]: row for row in bc.assess_owasp_bench(owasp_bench, tmp_path)}
    for clause in ("dual_official_product_scoring", "full_suite_macro_denominator",
                   "checkpoint_flush_and_fsync", "checkpoint_resume", "truncated_tail_recovery"):
        assert rows[clause]["status"] == bc.CONFORMANT, rows[clause]
    assert rows["full_b1_metric_set"]["status"] in (bc.PARTIAL, bc.CONFORMANT)
    for clause in ("raw_evidence_retention", "seal_before_key_enforced",
                   "explicit_result_vocabulary", "environment_failure_not_scored",
                   "position_independence"):
        assert rows[clause]["status"] in (bc.GAP, bc.PARTIAL, bc.CONFORMANT)


def test_conformance_artifact_has_required_provenance_and_a_stable_semantic_digest(tmp_path):
    first = bc.conformance_artifact(owasp_bench, tmp_path / "a", git_sha="abc")
    second = bc.conformance_artifact(owasp_bench, tmp_path / "b", git_sha="abc")
    assert first["git_sha"] == "abc" and first["environment_failures"] == []
    assert first["semantic_sha256"] == second["semantic_sha256"]
    assert sum(first["summary"].values()) == len(first["per_entry"])
