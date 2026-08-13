from __future__ import annotations

import proof_schema
from tier3 import registry
from tier3.runner import ERROR, NOT_RUN, PASS, build_artifact, run_controls


def _spec(control_id, node_id):
    return registry.ControlSpec(
        control_id=control_id,
        vulnerability_class="test_class",
        cwe=(),
        control_kind=registry.SAFE,
        node_id=node_id,
        proof_kind=proof_schema.proof_kind({}),
        naive_failure="A missing node could be counted as coverage.",
    )


def test_registry_is_valid_and_covers_every_declared_source_file():
    assert registry.validate_registry() == []
    assert {c.source_file for c in registry.CONTROLS} == registry.SOURCE_FILES


def test_every_entry_names_an_exact_node_and_the_naive_failure():
    for control in registry.CONTROLS:
        assert "::test_" in control.node_id
        assert control.naive_failure.strip()


def test_proof_kind_comes_from_the_shared_schema_vocabulary():
    source = {c.proof_kind for c in registry.CONTROLS if c.vulnerability_class.startswith("weak_")}
    behavioural = {c.proof_kind for c in registry.CONTROLS if c.vulnerability_class == "sqli"}
    assert source == {proof_schema.proof_kind({"lane": "code-assisted"})}
    assert behavioural == {proof_schema.proof_kind({})}


def test_a_registered_node_that_does_not_exist_is_not_run(tmp_path):
    (tmp_path / "test_sample.py").write_text("def test_real():\n    assert True\n", encoding="ascii")
    artifact = run_controls(
        controls=(_spec("real", "test_sample.py::test_real"),
                  _spec("stale", "test_sample.py::test_missing")),
        repo_root=tmp_path,
        timeout_s=20,
        git_sha="test-sha",
    )
    by_id = {row["control_id"]: row for row in artifact["per_entry"]}
    assert by_id["real"]["status"] == PASS
    assert by_id["stale"]["status"] == NOT_RUN
    assert artifact["coverage"]["passed"] == 1
    assert artifact["coverage"]["registered"] == 2


def test_an_import_error_is_an_error_not_a_killed_or_passing_control(tmp_path):
    (tmp_path / "test_broken.py").write_text(
        "import module_that_does_not_exist\n\ndef test_target():\n    assert True\n", encoding="ascii")
    artifact = run_controls(
        controls=(_spec("broken", "test_broken.py::test_target"),),
        repo_root=tmp_path,
        timeout_s=20,
        git_sha="test-sha",
    )
    assert artifact["per_entry"][0]["status"] in (ERROR, NOT_RUN)
    assert artifact["coverage"]["passed"] == 0
    assert artifact["environment_failures"]


def test_only_executed_passes_create_safe_coverage():
    rows = [
        {**_spec("pass", "test_x.py::test_pass").to_dict(), "status": PASS},
        {**_spec("missing", "test_x.py::test_missing").to_dict(), "status": NOT_RUN},
    ]
    artifact = build_artifact(rows, [], git_sha="abc")
    cls = artifact["per_class"]["test_class"]
    assert cls["registered"] == 2 and cls["passed"] == 1
    assert cls["has_passing_safe_control"] is True
    assert artifact["coverage"]["passed"] == 1


def test_artifact_carries_required_identity_rollups_and_semantic_digest():
    row = {**_spec("pass", "test_x.py::test_pass").to_dict(), "status": PASS,
           "pytest_nodes": ["test_x.py::test_pass"], "pytest_returncode": 0,
           "stdout_tail": "1 passed in 0.10s"}
    first = build_artifact([row], [], git_sha="abc")
    second = build_artifact([{**row, "stdout_tail": "1 passed in 9.99s"}], [], git_sha="abc")
    for key in ("tool_version", "git_sha", "timestamp", "per_entry", "per_class",
                "environment_failures", "semantic_sha256"):
        assert key in first
    assert first["semantic_sha256"] == second["semantic_sha256"]
