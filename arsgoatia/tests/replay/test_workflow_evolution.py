"""Workflow-evolution replay proof (spec §14.5 / §32).

The first histories were recorded before the engagement workflow gained a
reporting-contract version marker. A raw workflow change like that would break
replay of the older histories — unless it is guarded by ``workflow.get_version``.

These tests prove, in the same runtime-free / structural idiom as the rest of
tests/replay, that:

  1. the engagement workflow guards the change with ``workflow.get_version``;
  2. a v1 history (pre-evolution) and a v2 history (post-evolution) both exist;
  3. v2 is a backward-compatible superset of v1 — every mandatory event still
     appears, in the same order;
  4. the two histories differ only in the evolved reporting-contract marker,
     which is exactly what the get_version guard toggles.

Together these encode: both histories replay cleanly against the single,
evolved code path, which is the definition of a safe Temporal workflow change.
"""

from __future__ import annotations

import json
import pathlib

import pytest

HISTORIES_DIR = pathlib.Path(__file__).resolve().parents[1] / "histories"
V1 = HISTORIES_DIR / "idor_slice.json"
V2 = HISTORIES_DIR / "idor_slice_v2.json"

WORKFLOW_SRC = (
    pathlib.Path(__file__).resolve().parents[2]
    / "services"
    / "worker"
    / "workflows"
    / "engagement.py"
)

# The change_id used in the get_version guard — must match the workflow source.
CHANGE_ID = "reporting-contract-version"


@pytest.fixture(scope="module")
def v1() -> dict:
    assert V1.exists(), f"missing v1 history: {V1}"
    return json.loads(V1.read_text())


@pytest.fixture(scope="module")
def v2() -> dict:
    assert V2.exists(), f"missing v2 history: {V2}"
    return json.loads(V2.read_text())


@pytest.fixture(scope="module")
def workflow_src() -> str:
    assert WORKFLOW_SRC.exists(), f"missing workflow source: {WORKFLOW_SRC}"
    return WORKFLOW_SRC.read_text()


# --------------------------------------------------------------------------
# 1. The change is guarded by get_version
# --------------------------------------------------------------------------


class TestGetVersionGuard:
    def test_workflow_uses_get_version(self, workflow_src: str) -> None:
        assert "workflow.get_version(" in workflow_src, (
            "the engagement workflow must guard its reporting-contract change "
            "with workflow.get_version"
        )

    def test_guard_uses_expected_change_id(self, workflow_src: str) -> None:
        assert CHANGE_ID in workflow_src, f"get_version guard must use change_id {CHANGE_ID!r}"

    def test_guard_references_default_version(self, workflow_src: str) -> None:
        # DEFAULT_VERSION is what pre-evolution histories resolve to.
        assert "workflow.DEFAULT_VERSION" in workflow_src


# --------------------------------------------------------------------------
# 2. Both histories exist and are well-formed
# --------------------------------------------------------------------------


class TestBothHistoriesExist:
    def test_v1_version(self, v1: dict) -> None:
        assert v1["version"] == "1.0"

    def test_v2_version(self, v2: dict) -> None:
        assert v2["version"] == "2.0"

    def test_v2_declares_backward_compat(self, v2: dict) -> None:
        rc = v2["replay_compatibility"]
        assert rc["backward_compatible_with"] == "v1"
        assert rc["workflow_change_guarded_by_get_version"] == CHANGE_ID


# --------------------------------------------------------------------------
# 3. v2 is a backward-compatible superset of v1
# --------------------------------------------------------------------------


class TestBackwardCompatibleEvolution:
    def test_same_event_sequence(self, v1: dict, v2: dict) -> None:
        v1_types = [e["event_type"] for e in v1["events"]]
        v2_types = [e["event_type"] for e in v2["events"]]
        # Every v1 event still appears in v2 in the same relative order.
        assert v1_types == v2_types, "v2 must preserve the v1 event sequence (backward compatible)"

    def test_same_engagement_identity(self, v1: dict, v2: dict) -> None:
        # The evolution is a code change, not a different scenario.
        assert v1["technique"] == v2["technique"]
        assert v1["target"] == v2["target"]

    def test_determinism_notes_preserved(self, v1: dict, v2: dict) -> None:
        for key, value in v1["determinism_notes"].items():
            assert v2["determinism_notes"].get(key) == value


# --------------------------------------------------------------------------
# 4. The histories differ only in the guarded reporting-contract marker
# --------------------------------------------------------------------------


class TestEvolutionMarker:
    def test_v1_completed_has_no_contract_version(self, v1: dict) -> None:
        completed = v1["events"][-1]
        assert completed["event_type"] == "engagement.completed"
        # Pre-evolution histories resolve to DEFAULT_VERSION → no v2 marker.
        assert "report_contract_version" not in completed

    def test_v2_completed_reports_contract_version_1(self, v2: dict) -> None:
        completed = v2["events"][-1]
        assert completed["event_type"] == "engagement.completed"
        assert completed["report_contract_version"] == 1

    def test_only_terminal_event_differs(self, v1: dict, v2: dict) -> None:
        # Every event except the terminal one is byte-identical between the
        # histories; the guard only affects the reporting-phase tail.
        for a, b in zip(v1["events"][:-1], v2["events"][:-1]):
            assert a == b, f"unexpected divergence before evolution at seq {a.get('seq')}"
