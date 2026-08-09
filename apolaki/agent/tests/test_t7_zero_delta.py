"""T7 zero-behaviour-delta proof — the engine contract moved, routing did not.

T7 makes `engine_descriptor` the source of truth for `OBSERVATIONS`, `PRECONDITIONS` and `ALWAYS_ON`;
`technique_planner` re-exports them. That is a pure refactor, and the whole safety argument rests on one
claim: **the tables the platform routes on are byte-identical to what they were before the move.**

A refactor that quietly altered routing would look exactly like one that did not — every other test would
still pass, because they assert properties of the tables rather than their contents. So the contents are
pinned against `t7_tables_snapshot.json`, captured from the running system immediately BEFORE the move.

If a table legitimately changes later (a new engine, a new precondition), this test SHOULD fail: it is a
change-detector, not a correctness oracle. Regenerate the snapshot in the same commit that makes the
change, so the diff shows both.
"""
import json
import os

import engine_descriptor as ed
import technique_planner as tp

SNAPSHOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "t7_tables_snapshot.json")


def _snap():
    with open(SNAPSHOT, encoding="utf8") as fh:
        return json.load(fh)


def test_observation_vocabulary_is_unchanged():
    assert list(ed.OBSERVATIONS) == _snap()["OBSERVATIONS"]


def test_precondition_gate_is_unchanged():
    """THE load-bearing one. A single altered precondition silently changes which engines a scan runs."""
    before = _snap()["PRECONDITIONS"]
    after = {k: list(v) for k, v in ed.PRECONDITIONS.items()}
    assert after == before, "precondition gate changed: %s" % sorted(
        set(before) ^ set(after)) or "same keys, different values"


def test_always_on_reasons_are_unchanged():
    assert dict(ed.ALWAYS_ON) == _snap()["ALWAYS_ON"]


def test_the_planner_re_exports_the_very_same_objects_not_copies():
    """A copy would be a second source of truth — exactly what the descriptor exists to remove. Identity,
    not equality: `is`, so a future edit cannot fork them."""
    assert tp.OBSERVATIONS is ed.OBSERVATIONS
    assert tp._PRECONDITIONS is ed.PRECONDITIONS
    assert tp.ALWAYS_ON is ed.ALWAYS_ON


def test_the_dependency_now_runs_descriptor_first():
    """engine_descriptor must not import technique_planner — that was the old direction, and reinstating
    it would make the two mutually dependent."""
    src = open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                            "engine_descriptor.py"), encoding="utf8").read()
    code = "\n".join(l for l in src.splitlines() if not l.strip().startswith("#"))
    body = code.split('"""', 2)[-1]                    # skip the module docstring
    assert "import technique_planner" not in body, "descriptor must not depend on the planner"


def test_orchestration_audit_still_reports_no_islands():
    """The invariant the whole platform is built on, re-checked after the move."""
    import techniques as T
    a = tp.orchestration_audit([T.get(t["id"]) for t in T.list_techniques()])
    assert a["islands"] == [], a["islands"]
    # always_on 40 -> 41 (enip_exposed, T14) -> 45 (request_url_override, dom_link_manipulation,
    # dom_data_manipulation, base64_param). Every one of these engines was ALREADY shipping confirmed
    # findings — the blind benchmark was even scoring them as true positives — while having no registry
    # record at all: no taxonomy entry, no coverage credit, no planner reachability, no remediation
    # mapping. The count rising is the gap closing, not new engines appearing.
    assert len(a["gated"]) == 41 and len(a["always_on"]) == 45, (len(a["gated"]), len(a["always_on"]))


def test_planning_from_evidence_produces_the_same_selection():
    """End-to-end: the same observations must still select the same techniques in the same order."""
    import techniques as T
    full = [T.get(t["id"]) for t in T.list_techniques()]
    for obs in ({"has_login"}, {"has_api", "serves_js"}, {"authenticated", "has_login"}, set()):
        selected = tp.plan(obs, full)
        # Every selected technique's preconditions must hold — the gate, unchanged by the move.
        for p in selected:
            assert set(ed.PRECONDITIONS[p["id"]]) <= obs, (p["id"], obs)
        # And nothing applicable was dropped.
        expected = {tid for tid, pre in ed.PRECONDITIONS.items()
                    if set(pre) <= obs and any(t.get("id") == tid for t in full)}
        assert {p["id"] for p in selected} == expected, obs
    assert tp.plan(set(), full) == [], "no evidence must select nothing, not everything"


def test_snapshot_covers_every_table_the_planner_exposes():
    """Guard against the snapshot silently going out of date by omission rather than by mismatch."""
    snap = _snap()
    assert set(snap) == {"OBSERVATIONS", "PRECONDITIONS", "ALWAYS_ON"}
    assert len(snap["PRECONDITIONS"]) == 41 and len(snap["ALWAYS_ON"]) == 45   # +enip_exposed, +4 DOM/encoding families
    assert len(snap["OBSERVATIONS"]) == 17
