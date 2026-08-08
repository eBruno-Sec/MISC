"""The mutation gate itself (#125, Robust Python Ch.24).

The full gate re-runs the suite once per mutant, so it is opt-in via APOLAKI_MUTATION_GATE=1 (and in the
ship-gate). These tests keep the harness honest cheaply, so a broken gate cannot quietly pass.
"""
import os

import pytest

import mutation_gate as mg


def test_every_oracle_module_with_an_fp_guard_has_a_mutant():
    """A new oracle without a mutant is an unguarded guard. This is the list that must grow."""
    covered = {m[0] for m in mg.MUTANTS}
    required = {"bie.py", "transport_posture.py", "ics_dnp3_s7.py", "blind_benchmark.py",
                "proof_schema.py"}
    assert required <= covered, "oracle modules with no mutant: %s" % sorted(required - covered)


def test_mutants_are_well_formed():
    for module, desc, pattern, repl, tests in mg.MUTANTS:
        assert module.endswith(".py") and tests.startswith("tests/")
        assert len(desc) > 20, desc
        assert pattern and repl and pattern != repl


def test_a_stale_mutant_fails_the_gate_rather_than_passing_silently():
    """If a guard is refactored so its pattern no longer matches, the mutant cannot be applied. That must
    FAIL the gate — otherwise an unguarded rewrite slips through looking green."""
    bogus = [("bie.py", "a pattern that cannot possibly match anything in the file",
              r"ZZZ_this_pattern_does_not_exist_ZZZ", "x", "tests/test_bie.py")]
    res = mg.run(bogus)
    assert res["passed"] is False
    assert res["not_applied"] and "stale" in res["not_applied"][0]["why"]


def test_the_gate_restores_every_file_it_touches():
    """A mutation run that leaves a mutated file behind would poison the repo."""
    path = os.path.join(mg.APP_DIR, "bie.py")
    before = open(path, encoding="utf8").read()
    mg.run([mg.MUTANTS[0]])
    assert open(path, encoding="utf8").read() == before
    assert not os.path.exists(path + ".mutbak")


@pytest.mark.skipif(os.environ.get("APOLAKI_MUTATION_GATE") != "1",
                    reason="full mutation gate is slow; set APOLAKI_MUTATION_GATE=1 (ship-gate runs it)")
def test_no_mutant_weakening_a_false_positive_guard_survives():
    """THE GATE. A survivor means the suite does not defend that guard — which is exactly how
    blind_benchmark._has_proof was found accepting evidence-free findings."""
    res = mg.run()
    assert res["passed"], res["summary"] + " :: survived=%s not_applied=%s" % (
        [r["desc"] for r in res["survived"]], [r["desc"] for r in res["not_applied"]])
