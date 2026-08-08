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


def test_an_empty_mutant_list_runs_nothing_rather_than_everything():
    """`mutants or MUTANTS` would make an empty list falsy and silently expand to the FULL gate — twelve
    full suite runs for a caller who asked for none. Caught when a test in this file passed `[]` and
    quietly turned the normal suite into the slow gate."""
    res = mg.run([])
    assert res["results"] == [] and res["killed"] == [] and res["survived"] == []


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


def test_a_crashed_run_is_recovered_before_the_next_one_applies_anything():
    """The dangerous failure mode, simulated. A run killed between apply and restore leaves the source
    weakened and a `.mutbak` holding the original. The next run then cannot match its pattern and reports
    "guard changed, mutant is stale" — which tells the operator to update the MUTANT, cementing the
    weakened guard as the new baseline. The gate would pass while defending nothing.

    `make mutation-gate` runs `docker exec` against the LIVE agent, so the weakened guard would also be
    what the running scanner uses until someone rebuilds."""
    path = os.path.join(mg.APP_DIR, "bie.py")
    original = open(path, encoding="utf8").read()
    module, desc, pattern, repl, tests = mg.MUTANTS[0]
    assert module == "bie.py", "this test pins MUTANTS[0]; update it if the order changed"

    # Simulate the crash: apply the mutant, then do NOT restore.
    assert mg._apply(path, pattern, repl)
    assert open(path, encoding="utf8").read() != original, "the mutant did not actually change the file"
    assert os.path.exists(path + ".mutbak")

    try:
        recovered = mg.recover()
        assert "bie.py" in recovered, recovered
        assert open(path, encoding="utf8").read() == original, "recover() did not restore the original"
        assert not os.path.exists(path + ".mutbak")
    finally:
        mg._restore(path)                       # belt-and-braces if an assert above fired
        if open(path, encoding="utf8").read() != original:
            open(path, "w", encoding="utf8").write(original)


def test_a_recovery_is_reported_not_silent():
    """Recovering is not the same as nothing having gone wrong — the run must say so."""
    path = os.path.join(mg.APP_DIR, "bie.py")
    original = open(path, encoding="utf8").read()
    module, desc, pattern, repl, tests = mg.MUTANTS[0]
    assert mg._apply(path, pattern, repl)
    try:
        res = mg.run([])                        # no mutants: exercises only the recovery step
        assert res["recovered"] == ["bie.py"], res["recovered"]
        assert "recovered" in res["summary"], res["summary"]
    finally:
        mg._restore(path)
        if open(path, encoding="utf8").read() != original:
            open(path, "w", encoding="utf8").write(original)
    assert open(path, encoding="utf8").read() == original


@pytest.mark.skipif(os.environ.get("APOLAKI_MUTATION_GATE") != "1",
                    reason="full mutation gate is slow; set APOLAKI_MUTATION_GATE=1 (ship-gate runs it)")
def test_no_mutant_weakening_a_false_positive_guard_survives():
    """THE GATE. A survivor means the suite does not defend that guard — which is exactly how
    blind_benchmark._has_proof was found accepting evidence-free findings."""
    res = mg.run()
    assert res["passed"], res["summary"] + " :: survived=%s not_applied=%s" % (
        [r["desc"] for r in res["survived"]], [r["desc"] for r in res["not_applied"]])
