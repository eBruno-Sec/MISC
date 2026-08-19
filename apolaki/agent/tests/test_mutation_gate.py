"""The mutation gate itself (#125, Robust Python Ch.24).

The full gate re-runs the suite once per mutant, so it is opt-in via APOLAKI_MUTATION_GATE=1 (and in the
ship-gate). These tests keep the harness honest cheaply, so a broken gate cannot quietly pass.
"""
import ast
import os

import pytest

import mutation_gate as mg


AGENT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# MEASURED 2026-08-09: 48 modules explicitly produce a {"confidence": "confirmed"} finding and only
# two of those modules have a mutant, leaving 46 uncovered. This ceiling may fall, never rise.
_KNOWN_UNMUTATED_CONFIRMED_PRODUCERS = 46

# The baseline as a SET (Q-076 anti-idle), which is a different thing from the count above and exists for
# a different reason. RE-MEASURED 2026-08-18: 53 producers, 11 mutant modules of which only 7 are
# producers (bie, blind_benchmark, dependency_intel and proof_schema are oracle modules that emit no
# literal confirmed finding), so 53 - 7 = 46 uncovered against a ceiling of 46. Slack 0.
#
# WHY, given slack is already 0 and a pure addition already fails. Because slack 0 does NOT close the
# swap. MEASURED on an isolated snapshot: register a mutant for `sqli_tool.py` AND add a new module
# emitting {"confidence": "confirmed"} with no mutant, and `uncovered` stays at 46 -- a new unguarded
# confirmed-producer ships and this ratchet passes in silence. That is the Q-076 defect exactly, and a
# count cannot express it, because the count did not move.
#
# The second gain is the message. Without a baseline the failure prints all 47 sorted names and the
# reader must diff them against memory; the new one landed FIRST in that list only because it was called
# `apolaki_new_engine.py`, and a `zzz_tool.py` would have sorted last.
#
# `len(_UNCOVERED_BASELINE) <= _KNOWN_UNMUTATED_CONFIRMED_PRODUCERS` is asserted below, and that
# inequality is what makes a firing alarm provably non-empty.
#
# Deliberately NO staleness test, for the reason Q-075 recorded: this set moves whenever any lane adds a
# mutant, and failing their green work to force an edit to a file they do not own is how a gate earns the
# distrust that gets it silenced. Rot runs one way only, into `covered_since`, never into a false
# `newly_uncovered`.
_UNCOVERED_BASELINE = frozenset({
    "cache_deception_tool.py", "client_checks_tool.py", "cmdi_tool.py", "codereview.py",
    "collaborator.py", "create_object_idor.py", "css_injection_tool.py", "default_creds_tool.py",
    "deser_tool.py", "dom_tool.py", "dom_trace.py", "encoding_probe.py", "enip_audit_tool.py",
    "exposure_tool.py", "graphql_tool.py", "ics_fingerprint.py", "ipmi_audit_tool.py", "jwt_tool.py",
    "ldap_enum_tool.py", "ldap_tool.py", "llm_tool.py", "main.py", "modbus_audit_tool.py",
    "nosqli_tool.py", "ntp_audit_tool.py", "oauth_tool.py", "rdp_audit_tool.py", "read_object_idor.py",
    "rsync_audit_tool.py", "saml_tool.py", "session_fixation_tool.py", "session_token_tool.py",
    "smb_enum_tool.py", "snmp_audit_tool.py", "sqli_tool.py", "ssh_audit_tool.py", "ssi_tool.py",
    "ssrf_tool.py", "tools.py", "upload_tool.py", "username_enum_tool.py", "vnc_audit_tool.py",
    "waf_bypass_tool.py", "xpath_tool.py", "xss_tool.py", "xxe_tool.py",
})


def _uncovered_delta(uncovered):
    """The true set difference, in both directions, plus the message. Mirrors `liveness.py::evaluate`
    with the polarity inverted: the baseline records what is UNGUARDED, so `now - base` is the
    regression and `base - now` is another lane's green work."""
    newly_uncovered = sorted(set(uncovered) - _UNCOVERED_BASELINE)
    covered_since = sorted(_UNCOVERED_BASELINE - set(uncovered))
    lines = ["confirmed-producing modules without a mutant: %d (ceiling %d, recorded baseline %d)"
             % (len(uncovered), _KNOWN_UNMUTATED_CONFIRMED_PRODUCERS, len(_UNCOVERED_BASELINE))]
    if newly_uncovered:
        lines.append("NEWLY UNCOVERED -- produces a confirmed finding, has no mutant, and is not in the "
                     "recorded baseline:")
        lines += ["  %s" % n for n in newly_uncovered]
    else:
        lines.append("NEWLY UNCOVERED -- none. Every module now uncovered is already in the recorded "
                     "baseline, so a true set difference has no names to give; that is only possible if "
                     "the recorded baseline outgrew the ceiling.")
    if covered_since:
        lines.append("gained a mutant since the baseline was recorded (green work, never a failure):")
        lines += ["  %s" % n for n in covered_since]
    lines.append("A new confirmed-producing module must add a mutant or consume existing debt.")
    return {"newly_uncovered": newly_uncovered, "covered_since": covered_since,
            "message": "\n".join(lines)}


def _a_mutant_for(module):
    """The first registered mutant targeting `module`, by NAME rather than by index.

    These tests used `MUTANTS[0]` while also hardcoding `bie.py` as the file to check, so the list's
    ORDER was load-bearing without saying so. Adding a mutant at the front (ws_tool.py, Q-002) made
    `_apply` silently no-op against bie.py and two unrelated tests failed. Selecting by module means
    the registry can be extended in any order -- and a test that pins an index is a test that fails
    for a reason unrelated to what it is about.
    """
    for m in mg.MUTANTS:
        if m[0] == module:
            return m
    raise AssertionError("no mutant registered for %s" % module)


def _literal(node, value):
    return isinstance(node, ast.Constant) and node.value == value


def _produces_confirmed_finding(tree):
    """Find explicit confirmed-finding writes without counting modules that merely consume the string."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Dict):
            if any(_literal(k, "confidence") and _literal(v, "confirmed")
                   for k, v in zip(node.keys, node.values)):
                return True
        if isinstance(node, ast.Call) and getattr(node.func, "id", None) == "dict":
            if any(k.arg == "confidence" and _literal(k.value, "confirmed") for k in node.keywords):
                return True
        if isinstance(node, (ast.Assign, ast.AnnAssign)) and _literal(node.value, "confirmed"):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if any(isinstance(t, ast.Subscript) and _literal(t.slice, "confidence") for t in targets):
                return True
    return False


def _confirmed_producer_modules():
    producers = set()
    for fname in sorted(os.listdir(AGENT_DIR)):
        if not fname.endswith(".py"):
            continue
        path = os.path.join(AGENT_DIR, fname)
        with open(path, encoding="utf8") as src:
            tree = ast.parse(src.read(), filename=path)
        if _produces_confirmed_finding(tree):
            producers.add(fname)
    return producers


def test_the_original_oracle_modules_keep_their_mutants():
    covered = {m[0] for m in mg.MUTANTS}
    required = {"bie.py", "transport_posture.py", "ics_dnp3_s7.py", "blind_benchmark.py",
                "proof_schema.py"}
    assert required <= covered, "oracle modules with no mutant: %s" % sorted(required - covered)


def test_confirmed_producers_without_a_mutant_never_grow():
    """RATCHET. Adding a confirmed-producing module must add a mutant or consume existing debt."""
    producers = _confirmed_producer_modules()
    named_uncovered = {"sqli_tool.py", "cmdi_tool.py", "graphql_tool.py", "ssrf_tool.py",
                       "xxe_tool.py", "dom_trace.py", "encoding_probe.py", "exposure_tool.py"}
    assert named_uncovered <= producers, "producer scan became vacuous: %s" % sorted(named_uncovered - producers)

    covered = {m[0] for m in mg.MUTANTS}
    uncovered = producers - covered
    assert len(uncovered) <= _KNOWN_UNMUTATED_CONFIRMED_PRODUCERS, _uncovered_delta(uncovered)["message"]


def test_no_unguarded_confirmed_producer_appears_that_the_baseline_does_not_hold():
    """RATCHET TWO, the SET -- the one the count above cannot express (Q-076 anti-idle).

    A module gaining a mutant and a new confirmed-producer arriving in the same run leave the count
    untouched at 46, and the count ratchet passes. MEASURED: that is exactly what happened when the
    control registered a mutant for `sqli_tool.py` and added a new engine alongside it. This is the
    assertion that sees it, and it names the module rather than reprinting all 47.

    `covered_since` is deliberately absent from the condition: a name leaving the baseline is a lane
    adding a mutant, which is the whole point of the ratchet."""
    producers = _confirmed_producer_modules()
    uncovered = producers - {m[0] for m in mg.MUTANTS}
    delta = _uncovered_delta(uncovered)
    assert not delta["newly_uncovered"], delta["message"]


def test_a_recorded_baseline_no_larger_than_the_ceiling_guarantees_a_named_entry():
    """The property that makes the alarm's message provably non-empty. If every uncovered module were
    already recorded, the count could be at most len(baseline); with that <= the ceiling the count ratchet
    would not have fired, so a firing alarm always has a name to print."""
    assert len(_UNCOVERED_BASELINE) <= _KNOWN_UNMUTATED_CONFIRMED_PRODUCERS, (
        "recorded baseline of %d exceeds the ceiling of %d -- a rise could then name nothing"
        % (len(_UNCOVERED_BASELINE), _KNOWN_UNMUTATED_CONFIRMED_PRODUCERS))


def test_the_recorded_baseline_is_shaped_like_a_real_measurement():
    """A hand-typed set rots into fiction quietly, so the entries are checked for shape.

    STRUCTURE ONLY, and deliberately so. A first draft also asserted that no recorded entry currently has
    a mutant -- and the swap control caught it immediately, because that is a STALENESS TEST wearing a
    structural disguise: the moment a lane adds a mutant for a recorded module, its green work turns this
    file red for a fact that is already reported, correctly and harmlessly, under `covered_since`. Rot
    runs one way only. `mg.MUTANTS` is live data and must not appear in an assertion about these
    literals."""
    for name in _UNCOVERED_BASELINE:
        assert name.endswith(".py") and "/" not in name and "::" not in name, name


def test_the_delta_names_both_directions_and_says_so_when_it_cannot():
    """The message itself, on synthetic inputs, including the branch that has nothing to name."""
    sample = next(iter(_UNCOVERED_BASELINE))
    named = _uncovered_delta((_UNCOVERED_BASELINE - {sample}) | {"brand_new_engine.py"})
    assert named["newly_uncovered"] == ["brand_new_engine.py"]
    assert named["covered_since"] == [sample]
    assert "brand_new_engine.py" in named["message"] and "NEWLY UNCOVERED" in named["message"]
    assert sample in named["message"] and "never a failure" in named["message"]

    blind = _uncovered_delta(set(_UNCOVERED_BASELINE))
    assert blind["newly_uncovered"] == [] and blind["covered_since"] == []
    assert "none" in blind["message"] and "no names to give" in blind["message"]


def test_the_swap_that_the_count_cannot_see_is_named(monkeypatch):
    """NEGATIVE CONTROL for this ratchet, the same shape Q-076 required.

    Reproduces the measured event: one recorded module gains a mutant while a brand-new confirmed
    producer arrives with none. The COUNT is unchanged and its ratchet passes -- asserted here, because a
    control that also moved the count would not prove the set ratchet contributed anything."""
    victim = sorted(_UNCOVERED_BASELINE)[0]
    swapped = (_UNCOVERED_BASELINE - {victim}) | {"apolaki_smuggled_engine.py"}
    assert len(swapped) == len(_UNCOVERED_BASELINE), "the control must hold the count constant"
    assert len(swapped) <= _KNOWN_UNMUTATED_CONFIRMED_PRODUCERS, "the count ratchet must still pass"

    delta = _uncovered_delta(swapped)
    assert delta["newly_uncovered"] == ["apolaki_smuggled_engine.py"], delta["newly_uncovered"]
    assert delta["covered_since"] == [victim], delta["covered_since"]
    assert "apolaki_smuggled_engine.py" in delta["message"] and victim in delta["message"]
    # And nothing else is named. A message that names the wrong thing is the Q-075 failure inverted.
    body = delta["message"].split("NEWLY UNCOVERED")[1].split("gained a mutant")[0]
    for innocent in sorted(_UNCOVERED_BASELINE)[1:6]:
        assert innocent not in body, "%s is not the delta and must not be named" % innocent


def test_the_baseline_literals_cannot_be_self_read():
    """Recording a baseline as strings nearly silenced a different ratchet in Q-075, where the scan read
    its own source and matched its own literals. Checked rather than assumed: the producer scan lists only
    top-level `agent/*.py` and this file lives in `agent/tests/`, and it matches AST dict/assign shapes,
    so a module NAME in a set literal is not a confirmed-finding producer under any reading."""
    producers = _confirmed_producer_modules()
    assert not any(p.startswith("test_") for p in producers), sorted(producers)
    assert producers, "positive control: the producer scan must still find something"
    assert os.path.basename(__file__) not in producers


def test_an_empty_mutant_list_runs_nothing_rather_than_everything():
    """`mutants or MUTANTS` would make an empty list falsy and silently expand to the FULL gate — twelve
    full suite runs for a caller who asked for none. Caught when a test in this file passed `[]` and
    quietly turned the normal suite into the slow gate."""
    res = mg.run([])
    assert res["results"] == [] and res["killed"] == [] and res["survived"] == []


def test_mutants_are_well_formed():
    for module, desc, pattern, repl, tests in mg.MUTANTS:
        assert module.endswith(".py") and tests.startswith("tests/") and "::test_" in tests
        assert len(desc) > 20, desc
        assert pattern and repl and pattern != repl


def test_an_import_error_does_not_impersonate_an_oracle_kill(tmp_path):
    """Regression: the old `returncode != 0` predicate credited this broken import as a killed mutant."""
    app = tmp_path / "synthetic_app"
    tests = app / "tests"
    tests.mkdir(parents=True)
    victim = app / "victim.py"
    original = b"VALUE = 1\n"
    victim.write_bytes(original)
    (tests / "test_victim.py").write_text(
        "import victim\n\ndef test_oracle_guard():\n    assert victim.VALUE == 1\n", encoding="utf8")
    mutant = [("victim.py", "break import instead of weakening the oracle guard",
               r"VALUE = 1", "VALUE = (", "tests/test_victim.py::test_oracle_guard")]

    res = mg.run(mutant, app_dir=str(app), timeout=60)
    record = res["results"][0]
    assert record["pytest_returncode"] != 0, "the synthetic import break did not make pytest fail"
    assert record["killed"] is False, "a collection/import error was credited as an oracle kill"
    assert record["outcome"] == "expected test did not fail"
    assert victim.read_bytes() == original and not (app / "victim.py.mutbak").exists()


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
    mg.run([_a_mutant_for("bie.py")])
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
    module, desc, pattern, repl, tests = _a_mutant_for("bie.py")
    assert module == "bie.py"

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
    module, desc, pattern, repl, tests = _a_mutant_for("bie.py")
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
