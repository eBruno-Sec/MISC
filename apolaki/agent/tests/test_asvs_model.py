"""ASVS-5 curated-partial objective model (Codex Tier-1 #1): findings violate objectives, clean attempted
checks verify them, blocked/untested are never counted as verified, and the model never claims full ASVS.

Q-012 adds the guard that matters: every `engine` name in OBJECTIVES must resolve to something a REAL
dispatcher can reach, computed from the dispatch tables rather than from a hand-written allowlist (an
allowlist would be the same declaration-vs-fact defect one layer up), plus the rule that a capability the
product does not have reports "not_implemented" and never hides inside "not_tested".
"""
import re

import asvs_model as A
import tools


def _dispatch_reachable():
    """Every tool name a real dispatcher can reach — DERIVED from the dispatch tables, never hand-listed.

    `ToolRegistry.execute()` resolves a call with `getattr(self, "_" + tool_name)`, so a name is reachable
    only when BOTH hold: some emitter can name it, and the method it would resolve to exists. There are two
    emitters, and checking one alone was how phantoms survived — `TOOL_PERMISSIONS` (the gate every
    deterministic/internal dispatch passes through) and `CLAUDE_TOOLS` (the spec handed to the model).
    Aliases fall out for free: spec name `enumerate_ids` resolves via `_enumerate_ids`.
    """
    emitters = set(tools.TOOL_PERMISSIONS) | {t["name"] for t in tools.CLAUDE_TOOLS}
    return {n for n in emitters if hasattr(tools.ToolRegistry, "_" + n)}


def test_the_reachability_scan_is_not_vacuous():
    """Guard the guard: if this set came back empty every assertion below would pass for free."""
    reachable = _dispatch_reachable()
    assert len(reachable) > 50
    assert {"run_sqli", "run_authz_matrix", "run_js_review"} <= reachable


def test_every_objective_engine_resolves_to_a_real_dispatcher():
    """Q-012, the regression that fails the moment the model regains a phantom.

    Six names claimed capability nothing could reach: authz_matrix (the ToolResult LABEL of
    run_authz_matrix), dependency_intel + bizlogic_graph (MODULES, not tools), header_analysis and
    run_deser (never existed at all), run_mass_assignment (no executor, Q-011). Each silently pinned its
    objective to "not_tested" even on a mission that ran every engine in the product.
    """
    reachable = _dispatch_reachable()
    phantom = sorted({n for o in A.OBJECTIVES for n in A._engine_names(o)
                      if n != A.NO_ENGINE and n not in reachable})
    assert phantom == [], (
        "OBJECTIVES name engines no dispatcher can reach (claimed capability that cannot run): %s" % phantom)


def test_no_engine_sentinel_is_only_used_where_a_reason_is_declared():
    """NO_ENGINE must never become a quiet parking spot for a broken name. An objective with no engine has
    to say WHY — safety-excluded (blocked) or capability-absent (not_implemented) — and must not mix the
    sentinel with a real engine, which would let a reader think something ran."""
    for o in A.OBJECTIVES:
        names = A._engine_names(o)
        if A.NO_ENGINE in names:
            assert names == (A.NO_ENGINE,), "%s mixes NO_ENGINE with a real engine: %s" % (o["cid"], names)
            assert o.get("blocked_reason") or o.get("not_implemented_reason"), \
                "%s has no engine and no reason — indistinguishable from an untested objective" % o["cid"]
        else:
            assert not o.get("not_implemented_reason"), \
                "%s claims not-implemented while naming a real engine" % o["cid"]


def test_curated_objectives_tally_and_shape():
    r = A.assess()
    assert r["total_objectives"] == len(A.OBJECTIVES)
    assert sum(r["tally"].values()) == r["total_objectives"]
    assert r["model_type"] == "curated_partial"
    # every objective row carries curated provenance and a local (non-authoritative) cid
    for row in r["objectives"]:
        assert row["provenance"] == "curated"
        assert row["standard"] == "OWASP_ASVS" and row["version"] == "5.0-curated-partial"
        assert not re.match(r"^V\d", row["cid"])         # not a spoofed official clause number (V6.2.1)


def test_findings_map_to_violated_requirements():
    findings = [{"id": "F1", "family": "sqli"}, {"id": "F2", "family": "idor"}]
    m = A.map_findings(findings)
    assert m["VAL-01"] == ["F1"] and m["ATHZ-01"] == ["F2"]
    r = A.assess(findings)
    val01 = next(o for o in r["objectives"] if o["cid"] == "VAL-01")
    athz01 = next(o for o in r["objectives"] if o["cid"] == "ATHZ-01")
    assert val01["status"] == "failed" and val01["finding_ids"] == ["F1"]
    assert athz01["status"] == "failed" and athz01["finding_ids"] == ["F2"]


def test_clean_attempted_check_marks_verified():
    # SQLi engine ran, no sqli finding -> the SQLi objective is VERIFIED (negative-control discipline)
    r = A.assess([], attempted_engines={"run_sqli"})
    val01 = next(o for o in r["objectives"] if o["cid"] == "VAL-01")
    assert val01["status"] == "verified"
    assert r["tally"]["verified"] >= 1


def test_finding_beats_clean_run():
    # engine ran but a violating finding exists -> failed wins over verified
    r = A.assess([{"id": "F9", "family": "sqli"}], attempted_engines={"run_sqli"})
    val01 = next(o for o in r["objectives"] if o["cid"] == "VAL-01")
    assert val01["status"] == "failed"


def test_blocked_objectives_are_never_verified():
    # lockout + MFA are safety-excluded: blocked no matter what engines "ran"
    r = A.assess([], attempted_engines={"run_default_creds", "n/a"})
    blocked = [o for o in r["objectives"] if o["status"] == "blocked"]
    assert {o["cid"] for o in blocked} >= {"AUTHN-05", "AUTHN-06"}
    for o in blocked:
        assert o["status"] != "verified" and o.get("blocked_reason")


def test_attempt_only_objectives_never_auto_verify():
    # business-logic reasoning ran, but it is inconclusive-by-nature -> "attempted", not "verified".
    # Q-012: was driven by "bizlogic_graph", a MODULE name that can never appear in a real ledger, so this
    # asserted behaviour for an input the product cannot produce. Now driven by the real engines.
    r = A.assess([], attempted_engines={"run_workflow", "test_numeric_abuse", "run_race"})
    busl = [o for o in r["objectives"] if o["cid"] in ("BUSL-01", "BUSL-02")]
    assert all(o["status"] == "attempted" for o in busl)


def test_real_emitted_families_fail_their_objective_even_when_engine_ran():
    # Regression: Apolaki's real dominant families (access_control, backup_exposure) must FAIL their
    # objective, never read "verified" just because the authz/exposure engine ran clean of narrower families.
    findings = [{"id": "A", "family": "access_control"}, {"id": "B", "family": "backup_exposure"}]
    ran = {"run_bfla", "confirm_idor", "run_authz_matrix", "run_exposure", "run_dir_harvest"}
    r = A.assess(findings, attempted_engines=ran)
    athz0 = next(o for o in r["objectives"] if o["cid"] == "ATHZ-00")
    comm3 = next(o for o in r["objectives"] if o["cid"] == "COMM-03")
    assert athz0["status"] == "failed" and athz0["finding_ids"] == ["A"]
    assert comm3["status"] == "failed" and comm3["finding_ids"] == ["B"]


def test_umbrella_access_control_fails_when_any_child_violation_exists():
    # #11 regression: ATHZ-00 is the UMBRELLA "no broken access control" property. A confirmed idor/bola/
    # bfla/privilege_escalation/mass_assignment must FAIL it too — it can never read "verified" while a
    # specific access-control child is failed (that self-contradiction was the bug).
    # Q-012: `run_mass_assignment` used to sit in this `ran` set — a name that can NEVER appear in a real
    # ledger, because no such executor exists (Q-011). Asserting behaviour for an impossible input is the
    # guard-that-checks-a-declaration pattern; the set now contains only names a real dispatcher emits.
    # ATHZ-04 is not_implemented, and the mass_assignment case below proves a finding still FAILS it.
    ran = {"run_bfla", "confirm_idor", "run_authz_matrix"}
    for fam, child_cid in (("idor", "ATHZ-01"), ("bola", "ATHZ-01"), ("bfla", "ATHZ-02"),
                           ("privilege_escalation", "ATHZ-02"), ("mass_assignment", "ATHZ-04")):
        r = A.assess([{"id": "X", "family": fam}], attempted_engines=ran)
        athz0 = next(o for o in r["objectives"] if o["cid"] == "ATHZ-00")
        child = next(o for o in r["objectives"] if o["cid"] == child_cid)
        assert athz0["status"] == "failed", "ATHZ-00 must fail for child family %s" % fam
        assert child["status"] == "failed"


def test_untested_is_not_verified():
    r = A.assess()          # nothing ran
    assert r["tally"]["verified"] == 0
    assert r["tally"]["not_tested"] > 0


def test_a_perfect_run_leaves_nothing_merely_not_tested():
    """THE Q-012 regression, stated as an outcome rather than a name check.

    Drive assess() with every engine a real dispatcher can reach — the best a mission could possibly do —
    and nothing may come back "not_tested". Before the fix this returned 3 (AUTHN-04, ATHZ-04, BUSL-01):
    objectives that read "we did not get to it" when the truth was "no engine we have could ever get to it".
    A phantom re-entering OBJECTIVES fails this immediately.
    """
    r = A.assess([], attempted_engines=_dispatch_reachable())
    left = sorted(o["cid"] for o in r["objectives"] if o["status"] == "not_tested")
    assert left == [], "a perfect run still reports these as merely-untested: %s" % left
    assert r["tally"]["not_tested"] == 0


def test_absent_capability_reports_not_implemented_with_a_reason():
    """A capability the product does not have must be distinguishable from one it merely skipped."""
    r = A.assess([], attempted_engines=_dispatch_reachable())
    ni = [o for o in r["objectives"] if o["status"] == "not_implemented"]
    assert {o["cid"] for o in ni} == {"AUTHN-04", "ATHZ-04"}
    for o in ni:
        assert o.get("not_implemented_reason"), "%s is not_implemented with no stated reason" % o["cid"]
        assert o["engine"] == A.NO_ENGINE
    assert r["tally"]["not_implemented"] == 2
    # and it is never quietly counted as a pass
    assert "not_implemented" in A.STATUSES and r["tally"]["verified"] == 27


def test_not_implemented_survives_every_engine_claiming_to_have_run():
    """Absence of capability is a property of the PRODUCT, not of the mission: no set of "engines that ran",
    however dishonest or over-broad, can flip a not-implemented objective to verified."""
    liar = _dispatch_reachable() | {n for o in A.OBJECTIVES for n in A._engine_names(o)} | {A.NO_ENGINE}
    r = A.assess([], attempted_engines=liar)
    for cid in ("AUTHN-04", "ATHZ-04"):
        o = next(x for x in r["objectives"] if x["cid"] == cid)
        assert o["status"] == "not_implemented", "%s flipped to %s" % (cid, o["status"])


def test_a_finding_still_fails_a_not_implemented_objective():
    """Negative control on the precedence order. Apolaki has no mass-assignment engine, but the Juice Shop
    lab solver can still demonstrate one. A violation someone else proved must never be hidden behind
    "we have no engine" — failed outranks not_implemented."""
    r = A.assess([{"id": "M1", "family": "mass_assignment"}], attempted_engines=set())
    athz4 = next(o for o in r["objectives"] if o["cid"] == "ATHZ-04")
    assert athz4["status"] == "failed" and athz4["finding_ids"] == ["M1"]
    # ...and the umbrella access-control objective fails with it
    athz0 = next(o for o in r["objectives"] if o["cid"] == "ATHZ-00")
    assert athz0["status"] == "failed"


def test_authz_matrix_objectives_verify_from_the_REAL_ledger_name():
    """The naming-boundary bug, pinned to the name a real mission actually records.

    `_run_authz_matrix` returns ToolResult("authz_matrix", ...), but BOTH tool_call emitters
    (agent.py:551 and agent.py:634) log the REQUESTED name, so a real ledger carries
    "run_authz_matrix" and never the bare label. The model matched the label, so ATHZ-00/AUTHN-02 read
    not_tested on a mission where the authz matrix genuinely ran. Measured in docs/handoff/asvs.md.
    """
    r = A.assess([], attempted_engines={"run_authz_matrix"})
    for cid in ("ATHZ-00", "AUTHN-02"):
        o = next(x for x in r["objectives"] if x["cid"] == cid)
        assert o["status"] == "verified", "%s did not verify from the real ledger name" % cid
    # the bare ToolResult LABEL is not a ledger key and must verify nothing
    stale = A.assess([], attempted_engines={"authz_matrix"})
    for cid in ("ATHZ-00", "AUTHN-02"):
        o = next(x for x in stale["objectives"] if x["cid"] == cid)
        assert o["status"] == "not_tested", "%s verified from a name no ledger records" % cid


def test_report_never_claims_full_asvs_coverage():
    all_engines = {n for o in A.OBJECTIVES for n in A._engine_names(o)}
    r = A.assess([], attempted_engines=all_engines)
    assert r["model_type"] == "curated_partial"
    assert "not" in r["disclaimer"].lower() and "full asvs" in r["disclaimer"].lower()
    # even with every engine "run", verified can never reach 100% because some objectives are blocked
    assert r["verified_pct"] < 100.0
