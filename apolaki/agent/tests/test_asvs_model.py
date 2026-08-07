"""ASVS-5 curated-partial objective model (Codex Tier-1 #1): findings violate objectives, clean attempted
checks verify them, blocked/untested are never counted as verified, and the model never claims full ASVS."""
import re

import asvs_model as A


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
    # business-logic reasoning ran, but it is inconclusive-by-nature -> "attempted", not "verified"
    r = A.assess([], attempted_engines={"bizlogic_graph", "run_race"})
    busl = [o for o in r["objectives"] if o["cid"] in ("BUSL-01", "BUSL-02")]
    assert all(o["status"] == "attempted" for o in busl)


def test_real_emitted_families_fail_their_objective_even_when_engine_ran():
    # Regression: Apolaki's real dominant families (access_control, backup_exposure) must FAIL their
    # objective, never read "verified" just because the authz/exposure engine ran clean of narrower families.
    findings = [{"id": "A", "family": "access_control"}, {"id": "B", "family": "backup_exposure"}]
    ran = {"run_bfla", "confirm_idor", "authz_matrix", "run_exposure", "run_dir_harvest"}
    r = A.assess(findings, attempted_engines=ran)
    athz0 = next(o for o in r["objectives"] if o["cid"] == "ATHZ-00")
    comm3 = next(o for o in r["objectives"] if o["cid"] == "COMM-03")
    assert athz0["status"] == "failed" and athz0["finding_ids"] == ["A"]
    assert comm3["status"] == "failed" and comm3["finding_ids"] == ["B"]


def test_umbrella_access_control_fails_when_any_child_violation_exists():
    # #11 regression: ATHZ-00 is the UMBRELLA "no broken access control" property. A confirmed idor/bola/
    # bfla/privilege_escalation/mass_assignment must FAIL it too — it can never read "verified" while a
    # specific access-control child is failed (that self-contradiction was the bug).
    ran = {"run_bfla", "confirm_idor", "authz_matrix", "run_mass_assignment"}
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


def test_report_never_claims_full_asvs_coverage():
    all_engines = {n for o in A.OBJECTIVES for n in A._engine_names(o)}
    r = A.assess([], attempted_engines=all_engines)
    assert r["model_type"] == "curated_partial"
    assert "not" in r["disclaimer"].lower() and "full asvs" in r["disclaimer"].lower()
    # even with every engine "run", verified can never reach 100% because some objectives are blocked
    assert r["verified_pct"] < 100.0
