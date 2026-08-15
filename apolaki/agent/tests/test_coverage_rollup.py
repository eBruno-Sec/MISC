"""Coverage view (#123): the unified confirmed-safe / vulnerable / inconclusive / blocked / not-tested rollup
from ASVS + WSTG + the candidate ledger — a curated-partial model, never a full-coverage claim."""
import report


def test_rollup_buckets_from_asvs():
    # a confirmed idor + engines that ran clean -> some verified (safe), some failed (vuln), rest not-tested
    cr = report.coverage_rollup(
        [{"id": "F", "family": "idor", "confidence": "confirmed"}],
        tool_ledger={"run_sqli": 1, "confirm_idor": 1, "authz_matrix": 1, "run_xss": 1})
    p = cr["properties"]
    assert p["vulnerable"] >= 1                      # the idor fails its access-control objective(s)
    assert p["confirmed_safe"] >= 1                  # sqli/xss engines ran clean -> those properties verified
    assert p["blocked"] >= 1                         # lockout/MFA are safety-blocked
    # The accounting identity, now including `not_implemented` (Q-012). It is a SIXTH bucket rather
    # than part of `not_tested` on purpose: a property Apolaki has no engine for is a different claim
    # to a reader than one it merely did not reach. The identity is what keeps the split honest -- a
    # status that fell out of every bucket would silently shrink the reported model.
    assert p["total"] == (p["confirmed_safe"] + p["vulnerable"] + p["inconclusive"]
                          + p["blocked"] + p["not_tested"] + p["not_implemented"])
    assert 0 <= p["tested_pct"] <= 100


def test_not_implemented_is_never_folded_into_not_tested():
    """The distinction Q-012 exists to make, asserted at the rollup layer too. `not_implemented`
    stays in the `total` and in the `tested_pct` denominator -- a property we cannot test is not
    tested, and hiding it would inflate the coverage percentage."""
    import asvs_model
    absent = [o for o in asvs_model.OBJECTIVES if o.get("not_implemented_reason")]
    assert absent, "precondition: the model declares at least one absent capability"

    p = report.coverage_rollup([], tool_ledger={})["properties"]
    assert p["not_implemented"] == len(absent), (p["not_implemented"], len(absent))
    assert p["not_implemented"] >= 1 and "not_implemented" in p


def test_rollup_carries_wstg_and_never_claims_full():
    cr = report.coverage_rollup([], tool_ledger={})
    assert cr["model"] == "curated_partial"
    assert cr["wstg"]["total"] == 109 and cr["wstg"]["tested"] >= 0


def test_rollup_folds_candidate_ledger():
    cv = {"candidates": [{"state": "confirmed"}, {"state": "blocked: needs browser"}, {"state": "dismissed"}]}
    cr = report.coverage_rollup([], {}, candidate_validation=cv)
    assert cr["candidates"]["confirmed"] == 1 and cr["candidates"]["blocked"] == 1 and cr["candidates"]["total"] == 3


def test_rollup_is_present_in_report_json():
    import json
    pkg = json.loads(report.findings_json("p", [{"id": "F", "family": "sqli", "confidence": "confirmed",
                                                 "severity": "high"}], {"in_scope": ["x"]},
                                          tool_ledger={"run_sqli": 1}))
    assert "coverage_rollup" in pkg and "properties" in pkg["coverage_rollup"]
