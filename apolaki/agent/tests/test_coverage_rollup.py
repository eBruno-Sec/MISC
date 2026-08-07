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
    assert p["total"] == p["confirmed_safe"] + p["vulnerable"] + p["inconclusive"] + p["blocked"] + p["not_tested"]
    assert 0 <= p["tested_pct"] <= 100


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
