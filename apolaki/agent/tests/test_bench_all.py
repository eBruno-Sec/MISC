"""Multi-lab regression harness (#101). The aggregation is pure + scan-function-injected, so the metric math is
proven here with synthetic findings — no containers. A lab that over-detects raises unexpected; a lab that
misses raises false-negatives; the min-gate flags when a required lab wasn't scored."""
import bench_all as BA


def _finding(family, confirmed=True):
    return {"family": family, "confidence": "confirmed" if confirmed else "lead"}


def _scan_fn(mapping):
    """Return a scan_fn that yields the synthetic findings mapped per lab key."""
    def fn(key, url):
        return mapping.get(key, []), []
    return fn


def test_bench_scores_per_lab_and_aggregates():
    # vampi expects broken_auth/access_control/sensitive_exposure/sqli — supply 3 of 4 confirmed
    mapping = {"vampi": [_finding("session_fixation"), _finding("idor"), _finding("git_exposure")]}
    out = BA.bench(["vampi"], _scan_fn(mapping))
    res = out["results"][0]
    assert res["fixture"] == "vampi"
    m = res["metrics"]
    assert m["expected_classes"] == 4 and m["discovered_classes"] == 3      # sqli missing
    assert "sqli" in res["false_negatives"]
    assert out["summary"]["labs"] == 1 and out["summary"]["mean_class_coverage_pct"] == 75.0


def test_unexpected_class_is_flagged():
    # dvga expects sqli/command_injection/xss/access_control/sensitive_exposure; ssrf is OUTSIDE the manifest
    mapping = {"dvga": [_finding("sqli"), _finding("ssrf")]}
    out = BA.bench(["dvga"], _scan_fn(mapping))
    assert "ssrf" in out["results"][0]["unexpected"]
    assert out["summary"]["total_unexpected"] >= 1


def test_gate_flags_missing_required_lab():
    # only vampi scored; juiceshop is in MIN_GATE but not scanned -> gate_ok False
    out = BA.bench(["vampi"], _scan_fn({"vampi": [_finding("session_fixation")]}))
    assert out["gate_ok"] is False
    both = BA.bench(["juiceshop", "vampi"],
                    _scan_fn({"juiceshop": [_finding("sqli")], "vampi": [_finding("session_fixation")]}))
    assert both["gate_ok"] is True


def test_unknown_or_unwired_lab_is_skipped():
    out = BA.bench(["nope", "gruyere"], _scan_fn({}))       # gruyere has a manifest but no wired URL
    assert out["results"] == [] and out["summary"]["labs"] == 0


def test_scan_error_recorded_not_raised():
    def boom(key, url):
        raise RuntimeError("scanner blew up")
    out = BA.bench(["vampi"], boom)
    assert out["results"][0]["error"].startswith("scanner blew up") and out["summary"]["labs"] == 0


def test_aggregate_means_across_labs():
    evals = [{"fixture": "a", "metrics": {"class_coverage_pct": 100.0, "confirmed_coverage_pct": 50.0,
                                          "false_negatives": 0, "unexpected_classes": 1}},
             {"fixture": "b", "metrics": {"class_coverage_pct": 50.0, "confirmed_coverage_pct": 50.0,
                                          "false_negatives": 2, "unexpected_classes": 0}}]
    s = BA.aggregate(evals)
    assert s["labs"] == 2 and s["mean_class_coverage_pct"] == 75.0 and s["total_false_negatives"] == 2
