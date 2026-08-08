"""Probe selection (T3) — practical MBT §4.2.3 + Automated Planning §4.2.1.

The point is not fewer requests. It is that "the first 12" cannot state what it covered, and a pairwise
selection can. These tests assert the coverage PROPERTY, not a case count.
"""
import probe_selection as ps

FACTORS = {
    "param": ["id", "q", "redirect", "file"],
    "payload": ["' OR 1=1--", "<script>", "../../etc/passwd", "${7*7}"],
    "encoding": ["raw", "urlencoded", "double"],
}


def test_every_value_pair_is_covered():
    """THE property. Anything less and the criterion is not met."""
    cases = ps.pairwise(FACTORS)
    c = ps.coverage(FACTORS, cases)
    assert c["pair_coverage_pct"] == 100.0, c


def test_pairwise_is_much_cheaper_than_the_full_grid():
    cases = ps.pairwise(FACTORS)
    c = ps.coverage(FACTORS, cases)
    assert c["full_grid_cases"] == 4 * 4 * 3 == 48
    assert c["cases"] < c["full_grid_cases"] / 2, c


def test_every_case_assigns_every_factor():
    for case in ps.pairwise(FACTORS):
        assert set(case) == set(FACTORS)
        for k, v in case.items():
            assert v in FACTORS[k]


def test_deterministic_across_runs():
    """A scan must stay replayable, so selection cannot wander between runs."""
    assert ps.pairwise(FACTORS) == ps.pairwise(FACTORS)


def test_a_first_n_cut_does_not_reach_full_pair_coverage():
    """Demonstrates what is being replaced rather than asserting it in prose."""
    grid = ps.full_grid(FACTORS)
    first_n = grid[:len(ps.pairwise(FACTORS))]
    assert ps.coverage(FACTORS, first_n)["pair_coverage_pct"] < 100.0


def test_single_factor_returns_its_values():
    cases = ps.pairwise({"payload": ["a", "b", "c"]})
    assert [c["payload"] for c in cases] == ["a", "b", "c"]


def test_empty_and_degenerate_inputs():
    assert ps.pairwise({}) == []
    assert ps.pairwise({"a": []}) == []
    assert ps.full_grid({}) == []


def test_max_cases_bounds_the_selection_but_coverage_reports_the_shortfall():
    """A hard cap is still allowed — what changes is that the shortfall is MEASURED, not silent."""
    cases = ps.pairwise(FACTORS, max_cases=3)
    assert len(cases) == 3
    assert ps.coverage(FACTORS, cases)["pair_coverage_pct"] < 100.0


def test_describe_states_the_limit_not_just_the_win():
    d = ps.describe(FACTORS, ps.pairwise(FACTORS))
    assert "pairwise" in d and "not exhaustive" in d or "THREE specific" in d
    assert "%" in d


def test_safety_labels_follow_the_planning_vocabulary():
    assert ps.safety_label("full_grid").startswith("safe")
    assert "NOT safe" in ps.safety_label("first_n")
    assert "declared" in ps.safety_label("pairwise")


def test_scales_without_blowing_up():
    big = {"a": list("12345"), "b": list("12345"), "c": list("12345"), "d": list("12345")}
    cases = ps.pairwise(big)
    c = ps.coverage(big, cases)
    assert c["pair_coverage_pct"] == 100.0
    assert c["cases"] < 60, "pairwise should stay far below the 625-case grid"
