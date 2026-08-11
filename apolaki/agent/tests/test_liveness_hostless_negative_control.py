"""NEGATIVE CONTROL for the `max_hostless` reach gate (1709f59, Q-019) — the branch shipped untested.

Commit 1709f59 is entirely one branch: a surface check must fail DEAD when the discovered surface
carries URLs with no host, because `ScopeEngine` refuses every one of them and a crawl that "grew to
2756 URLs" while losing the pages that mattered is not reach. MEASURED: deleting that whole branch from
`liveness.verdict` leaves all 30 liveness tests green — `test_liveness_surface_check.py` builds its
fixture WITHOUT `max_hostless`, so every one of its cases takes the `cap is None` path and the gate the
commit exists to add is never exercised.

A guard nobody can fail is a declaration, not a guard. These are the assertions that kill that mutant.
"""
import liveness as lv


def _check(min_urls=2, max_hostless=0):
    return {"technique": "surface_discovery", "lab": "owaspbench", "kind": "surface",
            "seed": "https://owaspbench:8443/benchmark/", "min_urls": min_urls,
            "max_hostless": max_hostless}


# the exact shape mission 90cee81c produced: urljoin("https://", "/benchmark/x.html")
HOSTLESS = "https:///benchmark/cmdi-Index.html"
REAL = ["https://owaspbench:8443/benchmark/sqli-00/BenchmarkTest00001.html",
        "https://owaspbench:8443/benchmark/xss-00/BenchmarkTest00002.html",
        "https://owaspbench:8443/benchmark/cmdi-00/BenchmarkTest00003.html"]


def test_a_hostless_url_fails_the_reach_check_DEAD():
    """THE mutant-killer. Enough URLs to clear `min_urls`, so the ONLY thing that can produce DEAD here
    is the addressability gate. Delete that branch and this assertion fails for its own reason."""
    v = lv.verdict(_check(min_urls=2), REAL + [HOSTLESS], lab_up=True)
    assert v["verdict"] == lv.DEAD, v
    assert "no host" in v["detail"], v
    assert HOSTLESS in v["detail"], "the failure must NAME an offending URL, or it cannot be acted on"


def test_addressability_is_judged_before_the_count_so_a_big_broken_surface_cannot_pass():
    """Mission 90cee81c is the case: a surface far OVER `min_urls` whose index pages are unaddressable.
    Counting first and checking hosts second would have confirmed that mission."""
    v = lv.verdict(_check(min_urls=2), [HOSTLESS] * 40 + REAL, lab_up=True)
    assert v["verdict"] == lv.DEAD and "40 URL(s) on the surface have no host" in v["detail"], v


def test_an_addressable_surface_still_confirms():
    """The other half. A gate that also kills the true positive is a mute button, not a fix."""
    v = lv.verdict(_check(min_urls=2), REAL, lab_up=True)
    assert v["verdict"] == lv.CONFIRMED and "all addressable" in v["detail"], v


def test_the_cap_is_a_threshold_not_a_boolean():
    """`max_hostless` is read as a number; a non-zero budget must tolerate exactly that many and no
    more. Hardcoding `if hostless:` would pass every test above and fail this one."""
    assert lv.verdict(_check(max_hostless=1), REAL + [HOSTLESS], lab_up=True)["verdict"] == lv.CONFIRMED
    v = lv.verdict(_check(max_hostless=1), REAL + [HOSTLESS, HOSTLESS], lab_up=True)
    assert v["verdict"] == lv.DEAD, v


def test_a_check_with_no_cap_declared_does_not_silently_gain_one():
    """The `cap is None` path is the pre-1709f59 behaviour and must stay reachable, or every existing
    surface entry would start failing on a shape it never declared a bar for."""
    c = {k: v for k, v in _check().items() if k != "max_hostless"}
    assert lv.verdict(c, REAL + [HOSTLESS], lab_up=True)["verdict"] == lv.CONFIRMED


def test_the_registered_check_actually_declares_a_cap():
    """Guard the guard: the branch is worthless if no entry in CHECKS opts into it. This is the
    assertion that fails if someone drops `max_hostless` from the table while keeping the code."""
    surf = [c for c in lv.CHECKS if c.get("kind") == "surface"]
    assert surf, "no surface check registered"
    for c in surf:
        assert c.get("max_hostless") is not None, c["technique"]
        assert int(c["max_hostless"]) == 0, "a reach check should tolerate zero unaddressable URLs"


def test_a_down_lab_is_still_SKIPPED_even_with_a_hostless_surface():
    """Ordering guard: an absent lab must never be reported as a product defect (DEAD). SKIPPED is not
    a pass, but it is also not a false accusation."""
    v = lv.verdict(_check(), [HOSTLESS], lab_up=False)
    assert v["verdict"] == lv.SKIPPED and "NOT a pass" in v["detail"], v
