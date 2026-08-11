"""The surface-discovery liveness check: can the product still REACH a target at all?

Five orchestration defects shipped while 1645 unit tests stayed green, because every one tested an
ENGINE and none asserted Apolaki can find anything to point an engine at. A mission against a
1415-vulnerability target returned ZERO findings in 40 seconds and called it "coverage completed".

These tests cover the SCORER for that check. The check itself runs in the liveness gate against a live
lab, where an absent lab is SKIPPED and never a pass.
"""
import liveness as lv


def _check(min_urls=8):
    return {"technique": "surface_discovery", "lab": "owaspbench", "kind": "surface",
            "seed": "https://owaspbench:8443/benchmark/", "min_urls": min_urls}


def test_enough_reach_confirms():
    v = lv.verdict(_check(3), ["u1", "u2", "u3"], lab_up=True)
    assert v["verdict"] == lv.CONFIRMED
    assert "3 URL(s)" in v["detail"]


def test_too_little_reach_is_DEAD_not_a_pass():
    """The regression that matters: reaching only the seed means the crawl is broken."""
    v = lv.verdict(_check(8), ["https://owaspbench:8443/benchmark/"], lab_up=True)
    assert v["verdict"] == lv.DEAD
    assert "cannot see the target" in v["detail"]


def test_reaching_nothing_is_DEAD():
    assert lv.verdict(_check(), [], lab_up=True)["verdict"] == lv.DEAD


def test_an_absent_lab_is_SKIPPED_never_confirmed():
    """Treating a stopped lab as success is how a gate silently stops gating."""
    v = lv.verdict(_check(), [], lab_up=False)
    assert v["verdict"] == lv.SKIPPED and "NOT a pass" in v["detail"]


def test_a_harness_error_is_ERROR_not_dead():
    """A broken harness must not read as a broken product."""
    v = lv.verdict(_check(), [], lab_up=True, error="ConnectError: boom")
    assert v["verdict"] == lv.ERROR


def test_the_check_is_registered_in_the_table():
    """Guard the guard: a scorer with no check in CHECKS protects nothing."""
    surf = [c for c in lv.CHECKS if c.get("kind") == "surface"]
    assert surf, "no surface check registered in CHECKS"
    assert all(c.get("seed") and c.get("min_urls", 0) >= 2 for c in surf)
