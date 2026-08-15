"""The sweep budget is rationed PER SHAPE, not per candidate -- and that is the whole of the
21 -> 11 sqli recall loss.

DIAGNOSIS (docs/handoff/sqli.md, BREAKER lane). Between the sealed baseline `ebd96f45` and both
reruns since (seals `e6674d6d`, `82f55903`) the `sqli` family went 21 findings -> 11. Ten cases were
dropped, the same ten in both reruns:

    00335 00337 00339 00341 00342 00428 00429 00433 00438   (nine true positives)
    00494                                                    (the baseline's one false positive)

MEASURED from the rerun's own `coverage` block: nine of the ten received ZERO tool dispatches. The
oracle never declined them and no engine errored on them -- `run_sqli` was simply handed a target
list that did not contain their URLs. The tenth, 00494, was touched only by `run_csrf`.

THE MECHANISM. `target_shape()` collapses every digit run to `#`, so an application whose whole
surface is one URL template over N category directories collapses to N shapes. `_spread_by_shape()`
then round-robins the `SWEEP_TARGET_CAP` budget across those shapes, which spends it EVENLY BY SHAPE
rather than proportionally by shape size. On the OWASP Benchmark that is 11 shapes holding 27 to 456
candidates each, and every one of them received ~37 slots: the 27-candidate class was covered 100%,
the 456-candidate class 8.1%. All 11 surviving sqli claims sit at shape-group indices 1..28 and all
nine lost cases at 38..58 -- a pure ordinal cut, with zero exceptions in either direction.

WHY THE ROUND-ROBIN IS STILL RIGHT. It is not a bug to be reverted. It replaced a truncation in
discovery order that spent the entire budget inside the first directory the crawl walked, which is
strictly worse. What is wrong is the RATION: a class holding 18% of the candidates and a class
holding 1% draw the same slot count, so the fix is a proportional (or at least size-aware) split,
not the removal of the spread.

These tests drive the REAL `agent.sweep_targets` on SYNTHETIC urls. They assert a property of the
selection function -- no OWASP Benchmark path, case id or category name appears in any assertion, so
nothing here can degrade into a benchmark-specific signature.
"""
from __future__ import annotations

import pytest

import agent as agent_mod

#: Why the proportionality test does not hold today. One string so the two halves cannot drift.
_RATION = ("_spread_by_shape rations the sweep budget evenly across shapes, so a class holding "
           "18% of the candidate surface draws the same slots as one holding 1%. This is the "
           "measured cause of the sqli 21 -> 11 recall loss (docs/handoff/sqli.md).")

#: A surface shaped like a generated test-suite: many sibling directories, ONE url template, class
#: sizes deliberately lopsided. Sizes mirror the real spread (smallest 27, largest 456) without
#: naming anything about the application they were observed on.
_CLASS_SIZES = {"alpha": 456, "bravo": 455, "charlie": 448, "delta": 241, "echo": 232,
                "foxtrot": 225, "golf": 214, "hotel": 112, "india": 60, "juliet": 54,
                "kilo": 27}


def _surface():
    """Query-bearing candidates, grouped by class, in class order then member order."""
    urls = []
    for cls, n in _CLASS_SIZES.items():
        for i in range(n):
            urls.append("https://t/app/%s-00/Case%05d.html?Case%05d=x" % (cls, i, i))
    return urls


def _select(urls, limit):
    return agent_mod.sweep_targets(urls, [], lambda _u: True, limit=limit)


def _by_class(selected):
    out = {}
    for u in selected:
        cls = u.split("/app/")[1].split("-00/")[0]
        out[cls] = out.get(cls, 0) + 1
    return out


def test_the_surface_really_does_collapse_to_one_shape_per_class():
    """Non-vacuity for everything below. If each url kept its own shape the round-robin would be a
    no-op and none of these tests would be testing the thing they are named for."""
    shapes = {agent_mod.target_shape(u) for u in _surface()}
    assert len(shapes) == len(_CLASS_SIZES), (
        "expected one shape per class, got %d shape(s) for %d class(es)"
        % (len(shapes), len(_CLASS_SIZES)))


def test_the_selection_is_deterministic():
    """The platform's standing property, and the reason the same ten cases were lost on BOTH
    reruns rather than a random ten each time."""
    assert _select(_surface(), 400) == _select(_surface(), 400)


def test_a_budget_cut_truncates_each_class_as_a_PREFIX_of_its_own_order():
    """The shape of the loss. Within a class nothing is sampled or skipped -- the cut is an ordinal
    boundary, so case N is tested and case N+1 is not for no reason but their position. This is what
    makes the lost set stable across reruns and invisible to any per-case reasoning."""
    selected = set(_select(_surface(), 400))
    members = [u for u in _surface() if u.startswith("https://t/app/alpha-00/")]
    taken = [i for i, u in enumerate(members) if u in selected]
    assert taken, "the largest class received no slots at all"
    assert taken == list(range(len(taken))), (
        "expected a contiguous prefix of the class, got a gapped selection: %s" % taken[:20])


def test_no_class_is_starved_to_zero_and_the_whole_budget_is_spent():
    """Policy-agnostic floor. Whatever the ration is, a truncated sweep must reach every class that
    has candidates and must not leave budget unspent -- both true of the even round-robin and of any
    size-aware replacement, so this keeps its meaning across the fix rather than freezing today's
    numbers in place."""
    selected = _select(_surface(), 400)
    assert len(selected) == 400, "budget under-spent: %d of 400" % len(selected)
    got = _by_class(selected)
    missing = sorted(c for c in _CLASS_SIZES if not got.get(c))
    assert not missing, "class(es) received no slots at all: %s" % missing


def test_a_larger_class_never_receives_fewer_slots_than_a_smaller_one():
    """Monotonicity, the weakest form of size-awareness. The even round-robin satisfies it only by
    accident -- a class smaller than the per-shape quota simply exhausts -- so this does NOT stand in
    for the proportionality invariant below. It is here to catch a ration that actively inverts.

    NOTE for whoever fixes this: the defect is that today's ration gives the 456-candidate class and
    the 60-candidate class the SAME ~37 slots. That measurement lives in docs/handoff/sqli.md and is
    deliberately NOT asserted anywhere in this file, because a test that pins the disparity would
    fail on the day it is repaired."""
    got = _by_class(_select(_surface(), 400))
    order = sorted(_CLASS_SIZES, key=_CLASS_SIZES.get)
    for smaller, larger in zip(order, order[1:]):
        assert got.get(larger, 0) >= got.get(smaller, 0), (
            "class %s (%d candidates) drew %d slot(s), fewer than %s (%d candidates) with %d"
            % (larger, _CLASS_SIZES[larger], got.get(larger, 0),
               smaller, _CLASS_SIZES[smaller], got.get(smaller, 0)))


def test_raising_the_cap_is_the_only_lever_that_moves_a_starved_class():
    """Why 'raise MAX_STEPS' bought nothing. The bound on a large class is SWEEP_TARGET_CAP divided
    by the shape count, so its coverage responds to the cap and to nothing else."""
    surface = _surface()
    large = max(_CLASS_SIZES, key=_CLASS_SIZES.get)
    at400 = _by_class(_select(surface, 400)).get(large, 0)
    at800 = _by_class(_select(surface, 800)).get(large, 0)
    assert at800 > at400, (
        "doubling the sweep cap did not increase the starved class's coverage (%d -> %d)"
        % (at400, at800))


@pytest.mark.xfail(strict=True, reason=_RATION)
def test_budget_share_tracks_candidate_share():
    """THE invariant this lane says is missing. A class holding X% of the parameterized surface
    should receive a budget share of roughly X%, so that truncating a scan degrades every class
    proportionally instead of testing the rarest class exhaustively and the commonest hardly at all.

    Tolerance is deliberately loose (a factor of two either way): the claim is that the ration is
    size-AWARE, not that it is exact. Strict xfail so that the day a size-aware split lands, the
    unexpected pass fails the suite and forces this file and docs/handoff/sqli.md to be updated
    together rather than silently diverging."""
    surface = _surface()
    total = len(surface)
    limit = 400
    got = _by_class(_select(surface, limit))
    offenders = []
    for cls, size in _CLASS_SIZES.items():
        want = limit * size / total
        have = got.get(cls, 0)
        if have < want / 2 or have > want * 2:
            offenders.append("%s: %d slot(s) for %d candidate(s), proportional share %.1f"
                             % (cls, have, size, want))
    assert not offenders, "%d class(es) off proportional share: %s" % (len(offenders), offenders)
