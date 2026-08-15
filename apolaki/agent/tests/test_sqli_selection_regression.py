"""The sweep budget is rationed PER SHAPE, and that is the whole of the 21 -> 11 sqli recall loss.

DIAGNOSIS (docs/handoff/sqli.md, BREAKER lane). Between the sealed baseline `ebd96f45` and both
reruns since (seals `e6674d6d`, `82f55903`) the `sqli` family went 21 findings -> 11. Ten cases were
dropped, the same ten in both reruns:

    00335 00337 00339 00341 00342 00428 00429 00433 00438   (nine true positives, CWE-89)
    00494                                                    (the baseline's one false positive)

MEASURED from the rerun's own `coverage` block: nine of the ten received ZERO tool dispatches. The
oracle never declined them and no engine errored on them -- `run_sqli` was simply handed a target
list that did not contain their URLs. The tenth, 00494, was touched only by `run_csrf`.

THE MECHANISM. `target_shape()` collapses every digit run to `#`, so an application whose whole
surface is one URL template over N category directories collapses to N shapes. `_spread_by_shape()`
then round-robins the `SWEEP_TARGET_CAP` budget across those shapes. On the OWASP Benchmark that is
11 shapes holding 27 to 456 candidates each, and every one drew ~37 slots: the 27-candidate class
was covered 100%, the 456-candidate class 8.1%. All 11 surviving sqli claims sit at shape-group
indices 1..28 and all nine lost cases at 38..58 -- a pure ordinal cut, no exceptions either side.

THE EVEN RATION IS CORRECT AND MUST NOT BE MADE PROPORTIONAL. This file originally carried a strict
xfail demanding that budget share track candidate share. That demand was MEASURED and WITHDRAWN:
vulnerability density is ~51% in every class, so at a fixed budget no partition reaches more than
~230 vulnerable cases, and a proportional split scores 226 against the even split's 228. Under the
macro-averaging this project mandates it is far worse -- 17.8% reachable recall against 34.1%,
roughly half -- because the even ration is what buys the small classes complete coverage. See
docs/handoff/sqli.md section 4 for the numbers. The recall loss is the PRICE of a policy that is
right on the metric, and the only lever that moves both macro and micro is `SWEEP_TARGET_CAP`
itself (400 -> 650 is +13.8 macro, +10.7 micro, and costs no class anything).

So the tests below lock the mechanism and the small-class guarantee, and deliberately do NOT
assert proportionality. They drive the REAL `agent.sweep_targets` on SYNTHETIC urls: no OWASP
Benchmark path, case id or category name appears in any assertion, so nothing here can degrade
into a benchmark-specific signature.
"""
from __future__ import annotations

import agent as agent_mod

#: A surface shaped like a generated test-suite: many sibling directories, ONE url template, class
#: sizes deliberately lopsided. Sizes mirror the real spread (smallest 27, largest 456) without
#: naming anything about the application they were observed on.
_CLASS_SIZES = {"alpha": 456, "bravo": 455, "charlie": 448, "delta": 241, "echo": 232,
                "foxtrot": 225, "golf": 214, "hotel": 112, "india": 60, "juliet": 54,
                "kilo": 27}

_CAP = 400


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
    assert _select(_surface(), _CAP) == _select(_surface(), _CAP)


def test_a_budget_cut_truncates_each_class_as_a_PREFIX_of_its_own_order():
    """The shape of the loss. Within a class nothing is sampled or skipped -- the cut is an ordinal
    boundary, so case N is tested and case N+1 is not for no reason but their position. This is what
    made the lost set identical across reruns and invisible to any per-case reasoning."""
    selected = set(_select(_surface(), _CAP))
    members = [u for u in _surface() if u.startswith("https://t/app/alpha-00/")]
    taken = [i for i, u in enumerate(members) if u in selected]
    assert taken, "the largest class received no slots at all"
    assert taken == list(range(len(taken))), (
        "expected a contiguous prefix of the class, got a gapped selection: %s" % taken[:20])


def test_no_class_is_starved_to_zero_and_the_whole_budget_is_spent():
    """Policy-agnostic floor. Whatever the ration is, a truncated sweep must reach every class that
    has candidates and must not leave budget unspent."""
    selected = _select(_surface(), _CAP)
    assert len(selected) == _CAP, "budget under-spent: %d of %d" % (len(selected), _CAP)
    got = _by_class(selected)
    missing = sorted(c for c in _CLASS_SIZES if not got.get(c))
    assert not missing, "class(es) received no slots at all: %s" % missing


def test_a_larger_class_never_receives_fewer_slots_than_a_smaller_one():
    """Monotonicity. The even round-robin satisfies it only because a class smaller than the
    per-shape quota simply exhausts, so this is a floor and not a size-awareness claim."""
    got = _by_class(_select(_surface(), _CAP))
    order = sorted(_CLASS_SIZES, key=_CLASS_SIZES.get)
    for smaller, larger in zip(order, order[1:]):
        assert got.get(larger, 0) >= got.get(smaller, 0), (
            "class %s (%d candidates) drew %d slot(s), fewer than %s (%d candidates) with %d"
            % (larger, _CLASS_SIZES[larger], got.get(larger, 0),
               smaller, _CLASS_SIZES[smaller], got.get(smaller, 0)))


def test_every_class_smaller_than_its_quota_is_covered_COMPLETELY():
    """THE invariant a proportional ration would destroy, and the reason the even one is kept.

    A class that fits inside its share of the budget must be tested exhaustively. This is what makes
    the macro-averaged reachable recall 34.1% instead of 17.8%: the small classes are finished, and
    finishing them costs the large classes only slots they could never have converted into complete
    coverage anyway. MEASURED against a size-proportional `_spread_by_shape` mutant, which drops the
    smallest class from 100% to 14.8% and fails here -- so this test detects the change it forbids.

    It does NOT forbid every future improvement: a scheme that finishes the small classes first and
    then distributes the remainder by size still passes. It forbids only the naive proportional
    split, which measurement says is a regression (docs/handoff/sqli.md section 4)."""
    got = _by_class(_select(_surface(), _CAP))
    quota = _CAP / len(_CLASS_SIZES)
    checked = 0
    for cls, size in _CLASS_SIZES.items():
        if size <= quota:
            checked += 1
            assert got.get(cls, 0) == size, (
                "class %s holds %d candidate(s), under the %.0f-slot quota, but only %d were "
                "selected -- a class that fits in its share must be finished"
                % (cls, size, quota, got.get(cls, 0)))
    assert checked, "no class was under quota; this test asserted nothing"


def test_raising_the_cap_is_the_only_lever_that_moves_a_starved_class():
    """Why 'raise MAX_STEPS' bought nothing, and why SWEEP_TARGET_CAP is the recommendation. The
    bound on a large class is the cap divided by the shape count, so its coverage responds to the
    cap and to nothing else."""
    surface = _surface()
    large = max(_CLASS_SIZES, key=_CLASS_SIZES.get)
    at_cap = _by_class(_select(surface, _CAP)).get(large, 0)
    at_double = _by_class(_select(surface, _CAP * 2)).get(large, 0)
    assert at_double > at_cap, (
        "doubling the sweep cap did not increase the starved class's coverage (%d -> %d)"
        % (at_cap, at_double))
