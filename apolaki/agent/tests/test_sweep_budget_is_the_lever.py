"""Q-049 - the nine lost sqli cases are a BUDGET problem, not an allocation problem.

The hypothesis was that the sweep's even shape round-robin rationed the dominant class unfairly and
that proportional allocation would recover the nine true positives at class indices 38-58. It was
implemented and it is WRONG, in two independent ways that only measurement separated:

  1. A round-robin truncated at N already IS the classic water-filling optimum: each shape receives
     min(size, level) for the largest level that fits. There is no slack in it to reallocate.
  2. Any split that hands the dominant class more must take it from shapes that would then stop being
     finished -- and finishing the small classes is worth macro-averaged reachable recall 34.1% vs
     17.8% (docs/handoff/sqli.md). The breaker lane measured that and left
     test_sqli_selection_regression.py, whose monotonicity and complete-coverage invariants both fail
     against a proportional split. They caught this change.

MEASURED, over the real class spread (2524 candidates, sizes 456..27 over 11 shapes):

    cap  400 -> dominant class 38 slots   (the shipped cap)
    cap  600 -> 58
    cap  605 -> 59   <- the first cap that probes ALL NINE lost cases
    cap  700 -> 70

So the nine cases need the sweep to keep ~24% of the candidate surface instead of ~15.8%. The lever
is SWEEP_TARGET_CAP, and this file exists so that conclusion cannot quietly rot: if the allocator or
the cap changes, these numbers move and the tests say so.
"""
import agent as agent_mod

#: The measured surface: 2524 query-bearing candidates over 11 structural shapes. Distinct WORDS, not
#: distinct digits -- `target_shape` normalises digits, so `cls00-00 .. cls09-00` would collapse to a
#: SINGLE shape and every assertion below would pass for free. An earlier draft did exactly that.
_CLASS_SIZES = {"alpha": 456, "bravo": 455, "charlie": 448, "delta": 241, "echo": 232,
                "foxtrot": 225, "golf": 214, "hotel": 112, "india": 60, "juliet": 54, "kilo": 27}
_DOMINANT = "alpha"
_LOST_INDICES = (38, 45, 51, 58)          # where the nine lost true positives sat in their class


def _surface():
    return ["https://t/app/%s-00/Case%05d.html?Case%05d=x" % (cls, i, i)
            for cls, n in _CLASS_SIZES.items() for i in range(n)]


def _selected(cap):
    return agent_mod.sweep_targets(_surface(), [], lambda _u: True, limit=cap)


def _by_class(selected):
    out = {}
    for u in selected:
        out[u.split("/app/")[1].split("-00/")[0]] = out.get(
            u.split("/app/")[1].split("-00/")[0], 0) + 1
    return out


def test_the_fixture_reproduces_the_measured_surface():
    """GUARD THE GUARD. Two earlier drafts silently failed to reproduce the defect -- once because the
    class names collapsed to one shape, once because the small classes were too small and the dominant
    class absorbed the leftover budget. Pin what makes this discriminate."""
    surface = _surface()
    shapes = {agent_mod.target_shape(u) for u in surface}
    assert len(shapes) == len(_CLASS_SIZES) == 11, "the fixture collapsed to %d shape(s)" % len(shapes)
    assert sum(_CLASS_SIZES.values()) == 2524 == len(surface)


def test_the_shipped_cap_cannot_reach_the_nine_lost_cases():
    """The finding, stated as a fact about the CURRENT product rather than as a complaint."""
    got = _by_class(_selected(400))
    assert got[_DOMINANT] < 59, (
        "the dominant class now draws %d slots at cap 400; if this rose, re-measure Q-049"
        % got[_DOMINANT])


def test_the_allocation_is_already_the_water_filling_OPTIMUM():
    """Why reallocating cannot help: every shape receives min(size, level) for one shared level, which
    is the most even feasible split. A shape only gets fewer than the level when it has run out."""
    got = _by_class(_selected(400))
    level = max(got.values())
    for cls, size in _CLASS_SIZES.items():
        n = got.get(cls, 0)
        assert n == min(size, level) or n == min(size, level) - 1, (cls, size, n, level)


def test_a_class_that_fits_inside_the_level_is_finished():
    """The invariant a proportional split destroys, restated here so this file agrees with
    test_sqli_selection_regression.py rather than quietly contradicting it."""
    got = _by_class(_selected(400))
    assert got["kilo"] == _CLASS_SIZES["kilo"], got


def test_the_budget_that_WOULD_reach_them_is_recorded_and_still_true():
    """The lever, measured. If the allocator changes, this number changes and the assertion fails --
    which is the point: the conclusion 'raise the cap to ~605' must not outlive its evidence."""
    assert _by_class(_selected(605))[_DOMINANT] >= 59
    assert _by_class(_selected(600))[_DOMINANT] < 59, "605 is no longer the boundary; re-measure"
    selected = set(_selected(605))
    for idx in _LOST_INDICES:
        u = "https://t/app/%s-00/Case%05d.html?Case%05d=x" % (_DOMINANT, idx, idx)
        assert u in selected, "class index %d is still outside a 605 budget" % idx


def test_raising_the_cap_never_un_probes_a_target():
    """Monotonic in the budget: a bigger sweep must be a superset of a smaller one, or a re-run with a
    raised cap would silently drop endpoints the previous run had covered."""
    assert set(_selected(400)) <= set(_selected(605)) <= set(_selected(800))
