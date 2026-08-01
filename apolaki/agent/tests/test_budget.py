"""Mission request budget: unlimited by default, hard cap when set."""
from __future__ import annotations

import budget


def test_unlimited_by_default():
    b = budget.MissionBudget(0)
    for _ in range(1000):
        assert b.charge() is True
    assert b.remaining() == -1 and b.exhausted() is False


def test_hard_cap():
    b = budget.MissionBudget(3)
    assert b.charge() and b.charge() and b.charge()   # 3 allowed
    assert b.charge() is False                         # 4th blocked
    assert b.spent == 3 and b.remaining() == 0 and b.exhausted() is True


def test_batch_charge_respects_remaining():
    b = budget.MissionBudget(5)
    assert b.charge(3) is True
    assert b.charge(3) is False                        # would exceed (3+3 > 5)
    assert b.charge(2) is True                         # fits
    assert b.remaining() == 0


def test_bad_limit_is_unlimited():
    assert budget.MissionBudget("nonsense").limit == 0
    assert budget.MissionBudget(-4).limit == 0


def test_external_tool_charged_against_budget():
    # the budget is mission-wide: an external tool run is charged + blocked when the budget is spent,
    # BEFORE the subprocess launches (CHAD #12).
    import asyncio
    import scope
    import tools
    sc = scope.ScopeEngine()
    sc.load_manual(["x.tld"], [], "T")
    reg = tools.ToolRegistry(sc, lab_mode=True)
    reg.budget = budget.MissionBudget(10)                 # tiny; default tool weight (25) exceeds it
    out, err = asyncio.new_event_loop().run_until_complete(reg._cmd(["echo", "hi"]))
    assert out == "" and "__BUDGET__" in err              # blocked, never ran
