"""Q-115 -- the Assessment Coverage header disagreed with the ledger and the heartbeat.

Every snapshot of the operator's Shopify mission carried three counts of ONE quantity, and no two
agreed:

    Assessment Coverage:  Tools Invoked 848   | Distinct Tools 8
    Execution ledger:     2181 calls          | 31 rows
    mission_heartbeat:    2181 dispatches

The ledger and the heartbeat agree because Q-105 and Q-107 made both cumulative. `_coverage` was
left behind on `db.get_logs(session_id, limit=2000)` -- the SAME defect, in the SAME file, ninety
lines above the function Q-105 repaired.

`get_logs` keeps the NEWEST rows when the limit bites. That is deliberate and correct for a log view
(Q-017 fixed the opposite defect, where a truncated tail made a live mission look stopped) and it is
wrong for an aggregate. On a 2181-dispatch mission the 2000-row window sat entirely inside the
injection sweep, where the run was hammering the same handful of engines -- which is precisely why
`distinct_tools` read 8 against 31 ledger rows. Every engine that ran EARLIER had aged out of the
window.

A report that states one fact three times with two different answers is not evidence, whichever
number happens to be right. The load-bearing test here is
`test_coverage_and_the_ledger_agree_on_a_mission_longer_than_the_window` -- that comparison IS the
field symptom.
"""
import db as dbmod
import main as mainmod
import pytest


@pytest.fixture()
def mission(tmp_path):
    dbmod.init(str(tmp_path / "coverage.db"))
    mid = "q115"
    dbmod.create_mission(mid, "P", "active", "o", {"in_scope": ["example.test"]}, {})
    return mid


def _call(mid, tool):
    dbmod.add_log(mid, "tool_call", {"tool": tool})
    dbmod.add_log(mid, "tool_result", {"tool": tool, "count": 0, "output": ""})


# -- the field failure --------------------------------------------------------

def test_an_engine_that_ran_early_is_still_counted_after_a_long_tail(mission):
    """`run_transport_posture` runs in the first minute of a real mission. Under the window it had
    aged out by the time the report rendered, taking its calls AND its slot in `distinct_tools`."""
    _call(mission, "run_transport_posture")
    for _ in range(1500):                       # 3000 rows: past the old 2000-row window
        _call(mission, "run_sqli")

    cov = mainmod._coverage(mission)
    assert cov["tools_invoked"] == 1501, cov
    assert cov["distinct_tools"] == 2, cov


def test_coverage_and_the_ledger_agree_on_a_mission_longer_than_the_window(mission):
    """THE POINT OF THE TICKET. Two aggregates over one population, rendered into one report. They
    may not disagree.

    Asserted against LITERALS as well as against each other -- an equality between two expressions
    that share a bug passes happily while both are wrong, which is how I once shipped a cap gate
    that killed none of its four mutants."""
    for i in range(12):
        _call(mission, "tool_%02d" % i)
    for _ in range(1400):
        _call(mission, "run_sqli")

    cov = mainmod._coverage(mission)
    ledger = {t["tool"]: t for t in (mainmod._tool_ledger(mission).get("tools") or [])}

    assert cov["tools_invoked"] == 1412, cov
    assert cov["distinct_tools"] == 13, cov
    assert sum(t["calls"] for t in ledger.values()) == cov["tools_invoked"]
    assert len([t for t in ledger.values() if t["calls"]]) == cov["distinct_tools"]


def test_the_count_never_decreases_as_the_mission_continues(mission):
    """A coverage counter is cumulative by definition. One that can fall is worse than none, because
    the reader has no way to know which direction to trust."""
    for i in range(5):
        _call(mission, "tool_%d" % i)
    before = mainmod._coverage(mission)["tools_invoked"]
    for _ in range(1200):
        _call(mission, "noisy")
    after = mainmod._coverage(mission)["tools_invoked"]
    assert after > before, "coverage fell from %d to %d" % (before, after)


# -- the negative control -----------------------------------------------------

def test_a_short_mission_is_unchanged(mission):
    """Most missions never approach the window, and this fix must be invisible to them. Without
    this, a change that broke ordinary counting would still pass everything above."""
    for name in ("run_dns", "run_dns", "run_zap"):
        _call(mission, name)
    cov = mainmod._coverage(mission)
    assert cov["tools_invoked"] == 3, cov
    assert cov["distinct_tools"] == 2, cov


def test_an_empty_mission_reports_zero_not_a_crash(mission):
    cov = mainmod._coverage(mission)
    assert cov["tools_invoked"] == 0 and cov["distinct_tools"] == 0, cov


# -- the population, which is the half that makes the two agree ---------------

def test_a_tool_call_row_with_no_tool_name_is_not_a_distinct_tool(mission):
    """`_tool_ledger` skips a row with no tool; `_coverage` used to bucket it under a None key and
    count it as one more distinct engine. Same population or the two numbers drift again for a
    second, quieter reason."""
    _call(mission, "run_dns")
    dbmod.add_log(mission, "tool_call", {})
    dbmod.add_log(mission, "tool_call", {"tool": ""})
    cov = mainmod._coverage(mission)
    assert cov["tools_invoked"] == 1, cov
    assert cov["distinct_tools"] == 1, cov


def test_non_tool_events_are_not_counted_as_invocations(mission):
    """`tool_result` and `info` rows outnumber `tool_call` rows in a real mission. Counting the
    wrong etype would double the header while leaving every test above green."""
    _call(mission, "run_dns")
    for _ in range(50):
        dbmod.add_log(mission, "info", {"content": "x"})
    assert mainmod._coverage(mission)["tools_invoked"] == 1
