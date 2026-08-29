"""Q-113, the reporting half - a denominator that never leaves the process is not a disclosure.

The sweep computes what it declined and records it on the mission (`_sweep_budget`). Lane A's own
island check was honest about the gap: "`scan._sweep_budget` IS currently unread by product code."
So the count existed and the report still read as whole-surface coverage.

    "0 confirmed across 465 endpoints"                        <- evidence about the target
    "0 confirmed across the 40 we reached before the clock"   <- evidence about our budget

Only one of those is evidence, and a reader who cannot see which one is being made has no way to
weigh the zeros. Same rule as Q-110's counted truncation and Q-093's refusal to report a failed
attempt as a clean result.

Two routes are asserted, because a live mission and an archived one render from different places and
fixing only the one you happen to open is how half a disclosure ships:

  * LIVE   - read off the running agent through `sessions`
  * ARCHIVED - read off the mission context snapshot persisted at mission end

The negative control is the load-bearing one: a sweep that declined NOTHING must print no line at
all, or every ordinary mission grows a scary-looking coverage caveat it has not earned.
"""
import db as dbmod
import main as mainmod
import pytest


@pytest.fixture()
def mission(tmp_path):
    dbmod.init(str(tmp_path / "q113rep.db"))
    mid = "q113rep"
    dbmod.create_mission(mid, "P", "active", "o", {"in_scope": ["example.test"]}, {})
    return mid


class _Tools:
    """A live session always carries one (`main.py:672`); `_coverage` reads `urls` off it for the
    surface count. Stubbed so this fixture is the shape production actually builds."""
    urls = []


class _Agent:
    def __init__(self, budget):
        self._sweep_budget = budget


# -- the live route ------------------------------------------------------------

def test_a_bounded_sweep_states_its_denominator_in_coverage(mission, monkeypatch):
    monkeypatch.setitem(mainmod.sessions, mission,
                        {"tools": _Tools(), "agent": _Agent({"candidates": 465, "selected": 40, "declined": 425,
                                          "cap": 700, "timed_out": 425})})
    line = mainmod._coverage(mission).get("injection_sweep", "")
    assert "465" in line and "40" in line and "425" in line, line
    assert "wall-clock" in line, "a timed-out sweep must say WHY it stopped: %r" % line


def test_the_reason_is_omitted_when_the_stop_was_not_the_clock(mission, monkeypatch):
    """A count ceiling and a clock are different facts about the run. Printing "wall-clock" for a
    volume truncation would be a false statement about which bound bound."""
    monkeypatch.setitem(mainmod.sessions, mission,
                        {"tools": _Tools(), "agent": _Agent({"candidates": 900, "selected": 700, "declined": 200,
                                          "cap": 700})})
    line = mainmod._coverage(mission)["injection_sweep"]
    assert "wall-clock" not in line, line
    assert "200 declined" in line, line


# -- the archived route --------------------------------------------------------

def test_an_archived_mission_still_carries_the_denominator(mission):
    """No live session at all: the report renders from the persisted snapshot. Without this the
    disclosure evaporates the moment the mission ends, which is when reports are actually read."""
    dbmod.update_mission(mission, context={"sweep_budget": {"candidates": 465, "selected": 40,
                                                            "declined": 425, "timed_out": 425}})
    line = mainmod._coverage(mission).get("injection_sweep", "")
    assert "465" in line and "425" in line, line


def test_the_live_agent_wins_over_a_stale_snapshot(mission, monkeypatch):
    """A running mission's numbers move. The snapshot is the FALLBACK, not the source of truth, or a
    long run would report the figures it had at its first checkpoint."""
    dbmod.update_mission(mission, context={"sweep_budget": {"candidates": 465, "selected": 5,
                                                            "declined": 460}})
    monkeypatch.setitem(mainmod.sessions, mission,
                        {"tools": _Tools(), "agent": _Agent({"candidates": 465, "selected": 40, "declined": 425})})
    assert "40 of 465" in mainmod._coverage(mission)["injection_sweep"]


# -- the negative control ------------------------------------------------------

def test_a_full_sweep_prints_no_caveat(mission, monkeypatch):
    """THE ONE THAT MATTERS. Most missions decline nothing. A line that always appears is a line
    nobody reads, and "0 declined" phrased as a coverage caveat actively misleads."""
    monkeypatch.setitem(mainmod.sessions, mission,
                        {"tools": _Tools(), "agent": _Agent({"candidates": 10, "selected": 10, "declined": 0})})
    line = mainmod._coverage(mission)["injection_sweep"]
    assert "0 declined" in line, "a full sweep should still state that it was full: %r" % line
    assert "wall-clock" not in line, line


def test_a_mission_whose_sweep_never_ran_says_nothing(mission):
    """Absent is not zero. A recon-only mission has no sweep denominator to report and must not
    invent one."""
    assert "injection_sweep" not in mainmod._coverage(mission)


def test_a_budget_with_no_candidates_says_nothing(mission, monkeypatch):
    """`candidates == 0` means there was no parameterized surface at all, so there is no coverage
    claim to qualify - and `0 of 0 probed` reads as a failure when it is a fact about the target."""
    monkeypatch.setitem(mainmod.sessions, mission,
                        {"tools": _Tools(), "agent": _Agent({"candidates": 0, "selected": 0, "declined": 0})})
    assert "injection_sweep" not in mainmod._coverage(mission)


# -- the wiring, so this cannot become an island again -------------------------

def test_the_mission_context_is_where_the_report_reads_it_from():
    """NO ISLANDS. `_record_orchestration` writes `ctx["sweep_budget"]` and `_coverage` reads it;
    pin the key to both sides, because a rename on one side alone is silent."""
    import inspect
    src = inspect.getsource(mainmod)
    assert 'ctx["sweep_budget"] = swb' in src, "nothing persists the sweep budget"
    assert '.get("sweep_budget")' in src, "nothing reads the persisted sweep budget"
