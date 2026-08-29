"""Q-116 -- the census behind Q-115: which OTHER consumers fold a log WINDOW as an aggregate.

Q-105 moved `_tool_ledger` off `db.get_logs(limit=4000)`. Q-115 found the sibling in the same file,
`_coverage`, still on `limit=2000`. Fixing two instances of a defect and not asking how many there
are is how it comes back, so this is the whole population of `get_logs` call sites outside tests:

    main.py:835   "logs": db.get_logs(session_id, limit=500)      LOG VIEW      correct, windowed
    main.py:4180  "logs": db.get_logs(session_id, limit=500)      LOG VIEW      correct, windowed
    main.py:1733  ASVS attempted_engines, limit=4000              AGGREGATE     fixed here
    main.py:2942  _missing_zap_invocation, limit=100000           GUARD         fixed here

The split is the point, and it is why `get_logs` was not simply changed. Q-017 made it keep the
NEWEST rows deliberately, so a truncated tail cannot make a live mission look stopped. That is right
for a view of a log and wrong for every total computed over one.

WHY THE TWO FIXED ONES MATTER:

  ASVS. `attempted_engines` is how a clean run VERIFIES a property -- an engine that ran and found
  nothing is evidence the objective holds. Aged out of the window, that engine's objective silently
  reverts to "not tested". Q-105 already recorded the symptom (`ASVS "engine ran clean" 7 -> 4`) and
  repaired the ledger; this endpoint is a second, independent path to the same number. DERIVED, not
  directly observed: the operator's mission logged 2181 dispatches, and each dispatch persists at
  least a `tool_call` and a `tool_result`, so that run was already past the 4000-row window.

  ZAP. `_missing_zap_invocation` is a FAIL-CLOSED integrity guard: it refuses to let a mission claim
  ZAP ran when no dispatch was persisted. `run_zap` dispatches EARLY. Under a window the guard would
  accuse the run of skipping ZAP precisely BECAUSE ZAP ran first and the mission then got long. A
  guard that fires on the mission's own length is worse than no guard, and this is the same shape as
  the three repaired Codex guards: scoped to its author's attention rather than to the fact.
"""
import asyncio

import db as dbmod
import main as mainmod
import pytest


def _call(mid, tool):
    dbmod.add_log(mid, "tool_call", {"tool": tool})
    dbmod.add_log(mid, "tool_result", {"tool": tool, "count": 0, "output": ""})


@pytest.fixture()
def mission(tmp_path):
    dbmod.init(str(tmp_path / "q116.db"))
    mid = "q116"
    dbmod.create_mission(mid, "P", "active", "o", {"in_scope": ["example.test"]},
                         {"enable_zap": True})
    return mid


# -- ASVS: an engine that ran early still counts as attempted ------------------

def _attempted(monkeypatch, mid):
    """Capture what the endpoint hands to the model, so this tests the change and not ASVS."""
    import asvs_model as am
    seen = {}

    def _fake(findings, attempted_engines=()):
        seen["engines"] = set(attempted_engines or ())
        return {"ok": True}

    monkeypatch.setattr(am, "assess", _fake)
    asyncio.run(mainmod.asvs_coverage(session=mid))
    return seen.get("engines", set())


def test_an_engine_that_ran_early_is_still_an_attempted_engine(monkeypatch, mission):
    """THE FIELD SHAPE. transport_posture runs in the first minute; the sweep then runs for hours."""
    _call(mission, "run_transport_posture")
    for _ in range(2200):                       # 4400 rows: past the old 4000-row window
        _call(mission, "run_sqli")

    engines = _attempted(monkeypatch, mission)
    assert "run_transport_posture" in engines, (
        "an engine that RAN is absent from attempted_engines, so its ASVS objective reverts to "
        "'not tested': %r" % (sorted(engines),))


def test_a_short_mission_reports_the_same_engines_as_before(monkeypatch, mission):
    """Negative control. Most missions never approach the window and must be unaffected."""
    for name in ("run_dns", "run_zap", "run_dns"):
        _call(mission, name)
    assert _attempted(monkeypatch, mission) == {"run_dns", "run_zap"}


def test_a_tool_call_with_no_tool_name_is_not_an_engine(monkeypatch, mission):
    """Pre-existing behaviour, pinned so the accessor swap cannot have widened the population."""
    _call(mission, "run_dns")
    dbmod.add_log(mission, "tool_call", {})
    assert _attempted(monkeypatch, mission) == {"run_dns"}


# -- the ZAP guard: it may not fire because the mission got long ---------------

def _bulk_filler(mid, n):
    """`n` filler rows in one statement. The guard's old window was 100000, so a test that only
    reaches 4000 rows cannot kill the mutant that restores it -- and a gate that does not exercise
    the bound it exists to check is the failure mode I shipped once already this month. Direct
    INSERT rather than 100k `add_log` calls, matching the pattern the sibling suite already uses for
    a hand-built row."""
    dbmod._exec(
        "INSERT INTO logs(mission_id,etype,data,created_at) "
        "SELECT ?, 'tool_call', '{\"tool\":\"filler\"}', '2026-01-01' FROM ("
        "  WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c WHERE x < ?)"
        "  SELECT x FROM c)", (mid, n))


def test_the_zap_guard_does_not_accuse_a_run_that_did_invoke_zap(mission):
    """run_zap dispatches EARLY, so a window is exactly backwards for this guard. The filler count
    is deliberately past the OLD 100000-row cap: the whole claim is that mission LENGTH can no
    longer flip this verdict."""
    _call(mission, "run_zap")
    _bulk_filler(mission, 100_100)
    assert mainmod._missing_zap_invocation(mission) is None, (
        "the guard reported ZAP was never invoked on a mission that invoked it first")


def test_the_zap_guard_still_fires_when_zap_really_never_ran(mission):
    """NON-VACUITY. Without this, `return None` satisfies the test above."""
    for _ in range(50):
        _call(mission, "run_sqli")
    got = mainmod._missing_zap_invocation(mission)
    assert got and got.get("tool") == "run_zap", got
    assert got.get("type") == "tool_error", got


def test_the_zap_guard_is_silent_when_zap_was_not_enabled(tmp_path):
    """A mission that never opted in is not owed a ZAP run."""
    dbmod.init(str(tmp_path / "q116b.db"))
    dbmod.create_mission("nozap", "P", "active", "o", {"in_scope": ["example.test"]}, {})
    assert mainmod._missing_zap_invocation("nozap") is None


# -- the negative half of the census ------------------------------------------

def test_a_log_view_is_still_a_window(mission):
    """`get_logs` must KEEP its windowing. Q-017 made it hold the newest rows on purpose, so a
    truncated tail cannot make a live mission look stopped. This census fixed the aggregates; a
    change that also 'fixed' the views would undo a different ticket."""
    for _ in range(400):
        _call(mission, "t")
    rows = dbmod.get_logs(mission, limit=100)
    assert len(rows) == 100
    assert sum(1 for _ in dbmod.iter_logs(mission)) == 800
