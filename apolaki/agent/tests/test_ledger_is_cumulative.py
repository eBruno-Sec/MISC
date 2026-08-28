"""Q-105 — the tool ledger was a WINDOW over a running mission, so it went backwards.

MEASURED across two renders of one live Shopify mission, with the findings, the evidence timestamps
and the surface count all identical between them. Only the ledger moved, and it moved DOWN:

    tools listed              12  ->  7
    run_transport_posture     executed, 3 calls, 10 findings  ->  ABSENT
    run_subfinder calls       67  ->  286   while its note went "2 subdomains" -> "1 subdomains"
    "never dispatched"        83  ->  86
    ASVS "engine ran clean"    7  ->  4

`_tool_ledger` folded `db.get_logs(session_id, limit=4000)`, and `get_logs` keeps the NEWEST rows
when the limit bites -- correct for a log view (Q-017 fixed the opposite defect) and wrong for an
aggregate. Early rows fell out of the window, so an engine that RAN was reported as never
dispatched, and the error reached the ASVS coverage numbers.

THE LOAD-BEARING TEST IS `test_a_tool_that_ran_early_survives_a_long_tail_of_later_events`. That is
the exact field failure: transport_posture ran in the first minute and was gone by the second render.
"""
import db as dbmod
import main as mainmod
import pytest


@pytest.fixture()
def mission(tmp_path):
    dbmod.init(str(tmp_path / "ledger.db"))
    mid = "q105"
    dbmod.create_mission(mid, "P", "active", "o", {"in_scope": ["example.test"]}, {})
    return mid


def _call(mid, tool, count=0, note=""):
    dbmod.add_log(mid, "tool_call", {"tool": tool})
    dbmod.add_log(mid, "tool_result", {"tool": tool, "count": count, "output": note})


def _tools(mid):
    return {t["tool"]: t for t in (mainmod._tool_ledger(mid).get("tools") or [])}


# ── the field failure ─────────────────────────────────────────────────────────

def test_a_tool_that_ran_early_survives_a_long_tail_of_later_events(mission):
    """transport_posture ran in the first minute of the real mission and had vanished from the
    ledger by the second render. The window was 4000 rows; this pushes well past it."""
    _call(mission, "run_transport_posture", count=10, note="7 finding(s)")
    for i in range(2600):                       # 5200 rows: past the old 4000-row window
        _call(mission, "run_subfinder", count=1, note="1 subdomains found")

    tools = _tools(mission)
    assert "run_transport_posture" in tools, (
        "an engine that RAN is missing from the ledger, so it will be reported as never "
        "dispatched: %r" % (sorted(tools),))
    assert tools["run_transport_posture"]["calls"] == 1


def test_counts_never_decrease_as_the_mission_continues(mission):
    """A ledger is cumulative by definition. A counter that can fall is worse than no counter,
    because a reader has no way to know which direction to trust."""
    _call(mission, "run_dns")
    before = _tools(mission)["run_dns"]["calls"]
    for _ in range(3000):
        _call(mission, "run_other")
    after = _tools(mission)["run_dns"]["calls"]
    assert after >= before, "run_dns calls fell from %d to %d" % (before, after)


def test_every_tool_that_ever_ran_is_present(mission):
    """The count of DISTINCT tools dropped 12 -> 7 in the field. Nothing may age out."""
    names = ["tool_%02d" % i for i in range(12)]
    for n in names:
        _call(mission, n)
    for _ in range(3000):
        _call(mission, "noisy_tool")
    tools = _tools(mission)
    missing = [n for n in names if n not in tools]
    assert not missing, "tools aged out of the ledger: %r" % (missing,)


# ── the accessor itself ───────────────────────────────────────────────────────

def test_iter_logs_returns_everything_and_get_logs_still_windows(mission):
    """Both behaviours are correct for their own caller, which is why this needed a SECOND accessor
    rather than a change to `get_logs`. Q-017 deliberately made `get_logs` keep the newest rows so a
    truncated tail cannot make a live mission look stopped; that must not regress."""
    for _ in range(1200):
        _call(mission, "t")
    assert sum(1 for _ in dbmod.iter_logs(mission)) == 2400
    assert len(dbmod.get_logs(mission, limit=100)) == 100


def test_iter_logs_is_a_generator_not_a_list(mission):
    """A long mission has tens of thousands of rows and the ledger only folds each into a running
    total. Materialising them would trade one resource problem for another."""
    import types
    _call(mission, "t")
    assert isinstance(dbmod.iter_logs(mission), types.GeneratorType)


def test_a_malformed_row_is_skipped_rather_than_fatal(mission):
    """A report must still render. One unreadable event cannot take the whole ledger with it."""
    _call(mission, "good")
    dbmod._exec("INSERT INTO logs(mission_id,etype,data,created_at) VALUES(?,?,?,?)",
                (mission, "tool_call", "{not json", "2026-01-01"))
    _call(mission, "also_good")
    tools = _tools(mission)
    assert "good" in tools and "also_good" in tools, sorted(tools)
