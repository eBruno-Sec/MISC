"""Q-017 - `get_logs` kept the OLDEST rows when the limit bit, so the newest events vanished.

MEASURED on mission 54155d4b (1287 stored rows): `get_logs(limit=500)[-1].ts` was 22:31:01 against a
true last event of 22:35:20. The mission view and the backup export both ended four minutes early, and
a truncated tail is indistinguishable from a mission that stopped -- the failure mode is that the
evidence of what went wrong is exactly what gets dropped.

Half of the original ticket was DISPROVED and is not re-litigated here: the 4000-row caps at
`main._tool_ledger` and `asvs_coverage` have never truncated anything, because the largest mission ever
recorded is 1287 rows. Only the ordering was real.
"""
import db


def _seed(mid, n):
    for i in range(n):
        db.add_log(mid, "tool_call", {"seq": i})


def test_the_limit_keeps_the_NEWEST_rows(tmp_path, monkeypatch):

    db.init(str(tmp_path / "t.db"))
    mid = "m-newest"
    _seed(mid, 50)
    got = db.get_logs(mid, limit=10)
    assert len(got) == 10
    assert [r["seq"] for r in got] == list(range(40, 50)), [r["seq"] for r in got]


def test_the_rows_are_still_returned_oldest_first(tmp_path, monkeypatch):
    """The negative control for the fix: callers render these in order, so recovering the tail must
    not hand them back reversed. `ORDER BY id DESC` alone would pass the test above and break every
    consumer."""

    db.init(str(tmp_path / "t.db"))
    mid = "m-order"
    _seed(mid, 20)
    got = db.get_logs(mid, limit=5)
    assert [r["seq"] for r in got] == sorted(r["seq"] for r in got)


def test_an_unlimited_read_is_unchanged(tmp_path, monkeypatch):
    """When the limit does not bite, nothing about the result may move."""

    db.init(str(tmp_path / "t.db"))
    mid = "m-all"
    _seed(mid, 30)
    got = db.get_logs(mid, limit=1000)
    assert [r["seq"] for r in got] == list(range(30))


def test_the_last_event_is_the_last_event(tmp_path, monkeypatch):
    """Stated the way the defect was measured: the final row of a truncated read must be the mission's
    true final row, because that is where the cause of a failed run lives."""

    db.init(str(tmp_path / "t.db"))
    mid = "m-tail"
    _seed(mid, 100)
    assert db.get_logs(mid, limit=7)[-1]["seq"] == db.get_logs(mid, limit=1000)[-1]["seq"] == 99


def test_other_missions_are_not_mixed_in(tmp_path, monkeypatch):
    """The new subselect changes the WHERE/LIMIT nesting, so pin the scoping it must not lose."""

    db.init(str(tmp_path / "t.db"))
    _seed("m-a", 10)
    _seed("m-b", 10)
    assert len(db.get_logs("m-a", limit=100)) == 10
