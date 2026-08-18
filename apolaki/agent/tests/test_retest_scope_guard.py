"""Q-018 -- the retest scope guard must fail CLOSED, and the refusal must be readable.

`POST /retest/{sid}` rebuilds the mission's ScopeEngine and validates every retest URL against it.
The pre-fix code swallowed a construction error and set `_eng = None`; because every use site read
`if _eng is not None and not _eng.validate(url)[0]`, that did not weaken the check -- it DELETED it.
One malformed entry in `scope["bases"]` and the retest ran with no boundary at all.

Scope is the line between authorised testing and hitting something nobody asked us to touch, so an
exception while BUILDING that line can only mean "the line is unknown", and unknown is not
permission. Three properties are pinned here, and a fix that satisfies fewer than all three is not
a fix:

  REFUSE   a malformed scope entry stops the retest, with a reason an operator can act on
  ALLOW    a well-formed scope still retests normally -- refusing everything is not a fix
  VISIBLE  refusal and completion leave DIFFERENT rows in the mission log; before this ticket the
           handler logged nothing at all, so the two outcomes were byte-identical evidence

FAIL-BEFORE-FIX, all seven measured against the pre-fix `main.py` (loaded from `git show
3c47bdf:apolaki/agent/main.py`, every other module current). These are NOT import errors -- every
symbol used already existed:

  * refuses_the_whole_retest           : `assert 200 == 409` -- and the recorder held one real
                                         outbound request to the off-scope host
  * no_in_scope_declared_also_refuses  : `assert 200 == 409`
  * distinguishable_in_the_mission_log : `assert [] != []` -- the two outcomes literally were
                                         identical evidence, which is the ticket's third clause
  * ledger_reads_a_refused_retest      : StopIteration -- no `retest` row existed to read
  * no_outbound_url_escapes_validation : requested[0] was `http://evil.example.com/users/v1/_debug`
  * the two ALLOW controls             : failed only on the NEW `refused` key. Their BEHAVIOUR was
                                         measured separately on the pre-fix build and is unchanged
                                         by the fix -- in-scope `{'open': 1}` and one request to
                                         `http://app:3000/users/v1/_debug`; off-scope
                                         `{'inconclusive': 1}` and zero requests. So the fix
                                         preserved the working path rather than deleting the
                                         distinction; only the refusal direction moved.

Hermetic: `httpx.AsyncClient` is replaced by a recorder, so no test here touches the network. The
recorder is also the oracle -- "the guard refused" is proved by ZERO outbound requests, not by
reading the handler's own summary of itself.
"""
import os
import tempfile

import httpx
import pytest

import db as dbmod
import scope as scopemod

# `app` is the in-scope host for these missions; `evil.example.com` is never requested by any test
# in this file -- the recorder asserts that, and asserting it is most of the point.
MALFORMED = {"in_scope": ["app"], "bases": [{"nested": "dict"}], "out_of_scope": []}
WELLFORMED = {"in_scope": ["app"], "bases": ["http://app:3000"], "out_of_scope": []}
NO_SCOPE = {"in_scope": [], "bases": [], "out_of_scope": []}
PERMISSIVE = {"in_scope": ["app", "evil.example.com"],
              "bases": ["http://app:3000", "http://evil.example.com"], "out_of_scope": []}

IN_SCOPE_URL = "http://app:3000/users/v1/_debug"
OFF_SCOPE_URL = "http://evil.example.com/users/v1/_debug"

# `exposure` is one of the families with a safe idempotent GET oracle, so these findings are
# genuinely retestable -- a not_retestable finding would never reach the guard and would prove
# nothing about it.
_BODY = '{"users":[{"username":"admin","password":"pw"}]}'


class _Recorder:
    """Stands in for `httpx.AsyncClient`. Records every URL the handler actually asks for."""

    requested = []

    def __init__(self, *a, **kw):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def get(self, url, *a, **kw):
        _Recorder.requested.append(str(url))
        return httpx.Response(200, text=_BODY, request=httpx.Request("GET", url))


@pytest.fixture()
def client(monkeypatch):
    from fastapi.testclient import TestClient
    import main as mainmod

    dbmod.DB_PATH = os.path.join(tempfile.mkdtemp(), "t.db")
    dbmod._conn = None
    dbmod.init(dbmod.DB_PATH)
    _Recorder.requested = []
    monkeypatch.setattr(httpx, "AsyncClient", _Recorder)
    with TestClient(mainmod.app) as c:
        yield c


def _mission(mid: str, scope: dict, target: str) -> str:
    """A mission holding one retestable finding at `target`, then re-scoped to `scope`.

    The finding is seeded under PERMISSIVE and the scope flipped afterwards because
    `db.add_finding` enforces the write-time scope gate: an off-scope row cannot be inserted
    directly. Seeding then re-scoping isolates the RETEST guard as the single variable, which is
    what this file is about.
    """
    dbmod.create_mission(mid, "P", "active", "o", PERMISSIVE, {})
    fid = dbmod.add_finding(mid, {"title": "debug endpoint exposed", "confidence": "confirmed",
                                  "family": "exposure", "target": target,
                                  "evidence": "GET %s -> 200 with a user list including passwords" % target,
                                  "reproduction_steps": ["GET " + target]})
    assert fid, "the seed finding was refused under the permissive scope -- fixture is broken"
    dbmod.update_mission(mid, scope=scope)
    return fid


def _log_types(mid: str) -> list:
    return [(l.get("type"), l.get("tool")) for l in dbmod.get_logs(mid)]


# ── REFUSE ───────────────────────────────────────────────────────
def test_malformed_scope_entry_refuses_the_whole_retest(client):
    """A scope that cannot be parsed into a boundary stops the retest before any request."""
    _mission("mf", MALFORMED, OFF_SCOPE_URL)
    r = client.post("/retest/mf")

    assert r.status_code == 409, (
        "a retest with no enforceable boundary answered %d; a 2xx with an empty result set is "
        "exactly what a caller reads as 'nothing is still open'" % r.status_code)
    body = r.json()
    assert body["refused"] is True
    assert body["retested"] == 0 and body["results"] == []
    # the reason has to be actionable, not just present: it must name WHERE the bad entry lives
    assert "scope" in body["reason"].lower()
    assert "bases" in body["reason"] and "in_scope" in body["reason"]
    # the oracle that matters: nothing was hit
    assert _Recorder.requested == [], (
        "the retest reached out to %r despite an unenforceable scope" % _Recorder.requested)


def test_no_in_scope_declared_also_refuses(client):
    """No declared boundary is the same answer as an unparseable one: refuse, do not skip the check."""
    _mission("ns", NO_SCOPE, IN_SCOPE_URL)
    r = client.post("/retest/ns")
    assert r.status_code == 409 and r.json()["refused"] is True
    assert "in_scope" in r.json()["reason"]
    assert _Recorder.requested == []


# ── ALLOW (the mandatory negative control) ───────────────────────
def test_wellformed_scope_still_retests_an_in_scope_finding(client):
    """A fix that refuses everything is not a fix. A good scope must still do the whole job."""
    _mission("wf", WELLFORMED, IN_SCOPE_URL)
    r = client.post("/retest/wf")

    assert r.status_code == 200
    body = r.json()
    assert body["refused"] is False
    assert body["retested"] == 1
    assert body["summary"]["open"] == 1, body["summary"]
    assert body["results"][0]["verdict"] == "open"
    assert _Recorder.requested == [IN_SCOPE_URL], (
        "the in-scope target was not actually requested: %r" % _Recorder.requested)


def test_wellformed_scope_still_refuses_an_off_scope_target(client):
    """The guard's ORIGINAL job, unchanged: an in-scope mission does not retest an off-scope URL."""
    _mission("off", WELLFORMED, OFF_SCOPE_URL)
    r = client.post("/retest/off")

    assert r.status_code == 200 and r.json()["refused"] is False
    v = r.json()["results"][0]
    assert v["verdict"] == "inconclusive"
    assert "out of mission scope" in v["detail"]
    assert _Recorder.requested == [], (
        "an off-scope target was requested under a WELL-FORMED scope: %r" % _Recorder.requested)


# ── VISIBLE ──────────────────────────────────────────────────────
def test_refusal_and_completion_are_distinguishable_in_the_mission_log(client):
    """Before this ticket both outcomes logged nothing, so the log could not tell them apart.

    Asserted as a DIFFERENCE, not as the presence of one row: a future change that logs the same
    thing on both paths would restore the ambiguity while leaving a 'we log it now' test green.
    """
    _mission("vis_mf", MALFORMED, OFF_SCOPE_URL)
    _mission("vis_wf", WELLFORMED, IN_SCOPE_URL)
    client.post("/retest/vis_mf")
    client.post("/retest/vis_wf")

    refused, ran = _log_types("vis_mf"), _log_types("vis_wf")
    assert refused != ran, "a refused retest and a completed retest left identical log evidence"

    assert ("tool_error", "retest") in refused
    assert ("tool_error", "retest") not in ran
    assert ("tool_result", "retest") in ran
    assert ("tool_result", "retest") not in refused

    # the operator reads the log, not the HTTP body they no longer have
    err = next(l for l in dbmod.get_logs("vis_mf") if l.get("type") == "tool_error")
    assert "SCOPE GUARD UNAVAILABLE" in err["error"] and "bases" in err["error"]

    # a completed retest is not a scope_block: that type means enforcement WORKED and a target was
    # correctly skipped, which is the opposite claim (936f6bd / Q-067 vocabulary).
    assert not [t for t, _ in refused + ran if t == "scope_block"]


def test_the_ledger_reads_a_refused_retest_as_a_failed_tool(client):
    """The visibility row has to survive into `_tool_ledger`, or only this test can see it."""
    import main as mainmod

    _mission("led", MALFORMED, OFF_SCOPE_URL)
    client.post("/retest/led")
    row = next(t for t in mainmod._tool_ledger("led")["tools"] if t["tool"] == "retest")
    assert row["status"] == "failed", row
    assert "SCOPE GUARD UNAVAILABLE" in row["note"]

    # POSITIVE CONTROL for the ledger apparatus: a completed retest must NOT read as failed, so
    # `status == "failed"` above is the refusal being reported and not the ledger's default answer.
    _mission("led_ok", WELLFORMED, IN_SCOPE_URL)
    client.post("/retest/led_ok")
    ok = next(t for t in mainmod._tool_ledger("led_ok")["tools"] if t["tool"] == "retest")
    assert ok["status"] == "executed", ok
    assert ok["findings"] == 0, "a retest re-confirms existing findings; it must not mint new ones"


# ── the structural invariant, asserted behaviourally ─────────────
def test_no_outbound_retest_url_escapes_validation(client, monkeypatch):
    """Every URL requested must first have been handed to `ScopeEngine.validate`.

    This is the general form of the defect. `_eng is not None and ...` let a request reach the
    network without ever being validated; asserting requested <= validated catches ANY future
    re-introduction of an "unless we could not build the guard" clause, including one that spells
    it differently.
    """
    validated = []
    real = scopemod.ScopeEngine.validate

    def spy(self, target):
        validated.append(str(target))
        return real(self, target)

    monkeypatch.setattr(scopemod.ScopeEngine, "validate", spy)

    for mid, scope, target in (("g_mf", MALFORMED, OFF_SCOPE_URL),
                               ("g_wf", WELLFORMED, IN_SCOPE_URL),
                               ("g_off", WELLFORMED, OFF_SCOPE_URL),
                               ("g_ns", NO_SCOPE, IN_SCOPE_URL)):
        _mission(mid, scope, target)
        client.post("/retest/%s" % mid)

    assert set(_Recorder.requested) <= set(validated), (
        "requested without validating: %r" % (set(_Recorder.requested) - set(validated)))
    # POSITIVE CONTROL: the spy was installed and the apparatus really was looking -- an empty
    # `validated` would make the subset assertion above vacuously true.
    assert IN_SCOPE_URL in validated and OFF_SCOPE_URL in validated
    assert _Recorder.requested == [IN_SCOPE_URL]
