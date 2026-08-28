r"""Q-099 -- the SCOPE write-gate must fail CLOSED, and a mission with an unstateable boundary must
be a readable state rather than an unhandled exception.

`findings_gate.off_scope(finding, scope)` returns **True to BLOCK**, so every `return False` ADMITS.
Two of its arms returned False exactly where scope is least trustworthy, both with a comment saying
so on purpose:

    findings_gate.py:93   if not _host_of(target): return False   # "no host to judge -> admit"
    findings_gate.py:104  except Exception:        return False   # "scope engine unavailable"

Q-096 made `scope.load_manual` RAISE `ScopeConfigurationError` on a scope made entirely of regex
patterns -- the real 2026-08-24 Shopify engagement. `ScopeEngine.to_dict` concatenates
`in_scope + in_scope_patterns`, so such a mission's stored `scope["in_scope"]` is NON-empty and the
"no scope configured" arm never fires. Execution reaches the try, `load_manual` raises, and the
second arm above admits **every finding from a mission whose boundary could not be built at all**.

MEASURED at HEAD (`docker run ... apolaki-agent python -`), stored scope = the three anchored
Shopify patterns and nothing else:

    off_scope({"target": "http://evil.example.com/x"}, stored)  -> False    (ADMITTED)
    off_scope({"target": "https://www.shopify.com/x"}, stored)  -> False    (ADMITTED)
    ScopeEngine().load_manual(SHOPIFY, [], "Shopify")           -> ScopeConfigurationError

DIRECTION IS THE WHOLE TICKET. An engine failing closed loses a finding. A SCOPE gate failing open
puts an out-of-scope finding into a report submitted to a bug bounty program -- a program-rules
violation, not a missed bug. The discipline is already written at `main.py:3081`: *"Scope is the
boundary between authorised testing and hitting something nobody asked us to touch, so an exception
while BUILDING that boundary can only mean 'the boundary is unknown'. Unknown is not permission."*

BOTH HALVES ARE PINNED HERE, because the naive fix refuses everything and a gate that refuses
everything is not a gate:

    REFUSE   an unbuildable scope, or an http(s) target with no parseable host, writes NOTHING
    ADMIT    a well-formed scope still stores EVERY in-scope finding ...
    BLOCK    ... and still refuses a genuinely off-scope one
    CARVE    a non-web target (cloud posture label, network host:port) is judged by its OWN
             authorisation namespace and is never touched by the web scope, broken or not
    CLEAN    reopening a mission whose scope cannot be parsed is a 200 carrying `scope_error`,
             and the endpoints that would send traffic under it refuse 409 -- not a 500

Hermetic: no test in this file opens a socket. `replay.send` is replaced by a recorder that fails
the test if it is ever reached, so "the guard refused" is proved by ZERO outbound requests rather
than by the handler's own summary of itself.
"""
from __future__ import annotations

import os
import tempfile

import pytest

import db as dbmod
import findings_gate as fg
import scope as scope_mod

# The operator's real entries, verbatim from the engagement that produced Q-096.
SHOPIFY = [r"^.*\.shopify\.com$", r"^.*\.shopifycs\.com$", r"^.*\.myshopify\.com$"]

# What `ScopeEngine.to_dict()` stores for that mission: patterns land in `in_scope` (scope.py:398
# concatenates in_scope + in_scope_patterns), so `in_scope` is non-empty and the "no scope
# configured" arm cannot catch this.
# Q-100 SUPERSEDED THE ORIGINAL FIXTURE, NOT THIS INVARIANT. This was `list(SHOPIFY)`, because at the
# time no target could be derived from any pattern and a wildcard scope was genuinely unbuildable.
# Q-100 made wildcards yield recon roots and anchored literals yield hosts, so the operator's real
# Shopify scope is buildable now and MUST be -- that is the whole point of it. What still has to fail
# closed is a scope from which nothing at all can be derived, so the fixture moved to patterns that
# denote neither one host nor one root: alternation and a digit class.
#
# Changing the ASSERTIONS instead would have re-opened Q-099. The invariant is unchanged and every
# test below still runs against a boundary that truly cannot be built.
UNUSABLE_ENTRY = r"^(a|b)\.example\.com$"
UNBUILDABLE = {"in_scope": [UNUSABLE_ENTRY, r"^\d+\.example\.com$"],
               "bases": [], "out_of_scope": [], "program": "Unusable"}

# A second, independent way to reach the same state -- a malformed `bases` entry, the shape
# `tests/test_retest_scope_guard.py` uses. Two roads to "the boundary is unknown", so the fix is
# proved general rather than keyed to the Shopify strings.
MALFORMED = {"in_scope": ["app"], "bases": [{"nested": "dict"}], "out_of_scope": [], "program": "P"}

WELLFORMED = {"in_scope": ["app"], "bases": ["http://app:3000"], "out_of_scope": [], "program": "P"}

IN_SCOPE_TARGETS = [
    "http://app:3000/rest/products/search?q=apple",
    "http://app:3000/",
    "http://app:3000/admin/panel",
    "http://app:3000/api/v1/users/1",
    "http://app:3000/#/login",
]
OFF_SCOPE_URL = "http://evil.example.com/p"


def _fresh_db():
    dbmod.DB_PATH = os.path.join(tempfile.mkdtemp(), "t.db")
    dbmod._conn = None
    dbmod.init(dbmod.DB_PATH)


def _finding(target: str, title: str = "reflected parameter") -> dict:
    return {"title": title, "confidence": "confirmed", "family": "xss", "target": target,
            "evidence": "payload echoed verbatim", "reproduction_steps": ["GET " + target]}


# ── REFUSE: the defect ────────────────────────────────────────────────────────

def test_a_mission_whose_scope_cannot_be_built_emits_zero_findings():
    """THE gate. MUST FAIL before the fix: MEASURED, all five rows were stored.

    Not "fewer" findings -- ZERO. With no enforceable boundary no target can be proved authorised,
    so there is nothing to partially allow, exactly as the retest guard already reasons at
    `main.py:3081`. The off-scope target is in the batch deliberately: pre-fix this mission
    published a finding about a host nobody authorised.
    """
    _fresh_db()
    dbmod.create_mission("q99a", "Shopify", "active", "o", UNBUILDABLE, {})
    writes = [dbmod.add_finding("q99a", _finding(t))
              for t in IN_SCOPE_TARGETS + [OFF_SCOPE_URL, "https://www.shopify.com/x"]]

    assert dbmod.get_findings("q99a") == [], (
        "a mission with no enforceable boundary published %d finding(s)"
        % len(dbmod.get_findings("q99a")))
    assert [w.verdict for w in writes] == [dbmod.REFUSED] * len(writes), (
        "the writes did not report a SCOPE refusal: %r" % ([w.verdict for w in writes],))
    assert not any(w.stored for w in writes)


def test_off_scope_blocks_when_the_boundary_cannot_be_built():
    """The unit behind the gate, on BOTH roads to an unstateable boundary.

    Note the second assertion in each pair: the operator's OWN asset is refused too. That is not a
    bug in the fix, it is the fix -- 'unknown' is a statement about the boundary, not about the
    target, so nothing can be proved inside it.
    """
    for name, sc in (("all-pattern", UNBUILDABLE), ("malformed bases", MALFORMED)):
        assert fg.off_scope(_finding(OFF_SCOPE_URL), sc) is True, name
        assert fg.off_scope(_finding("https://www.shopify.com/x"), sc) is True, name
        assert fg.off_scope(_finding("http://app:3000/rest/x"), sc) is True, name


def test_an_http_target_with_no_parseable_host_is_refused():
    """`findings_gate.py:93`. MEASURED: `_host_of` returns '' for both of these.

    This is the Q-096 shape at the finding boundary -- something claimed a URL, and what it
    actually holds cannot be resolved, matched, or judged. Admitting it was the fail-open.
    """
    for junk in ("http://", "http:///path", "https://", "https:///"):
        assert fg._host_of(junk) == "", "fixture assumption broken for %r" % junk
        assert fg.off_scope(_finding(junk), WELLFORMED) is True, junk


def test_scope_refusal_states_why_and_stays_silent_on_a_good_scope():
    """A bare `True` cannot tell an operator what to fix. The reason must name the entry.

    The empty string for a well-formed scope is the half that makes this usable as a predicate:
    `if fg.scope_refusal(sc):` must not fire on every mission.
    """
    why = fg.scope_refusal(UNBUILDABLE)
    assert why, "an unbuildable scope produced no reason at all"
    assert UNUSABLE_ENTRY in why, "the reason does not name the entry to fix: %r" % (why,)

    why2 = fg.scope_refusal(MALFORMED)
    assert why2 and ("bases" in why2 or "in_scope" in why2), why2

    assert fg.scope_refusal(WELLFORMED) == ""
    # No declared boundary is NOT this condition -- it is the pre-existing arm at findings_gate.py:83
    # and it is out of this ticket's scope. Pinned so a later widening is a deliberate choice.
    assert fg.scope_refusal({"in_scope": []}) == ""


# ── ADMIT / BLOCK: the mandatory negative controls ────────────────────────────

def test_a_wellformed_scope_still_stores_every_in_scope_finding():
    """A fix that refuses everything is not a fix -- and refusing everything is the naive fix here."""
    _fresh_db()
    dbmod.create_mission("q99b", "P", "active", "o", WELLFORMED, {})
    writes = [dbmod.add_finding("q99b", _finding(t, "finding %d" % i))
              for i, t in enumerate(IN_SCOPE_TARGETS)]

    assert all(w.stored for w in writes), [w.verdict for w in writes]
    assert len(dbmod.get_findings("q99b")) == len(IN_SCOPE_TARGETS)
    for t in IN_SCOPE_TARGETS:
        assert fg.off_scope(_finding(t), WELLFORMED) is False, t


def test_a_wellformed_scope_still_blocks_a_genuinely_off_scope_finding():
    """The gate's ORIGINAL job, unchanged. Without this, `True` everywhere would look like a pass."""
    _fresh_db()
    dbmod.create_mission("q99c", "P", "active", "o", WELLFORMED, {})
    w = dbmod.add_finding("q99c", _finding(OFF_SCOPE_URL))

    assert w.verdict == dbmod.REFUSED and not w.stored
    assert dbmod.get_findings("q99c") == []
    assert fg.off_scope(_finding(OFF_SCOPE_URL), WELLFORMED) is True


def test_a_non_web_target_is_never_judged_by_the_web_scope_broken_or_not():
    """DELIBERATE CARVE-OUT, pinned so the fix cannot quietly swallow it.

    A cloud-posture label (`fw-web`) and a network host:port live in their own authorisation
    namespace -- the cloud token, the service-pack scope. The WEB ScopeEngine has no jurisdiction
    over them, so its failure to build says nothing about them and must not drop them. The
    reversal in this ticket applies to http(s) targets only.
    """
    for sc in (WELLFORMED, UNBUILDABLE, MALFORMED):
        assert fg.off_scope({"target": "fw-web"}, sc) is False
        assert fg.off_scope({"target": "10.0.0.5:445"}, sc) is False
        assert fg.off_scope({"title": "no target at all"}, sc) is False


# ── CLEAN: the UX decision (D3 in docs/handoff/scope_gate_failopen.md) ────────

class _NeverCalled:
    """Stands in for `replay.send`. Reaching it at all fails the test."""

    calls = []

    @staticmethod
    async def send(c, method, url, headers, body):
        _NeverCalled.calls.append(str(url))
        raise AssertionError("an outbound request was issued: %s %s" % (method, url))


@pytest.fixture()
def client(monkeypatch):
    from fastapi.testclient import TestClient
    import main as mainmod
    import replay as replay_mod

    _fresh_db()
    _NeverCalled.calls = []
    monkeypatch.setattr(replay_mod, "send", _NeverCalled.send)
    dbmod.create_mission("bad", "Shopify", "complete", "o", UNBUILDABLE, {})
    dbmod.create_mission("good", "P", "complete", "o", WELLFORMED, {})
    with TestClient(mainmod.app) as c:
        yield c


def test_reopening_a_mission_with_an_invalid_scope_is_a_readable_state(client):
    """MUST FAIL before the fix: there is no `scope_error` key to read.

    The mission still OPENS -- 200, with its findings, notes and logs -- because refusing to render
    a historical record helps nobody. What changes is that the record now SAYS its boundary is
    invalid, instead of the operator discovering it through a traceback on the first action.
    """
    r = client.get("/missions/bad")
    assert r.status_code == 200, r.text
    err = r.json().get("scope_error")
    assert err, "a mission whose scope cannot be parsed reports no scope_error at all"
    assert UNUSABLE_ENTRY in err, "scope_error does not name the entry to fix: %r" % (err,)

    ok = client.get("/missions/good")
    assert ok.status_code == 200
    assert not ok.json().get("scope_error"), (
        "a WELL-FORMED mission reports a scope error: %r" % (ok.json().get("scope_error"),))


def test_a_scope_guarded_endpoint_refuses_409_instead_of_raising(client):
    """MUST FAIL before the fix: `_scope_for` lets `ScopeConfigurationError` escape, so the
    TestClient re-raises it and the product answers 500.

    409, not 400: the REQUEST is well-formed, the stored mission scope is what is invalid. Same
    status and same vocabulary the retest guard already uses for this exact condition
    (`main.py:3115`).
    """
    r = client.post("/workbench/bad/replay", json={"method": "GET", "url": "http://app:3000/x"})
    assert r.status_code == 409, r.text
    detail = str(r.json().get("detail", ""))
    assert "scope" in detail.lower() and UNUSABLE_ENTRY in detail, detail
    assert _NeverCalled.calls == [], _NeverCalled.calls


def test_the_409_is_a_new_state_and_not_the_ordinary_off_scope_refusal(client):
    """POSITIVE CONTROL for the status code. A well-formed mission handed an off-scope URL must
    still answer the ORIGINAL 400 -- otherwise 409 is just what this endpoint always says now."""
    r = client.post("/workbench/good/replay", json={"method": "GET", "url": OFF_SCOPE_URL})
    assert r.status_code == 400, r.text
    assert "Off-scope" in str(r.json().get("detail", ""))
    assert _NeverCalled.calls == []


def test_scope_for_still_returns_a_working_engine_for_a_wellformed_mission():
    """The other half of the control: the refusal path did not replace the working one."""
    import main as mainmod

    _fresh_db()
    dbmod.create_mission("wf", "P", "complete", "o", WELLFORMED, {})
    eng = mainmod._scope_for("wf")
    assert isinstance(eng, scope_mod.ScopeEngine)
    assert eng.validate("http://app:3000/rest/x")[0] is True
    assert eng.validate(OFF_SCOPE_URL)[0] is False
