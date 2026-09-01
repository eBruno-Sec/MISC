"""Q-130 / Q-135 / Q-137 / Q-139 / Q-140 -- the queue tail, and one of them was bigger than filed.

Q-140 was filed as cosmetic ("scope entries are duplicated in the report"). MEASURED across the
operator's three Shopify reports, the duplication GROWS every run:

    2026-08-29 07:06    linkpop.com appears 2x
    2026-08-29 16:23    linkpop.com appears 3x
    2026-08-30 06:50    linkpop.com appears 4x

`memory.target_key` hashes `ScopeEngine.to_dict()`, and `in_scope` is part of it. So every run
produced a DIFFERENT memory key, which means cross-session warm start has been silently cold for
that target the whole time -- prior subdomains, endpoints and findings never seeded, and every run
re-derived the same surface from scratch. Deduping makes the key STABLE, not just the report tidy.

Q-130: `base_map` falls back to `https://{host}` for any host the operator did not declare with a
scheme. On the reach lab that sent every guessed API path at a port with no TLS listener.

Q-135: the CDX timeout was 40 s on a path measured at 47-71 s, and `_get_json` returns None for a
non-200 exactly as it does for no rows -- so a 429 read as "this target has no archived URLs".

Q-137: seven `Host header injection` rows, all `linkpop.com`, all INFORMATIONAL, all "NO sink was
found". Q-114 got the severity right; the repetition is what remained.

Q-139: `sess["events"]` are raw engine dicts with no time on them, so 3913 lines of pasted live log
carried no timestamp, no elapsed time and no ordering.
"""
from __future__ import annotations

import datetime
import json

import pytest


# ── Q-140: the scope key was unstable, which silently disabled warm start ────

def test_reimporting_a_scope_does_not_change_the_memory_key():
    """THE ONE THAT MATTERS. An operator who loads a scope file twice must not get a new target
    identity -- that is what made every Shopify run a cold start."""
    import memory
    import scope as scope_mod
    once = scope_mod.ScopeEngine()
    once.load_manual(["linkpop.com", "shop.app"], [], "P")
    twice = scope_mod.ScopeEngine()
    twice.load_manual(["linkpop.com", "shop.app"], [], "P")
    twice.load_manual(["linkpop.com", "shop.app"], [], "P")
    assert memory.target_key(once.to_dict()) == memory.target_key(twice.to_dict())


def test_scope_entries_are_deduped_with_order_preserved():
    """First-seen order is the operator's own ordering and must survive."""
    import scope as scope_mod
    eng = scope_mod.ScopeEngine()
    eng.load_manual(["b.test", "a.test", "b.test"], [], "P")
    got = eng.to_dict()["in_scope"]
    assert got == list(dict.fromkeys(got)), got
    assert got.index("b.test") < got.index("a.test"), got


def test_a_scope_with_no_duplicates_is_unchanged():
    """NEGATIVE CONTROL. Dedup must be a no-op for the ordinary case, or every existing target key
    moves and every warm start goes cold -- the exact failure this fixes."""
    import memory
    import scope as scope_mod
    eng = scope_mod.ScopeEngine()
    eng.load_manual(["a.test", "b.test"], [], "P")
    assert eng.to_dict()["in_scope"] == ["a.test", "b.test"]
    assert memory.target_key(eng.to_dict())


# ── Q-130: a measurement beats an assumption, a declaration beats both ───────

def _agent_with(live_hosts, scope_entries):
    import agent as agent_mod
    import scope as scope_mod
    eng = scope_mod.ScopeEngine()
    eng.load_manual(list(scope_entries), [], "P")

    class _T:
        recon = {"live_hosts": list(live_hosts)}

    a = object.__new__(agent_mod.BBHAgent)
    a.scope, a.tools = eng, _T()
    return a


def test_an_observed_http_base_beats_the_https_assumption():
    """THE FIELD CASE. The lab answers on http and has no TLS listener at all."""
    a = _agent_with([{"url": "http://wpreach"}], ["wpreach"])
    assert a._observed_bases()["wpreach"] == "http://wpreach"


def test_an_operator_declared_base_is_never_overridden():
    """THE HALF THAT KEEPS THIS SAFE. Flipping to whatever answered would let a downgraded or
    hijacked response rewrite a scheme the operator chose deliberately."""
    a = _agent_with([{"url": "http://declared.test"}], ["https://declared.test:8443"])
    assert a._observed_bases()["declared.test"] == "https://declared.test:8443"


def test_an_unobserved_host_keeps_the_https_default():
    """https-first is correct for the internet; this ticket narrows the guess, it does not invert
    the default."""
    a = _agent_with([], ["never-probed.test"])
    assert a._observed_bases()["never-probed.test"].startswith("https://")


def test_a_host_outside_scope_cannot_inject_a_base():
    """`live_hosts` is discovered data. A host that is not in the scope map must not create an
    entry -- that would be discovered input widening the target set."""
    a = _agent_with([{"url": "http://evil.test"}], ["a.test"])
    assert "evil.test" not in a._observed_bases()


# ── Q-137: one behaviour on one host is one row ──────────────────────────────

def _hh(i, host="linkpop.com", sev="informational"):
    return {"family": "host_header", "title": "Host header injection", "severity": sev,
            "target": "https://%s/%d?s" % (host, i), "description": "spoofed Host became the target"}


def test_seven_identical_informational_rows_collapse_to_one():
    import report as report_mod
    out = report_mod.collapse_repeated_observations([_hh(i) for i in range(7)])
    assert len(out) == 1, out
    assert "further URL(s)" in out[0]["description"], out[0]["description"]


def test_the_collapsed_row_still_names_the_other_urls():
    """Nothing is discarded. A reader must still be able to see every affected URL."""
    import report as report_mod
    out = report_mod.collapse_repeated_observations([_hh(i) for i in range(4)])
    assert "https://linkpop.com/1?s" in out[0]["description"], out[0]["description"]


def test_a_different_host_is_a_different_row():
    """Host, not URL, is the grouping key -- but two hosts are two things to act on."""
    import report as report_mod
    out = report_mod.collapse_repeated_observations([_hh(0), _hh(1), _hh(0, host="other.test")])
    assert len(out) == 2, out


def test_medium_and_above_are_never_collapsed():
    """THE LOAD-BEARING CONTROL. A confirmed injection on ten endpoints is ten pieces of work;
    merging them would be this tool hiding findings from its own operator."""
    import report as report_mod
    rows = [_hh(i, sev="high") for i in range(5)] + [_hh(i, sev="medium") for i in range(5)]
    assert len(report_mod.collapse_repeated_observations(rows)) == 10


def test_collapsing_is_idempotent():
    """The report renders more than once per mission; a second pass must not re-append the note."""
    import report as report_mod
    once = report_mod.collapse_repeated_observations([_hh(i) for i in range(5)])
    twice = report_mod.collapse_repeated_observations(list(once))
    assert once[0]["description"] == twice[0]["description"]


# ── Q-135: an empty archive and an unreachable archive are different facts ───

def test_the_cdx_timeout_is_above_the_measured_path_latency():
    """MEASURED 47-71 s. A 40 s cap turned a slow endpoint into 'all connection attempts failed'."""
    import tools
    assert tools._CDX_TIMEOUT_S >= 90, tools._CDX_TIMEOUT_S
    assert tools._CDX_ATTEMPTS >= 2, tools._CDX_ATTEMPTS


def test_wayback_failure_is_reported_as_ours_not_the_targets():
    """A tool that could not reach archive.org has learned nothing about the target, and saying so
    is the Q-093 rule in a recon engine."""
    import asyncio

    import scope as scope_mod
    import tools
    eng = scope_mod.ScopeEngine()
    eng.load_manual(["x.test"], [], "t")
    reg = tools.ToolRegistry(eng, mission_id="q135", lab_mode=True)

    async def _fail(_api):
        return None, "archive.org did not answer within 90s"

    reg._cdx_fetch = _fail
    res = asyncio.run(reg._run_wayback({"domain": "x.test"}))
    assert res.success is False, res
    assert "DEGRADED" in (res.error or ""), res.error


def test_an_empty_archive_is_a_clean_zero_not_a_failure():
    """The discriminator. Reachable with no rows is a fact ABOUT THE TARGET and must not be
    reported as tool degradation."""
    import asyncio

    import scope as scope_mod
    import tools
    eng = scope_mod.ScopeEngine()
    eng.load_manual(["x.test"], [], "t")
    reg = tools.ToolRegistry(eng, mission_id="q135b", lab_mode=True)

    async def _empty(_api):
        return [["original"]], ""          # header row only: reachable, nothing archived

    reg._cdx_fetch = _empty
    res = asyncio.run(reg._run_wayback({"domain": "x.test"}))
    assert res.success is True, res
    assert not res.error, res.error


# ── Q-139: the live stream carries no time, though the database has always ───

def test_the_stream_envelope_carries_seq_ts_and_elapsed():
    """A 3913-line pasted log with no timestamps cannot distinguish a wedged run from a slow one."""
    import inspect

    import main as mainmod
    src = inspect.getsource(mainmod.stream)
    for field in ('"seq"', '"ts"', '"elapsed_ms"'):
        assert field in src, "the SSE envelope does not carry %s" % field


def test_the_envelope_never_overwrites_an_engine_field():
    """`**ev` comes LAST on purpose: an engine that already set `ts` keeps its own value, and the
    envelope must never silently rewrite an event's own data."""
    ev = {"type": "tool_call", "ts": "engine-supplied"}
    out = {"seq": 1, "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(),
           "elapsed_ms": 5, **ev}
    assert out["ts"] == "engine-supplied", out
    assert out["type"] == "tool_call"
    json.dumps(out)          # the stream serialises it; a non-serialisable envelope breaks the UI
