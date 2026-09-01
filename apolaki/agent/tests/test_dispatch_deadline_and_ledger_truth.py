"""Q-142 + Q-131 + Q-134 -- the wedge, the reaper, and the number that misled two reviews.

Q-142. A PER-REQUEST TIMEOUT DOES NOT BOUND AN ENGINE THAT LOOPS. Measured on the operator's Airbnb
mission `4cac266c`: `run_header_trust` walked many requests against one origin, every one inside its
own timeout, and the mission sat in recon for 2h44m46s with no progress while the API starved behind
it. Q-110 solved this for three engines with `_PROBE_CALL_BUDGET_S`; retrofitting a fourth leaves the
fifth open, so the bound belongs at `ToolRegistry.execute`, the one boundary every dispatch crosses.

Q-131. PID 1 MUST REAP. 614 browser-related zombies accumulated under uvicorn across two field runs
(338 chrome, 246 chrome_crashpad, 30 leakless) while `/health` went from 0.23 s to timing out at 20 s.
`tini -g` in ENTRYPOINT travels with the image, so it protects `docker run` and CI identically, and
it does not require editing a compose file another lane currently holds uncommitted.

Q-134. THE LEDGER NOTE IS ONE CALL'S OUTPUT IN A COLUMN THAT READS AS A RUN TOTAL. `run_sqli |
49 calls | "tested 3 param(s)"` was read by TWO independent external reviews as "Apolaki only tested
three parameters", and a work order was written to fix crawl depth. Measured on the lab: five calls
said "tested 1 param" and one said "tested 3". The engine was testing every parameter each URL had.
"""
from __future__ import annotations

import asyncio
import os

import deadline
import pytest
import scope as scope_mod
import tools


# ── Q-142: the whole-dispatch deadline ────────────────────────────────────────

def _registry():
    eng = scope_mod.ScopeEngine()
    eng.load_manual(["x.test"], [], "t")
    return tools.ToolRegistry(eng, mission_id="q142", lab_mode=True)


def test_a_hung_dispatch_is_cancelled_and_reported_degraded():
    """THE FIELD CASE. An engine that never returns is stopped, and the result is DEGRADED rather
    than a clean zero -- the Q-093/Q-110/Q-112 rule applied to the dispatch boundary."""
    reg = _registry()

    async def _hang(_tool, _inp, _sid):
        await asyncio.sleep(3600)

    reg._dispatch_engine = _hang
    deadline.OVERRIDES["run_header_trust"] = 1
    try:
        res = asyncio.run(reg.execute("run_header_trust", {"url": "http://x.test/"}, "s"))
    finally:
        deadline.OVERRIDES.pop("run_header_trust", None)

    assert res.success is False, res
    assert "deadline" in (res.error or "").lower(), res.error
    assert "NOT a clean result" in (res.error or ""), res.error


def test_a_normal_dispatch_is_untouched():
    """NON-VACUITY, and the control that matters: a deadline that fires on healthy engines would be
    worse than the wedge it prevents."""
    reg = _registry()

    async def _quick(_tool, _inp, _sid):
        return tools.ToolResult("t", "http://x.test/", True, "2 finding(s)", [{"a": 1}])

    reg._dispatch_engine = _quick
    res = asyncio.run(reg.execute("run_header_trust", {"url": "http://x.test/"}, "s"))
    assert res.success is True and res.error is None, res


def test_the_mission_continues_after_a_timeout():
    """One wedged engine must not end the mission. The next dispatch has to work normally."""
    reg = _registry()
    calls = {"n": 0}

    async def _first_hangs(_tool, _inp, _sid):
        calls["n"] += 1
        if calls["n"] == 1:
            await asyncio.sleep(3600)
        return tools.ToolResult("t", "", True, "ok", [])

    reg._dispatch_engine = _first_hangs
    deadline.OVERRIDES["run_header_trust"] = 1
    try:
        first = asyncio.run(reg.execute("run_header_trust", {"url": "http://x.test/"}, "s"))
        second = asyncio.run(reg.execute("run_header_trust", {"url": "http://x.test/2"}, "s"))
    finally:
        deadline.OVERRIDES.pop("run_header_trust", None)
    assert first.success is False and second.success is True, (first, second)


def test_every_engine_is_bounded_by_default():
    """THE CLASS, NOT THE ENGINE. An unlisted engine must inherit the default rather than run free;
    that is the whole reason the bound sits at `execute` instead of inside four engines."""
    assert deadline.budget_for("some_engine_invented_today") == deadline.DEFAULT_S
    assert 30 <= deadline.DEFAULT_S <= 1800, deadline.DEFAULT_S


def test_legitimately_slow_engines_get_a_bigger_budget_not_an_exemption():
    """"Slow" and "wedged" are different facts. ZAP at turtle/thorough is honestly long -- but it is
    still BOUNDED, or the override becomes the hole."""
    assert deadline.budget_for("run_zap") > deadline.DEFAULT_S
    for tool, seconds in deadline.OVERRIDES.items():
        assert seconds < 86400, (tool, seconds)


def test_an_env_override_wins_and_a_bad_one_is_ignored(monkeypatch):
    monkeypatch.setenv("BBH_TOOL_DEADLINE_RUN_ZAP_S", "77")
    assert deadline.budget_for("run_zap") == 77
    monkeypatch.setenv("BBH_TOOL_DEADLINE_RUN_ZAP_S", "not-a-number")
    assert deadline.budget_for("run_zap") == deadline.OVERRIDES["run_zap"]


# ── Q-131: PID 1 reaps, and the documented test path can import ───────────────

def _dockerfile() -> str:
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return open(os.path.join(here, "Dockerfile"), encoding="utf8").read()


def test_pid1_is_an_init_that_reaps():
    """614 zombies accumulated because uvicorn was PID 1 and PID 1 does not reap orphans."""
    src = _dockerfile()
    assert 'ENTRYPOINT ["/usr/bin/tini"' in src, "PID 1 is not an init; browser orphans will pile up"
    assert '"-g"' in src, "tini must forward signals to the process GROUP or a stop orphans browsers"


def test_the_reaper_install_has_no_silent_fallback():
    """The security tools above it fall back to native equivalents. A missing reaper has no
    equivalent, and `|| echo` there would ship an image whose ENTRYPOINT cannot start."""
    src = _dockerfile()
    line = [ln for ln in src.splitlines() if "tini" in ln and "install" in ln]
    assert line, "tini is not installed at all"
    assert not any("||" in ln for ln in line), line
    assert "test -x /usr/bin/tini" in src, "the build never verifies the reaper actually landed"


def test_tier3_is_shipped_so_the_documented_tests_can_import_it():
    """Q-136: the published in-container command failed with ModuleNotFoundError. A documented test
    path that cannot run is a gate nobody is enforcing."""
    assert "COPY tier3" in _dockerfile()


# ── Q-134: the number that misled two reviews ─────────────────────────────────

def test_a_multi_call_ledger_note_says_it_is_one_call():
    """`run_sqli | 49 calls | "tested 3 param(s)"` was read by two independent reviews as the run
    total, and a work order was written against a display bug."""
    import main as mainmod
    import db as dbmod
    dbmod.init(":memory:")
    mid = "q134"
    dbmod.create_mission(mid, "P", "active", "o", {"in_scope": ["x.test"]}, {})
    for i in range(4):
        dbmod.add_log(mid, "tool_call", {"tool": "run_sqli"})
        dbmod.add_log(mid, "tool_result",
                      {"tool": "run_sqli", "count": 0, "output": "tested %d param(s), 0 confirmed" % (i + 1)})
    row = {t["tool"]: t for t in (mainmod._tool_ledger(mid).get("tools") or [])}["run_sqli"]
    assert row["calls"] == 4, row
    assert row["note"].startswith("[1 of 4 calls]"), row["note"]


def test_a_single_call_note_is_not_annotated():
    """One call IS the run for that engine, so the label would be noise."""
    import main as mainmod
    import db as dbmod
    dbmod.init(":memory:")
    mid = "q134b"
    dbmod.create_mission(mid, "P", "active", "o", {"in_scope": ["x.test"]}, {})
    dbmod.add_log(mid, "tool_call", {"tool": "run_dns"})
    dbmod.add_log(mid, "tool_result", {"tool": "run_dns", "count": 0, "output": "SPF set, DMARC set"})
    row = {t["tool"]: t for t in (mainmod._tool_ledger(mid).get("tools") or [])}["run_dns"]
    assert row["note"] == "SPF set, DMARC set", row["note"]


def test_the_annotation_never_invents_a_total():
    """DELIBERATE NON-GOAL. Summing would mean regex over engine prose, and parsing a number back
    out of a sentence is how a ledger starts disagreeing with itself. The note stays an exemplar and
    is labelled as one; the CALL COUNT is the number that is actually aggregated."""
    import main as mainmod
    import db as dbmod
    dbmod.init(":memory:")
    mid = "q134c"
    dbmod.create_mission(mid, "P", "active", "o", {"in_scope": ["x.test"]}, {})
    for _ in range(3):
        dbmod.add_log(mid, "tool_call", {"tool": "run_sqli"})
        dbmod.add_log(mid, "tool_result", {"tool": "run_sqli", "count": 0, "output": "tested 2 param(s)"})
    row = {t["tool"]: t for t in (mainmod._tool_ledger(mid).get("tools") or [])}["run_sqli"]
    assert "tested 6" not in row["note"], row["note"]
    assert "tested 2 param(s)" in row["note"], row["note"]


# ── Q-132: a healthy ZAP daemon is not coverage, and neither is a silence ─────
#
# Across every Shopify and Airbnb field run: `run_zap | failed | 0 calls | "ZAP was enabled but no
# run_zap tool_call was persisted"`. That sentence is Q-116's guard working correctly and must not
# be "fixed". What was missing is WHICH precondition failed. `run_zap` is planned in planner phase
# F2, which runs LATE -- after the fast tools -- and builds its steps from `host_bases`. So an
# opted-in mission reaches the end without ZAP for one of a small number of reasons, and naming
# none of them leaves the operator guessing between reconfiguring the daemon and reordering
# the scan.

def _zap_mission(tmp_path, name, rows, enable=True):
    import db as dbmod
    dbmod.init(str(tmp_path / (name + ".db")))
    dbmod.create_mission(name, "P", "active", "o", {"in_scope": ["x.test"]}, {"enable_zap": enable})
    for etype, payload in rows:
        dbmod.add_log(name, etype, payload)
    return name


def test_a_dispatched_zap_is_silent(tmp_path):
    """NON-VACUITY: the guard must not fire on a mission that DID run ZAP."""
    import main as mainmod
    mid = _zap_mission(tmp_path, "zap_ok", [("tool_call", {"tool": "run_zap"})])
    assert mainmod._missing_zap_invocation(mid) is None


def test_a_mission_that_never_reached_phase_f2_says_so(tmp_path, monkeypatch):
    """THE FIELD CASE. Live hosts were found, the daemon is configured, and the run still ended
    before the late phase that schedules ZAP."""
    import main as mainmod
    monkeypatch.setattr(mainmod, "_zap_configured", lambda: True)
    mid = _zap_mission(tmp_path, "zap_starved", [
        ("tool_call", {"tool": "run_httpx"}),
        ("tool_result", {"tool": "run_httpx", "count": 25, "output": "25 live hosts"}),
        ("tool_call", {"tool": "run_sqli"}),
    ])
    err = (mainmod._missing_zap_invocation(mid) or {}).get("error", "")
    assert "phase F2" in err and "starves ZAP" in err, err


def test_an_unconfigured_daemon_is_named_as_the_cause(tmp_path, monkeypatch):
    import main as mainmod
    monkeypatch.setattr(mainmod, "_zap_configured", lambda: False)
    mid = _zap_mission(tmp_path, "zap_unconf", [("tool_call", {"tool": "run_dns"})])
    err = (mainmod._missing_zap_invocation(mid) or {}).get("error", "")
    assert "ZAP_ADDR is not configured" in err, err


def test_no_live_host_is_named_as_the_cause(tmp_path, monkeypatch):
    """Phase F2 builds its steps from `host_bases`; with none it produces no step and falls
    through without a word."""
    import main as mainmod
    monkeypatch.setattr(mainmod, "_zap_configured", lambda: True)
    mid = _zap_mission(tmp_path, "zap_nohost", [
        ("tool_call", {"tool": "run_httpx"}),
        ("tool_result", {"tool": "run_httpx", "count": 0, "output": "0 live hosts"}),
    ])
    err = (mainmod._missing_zap_invocation(mid) or {}).get("error", "")
    assert "no live host base" in err, err


def test_a_refused_zap_step_outranks_the_other_causes(tmp_path, monkeypatch):
    """A step that was BUILT and then refused is a more specific and more actionable answer than
    any of the never-got-there explanations, so it must win."""
    import main as mainmod
    monkeypatch.setattr(mainmod, "_zap_configured", lambda: True)
    mid = _zap_mission(tmp_path, "zap_blocked", [
        ("scope_block", {"tool": "run_zap", "error": "out of scope"}),
    ])
    err = (mainmod._missing_zap_invocation(mid) or {}).get("error", "")
    assert "refused" in err, err


def test_the_guard_stays_silent_when_zap_was_never_enabled(tmp_path):
    import main as mainmod
    mid = _zap_mission(tmp_path, "zap_off", [("tool_call", {"tool": "run_dns"})], enable=False)
    assert mainmod._missing_zap_invocation(mid) is None
