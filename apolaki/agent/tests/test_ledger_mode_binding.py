"""The tool ledger must carry the mission's PERMISSION TIER, or the report tells the reader the
opposite of the truth about ~40 engines.

Q-051 shipped `report.arsenal_gap()`, which separates two classes that have opposite fixes:

  blocked_by_mode  the engine COULD NOT run at this permission tier   -> fix = raise the mode
  not_dispatched   the engine could have run and was not selected     -> fix = the planner

`arsenal_gap` reads `ledger["mode"]`, and falls back to `ledger["strategy"]` only when that names a
real mode. That fallback can NEVER fire: the vocabularies are disjoint (strategy is
manual|deterministic|low_ai|agentic; a mode is passive|active|full). `main._tool_ledger()` never
emitted `mode`, so `blocked_by_mode` was permanently empty and every tier-blocked engine fell through
to "Available but not selected" -- the report asserting the planner declined `run_sqli`, `run_sqlmap`,
`run_ssrf`, `run_cmdi`, `run_xxe` and `run_zap` when the permission tier had barred them outright.

This is the "verify BOTH halves of a fix" rule: the READER half (mode-then-strategy) landed and the
PRODUCER half did not, and no test caught it because every existing fixture supplied `mode` by hand.
So these tests assert against a ledger built by the real producer, never a literal.
"""
# Q-052 re-tiered the permission model: ACTIVE now means "sends payloads, READ-ONLY" and
# INTRUSIVE means "CHANGES STATE". run_cmdi sends a payload and reads the answer, so it is
# ACTIVE and is no longer blocked at that mode. These tests are about the DISTINCTION between
# tier-blocked and not-selected, which is unchanged -- only the engine that demonstrates it
# moved. run_upload_test is one of the nine that genuinely write, so it still demonstrates it.

from __future__ import annotations

import os
import tempfile

import db as dbmod
import main as mainmod
import report as reportmod


def _mission(mid: str, mode: str):
    dbmod.init(os.path.join(tempfile.mkdtemp(), "t.db"))
    dbmod.create_mission(mid, "P", mode, "o", {"in_scope": ["juice-shop:3000"]}, {})
    # One engine that actually ran, so the ledger is not empty and `dispatched` is non-trivial.
    dbmod.add_log(mid, "tool_call", {"tool": "run_xss"})
    dbmod.add_log(mid, "tool_result", {"tool": "run_xss", "count": 0, "output": "no reflection"})
    return mainmod._tool_ledger(mid)


def test_the_producer_emits_the_mission_mode():
    """The half that was missing. Before this fix the key was simply absent."""
    led = _mission("mode1", "active")
    assert "mode" in led, "main._tool_ledger dropped the mode key; arsenal_gap cannot classify tiers"
    assert led["mode"] == "active"


def test_tier_blocked_engines_are_counted_and_not_reported_as_unselected():
    """END TO END through the real producer: active mode must yield a non-empty blocked_by_mode.

    This is the negative control that was specified when the defect was measured: render at
    mode=active and assert a non-zero "unable to run at this permission tier" count. Measured as 0
    on a real ledger before the producer patch, twice.
    """
    led = _mission("mode2", "active")
    gap = reportmod.arsenal_gap(led)
    assert not gap["error"], gap["error"]
    assert gap["blocked_by_mode"], (
        "no engine was classified as tier-blocked at mode=active, so every INTRUSIVE engine is "
        "being reported to the reader as 'available but not selected'")
    # The two classes must stay disjoint -- merging them is the whole defect.
    assert not (set(gap["blocked_by_mode"]) - set(gap["not_dispatched"])), \
        "blocked_by_mode must be a SUBSET of not_dispatched"
    # A known-INTRUSIVE engine is the concrete case a reader would be misled about.
    assert "run_upload_test" in gap["blocked_by_mode"]


def test_full_mode_blocks_nothing_which_is_the_positive_control():
    """Same producer, same shape, only the tier differs.

    Without this, a hardcoded non-empty list would satisfy the test above. `full` permits every
    tier, so the correct answer here is genuinely empty -- and that is what distinguishes a working
    classifier from one that always says "blocked".
    """
    led = _mission("mode3", "full")
    assert led["mode"] == "full"
    gap = reportmod.arsenal_gap(led)
    assert not gap["error"], gap["error"]
    assert gap["blocked_by_mode"] == [], \
        "mode=full permits every permission tier, so nothing can be tier-blocked"


def test_the_rendered_section_states_the_tier_bound():
    """The classification is only worth anything if it reaches the page the client reads."""
    led = _mission("mode4", "active")
    md = "\n".join(reportmod._arsenal_md(led))
    assert "unable to run at this permission tier" in md, \
        "the tier line never rendered, so the report still reads as if the planner declined them"


def test_a_ledger_without_a_mode_does_not_silently_claim_nothing_was_blocked():
    """The failure this whole file exists to pin, held open deliberately.

    An absent mode must not be reported as "0 engines were tier-blocked" -- that is a claim, and the
    data does not support it. arsenal_gap returns an empty list because it CANNOT tell, and
    `_arsenal_md` prints the tier line only when the list is non-empty, so an unknown tier prints
    nothing rather than an untrue zero. Asserting that here so a future change cannot turn silence
    into a false reassurance.
    """
    led = _mission("mode5", "active")
    led.pop("mode", None)   # default: this test's subject is arsenal_gap, not the producer
    gap = reportmod.arsenal_gap(led)
    assert gap["blocked_by_mode"] == []
    assert "unable to run at this permission tier" not in "\n".join(reportmod._arsenal_md(led))
