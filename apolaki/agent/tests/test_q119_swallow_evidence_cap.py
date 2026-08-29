"""Q-119 -- `_swallow`'s 160-char cap ate the evidence of 5 sites, 3 of them entirely.

MEASURED by AST census over every `_swallow` call whose message is built from string literals:

    ./agent.py:3567   literal_len=258  (cap was 160)
    ./agent.py:3870   literal_len=257  (cap was 160)
    ./agent.py:1619   literal_len=175  (cap was 160)
    ./agent.py:3578   literal_len=149  (cap was 160)   <- the Q-109 reporter itself
    ./agent.py:3837   literal_len=136  (cap was 160)

Every one of these is a swallow that explains ITSELF in prose and then appends the runtime evidence
("First: <the actual offending keys/URLs>") -- and the old cap ate the half that is evidence. Three
exceeded 160 outright, so their runtime detail was discarded completely; the other two kept only the
first offender, truncated mid-word.

FIX: `ToolRegistry._swallow` (tools.py) now caps the exception text at 500 chars, not 160 -- covers
every measured site (max 258) with headroom. The record COUNT stays the actual defence against an
unbounded ledger (tests/test_swallow_ledger.py::test_ledger_is_bounded... already covers that; the
250-char case below is the NEGATIVE control that proves this fix did not simply remove the bound).
"""
from __future__ import annotations

import scope
import tools


def _reg():
    sc = scope.ScopeEngine()
    sc.load_manual(["target.tld"], [], "T")
    return tools.ToolRegistry(sc, mission_id=None, lab_mode=True)


def test_a_250_char_explanation_survives_intact():
    """GATE: a swallow whose explanation is 250 characters still records its exception text."""
    prose = ("%d graph endpoint node(s) name a session-destroying action and were NOT promoted to "
              "the planner's probe surface (Q-080: probing them with the mission session logs the "
              "scan out). First: %s" % (3, "https://target.tld/logout, https://target.tld/signout"))
    assert len(prose) > 160, "fixture must reproduce the real >160 shape, got %d" % len(prose)
    reg = _reg()
    try:
        raise ValueError(prose)
    except Exception as e:
        reg._swallow(e, "graph_primary_state.session_kill_quarantine", "https://target.tld/logout")
    rec = reg.swallowed[0]
    assert prose in rec["error"], rec["error"]
    # the evidence tail specifically, not just "more of the prose than before"
    assert "https://target.tld/logout, https://target.tld/signout" in rec["error"], rec["error"]


def test_the_exact_agent_py_quarantine_message_keeps_all_three_offenders():
    """Reproduces the real Q-080 call shape byte-for-byte (agent.py's session_kill_quarantine
    swallow): three URLs named in the 'First: ...' tail, none of them a dictionary-order accident."""
    quarantined = ["https://target.tld/a/logout", "https://target.tld/b/signout",
                   "https://target.tld/c/session/end"]
    msg = ("%d graph endpoint node(s) name a session-destroying action and were NOT promoted to "
           "the planner's probe surface (Q-080: probing them with the mission session logs the scan "
           "out and every later authenticated probe then silently tests as anonymous). First: %s"
           % (len(quarantined), ", ".join(quarantined[:3])))
    reg = _reg()
    try:
        raise ValueError(msg)
    except Exception as e:
        reg._swallow(e, "graph_primary_state.session_kill_quarantine", quarantined[0])
    rec = reg.swallowed[0]
    for q in quarantined:
        assert q in rec["error"], "%s missing from %r" % (q, rec["error"])


def test_negative_control_a_pathological_message_is_still_bounded():
    """The cap was added to stop an unbounded ledger row -- raising it must not mean removing it."""
    reg = _reg()
    try:
        raise RuntimeError("x" * 10000)
    except Exception as e:
        reg._swallow(e, "engine.loop", "https://target.tld/y")
    rec = reg.swallowed[0]
    assert len(rec["error"]) < 600, "the cap was raised, not removed: got %d chars" % len(rec["error"])
    assert len(rec["error"]) > 250, "still generous enough to cover every measured real site"
