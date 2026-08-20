"""Q-084. The client report said "WSTG active tests: 85/109" and that number is a CONSTANT.

MEASURED before the fix, at `report.py:2501`, rendered into the client HTML under a heading called
Coverage Overview:

    WSTG active tests: 85/109 covered (60 full, 25 partial), 5 safety-excluded.

"Active tests" asserts activity. The number is a property of a static catalogue and has nothing to do
with the mission that produced the report:

    coverage()          tally: {'full': 60, 'partial': 25, 'none': 24, 'excluded': 5}
    coverage([])        tally: {'full': 60, 'partial': 25, 'none': 24, 'excluded': 5}
    coverage(['xss'])   tally: {'full': 60, 'partial': 25, 'none': 24, 'excluded': 5}

Two defects were stacked, and the second is why fixing only the first would not have worked:

  1. `report.py:343` called `wstg_catalog.coverage()` with no argument, so no evidence reached it.
  2. `coverage(techniques=None)` ACCEPTED an evidence parameter and never referenced it, so passing
     the ledger would have changed nothing. Its docstring claimed the parameter "only enriches the
     `by` label"; it did not do that either.

WHY THE FIX IS THE SENTENCE AND NOT AN EVIDENCE-DRIVEN TALLY. The obvious repair -- make the number
count what actually ran -- is not derivable from this data. `FULL` and `PARTIAL` map a WSTG id to
PROSE, and the prose is not a machine-readable engine reference:

    WSTG-APIT-01   'fetch_openapi + recon'
    WSTG-ATHZ-02   'authz matrix + run_bfla'
    WSTG-BUSL-01   'business-logic graph reasons about it; no generic confirm'

Some name engines, some name concepts, some name no engine at all. Pulling engine names out of that
with a regex is exactly the "no regex on records" mistake this project has already paid for. So the
catalogue is what it always was -- a statement about the TOOL, not about the mission -- and the fix
is to make the sentence say that. Restructuring the catalogue into machine-readable engine references
is a separate, larger job; until someone does it, an evidence-driven WSTG tally cannot be computed
honestly and this report must not imply one.

The ASVS half six lines away in the same function IS evidence-driven
(`asvs_model.assess(findings, attempted_engines=_engines_from_ledger(tool_ledger))`), which is what
made this a defect rather than a design choice: two numbers with opposite epistemics rendered in one
visual group, with nothing telling the reader which is which.
"""
from __future__ import annotations

import os
import re
import tempfile

import db as dbmod
import main as mainmod
import report as reportmod
import wstg_catalog as wc

_MID = [0]


def _real_ledger(engines):
    """Build the ledger with the REAL producer, never by hand.

    The first draft of this file invented `{"tools": {"run_sqli": {"count": 3}}}` and the renderer
    raised `'str' object has no attribute 'get'` -- `tools` is a LIST of dicts carrying
    tool/status/calls/findings, not a mapping. Four defects in this project have come from invented
    fixtures, and the ledger-mode tests already learned this lesson the expensive way: every earlier
    fixture supplied `mode` by hand, which is exactly why nothing caught Q-051.
    """
    _MID[0] += 1
    mid = "wstgclaim%d" % _MID[0]
    dbmod.init(os.path.join(tempfile.mkdtemp(), "t.db"))
    dbmod.create_mission(mid, "P", "full", "o", {"in_scope": ["juice-shop:3000"]}, {})
    for tool, count, note in engines:
        dbmod.add_log(mid, "tool_call", {"tool": tool})
        dbmod.add_log(mid, "tool_result", {"tool": tool, "count": count, "output": note})
    return mainmod._tool_ledger(mid)


# COPIED FROM REALITY. The field shape is taken verbatim from a stored finding in the corpus
# (mission DB, 1773 findings): title/severity/target/cwe/family/tags. The first draft of this fixture
# omitted `family`, and that mattered -- `asvs_model.map_findings` maps 1773 real findings onto 11
# violated objectives and maps this same dict WITHOUT `family` onto ZERO. The test still passed,
# because engine attribution alone moved the ASVS tally, so a weaker fixture would have left the
# violation path completely unexercised while looking green.
_RICH_FINDINGS = [{"title": "SQL injection (error-based) in 'q'", "severity": "high",
                   "target": "http://juice-shop:3000/rest/products/search?q",
                   "cwe": "CWE-89", "family": "sqli", "tags": ["sqli", "error-based"],
                   "evidence": "SQLite error triggered by \"')\""}]
_RICH_ENGINES = [("run_sqli", 1, "injectable"), ("run_xss", 0, "no reflection")]


def _render(findings, ledger):
    """Render the real client HTML through the real renderer. No fixture stands in for it: the whole
    defect was a sentence in the output, and only the output can carry a sentence."""
    return reportmod.generate_html_report(
        program="P", findings=findings, scope={"in_scope": ["juice-shop:3000"]},
        tool_ledger=ledger, mode="active")


# --------------------------------------------------------------------------- the claim itself

def test_an_empty_mission_does_not_claim_85_tests_were_active():
    """THE FAILING TEST. Zero engines ran; the report must not say tests were active.

    Before the fix this rendered "WSTG active tests: 85/109 covered", from a ledger with nothing in
    it. That is the same family as Q-082's 716 fabricated curl reproductions: the report asserting
    work that was never done.
    """
    html = _render([], {})
    assert "WSTG active tests" not in html, (
        "the report claims WSTG tests were ACTIVE on a mission where no engine ran; the number is a "
        "catalogue property and cannot support the word")


def test_the_wstg_sentence_says_it_describes_the_tool_not_the_mission():
    """Removing the word is not enough -- a reader still needs to know what the number IS.

    A bare "WSTG: 85/109" beside evidence-driven ASVS cells is still misleading by placement, so the
    line has to name its own epistemics.
    """
    html = _render([], {})
    line = _wstg_line(html)
    assert line, "the WSTG coverage line vanished entirely; it is useful and should not be deleted"
    low = line.lower()
    assert ("this tool" in low or "not this mission" in low or "engines for" in low), (
        "the WSTG line does not tell the reader it describes Apolaki's catalogue rather than this "
        "mission, and it sits next to ASVS cells that DO describe the mission: %r" % line)


def _wstg_line(html: str) -> str:
    m = re.search(r"<div class='sub'[^>]*>([^<]*WSTG[^<]*)</div>", html)
    return m.group(1) if m else ""


# --------------------------------------------------------------------------- non-vacuity controls

def test_the_number_itself_is_still_reported_because_it_is_useful():
    """POSITIVE CONTROL. The fix must not be "delete the line".

    85 of 109 is a real, competitor-relevant capability statement. If this assertion ever fails
    because the line was removed rather than corrected, the defect was traded for a worse one:
    silence about coverage.
    """
    html = _render([], {})
    line = _wstg_line(html)
    assert "109" in line and "85" in line, (
        "the coverage MODEL number is gone; the fix was supposed to correct the claim, not remove "
        "the information: %r" % line)


def test_a_rich_mission_and_an_empty_one_render_the_same_wstg_number():
    """The proof that the number is a catalogue property, asserted so nobody re-reads it as a result.

    This is deliberately the OPPOSITE of what you would want from an evidence-driven figure. It is
    correct here only because the sentence now says the number describes the tool. If someone later
    makes this tally mission-sensitive, this test fails and forces them to revisit the wording in the
    same change -- which is the coupling that was missing the first time.
    """
    empty = _wstg_line(_render([], {}))
    rich = _wstg_line(_render(_RICH_FINDINGS, _real_ledger(_RICH_ENGINES)))
    assert empty == rich, (
        "the WSTG line now varies with the mission; if that is intended, the wording must stop "
        "saying it describes the tool.\n  empty: %r\n  rich:  %r" % (empty, rich))


# --------------------------------------------------------------------------- the dead parameter

def test_coverage_does_not_advertise_an_evidence_path_it_does_not_have():
    """Defect 2. A parameter that cannot change the output is an island inside a signature.

    Either `coverage` takes evidence and USES it, or it does not take evidence. What it must not do
    is accept a `techniques` list, ignore it, and leave a signature implying the caller can make the
    number honest by passing one -- which is precisely what invited `report.py:343` to look correct.
    """
    import inspect
    params = [p for p in inspect.signature(wc.coverage).parameters]
    if params:
        # It kept a parameter, so that parameter must demonstrably matter.
        a = wc.coverage()["tally"]
        b = wc.coverage([])["tally"]
        c = wc.coverage(["xss"])["tally"]
        assert not (a == b == c), (
            "coverage() still accepts %r and every value produces an identical tally, so the "
            "parameter is decoration: %r" % (params, a))
    else:
        assert wc.coverage()["tally"]["full"] == 60, "sanity: the catalogue still parses"


def test_the_catalogue_totals_are_unchanged_by_this_fix():
    """NEGATIVE CONTROL on scope. Q-084 is about a SENTENCE. If these move, the fix went too far and
    started editing the coverage model, which is a different ticket with a different bar."""
    t = wc.coverage()["tally"]
    assert t == {"full": 60, "partial": 25, "none": 24, "excluded": 5}, t
    assert wc.coverage()["total_tests"] == 109


# --------------------------------------------------------------------------- the sibling

def test_the_asvs_half_is_still_evidence_driven():
    """The ASVS cells were always correct. This pins that the Q-084 fix did not "fix" them into
    constants by accident -- the two numbers sit in one visual group and it would be easy to
    accidentally unify them in the wrong direction."""
    empty = reportmod.coverage_rollup([], {})["properties"]
    rich = reportmod.coverage_rollup(_RICH_FINDINGS, _real_ledger(_RICH_ENGINES))["properties"]
    assert empty != rich, (
        "ASVS properties are identical for an empty and a vulnerable mission, so the evidence-driven "
        "half stopped reading evidence: %r" % (empty,))
    # BOTH evidence paths, asserted separately, because they can fail independently and the first
    # draft of this test only exercised one of them without saying so.
    assert rich["not_tested"] < empty["not_tested"], (
        "the ENGINE path stopped counting: engines ran and nothing moved out of not_tested")
    assert rich["vulnerable"] > empty["vulnerable"], (
        "the FINDING path stopped counting: a CWE-89 finding shaped like the stored corpus produced "
        "no violated objective. asvs_model.map_findings maps the real 1773-finding corpus onto 11 "
        "objectives, so a zero here is the mapping breaking, not the fixture being thin")
