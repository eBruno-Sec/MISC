"""Every number in the Coverage Overview block must say which rule it follows.

Q-084 caught ONE number in this block that was a catalogue constant worded as a measurement
("WSTG active tests: 85/109"). It fixed that number's sentence. **The rest of the block was never
audited**, and auditing it -- by VARYING THE INPUT rather than by reading the code -- found two more:

    input span                       A: nothing ran     B: perfect clean  C: perfect + findings
    ------------------------------------------------------------------------------------------
    ASVS total                       34                 34                34     CONSTANT
    confirmed_safe                    0                 29                 0     evidence
    vulnerable                        0                  0                32     evidence
    inconclusive                      0                  2                 0     evidence
    not_tested                       31                  0                 0     evidence
    not_implemented                   1                  1                 0     evidence
    blocked                           2                  2                 2     CONSTANT
    WSTG tested/total/full/partial    85/109/60/25       same              same   CONSTANT

  1. `not_implemented` was NOT RENDERED AT ALL. The block stated a total of 34 and its five cells
     summed to 33 in A and B. `coverage_rollup` gives that bucket its own key with a comment saying
     Q-012's distinction must not be undone "one layer up" -- and the renderer, one layer further up,
     dropped it. It closed in C only because a finding had emptied the bucket, which is worse than
     never closing: a reader who checks the arithmetic once concludes it always closes.
  2. `blocked` is a CATALOGUE CONSTANT (AUTHN-05 and AUTHN-06 carry `violated_by=()`, so nothing can
     ever move it) rendered unlabelled among five evidence-driven cells -- Q-084's defect one row
     down. Worse, the sentence Q-084 ADDED said the WSTG number does not vary "unlike the figures
     above", which asserts that Blocked varies. It does not.

THE Q-084 FIX IS EXTENDED HERE, NEVER UNDONE: `tests/test_wstg_coverage_claim.py` still pins the 85,
the 109, and "this tool, not this mission", including its control that fails if the line is deleted.
"""
from __future__ import annotations

import re

import asvs_model as A
import report
import tools

_SCOPE = {"in_scope": ["http://x/"]}


def _reachable() -> set:
    """Every engine name a real dispatcher can reach — DERIVED, never hand-listed (Q-012)."""
    emitters = set(tools.TOOL_PERMISSIONS) | {t["name"] for t in tools.CLAUDE_TOOLS}
    return {n for n in emitters if hasattr(tools.ToolRegistry, "_" + n)}


def _keyed_families() -> list:
    """Every family some objective keys on — taken from the model, so it cannot go stale."""
    return sorted({f for o in A.OBJECTIVES for f in o["violated_by"]})


def _finding(fam: str, i: int = 0) -> dict:
    """Shaped like a stored row: a fixture that omits `family` maps to ZERO objectives while looking
    green, which is how this module's violation path once went completely unexercised."""
    return {"id": "f%d" % i, "family": fam, "title": "t", "severity": "low",
            "confidence": "confirmed", "target": "http://x/"}


#: The three inputs that span what a mission can be. Anything that varies across these is evidence
#: driven; anything identical across all three cannot be a measurement of this mission.
def _cases():
    ran = _reachable()
    return {
        "A nothing ran": ([], {}),
        "B perfect clean": ([], {n: {} for n in ran}),
        "C perfect + findings": ([_finding(f, i) for i, f in enumerate(_keyed_families())],
                                 {n: {} for n in ran}),
    }


def _block(html: str) -> str:
    m = re.search(r"<h2 id='coverage-overview'>.*?(?=<h2|\Z)", html, re.S)
    return m.group(0) if m else ""


def _cells(block: str) -> dict:
    return {lbl: int(v) for v, lbl in
            re.findall(r"<div class='cov'><span[^>]*>(\d+)</span><label>([^<]+)</label></div>", block)}


def _stated_total(block: str):
    m = re.search(r"models \((\d+) ASVS objectives", block)
    return int(m.group(1)) if m else None


# ── the apparatus, guarded first: a vacuous span proves nothing ───────────────────────────────
def test_the_input_span_is_real():
    ran = _reachable()
    assert len(ran) > 50, len(ran)
    assert len(_keyed_families()) > 20
    tallies = [report.coverage_rollup(fs, led)["properties"] for fs, led in _cases().values()]
    assert len({tuple(sorted(t.items())) for t in tallies}) == 3, \
        "the three cases produce identical rollups, so nothing below can discriminate"


# ── defect 1: the arithmetic did not close ────────────────────────────────────────────────────
def test_the_cells_sum_to_the_total_the_block_states_in_every_case():
    """FAILS BEFORE THE FIX in cases A and B: stated 34, cells summed to 33.

    Asserted across the whole span deliberately. Case C closed on its own before the fix, so a test
    written against one input would have passed while the block was wrong on the other two.
    """
    for label, (fs, led) in _cases().items():
        block = _block(report.generate_html_report("cov", fs, _SCOPE, tool_ledger=led))
        assert block, "the Coverage Overview block vanished (%s)" % label
        cells, total = _cells(block), _stated_total(block)
        assert total == len(A.OBJECTIVES), (label, total)
        assert sum(cells.values()) == total, \
            "%s: cells %s sum to %d, block states %d" % (label, cells, sum(cells.values()), total)


def test_the_bucket_q012_created_is_actually_shown():
    """`not_implemented` must be a CELL, not only a key in the rollup dict.

    The rollup asserts this distinction one layer down and the renderer discarded it -- producer
    landed, consumer never did. A test on the dict passes for free; only the artifact settles it.
    """
    block = _block(report.generate_html_report("cov", [], _SCOPE, tool_ledger={}))
    cells = _cells(block)
    assert "No engine" in cells, cells
    assert cells["No engine"] == report.coverage_rollup([], {})["properties"]["not_implemented"]
    assert cells["No engine"] >= 1, "non-vacuity: the product has at least one absent capability"
    # and it is NOT folded into Not tested, which is the whole point of the bucket
    assert "Not tested" in cells and cells["Not tested"] != cells["Not tested"] + cells["No engine"]


def test_the_markdown_report_projects_the_same_six_buckets():
    """One projection, two renderers. The markdown table dropped the same bucket the HTML did.

    Driven with findings present because `generate_report` early-returns a short "no confirmed
    vulnerabilities were recorded" note when the ledger is empty — the markdown ASVS table renders
    only on a report that HAS findings, which is asserted from the other side below.
    """
    ran = _reachable()
    fs = [_finding(f, i) for i, f in enumerate(_keyed_families())]
    md = report.generate_report("cov", fs, _SCOPE, tool_ledger={n: {} for n in ran})
    rows = dict(re.findall(r"^\| ([A-Z][^|]*?) \| (\d+) \| (?:evidence|catalogue constant) \|",
                           md, re.M))
    assert set(rows) == {"Verified (engine ran clean)", "Failed (finding violates)",
                         "Attempted (inconclusive by nature)",
                         "No engine (Apolaki cannot test this)",
                         "Blocked (safety-excluded by design)", "Not tested"}, sorted(rows)
    assert sum(int(v) for v in rows.values()) == len(A.OBJECTIVES), rows
    assert "| **Total objectives modelled** | **%d** |" % len(A.OBJECTIVES) in md
    # the rule is stated per row, and BOTH rules appear -- a table that labelled everything the same
    # way would satisfy a membership check while telling the reader nothing
    assert "| evidence |" in md and "| catalogue constant |" in md


# ── defect 2: a constant standing unlabelled among measurements ───────────────────────────────
def test_blocked_really_is_a_constant_so_the_page_is_right_to_say_so():
    """The claim the page now makes, asserted rather than assumed.

    If someone gives AUTHN-05/06 a `violated_by` family, this number starts varying and the legend
    becomes false — this test fails and forces the wording to be revisited in the same change, which
    is the coupling Q-084 was missing the first time.
    """
    vals = {report.coverage_rollup(fs, led)["properties"]["blocked"] for fs, led in _cases().values()}
    assert len(vals) == 1, "blocked now varies with the mission: %s -- update the legend" % vals
    for o in A.OBJECTIVES:
        if o.get("blocked_reason"):
            assert not o["violated_by"], \
                "%s is 'blocked' yet a finding could fail it, so the number can move" % o["cid"]


def test_the_page_states_the_rule_each_number_follows():
    """A number and its epistemics must travel together, which is the whole of Q-084 generalised."""
    block = _block(report.generate_html_report("cov", [], _SCOPE, tool_ledger={}))
    low = block.lower()
    assert "evidence-driven" in low, "the legend does not name the evidence-driven cells"
    assert "no run and no finding can change that number" in low, \
        "the constant cell is not named as a constant"
    assert "size of the model" in low, "the denominator is not named as a denominator"
    for lbl in ("Confirmed safe", "Vulnerable", "Inconclusive", "No engine", "Not tested"):
        assert lbl in block


def test_the_q084_sentence_is_extended_and_not_undone():
    """The pinned half of Q-084 survives verbatim; only its false comparison is repaired.

    It used to read "unlike the figures above it does not vary with what ran" — which asserts that
    every figure above varies. `Blocked` does not.
    """
    block = _block(report.generate_html_report("cov", [], _SCOPE, tool_ledger={}))
    m = re.search(r"WSTG catalogue:[^<]*", block)
    assert m, "the WSTG line was deleted rather than corrected"
    line = m.group(0)
    assert "109" in line and "85" in line                      # Q-084's positive control
    assert "this tool, not this mission" in line               # Q-084's wording
    assert "unlike the figures above" not in line, \
        "the line still claims every cell above varies with the mission; Blocked does not"
    assert "neither does the Blocked cell" in line


# ── the negative control whose absence let Q-084 survive ──────────────────────────────────────
def test_an_empty_mission_claims_no_work_was_done():
    """Nothing ran and nothing was found: no cell may assert activity, in either renderer."""
    html = report.generate_html_report("empty", [], _SCOPE, tool_ledger={})
    cells = _cells(_block(html))
    assert cells["Confirmed safe"] == 0 and cells["Vulnerable"] == 0 and cells["Inconclusive"] == 0
    assert cells["Not tested"] >= 1
    assert "WSTG active tests" not in html                     # Q-084, still dead

    md = report.generate_report("empty", [], _SCOPE, tool_ledger={})
    assert "No confirmed vulnerabilities were recorded" in md
    assert "Failed objectives" not in md
    assert "ASVS Objective Coverage" not in md, \
        "an empty markdown report now renders an objective tally; it must not imply work was done"

    # POSITIVE CONTROL in the opposite direction, so the three assertions above cannot be satisfied
    # by a renderer that has simply stopped emitting the section: with one real finding it appears.
    md2 = report.generate_report("one", [_finding("sqli")], _SCOPE, tool_ledger={"run_sqli": {}})
    assert "ASVS Objective Coverage" in md2 and "Failed objectives" in md2
