"""Q-103 — the integrity checker reported a WIRING GAP as a clean bill of health.

From the operator's 2026-08-27 Shopify run. The Report Integrity block said:

    ✓ Consistent — 5 of 10 automated consistency checks applied and passed
    Not applicable to this report: ... ledger-note-contradiction (the report carries no tool
    ledger rows to cross-check)

The report printed a full tool ledger two sections above that sentence.

The markdown renderer called `check_report_consistency(findings, leads, risk, counts)` with four
arguments, so `tool_ledger` and `chains` arrived as `None`. `applicable()` treated `None` and "empty"
as the same answer and rendered both as "not applicable to this report", so a plumbing mistake was
laundered into reassurance. The HTML renderer had always passed six arguments; only the markdown one,
which is what an operator actually reads, was unchecked.

REASSURANCE IS THE ONE OUTPUT A VERIFIER MUST NEVER INVENT. A checker that cannot tell ABSENT from
NOT-SUPPLIED will report every future wiring bug as a pass, and this project has now shipped that
same shape in a guard, an engine, a parser and a report.
"""
import report
import report_integrity as ri


LEDGER = {"tools": [{"tool": "run_sqli", "status": "executed", "calls": 3, "findings": 2,
                     "note": "no SQLi confirmed on this endpoint"}]}
CLEAN_LEDGER = {"tools": [{"tool": "run_sqli", "status": "executed", "calls": 3, "findings": 2,
                           "note": "2 injectable parameter(s)"}]}

# generate_report has a SEPARATE short path for a mission with no confirmed findings, and that path
# renders no Report Integrity section at all. These tests must exercise the real report, so they
# carry one finding -- otherwise they would assert against a document the operator never sees.
FINDING = {"id": "x1", "title": "t", "severity": "low", "target": "https://example.test/",
           "description": "d", "engine": "transport_posture", "family": "security_misconfig"}


def _skipped(res):
    return {s["check"]: s["reason"] for s in res.get("checks_skipped", [])}


# ── absent and not-supplied are different answers ─────────────────────────────

def test_not_supplied_is_reported_as_a_wiring_gap_not_as_not_applicable():
    """The defect itself. A caller that omits the argument must be told so, in words that cannot be
    mistaken for 'this report has none'."""
    res = ri.check_report_consistency([], [], None, None)
    reason = _skipped(res).get("ledger-note-contradiction", "")
    assert "NOT SUPPLIED" in reason, reason
    assert "clean result" in reason, reason


def test_a_genuinely_empty_ledger_still_reads_as_not_applicable():
    """The non-vacuity control. If everything became a 'wiring gap' the message would be noise, and a
    report that truly has no ledger is a legitimate not-applicable."""
    res = ri.check_report_consistency([], [], None, None, tool_ledger={"tools": []})
    reason = _skipped(res).get("ledger-note-contradiction", "")
    assert "NOT SUPPLIED" not in reason, reason
    assert "no tool ledger rows" in reason, reason


# ── the check itself still works when it is actually given something ──────────

def test_the_contradiction_is_caught_when_the_ledger_is_passed():
    res = ri.check_report_consistency([], [], None, None, tool_ledger=LEDGER)
    ids = [i["check"] for i in res["issues"]]
    assert "ledger-note-contradiction" in ids, res["issues"]
    assert res["ok"] is False


def test_a_consistent_ledger_produces_no_issue():
    """Both halves. Without this, 'flag everything' would satisfy the test above."""
    res = ri.check_report_consistency([], [], None, None, tool_ledger=CLEAN_LEDGER)
    assert [i for i in res["issues"] if i["check"] == "ledger-note-contradiction"] == []


# ── the renderer must actually hand it over ───────────────────────────────────

def test_the_markdown_renderer_passes_the_ledger():
    """The end-to-end regression. The check being correct is worthless if the report never feeds it,
    which was the entire bug: a working check, wired to nothing, reporting success."""
    md = report.generate_report("p", [FINDING], {"in_scope": ["example.test"]}, tool_ledger=LEDGER)
    assert "ledger-note-contradiction" in md
    assert "the report carries no tool ledger rows" not in md


def test_the_markdown_renderer_does_not_claim_a_ledger_it_was_never_given():
    """With no ledger supplied at all, the report must say the renderer did not evaluate it rather
    than asserting the report has none."""
    md = report.generate_report("p", [FINDING], {"in_scope": ["example.test"]})
    assert "the report carries no tool ledger rows to cross-check" not in md
