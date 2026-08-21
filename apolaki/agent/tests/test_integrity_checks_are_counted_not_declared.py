"""The Report Integrity section gave a clean VERDICT on a report containing nothing.

`check_report_consistency` incremented its counter unconditionally at ten sites, including the four
its own comments describe as running "only when such a counter is actually present". So the number
was a property of `report_integrity.py`, not of the report. MEASURED by varying the input across its
whole span, exactly as the WSTG constant was found:

    nothing at all                  checks_run 10
    findings only, no counters      checks_run 10
    every optional counter present  checks_run 10

and the client page said, on `findings=[] leads=[] risk=None counts=None attack_surface=None
tool_ledger=None chains=None`:

    ✓ Consistent — 10 automated consistency checks passed; no metric or status contradictions.

Two claims, both false: the count, and the green tick. `ok` is True whenever no ERROR exists, which
an empty report satisfies for free — so the badge asserted a clean verdict over data that does not
exist. **This is the negative control the brief names** ("a report rendered from an EMPTY ledger must
not claim work was done") failing in the one section whose entire purpose is a truth guarantee. Same
family as Q-084's "WSTG active tests: 85/109", one section down and worse, because "passed" claims an
OUTCOME rather than a capability.

Nothing about WHAT is checked, what counts as an error, or `ok` changed. Only the counter's meaning,
the wording, and the badge's third state.
"""
from __future__ import annotations

import re

import report
import report_integrity as ri

_SCOPE = {"in_scope": ["http://x/"]}
_FIND = [{"title": "SQLi in q", "severity": "high", "confidence": "confirmed", "family": "sqli",
          "target": "http://x/?q=1", "cwe": "CWE-89"}]
_LEAD = [{"title": "eval sink", "severity": "high", "confidence": "candidate"}]


def _integrity_preamble(html: str) -> str:
    """The rendered sentence that states how many checks applied, or "" when it is absent."""
    m = re.search(r"<p class=.sub.>An automated cross-check[^<]*</p>", html)
    return m.group(0) if m else ""


def _rich():
    return ri.check_report_consistency(
        _FIND, _LEAD, risk={"score": 25, "label": "high", "note": "formula"}, counts={"high": 1},
        attack_surface={"known_cves": 2, "technologies_count": 3},
        tool_ledger={"confirmed_exploits": 1,
                     "tools": [{"tool": "run_sqli", "findings": 1, "note": "injectable"}]},
        chains=[{"name": "c1"}])


# ── the number is a measurement now, asserted across the span rather than at one point ────────
def test_the_count_varies_with_the_report_and_is_not_the_size_of_the_checklist():
    empty = ri.check_report_consistency([], [])
    thin = ri.check_report_consistency(_FIND, _LEAD)
    rich = _rich()
    assert empty["checks_run"] == 0, empty
    assert 0 < thin["checks_run"] < rich["checks_run"], (thin["checks_run"], rich["checks_run"])
    # the denominator is the constant, and it is still reported -- a bare numerator would trade an
    # overclaim for a mystery
    assert empty["checks_total"] == thin["checks_total"] == rich["checks_total"]
    assert rich["checks_run"] == rich["checks_total"], "a fully-populated report skips nothing"


def test_every_skipped_check_is_named_with_a_reason():
    """Nothing is quietly dropped: the smaller numerator has to be accountable."""
    r = ri.check_report_consistency([], [])
    assert len(r["checks_skipped"]) == r["checks_total"]
    for s in r["checks_skipped"]:
        assert s["check"] and s["reason"], s
    assert _rich()["checks_skipped"] == []


# ── the verdict itself: a clean tick over nothing ─────────────────────────────────────────────
def test_an_empty_report_does_not_report_a_clean_verdict():
    """THE FAILING TEST. Before the fix this read "10 automated consistency checks passed"."""
    line = ri.summary_line(ri.check_report_consistency([], []))
    assert "checks passed" not in line and "checks applied and passed" not in line, line
    assert "NO consistency check was applicable" in line
    assert "nothing here has been verified against anything" in line


def test_the_badge_has_a_third_state_and_it_is_not_green():
    """`ok` is True for an empty report, so the badge could never have told the difference.

    CORRECTED BY MEASUREMENT. The first draft asserted the GREY state on
    `generate_html_report("empty", [], _SCOPE)` and failed, and the production code was right:

        check_report_consistency([], [])                 checks_run=0   <- grey, correctly
        ...the HTML path never calls it that way. It SYNTHESISES `counts` and `rk` from the
        report itself, so an "empty" report really does run two checks:
        + counts only                                    checks_run=1  skipped=9
        + risk only                                      checks_run=1  skipped=9
        + both  (what generate_html_report passes)        checks_run=2  skipped=8

    Two checks genuinely ran and genuinely passed, so a green badge over them is TRUE and forcing
    it grey would be a new overclaim in the opposite direction. The guarantee this test exists to
    hold is narrower than the draft assumed: **a green tick must never stand over ZERO applied
    checks** -- and that is asserted at the level where zero is reachable.
    """
    zero = ri.check_report_consistency([], [])
    assert zero["checks_run"] == 0 and zero["ok"], \
        "the zero-applied case must still be reachable, or the grey state is unreachable code"

    empty = report.generate_html_report("empty", [], _SCOPE)
    # It states a number SMALLER than the checklist, which was the defect. Asserted as a PROPERTY,
    # not as a literal: my first attempt hardcoded 2, from enumerating the arguments the HTML path
    # passes -- and it passes a third I had not found, so the real answer is 3 of 10. Pinning the
    # digit would re-create this file's own defect one level up: a number that is a property of the
    # renderer's plumbing rather than of the report, brittle to a change that is not a regression.
    pre = _integrity_preamble(empty)
    m = re.search(r"(\d+) of (\d+) checks had data", pre)
    assert m, "the empty report does not state how many checks had data: %r" % pre
    applied, total = int(m.group(1)), int(m.group(2))
    assert 0 < applied < total, \
        "an empty report claims %d of %d checks -- the whole checklist over almost no data" % (applied, total)
    assert "Not applicable to this report" in empty, \
        "8 checks were skipped and none of them is named; a smaller numerator with no reasons trades " \
        "an overclaim for a mystery"

    # POSITIVE CONTROL, the other direction: a report that DID get cross-checked still says so, or
    # the fix has merely deleted the guarantee.
    rich_html = report.generate_html_report("rich", _FIND, _SCOPE, leads=_LEAD,
                                            attack_surface={"known_cves": 2, "technologies_count": 3},
                                            tool_ledger={"tools": [{"tool": "run_sqli", "findings": 1,
                                                                    "note": "injectable"}]})
    # The renderer HTML-ESCAPES the tick, so the literal "2713 Consistent" never appears in the
    # output -- measured: the page carries "&#10003; Consistent". Asserting the unescaped form was
    # the last thing wrong with this test, and it would have failed forever against correct code.
    assert "Consistent" in rich_html and "Nothing to cross-check" not in rich_html


def test_the_rendered_count_describes_this_report_and_says_so():
    html = report.generate_html_report("rich", _FIND, _SCOPE, leads=_LEAD)
    m = re.search(r"<p class='sub'>An automated cross-check[^<]*</p>", html)
    assert m, "the integrity preamble vanished"
    txt = m.group(0)
    assert "checks run." not in txt, "the old unconditional phrasing is back"
    assert "had data to examine in this report" in txt
    assert "not the size of the checklist" in txt


def test_the_two_renderers_state_the_same_applied_count():
    """One projection, two renderers — the rule Q-022's oracle 3 established for this file too."""
    for fs, leads in (([], []), (_FIND, _LEAD)):
        expect = ri.check_report_consistency(fs, leads, report.risk_score(fs),
                                             report._confirmed_counts(fs) if fs else {})
        md = report.generate_report("p", fs, _SCOPE, leads=leads)
        if not fs:
            assert "Report Integrity" not in md or ri.summary_line(expect) in md
        else:
            assert ri.summary_line(expect) in md, "the markdown states a different verdict"


# ── the checks themselves are UNCHANGED: this was a counter fix, not a detector fix ────────────
def test_no_contradiction_stopped_being_caught():
    """NEGATIVE CONTROL ON SCOPE. Gating the COUNTER must not gate the CHECK — the failure mode of
    this change is a check that silently stops running because its input test is wrong."""
    cve_f = [{"title": "angular@1.7.7 (CVE-2023-26117)", "severity": "high", "confidence": "confirmed",
              "cve": "CVE-2023-26117", "family": "vulnerable_component"}]
    r = ri.check_report_consistency(cve_f, [], {"score": 25, "label": "High", "note": "f"}, {"high": 1},
                                    attack_surface={"known_cves": 0, "technologies_count": 0},
                                    tool_ledger={"confirmed_exploits": 0})
    caught = {i["check"] for i in r["issues"]}
    for expect in ("cve-count-mismatch", "technology-count-mismatch",
                   "confirmed-exploit-counter-mismatch"):
        assert expect in caught, "the counter gate silenced %s" % expect
    assert r["ok"] is False

    lead_conflict = ri.check_report_consistency(_FIND, [{"title": "XSS", "confidence": "confirmed"}],
                                                {"score": 25, "label": "high"}, {"high": 1})
    assert not lead_conflict["ok"]
    assert any(i["check"] == "confirmed-status-conflict" for i in lead_conflict["issues"])

    inflated = ri.check_report_consistency(_FIND, _LEAD, {"score": 97, "label": "critical"}, {"high": 1})
    checks = {i["check"] for i in inflated["issues"]}
    assert "risk-score-source" in checks and "risk-label-exceeds-evidence" in checks

    chain = ri.check_report_consistency([], [], chains=[{"name": "c", "cvss_vector": "AV:N/AC:L"}])
    assert any(i["check"] == "chain-level-cvss" for i in chain["issues"])
    assert chain["checks_run"] == 1, "the chain check ran, so exactly one check was applicable"


def test_ok_is_byte_for_byte_the_same_predicate():
    """`ok` must still be 'no ERROR exists' — a caller may block export on it."""
    for r in (ri.check_report_consistency([], []), ri.check_report_consistency(_FIND, _LEAD), _rich()):
        assert r["ok"] == (not any(i["level"] == "error" for i in r["issues"]))
