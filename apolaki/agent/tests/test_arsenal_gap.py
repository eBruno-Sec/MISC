"""A report must say what the platform did NOT run (Q-050 / Q-051).

The tool ledger has always recorded what ran. Nothing recorded what did not, so discovering that
**32 of 92 engines had never executed across 151 missions** required a SQL query over the whole store
rather than a glance at any report. Among them was `run_cmdi` -- a complete command-injection engine
with its own oracle, unreachable in the default `active` mode because
`planner._ALLOWED["active"] = {PASSIVE, ACTIVE}` excludes INTRUSIVE and the only intrusive dispatch
path is the eight-entry `_SWEEP_HTTP_ENGINES` tuple.

The distinction this section exists to preserve: an engine that RAN AND FOUND NOTHING is a result; an
engine that was NEVER DISPATCHED is a gap; and an engine that COULD NOT run at the mission's
permission tier was never a candidate at all. Collapsing those three is how a scanner comes to look
thorough.
"""
import report


def _ledger(tools, mode="active", strategy="deterministic", **kw):
    # THE REAL LEDGER SHAPE: `strategy` is deterministic/low_ai/agentic, `mode` is passive/active/full.
    # An earlier version of this helper put the MODE string in the STRATEGY key -- an invented shape --
    # so the tier assertions passed while the product rendered nothing. Fixtures mirror reality here.
    return {"strategy": strategy, "mode": mode, "tools": tools, **kw}


def test_an_engine_that_ran_and_found_nothing_is_a_RESULT_not_a_gap():
    gap = report.arsenal_gap(_ledger([{"tool": "run_sqli", "calls": 12, "findings": 0},
                                      {"tool": "run_xss", "calls": 3, "findings": 1}]))
    assert "run_sqli" in gap["silent"], gap
    assert "run_xss" not in gap["silent"]
    assert "run_sqli" not in gap["not_dispatched"] and "run_xss" not in gap["not_dispatched"]


def test_engines_that_never_ran_are_named():
    gap = report.arsenal_gap(_ledger([{"tool": "run_sqli", "calls": 1, "findings": 0}]))
    assert gap["not_dispatched"], "the registry has more engines than one mission dispatches"
    assert "run_cmdi" in gap["not_dispatched"], gap["not_dispatched"][:10]


def test_tier_blocked_is_reported_SEPARATELY_from_not_selected():
    """THE distinction. run_cmdi is INTRUSIVE, so in `active` it was never a candidate -- reporting
    that as 'not selected' would send a reader looking for a selection bug that does not exist."""
    gap = report.arsenal_gap(_ledger([{"tool": "run_sqli", "calls": 1, "findings": 0}], "active"))
    assert "run_cmdi" in gap["blocked_by_mode"], gap["blocked_by_mode"][:10]
    # An ACTIVE engine is available in this mode, so it must NOT be excused as tier-blocked.
    assert "run_jwt" not in gap["blocked_by_mode"]
    assert "run_jwt" in gap["not_dispatched"]


def test_full_mode_blocks_nothing():
    """The negative control for the tier split: at `full` no engine can be excused by its tier, so
    anything missing is a genuine selection gap."""
    gap = report.arsenal_gap(_ledger([{"tool": "run_sqli", "calls": 1, "findings": 0}], "full"))
    assert gap["blocked_by_mode"] == [], gap["blocked_by_mode"][:10]
    assert "run_cmdi" in gap["not_dispatched"]


def test_a_broken_registry_says_so_instead_of_reporting_no_gaps():
    """An empty gap list from a failed import would read as 'every engine ran' -- the exact silent
    failure this section exists to expose. It must be recorded, and the section must say NOT
    ESTABLISHED rather than print a reassuring zero."""
    import builtins
    real = builtins.__import__

    def boom(name, *a, **k):
        if name == "tools":
            raise ImportError("simulated registry failure")
        return real(name, *a, **k)

    builtins.__import__ = boom
    try:
        gap = report.arsenal_gap(_ledger([{"tool": "run_sqli", "calls": 1, "findings": 0}]))
    finally:
        builtins.__import__ = real
    assert gap["error"] and "ImportError" in gap["error"], gap
    assert gap["not_dispatched"] == []
    md = "\n".join(report._arsenal_md(_ledger([{"tool": "run_sqli", "calls": 1, "findings": 0}])))
    assert md  # rendering still works on the healthy path


def test_no_ledger_prints_NOTHING_rather_than_a_reassuring_zero():
    """An absent ledger is not evidence that nothing was skipped."""
    assert report._arsenal_md({}) == []
    assert report._arsenal_md(None) == []


def test_the_section_reaches_the_rendered_report():
    """Registration is not invocation: the section must appear in the document a reader receives."""
    md = report.generate_report("P", [], {"in_scope": ["t"]},
                                tool_ledger=_ledger([{"tool": "run_sqli", "calls": 5, "findings": 0}]))
    assert "Arsenal coverage" in md
    assert "Never dispatched this mission" in md
    assert "run_cmdi" in md, "the tier-blocked engines must be named, not just counted"


# ── Q-051: per-finding attribution, and the two-record cross-check ───────────
def _finding(engine=None, title="SQLi"):
    f = {"title": title, "severity": "high", "family": "sqli", "confidence": "confirmed",
         "target": "http://x/?id=1"}
    if engine:
        f["engine"] = engine
    return f


def test_a_finding_names_the_engine_that_produced_it():
    md = report.generate_report("P", [_finding("run_sqli")], {"in_scope": ["x"]})
    assert "**Found by:** `run_sqli`" in md


def test_a_finding_with_no_engine_says_NOTHING_rather_than_unknown():
    """~1052 findings were stored before the binding existed. 'Found by: unknown' would be a claim
    about provenance this report cannot make; absence is the honest rendering."""
    md = report.generate_report("P", [_finding()], {"in_scope": ["x"]})
    assert "Found by" not in md


def test_an_engine_that_produced_a_finding_is_reported_as_productive():
    led = _ledger([{"tool": "run_sqli", "calls": 9, "findings": 1}])
    dis = report.ledger_finding_disagreement(led, [_finding("run_sqli")])
    assert dis["productive"] == ["run_sqli"]
    assert dis["produced_but_unlogged"] == []
    assert dis["counts"]["run_sqli"] == 1


def test_a_finding_from_an_ENGINE_THE_LEDGER_NEVER_RAN_is_flagged():
    """THE cross-check, and the reason the engine name is bound at construction rather than
    back-filled from the ledger: two records that share a source cannot disagree, so they can never
    catch each other. Here they can."""
    led = _ledger([{"tool": "run_sqli", "calls": 9, "findings": 1}])
    dis = report.ledger_finding_disagreement(led, [_finding("run_sqli"), _finding("run_ghost", "G")])
    assert dis["produced_but_unlogged"] == ["run_ghost"]
    md = "\n".join(report._arsenal_md(led, [_finding("run_ghost", "G")]))
    assert "Ledger disagreement" in md and "run_ghost" in md


def test_agreement_prints_no_warning():
    """The negative control: a consistent mission must not carry a scary banner. A check that fires
    on healthy input gets ignored, and an ignored check is not a check."""
    led = _ledger([{"tool": "run_sqli", "calls": 9, "findings": 1}])
    md = "\n".join(report._arsenal_md(led, [_finding("run_sqli")]))
    assert "Ledger disagreement" not in md


def test_findings_without_engines_do_not_manufacture_a_disagreement():
    """Legacy findings carry no engine. They must not be read as 'produced by an unlogged engine' --
    that would make every pre-binding mission report a false contradiction."""
    led = _ledger([{"tool": "run_sqli", "calls": 9, "findings": 1}])
    dis = report.ledger_finding_disagreement(led, [_finding(), _finding()])
    assert dis["produced_but_unlogged"] == [] and dis["productive"] == []


# ── both renderers, or it is an island ───────────────────────────────────────
_LEDGER = {"strategy": "deterministic", "mode": "active",
           "tools": [{"tool": "run_sqli", "calls": 400, "findings": 20},
                     {"tool": "run_xss", "calls": 55, "findings": 0}]}


def _both(findings):
    return (report.generate_report("P", findings, {"in_scope": ["x"]}, tool_ledger=_LEDGER),
            report.generate_html_report("P", findings, {"in_scope": ["x"]}, tool_ledger=_LEDGER))


def test_every_new_section_reaches_BOTH_renderers():
    """AN ISLAND THE COORDINATOR BUILT, caught by checking rather than assuming.

    Arsenal coverage, technique coverage and per-finding attribution were all wired into
    `generate_report` (markdown) and NONE of them appeared in `generate_html_report` -- the
    CLIENT-FACING artifact. A section whose entire purpose is "what the platform did NOT run" is worth
    most to the person reading the deliverable, and it was visible only in the format they do not get.

    Same registration-is-not-invocation defect this codebase has now found seven times, written by the
    person who has been filing the tickets about it. Pinned across BOTH renderers so a third output
    format cannot silently skip them either.
    """
    md, html = _both([_finding("run_sqli")])
    for section in ("Arsenal coverage", "Technique coverage", "Found by"):
        assert section in md, "%s missing from the MARKDOWN report" % section
        assert section in html, "%s missing from the HTML report" % section


def test_the_ledger_disagreement_warning_reaches_both():
    """The two findings must differ in FAMILY as well as engine.

    The first draft gave both `family: "sqli"` and the HTML renderer merged them, so the ghost
    disappeared and the warning did not render -- while `ledger_finding_disagreement()` still
    returned ['run_ghost'] when called directly. The code was right and the FIXTURE was wrong, which
    is the third fixture collision in this project to masquerade as a product defect (the sweep
    allocator's class names collapsing to one shape was the same shape of mistake). Check the helper
    before the code.
    """
    ghost = dict(_finding("run_ghost", "G"), family="open_redirect", target="http://y/?next=2")
    md, html = _both([_finding("run_sqli"), ghost])
    assert "Ledger disagreement" in md, "missing from the MARKDOWN report"
    assert "Ledger disagreement" in html, "missing from the HTML report"
    assert "run_ghost" in md and "run_ghost" in html


def test_a_consistent_mission_warns_in_NEITHER():
    """The negative control on both paths at once: a check that fires on healthy input is noise, and
    noise in the client-facing report is worse than noise in the markdown one."""
    md, html = _both([_finding("run_sqli")])
    assert "Ledger disagreement" not in md and "Ledger disagreement" not in html


def test_the_tier_line_RENDERS_on_a_real_ledger_shape():
    """THE TEST THAT WAS MISSING, and its absence hid a guard that had never once fired.

    `arsenal_gap` read `strategy` before `mode`. A real ledger carries `strategy: "deterministic"`
    (the AI axis: deterministic / low_ai / agentic) and `mode: "active"` (the permission axis), so
    `_ALLOWED.get("deterministic")` was None and the permission-tier split NEVER RENDERED in any real
    report. Every tier assertion in this file passed because the fixture put the MODE string in the
    STRATEGY key -- a ledger shape the product does not produce.

    Caught by a lane reading the code rather than the tests. Third fixture defect of mine this
    session; all three shared one cause: a fixture invented rather than copied from reality proves
    only that the code works on the invention.
    """
    real = {"strategy": "deterministic", "mode": "active",
            "tools": [{"tool": "run_sqli", "calls": 5, "findings": 0}]}
    gap = report.arsenal_gap(real)
    assert gap["blocked_by_mode"], (
        "the tier split is empty on a REAL ledger shape -- the guard is not firing")
    assert "run_cmdi" in gap["blocked_by_mode"]
    assert "Of those, unable to run at this permission tier" in "\n".join(report._arsenal_md(real))


def test_an_unrecognised_mode_yields_no_tier_claim_rather_than_a_wrong_one():
    """The negative control on the fallback: `strategy` is still read, but ONLY when it names a real
    mode. A ledger whose mode is missing or unknown must make NO tier claim -- silence is honest,
    while defaulting to a tier would excuse engines that were never excused."""
    unknown = {"strategy": "deterministic", "mode": "sideways",
               "tools": [{"tool": "run_sqli", "calls": 5, "findings": 0}]}
    assert report.arsenal_gap(unknown)["blocked_by_mode"] == []
    legacy = {"strategy": "active", "tools": [{"tool": "run_sqli", "calls": 5, "findings": 0}]}
    assert report.arsenal_gap(legacy)["blocked_by_mode"], (
        "an older single-key artifact whose strategy names a real mode must still resolve")
