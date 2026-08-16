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


def _ledger(tools, strategy="active", **kw):
    return {"strategy": strategy, "tools": tools, **kw}


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
