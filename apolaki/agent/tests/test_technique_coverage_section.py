"""The report must state what the platform has TECHNIQUES for, and what it cannot say (Q-051).

`techniques.coverage_matrix()` was complete, correct and called by NOTHING -- it sat in the
qualified-dead-code list while the question it answers went unanswered in every report. Erwin's ask
was "does the report state what tools are being used for each check, and are all techniques used?"

The four numbers mean different things and are routinely conflated:

    total        techniques in the registry                        88
    proven       a liveness run produced the artifact              16
    claimed      a human typed a validated_on value                48
    generalized  >= 2 RESOLVABLE labs AND a liveness artifact       1

`claimed - proven` is the honesty debt. Before the derived lab vocabulary landed, two invented lab ids
conferred `generalized` and a fabricated claim scored 90/100; the number is now 1, and 1 is the true
one. A report that printed 48 as capability would be overstating the product by 3x.

THE LIMIT IS THE POINT. A technique record carries maps_to, validated_on and oracle -- and NO engine
binding. Nothing links a technique to the tools a mission dispatched, so this report cannot say which
techniques ran against THIS target. It says so, rather than printing registry totals in a position
where a reader would take them for engagement coverage.
"""
import report


def test_the_four_numbers_are_reported_separately():
    tc = report.technique_coverage()
    assert not tc["error"], tc["error"]
    assert tc["total"] >= 80, tc
    # The distinctions that matter: each is a different claim about the same registry.
    assert tc["proven"] < tc["claimed"], "collapsing proven into claimed hides the honesty debt"
    assert tc["unverified"] == tc["claimed"] - tc["proven"]
    assert tc["generalized"] <= tc["proven"], (
        "generalized requires a liveness artifact, so it cannot exceed proven")


def test_the_section_reports_the_debt_rather_than_the_flattering_number():
    md = "\n".join(report._technique_md())
    tc = report.technique_coverage()
    assert "Technique coverage" in md
    assert "Unverified claims (the honesty debt)" in md
    assert str(tc["claimed"] - tc["proven"]) in md
    assert "Proven" in md and "Claimed" in md, "both words must appear; they are not synonyms here"


def test_the_section_states_what_it_CANNOT_measure():
    """The limit, asserted. Registry totals printed without this caveat would be read as engagement
    coverage, which is the overclaim the whole section exists to avoid."""
    md = "\n".join(report._technique_md())
    assert "Not measured here" in md
    assert "no engine binding" in md


def test_a_broken_registry_says_NOT_ESTABLISHED_rather_than_zero():
    """An empty result from a failed import would render as 'this product has no techniques', which
    is worse than saying nothing. Same rule as the arsenal section."""
    import builtins
    real = builtins.__import__

    def boom(name, *a, **k):
        if name == "techniques":
            raise ImportError("simulated registry failure")
        return real(name, *a, **k)

    builtins.__import__ = boom
    try:
        tc = report.technique_coverage()
        md = "\n".join(report._technique_md())
    finally:
        builtins.__import__ = real
    assert tc["error"] and "ImportError" in tc["error"], tc
    assert "NOT ESTABLISHED" in md
    assert "0" not in md.split("NOT ESTABLISHED")[0], "must not print a count it could not read"


def test_the_section_reaches_the_rendered_report():
    """Registration is not invocation. coverage_matrix was correct and uncalled for months."""
    md = report.generate_report("P", [], {"in_scope": ["t"]},
                                tool_ledger={"strategy": "active",
                                             "tools": [{"tool": "run_sqli", "calls": 5, "findings": 0}]})
    assert "Technique coverage" in md
    assert "Not measured here" in md
