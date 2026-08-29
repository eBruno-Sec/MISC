"""Q-124 -- the FAILED banner asserted a cause it never measured.

MEASURED: a real failed report used `AI calls used: 0, execution strategy deterministic` --
there was no provider and no quota -- yet every FAILED run printed:

    "This assessment did not complete (commonly a provider quota/rate-limit or network error,
    not a target result)."

That sends the operator to check API billing instead of `run_zap`'s daemon error and
`run_wayback`'s 25 failed connections, both of which the Tool Ledger names correctly three
sections further down. Same disease as Q-114: stated with confidence, never measured.

GATE: a deterministic run's failure banner never mentions a provider quota.
Negative control: a run that genuinely used a provider (ai_calls > 0) still says so.
"""
import report


def test_a_deterministic_failed_run_never_blames_a_provider():
    note = report._status_note("failed", {"strategy": "deterministic", "ai_calls": 0})
    assert "provider" not in note.lower()
    assert "quota" not in note.lower()
    assert "FAILED" in note


def test_a_deterministic_failed_run_points_at_the_tool_ledger_instead():
    note = report._status_note("failed", {"strategy": "deterministic", "ai_calls": 0})
    assert "Tool Ledger" in note


def test_a_failed_run_with_no_execution_context_never_blames_a_provider():
    """Absence of `execution` means AI usage is unknown, not confirmed -- the banner must not
    guess a provider was involved just because it cannot rule one out."""
    assert "provider" not in report._status_note("failed", None).lower()
    assert "provider" not in report._status_note("failed", {}).lower()


def test_NEGATIVE_CONTROL_a_run_that_genuinely_used_a_provider_still_blames_it():
    """A run that made real provider calls and then failed keeps the original explanation --
    this must not become 'never mention a provider', only 'never mention one we never called'."""
    note = report._status_note("failed", {"strategy": "agentic", "ai_calls": 4})
    assert "provider" in note.lower()
    assert "quota" in note.lower()


def test_non_failed_statuses_are_unaffected():
    assert report._status_note("stopped", {"strategy": "deterministic", "ai_calls": 0}) \
        == report._status_note("stopped")
    assert report._status_note("running") == report._status_note("running", {"ai_calls": 0})


def test_the_deterministic_banner_reaches_the_markdown_renderer_end_to_end():
    md = report.generate_report("P", [], {"in_scope": ["x"]}, status="failed",
                                 execution={"strategy": "deterministic", "ai_calls": 0})
    assert "provider" not in md.lower()
    assert "Tool Ledger" in md


def test_the_deterministic_banner_reaches_the_html_renderer_end_to_end():
    html = report.generate_html_report("P", [], {"in_scope": ["x"]}, status="failed",
                                        execution={"strategy": "deterministic", "ai_calls": 0})
    assert "provider" not in html.lower()
