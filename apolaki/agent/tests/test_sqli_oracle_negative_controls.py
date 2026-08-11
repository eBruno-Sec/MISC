"""The sqli oracles must confirm on INJECTION, never on an application's own noise.

MEASURED (docs/handoff/breaker.md, TARGET 1). The first honest whole-product benchmark scored
22 TP / 1 FP. The single false positive was `BenchmarkTest00494` -- a CLEAN `cmdi` case on which
`boolean-blind` reported CWE-89 in a POST field (`productID`) the application never reads.

Root cause, reproduced live against `https://owaspbench:8443/benchmark/cmdi-00/BenchmarkTest00494`:
the page shells out to `ping moresafe` and the resolver's failure text is NOT deterministic. Eight
byte-identical POSTs returned two distinct bodies -- "No address associated with hostname" and
"Name or service not known" -- whose mutual similarity is 0.9091, i.e. BELOW the oracle's 0.95
divergence threshold. `analyze_boolean` compares three single samples and never establishes that
the baseline reproduces, so the application's own noise satisfies "TRUE tracks the baseline, FALSE
diverges".

The distinguishing property, measured over all six boolean-blind confirmations in that run:

    BenchmarkTest00033/00428/00429/00433/00438  baseline self-similarity 1.0000  fired 3/3 replays
    BenchmarkTest00494 (the false positive)     baseline self-similarity 0.9091  fired 0/3 replays

Baseline stability separates the five true positives from the one false positive perfectly and
costs the true positives nothing.

These tests are negative controls for the shapes an attacker-minded reviewer would throw at these
oracles. The ones that pass today pin properties the oracles genuinely have, so a loosened
threshold or a dropped leg of a differential fails here. The instability case is marked xfail
because the defect is still live; fixing it turns the xfail into a failure, which is the signal to
delete the marker.
"""
import pytest

import sqli_tool as sqli

# ── the two REAL bodies BenchmarkTest00494 returns for byte-identical requests ──
_PAGE = ('<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" '
         '"http://www.w3.org/TR/html4/loose.dtd">\n<html>\n<head>\n'
         '<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">\n</head>\n<body>\n<p>\n'
         'Here is the standard output of the command:<br><br>'
         'Here is the std err of the command (if any):<br>ping&#x3a; moresafe&#x3a; %s<br>')
NOISE_A = _PAGE % "No address associated with hostname"
NOISE_B = _PAGE % "Name or service not known"


def test_the_two_recorded_bodies_really_do_straddle_the_threshold():
    """Pins the measurement the rest of the file rests on: same request, two bodies, 0.9091."""
    assert NOISE_A != NOISE_B
    assert sqli.similar(NOISE_A, NOISE_B) == pytest.approx(0.9091, abs=1e-3)
    assert sqli.similar(NOISE_A, NOISE_B) < 0.95, "below the oracle's divergence threshold"


@pytest.mark.xfail(strict=True, reason="LIVE DEFECT: analyze_boolean has no baseline-stability "
                                       "control, so an unstable page confirms blind SQLi. "
                                       "Remove this marker when the oracle re-samples the baseline.")
def test_an_unstable_page_must_not_confirm_blind_sqli():
    """BenchmarkTest00494 exactly: the app ignores the field, and the only thing that 'diverged'
    was which resolver error the container happened to return."""
    assert not sqli.analyze_boolean(NOISE_A, NOISE_A, NOISE_B)


# ── negative controls the oracles DO survive; these must keep passing ──────────
def test_a_parameter_that_merely_echoes_cannot_confirm_blind_sqli():
    """The pathtraver failure shape does not transfer. TRUE and FALSE differ by one character, so
    on any page long enough for TRUE to track the baseline they are far too similar to diverge.

    Both page sizes matter. On a SHORT page the baseline leg fails; on a LONG page (>=133 bytes,
    where the 14-character payload is under 5% of the body) the baseline leg passes and only the
    divergence leg holds the line -- that is the case a loosened oracle would confirm on.
    """
    short = "<html><body>You searched for: %s</body></html>"
    long_ = "<html><body>" + ("filler " * 60) + "You searched for: %s</body></html>"
    for page in (short, long_):
        for orig in ("1", "bar", "abc123"):
            for pair in sqli.boolean_payloads(orig):
                base = page % orig
                assert not sqli.analyze_boolean(base, page % pair["true"], page % pair["false"]), \
                    (len(base), pair)


def test_identical_responses_never_confirm_blind_sqli():
    same = "<html>nothing varies here</html>"
    assert not sqli.analyze_boolean(same, same, same)


def test_a_page_that_errors_on_every_input_is_not_error_recovery():
    """A generic error page has no RECOVERY leg: doubling the quote does not repair anything."""
    assert not sqli.quote_break_recovers(500, 500, 500)
    assert not sqli.quote_break_recovers(200, 500, 500)


def test_a_500_unrelated_to_the_payload_is_not_error_recovery():
    """The baseline already 5xx: the quote did not break anything, so there is nothing to recover."""
    assert not sqli.quote_break_recovers(503, 503, 200)
    assert not sqli.quote_break_recovers(500, 500, 200)


def test_a_404_or_a_400_is_not_a_break():
    """Only a SERVER error counts as the query breaking; a rejected request is the app saying no."""
    for bad in (400, 401, 403, 404, 422):
        assert not sqli.quote_break_recovers(200, bad, 200), bad


def test_error_recovery_needs_both_legs():
    assert sqli.quote_break_recovers(200, 500, 200), "the real signal must still confirm"
    assert not sqli.quote_break_recovers(200, 200, 200), "no break"
    assert not sqli.quote_break_recovers(200, 500, 500), "no recovery"


def test_an_endpoint_that_is_slow_for_everything_cannot_confirm_time_blind():
    """The control carries the same latency as the payload, so the DIFFERENCE is what is measured."""
    for latency in (5.0, 9.0, 30.0):
        assert not sqli.analyze_time(latency, latency, 5)
        assert not sqli.analyze_time(latency, latency + 0.4, 5)
    assert sqli.analyze_time(0.2, 5.1, 5), "a real injected sleep must still confirm"


def test_error_text_already_in_the_baseline_is_not_evidence():
    """A page that always displays a DBMS error did not produce one because we asked it to."""
    body = "You have an error in your SQL syntax; check the manual"
    assert sqli.error_signatures("clean page", body), "control: it is a real signature"
    assert not sqli.error_signatures(body, body)


def test_structural_oracle_needs_a_differential_not_just_an_error():
    """A context that errors on ANY invalid value gives the same result for both probes."""
    err = "You have an error in your SQL syntax"
    confirmed, _ = sqli.structural_confirmed("clean", err, err)
    assert not confirmed, "valid subquery errored too -- no differential"
    confirmed, hits = sqli.structural_confirmed("clean", "clean", err)
    assert confirmed and hits, "control: the real differential must still confirm"
