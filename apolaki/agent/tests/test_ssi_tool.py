

# ── the false negative Codex batch 2 #9 named ────────────────────────────────
def test_numeric_timefmt_server_is_now_confirmed():
    """REGRESSION. The oracle required a month ABBREVIATION, which only appears under the DEFAULT
    timefmt. A server configured with a numeric format executed the directive and still failed
    confirmation — a false negative caused by assuming a server setting we had no reason to assume.
    We now DECLARE the format via #config timefmt and require exactly that shape back."""
    import ssi_tool as s
    tok = "abc123"
    m = s.marker(tok)
    # server honoured #config: it emits our prefix+token with year and day-of-year, no month name
    body = "<html>x" + m + "APO-abc123-2026-221" + m + "y</html>"
    v = s.evaluate(body, tok)
    assert v["confirmed"] is True
    assert "EXECUTED" in v["oracle"]


def test_default_timefmt_still_confirms_via_the_fallback():
    """Declaring a format must only ADD confirmations. A server that ignores #config but honours #echo
    still renders the default format and must keep working."""
    import ssi_tool as s
    tok = "def456"
    m = s.marker(tok)
    body = m + "Saturday, 09-Aug-2026 17:42:01 GMT" + m
    assert s.evaluate(body, tok)["confirmed"] is True


def test_the_raw_format_string_coming_back_is_reflection_not_execution():
    """THE negative control for the new path. If %Y-%j returns verbatim the server echoed our payload
    without expanding it — the opposite of a finding, and the easiest way to fake one."""
    import ssi_tool as s
    tok = "ghi789"
    m = s.marker(tok)
    assert s.evaluate(m + "APO-ghi789-%Y-%j" + m, tok)["confirmed"] is False


def test_a_plausible_but_wrong_token_cannot_confirm():
    """The token is what makes the expansion unforgeable — another request's marker must not satisfy it."""
    import ssi_tool as s
    tok = "jkl012"
    m = s.marker(tok)
    assert s.evaluate(m + "APO-DIFFERENTTOKEN-2026-221" + m, tok)["confirmed"] is False


def test_an_impossible_day_of_year_is_rejected():
    """Shape alone is not proof: day-of-year must be a real one, or a coincidental number pattern
    could satisfy the regex."""
    import ssi_tool as s
    tok = "mno345"
    m = s.marker(tok)
    assert s.evaluate(m + "APO-mno345-2026-999" + m, tok)["confirmed"] is False


def test_the_payload_sets_the_format_before_echoing_it():
    """Order matters: #config must precede #echo or the server expands the OLD format."""
    import ssi_tool as s
    p = s.payload("pqr678")
    assert p.index("#config timefmt") < p.index("#echo"), p
    assert "#exec" not in p, "never construct a command-executing directive"
