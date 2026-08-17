"""Q-067 - a NEGATIVE RESULT is not a tool FAILURE, and a FAILURE is still a failure.

`main._tool_ledger` marked a row `failed` whenever an error string was present with no successful
call. An engine that reached its target and concluded "the thing is not here" arrives on exactly
that path, so a correct negative verdict was reported as a broken engine. Q-063 has just made
`errored` a first-class class in the report's Arsenal-coverage summary precisely because a broken
engine is an invisible false negative; filling that class with correct verdicts is how an alarm
stops being read.

Same argument, and the same fix shape, as `936f6bd` (a SCOPE BLOCK is correct enforcement, not a
tool failure): the producer splits on a TYPED TOKEN the engine emits, and tracks the class apart
from real errors. `ok` / `scope_blocks` / `error` gain a fourth sibling, `negatives`.

THE FIXTURES ARE COPIED FROM REALITY. Every URL and every error string below was read out of the
live mission DB for `57cc3b49` (the mode=active / strategy=deterministic Juice Shop run behind
`tool_ledger_57cc3b49.json`), like this:

    docker exec -i apolaki-agent-1 python - <<'PY'
    import db; db.init()
    rows = db.get_logs('57cc3b49', limit=4000)
    fo = [r for r in rows if r.get("tool") == "fetch_openapi"]
    PY

    fetch_openapi rows: 20      Counter({'tool_call': 10, 'tool_error': 10})
    error histogram:
       5  [SSL: WRONG_VERSION_NUMBER] wrong version number (_ssl.c:1010)
       5  Response is not valid JSON (not an OpenAPI spec)

That histogram is why this file does NOT simply assert "fetch_openapi is executed". The ticket said
the engine established a negative on 10 of 10 paths; the DB says 5. The five `https://` dispatches
spoke TLS at a plaintext port and NEVER REACHED THE TARGET - they are genuine faults. The honest row
is a mixed one that shows the verdict AND keeps the five faults visible, and
`test_the_real_fetch_openapi_shape_shows_the_verdict_AND_keeps_the_faults_visible` pins exactly that.

WHY A TOKEN AND NOT A RULE OVER THE ERROR TEXT. Measured, by driving the real engine against the
real lab: the verdict and the fault are byte-identical in every `ToolResult` field except the prose
of `error` (both `success=False`, `output=''`, `findings=[]`), and the persisted row carries only
`{type, tool, error, ts}`. So a producer-only classifier would have to read English - the shape this
project measured at 5 false positives in 6 and rejected as Q-056 rule C.
`test_the_producer_does_not_classify_by_reading_the_error_prose` is the standing guard against
anyone "fixing" this ticket that way later.
"""
from __future__ import annotations

import os
import tempfile

import db as dbmod
import main as mainmod

# Verbatim from mission 57cc3b49 (see module docstring).
_SSL_FAULT = "[SSL: WRONG_VERSION_NUMBER] wrong version number (_ssl.c:1010)"
_UNTYPED_VERDICT = "Response is not valid JSON (not an OpenAPI spec)"
_TYPED_VERDICT = "NOT PRESENT: response is not JSON (no OpenAPI spec at this path)"
_SPEC_PATHS = ["/openapi.json", "/swagger.json", "/v3/api-docs", "/api-docs",
               "/swagger/v1/swagger.json"]


def _fresh(mid: str):
    dbmod.init(os.path.join(tempfile.mkdtemp(), "t.db"))
    dbmod.create_mission(mid, "P", "active", "o", {"in_scope": ["juice-shop:3000"]}, {})


def _ledger(mid: str):
    return {t["tool"]: t for t in mainmod._tool_ledger(mid)["tools"]}


def _dispatch(mid: str, tool: str, url: str, *, row_type: str, error: str):
    dbmod.add_log(mid, "tool_call", {"tool": tool, "input": {"url": url}, "permission": "active"})
    dbmod.add_log(mid, row_type, {"tool": tool, "error": error})


# ── positive control: the apparatus is looking at something the producer really reads ──
def test_positive_control_the_harness_produces_rows_the_producer_aggregates():
    """Every zero and every status below is worthless if these rows never reach `_tool_ledger`.
    A clean tool written through the same helper must come out `executed` with its call counted."""
    _fresh("neg_pc")
    dbmod.add_log("neg_pc", "tool_call", {"tool": "fetch_openapi",
                                          "input": {"url": "http://juice-shop:3000/api-docs"}})
    dbmod.add_log("neg_pc", "tool_result", {"tool": "fetch_openapi", "count": 12,
                                            "output": "12 endpoints imported"})
    row = _ledger("neg_pc")["fetch_openapi"]
    assert row["status"] == "executed" and row["calls"] == 1 and row["findings"] == 12, row


# ── THE defect ────────────────────────────────────────────────────────────────────────
def test_a_typed_negative_result_is_executed_not_failed():
    """THE assertion. Five paths probed, five answers of 'no spec here', nothing broken.

    Before the fix this row reads `failed`, and `report.arsenal_gap` files a working engine under
    `errored` - the class that means 'this was never actually tested, go fix the engine'."""
    _fresh("neg1")
    for p in _SPEC_PATHS:
        _dispatch("neg1", "fetch_openapi", "http://juice-shop:3000" + p,
                  row_type="tool_error", error=_TYPED_VERDICT)
    row = _ledger("neg1")["fetch_openapi"]
    assert row["status"] == "executed", (
        "an engine that reached its target and concluded NOT PRESENT is reported as a broken "
        "engine; that is the false-negative alarm class filling with noise: %r" % (row,))
    assert row["calls"] == 5 and row["findings"] == 0, row
    # the operator still gets the verdict, and the token itself is not shouted at them
    assert "no OpenAPI spec at this path" in row["note"], row
    assert "NOT PRESENT:" not in row["note"], row


def test_the_row_type_alone_is_enough_when_the_error_text_carries_no_token():
    """The producer accepts EITHER signal, exactly as the scope-block split does
    (`typ == "scope_block" or "SCOPE BLOCK" in err`). A dispatch logger that types the row is
    authoritative even if the engine's own text is untyped, so a half-applied engine patch cannot
    silently produce the pre-fix behaviour."""
    _fresh("neg2")
    _dispatch("neg2", "fetch_openapi", "http://juice-shop:3000/api-docs",
              row_type="tool_negative", error="no OpenAPI spec at this path")
    row = _ledger("neg2")["fetch_openapi"]
    assert row["status"] == "executed", row
    assert row["calls"] == 1, row


def test_the_real_fetch_openapi_shape_shows_the_verdict_AND_keeps_the_faults_visible():
    """The REAL mission shape: 10 dispatches = 5 https:// transport faults + 5 http:// verdicts.

    The row must not read `failed` (5 calls reached a conclusion) and must not read clean either
    (5 calls never reached the target). Burying the faults would be a strictly worse bug than the
    one this ticket is about."""
    _fresh("neg3")
    for scheme, err in (("https", _SSL_FAULT), ("http", _TYPED_VERDICT)):
        for p in _SPEC_PATHS:
            _dispatch("neg3", "fetch_openapi", "%s://juice-shop:3000%s" % (scheme, p),
                      row_type="tool_error", error=err)
    row = _ledger("neg3")["fetch_openapi"]
    assert row["status"] == "executed", row
    assert row["calls"] == 10 and row["findings"] == 0, row
    assert "no OpenAPI spec at this path" in row["note"], ("the verdict vanished: %r" % (row,))
    assert "errored" in row["note"], (
        "five dispatches never reached the target and the row does not say so: %r" % (row,))


# ── negative controls: the fix must not turn every failure into a pass ────────────────
def test_a_genuinely_broken_engine_still_reads_failed():
    """MANDATORY negative control. The same ten dispatches, all of them real transport faults and
    no verdict anywhere. Making this row `executed` would be strictly worse than Q-067 itself."""
    _fresh("neg4")
    for scheme in ("https", "http"):
        for p in _SPEC_PATHS:
            _dispatch("neg4", "fetch_openapi", "%s://juice-shop:3000%s" % (scheme, p),
                      row_type="tool_error", error=_SSL_FAULT)
    row = _ledger("neg4")["fetch_openapi"]
    assert row["status"] == "failed", ("a broken engine must still read failed: %r" % (row,))
    assert "WRONG_VERSION_NUMBER" in row["note"], row


def test_the_producer_does_not_classify_by_reading_the_error_prose():
    """THE ANTI-REGEX GUARD, and the mutation control for the whole file.

    These are the CURRENT, untyped words the engine emits - the very sentence quoted in the
    ticket. Untyped, they must STILL read `failed`, because the producer cannot tell them from a
    crash and must not guess. This is what makes `test_a_typed_negative_result_is_executed_not_failed`
    a test of the token rather than a test of the word 'JSON': the two differ only by the prefix.

    If someone later 'fixes' Q-067 with a phrase list, this test fails and tells them why."""
    _fresh("neg5")
    for p in _SPEC_PATHS:
        _dispatch("neg5", "fetch_openapi", "http://juice-shop:3000" + p,
                  row_type="tool_error", error=_UNTYPED_VERDICT)
    row = _ledger("neg5")["fetch_openapi"]
    assert row["status"] == "failed", (
        "the producer classified a negative result from its English, not from a typed signal; "
        "Q-056 rule C was that shape and measured 5 false positives in 6: %r" % (row,))
    # the token is the contract; pin its exact value so a rename cannot silently desync from the
    # engine-side literal (agent/tools.py) that the other half of this fix emits.
    assert mainmod.NEGATIVE_RESULT_TOKEN == "NOT PRESENT:"
    assert _TYPED_VERDICT == mainmod.NEGATIVE_RESULT_TOKEN + _TYPED_VERDICT.split(":", 1)[1]


def test_a_mid_string_mention_of_the_token_does_not_qualify():
    """The token is a PREFIX by contract, unlike the looser `"SCOPE BLOCK" in err` test it is
    modelled on. An engine that merely quotes the phrase inside a crash message has not made a
    verdict, and the strict form is what keeps this from decaying into substring matching."""
    _fresh("neg6")
    _dispatch("neg6", "fetch_openapi", "http://juice-shop:3000/api-docs", row_type="tool_error",
              error="crashed while formatting a NOT PRESENT: verdict")
    assert _ledger("neg6")["fetch_openapi"]["status"] == "failed"


def test_a_negative_result_does_not_swallow_a_scope_block():
    """The two correct-outcome classes compose: a tool that concluded NOT PRESENT on its in-scope
    targets and skipped an off-scope one reports both, and neither is a failure."""
    _fresh("neg7")
    _dispatch("neg7", "fetch_openapi", "http://juice-shop:3000/api-docs",
              row_type="tool_error", error=_TYPED_VERDICT)
    _dispatch("neg7", "fetch_openapi", "https://cdn.example.com/api-docs",
              row_type="scope_block", error="SCOPE BLOCK: cdn.example.com not in scope")
    row = _ledger("neg7")["fetch_openapi"]
    assert row["status"] == "executed", row
    assert "no OpenAPI spec at this path" in row["note"], row
    assert "off-scope target" in row["note"], row


def test_a_tool_whose_only_outcome_is_a_scope_block_is_still_skipped_not_executed():
    """Regression guard on `936f6bd`: `negatives` joins `ok` as evidence the engine RAN, so the
    'every target was out of scope -> skipped' branch must not start reading `executed` because a
    counter it does not own changed shape."""
    _fresh("neg8")
    _dispatch("neg8", "run_transport_posture", "https://cdn.example.com/",
              row_type="scope_block", error="SCOPE BLOCK: cdn.example.com not in scope")
    assert _ledger("neg8")["run_transport_posture"]["status"] == "skipped"


def test_a_verdict_does_not_erase_the_note_of_a_call_that_found_something():
    """A tool that confirmed on one target and concluded NOT PRESENT on another must lead with the
    finding, and still account for the negative rather than dropping it."""
    _fresh("neg9")
    dbmod.add_log("neg9", "tool_call", {"tool": "run_graphql", "input": {"url": "http://juice-shop:3000/graphql"}})
    dbmod.add_log("neg9", "tool_result", {"tool": "run_graphql", "count": 2,
                                          "output": "introspection enabled"})
    _dispatch("neg9", "run_graphql", "http://juice-shop:3000/api/graphql",
              row_type="tool_error", error="NOT PRESENT: no GraphQL endpoint at this path")
    row = _ledger("neg9")["run_graphql"]
    assert row["status"] == "executed" and row["findings"] == 2, row
    assert "introspection enabled" in row["note"], row
    assert "concluded not present" in row["note"], row
