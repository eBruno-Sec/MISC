"""Q-069 - the ledger kept only the LAST error per tool, so an engine failing ten ways reported one.

`main._tool_ledger` aggregated errors with `a["error"] = str(...)[:140]`: last write wins, no count,
no histogram. A tool that failed 48 times rendered a single sentence, and a reader could not tell it
from one flaky request. This is the next rung of the Q-063/Q-067 ladder - that line of work exists so
a reader can tell "never tested" from "tested, found nothing", and "failed 48 times, two ways" from
"failed once" is the same distinction one level down.

THE FIXTURES ARE COPIED FROM REALITY. Every error string below was read out of the live mission DB
of the running deployment, over all 153 missions it holds:

    docker exec -i apolaki-agent-1 python - <<'PY'
    import db; from collections import Counter
    db.init('/app/data/bbh.db')
    for m in db.list_missions(limit=200):
        for r in db.get_logs(m["id"], limit=4000):
            ...  # bucket tool_error rows per tool
    PY

    missions: 153
    tool-rows carrying >=1 error : 65
      of those, >1 error  (COUNT lost)      : 48 = 74%
      of those, >1 distinct (HISTOGRAM lost): 16 = 25%
    worst single row: total=48 distinct=2

    worst row: 5102527f sweep-full-det-r3-deep | http_probe | total errors: 48 | distinct: 2
        31  [Errno -2] Name or service not known
        17  [Errno -5] No address associated with hostname

    57cc3b49 (the Q-067 mission)
      fetch_openapi          total=10  distinct=2   (5x SSL fault + 5x not-a-spec verdict)
      run_injection_probes   total=6   distinct=1   (6 identical SSL faults, row said one)

Two consequences of that measurement drive the shape of this file. First, `distinct == 1` is the
MAJORITY case (48 rows lose a count, only 16 lose a histogram), so the COUNT is the higher-value
half and is tested first. Second, the note is read by a human in a table cell that already carries a
verdict, a finding note and a scope-block count, so `test_the_digest_is_bounded_not_a_wall_of_text`
is a first-class assertion, not politeness: pasting 48 stack traces would trade one bad row for
another.

The Q-067 counters (`ok` / `scope_blocks` / `negatives`) live in the same aggregation.
`test_the_error_counters_do_not_swallow_a_scope_block_or_a_negative_verdict` is the standing guard
that this ticket did not reach into them.
"""
from __future__ import annotations

import os
import tempfile

import db as dbmod
import main as mainmod

# Verbatim from mission 5102527f (`sweep-full-det-r3-deep`), the worst row in the deployment.
_DNS_NXDOMAIN = "[Errno -2] Name or service not known"
_DNS_NO_ADDR = "[Errno -5] No address associated with hostname"
# Verbatim from mission 57cc3b49 (the Q-067 mission).
_SSL_FAULT = "[SSL: WRONG_VERSION_NUMBER] wrong version number (_ssl.c:1010)"
_TYPED_VERDICT = "NOT PRESENT: response is not JSON (no OpenAPI spec at this path)"


def _fresh(mid: str):
    dbmod.init(os.path.join(tempfile.mkdtemp(), "t.db"))
    dbmod.create_mission(mid, "P", "active", "o", {"in_scope": ["juice-shop:3000"]}, {})


def _ledger(mid: str):
    return {t["tool"]: t for t in mainmod._tool_ledger(mid)["tools"]}


def _dispatch(mid: str, tool: str, error: str, *, row_type: str = "tool_error", n: int = 1):
    for _ in range(n):
        dbmod.add_log(mid, "tool_call", {"tool": tool, "permission": "active"})
        dbmod.add_log(mid, row_type, {"tool": tool, "error": error})


# ── positive control ──────────────────────────────────────────────────────────────────
def test_positive_control_the_harness_rows_reach_the_producer():
    """Every count asserted below is worthless if these rows never reach `_tool_ledger`.
    A clean tool written through the same helper comes out executed, with no error annotation."""
    _fresh("div_pc")
    dbmod.add_log("div_pc", "tool_call", {"tool": "http_probe"})
    dbmod.add_log("div_pc", "tool_result", {"tool": "http_probe", "count": 12, "output": "links + params"})
    row = _ledger("div_pc")["http_probe"]
    assert row["status"] == "executed" and row["calls"] == 1 and row["findings"] == 12, row
    assert row["errors"] == 0 and row["error_kinds"] == [] and row["error_distinct"] == 0, row
    assert "errored" not in row["note"], row


# ── THE defect: the count ─────────────────────────────────────────────────────────────
def test_a_tool_that_failed_six_times_does_not_report_one_failure():
    """THE assertion, and the majority case: `run_injection_probes` in mission 57cc3b49 errored SIX
    times with the same SSL fault and its row rendered one message with no count.

    Before the fix the note is the bare sentence and nothing anywhere says 'six'."""
    _fresh("div1")
    _dispatch("div1", "run_injection_probes", _SSL_FAULT, n=6)
    row = _ledger("div1")["run_injection_probes"]
    assert row["status"] == "failed", row              # unchanged: it really is broken
    assert row["errors"] == 6, ("the ledger still keeps no error count, so six failed dispatches "
                                "read as one: %r" % (row,))
    assert "6" in row["note"], ("the reader of the table cell cannot tell 6 failures from 1: %r"
                                % (row,))
    assert "WRONG_VERSION_NUMBER" in row["note"], row  # the message itself is not lost either


def test_the_count_is_of_error_rows_not_of_calls():
    """Negative control on the counter: a tool that returned on eight calls and errored on two
    reports TWO errors, not ten. An over-counting ledger is not better than an under-counting one."""
    _fresh("div2")
    for _ in range(8):
        dbmod.add_log("div2", "tool_call", {"tool": "run_xss"})
        dbmod.add_log("div2", "tool_result", {"tool": "run_xss", "count": 0, "output": "0 XSS signal(s)"})
    _dispatch("div2", "run_xss", "timeout on /search", n=2)
    row = _ledger("div2")["run_xss"]
    assert row["calls"] == 10 and row["errors"] == 2, row
    assert row["status"] == "executed", row
    assert "2 calls errored" in row["note"], ("the mixed row still says '1+ call errored', which is "
                                              "true of 2 errors and of 48: %r" % (row,))


# ── THE defect: the histogram ─────────────────────────────────────────────────────────
def test_two_distinct_failure_modes_are_both_visible():
    """The worst row in the deployment: `http_probe` in mission 5102527f, 48 errors, two genuinely
    different DNS faults (`-2` is NXDOMAIN, `-5` is a name that resolves to no address). The row
    displayed exactly one of them, so half the failure surface was invisible."""
    _fresh("div3")
    _dispatch("div3", "http_probe", _DNS_NXDOMAIN, n=31)
    _dispatch("div3", "http_probe", _DNS_NO_ADDR, n=17)
    row = _ledger("div3")["http_probe"]
    assert row["status"] == "failed", row
    assert row["errors"] == 48 and row["error_distinct"] == 2, row
    assert "31" in row["note"] and "17" in row["note"], (
        "the per-message counts are gone: %r" % (row["note"],))
    assert "Name or service not known" in row["note"], row
    assert "No address associated with hostname" in row["note"], (
        "the second failure mode is still invisible - this is the whole ticket: %r" % (row["note"],))


def test_the_row_carries_a_machine_readable_histogram_ranked_by_count():
    """The note is prose for a human in a table cell; the JSON report export carries the ledger
    wholesale, so the histogram is also a structured field. Ranked by count, descending, so a
    consumer never has to re-sort and the top entry is the tool's dominant failure."""
    _fresh("div4")
    _dispatch("div4", "http_probe", _DNS_NO_ADDR, n=17)
    _dispatch("div4", "http_probe", _DNS_NXDOMAIN, n=31)
    row = _ledger("div4")["http_probe"]
    assert row["error_kinds"] == [[_DNS_NXDOMAIN, 31], [_DNS_NO_ADDR, 17]], row["error_kinds"]
    assert sum(n for _, n in row["error_kinds"]) == row["errors"] == 48, row


def test_the_most_common_error_leads_not_the_last_one_written():
    """The old row was the LAST error by log order, which is an artifact of dispatch order (the five
    http:// probes in 57cc3b49 simply ran after the five https:// ones). The digest leads with the
    DOMINANT failure instead - a property of the run, not of the ordering."""
    _fresh("div5")
    _dispatch("div5", "http_probe", _DNS_NXDOMAIN, n=9)
    _dispatch("div5", "http_probe", "connection reset by peer", n=1)   # last written, rare
    note = _ledger("div5")["http_probe"]["note"]
    assert note.index("Name or service not known") < note.index("connection reset by peer"), note


def test_the_distinct_count_is_not_an_artifact_of_the_display_budget():
    """Two errors that agree for 140 characters and diverge after are two faults, not one. Counting
    on a truncated key would have made the histogram a function of the column width."""
    _fresh("div6")
    base = "upstream refused the request after retries " + ("-" * 110)
    _dispatch("div6", "run_nuclei", base + " target=a.example", n=1)
    _dispatch("div6", "run_nuclei", base + " target=b.example", n=1)
    row = _ledger("div6")["run_nuclei"]
    assert row["errors"] == 2 and row["error_distinct"] == 2, row


# ── the DoD's other half: do not inflate the note ─────────────────────────────────────
def test_the_digest_is_bounded_not_a_wall_of_text():
    """A pentester reads this in one table cell that already carries a note and a scope-block count.
    Twelve distinct failures must summarise, not paste: the total, the distinct count, the top few
    with their counts, and an explicit remainder so nothing is silently dropped."""
    _fresh("div7")
    for i in range(12):
        _dispatch("div7", "run_nuclei", "template %02d failed: %s" % (i, "x" * 120), n=i + 1)
    row = _ledger("div7")["run_nuclei"]
    assert row["errors"] == 78 and row["error_distinct"] == 12, row
    assert len(row["note"]) <= 260, ("the note became a wall of text (%d chars): %r"
                                     % (len(row["note"]), row["note"]))
    assert "12 distinct" in row["note"], row
    assert "more" in row["note"], ("the kinds that did not fit are not accounted for, so the note "
                                   "under-reports the failure surface: %r" % (row["note"],))
    assert len(row["error_kinds"]) <= 5, ("the structured histogram is unbounded; a tool erroring "
                                          "with a unique message per call would bloat every "
                                          "report export: %r" % (row["error_kinds"],))


def test_a_single_error_reads_exactly_as_it_did_before():
    """NEGATIVE CONTROL on the prose. 65 rows in the deployment carry an error and 17 of them carry
    exactly one; those rows must not gain '1 call errored, 1 distinct' noise. The count only earns
    its place in the cell when there is more than one."""
    _fresh("div8")
    _dispatch("div8", "run_katana", "katana: exec format error", n=1)
    row = _ledger("div8")["run_katana"]
    assert row["status"] == "failed" and row["errors"] == 1, row
    assert row["note"] == "katana: exec format error", (
        "a single failure gained bookkeeping prose it does not need: %r" % (row["note"],))


# ── negative controls: Q-067 must survive untouched ───────────────────────────────────
def test_a_genuinely_broken_engine_still_reads_failed():
    """MANDATORY negative control, restated at this rung: adding counts must not turn a broken
    engine into an executed one. Ten transport faults, no verdict anywhere, still `failed`."""
    _fresh("div9")
    _dispatch("div9", "fetch_openapi", _SSL_FAULT, n=10)
    row = _ledger("div9")["fetch_openapi"]
    assert row["status"] == "failed", ("a broken engine must still read failed: %r" % (row,))
    assert "WRONG_VERSION_NUMBER" in row["note"] and row["errors"] == 10, row


def test_the_error_counters_do_not_swallow_a_scope_block_or_a_negative_verdict():
    """Q-067 landed `negatives` beside `ok`/`scope_blocks`/`error` in this same aggregation, and
    936f6bd landed `scope_blocks` before it. Neither is a fault, so neither may be counted as one -
    a scope block inflating the error count would re-create the exact mislabel those tickets fixed.
    """
    _fresh("div10")
    _dispatch("div10", "fetch_openapi", _SSL_FAULT, n=5)
    _dispatch("div10", "fetch_openapi", _TYPED_VERDICT, n=5)
    _dispatch("div10", "fetch_openapi", "SCOPE BLOCK: cdn.example.com not in scope",
              row_type="scope_block", n=3)
    row = _ledger("div10")["fetch_openapi"]
    assert row["errors"] == 5 and row["error_distinct"] == 1, (
        "the 5 typed verdicts and/or the 3 scope blocks were counted as faults: %r" % (row,))
    assert row["status"] == "executed", row            # Q-067 behaviour, unchanged
    assert "no OpenAPI spec at this path" in row["note"], row
    assert "5 calls errored" in row["note"], (
        "the real mission shape still says '1+ call errored' where it means five: %r" % (row["note"],))
    assert "3 off-scope target" in row["note"], row    # 936f6bd behaviour, unchanged


def test_an_executed_row_reports_the_DIVERSITY_without_pasting_engine_prose():
    """The other half of the note grammar. On an EXECUTED row the finding is the headline, so the
    cell gets the count and the distinct count and stops there - the full histogram is on the row
    for the JSON export. What it must never do again is say '1+ call errored' about 20 failures in
    two different failure modes."""
    _fresh("div12")
    dbmod.add_log("div12", "tool_call", {"tool": "http_probe"})
    dbmod.add_log("div12", "tool_result", {"tool": "http_probe", "count": 3, "output": "links + params"})
    _dispatch("div12", "http_probe", _DNS_NXDOMAIN, n=12)
    _dispatch("div12", "http_probe", _DNS_NO_ADDR, n=8)
    row = _ledger("div12")["http_probe"]
    assert row["status"] == "executed" and row["errors"] == 20, row
    assert "20 calls errored, 2 distinct" in row["note"], row
    assert "1+" not in row["note"], row
    assert row["error_kinds"] == [[_DNS_NXDOMAIN, 12], [_DNS_NO_ADDR, 8]], row["error_kinds"]
    assert "Errno" not in row["note"], ("the executed row pasted engine prose next to the finding "
                                        "note it exists to lead with: %r" % (row["note"],))


def test_the_counts_survive_into_the_row_of_a_tool_that_also_found_something():
    """A tool that confirmed on one target and failed on nine leads with the finding and still
    reports the nine - the ledger-vs-findings disagreement check downstream reads this row."""
    _fresh("div11")
    dbmod.add_log("div11", "tool_call", {"tool": "run_sqli"})
    dbmod.add_log("div11", "tool_result", {"tool": "run_sqli", "count": 1, "output": "SQLi confirmed on /rest/x"})
    _dispatch("div11", "run_sqli", "timeout on /rest/y", n=9)
    row = _ledger("div11")["run_sqli"]
    assert row["status"] == "executed" and row["findings"] == 1, row
    assert "SQLi confirmed" in row["note"], row
    assert "9 calls errored" in row["note"], row
    assert row["errors"] == 9, row
