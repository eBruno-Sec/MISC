# Q-069 - the ledger keeps only the LAST error per tool

Lane: ledger-diversity (Builder). Owns `agent/main.py`, new tests under `agent/tests/`, this file.
Does NOT own `agent/tools.py`, `agent/agent.py`, `agent/report.py` - patches for those are written
out here, not applied.

Every row below is MEASURED (command + real output) or UNVERIFIED. Nothing is marked done ahead of
its evidence.

---

## STATUS

| slice | what | state |
| --- | --- | --- |
| 1 | measure how much the last-write-wins collapse actually loses, across the whole live DB | **MEASURED** (section 1) |
| 2 | failing test, then the mechanism in `main._tool_ledger` | **MEASURED** (sections 2-3) |
| 3 | full suite + mutation | pending |
| 4 | anti-idle: audit the rest of `_tool_ledger` for other many-to-one collapses | pending |

---

## 1. How much is lost - MEASURED over every mission in the live DB

The ticket cites one row in one mission. Before changing anything, the same question was asked of
all 153 missions the deployment holds, counting per (mission, tool) how many error rows exist and
how many DISTINCT messages they carry. The producer keeps exactly one of them, so
`total > 1` means a COUNT was lost and `distinct > 1` means a HISTOGRAM was lost.

```
$ docker exec -i apolaki-agent-1 python - < scratchpad/agg.py
missions: 153
tool-rows carrying >=1 error : 65
  of those, >1 error  (COUNT lost)    : 48 = 74%
  of those, >1 distinct (HISTOGRAM lost): 16 = 25%
worst single row: total=48 distinct=2
```

So this is not a one-mission curiosity: **74% of all tool rows that ever carried an error showed a
count of "1"** to the reader, and a quarter of them silently dropped an entirely different failure
mode.

### The worst row in the deployment

```
$ docker exec -i apolaki-agent-1 python - < scratchpad/worst.py
worst row: 5102527f sweep-full-det-r3-deep | http_probe | total errors: 48 | distinct: 2
    31  [Errno -2] Name or service not known
    17  [Errno -5] No address associated with hostname
```

48 failed dispatches rendered as one sentence. A reader of that report cannot tell this from a
single flaky request, and the two messages are not the same fault (`-2` is NXDOMAIN, `-5` is a
resolvable name with no address record).

### The ticket's own row, re-measured

```
$ docker exec -i apolaki-agent-1 python - < scratchpad/measure_hist.py   (head)
57cc3b49 | tools with >=1 error: 2 | >1 error: 2 | >1 DISTINCT: 1
  fetch_openapi              total=10   distinct=2
        5  [SSL: WRONG_VERSION_NUMBER] wrong version number (_ssl.c:1010)
        5  Response is not valid JSON (not an OpenAPI spec)
  run_injection_probes       total=6    distinct=1
        6  [SSL: WRONG_VERSION_NUMBER] wrong version number (_ssl.c:1010)
```

Two things the ticket did not say, both of which the fix has to serve:

* `run_injection_probes` sat in the SAME mission with **6 identical SSL faults** and a row that
  said one. `distinct == 1` is the majority case (48 rows lose a count, only 16 lose a histogram),
  so **a count alone is the higher-value half of this ticket**, not the histogram.
* The same two-mode `fetch_openapi` shape repeats across 12+ missions - it is the deployment's
  standard shape, not an outlier, which is why the fixture in the tests is that shape.

All fixture strings used in the tests are copied verbatim from these outputs.

---

## 2. The change

`agent/main.py` only. Three counters beside the Q-067 ones, one digest helper, three new row keys.

* aggregation gains `errors` (total) and `error_kinds` ({full message: count}). Keyed on the FULL
  message, so distinctness is not an artifact of the 140-char display budget.
* `a["error"]` is UNCHANGED and still last-write-wins. The status heuristic (`low`, the
  skipped/failed branches) reads it, and Q-067 + `936f6bd` measured that behaviour; a reporting
  ticket must not shift a classification underneath them.
* `_rank_errors` orders by count desc, message asc. The message tie-break is load-bearing: two
  identical runs must not print two different sentences because a dict iterated differently.
* `_error_digest` builds the FAILED row's note, where the error IS the note:
  * 1 error -> the message alone, byte-for-byte what it printed before;
  * n identical -> `<msg> (n calls, same error)`;
  * n over d kinds -> `n calls errored, d distinct: n1x <msg>; n2x <msg>[; +k more]`.
* EXECUTED rows get counts only (`5 calls errored`, `20 calls errored, 2 distinct`) in place of the
  old `1+ call errored`. No error prose there on purpose: the finding or the verdict is the headline
  and a second engine-worded sentence competes with it - the same argument the `negatives` branch
  above it already makes.
* every row now carries `errors`, `error_distinct` and `error_kinds` (top 5, ranked). The JSON
  report export carries the ledger wholesale, so the machine-readable histogram travels with it and
  a consumer never re-parses the sentence. `report.py`'s two renderers read only
  `tool/status/calls/findings/note`, so nothing downstream changes shape.

## 3. Fails before, passes after - and replayed on the real missions

New file `agent/tests/test_ledger_error_diversity.py`, 13 tests. Before the change, on the
unmodified producer:

```
$ docker run --rm --network apolaki_default -v ".../apolaki/agent:/app" -w /app apolaki-agent \
    python -m pytest tests/test_ledger_error_diversity.py -p no:cacheprovider -q
FAILED ... test_a_tool_that_failed_six_times_does_not_report_one_failure
FAILED ... test_two_distinct_failure_modes_are_both_visible
FAILED ... test_the_most_common_error_leads_not_the_last_one_written
FAILED ... test_the_count_is_of_error_rows_not_of_calls
   (12 of 12 failed; reasons: 9x KeyError 'errors', 1x KeyError 'error_kinds',
    1x ValueError: substring not found  -- the dominant error was not in the note at all,
    1x assert '9 calls errored' in 'SQLi confirmed on /rest/x (1+ call errored)')
```

After the change, the new file plus every test that pins the surrounding behaviour:

```
$ ... python -m pytest tests/test_ledger_error_diversity.py tests/test_ledger_negative_result.py \
    tests/test_tool_ledger_status.py tests/test_ledger_records_dispatch.py \
    tests/test_ledger_mode_binding.py tests/test_arsenal_errored_class.py tests/test_arsenal_gap.py \
    -p no:cacheprovider -q
69 passed
```

### Replayed on the real mission rows, not only on fixtures

The patched producer run against a COPY of the live `bbh_data` volume (read-only mount, DB copied
to /tmp inside a throwaway container - the running agent was never touched):

```
mission 57cc3b49 | tools: 46
  fetch_openapi          failed    calls=10  errors=10  distinct=2
     note   : 10 calls errored, 2 distinct: 5x Response is not valid JSON (not an OpenAPI spec);
              5x [SSL: WRONG_VERSION_NUMBER] wrong version number (_ssl.c:1010)
  run_injection_probes   executed  calls=9   errors=6   distinct=1
     note   : 0 reflection signal(s) (6 calls errored)

mission 5102527f | tools: 40
  http_probe             failed    calls=48  errors=48  distinct=2
     note   : 48 calls errored, 2 distinct: 31x [Errno -2] Name or service not known;
              17x [Errno -5] No address associated with hostname
```

Those three rows previously read, respectively: one of the two messages; `0 reflection signal(s)
(1+ call errored)`; and one of the two DNS messages. `fetch_openapi` still reads `failed` on this
mission because its rows are UNTYPED (they predate the Q-067 engine-side token) - that is Q-067's
half, not this one, and the row is honest about it either way.
