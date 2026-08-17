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
| 2 | failing test, then the mechanism in `main._tool_ledger` | pending |
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
