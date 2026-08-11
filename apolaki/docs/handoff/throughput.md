# Throughput lane -- hand-off

Owner: Implementation Agent (Builder, throughput lane).
Files owned: `agent/agent.py`, `agent/race_tool.py`, `agent/proxy.py`, `agent/tools.py`, their tests.

Ticket: recall on OWASP Benchmark Java v1.2 is 22/1415 = 1.6% while precision is 22/23 = 95.7%.
Recall is bounded by wall clock, not by detection. Find the real cost, then raise throughput without
losing determinism or the no-DoS discipline.

---

## JOB 1 -- MEASURED COST BREAKDOWN (done before any change)

Everything below is measured, not read. Two independent measurements agree.

### Measurement 1 -- the real mission, from its own log timestamps

Mission `ebd96f45` (`owaspbench-q019`, active mode, 2026-08-11), the most recent whole-product run
against `https://owaspbench:8443`. Every `tool_call` log row paired with its `tool_result` row gives
that engine's true in-situ cost. 96% of the mission span is attributable this way.

```
span 5329 s   tool-attributed 5089 s (96%)   unattributed 240 s
tool                     calls   total_s   mean_s   %span
run_xss                     55    3235.0    58.82   60.7%     <-- the binding constraint
run_dom_audit               17     505.2    29.72    9.5%
run_sqli                   400     361.4     0.90    6.8%
run_dom_trace               42     333.9     7.95    6.3%
run_ldap                   412     254.5     0.62    4.8%
run_xpath                  412     226.4     0.55    4.2%
run_injection_probes       400      42.7     0.11    0.8%
run_ssi                    412      39.9     0.10    0.7%
run_waf_bypass             400      26.6     0.07    0.5%
run_sqli_structural        400      23.9     0.06    0.4%
run_css_injection          400       9.6     0.02    0.2%
(recon: subfinder 22.3 s, wayback 5.1 s, everything else < 1 s)
TOTAL 3470 calls, mean 1.47 s/call
```

**The three browser-backed engines are 4074 s = 76.5% of the mission, from 114 of 3470 calls (3.3%).**
The eight HTTP-only engines are 985 s = 18.5% from 3236 calls (93%).

Note the mean is 1.47 s/call here, not the 8.5 s/call in the ticket -- the ticket's figure predates the
Q-019 cap split. The *distribution* is the finding, not the mean: one engine owns 61% of the clock.

### Measurement 2 -- isolated per-engine timing, with an httpx request counter

Harness monkey-patches `httpx.AsyncClient.send` and `__init__` to count requests, time spent inside
HTTP, and clients constructed. One benchmark URL,
`https://owaspbench:8443/benchmark/sqli-00/BenchmarkTest00008.html?BenchmarkTest00008=a`.

```
engine                  wall_s   reqs  in_http_s  overhead_s  clients
run_sqli                  0.68     66       0.43        0.25        1
run_sqli_structural       0.03      3       0.03        0.01        3
run_xpath                 0.44     57       0.35        0.09        9
run_ldap                  0.60     64       0.52        0.08       10
run_ssi                   0.05      8       0.04        0.01        2
run_css_injection         0.01      1       0.01        0.00        1
run_waf_bypass            0.04      3       0.03        0.01        3
run_injection_probes      0.02      5       0.02        0.00        1
run_xss                  10.40      4       0.04       10.36        4
run_dom_trace             9.83      3       0.03        9.80        3
run_form_xss              0.02      7       0.02        0.00        1
run_client_checks         0.02      3       0.02        0.00        3
TOTAL                    22.14    224       1.54       20.60
```

91% of the wall clock is non-HTTP overhead inside `run_xss` + `run_dom_trace`.

### Measurement 3 -- inside run_xss: where the 10.4 s goes

```
playwright_start_s        0.388
chromium_launch_s         0.191
context_and_page_s        0.109
teardown_s                0.134     -> browser startup+teardown total 0.82 s  ( 8%)
goto_mean_s               0.043     -> 24 navigations x 0.043  = 1.03 s       (10%)
fixed sleep per nav       0.350     -> 24 navigations x 0.350  = 8.40 s       (82%)
nav_count_for_this_url      24      (1 param x 12 EXEC_PAYLOADS + 12 fragment payloads)
PROJECTED total          10.25 s    (measured 10.40 s -- the model is right)
```

**`agent/tools.py` `_xss_execute`: `await page.wait_for_timeout(350)` after every
`page.goto(...)`, in a strictly serial loop.** That single fixed sleep is 82% of the biggest engine,
which is 61% of the mission -- so roughly **half the whole mission wall clock is a hardcoded sleep.**
It scales as `(len(params) + 1) * 12 * 0.35`, which is why the in-mission mean is 58.8 s (a benchmark
page with a form yields ~10-12 discovered params) and the 1-param isolated case is 10.4 s.

The same serial `goto` + fixed-settle shape is in `_run_dom_trace` (7.95 s/call) and `_run_dom_audit`
(29.7 s/call).

### Hypotheses TESTED AND REJECTED (none of these is the cost)

| candidate | measured | verdict |
|---|---|---|
| network latency to the lab | 1.8 ms per request on a reused client | not the cost |
| TLS handshake per request | fresh client 8.6 ms vs reused 1.8 ms = 6.8 ms delta; ~3200 requests => ~22 s over a 5329 s mission | real but 0.4% |
| httpx client construction | 0.5 ms per construct/teardown | negligible |
| the intercept proxy (`agent/proxy.py`) | `PROXY_URL=http://mitmproxy:8080` is set but no mitmproxy container is running, and `_xss_execute` launches Chromium with `--no-sandbox --disable-gpu --disable-dev-shm-usage` only -- no `--proxy-server`. Proxy is not in the probe path at all. | not the cost |
| retry/backoff | no global retry/backoff layer exists in `tools.py`; the only rate-limit handling is `if r.status_code in (403, 429): stop politely` (tools.py:3358, content discovery) | not the cost |
| per-call headless-browser startup | 0.82 s of 10.25 s | real, 8%, secondary |
| sequential awaits that could be gathered | yes -- but the thing being serialised is the sleep, not the I/O | THE cost |

Secondary, worth noting but not the ticket: there are **8 separate `pw.chromium.launch()` call sites in
`tools.py`** each launching a fresh in-container Chromium per tool call, while a shared
`headless-chrome` sidecar (`CDP_BROWSER_URL=http://headless-chrome:3000`) sits unused by these engines.
That is the 8% tier. Not touched in this lane's first slices.

---

## JOB 2 -- the fix, and why this shape

Do **not** shorten the 350 ms settle. It is the window an async payload
(`<img src=x onerror=alert()>`) needs to fire its dialog; shortening it trades wall clock for recall
and would be a silent detection regression. **Overlap the sleeps instead** -- every payload still gets
its full 350 ms, they just wait at the same time.

Design constraints held:
- **Bounded + configurable**, never unbounded (`BBH_BROWSER_CONCURRENCY`, default small).
- **Deterministic.** Targets are processed in fixed-size chunks *in list order*; within a chunk they run
  concurrently; findings are selected strictly by original target order, never by which finished first.
  Chunk boundaries are a function of the ordered list and the configured width, not of timing, so the
  request count is deterministic too.
- The existing early-exit (`done` set: once a `(where, param)` is confirmed, stop paying for its
  remaining payloads) is preserved -- applied at chunk boundaries.
- 429/`Retry-After` courtesy at `tools.py:3358` is untouched.

### Slices

- [x] slice 0 -- measured diagnosis (this document)
- [ ] slice 1 -- `_bounded_gather`: one bounded, order-preserving, deterministic concurrency primitive
      in `tools.py`, plus `BBH_BROWSER_CONCURRENCY`. Tests first (they must fail before the code exists).
- [ ] slice 2 -- `_xss_execute` uses it: N pages in the one already-launched browser, per-page dialog
      state, chunked in target order, early-exit preserved.
- [ ] slice 3 -- `_run_dom_trace` + `_run_dom_audit` same treatment.
- [ ] slice 4 -- acceptance: serial vs parallel finding-set diff; parallel run twice, byte-identical.

### Why not reuse `agent/race_tool.py`'s primitive

Checked it first, as the ticket requires. `race_tool.py` is pure analysis (`summarize`, `best_round`,
`verify_delta`, `analyze_race`); the actual synchronized-parallel transport is `tools._run_race`. That
primitive is a **gate-release burst**: N workers park on an `asyncio.Event` and are released at the same
instant so the requests land together. It is deliberately *unbounded within the burst* and
*deliberately simultaneous* -- that is the whole point of a TOCTOU race. It is the wrong tool for a
throughput limiter, which needs the opposite property (a ceiling on in-flight work, never a
simultaneity guarantee). Reused where it belongs: `_bounded_gather` is added next to it and
`_run_race` keeps its gate untouched, so there is still exactly one race primitive on the platform.

---

## MEASURED RESULT (after)

NOT YET MEASURED -- filled in only from a real run, never projected. Baseline to beat, same URL, same
target, measurement 2 above: `run_xss` 10.40 s, `run_dom_trace` 9.83 s, 12-engine sweep 22.14 s.

---

## Cross-lane notes

Nothing needed from another lane yet.
