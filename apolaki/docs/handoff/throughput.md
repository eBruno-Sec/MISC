# Throughput lane - hand-off

## JOB 1: THE DIAGNOSIS (MEASURED 2026-08-11, live, against the owaspbench lab)

**Where the seconds go: fixed post-render settle sleeps, executed strictly serially.
Not the network, not browser startup, not the proxy, not TLS, not retries.**

Method: `Page.goto / wait_for_timeout / wait_for_load_state / evaluate / screenshot`,
`Browser.launch / new_context / close` and `ToolRegistry._http` were each wrapped with a
`perf_counter` timer, then ONE real tool call was run against
`https://owaspbench:8443/benchmark/` inside `apolaki-agent-1`. Awaits nest, so the leaf sum
is reported separately; unattributed time is python/analysis and is <6% everywhere.
Harness: `/tmp/diag.py` in the container (scratchpad, not committed - it monkeypatches
playwright classes and is a measuring instrument, not product code).

### Transport floor - ruled out
    tcp_connect      1.3 ms
    tls_handshake    3.8 ms
Round-trip to the lab is ~5 ms. It cannot account for 8.5 s. **Network latency is not the cost.**

### run_dom_audit - 26.58 s for one call (STILL SERIAL, this is the slice-3b target)
    bucket                    n    total_s    %call
    fixed_settle_sleep       24      13.40    50.4%
    page_goto                24       5.20    19.6%
    wait_networkidle          9       4.52    17.0%
    page_create              24       1.39     5.2%
    context_create           24       0.54     2.0%
    context_close            24       0.32     1.2%
    page_evaluate            48       0.30     1.1%
    http_request(_http)       3       0.21     0.8%
    browser_launch            1       0.15     0.6%
    browser_close             1       0.13     0.5%
    [unattributed]                    0.42     1.6%

### run_xss - 10.20 s for one call (width 1; slice 2 already overlaps this in production)
    fixed_settle_sleep       24       8.44    82.8%
    page_goto                24       0.78     7.6%
    browser_launch            1       0.16     1.6%
    browser_close             1       0.13     1.3%
    http_request(_http)       3       0.08     0.8%
    page_create               1       0.07     0.7%
    [unattributed]                    0.52     5.1%

### run_dom_trace - 10.80 s for one call (width 1; slice 3a already overlaps this in production)
    fixed_settle_sleep       11       6.61    61.2%
    page_goto                11       1.74    16.1%
    page_create              11       0.81     7.5%
    http_request(_http)       3       0.27     2.5%
    context_create           11       0.25     2.3%
    browser_launch            1       0.20     1.9%
    browser_close             1       0.16     1.5%
    context_close            11       0.14     1.3%
    page_evaluate            11       0.09     0.8%
    [unattributed]                    0.52     4.8%

### Each candidate, answered with a number
| candidate | verdict | measurement |
|---|---|---|
| network latency to the lab | **NO** | 1.3 ms connect, 3.8 ms TLS; ~5 ms of an 8.5 s call |
| per-call headless-browser startup | **NO** | `browser_launch` 0.15-0.20 s, paid ONCE per tool call (not per probe): 0.6-1.9% |
| TLS handshake per request | **NO** | 3.8 ms, and the browser pools connections anyway |
| the intercept proxy (`agent/proxy.py`) | **NO** | `_http` is 3 calls / 0.08-0.27 s per tool call: 0.8-2.5% |
| retry / backoff | **NO** | zero retries fired on a healthy lab; the `429`/`Retry-After` path at `tools.py:3296` never ran |
| **a fixed sleep, run serially** | **YES** | **50.4% / 82.8% / 61.2%** of the three browser engines |
| **serial `goto` + `networkidle`** | **YES** | another **36.6% / 7.6% / 16.1%** - also strictly serial, also overlappable |

**Overlappable share of a browser tool call: 87.0% (dom_audit), 90.4% (xss), 77.3% (dom_trace).**

The settle window is NOT a bug and must not be shortened: an async payload
(`<img src=x onerror=...>`) needs it to fire, and cutting it trades recall for speed silently.
The fix is to make the sleeps wait AT THE SAME TIME, not to make them shorter.

### Mission-level confirmation (mission ebd96f45, 5329 s, from the `logs` table)
Per-tool totals, FIFO-pairing each tool_call with the next tool_result of the same name:

    run_dom_audit     17 calls    unreliable*   see live 26.6 s measurement above
    run_xss           55 calls    3235 s  mean 58.82 s  max 67.63 s   60.7% of wall
    run_sqli         400 calls     361 s  mean  0.90 s
    run_dom_trace     42 calls     334 s  mean  7.95 s
    run_ldap         412 calls     255 s  mean  0.62 s
    run_xpath        412 calls     226 s  mean  0.55 s
    ...every remaining tool is under 1% of wall

*`run_dom_audit` has one tool_call with no matching tool_result, so FIFO pairing drifts and
its log-derived mean (326 s, max 4531 s) is an artifact. Do not quote it. The live
instrumented 26.58 s above is the honest number. Everything else pairs cleanly (run_xss
variance is 58.8 +/- 9 s across 55 calls).

**Conclusion: the three browser engines are ~99% of the browser-time budget, and ~80-90% of
each of those calls is serial waiting. Non-browser tools are already sub-second and are not
worth touching.**

---

## Status

- slice 1 (a0d0926): `tools.bounded_map` + `browser_concurrency()` - the one bounded primitive
- slice 2 (9e7f5aa): `run_xss` settle windows overlap
- slice 3a (91d4d16): `run_dom_trace` renders parameters concurrently
- slice 3b (this lane): `run_dom_audit` renders probes concurrently - **the last serial engine,
  and the single most expensive tool call in the product at 26.6 s**

### The held-back test - RESOLVED, it was a red test, not a broken one
`agent/tests/test_dom_audit_concurrency.py` was uncommitted and failing. Its previous author
believed the whole file was a broken oracle. It was not - only ONE of its assertions ever had
the render-count problem, and that assertion (`test_the_early_exit_still_saves_renders`) had
already been repaired in the uncommitted file by spending the mission-wide gadget budget up
front (`gadget_pass=False`), so confirming `proto` can no longer unlock the extra gadget
renders and move the metric.

The one still-failing test, `test_probe_renders_actually_overlap`, was failing for the
ordinary reason: `peak in-flight == 1` because `_run_dom_audit` had not been made concurrent
yet. It measures overlap DIRECTLY - a counter incremented at `goto` and decremented at the end
of the settle, i.e. timestamped occupancy spans - and it runs on a CLEAN page
(`_confirm_none`), so the number of confirmations cannot move it. No assertion was relaxed.
