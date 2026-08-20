# Q-043 — target rate policy, verified clause by clause. Rate-policy lane (Breaker).

Written as the work happens. Every row is MEASURED (command + real output) or UNVERIFIED.
This lane was asked to answer "does it WORK", not "does it exist", because Q-043 was filed after a
fabricated `tools.py:3296` citation survived five lease prompts unchallenged.

Snapshot under test: `git archive HEAD:apolaki` at `cffc559`, extracted to a private directory.
Never the shared tree — three other lanes are live.

    SNAP=<scratch>/snap/agent
    docker run --rm --network apolaki_default -v "$SNAP:/app" -w /app apolaki-agent <cmd>

**Note on `pytest.ini`**: `addopts = -q` is already set. Passing `-q` again makes `-qq`, which
**suppresses the summary line entirely** — a run that printed only dots and exited 0. Do not pass
`-q` to this suite or you will read a truncated result as a clean one.

---

## Verdict table

| # | Clause | `_http` | browser | Verdict |
|---|---|---|---|---|
| 1 | `Retry-After` delta-seconds | 2.006 s | see §3 | **PASS** |
| 2 | `Retry-After` HTTP-date (+ past clamps to 0) | 2.228 s / 0.003 s | see §3 | **PASS** |
| 3 | bare `429`, no `Retry-After` | **0.003 s** | **0.00 s** | **FAIL** |
| 4 | both paths | yes | yes | **PASS** (with §3's gap on both) |
| 5 | bounded + configurable | 4.007 s under a 4 s ceiling | shares the ceiling | **PASS** |
| 6 | negative control fails if policy removed | — | — | see §5 |

---

## 1. The ticket's premise is stale, in both directions — checked before believing either

Q-043 says *"`Retry-After` appears NOWHERE in `agent/`"*. That was true when filed. It is **not**
true now: `c02208d` landed a real per-origin policy and `9c37ced` bounded the wait.

But the briefing's newer claim needed checking too. `agent/browser_engine.py:134` declares the policy
is *"observed by sync and async transports"*. That is a docstring, i.e. a claim. What is actually
wired, verified by grep and then by execution:

| path | gate | evidence |
|---|---|---|
| `_http` async transport | `tools._target_client` → `browser_engine.rate_limited_async_client` httpx event hooks (`agent/browser_engine.py:277-300`) | measured, §2 |
| `_http` explicit gate | `tools._http_send` waits then observes (`agent/tools.py:1901`, `:1911`) | measured, §2 |
| Playwright navigation | `rate_limited_goto` + `_guard_playwright_page` route interception (`agent/browser_engine.py:302-338`) | measured, §3 |
| browserless `/function` | `drive()` `wait_sync` before POST (`:521`), `observe` on returned nav + in-page events (`:530-533`), in-page JS deadline map (`:440-473`) | measured, §3 |

So the docstring is **accurate**. That is a result, not an assumption: it was tested, not read.

---

## 2. MEASURED — `_http` path, the real production transport

Not a unit test of the policy object. This drives `tools._target_client`, the exact factory
`tools._http_send` uses, against a loopback responder inside my own throwaway container. Two GETs;
the gap between the **start** of request 1 and the **start** of request 2 is the backoff.

    docker run --rm --network apolaki_default -e BBH_RETRY_AFTER_MAX_SECONDS=4 \
      -v "$SNAP:/app" -v "$MEASURE:/measure" -w /app apolaki-agent python -u /measure/probe_http.py

    BBH_RETRY_AFTER_MAX_SECONDS='4'
    effective max_wait = 4.0s
    C1 delta-seconds  Retry-After: 2       status=429->200  gap=2.006s   expect >=2s
    C2 HTTP-date      now+3s               status=429->200  gap=2.228s   expect >=2s
    C2b HTTP-date     now-3600s (PAST)     status=429->200  gap=0.003s   expect ~0s, never negative
    C3 bare 429       no Retry-After       status=429->200  gap=0.003s   expect TICKET WANTS >0s
    C3b 503           no Retry-After       status=503->200  gap=0.002s   expect TICKET WANTS >0s
    C5 absurd         Retry-After: 86400   status=429->200  gap=4.007s   expect capped at max_wait
    NEG 200 carrying  Retry-After: 5       status=200->200  gap=0.002s   expect ~0s (positive control)
    NEG 429           Retry-After: banana  status=429->200  gap=0.002s   expect ~0s

- **Clause 1 PASS** — 2.006 s for `Retry-After: 2`.
- **Clause 2 PASS** — an HTTP-date 3 s out produced 2.228 s. HTTP-date has 1 s resolution, so a gap
  between 2 s and 3 s is the *correct* answer, not a near-miss. **The past-date case clamps to
  0.003 s and never goes negative** (`retry_after_seconds` returns `max(0.0, delta)`,
  `agent/browser_engine.py:128`). This is the rot the ticket predicted; it is not present.
- **Clause 3 FAIL** — see §4.
- **Clause 5 PASS** — see §5.

**Positive control**: C1/C2/C5 are non-zero on the same harness that reports zero for C2b/C3/NEG.
The zeros mean "no wait", not "no instrument".

