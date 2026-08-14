# Selection lane - hand-off

Question this lane answers: **where do the 309 steps go, and what is the marginal value of each
consumer?** The ticket offers two levers (raise `MAX_STEPS`; change what fills the steps) and
requires the measurement before the choice.

Status legend: `[MEASURED]` a number I took - `[in progress]` running, no number yet -
`[READ]` derived from source, not from a run.

---

## 0. Standing facts inherited (not mine, not re-derived)

| fact | source |
|---|---|
| run A/B: 309 plan steps / cap 220, 3659 tool calls, 373 cases probed, 18 claims | `docs/handoff/breaker.md` 3-two-a/c |
| jaccard 1.000 across two full runs, identical seals | breaker 3-two-c |
| 85.5% of the recall shortfall never probed; 8.2% detection on probed | breaker 3-two-d |
| published baseline `ebd96f45` cannot be re-derived from the store | `scripts/whole_product_score.py` BASELINE caveat |

---

## 1. First reading of the source, BEFORE any run [READ]

The ticket's framing is "the run is cut off by a step cap it exceeds by 40%". The source does not
support that being the coverage bound, and the arithmetic of the breaker's own tool-call census
says so out loud.

`MAX_STEPS = 220` (`agent/agent.py:3160`) bounds **`_execute_plan` only**. The deterministic
injection sweep - `_inject_sweep_surface`, `agent/agent.py:3364` - runs AFTER `_execute_plan`
returns (`_run_deterministic`, `agent.py:3569-3578`) and **is not step-capped at all**. Its budget
is `SWEEP_TARGET_CAP` (default 400, env `BBH_SWEEP_TARGETS`) and `SWEEP_BROWSER_CAP` (default 30,
env `BBH_SWEEP_BROWSER_TARGETS`).

Reconciling the breaker's census against those two constants:

```
run_sqli 400, run_sqli_structural 400, run_css_injection 400, run_waf_bypass 400,
run_injection_probes 400          = 5 x 400  = 2000
run_xpath 412, run_ldap 412, run_ssi 412     = 3 x 400 + 3 x 12 (HTML-page sweep) = 1236
                                              -> 8 HTTP engines x 400 targets    = 3200
run_xss 55, run_dom_trace 42                 -> 2 browser engines x 30 targets   =   60 + extras
                                              plan steps                          =  309
```

**~3260 of 3659 tool calls (89%) are dispatched by the sweep, not by the planner.** The 309 planner
steps are 8.4% of the dispatch budget. If that holds under my own instrumentation, lever 1
(`MAX_STEPS`) cannot be the coverage lever, and raising it buys more of the 8.4%.

To be tested, not assumed:
1. the phase split of the 3659 calls (planner vs sweep vs recon vs post) - `[in progress]`
2. distinct **vulnerable** cases reached per tool, and per tool **uniquely** - `[in progress]`
3. wall-clock per tool - `[in progress]`
4. whether the planner is at fixpoint when the cap bites - `[in progress]`

## 1b. The second reading, and it is a bigger finding than the cap [READ]

`agent/owasp_bench.py:46` already declares which SHIPPING engine owns each benchmark category. It
is the map the per-category harness uses to decide which engine is even allowed to score a
category, so it cannot be accused of being chosen to flatter anything:

| category | Java cases | owning engine | in `_SWEEP_HTTP_ENGINES`? |
|---|---:|---|---|
| sqli | 504 | `run_sqli` | YES |
| xss | 455 | `run_xss` | browser tier only - **30 of 400 targets** |
| weakrand | 493 | `run_web_probes` | **NO** |
| pathtraver | 268 | `run_web_probes` | **NO** |
| cmdi | 251 | `run_form_cmdi` | **NO** |
| securecookie | 67 | `run_web_probes` | **NO** |
| ldapi | 59 | `run_ldap` | YES |
| xpathi | 35 | `run_xpath` | YES |

`_SWEEP_HTTP_ENGINES` (`agent/agent.py:188`) is
`run_sqli, run_sqli_structural, run_xpath, run_ldap, run_ssi, run_css_injection, run_waf_bypass,
run_injection_probes`. Three of the eight own a Java category; the other five own none of them.

**`run_web_probes` - the platform's traversal + IDOR + cookie-flag engine - is dispatched by the
PLANNER only**, `planner.py:494`, over `CAP_ENDPOINTS = 25` parameterized endpoints. Verified by
grep: its only other dispatch site is the graph action map (`agent.py:3007`,
`arbitrary_file_read`). So the mission's coverage-guarantee sweep guarantees that every discovered
parameterized endpoint is tested for SQLi, XPath, LDAP, SSI, CSS-injection, WAF bypass and
CORS/redirect - and guarantees **nothing** for path traversal, IDOR, insecure cookies or command
injection.

**This is general, not benchmark-shaped.** On any target, a discovered `?file=` parameter receives
seven engines that cannot read a file and not the one that can. The engine exists, ships, is
HTTP-only and is already scored at 65.4% on `pathtraver` by the per-category harness.

**And it reframes the 202 "MISSED-AFTER-PROBING".** The coverage record scores a case as PROBED
when ANY payload-bearing tool was dispatched at its URL. A `pathtraver` case that received
`run_sqli`, `run_ldap`, `run_xpath` and `run_ssi` is "probed" and was never tested for traversal.
Its miss is booked as a DETECTION shortfall and it is a SELECTION shortfall. How much of the 202
this accounts for is the number `whole_product_score.py`'s new class-correctness table prints, and
it is the first thing my baseline run will answer.

## 2. Harness

`scripts/whole_product_rerun.py` and `whole_product_score.py` extended (additively; the SEAL is
unchanged so older artifacts stay comparable). Committed `2eba60c`.

**How the instrument is guarded, since it lives in `scripts/` and the suite container mounts only
`agent/`.** No pytest can see these files, and a test that self-skips is not a pass. So both
scripts fail LOUDLY at startup instead: `check_probe_tools()` refuses to run when a tracked tool
name is not in the live registry, and `install_phases()` refuses when a wrapped method name no
longer exists on `BBHAgent`. Both run on every measurement rather than in a suite. Verified once
by throwaway-container smoke test: 16 methods wrapped, async-generator and coroutine kinds both
preserved, phase pops correctly when the wrapped generator raises, planner census records exactly
one entry per call and keeps the original callable.

## 2b. The targeted test, failing FIRST [MEASURED]

`agent/tests/test_sweep_class_coverage.py` drives the REAL `_inject_sweep_surface` with a recording
`_run_tool` and asserts what was DISPATCHED, not what a tuple declares. Asserting
`"run_web_probes" in _SWEEP_HTTP_ENGINES` would be a guard that checks a declaration - it passes on
a tuple no code path iterates.

On unmodified HEAD, in a throwaway container:

```
3 passed, 2 failed
FAILED test_every_swept_target_is_also_tested_for_traversal_and_idor
        12 of 12 swept target(s) were never handed to run_web_probes
FAILED test_the_traversal_engine_is_not_restricted_to_the_browser_budget
        run_web_probes reached 0 target(s), at or below the browser cap 30
```

The three that pass are the non-vacuity control (the sweep does reach all 12 parameterized URLs
with `run_sqli`), the budget bound (whatever is added must still respect `SWEEP_TARGET_CAP`) and
determinism (two identical sweeps dispatch identically). They pass BEFORE the change, so they
cannot be credited to it.

## 3. Numbers

Baseline run in progress. Nothing measured yet.
