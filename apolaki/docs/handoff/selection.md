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

## 2c. THE BASELINE DISCREPANCY, mechanically explained [MEASURED]

The ticket says not to anchor on the ledgered baseline because it cannot be re-derived. It can be
re-derived. The breaker checked `memory.finding_fp` as it exists TODAY, got 29 distinct
fingerprints, and correctly concluded that today's dedup does not explain it. The dedup that
explains it is one WITHOUT THE URL PATH.

MEASURED against the live store (`apolaki-agent-1:/app/data/bbh.db`, mission `ebd96f45`, 29 rows,
all created between 00:20:33 and 01:37:17 on 2026-08-11, i.e. inside the mission window):

```
fingerprint                       distinct   by family
memory.finding_fp today
  cls|fam|param|host+PATH             29     sqli 21, ldap 5, dom 1, sensitive 1, component 1
same key with the PATH removed
  cls|fam|param|host                  25     sqli 21, ldap 1, dom 1, sensitive 1, component 1
```

The second line is the ledgered line character for character (`docs/LEDGERS.md:151-153`), and the
case ids over those 25 findings number exactly **23** - the ledgered claim count.

**The mechanism.** `finding_fp` derives `param` from the title by `rsplit(" in '", 1)`. The sqli
titles are `... in 'header:BenchmarkTest00018'`, so each gets a distinct param and survives any
dedup. The LDAP titles are `LDAP injection in form field 'BenchmarkTest00630'` - `" in '"` does not
occur, so `param` is EMPTY for all five. With the path in the key they stay distinct; without it,
all five collapse to `cwe-90|ldap_injection||owaspbench`. That is why the collapse hits `ldapi`
alone and leaves `sqli 21` untouched, which is the exact asymmetry the ledger shows.

The ledgered `by (key category, is_vulnerable)` split is consistent with the same 23-case set:
21 sqli findings = 20 sqli-true + `00494` (cmdi-false, the known FP), plus `00407` and `00630`.

**What this settles.** The ledgered baseline is NOT a different run and is NOT missing findings. It
is the SAME 29 findings counted under a coarser fingerprint. Therefore:

* the store's **27 claimed cases** is the honest baseline claim count for `ebd96f45`;
* the 08-13 rerun's headline `ldapi 1 -> 5` "class broadening" is **zero** - the baseline already
  had all five;
* the whole-product comparison is **27 claimed -> 18**, and the loss is **-9, not -3**.

**What it does NOT settle, stated rather than glossed.** The recorded seal
`a95670f9c756...` still does not reproduce. I hashed the reconstructed 23-case list under ten
serializations (newline, trailing newline, comma, space, concat, json, repr, lower, upper, both for
the 23-set and the 27-set) and brute-forced every field subset up to size 4 over both the 29-row and
the 25-row bases - **no match**. The 08-11 sealing script was never committed (commit `1cd6df9`
carries only its printed output), so its exact serialization is unrecoverable. The COUNTS reconcile
exactly and reproducibly; the seal STRING does not, and I am not going to claim it does.

**Owner action** (`docs/LEDGERS.md` is not this lane's file): the `BASELINE` dict in
`scripts/whole_product_score.py` should read 27 claimed, not 23, once an owner accepts this
derivation. I have not changed it, because a baseline constant is exactly the kind of number that
must not move on one lane's say-so.

## 2d. Mutation check on the new test [MEASURED]

The obvious mutant (drop the engine) is already covered - the tests failed that way before the fix.
The non-obvious one is putting the engine in the WRONG TIER, which looks like a fix and silently
applies the guarantee to the first 30 targets:

```
MUTANT: run_web_probes moved from _SWEEP_HTTP_ENGINES to _SWEEP_BROWSER_ENGINES
  -> FAILED test_the_traversal_engine_is_not_restricted_to_the_browser_budget
     "run_web_probes reached 30 target(s), at or below the browser cap 30"
```

Killed by the intended assertion, with the mechanism in the message. Noted honestly:
`test_every_swept_target_is_also_tested_for_traversal_and_idor` PASSES on that mutant, because its
12-URL fixture is under the browser cap. Neither test catches it alone; the pair does, and that is
why both exist.

## 3. Numbers

Baseline run in progress. Nothing measured yet.

### Operational note for whoever runs this next

Do NOT `docker run -v <repo>/agent:/app -v <somefile>:/app/x.py`. Docker creates the second mount
point INSIDE the first, which means it creates the file in the repo's `agent/` on the host. It left
`agent/smoke.py`, `agent/smoke2.py` and `agent/wp_run.py` in my working tree. Removed, and verified
against history that none was ever staged - every commit in this lane used explicit paths, never
`git add -A`. Mount helper scripts into a directory that is not itself a host mount.
