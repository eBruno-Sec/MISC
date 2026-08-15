# Selection lane - hand-off

Question this lane answers: **where do the 309 steps go, and what is the marginal value of each
consumer?** The ticket offers two levers (raise `MAX_STEPS`; change what fills the steps) and
requires the measurement before the choice.

Status legend: `[MEASURED]` a number I took - `[in progress]` running, no number yet -
`[READ]` derived from source, not from a run - `[DERIVED]` computed from measured parts, with the
assumption named.

**STATE, for whoever inherits this.** Sections 0-6 are complete and every number in them is taken.
The change in section 7 is committed (`805a78e`) on a green suite (2377/0). Its whole-product
before/after is **`[in progress]`**: the "before" is sealed at `b97260c`
(18/18 precision, 18/1415 recall, seal `3ee7609d`), and the "after" run `apolaki-sel-wp1` was still
executing when this line was written. **Nothing in section 7 has an after-number yet.** If the run
never lands, the correct read of this lane is sections 0-6 - the account - plus a code change whose
suite is green and whose mission effect is unverified. The revert condition is written into
`805a78e`: if precision moves off 100.0%, revert rather than defend.

---

## 0. Standing facts inherited (not mine, not re-derived)

| fact | source |
|---|---|
| run A/B: 309 plan steps / cap 220, 3659 tool calls, 373 cases probed, 18 claims | `docs/handoff/breaker.md` 3-two-a/c |
| jaccard 1.000 across two full runs, identical seals | breaker 3-two-c |
| 85.5% of the recall shortfall never probed; 8.2% detection on probed | breaker 3-two-d |
| published baseline `ebd96f45` cannot be re-derived from the store | `scripts/whole_product_score.py` BASELINE caveat |

Row 4 is **superseded by this lane** - see 2c: the counts DO re-derive, under a path-less
fingerprint. The seal string still does not.

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

## 2e. What the sweep guarantees, and what it leaves to a 25-endpoint budget [READ]

Written down before the numbers so it cannot be fitted afterwards. Dispatch-site census by grep
(`_step("<tool>"` in `planner.py`, membership in the two sweep tiers, `_run_tool("<tool>"` in
`agent.py`):

| class | engine | guaranteed by the sweep? | otherwise reachable via |
|---|---|---|---|
| SQLi | `run_sqli`, `run_sqli_structural` | yes, `SWEEP_TARGET_CAP` | planner |
| XPath / LDAP / SSI | `run_xpath` `run_ldap` `run_ssi` | yes | planner, HTML-page sweep |
| CORS / redirect / SSTI | `run_injection_probes` | yes | planner |
| CSS injection / WAF bypass | `run_css_injection` `run_waf_bypass` | yes | - |
| **traversal / IDOR / cookies / PRNG** | **`run_web_probes`** | **NO** | planner only, `CAP_ENDPOINTS = 25` |
| XSS | `run_xss` | partial - `SWEEP_BROWSER_CAP = 30` | planner (25), `_promote_leads` |
| command injection | `run_cmdi` / `run_form_cmdi` | NO | planner only |
| NoSQL / SSRF / XXE / deser / upload / race / stored-XSS | 8 engines | NO | planner only, 1 step site each |

**This lane changes ONE row** - `run_web_probes` - because it owns the largest share of the
corpus's testable classes (`pathtraver` 268 + `securecookie` 67 + `weakrand` 493) AND is HTTP-only,
so it fits the cheap tier. `run_form_cmdi` (251 cases) and `run_xss` beyond 30 targets are the same
defect and are NAMED here as follow-ups rather than bundled: `run_xss` costs ~10 s per URL and
cannot join the cheap tier at all, and `run_form_cmdi` sends OS-command payloads in POST bodies,
which deserves its own measured ticket rather than a ride on this one.

**A risk this run will measure for the first time.** `owasp_bench.py` runs each engine only on the
cases of the category it owns, so `run_web_probes` has never been measured against `sqli`, `xss`,
`cmdi` or `xpathi` pages. In the sweep it will run on all 400 targets regardless of category. Its
per-category FPR of 0.0% therefore does NOT imply zero false positives in a mission - a `sqli` page
that happens to name `Math.random()` would be a cross-family confirmation the per-category harness
could never see. If whole-product precision moves off 100%, this is the first place to look, and
that is a reason to measure the change rather than to assume it.

## 2f. PREDICTIONS, written before the baseline artifact exists

Recorded so the account cannot be fitted to whatever comes back. Each is falsifiable by a single
field of `wp_claims.json`.

| # | prediction | falsified by |
|---|---|---|
| P1 | the `planner` phase is under 15% of tool dispatches and under 20% of tool-seconds | `effort.phase_calls` / `phase_seconds` |
| P2 | the `sweep` phase is over 80% of tool dispatches | same |
| P3 | `cases_unique_to_tool_n` is ~0 for all eight HTTP sweep engines - they ride ONE target list, so their cost is depth, not coverage | `coverage.cases_unique_to_tool_n` |
| P4 | `sweep_selection` shows 400 kept out of well over 1000 candidates - the cap binds hard | `effort.sweep_selection` |
| P5 | `run_web_probes` appears with roughly 25 dispatches (planner only), not 400 | `effort.tool_calls` |
| P6 | the class-correctness table shows `pathtraver` / `securecookie` / `weakrand` with a large `probed` and a `by owner` at or near 0 | `wp_score.py` table |
| P7 | the two browser engines are ~1.6% of dispatches and over 25% of tool-seconds | `effort.tool_seconds` |
| P8 | `planner_would_schedule_more` is small; if it is 0 the step cap did not bind and lever 1 is dead without a run | `effort.planner_would_schedule_more` |

If P1/P2 hold, **`MAX_STEPS` is not the coverage lever** and the ticket's lever 1 is answered
without spending a run on it. If P3 holds, adding or removing engines does not change coverage at
all - only `SWEEP_TARGET_CAP` does - and the ticket's "40% of the budget for 3% of the coverage"
shape is really "100% of the budget for 0% of the marginal coverage, bought as depth".

## 3. THE BASELINE, SEALED [MEASURED]

Own harness, own container, frozen snapshot of the agent tree, `/out` key-free, key never present.

```
=== WHOLE-PRODUCT RERUN, SEALED ===
elapsed                 : 1889s
findings total          : 20      leads 4
by family               : sqli 11, ldap_injection 5, dom_data_manipulation 1,
                          xpath_injection 1, sensitive_exposure 1, weak_random 1
distinct cases claimed  : 18
plan steps              : 309 / cap 220        (cap recovered by source read; see fa98906)
tool calls              : 3659
cases PROBED            : 373     probed but not claimed 355
SEAL sha256             : 3ee7609d766836d40ef44547ad00b485a83cf26fe14b85b2be7278ce7f7fbfdd
```

**The seal is byte-identical to the breaker's runs A and B** (`docs/handoff/breaker.md` 3-two-c,
committed `7fc3115` three days ago, before any key was read). This is a THIRD independent run of the
same pipeline producing the same 18 claims, the same 309 plan steps, the same 3659 tool calls and
the same 373 probed cases - now with sixteen wrapped methods, three census hooks and per-dispatch
timing attached. **The instrument does not change the measurement**, which is the precondition for
everything below.

### Where the budget goes, by phase

```
phase        calls    %calls    tool_s   %time   cases probed
sweep         3350     91.6%    1360.5   75.1%       373
planner        309      8.4%     451.2   24.9%        25
attributed 1812s of 1889s elapsed; 77s outside any tool dispatch (crawl, projection, report)
```

### Where the budget goes, by consumer

```
tool                    calls    tool_s   %time   cases  unique   claims
run_xss                    55     742.3   41.0%      50       0        0
run_sqli                  400     259.0   14.3%     373       0       11
run_dom_trace              42     166.0    9.2%      28       0        1*
run_ldap                  412     160.1    8.8%     373       0        5
run_dom_audit              18     151.2    8.3%       5       0        0
run_xpath                 412     144.1    8.0%     373       0        1
run_waf_bypass            400      34.0    1.9%       0       0        0
run_sqli_structural       400      28.6    1.6%     373       0        0
run_ssi                   412      22.8    1.3%     373       0        0
run_injection_probes      400      20.9    1.2%     373       0        0
run_css_injection         400      11.3    0.6%     373       0        0
run_web_probes              0       0.0    0.0%       0       0        0
```
`*` the one `dom_data_manipulation` claim; attribution by family, not by dispatch record.

## 4. THE EIGHT PREDICTIONS, SCORED

| # | prediction | result | number |
|---|---|---|---|
| P1 | planner < 15% of dispatches AND < 20% of tool-seconds | **HALF FALSIFIED** | 8.4% of dispatches (held), **24.9% of tool-seconds (wrong)** |
| P2 | sweep > 80% of dispatches | **HELD** | 91.6% |
| P3 | `unique` ~ 0 for all eight HTTP sweep engines | **HELD, exactly 0** | every engine, 0 |
| P4 | 400 kept of well over 1000 candidates | **HELD** | **400 of 2762 - the cap keeps 14.5%** |
| P5 | `run_web_probes` ~ 25 dispatches | **FALSIFIED, and worse than predicted** | **0 dispatches** |
| P6 | owning engine absent for pathtraver/securecookie/weakrand | pending the key | - |
| P7 | browser engines ~1.6% of dispatches, > 25% of tool-seconds | **HALF FALSIFIED** | 2.7% of dispatches (I said 1.6%), **50.1% of tool-seconds** |
| P8 | `planner_would_schedule_more` small; 0 kills lever 1 | **HELD** | **2** |

**The two that were wrong are the two worth having.**

**P1's time half.** I expected the planner to be cheap in time as well as in count. It is not: 309
dispatches cost 451 s, **1.46 s per step**, against the sweep's 0.41 s per dispatch. The planner is
3.6x more expensive per dispatch than the sweep, because in `active` mode it schedules the browser
engines (`run_xss` x25, `run_dom_audit` x6) and almost nothing else that costs anything.

**P5.** I predicted 25 and measured **zero**. The cause is `planner.py:175` -
`_ALLOWED["active"] = {PASSIVE, ACTIVE}` - and `fresh()` drops any step whose tool is not
`_allowed(tool, mode)`. `run_web_probes` is INTRUSIVE. **In the default `active` mode the planner
cannot schedule ANY intrusive tool at all**, so the traversal / IDOR / cookie-flag / PRNG engine is
not under-used, it is **completely dead**. The same gate silences `run_cmdi`, `run_nosqli`,
`run_ssrf`, `run_bfla`, `run_content_discovery` and `run_ffuf` in the planner.

This also explains why the sweep is the whole story: `_inject_sweep_surface` dispatches through
`_run_tool` directly, which applies the intrusive HITL gate (pre-authorised on an autonomous run)
rather than the planner's mode filter. **So `_SWEEP_HTTP_ENGINES` is not "one of two paths" to
intrusive injection coverage in an active-mode mission. It is the ONLY path.** A class absent from
that tuple is a class the mission never tests.

## 5. THE TICKET'S TWO LEVERS, ANSWERED

### Lever 1 - `MAX_STEPS`: DEAD, and cheaply

`planner_would_schedule_more = 2`. Batch sizes were `[14, 6, 30, 41, 218]`; the cap is checked at
the top of the `while`, so the 218-step batch started at step 91 and ran to 309 unimpeded. Asking
the real planner for one more batch at the final world-state returns **2 steps**.

So the honest reading of "309 steps against a cap of 220" is **not** "cut off 40% past its budget
with work remaining". It is "one batch overshot the cap by 89, and the planner was 2 steps from its
fixpoint anyway". Raising `MAX_STEPS` to any value buys **2 dispatches, roughly 3 seconds, and 0
additional cases** - the planner's reach is bounded by `CAP_ENDPOINTS = 25`, not by `MAX_STEPS`.

**Recommendation: do not raise `MAX_STEPS`.** It is not the coverage lever. (`exit_reason =
step_cap_exhausted` is still technically true and is what sent this ticket here; it is a true fact
that pointed at the wrong constant, which is exactly why the marginal-value measurement was
required before the change.)

### Lever 2 - what fills the steps: two findings, and the ticket's shape is confirmed

**(a) The ticket predicted "a tool that burns 40% of the budget for 3% of the coverage is the
finding". It exists, and the numbers are almost exactly those.**

`run_xss` is **55 of 3659 dispatches (1.5%)** and **742 s of 1812 attributed tool-seconds
(41.0%)**. It reached 50 cases, **0 of them uniquely**, and produced **0 of the 18 claims**. Add
`run_dom_trace` and `run_dom_audit` and the browser trio is **115 dispatches (3.1%) for 1059 s
(58.5%)** and **1 claim**.

At **13.5 s per `run_xss` call against 0.41 s for an average sweep dispatch, one browser target
costs 33 HTTP targets.** That is the real budget question, and it is a genuine trade rather than a
free win: browser confirmation is how reflected and DOM XSS become proof instead of leads, and it
is validated on Juice Shop and GinAndJuice. This lane measures it and does **not** cut it - trading
proof for corpus coverage on the strength of one benchmark is precisely the benchmark-fitting this
project forbids. It is recorded as a priced decision for an owner, not taken unilaterally.

**(b) Engines do not buy coverage at all. `unique = 0` for every single engine.**

All eight HTTP engines ride ONE target list, so their marginal contribution to *cases probed* is
exactly zero; what they buy is *classes tested per case*. Coverage is bought by exactly one number,
`SWEEP_TARGET_CAP`, and it is measured keeping **400 of 2762 candidates (14.5%)** - which is the
85.5%-never-probed figure, arriving from a completely independent direction and matching to within
a tenth of a point.

That reframes the ticket's brief. The budget is not mostly wasted on the wrong engines; the cheap
engines are genuinely cheap (`run_css_injection` 0.03 s/target, `run_injection_probes` 0.05,
`run_ssi` 0.06, `run_sqli_structural` 0.08 - all four together are 4.7% of tool time). The waste is
concentrated in the browser tier, and the coverage bound is a single constant.

**And the hole is that one of the cheap engines is missing from the list entirely.**

## 6. SCORED, AND THE HEADLINE NUMBER IS WRONG [MEASURED]

Key copied from the lab container AFTER the seal above was committed (`b97260c`), into a
`--network none` scorer. The scorer recomputes the sha256 and refuses to score if the claims moved;
it matched.

```
PRECISION : 18/18 = 100.0%        RECALL : 18/1415 = 1.27%       ELAPSED 1889s
MISSED-AFTER-PROBING : 202        NEVER PROBED : 1195   -> 85.5% never tested
```

Precision, recall, probed count and the 85.5% split all reproduce the breaker's run A exactly.

### P6, scored: HELD, and it carries the lane

```
category       owning engine          vuln  probed  by owner  claimed
sqli           run_sqli                272      22        22       11
xss            run_xss                 246      23         2        0
weakrand       run_web_probes          218      18         0        0
pathtraver     run_web_probes          133      16         0        0
crypto         (unmapped)              130      16         0        0
hash           (unmapped)              129      19         0        0
cmdi           run_form_cmdi           126      36         0        1
trustbound     (unmapped)               83      21         0        0
securecookie   run_web_probes           36      22         0        0
ldapi          run_ldap                 27      14        14        5
xpathi         run_xpath                15      13        13        1
TOTAL                                 1415     220        51       18
```

**Of 220 vulnerable cases that received a payload, only 51 - 23% - ever received the engine that
owns their class.**

```
detection on PROBED                : 18/220 = 8.2%
detection on CLASS-CORRECTLY PROBED: 18/51  = 35.3%
```

**The 8.2% detection rate that sent this ticket here is an artifact of the denominator.** It counts
a `pathtraver` case as "tested" when what it received was `run_sqli`, `run_ldap`, `run_xpath`,
`run_ssi`, `run_css_injection`, `run_waf_bypass`, `run_sqli_structural` and
`run_injection_probes` - eight engines, not one of which can observe a file read. When the
denominator is cases whose own engine actually ran, the oracles confirm **35.3%**.

### The 202 "detection shortfall" decomposes, and most of it is not detection

| bucket | n | what it is |
|---|---:|---|
| class-correctly probed, still missed | **33** | a genuine DETECTION shortfall - the real oracle gap |
| probed, no DAST engine exists for the class | **56** | crypto 16, hash 19, trustbound 21 - structurally invisible to any black-box tool, correctly scored 0 |
| probed, an owning engine EXISTS and never ran on them | **113** | a SELECTION shortfall wearing a detection shortfall's clothes |

The 113 break down exactly:

* **56 -> `run_web_probes`** (weakrand 18, pathtraver 16, securecookie 22). The engine had **ZERO
  dispatches in the entire mission**. This is the block this lane's change addresses.
* **36 -> `run_form_cmdi`**. Same defect, named follow-up.
* **21 -> `run_xss`** (2 of 23 got it). Not a missing engine - the `SWEEP_BROWSER_CAP = 30` budget,
  which is the priced trade in 5(a).

**So the ticket's framing needs one correction.** "We do not fail to confirm what we test. We never
test most of it" is right about the 1195 never probed. But of the 202 it says we *did* test and
failed to confirm, **only 33 were ever tested for the thing they are**. The recall shortfall is
selection at both ends: 1195 cases never reached, and 113 of the 220 reached but handed to the
wrong engines.

## 7. THE CHANGE, and six more predictions written before its artifact exists

**Change:** `run_web_probes` added to `_SWEEP_HTTP_ENGINES` (`agent/agent.py`). One line, plus the
comment block correcting the two things this lane measured: the engine ran ZERO times (not 25), and
the eight HTTP engines cost 1.70 s/URL (not the 1.1 s recorded from a single-URL sample in 08-10).

**Why this and not the cap.** Lever 1 is dead (2 steps). Raising `SWEEP_TARGET_CAP` is a real lever
- it is the ONLY thing that moves coverage - but it buys more cases at the same 23% class-correct
rate, i.e. it multiplies a known misallocation. Fixing the misallocation first is strictly cheaper:
it needs no extra targets, no extra crawl, and no longer run except this engine's own cost.

Predictions, falsifiable, recorded before `wp1` finishes:

| # | prediction | falsified by |
|---|---|---|
| Q1 | `run_web_probes` is dispatched exactly 400 times (sweep), still 0 from the planner | `effort.tool_phase_calls` |
| Q2 | `cases_probed` stays **373** - the target list is untouched, so COVERAGE does not move at all; only class-correctness does | `coverage.cases_probed_n` |
| Q3 | `by owner` goes 0 -> 18 / 16 / 22 for weakrand / pathtraver / securecookie | class-correctness table |
| Q4 | elapsed rises by 400 x the engine's per-call cost; I estimate 1-3 s/call, so **+400 to +1200 s (+21% to +64%)** | `elapsed_s` |
| Q5 | the gain skews to **weakrand and securecookie**; `pathtraver` UNDER-performs its 65.4% suite figure, because the suite harness passes `lab_mode=True` and the sweep deliberately does not - the mission gets `TRAVERSAL_SAFE_PAYLOADS` only, no `/etc/passwd` reads | per-category claims |
| Q6 | precision stays **18+/18+ = 100.0%**; any claim on a clean case falsifies it, and the first place to look is a cross-family PRNG or cookie confirmation on a `sqli`/`xss` page - a combination `owasp_bench.py` can never test because it runs each engine only on its own category | `wp_score.py` FP count |

### Which benchmark numbers CAN move, verified rather than asserted [MEASURED]

```
grep -rn "_SWEEP_HTTP_ENGINES|_SWEEP_BROWSER_ENGINES" agent/ --include=*.py
  agent/agent.py:222   the definition
  agent/agent.py:225   the browser tuple
  agent/agent.py:3498  the ONLY consumer -- the sweep's per-target engine loop
  agent/tests/test_sweep_class_coverage.py:13   a docstring, not a use
```

**One consumer.** No benchmark harness reads the tuple: `owasp_bench.py` maps category -> engine via
its own `ENGINES` dict and calls the engine directly (it does use `agent.sweep_targets`, which this
change does NOT touch), and `blind_benchmark.py`, `bench_all.py`, `bench_contract.py`,
`bench_juliet.py` and `benchmark.py` do not import `agent` at all. So **Java v1.2 DAST/hybrid,
Python v0.1, the GinAndJuice blind recall and Juliet are structurally incapable of moving from this
commit.** The only number that can move is the whole-product mission figure, which is the number
being measured.

### Lever 3 - `SWEEP_TARGET_CAP` - priced from measured parts [DERIVED, not measured]

The ticket asked for cost per marginal finding before any number is proposed. Three of the four
terms are now measured; the fourth is not, and the honest thing is to name it.

| term | value | status |
|---|---|---|
| cost of one additional target | **1.70 s** (eight HTTP engines; the browser tier does NOT grow with this cap) | MEASURED |
| cases reached per target | 373 / 400 = **0.93** | MEASURED |
| vulnerable share of probed cases | 220 / 373 = **59%** | MEASURED |
| class-correct rate x detection on the *unprobed* 85.5% | assumed equal to the probed sample | **NOT MEASURED** |

Taking `SWEEP_TARGET_CAP` 400 -> 1200 costs **+800 x 1.70 s = +1360 s (+72% elapsed)** and reaches
about +740 cases, ~440 of them vulnerable. At the measured 23% class-correct rate and 35.3%
detection that is **~+36 claims for +1360 s = ~38 s per marginal finding**, against the current
run's average of 1889 / 18 = **105 s per finding**. Marginal is ~2.8x cheaper than average, which is
what a hard truncation at 14.5% of candidates predicts.

**The unmeasured term is the whole risk.** `_spread_by_shape` round-robins across structural shapes
before truncating, so the first 400 are a representative sample rather than the first directory -
which is the reason to expect the rate to hold. It is still an assumption, and one full run at
`BBH_SWEEP_TARGETS=1200` settles it. **I am not proposing a new default from a derivation.** The
recommendation is: fix the class misallocation first (this lane's change, no extra targets, no
longer crawl), then measure the cap with the misallocation already fixed - otherwise the cap
experiment prices a surface that is still being tested by the wrong engines.

### Suite, with the change applied [MEASURED]

```
docker run --rm --network none -v <repo>/agent:/app -w /app apolaki-agent \
  python -m pytest tests/ -p no:cacheprovider -p no:warnings --tb=line -rf
  EXIT=0    2377 passed, 11 skipped, 1 xfailed, 0 failed   (262.70s)
```

2371 (the gate lane's baseline) + 5 new `test_sweep_class_coverage.py` tests + 1 from another lane
in flight. The single xfail pinning the proved-undecidable `00494` residual is untouched.

**Q5 and Q6 are the honest ones.** If the gain is mostly `weakrand`, it is largely a suite-specific
signal - `docs/handoff/measure.md` records that the Benchmark's weakrand handler ANNOUNCES its own
generator and that the 86.7% DAST score does not transfer. `securecookie` (raw `Set-Cookie`
analysis), `pathtraver` and `idor` do transfer. Any recall number from this change must be reported
split that way or it is a lab-fitted number wearing a product number's clothes.

### Operational note for whoever runs this next

Do NOT `docker run -v <repo>/agent:/app -v <somefile>:/app/x.py`. Docker creates the second mount
point INSIDE the first, which means it creates the file in the repo's `agent/` on the host. It left
`agent/smoke.py`, `agent/smoke2.py` and `agent/wp_run.py` in my working tree. Removed, and verified
against history that none was ever staged - every commit in this lane used explicit paths, never
`git add -A`. Mount helper scripts into a directory that is not itself a host mount.
