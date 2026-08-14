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

## 2. Harness

`scripts/whole_product_rerun.py` extended (additively; the SEAL is unchanged so older artifacts
stay comparable) to record phase attribution, per-tool case sets and per-tool wall clock.

## 3. Numbers

None yet.
