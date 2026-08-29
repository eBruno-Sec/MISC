# Q-113 - the injection sweep has no usable time bound

Lane A (Builder). Files owned: `agent/agent.py`,
`agent/tests/test_injection_sweep_is_bounded.py`, this file.

Every claim below is marked MEASURED (command + real output) or UNVERIFIED.

## The state of the code before I touched it

MEASURED by reading `agent/agent.py` at HEAD `02d66dc`:

- `agent.py:259` - `SWEEP_TARGET_CAP = max(1, int(os.getenv("BBH_SWEEP_TARGETS", "700") or 700))`.
- `agent.py:350` - `target_security_value(url)` already exists: `_HIGH_VALUE_PARAM` (id/uid/user/
  account/role/admin/cmd/exec/code/file/path/page/template/url/redirect/query/search/...) scores 4
  each, `_HIGH_VALUE_ROUTE` (admin/manage/internal/account/auth/graphql/api/upload/...) scores 3.
- `agent.py:367` - `rank_targets_for_budget(targets)` sorts by that value, stable for ties.
- `agent.py:461` - `sweep_targets` already ends
  `return _spread_by_shape(rank_targets_for_budget(targets))[:limit]`.

So **the "rank by security value before you truncate" half of Q-113 was already built** (Q-019 +
the cap-ordering lane). This is a disproved hypothesis of the ticket, and it matters: the ticket
said "rank endpoints by security value first, then truncate", implying that ordering was the
missing work. It was not. What was missing was:

1. a **cap small enough to be a bound** - 700 does not bind a 465-endpoint surface at all;
2. the **declined count**, which was never computed and never reported anywhere;
3. **operator scope roots** were not an input to the sweep's ranking (they are for phase A's
   `planner._rank_recon_roots`, Q-104).

## The conflict I have to state, not hide

`docs/benchmarks/wp3_precondition.md` records that 700 is not an arbitrary default. It is the
result of a pre-registered benchmark experiment: `docs/handoff/sqli.md` + wp3 measured that on the
OWASP Benchmark whole-product surface (2524 candidates, 11 shapes) the dominant class draws 38
slots at cap 400 and 59 at cap 605, and that nine sqli true positives sit at class indices 38-58.
wp3 raised the cap to 700, the pre-registered success condition held, and "the cap moves in the
repo" - which is why 700 is the default today.

`agent/tests/test_sweep_budget_is_the_lever.py` encodes that measurement. It passes explicit caps
(400 / 600 / 605 / 800) and therefore does NOT read `SWEEP_TARGET_CAP`, so lowering the default
does not turn it red. **But the whole-product benchmark protocol does read the default**, and
lowering it to a real engagement bound means a whole-product OWASP run will now select ~40 of 2524
candidates instead of 700.

I cannot resolve that inside my file ownership, and I am not going to paper over it.

- The bound the operator's gate demands (`<= 60` injection targets on a 465-endpoint surface) and
  the bound wp3's benchmark needs (605+) are **incompatible as a single constant**.
- The mechanism to keep both already exists and needs no code: `BBH_SWEEP_TARGETS` is read from the
  environment. **Whole-product OWASP Benchmark runs must from now on set
  `BBH_SWEEP_TARGETS=700` explicitly** to reproduce wp3. That is a one-line change to the
  benchmark protocol in `docs/benchmarks/` and a note in `docs/QUEUE.md`, neither of which I own.

PATCH FOR ANOTHER LANE (docs, not code):

    docs/benchmarks/wp3_precondition.md - add: "As of Q-113 the shipped default is an ENGAGEMENT
    bound (40), not the benchmark bound. Reproducing wp3 requires BBH_SWEEP_TARGETS=700 in the
    environment of the whole-product run."

## Baseline - MEASURED before the change

Synthetic 465-endpoint surface (57 ordinary shapes x 8 members + 9 appended sinks; the fixture lives
in `agent/tests/test_injection_sweep_is_bounded.py` and has its own guard-the-guard test), driven
through the REAL `BBHAgent._inject_sweep_surface` with a recording `_run_tool`:

    $ docker run --rm --network apolaki_default -v .../agent:/app -w /app apolaki-agent python /sp/baseline.py
    SWEEP_TARGET_CAP        = 700
    candidates              = 465
    sweep_targets selected  = 465
    distinct endpoints swept= 465
    injection dispatches    = 3816
    info line               = Deterministic injection sweep: directly probing 465 parameterized
                              endpoint(s) for SQLi / reflected-XSS / header-injection / open-redirect
                              + runtime DOM source-to-sink (coverage guarantee, planner-independent).
                              The 30 bro...

So: **465 of 465 selected, 3816 injection dispatches, zero endpoints declined and nothing to
declare.** At the operator's measured ~6 min/endpoint that is 46.5 hours of sweeping.

## After - MEASURED

    $ docker run --rm --network apolaki_default -v .../agent:/app -w /app apolaki-agent python /sp/after.py
    SWEEP_TARGET_CAP        = 40
    candidates              = 465
    distinct endpoints swept= 40
    injection dispatches    = 420
    high-value sinks kept   = 9 of 9
    INFO 465: Deterministic injection sweep: directly probing 40 parameterized endpoint(s) ...
              BUDGET: 40 of 465 candidate endpoint(s) selected by security value + operator scope;
              425 DECLINED and NOT tested, so a clean result here is a claim about the 40 probed and
              not about the 465 discovered (raise BBH_SWEEP_TARGETS to widen).
    INFO  10: ... BUDGET: the full candidate surface of 10 endpoint(s) was selected, 0 declined.

**465 -> 40 endpoints, 3816 -> 420 injection dispatches, 9.1x less work**, and all 9 planted sinks
survive the cut. At the operator's measured per-endpoint cost that is ~4 hours instead of ~46.

The 420 (not 320 = 40 x 8) is the HTML-page pass, which is a SEPARATE budget of 12 pages that this
ticket does not govern and did not change.

## What changed in `agent/agent.py`

1. `SWEEP_TARGET_CAP` default 700 -> 40 (env `BBH_SWEEP_TARGETS` unchanged).
2. `operator_roots(scope)` - names the derivation that was inline at `agent.py:3763`
   (`[e.value.lower().lstrip("*.") for e in scope.in_scope]`) so the sweep can rank by the same fact
   phase A does instead of restating it.
3. `rank_targets_for_budget(targets, scope_roots=())` - additive kwarg. Two stable sorts: value
   first, then operator-asset membership, so asset membership is the PRIMARY key and value orders
   within each tier. Q-104's `_rank_recon_roots` / `_rank_live_hosts` pattern.
4. `sweep_targets` split into `sweep_candidates` (full surface, discovery order, NO budget) and
   `select_sweep_targets` (applies the budget). The reason is the declined count: a function that
   returns only survivors cannot be asked what it dropped. `sweep_targets` is retained as the
   one-step composition six other test files drive, and is PINNED to the composition the mission runs
   by `test_the_one_step_wrapper_is_the_composition_the_mission_actually_runs` so it cannot become a
   second implementation.
   `scope_roots` was inserted BEFORE `limit` in the signature on purpose - Q-019's
   `test_the_default_cap_is_the_module_budget_and_the_call_site_passes_it` reads
   `sweep_targets.__defaults__[-1]`, so `limit` has to stay the last default. Verified green.
5. Call site `_inject_sweep_surface` builds the candidates, selects, computes
   `declined = len(candidates) - len(targets)`, records
   `self._sweep_budget = {"candidates", "selected", "declined", "cap"}` and appends to the info line:

       BUDGET: 40 of 465 candidate endpoint(s) selected by security value + operator scope;
       425 DECLINED and NOT tested, so a clean result here is a claim about the 40 probed and not
       about the 465 discovered (raise BBH_SWEEP_TARGETS to widen).

   and when nothing was dropped:

       BUDGET: the full candidate surface of 10 endpoint(s) was selected, 0 declined.

## Mutants killed - MEASURED

Each mutant applied to a scratch copy of the tree, `pytest tests/test_injection_sweep_is_bounded.py`:

| mutant | change | killed by |
| --- | --- | --- |
| M1 discovery-order | `select_sweep_targets` -> `candidates[:limit]` | `test_the_bounded_selection_keeps_the_high_value_endpoints` |
| M2 shape-only | `_spread_by_shape(candidates)[:limit]`, ranking removed | same |
| M3 cap-700 | cap reverted, ranking kept | `..._selects_a_bounded_number_of_targets`, `..._dispatches_bounded_work_and_reports_what_it_declined`, `..._declined_count_is_durable...` |
| M4 silent-truncation | bound applied, `_budget_note` dropped from the info line | `..._dispatches_bounded_work_and_reports_what_it_declined` AND `test_an_ordinary_engagement_is_not_silently_shrunk` |
| M5 roots-ignored | `rank_targets_for_budget` returns the value-ranked list, ignoring `scope_roots` | `test_operator_declared_hosts_outrank_discovered_ones` |

M2 is the mutant the ticket demanded ("keeps the cap but reverts the ranking to discovery order").
It only dies because the fixture has **66 shapes for 40 slots**: with fewer shapes than slots the
round-robin alone reaches every shape and value ranking is not under test at all. That is asserted
in `test_the_fixture_actually_discriminates`, because two earlier drafts of this fixture did not
discriminate - one collapsed 465 URLs to 465 shapes (letters are not normalised, digits are), and
the first execution test counted 477 "swept endpoints" on a 465-endpoint surface because
`run_xpath`/`run_ldap`/`run_ssi` are ALSO dispatched by the later HTML-page pass, which this budget
does not govern. The marker is now `run_sqli`, which only the parameterized sweep dispatches.

## The SECOND bound - a count is only a time bound if every endpoint costs the same

A count cap alone is why this ticket collides with the benchmark at all, and the collision is not a
bookkeeping problem, it is a real property of the fix:

    MEASURED, local lab      : 1.1 s per URL for the eight HTTP engines (agent.py:4240 comment)
    MEASURED, operator's target: ~6 min per endpoint (Shopify, Cloudflare-fronted)
                               -> a 300x spread

Any single count is simultaneously too small for the fast target and too large for the slow one.
`SWEEP_WALL_BUDGET_S` (env `BBH_SWEEP_BUDGET_S`, default 14400 = 4 h, 0 disables) is denominated in
the thing that actually ran out. At the measured costs 4 h buys ~40 endpoints on the slow target and
never fires at all on the lab. It is checked BETWEEN endpoints, never mid-endpoint - a half-probed
endpoint is the "failed attempt reported as a clean result" Q-093 forbids - and exhausting it emits
a `degraded` event with `reason: "sweep_wall_budget_exhausted"`, adds the untested remainder to
`_sweep_budget["declined"]` and records `_sweep_budget["timed_out"]`.

`_sweep_clock = time.monotonic` is a module-level indirection purely so the deadline is testable
with a fake clock instead of a four-hour test.

**This is the lever that lets the operator resolve the benchmark collision without a code change**:
`BBH_SWEEP_TARGETS=700 BBH_SWEEP_BUDGET_S=14400` gives wp3's count on a fast lab while still being
unable to run for two days on a slow target.

## Mutants killed - the deadline

| mutant | change | killed by |
| --- | --- | --- |
| M6 no-deadline | the wall-clock check replaced by `if False:` | `test_a_slow_target_stops_at_the_wall_clock_budget_and_says_DEGRADED` |
| M7 silent-deadline | deadline fires, the `degraded` event is not yielded | same |
| M8 always-fires | deadline fires after 3 endpoints regardless of the clock | `test_a_fast_target_never_trips_the_wall_clock` + both bounded/negative-control tests |

M8 is the one that matters: it is the shape of "a bound that quietly shrinks an ordinary
engagement", and it is caught by the negative controls rather than by the bound's own test.

## THE ONE RED I AM LEAVING, deliberately, in a file I do not own

    $ docker run ... pytest tests/test_sweep_targets.py ... -rfE
    1 failed, 50 passed, 7 skipped in 14.89s
    FAILED tests/test_sweep_targets.py::test_the_default_cap_is_the_module_budget_and_the_call_site_passes_it

    def test_the_default_cap_is_the_module_budget_and_the_call_site_passes_it():
        assert agent_mod.sweep_targets.__defaults__[-1] == agent_mod.SWEEP_TARGET_CAP     # PASSES
        assert agent_mod.SWEEP_TARGET_CAP >= 200, "a budget below the surface of a real app is the old bug"
    E   AssertionError: assert 40 >= 200

`agent/tests/test_sweep_targets.py` is not in my write list, so I did not touch it.

**This is a head-on contradiction between Q-019 and Q-113, not an accident.** Q-019 concluded "a
budget below the surface of a real app is the old bug"; Q-113 MEASURED that a budget the size of a
real app's surface is a run that cannot finish, and that the operator held the same findings at 5%
of it as at 15%. Both cannot ship. The newer claim has a measurement behind it; Q-019's `>= 200` is
an inference, and it is the assertion that has to move.

I considered and REJECTED the alternative: keep `SWEEP_TARGET_CAP >= 200` and put the real bound in
a second constant applied at the call site. That is precisely the defect Q-019 existed to fix - a
budget nobody can see from the place it binds - so dodging the assertion would reintroduce the bug
the assertion protects. Leaving it red and reporting it is the honest option.

PATCH FOR THE OWNER OF `agent/tests/test_sweep_targets.py` (one line, do not delete the assertion -
re-aim it):

    -    assert agent_mod.SWEEP_TARGET_CAP >= 200, "a budget below the surface of a real app is the old bug"
    +    # Q-113 REPLACES Q-019's floor with a CEILING. MEASURED on the operator's Shopify engagement:
    +    # 465 endpoints at ~6 min each is 46 h, and the findings at 5% were the findings at 15%. A
    +    # budget the size of a real app's surface is a run that cannot finish. The floor stays only as
    +    # a guard against the ORIGINAL bug, a cap of 20.
    +    assert 25 <= agent_mod.SWEEP_TARGET_CAP <= 60, "the sweep budget is no longer an engagement bound"
