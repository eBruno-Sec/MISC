# Apolaki QA — Browser Intelligence Engine build (2026-08-08)

Scope of this pass: build + integrate the Browser Intelligence Engine (#124), then verify the whole
platform still composes. Everything below is a result that was actually executed; where something was not
proven, it says so.

---

## 1. What shipped

| # | Slice | Technique id | CWE | Commit |
|---|-------|--------------|-----|--------|
| 1 | Runtime persona-swap BOLA | `browser_persona_bola` | CWE-639 | 914b80b |
| 2 | Client-side control surface | `client_side_authz` | CWE-602 | 914b80b |
| 3 | Route-interception identity-param tamper | `client_supplied_identity_param` | CWE-639 | c248927 |

`agent/bie.py` (~1,000 lines), `agent/tests/test_bie.py` (41 tests). Playwright + chromium were already in
the agent image, so no new dependency.

## 2. Test results

| Check | Result |
|-------|--------|
| Full suite, baked `python:3.12` image | **1106 passed, 0 failed** |
| BIE unit tests | 43 passed |
| Orchestration audit | 41 gated + 28 always-on, **0 islands** |
| Technique registry | 70 techniques |
| Endpoint sweep (from OpenAPI, 113 routes / 72 GET) | 64 ok · 8 expected (need a caller-supplied id) · **0 defects** |

No CI exists for this repo; the baked agent image is the bar, per the ship gate.

## 3. Live proof (real execution path, not inspection)

**Mission e33c1c96** — authenticated deterministic scan of Juice Shop through the real API:

- The persona artery's step 5e fired BIE on its own proven persona pair.
- The candidate came from **observation**: persona A's browser fetched `/rest/basket/6`, persona B's
  fetched `/rest/basket/7`. The swap changed only the id — this is the spec's canonical example, not
  id-spraying.
- **1 cross-user read CONFIRMED**, and it was the mission's only confirmed finding.
- Negative controls at confirmation time: anonymous `401`, implausible-id returned a different body.

Verified hop by hop:

| Hop | Evidence |
|-----|----------|
| Planner → BIE | artery step 5e invoked `confirm_browser_persona_bola` on the proven pair |
| BIE → Graph/state | 5 runtime observations added as `runtime:*` capabilities |
| BIE → shared ledger | 263 entries recorded as `engine="browser"` (so they are in the one HAR) |
| BIE → Evidence | PoC bundle carries `browser_evidence` + steps + replay script + screenshots |
| BIE → Report | HTML renders "Browser runtime proof" with embedded before/after PNGs |
| BIE → UI | Assurance panel row renders live from `/report/{id}/json` |

## 4. Defects found and fixed during this pass

1. **Shared wire sink destroyed persona attribution.** All three browser contexts wrote to one request
   list, so "which persona's browser made this request" — the entire basis of the cross-user hypothesis —
   was lost. Fixed: per-persona sinks.
2. **Control surface enumerated an empty DOM.** Phase 1's screenshot capture navigated the attacker page to
   a raw JSON endpoint; phase 2 then read the control surface from a page with no controls and reported a
   silent zero. Fixed: controls are read while the personas are still on application pages, accumulated
   across routes.
3. **The platform's own proof gate demoted the strongest evidence.** The BIE finding omitted `impact`, so
   `proof_schema.demote_unproven` downgraded a `confirmed` cross-user read to a `lead` in the report while
   the database still said `confirmed`. This is the gate working correctly and the producer being wrong.
   Fixed in both producers, plus a regression test asserting every BIE confirmation satisfies the proof
   contract. **Generalisable lesson: any new access-control producer must satisfy `proof_schema` or its
   findings are invisible in the report.**
4. **Fixed sleeps.** Replaced with condition-based waits (see §6).
5. **Phase-3 trigger page.** Route interception could not see the app re-issue a request because the page
   had been parked on an API URL; now an application page is re-driven first.

### Regression proof for defect 3

**Mission d2a651ca**, run on the rebuilt image after the `impact` fix, end to end:

```
DB     -> confirmed   CWE-639   impact set: True
REPORT -> confirmed   CWE-639   proof_gap: None      (was "lead" before the fix)
ARTERY -> BIE ran, 1 confirmed, candidate from observation
UI     -> Findings posture: Confirmed 1              (was 0 before the fix)
```

UI driven in a real browser (load mission → Assurance panel), **0 console errors**.

## 5. Honest limitations

- `client_side_authz` and `client_supplied_identity_param` carry **`validated_on: []`**. Both are
  unit-proven and both execute live without error, but neither has been confirmed by a lab yet:
  - Juice Shop's Angular **removes** privileged controls from the DOM rather than hiding them, so there is
    nothing to enumerate and phase 2 correctly reports zero. Routes that exist only in the JS bundle are
    the static collectors' job; the two views compose and neither pretends to be the other.
  - Juice Shop identifies objects by **path** id, not by an identity query parameter, so phase 3 correctly
    finds zero candidates there.
  Confirming these needs a lab that hides a privileged control with CSS, and one that passes an identity
  parameter in the query string.
- Phase 3 records its own provenance honestly: `route-interception` when the app re-issued the request and
  it was rewritten in flight, `in-page-fetch` when it did not and the mutated request had to be issued from
  inside the page — a weaker claim, so it is named rather than blurred.
- Screenshots embed as base64 in the HTML report, which grows it (110 KB for one finding).

## 6. Determinism

The Playwright books call `wait_for_timeout` an anti-pattern; every fixed sleep is gone from `bie.py`.
Navigation registers `expect_response` for the app's real object request **before** navigating, then
settles on `networkidle`. The settle **reason** is recorded as evidence (`networkidle+object-response`)
instead of hiding a magic number.

Those books also devote chapters to AI/Copilot/MCP-driven test generation. Those are **rejected by policy**:
generation may involve a model, confirmation never does. The oracle stays deterministic.

## 7. Queue completion (second pass)

The six gaps the book cluster surfaced are closed, except one that was deliberately declined.

| Gap | Outcome |
|-----|---------|
| Route-interception mutation | shipped (phase 3) |
| Object keys beyond id-shape | shipped — detection is now observational, so username/slug-keyed APIs are covered |
| Browser-driving failure taxonomy | shipped — 9 classes, retryable vs terminal, `click_intercepted` reported as a clickjacking **signal** |
| Playwright trace in the PoC bundle | shipped — frozen only on a confirmation; 268 KB artifact live-verified |
| `routeFromHAR` retest | shipped **as what it honestly is** (below) |
| Page-Object flow model | shipped as flow **recording**; flow **driving** declined (below) |

**Second lab, and the oracle earned its keep.** On VAmPI the attacker's request returned the owner's
object verbatim — the exact shape a scanner reports as BOLA — but the anonymous control returned the
identical body, so it was rejected as public data. Candidate formed by the new observational detection,
false positive refused by the oracle.

**What a HAR replay is not.** Replaying a HAR as the network layer reproduces the *recording*, so it can
never prove a bug still exists. It is a demonstration (show a client the exploit without touching
production) and a frozen baseline — never a verification. Only a live re-send decides OPEN/CLOSED. That
sentence lives in the code, with a test asserting the docstring keeps saying it.

What *did* become possible: access-control findings are inconclusive in `retest.plan` for want of a
persisted request, and a BIE finding carries one, so BIE findings are now auto-retestable. Conservative in
one direction on purpose — a 200 whose body merely changed stays INCONCLUSIVE, because ordinary data churn
looks exactly like a fix and a false "closed" is the worst thing a retest can produce.

**Declined: flow driving.** Recording the route a user takes needs no clicking, and is shipped. *Driving*
a flow by clicking is state-changing, so it must be operator-gated — and a driver that can never auto-fire
would be precisely the island the doctrine forbids. Building it needs the HITL design first; it is not
worth a half-wired engine in the meantime.

## 8. Guardrails, unchanged

Only safe methods auto-fire (GET). State-changing controls become operator leads and are never auto-clicked.
Every URL passes the caller's scope gate. Session secrets stay server-side — evidence carries cookie and
storage **names** only, and `redact_headers` masks authorization material. No DoS, no credential-brute loops.

---

# Session 2 — book-driven implementation (#125)

## New standing gates

Three gates now exist that catch classes of failure the test suite cannot:

| Gate | Command | Catches |
|------|---------|---------|
| Mutation | `python agent/mutation_gate.py` | a false-positive guard that no test defends |
| Dead code | `deadcode_gate.scan()` (in the suite) | a function with no caller — unwired engine or superseded duplicate |
| Bake drift | `sh scripts/bake_drift_check.sh` | running container holding code that was never baked |

`make ship-gate` runs bake-drift + suite + mutation gate together.

**Why each exists — all three were written after the failure they prevent actually happened:**

- The mutation gate's prototype found `blind_benchmark._has_proof` accepting evidence-free findings; every
  benchmark number Apolaki had reported could have been silently inflated.
- The dead-code gate found `dom_trace.trace_param`, a complete tracer duplicating the live async engine
  and emitting identical families — a trap waiting for someone to call the wrong one.
- The bake-drift gate was written the day five engines and six techniques existed only inside the running
  container. Git had them; the image did not; a `docker compose up` would have reverted the platform with
  no error and a green suite.

## Clean-clone verification (mandatory, performed twice)

`git clone` → `docker build agent/` → run, with nothing copied in:

| Check | Result |
|-------|--------|
| Full suite | **1251 passed, 0 failed** |
| Mutation gate | **12/12 mutants killed** |
| Techniques / islands | **80 / 0** |
| Dead-code gate | **passed** |
| Dependencies | hypothesis + playwright resolve from `requirements.txt` |
| Config | `.env.example` tracked; all 22 compose vars have defaults, so a clone runs with no `.env` |

## Capability honesty

The report now carries **"What This Assessment Could Not Test"**. On a default box that is nine
vulnerability classes across three unconfigured capabilities. This closed a real misreading: the blind
benchmark's missed XXE was never an engine weakness — `BBH_OOB_BASE` was unset, so the class was
untestable and the report said nothing at all.

## Natas (authorized)

Levels 0–4 solved via general techniques. Four map to engines Apolaki already has. Two outputs:

- **Fixed:** credentials in source comments. Natas 0 serves the password in an HTML comment;
  `scan_secrets` missed it (no vendor-shaped token) and `scan_comments` missed it (no todo/fixme keyword).
  New `scan_comment_secrets` closes the gap between them, with placeholder filtering and a regression test
  for the `//`-inside-`http://` false positive that the first live run produced.
- **Logged gap:** authorization decided by a client-controlled header (Natas 4 uses `Referer`). No engine.

---

# Pass 3 — effects model, planner search, mutation-gate recovery

Two commits: `fd463a8` (T6/T8/T10) and `9eaffed` (mutation-gate recovery).

## What the analysis got wrong

The reconciled MoreBooks analysis said Apolaki "has no effects model". That was imprecise in a way that
mattered. Effects **did** exist — `service_router._PACKS` `enables` lists and free-form
`state.add_capability` strings. The real defect is narrower and far more fixable:

> **Preconditions and effects spoke different languages.**

Preconditions use the 17-term `technique_planner.OBSERVATIONS` vocabulary. Effects used ad-hoc terms
(`arbitrary_file_read`, `ot_read`, `bmc_takeover`) that no precondition could ever consume. Nothing
chained because nothing an engine *produced* was expressible as something another could *require*.

Declaring effects in the precondition vocabulary is the entire fix. Measured result on the shipped
registry: **13 engines with effects, 50 chains, 5 ordering conflicts** — none of which the planner could
previously see.

## What shipped

| Module | Role |
|---|---|
| `engine_descriptor.py` | One record per engine: preconditions, effects, negative effects. Validates every effect is a real observation. |
| `effect_search.py` | BFS forward search — goal test + successor, the two thirds of *Automated Planning* §4.2 with no prior representation. |
| `POST /orchestration/reachability` | Serves the search. |
| `GET /orchestration/audit` (extended) | Serves the effects layer alongside the no-island audit. |
| Orchestration UI tab | The no-island north star had **no UI at all**. Now it does, plus an interactive reachability explorer. |

Additive by construction: `plan_techniques` and `_PRECONDITIONS` are untouched, so no answer Apolaki
already gave can change.

## Defects found this pass

| # | Defect | How it was caught | Why it mattered |
|---|--------|-------------------|-----------------|
| 1 | `find_hidden_route` given an `establishes` — but it is a lab-local catalog entry with **no executor and no gate** | own contract test | tells the planner a capability is obtainable by an action it can never take |
| 2 | `breaks()` reported an engine breaking **itself** (`weak_password_reset` deletes the login it consumed) | synthetic test | true but useless for ordering; buried the five real conflicts |
| 3 | Among equal-length plans the search returned whichever sorted first | live run against the shipped registry | recommended a plan silently assuming configured credentials over an equally short fully evidence-gated one |
| 4 | Mutation gate: a crashed run leaves source weakened; next run reports *"guard changed, mutant is stale"* | running the gate | the diagnostic tells the operator to update the **mutant**, cementing the weakened guard — gate then passes while defending nothing. `make mutation-gate` uses `docker exec` against the **live agent**, so the running scanner keeps the disabled guard until rebuild. |

Defect 3 is the one worth remembering: it only appeared against real data. Every synthetic test passed.

## Test results (exact)

| Check | Result |
|---|---|
| Full suite | **1334 collected, all pass** (was 1293; +39 effects model, +2 gate recovery) |
| `test_engine_descriptor.py` | 12/12 |
| `test_effect_search.py` | 27/27 |
| `test_mutation_gate.py` | 6 pass, 1 skipped (full gate is env-gated) |
| Mutation gate (full, on the baked image) | **12/12 mutants killed, passed** |
| Dead-code gate | passed — `unused: []`, `stale_allowlist: []` |
| Orchestration audit | **0 islands**, 41 gated / 40 always-on |
| Bake drift | `bake OK — running container matches the baked image (162 modules, 82 techniques)` |
| Clean clone (4th) | fresh `git clone` of `fd463a8`, full suite **EXIT=0** |

## Live verification (not inspection)

Against the running service after `docker compose up -d --build agent`:

```
obs={serves_js}  ->  applicable now: exposed_files_harvest, permissive_crossdomain,
                     reverse_tabnabbing, target_intel_harvest, weak_session_token
                     credentials_exposed  1 step   exposed_files_harvest
                     sql_error_seen       UNREACHABLE  (needs has_search_param)
obs={has_login}  ->  goal=authenticated   soft_deleted_login   assumes=[]
obs={}           ->  goal=authenticated   browser_persona_bola assumes=[browser_persona_bola]
```

The `sql_error_seen` result is the honest-exhausted-path answer, not a gap. The `assumes` split is
defect 3 fixed: with evidence the search picks the gated plan; with none it falls back and *says so*.

UI verified in-browser: Orchestration tab renders 41/40/0/50/5, reachability picker renders all 17
observations, plans and conflict tables populate.

## Honest limits, stated rather than hidden

- **T7 is PARTIAL by design.** `/orchestration/audit` and the UI read the descriptor, but the live routing
  tables are **not** generated from it. That is the only step that can change scan behaviour, so it earns
  its own reviewed change (task #28).
- **Always-on engines declare no observations**, so search treats them as applicable everywhere. Plans
  routed through one carry an `assumes` list rather than pretending the dependency is evidence.
- **13 of 82 engines have effects.** Conservative on purpose — an over-declared effect makes the planner
  chase a capability it does not have, which is worse than no model.
- **`planner_uses_effects: False`** is reported by the endpoint and shown in the UI. The chains are
  visible; the mission planner does not yet act on them.

## Integration QA — live scan after the change

Mission `cda5972b`, VAmPI (`vampi:5000`), deterministic, active, unauthenticated. Full pipeline
recon → enum → probe → report.

| Signal | Result |
|---|---|
| Completion | `status: complete`, `degraded: null` |
| Report integrity | `ok: true` |
| Findings / leads | 0 confirmed, 1 informational lead |
| Property coverage | 13 confirmed-safe, 0 vulnerable, 2 blocked, 18 not-tested (39.4% tested) |
| Persona artery | `ran: false` — no credentials configured |

**What this does and does not prove.** It proves the pipeline still composes end to end after the change:
nothing crashed, the report generated, integrity held, coverage computed, and negative results were
recorded as *confirmed-safe* rather than as silence. It does **not** demonstrate detection capability —
the artery did not run, so the cross-user BOLA path VAmPI is known to expose was never exercised. An
unauthenticated active scan is leads-by-design; reading 0 findings here as "VAmPI is clean" would be
exactly the WYSIATI error the capability-preflight section exists to prevent.

## API surface regression

114 routes / 72 GET / 43 POST. Both new endpoints registered. Every parameterless GET swept:
**0 non-200**.

## A fifth defect, found by self-review after the tests were green

`plan()` returned `unreachable` when `MAX_EXPANSIONS` was hit — *even if a valid plan had already been
found*. A false negative is the worst answer a planner can give: it says "no path exists" when one is in
hand. Now the found plan is returned with the bound disclosed in `reason` ("may not be shortest"). Two
tests pin it, including a negative control that the bound must not start inventing plans.

Worth noting how it was caught: every test passed. It took re-reading the loop against the question
"what does each early return discard?" The first attempt at the test did not even trip the bound — the
search finished normally — so the test had to be rebuilt around the exact interleaving where the action
that reaches the goal is expanded first and the bound trips on the next one.

## A sixth defect — found because a test was too slow

`mutation_gate.run(mutants)` used `mutants or MUTANTS`. An **empty list is falsy**, so a caller asking for
*no* mutants silently got the full gate: twelve complete suite runs. One of the new recovery tests passed
`[]` and quietly turned the ordinary test suite into the slow gate — noticed only because the suite stopped
finishing in its usual time.

Fixed to `MUTANTS if mutants is None else mutants`, with a test asserting an empty list runs nothing. The
recovery test went from minutes to **0.03s**.

This is the second time in this session that a falsy-coalescing default hid a behaviour change, and both
were invisible to a green suite. Worth treating `x or DEFAULT` as suspect whenever the empty value is a
meaningful input.

### The recovery fix, validated against a real crash

It did not stay hypothetical. A stray test container was killed while a mutant was applied, and the exact
predicted state appeared on disk:

```
agent/bie.py         MODIFIED   -- if _b(shell) == _b(persona):  ->  if False:
agent/bie.py.mutbak  untracked  -- holding the original
```

The disabled guard is the SPA-shell false-positive check in `judge_client_side_authz`. Left in place,
Apolaki would report the application shell as a leaked privileged control — a false positive in the exact
class the guard exists to prevent. And the *next* gate run would have called the mutant "stale".

`recover()` restored it byte-identically (`recovered: ['bie.py']`, `git status` clean, no `.mutbak`). The
fix was written from reasoning about the failure mode and then confirmed by the failure mode occurring.

---

# Pass 4 — T7 complete: the descriptor is now the source of truth

`engine_descriptor` now **owns** `OBSERVATIONS`, `PRECONDITIONS` and `ALWAYS_ON`; `technique_planner`
re-exports them under the same names. The dependency, which previously ran planner → descriptor, now runs
descriptor → planner. `engine_descriptor` no longer imports `technique_planner` at all.

Every consumer is untouched (`plan`, `orchestration_audit`, the graph projection, `/orchestration/*`,
`main.py`) because the names and the objects are the same. Verified by identity, not equality:

```
tp._PRECONDITIONS is ed.PRECONDITIONS   ->  True
```

`is`, deliberately: an equal-but-separate copy would be a second source of truth, which is the exact thing
the descriptor exists to remove. A test pins the identity so a future edit cannot fork them. Confirmed
separately that nothing anywhere mutates these tables, so sharing a reference is safe.

## Why a snapshot test, specifically

The safety of a pure refactor rests on one claim: **routing is byte-identical.** Every other test asserts
*properties* of the tables (every precondition uses a known observation, every engine is reachable), and a
refactor that silently altered a precondition would satisfy all of them. So the contents are pinned
against `tests/t7_tables_snapshot.json`, captured from the running system immediately before the move.

It is a change-detector, not a correctness oracle: a legitimate future change SHOULD fail it, and the
snapshot gets regenerated in the same commit so the diff shows both halves.

| Check | Result |
|---|---|
| Observation vocabulary | 17, unchanged |
| Precondition gate | 41 entries, unchanged |
| Always-on reasons | 40 entries, unchanged |
| Planner re-exports the same objects | `is` holds for all three |
| Descriptor imports the planner | no (asserted against source, docstring excluded) |
| Islands | 0 (41 gated / 40 always-on) |
| Selection from evidence | same techniques for `{has_login}`, `{has_api, serves_js}`, `{authenticated, has_login}`, `{}` |
| Empty evidence | selects nothing |
| Circular imports | none — `main.py` imports clean |
| Dead-code gate | passed |

## What the effects model can and cannot reach — measured, not assumed

With the descriptor as source of truth this became a straightforward query, and the answer bounds how much
T8's search can ever buy:

```
observations NO engine can establish (recon must supply them):
  has_coupon, has_file_upload, has_login, has_redirect_param, has_search_param,
  has_sensitive_route, has_versions, has_workflow, has_xml_input, reflects_input,
  saml_sso_detected, serves_js                                          -- 12 of 17

engine-producible: has_api, has_object_id, authenticated, credentials_exposed, sql_error_seen  -- 5
engines requiring more than one observation: session_fixation (has_login + authenticated)      -- 1
```

**Consequence, stated plainly:** most plans the search returns are one step long, because only 5 of the 17
observations are things an *engine* can create — the other 12 are properties of the target that recon
either finds or does not. The search is therefore not a deep escalation planner today; it is an accurate
one-hop-and-occasionally-two-hop reachability answer plus the ordering-conflict warning. Deeper chains
require more engines declaring effects, not a better search algorithm.

**No dead engines:** every precondition set is satisfiable, and the only multi-precondition engine
(`session_fixation`) needs `has_login` (recon) plus `authenticated` (six engines establish it). An
unsatisfiable precondition set would be a permanently unreachable engine, which the no-island guard cannot
detect — it only checks that a gate *exists*, not that it can ever *open*.

---

# Pass 5 — T5: design-level remediation (BSRS Ch.5/6/8/9)

Apolaki already answered "how do I fix this bug" three ways: a tactical one-liner (`report._FAMILY_FIX`),
copy-paste secure snippets (`remediation.CATALOG`), and a Fix Now / Fix If / Strengthen band. All three
are about the DEFECT. BSRS is a design book, and the gap it exposes is the set of questions asked *after*
the patch, none of which any layer answered:

| Field | BSRS chapter | The question |
|---|---|---|
| `structural` | Ch.5 Least Privilege, Ch.6 Understandability | what boundary or construction removes the CLASS, not the instance |
| `blast_radius` | Ch.8 Resilience | what bounds the damage when the fix is bypassed |
| `recovery` | Ch.9 Recovery | **assume it was already exploited** — what now |
| `verify` | — | how to prove the fix landed, naming the partial-fix trap for that class |

`recovery` is the one with no equivalent anywhere in the platform and the most likely to be acted on: a
confirmed finding is evidence the door was open, and the report never previously said what that implies
for the data behind it. "You have SQLi" without "treat the credential store as disclosed" describes a bug,
not an incident.

15 families covered — the ones with confirming oracles and real exploitability. Families with no
meaningful design-level answer get **no entry**, with the reason recorded in `NO_DEPTH_REASON` so the
omission is a decision on the record rather than an oversight.

## The tests are about quality, not just correctness

The failure mode for a remediation section is not being wrong, it is being FILLER — advice that applies to
everything, or the tactical fix restated at greater length. That trains readers to skip the section
including the parts that matter. So the load-bearing tests are:

- **no entry may paraphrase the tactical fix** for the same family (content-word overlap < 60%)
- **every entry must be specific to its family** (per-family concreteness markers)
- **`recovery` must read as response, not prevention** (asserted against a response-posture vocabulary)
- **every omission must carry a recorded reason**

The paraphrase check **caught two of my own entries** — `path_traversal.structural` at 60% and
`deserialization.structural` at 62% overlap. Both were rewritten to carry only what the tactical line does
not: OS-level confinement so application correctness is not the sole boundary, and treating the parser as
a trust boundary to be moved rather than a blocklist to be maintained. A reviewer would very likely have
passed both.

## Integration — both renderers

The markdown and HTML reports are **separate renderers**. Shipping this in one only would give two
different answers to the same question depending on export format, so both carry it, and both are tested.
Family resolution reuses `report._family_of`, so a finding carrying only a CWE still resolves (verified:
CWE-639 with no `family` field renders the IDOR block).

| Check | Result |
|---|---|
| Module tests | 17/17 |
| Markdown report, real generation | design block + recovery line present |
| HTML report, real generation | design block + recovery line present |
| CWE-only finding | resolves via `_family_of` |
| Uncovered family | renders nothing in both renderers |
| Malformed finding | neither renderer raises (a lost report is worse than a thin one) |
| HTML escaping | asserted to go through the caller's escaper |

---

# Pass 6 — a declared-reachable engine that was not reachable

## How it surfaced

Checking whether `probe_selection` (T3) had a production caller turned up something worse. The dead-code
gate reported `unused: []`, but three of its five functions had no caller outside tests. The gate matches
**bare function NAMES across the whole corpus**, and `coverage` / `describe` collide with same-named
functions in `main.py`, `report.py`, `wstg_catalog.py` and `stealth.py` — so unrelated code made them
look used.

Measured: **90 function names are defined in more than one module** (`finding` x30, `analyze` x20,
`probe` x11). A module-qualified, import-alias-aware probe finds **52 candidate-unused functions** where
the gate reports 0. Two distinct blind spots:

1. **Name collisions** — any of those 90 names can be masked by an unrelated definition.
2. **Test usage counts as production usage** — a function only its own test calls passes the gate.

Those 52 are heuristic **candidates, not proven dead**. Bulk-deleting them would violate the rule that
obsolete code goes only after it is *proven* unused. Filed as its own task.

## The serious one

Spot-checking three of the 52 found `graphql_tool.build_query` referenced **only in prose** — in
`techniques.py` and in the `ALWAYS_ON` reason itself:

> `graphql_argument_injection`: *"run_graphql introspection enumerates arguments; the existing injection
> engines consume them via graphql_tool.build_query"*

Nothing called `schema_operations`, `injectable_arguments` or `build_query`. `_run_graphql` did endpoint
discovery, introspection, batching and the bogus-field probe, then stopped. **The technique was reachable
on paper only, and I wrote the paper.**

**Why the no-island guard could not catch it:** an `ALWAYS_ON` entry is accepted on the strength of its
stated reason, and the reason is prose that nothing verifies. The guard proves a technique is *declared*
reached; it cannot prove the declaration is true. 40 engines rest on that kind of promise. Same shape as
the earlier finding that the guard checks a gate EXISTS but not that it can ever OPEN.

## Fixed, and confirmed live

`Tools._graphql_argument_injection` now runs on the introspection response `_run_graphql` already has.
Safety properties are inherited rather than reinvented: queries only (mutations never auto-fired), textual
arguments only, values JSON-encoded so a payload cannot restructure the document. The oracle is
`sqli_tool.error_signatures` — already a baseline differential — plus a second benign control value, so a
server that errors on any unexpected input cannot manufacture a finding.

Live against DVGA (`localhost:42092`, local lab):

```
operations enumerated   : 19
injectable textual args : 8
mutations auto-included : 0          <- the safety property, verified not assumed
pairwise selection      : 32 cases cover 32/32 value pairs (100.0%)
CONFIRMED  pastes.filter  payload="');"  dbms=SQLite
confirmed: 1        (0 false positives; every other argument stayed clean)
```

A real SQLite injection through the GraphQL argument surface, from an engine that was unreachable an hour
earlier.

## An honest correction to my own T3 claim

The first live run used `max_cases=24` and reached only 75% pair coverage. Worse, the reasoning behind
using pairwise here was weak: **this grid has two factors, and for two factors pairwise IS the full
grid** — it buys no combinatorial saving. What `probe_selection` actually contributes here is that the
shortfall is *measured and printed* when the cap bites, which is the real problem T3 set out to fix. Cap
raised to 48 so a typical schema is covered completely, and the code comment now says this plainly
instead of implying a saving that does not exist.

Wiring `safety_label` into `describe()` also gave it its first caller, so the pruning class is now stated
in the Automated Planning §4.2.1 vocabulary rather than left to the reader:

> `Pruning class: declared — every value pair is covered; 3-way interactions are not.`
