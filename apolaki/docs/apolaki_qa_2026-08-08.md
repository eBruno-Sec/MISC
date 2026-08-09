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

## The systemic fix: ALWAYS_ON reasons are now checked against the code

The GraphQL island was one instance of a class. `engine_descriptor.verify_always_on()` now extracts every
code identifier an always-on reason NAMES and requires it to be referenced by code that runs — with
`techniques.py` and `engine_descriptor.py` excluded, because those are prose and a mention there is
exactly how the false promise survived.

**Result across all 40 reasons: 39 identifier references checked, 0 unwired.** GraphQL was the only
genuine break, and it is fixed.

Two false alarms during development, both worth recording because each would have destroyed trust in the
guard:

- **13 ICS engines reported broken.** A tool is REGISTERED under a bare string (`"run_service_pack"`) and
  IMPLEMENTED as a private method (`_run_service_pack`). Treating those as different names flagged every
  service-pack engine. Fixed by normalising the leading underscore. Verified by hand first
  (`tools.py:2571`, dispatched from `agent.py:1376`) rather than trusting the tool that was under test.
- **`looks_like_chat_endpoint` and `run_header_trust` looked thin** at one reference each; both are real
  (`llm_tool.py:38` → `tools.py:7219`, and a registered tool plus `_run_header_trust`).

The lesson generalises: a guard's own false positives are as dangerous as its false negatives, because a
noisy guard gets switched off.

**Negative control, because a guard that cannot fail is not a guard.** Pointing a reason at
`bie.resolve_locator` — real, tested, no production caller — makes the check fail with the right message.
That is asserted as a test, not just run once.

Surfaced in `GET /orchestration/audit` (`reason_verification`) and in the Orchestration UI beside the
island count, so the property is visible rather than CI-only — the same treatment the no-island count got.

## The dead-code gate, fixed as a ratchet

`scan_qualified()` resolves usage through the actual import graph — module-qualified, alias-aware
(`import probe_selection as ps` → `ps.pairwise(...)` counts), `from`-import aware, and production-only
(a function its own test calls is *exercised*, not *wired*).

It ships **alongside** `scan()` rather than replacing it, as a ratchet:

| | count |
|---|---|
| bare-name `scan()` | 0 |
| qualified `scan_qualified()` | **47** (52 before this session's wiring removed 5) |

The 47 are **candidates, not proven dead** — some will be reachable through patterns the checker does not
model. Bulk-deleting them would be exactly the mistake the rule "remove obsolete code only after proving
it is unused" exists to prevent, and it is how a working engine gets removed. So the number is pinned:
**it may fall, never rise.** New dead code fails immediately; the backlog gets triaged deliberately.

A second test asserts the baseline is not slack (within 3 of the real count), because a baseline parked
far above reality silently permits regressions up to it.

**Performance note worth recording.** The first implementation was O(functions × files) — 1391 functions
across 166 files, ~231k regex passes — and blew past a two-minute test timeout. A module is only
reachable from files that import it, so indexing importers narrowed the inner loop from every file to a
handful: **5.4s, identical result.** A correctness check nobody can afford to run is not a check.

The blind spot is also demonstrated as an executable test rather than asserted in prose: two modules
define `helper`, only one is called, and the bare-name scan clears both while the qualified scan flags
exactly the dead one.

### Measured, not estimated

The `--durations` output made the cost concrete, and showed the new check is the cheap one:

```
BEFORE (six independent real-tree scans)
  55.91s  test_no_unexplained_dead_functions           }
  54.66s  test_the_allowlist_does_not_rot              }  legacy bare-name scan()
  54.01s  test_framework_invoked_functions_not_flagged }  ~55s each
  51.79s  test_the_scan_actually_finds_things          }
   5.21s  test_the_ratchet_holds                          <- the NEW qualified scan

AFTER (module-scoped fixtures, scans computed once)
  54.51s  setup :: scan()
   4.77s  setup :: scan_qualified()
```

Two observations worth keeping:

- **The legacy `scan()` is 10x slower than the qualified one AND less accurate.** The bare-name check is
  O(names x files) with no index — 1391 names against every file. `scan_qualified` resolves the import
  graph first and only searches files that import the module, so it is both cheaper and correct.
- **~162 seconds came off every full-suite run** by sharing the scans rather than recomputing them six
  times. That was pure waste, and it was invisible until something timed out.

---

# Pass 7 — triage found a SECOND unreachable engine, and it was mine

Working the 47 qualified-unused candidates (#30) surfaced three clusters. One is a correction to work
reported complete earlier in this same session.

## `run_header_trust` (T1) was never invoked

T1 shipped earlier today with a live Natas-derived design, a full implementation, and an ALWAYS_ON reason
reading *"run_header_trust on every in-scope origin + any denied path the scan met"*.

It was **registered** in the permission map and **implemented** as `_run_header_trust` — and its name was
never passed to `execute()` / `_exec_internal()`, nor present in the `CLAUDE_TOOLS` spec. Tool dispatch is
`getattr(self, "_" + tool_name)`, so a tool runs only when its NAME STRING reaches the dispatcher.
Unreachable by the deterministic path *and* the agentic path.

The contrast that made it provable:

```
run_transport_posture   in CLAUDE_TOOLS spec: False   in agent.py: True    -> wired (deterministic)
run_graphql             in CLAUDE_TOOLS spec: True    in agent.py: True    -> wired (both)
run_nmap / run_hash_id  in CLAUDE_TOOLS spec: True    in agent.py: True    -> wired (agentic)
run_header_trust        in CLAUDE_TOOLS spec: False   in agent.py: False   -> UNREACHABLE
```

**My reason-verifier passed it**, because `"run_header_trust"` appears as a key in the permission map and
the check counted any quoted occurrence. **Registration is not invocation.** The verifier now strips the
`PermissionLevel` registration line before looking for a reference, with a paired negative/positive
control: a registered-and-implemented-but-uninvoked tool must FAIL, and adding one real call site must
flip it to pass.

Fixed by `_do_header_trust`, mirroring `_do_transport_posture`: in-scope origins plus discovered
sensitive routes, read-only GETs, best-effort so a failure degrades to a no-op rather than a broken scan.
No separate denied-path tracker was invented — `_run_header_trust` establishes its own baseline per URL
and recognises a denial itself, so feeding it discovered routes is sufficient and avoids a second source
of truth. (A first draft read `self.tools.denied_paths`, which does not exist; `getattr` would have
returned `None` silently — dead intent that looks like wiring, the very thing being fixed.)

## `saml_tool` is doubly disconnected

`saml_signature_bypass` is gated on `saml_sso_detected`, which IS derived (from `saml`/`/sso`/`/acs`
path keywords). `execution` defaults to `"auto"`, so it is auto + oracle + transferable and the
orchestration audit counts it as wired. But:

1. nothing calls `saml_tool` — its only mention outside itself is prose in `techniques.py`; and
2. nothing ever captures a SAMLResponse to feed it, so even the analysis path has no input.

The module is well-built (zero-FP `confirm_bypass`, a safe `plan_leads` that makes no requests). Not
fixed in this pass — it needs a harvest step for the SAMLResponse parameter before an executor is
meaningful, which is its own change. Recorded rather than half-wired.

## `ics_fingerprint` is a superseded duplicate

`service_router` imports it but uses only its `PROTO_PORTS` constant. The live Modbus path is
`modbus_audit_tool`. Its six probe functions (`identify_protocol`, `modbus_read_device_id`,
`ethernetip_list_identity`, the two parsers, `is_read_only`) have no caller — the same shape as the
`dom_trace.trace_param` case this gate's own docstring already documents: a superseded implementation
sitting beside the live one, waiting to be called by mistake. Left in place pending proof it is safe to
remove; `is_write_frame` from the same module IS live and is the safety authority for OT writes.

## A third blind spot, and the right division of labour

Wiring `run_header_trust` did **not** change the qualified-unused count (47 → 47), and the reason matters:
both `scan()` and `scan_qualified()` walk `tree.body` only, so they see **module-level functions and no
class methods at all**. Apolaki's engines are overwhelmingly `Tools` methods (`_run_header_trust`,
`_run_graphql`, `_run_service_pack`), so the dead-code gate is blind to exactly the layer engines live in.

That is why neither unreachable engine was found by the gate. Both were found by following an ALWAYS_ON
reason to the code it names.

The honest division of labour, now explicit:

| Checker | Covers | Blind to |
|---|---|---|
| `scan_qualified()` | module-level helper functions | class methods; dynamic dispatch |
| `verify_always_on()` | engines named in an always-on reason | engines with no reason to check |
| `orchestration_audit()` | that a technique is *declared* reachable | whether the declaration is true |

Each catches what the others cannot, and none of them alone would have caught either island. Extending
the qualified scan to methods is worthwhile but is not a small change — method calls resolve through
`self`, so an AST-level receiver analysis is needed rather than a regex.

## Triage verdicts so far (#30)

Working the 47 candidates individually rather than in bulk. Each needs one of three verdicts: **wire it**,
**delete it after proving it unused**, or **allowlist it with a reason**. Progress:

| Candidate | Verdict | Basis |
|---|---|---|
| `graphql_tool.build_query` + `schema_operations` + `injectable_arguments` | **WIRED** | reachable-on-paper engine; live SQLite injection confirmed on DVGA |
| `probe_selection.pairwise` / `safety_label` | **WIRED** | pairwise now bounds the GraphQL argument grid; `safety_label` states the pruning class in `describe()` |
| `ssrf_tool.bypass_payloads` | **WIRED (as a new metadata variant)** | literal-address-only probing was a false-negative class |
| `saml_tool.*` (3 fns) | **RECORDED — needs a harvest step first** | nothing captures a SAMLResponse, so an executor alone would have no input |
| `ics_fingerprint.*` (6 fns) | **SUPERSEDED DUPLICATE** | live Modbus path is `modbus_audit_tool`; `service_router` uses only `PROTO_PORTS`. Do not delete blindly — `is_write_frame` in the same module IS live and is the OT write-safety authority |
| `waf_bypass_tool.pad` | **NOT A GAP — a second variant** | the live path pads inline via a SEPARATE `_pad` parameter; `pad()` pads WITHIN the payload's own parameter. Both are legitimate WAF-bypass shapes; only the first is exercised. Smaller coverage gap, not dead code |
| `wordlists.payloads_for`, `wordlists.seclists_available`, `security.validate_targets`, `service_router.is_ics_ot`, `dependency_intel.extract_script_srcs`, `xxe_tool.build_error_xml` | **ALREADY ALLOWLISTED** | present in `ALLOWED_UNUSED` with reasons; `scan_qualified` does not yet consult that list |

The `waf_bypass_tool.pad` case is worth generalising: **"has no caller" and "the capability is missing"
are different claims.** Three of the seven verdicts above turned out to be capability that exists by
another route. Checking which, before writing code, is what keeps the triage from becoming churn.

---

# Pass 8 — the report was under-reporting its own best engines

Verifying the header-trust wiring on a live Juice Shop scan (mission `5ebd704d`) produced a result I did
not expect. The mission log proves it ran:

```
info: "Header-trust: tested 6 target(s) for authorization decided by a client-controlled
       header (Referer / X-Forwarded-* / X-Original-URL)"
```

…and the report's tool ledger — the Methodology section's "tools executed" list — **does not contain it.**
Nor `run_transport_posture`. Nor `run_service_pack`. 35 tools listed, those absent.

Not truncation (869 log rows against a 4000 limit). The cause is structural:

- `_run_tool` (the model/deterministic path) **yields** `{"type": "tool_call", ...}`, and `main.py:2278`
  persists every yielded event. `_tool_ledger` is built from exactly those rows.
- `_exec_internal` — the gated dispatch for internal calls — **yielded nothing and logged nothing.**

So every engine dispatched internally was invisible in the report. All twelve:

```
confirm_authz_write          confirm_browser_persona_bola   confirm_create_object_idor
confirm_read_object_idor     run_authz_matrix               run_bfla
run_cloud_probe              run_exposure                   run_header_trust
run_service_pack             run_stored_xss                 run_transport_posture
```

That list is not peripheral. It is the **Browser Intelligence Engine, both BOLA oracles, the authorization
matrix, the transport-posture family and all thirteen ICS/service-pack techniques** — the work most worth
showing a client. A reader of the Methodology section would reasonably conclude none of it ran.

`_exec_internal` now writes `tool_call` and `tool_result`/`tool_error` rows directly (it is not a
generator, so it cannot yield), using the `count`/`output` keys `_tool_ledger` actually reads. Logging is
guarded both sides: a logging failure must never break a scan.

## A second defect, in code I wrote an hour earlier

While tracing this, my own `_do_header_trust` summary line was wrong:

```python
yield ... "Header-trust: tested %d target(s)" % min(len(targets), 6)   # counts TARGETS
```

It counted targets **queued**, not calls that **executed**, and every failure went to
`except Exception: continue` with nothing recorded. Had all six calls failed, the scan would still have
printed "tested 6 target(s)" — a silent total failure wearing the words of a successful pass. Now it
reports `tested N of M`, and on zero executions says so explicitly:

> *"Header-trust: DID NOT RUN on any of 6 target(s) — <reason>. Treat this class as untested, not as
> clean."*

Which is the same discipline as the capability-preflight section: **untested is not clean**, and a
summary that cannot distinguish the two is worse than no summary.

---

# Pass 9 — the method blind spot, closed (#32)

`scan()` and `scan_qualified()` walk `tree.body`, so they see **zero class methods**. This codebase keeps
**321 methods in classes, 147 of them in `ToolRegistry`** — every engine Apolaki runs. Neither
unreachable engine found today was caught by a dead-code scan; both came from following an ALWAYS_ON
reason to the code it named.

`scan_methods()` closes it. Resolution is conservative by design (a false negative costs nothing; a false
positive costs someone's afternoon): `self.name`, any `.name` attribute access, or a string literal
matching the name — the last because dispatch is `getattr(self, "_" + tool_name)`, and without that rule
all 147 tool methods would be flagged as noise.

**53 → 20 → 14, and 39 of the 53 were my own checker being wrong:**

| Fix | Removed | What was wrong |
|---|---|---|
| lookbehind before the dot | 33 | `(?<![\w])\.name` rejects the ordinary `self.tools.execute(...)` — the char before the dot is a word char. It flagged `ToolRegistry.execute`, the dispatcher itself |
| base-class overrides | 6 | `_FormParser.handle_starttag` is invoked by `html.parser.HTMLParser`. Recognised by walking the real MRO, not a callback-name list that would rot |

A checker whose obvious false positives are that visible gets ignored wholesale — worse than not having
one. Both fixes are pinned by tests, including a negative control (a genuinely orphaned method must be
caught) and a string-dispatch control.

## What the 14 actually are

The interesting cluster is six `AssetGraph` methods — `plan_next`, `apply_result`, `add_enable`,
`enabling`, `mark_consumed`, `neighbors` — **called only by tests**.

`AssetGraph` turns out to have **two planning APIs**:

- `to_observations()` + `next_best_actions()` — used by `plan_graph_authoritative`. **Wired.**
- `plan_next()` / `apply_result()` / `add_enable()` / `enabling()` / `mark_consumed()` — a stateful
  plan → execute → feed-back-capability loop. **Tests only.**

That second loop is a capability-chaining planner, which is exactly what `engine_descriptor` +
`effect_search` (T6/T8) now do with declared effects and a searchable vocabulary. The graph loop reads as
the earlier attempt at the same idea.

**Verdict: record, do not wire.** Wiring it means choosing which planner is authoritative — a design
decision, not a cleanup, and the effects model is the better-specified successor. Deleting it needs the
same decision first. This is the `waf_bypass_tool.pad` lesson again: *"has no caller" and "the capability
is missing" are different claims*, and a third variant appears here — *"has no caller because something
better replaced it"*.

---

# Pass 10 — SAML wired (#31), and the ratchet earned its keep

`saml_signature_bypass` was gated on `saml_sso_detected`, `execution` defaults to `auto`, so the
orchestration audit counted it wired. It was **doubly disconnected**: nothing called `saml_tool`, and
nothing ever captured a SAMLResponse to feed it. An executor alone would have had no input.

`saml_tool.harvest()` supplies the missing half — pure, no network. Two bindings, two places to look:
HTTP-Redirect (query string, base64 + DEFLATE) and HTTP-POST (hidden form input, base64). Only values
that `decode()` turns into real SAML XML are returned, so `?SAMLResponse=hello` cannot manufacture a
finding.

**A bug my own test caught immediately:** the first version used `parse_qs`, which form-decodes — and
base64 contains `+`, which form-decoding turns into a space. The payload was corrupted, `decode()`
returned nothing, and the **Redirect binding silently harvested zero while the POST binding worked.** A
partial failure that reads exactly like "this target has no SAML". Fixed by extracting the raw query
substring; `decode()` does its own unquoting.

`run_saml` is **PASSIVE** and auto-fires only harvest + analyse + `plan_leads` (which by construction
raises leads, never confirmations). The intrusive half — `wrap_assertion` + `confirm_bypass`, which
replay a tampered assertion to the SP — stays operator-gated and is now allowlisted with that reason.
Absence is reported as *"SAML assertion posture UNTESTED (not clean)"*, not as a pass.

## A test that checked prose instead of code

`test_the_intrusive_half_is_not_auto_fired` initially failed — because it matched the **docstring**
explaining why those functions are excluded, which necessarily names them. Checking code against prose is
the precise mistake that let `graphql_argument_injection` ship as reachable-on-paper. The test now strips
the docstring before looking.

## The ratchet caught me mid-change

Adding `harvest()` before wiring it pushed the qualified count 40 → 41 and **failed the suite** — exactly
the intended behaviour, on its first real opportunity. The fix was to finish the wiring, not to raise the
baseline.

```
40  →  41  (harvest added, unwired)     <- ratchet FAILED the build
    →  39  (harvest + plan_leads wired)
    →  37  (intrusive half allowlisted with a stated reason)
```

Baseline tightened to 37 at each step. This is the difference between a ratchet and a number: it only
ever moved down, and it refused a change that would have moved it up.

## Two allowlists, because the two scans disagree about "unused"

Putting the SAML justifications into `ALLOWED_UNUSED` broke `test_the_allowlist_does_not_rot`, and the
failure was correct. `scan()` counts a mention anywhere — including tests — as a use;
`scan_qualified()` requires a production caller through a resolved import. `saml_tool.confirm_bypass` is
therefore *used* to the first scan and *unused* to the second, so a shared allowlist is wrong for
whichever one disagrees, and the staleness check keeps flagging it forever.

Split into `ALLOWED_UNUSED` (bare names, `scan()`) and `ALLOWED_UNUSED_QUALIFIED` (keyed
`module.function`, `scan_qualified()`), with a test asserting the two never overlap — an entry in both
means the distinction was not understood and one of them will rot.

Final state of the three checkers:

| Checker | Sees | Result |
|---|---|---|
| `scan()` | module-level functions, bare-name match, tests count | 0 unused, 0 stale |
| `scan_qualified()` | module-level functions, import-resolved, production only | 37 (ratchet), 8 justified |
| `scan_methods()` | class methods — 321 of them, invisible to both others | 14 (ratchet) |

---

# Pass 11 — the Natas ladder (#33): 6/7 with zero level-specific logic

Natas is an unusually good benchmark because each level hides the NEXT level's password, so the oracle is
not a judgement call: a recovered value either authenticates to level N+1 or it does not.

**Result on the live ladder** (`POST /benchmark/natas`, authorized target):

```
natas0  SOLVED  engine:scan_comment_secrets
natas1  SOLVED  engine:scan_comment_secrets
natas2  SOLVED  recon@files/users.txt                 (directory index, one hop from a referenced asset)
natas3  SOLVED  recon@s3cr3t/users.txt                (robots.txt Disallow)
natas4  SOLVED  recon@ [Referer: http://natas5...]    (header-trust engine, T1)
natas5  SOLVED  recon@ [cookie loggedin=1]            (client-controlled boolean cookie)
natas6  no      no general engine surfaced a credential
```

**Two of those were earned by engines built earlier the same day.** `scan_comment_secrets` (from the
Natas 0 gap) takes levels 0 and 1. Level 4 falls to `header_trust_tool.expected_values_from_denial` —
the function that reads the values the REFUSAL ITSELF names. Natas 4 says *"authorized users should come
only from http://natas5..."*, which hands over the exact value needed. That engine was unreachable until
this session wired it; it now earns a level on a live external target.

## Disciplines, enforced in tests not prose

- **No level-specific logic.** `test_natas_ladder.py` asserts the module contains no hardcoded deep path,
  no level hostname, no `s3cr3t`-style tell. Everything that narrows the search comes from Apolaki's own
  general engines plus ordinary recon (robots.txt, referenced directories, depth-2 crawl).
- **No credentials in the repository.** The module carries no 32-char literal (asserted), the endpoint
  strips `next_password` from what it returns, and the runner writes only to gitignored `agent/data/`.
- **Honest ceiling.** Levels are bucketed surface / injection / session_logic / specialist, because a
  scanner missing a hash-extension forgery is a different fact from one missing a SQL injection.
  `blocked` (unreachable) is counted separately from `not_solved` (engines had their chance).

## Three self-inflicted defects, all caught

1. **Depth-1 recon** found the `files/` index but not `users.txt` inside it. A directory listing is one
   hop from its contents; depth-2 crawling is ordinary and fixed levels 2 and 3.
2. **The cookie probe read only the response BODY.** A `Set-Cookie` header is the ordinary place a server
   hands the client an authorization input — the probe could see half its own input surface. Level 5 fell
   immediately once headers were included.
3. **I truncated my own module.** A `partition`-and-rewrite dropped every function defined *after*
   `solve_level` — all five recon helpers. The endpoint failed with `name 'recon_targets' is not defined`.
   Same class as the near-miss on `graphql_tool.py` earlier: destructive rewrite instead of targeted edit.

## A bug worth remembering: an invisible character

After restoring the helpers through nested shell quoting, the cookie probe silently matched nothing.
`grep` showed the line as correct. The regex actually contained a literal **0x08 BACKSPACE** where `\b`
was intended — the shell had interpreted the escape:

```
repr: 'for m in re.finditer(r"\x08([A-Za-z_][A-Za-z0-9_]{2,20})\s*=\s*0\x08", source):'
```

A pattern that can never match, in a file that reads correctly. Fixed by lifting it to a named
`_BOOL_ZERO_RE` constant — a control character hidden inside a long inline regex is exactly what made it
invisible — and a repo-wide sweep confirmed no other file carries stray control characters.

**Standing lesson: do not write code through nested shell quoting.** Every escape passes through two
interpreters, and the corruption is invisible to `grep`.
