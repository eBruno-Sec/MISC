# Q-052 · Tier split — ACTIVE = payload-sending READ-ONLY, INTRUSIVE = state-changing

Lane: **Builder · tier-split**. Ticket **Q-052**, status DECIDED (docs/QUEUE.md:1125). This lane
IMPLEMENTS the decision; it does not re-open it.

Every claim below is **MEASURED** (command + real output) or **UNVERIFIED**. Written as the work
happens, not at the end.

---

## The decision being implemented

```
PASSIVE      observe only                                  (15 engines)
ACTIVE       requests + payload-sending READ-ONLY checks   (56 + the 31)
INTRUSIVE    STATE-CHANGING / destructive                  (the 9)
```
`active` = PASSIVE + ACTIVE. `full` = everything. The 9 stay behind the existing HITL gate and
`auto_approve`.

---

## BASELINE — MEASURED before any edit

```
$ docker run --rm --network apolaki_default -v .../agent:/app -w /app apolaki-agent \
    python /scratch/tiercount.py
TOTAL registered: 111
by tier: {'PASSIVE': 15, 'ACTIVE': 56, 'INTRUSIVE': 40}
selectable at passive: 15 of 111
selectable at active: 71 of 111
selectable at full: 111 of 111
NINE selectable at active: []
len(31 list) = 31  len(9 list) = 9
31 selectable at active: 0
names NOT registered: []
names NOT currently INTRUSIVE: []
all INTRUSIVE count: 40
INTRUSIVE not covered by 40: []
```

**MEASURED, and it validates the ticket's own arithmetic:** the 40 INTRUSIVE engines are *exactly*
the 31 + the 9, with no remainder in either direction. No name in either list is unregistered, and
no name in either list was already something other than INTRUSIVE. The partition in Q-052 is
complete and disjoint against the live registry.

**Baseline to beat: 71 of 111 selectable at `active`.** Expected after: 102 (71 + 31), with the 9
still unreachable.

---

## REVERT CONDITION 4 FIRED — 4 of the 31 are STATE-CHANGING. MEASURED by reading.

Q-052 says its own classification is "by name and by reading, and has NOT been confirmed by observing
each engine against a live target", and pre-registers condition 4 for exactly this. **Reading all 31
implementations found four that mutate state.** They are held at INTRUSIVE (moved to the 9) rather
than re-tiered. This is the ticket's own instruction, not a re-opening of the decision.

Apparatus (positive control): the same AST sweep that found these four also read the other 27 and
returned no write-method literal for 20 of them, so the sweep was demonstrably able to distinguish.

### 1. `http_request` — the codebase's own read/write boundary puts it on the write side
`agent/tools.py:2024`. Docstring, unmodified: `INTRUSIVE: send a scope-guarded request with ANY
method + body (state-changing).` No method allowlist; `DELETE` is permitted; body is caller-supplied.
The sibling `_http_diff` (`agent/tools.py:2050`) refuses any non-SAFE method with the literal message
`"http_diff is read-only; use http_request for writes"`. The project already draws the read-only line
*between these two tools*, and puts `http_request` on the write side.
**What it can write: anything, by any method, at any in-scope URL.**

### 2. `run_mass_assign` — CREATES persistent objects and does not delete them
`agent/tools.py:6546`. Docstring opens `INTRUSIVE (writes)`. The registry entry already carried a
standing Q-011 comment: *"INTRUSIVE, not ACTIVE: it WRITES ... a mass-assignment probe necessarily
persists an attribute on a real object."* The protocol is three-object by construction: a baseline
object, an ignored-field control object, **and one object per candidate field**, each via
`POST`/`PUT`/`PATCH`. Its own docstring: *"every object written to is one this engine created, and
the summary lists them all so an operator can undo the state"* — i.e. cleanup is MANUAL and
delegated to a human.
**What it writes: N+2 new server-side objects per run, left behind.** For contrast,
`confirm_create_object_idor` is in the 9 and it *does* delete what it creates. `run_mass_assign`
creates strictly more and cleans up strictly less.

### 3. `test_numeric_abuse` — its own docstring says the request is state-changing
`agent/tools.py:3360`. Docstring: *"Sends a benign control plus out-of-range values (negative / zero /
huge / fractional) **to a state-changing request**"*. Five writes per run (`control` + up to 4
values), default method `POST`. The docstring's mitigation is *"NEVER finalizes payment or performs
an irreversible action"* — but Q-052's line is **changes state**, not **irreversible**. A basket with
four abusive line items is changed state.
**What it writes: up to 5 application writes per probed field.**

### 4. `run_bfla` — sends `POST`/`PUT`/`PATCH` (and `DELETE` on opt-in) at arbitrary endpoints
`agent/tools.py:7144`, `methods = list(authz.SAFE_SWEEP) + (["DELETE"] if allow_delete else [])`.
**`authz_tool.py:21`: `SAFE_SWEEP = ("GET", "POST", "PUT", "PATCH")  # DELETE opt-in only`.** The name
is a trap: "SAFE" here means *DELETE-excluded*, not *read-only*. The engine sends each method with a
`{}` body, twice (test identity + anonymous). **A `PUT {}` against `/api/users/1` is a field wipe**,
and the engine chooses the method sweep, not the target.
**What it writes: 6 non-GET requests per endpoint (3 methods x 2 identities), 8 with `allow_delete`.**

**Net: the 9 become 13. The 31 become 27.** The safety property of Q-052 is strengthened, not
weakened, and the SQLi surface the ticket exists to recover is untouched — none of these four is a
SQLi engine.

---

## SLICE 1 — the re-tier. MEASURED.

**25 engines moved INTRUSIVE -> ACTIVE** (the 31 minus the 4 above, minus `run_form_cmdi` and
`run_web_probes` which are held for slice 2, below).

```
TOTAL registered: 111
by tier: {'PASSIVE': 15, 'ACTIVE': 81, 'INTRUSIVE': 15}
selectable at passive: 15 of 111
selectable at active: 96 of 111     <- was 71 of 111
selectable at full: 111 of 111
NINE selectable at active: []        <- REVERT CONDITION 1: still zero
```

**71 -> 96 selectable at `active`.** Revert condition 1 holds: none of the 9 (nor the 4 added to
them) is selectable at `active`.

### The description gate fired on exactly the predicted set — 26 violations, 25 engines
`run_dir_harvest` violated on BOTH surfaces (spec description *and* docstring), which is why 26 > 25.
Every one was a literal leading `INTRUSIVE:`. Fixed by replacing the leading declaration with the
registered tier as a **bare** token, located through the gate's own AST rather than by text search,
so no occurrence deeper in the prose was touched. No description was reworded to dodge the gate; the
tier token is still there, it now names the tier the engine is actually registered under.

Three carry an honest qualifier, all of which still name `ACTIVE` as a bare token and so satisfy
Rule B (compound declarations pass by design — `description_gate.py:26`):
* `run_zap` -> `ACTIVE, independently gated to \`full\` mode:`
* `run_sqlmap` -> `ACTIVE (heavy):`
* `run_nmap_vuln` -> `ACTIVE (heavy, slow):`

Positive control that the gate was looking: `dg.check_undeclared_tier` returned 26 violations before
the fix and 0 after, on the same source, same apparatus.

### THE COST GATE — the part the ticket did not anticipate, and revert condition 3 depends on it

Three tests failed in a way that was NOT a stale exemplar:
`test_planner_routes_heavy_sqlmap_on_deep_intensity_full_only`,
`test_planner_schedules_zap_in_full_mode_only_when_configured`,
`test_nmap_nse_vuln_parser_is_truth_first_and_planner_gates_to_full`.

MEASURED cause: `run_sqlmap`, `run_zap` and `run_nmap_vuln` were held out of `active` **only as a
side effect of being mis-tiered INTRUSIVE**. `planner.py` said so in three separate comments
(*"run_zap is INTRUSIVE, so fresh()/_allowed() gates it to FULL mode only"*). Re-tiering them removed
a wall-clock control that nothing had ever named — precisely revert condition 3, arriving as a red
test rather than as a slow mission.

Fixed by naming the axis instead of restoring the mis-tier: **`planner._HEAVY_FULL_ONLY`**, checked
in `_allowed()` BEFORE the tier check. Cost and consent are now two separate questions, which is the
same diagnosis the earlier Q-052 lane recorded (*"the tier is an aggression/cost axis, not a consent
axis"*). The three tests pass **unmodified** — their assertion was always "full-only scheduling", and
that is still true; only the reason changed.

### Tier SEMANTICS now live where the tiers are defined
`agent/scope.py` — `PermissionLevel` had **no docstring at all**, which is why "which tier does a new
engine go in" had no answer to look up. It now carries the decision rule (*does it change the target's
state*), the disambiguating test (*if the run were interrupted halfway, would the target need cleaning
up?*), worked examples per tier, and an explicit list of what is NOT this axis (cost, noise,
authentication). `agent/planner.py`'s module docstring carries the cost-vs-consent split.
