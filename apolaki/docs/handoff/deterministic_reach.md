# Q-050 · deterministic reach — the six LLM-only detection engines

Lane: **Builder / deterministic-reach**. Owns `agent/planner.py`, `agent/agent.py`,
`agent/tests/test_deterministic_reach.py` (new), this file.

Every claim below is **MEASURED** (command + real output) or **UNVERIFIED**.

---

## 0. The finding being acted on (given, not re-derived)

Q-050 RE-MEASUREMENT, `docs/QUEUE.md` @ `a35be46`. Over 154 missions / 29,945 `tool_call` rows:
111 registered tools, 72 ever dispatched, 40 never. Classified by whether the name appears
*anywhere* in `agent.py` or `planner.py`: 30 schedulable, **10 LLM-only**, 0 unreachable.

Six of the ten are real detection engines with a working `ToolRegistry._run_*` method:
`run_mass_assign`, `run_hash_id`, `run_external_surface`, `run_nosqlmap`, `run_ws_hijack`,
`run_hash_crack`. A deterministic mission can never select any of them.

`run_mass_assign` is first because two control catalogues cite it as coverage
(`asvs_model.py:179` ATHZ-04 `"verifiable": True`, `wstg_catalog.py:110` WSTG-INPV-20).

---

## 1. Slice 1 — `run_mass_assign` given a deterministic trigger

### 1.1 The pre-state, re-measured before touching anything

MEASURED at `0b991e9`:

```
$ grep -c "run_mass_assign" agent/planner.py agent/agent.py
agent/planner.py:0
agent/agent.py:0
```

Positive control for the same grep, on an engine that *is* scheduled:

```
$ grep -c "run_sqli" agent/planner.py agent/agent.py
agent/planner.py:3
agent/agent.py:11
```

So the zero is a real absence, not a broken command.

### 1.2 What the engine actually needs, read from its own dispatch

`tools.py:6641 _run_mass_assign` requires `url`, and refuses to invent a body:

```python
if not seed:
    return ToolResult("mass_assign", url, True, _json.dumps({
        "ran": False, "note": "no base body -- neither an explicit body nor typed OpenAPI "
                              "body parameters were supplied, ..."}), [])
```

So a trigger that hands it only a URL produces `ran: False` — the *appearance* of reach with none
of the substance. The step must carry the typed body parameters
(`surface.operations_from_openapi(...)["params"]`, `location == "body"`).

### 1.3 The observed signal the planner can evaluate

Already recorded, and nothing new had to be invented:

* `tools._fetch_openapi` keeps the parsed spec in `recon["openapi"]` (Q-031).
* `agent._project_spec_params` turns each operation's body parameters into graph `param` nodes
  carrying `location="body"`, `ptype`, `required`, `method` **and `content_type`**.
* `agent._forms_from_graph` is the one place a body parameter becomes schedulable surface.

MEASURED against the live VAmPI lab's own spec (`http://apolaki-vampi-1:5000/openapi.json`,
14 operations), via `surface.operations_from_openapi`:

```
GET  /                          ''                  body= []
GET  /books/v1                  ''                  body= []
POST /books/v1                  'application/json'  body= [('book_title','string'),('secret','string')]
GET  /books/v1/{book_title}     ''                  body= []
GET  /createdb                  ''                  body= []
GET  /me                        ''                  body= []
GET  /users/v1                  ''                  body= []
GET  /users/v1/_debug           ''                  body= []
POST /users/v1/login            'application/json'  body= [('password','string'),('username','string')]
POST /users/v1/register         'application/json'  body= [('email','string'),('password','string'),('username','string')]
DELETE /users/v1/{username}     ''                  body= []
GET  /users/v1/{username}       ''                  body= []
PUT  /users/v1/{username}/email 'application/json'  body= [('email','string')]
PUT  /users/v1/{username}/password 'application/json' body= [('password','string')]
```

**The trigger is therefore: a graph-recorded endpoint with (a) a write method, (b) a JSON
content type declared by the API's own spec, and (c) at least one typed body parameter.**
An HTML form matches none of it — `_project_form_params` writes no `content_type` at all, because
an HTML form posts urlencoded. That asymmetry is what makes the negative control real rather than
a filter written to pass a test.

### 1.4 The change

* `agent/agent.py::_forms_from_graph` — carries `content_type` and the typed `body_params` through
  to the planner's `recon["forms"]` entries. Purely additive keys; every existing consumer reads
  `action` / `method` / `fields` and is untouched.
* `agent/planner.py` — a new branch in phase E emitting `run_mass_assign` for endpoints meeting the
  three-part precondition, with `params` (typed body params), `method`, and `read_paths` (GET paths
  the mission actually observed, from `state["urls"]`, same host).

Login endpoints are deliberately excluded: a login write creates no object, so there is no re-read
view and the engine can only ever emit a lead. That is a stated budget decision, not a silent one.

`run_mass_assign` is INTRUSIVE, so `_allowed()` schedules it in **Full mode only** — the same gate
that already holds `run_stored_xss`, `run_race` and `run_deserialization`.

### 1.5 THE DISPATCH, SHOWN — `planner.next_batch` driven to exhaustion

Not an assertion that a name is in a table. State built the real way
(`_seed_and_project_graph` → `_project_spec_params` → `_forms_from_graph` →
`_graph_primary_state`), then `next_batch` driven until it returns `[]`:

```
TOTAL STEPS 86 | distinct tools 30

{"tool": "run_mass_assign",
 "input": {"url": "http://vampi.local:5000/users/v1/register", "method": "POST",
           "params": [{"name": "email",    "location": "body", "type": "string", "required": false},
                      {"name": "password", "location": "body", "type": "string", "required": false},
                      {"name": "username", "location": "body", "type": "string", "required": false}],
           "read_paths": ["/users/v1", "/users/v1/_debug", "/users/v1/1", "/"]},
 "key": "run_mass_assign:http://vampi.local:5000/users/v1/register"}

{"tool": "run_mass_assign",
 "input": {"url": "http://vampi.local:5000/users/v1/1/email", "method": "PUT",
           "params": [{"name": "email", "location": "body", "type": "string", "required": false}],
           "read_paths": ["/users/v1", "/users/v1/_debug", "/users/v1/1", "/"]}, ...}

{"tool": "run_mass_assign",
 "input": {"url": "http://vampi.local:5000/books/v1", "method": "POST",
           "params": [{"name": "book_title", "location": "body", "type": "string", ...},
                      {"name": "secret",     "location": "body", "type": "string", ...}], ...}}
```

Three steps, and `POST /users/v1/login` — which satisfies every mechanical condition — is not
among them.

`/users/v1/_debug` is in `read_paths`, and that is the point of the whole re-read half:
`docs/handoff/massassign.md` MEASURED that `GET /users/v1/{username}` does **not** expose `admin`
while `/users/v1/_debug` does. Feeding `read_views` the observed paths reaches the only view that
can answer.

### 1.6 NEGATIVE CONTROL — the same drive against an HTML-form target

An engine wired to fire always is worse than one that never fires. Same driver, same code, a target
whose entire write surface is HTML forms:

```
TOTAL STEPS 64 | run_mass_assign 0 | run_csrf 2 | forms delivered 2
```

`forms delivered 2` and `run_csrf 2` are the positive control for the apparatus: the forms reached
the planner on that same run, and the mass-assignment branch declined them. Zero here is a
decision, not an empty input.

Three more negative controls, all in `agent/tests/test_deterministic_reach.py`:

| control | why it is not a filter written to pass a test |
|---|---|
| read-only JSON API (GET operations only) | no write method anywhere → 0 steps |
| JSON write whose schema is an unresolved `$ref` | media type present, **zero** typed properties. `_run_mass_assign` would return `ran: False, "no base body"` — reach on paper, nothing on the wire |
| `active` and `passive` mode | INTRUSIVE; reach must not have widened the consent envelope |

`test_an_empty_content_type_is_not_read_as_json` pins the falsy-default trap at the one line where
it would bite: `""` is a real observation (an HTML form records no media type), not a missing value
to be defaulted to JSON.

`agent/tests/test_deterministic_reach.py` — 10 passed.

---
## 2. Slice 2 — `run_nosqlmap`: asked the question first, and the answer was DELETE

The instruction was to establish whether this is a distinct capability or a duplicate of the
already-dispatched `run_nosqli`, comparing what each **does**, not what each **claims**. It is a
duplicate, and a strictly weaker one. Five independent measurements, any one of which is
disqualifying on its own.

### 2.1 The binary does not exist in the shipped image

MEASURED, today, in the current image (not inherited from `islands.md`):

```
$ docker run --rm apolaki-agent sh -lc 'for b in nosqlmap sqlmap hashcat john ffuf nmap; do printf "%-12s " $b; command -v $b || echo MISSING; done'
nosqlmap     MISSING
sqlmap       /usr/bin/sqlmap
hashcat      MISSING
john         MISSING
ffuf         /usr/local/bin/ffuf
nmap         /usr/bin/nmap
```

`sqlmap`, `ffuf` and `nmap` are the positive control: the command finds binaries that are present,
so `MISSING` is a real absence. `agent/Dockerfile` and `docker-compose.yml` contain no reference to
`nosqlmap` (grep: zero hits). `_cmd` (`tools.py:1525`) short-circuits on `shutil.which`, so every
possible invocation returned `("", "__MISSING__nosqlmap")`. **Wiring it into the planner would have
bought one guaranteed-failing dispatch per parameterized URL and zero coverage.**

### 2.2 It has never run, and the capability it duplicates runs constantly

MEASURED against the named volume (`-v apolaki_bbh_data:/data`), reproducing the corpus exactly —
**154 missions, 1,773 findings, 66,395 log rows, 29,945 `tool_call` rows, 0 unparseable, 72 distinct
tools dispatched**:

```
run_nosqlmap             0
run_nosqli             342
run_form_nosqli        704
run_mass_assign          0
run_hash_id              0
run_hash_crack           0
run_ws_hijack            0
run_external_surface     0
run_sqli              1214      <- positive control
run_xss               1376      <- positive control
```

**1,046 native NoSQL dispatches is the positive control for this zero specifically.** The apparatus
counts NoSQL engines fine; `run_nosqlmap`'s 0 is absence, not a broken query.

### 2.3 The oracle comparison — the part descriptions would have hidden (Q-056)

| | `_run_nosqlmap` (deleted) | `_run_nosqli` + `_run_form_nosqli` (kept) |
|---|---|---|
| truth condition | `re.search(r"injectable\|vulnerable\|payload", stdout, re.I)` | operator payload broadens the match back to baseline shape, or a driver-error signature appears |
| baseline request | none | `base_r` fetched before any probe |
| control requests | none | non-matching-value control (`ctl_url`) **and** a missing-param control (`ns.missing_param_url`), both fed to `ns.analyze_boolean` |
| confidence emitted | `"lead"` | confirmed finding |
| body/auth coverage | none (`--url` only) | `_run_form_nosqli`: `{"$ne": null}` login bypass, the class query-string probes cannot reach |

The description claimed it "skips gracefully" and that "native `run_nosqli` remains the default".
Both are true and neither is the relevant fact: it skips *always*, and it is not a fallback for the
default — it is a weaker restatement of it.

### 2.4 A silent-failure swallow, recorded for the next adapter

`_cmd` returns `(stdout, stderr)` and **discards `proc.returncode`**. So a present-but-failing binary
(usage error to stderr, non-zero exit, empty stdout) produced
`ToolResult("nosqlmap", url, True, "nosqlmap completed", [])` — success, clean, zero findings. The
engine could not distinguish "no NoSQL injection here" from "the tool never ran". Kept as a comment
at the deletion site.

### 2.5 The one real differentiator was disabled by Apolaki's own invocation

Real NoSQLMap's non-duplicate capability is unauthenticated Mongo/CouchDB **port** enumeration.
The adapter shelled out to `nosqlmap --url <url>` — the web-injection path only. This is the
feroxbuster `--no-recursion` finding repeating exactly one file-section later (`tools.py:246`).

### 2.6 The change

* `agent/tools.py` — `TOOL_PERMISSIONS["run_nosqlmap"]`, its `CLAUDE_TOOLS` spec and
  `_run_nosqlmap` all removed; a note at each site carrying the argument, in the Q-057 style.
* `agent/tests/test_deterministic_reach.py` — `test_run_nosqlmap_is_removed_rather_than_left_unreachable`
  (absence in specs, permissions and methods, plus `shutil.which` still None) and
  **`test_the_nosql_capability_is_still_deterministically_dispatched`**, which is the half that
  makes the deletion safe: `planner.next_batch` driven to exhaustion on a parameterized-URL +
  login-form target emits `run_nosqli` (on the `?id=1` / `?q=a` endpoints specifically) and
  `run_form_nosqli`. An absence assertion alone would be the "name in a dict" defect inverted.
* `agent/tests/test_bbh.py` — **NOT one of this lane's named files.** Touched for two lines only,
  because `test_new_optional_binaries_and_permissions` asserted `run_nosqlmap in specs` and would
  otherwise have gone red. `run_nosqlmap` moved from the present-tuple into the existing Q-057
  absent-tuple, which is exactly what Q-057 did to that same function.

MEASURED: `pytest tests/test_deterministic_reach.py tests/test_bbh.py::test_new_optional_binaries_and_permissions` → **13 passed** (10 from slice 1, 2 new, 1 existing).

### 2.7 Left stale on purpose, for owners who are not this lane

| file | line | what it still says |
|---|---|---|
| `README.md` | 151, 156 | lists `run_nosqlmap` in the engine table and in the auto-detected-binary list. **Already stale before this change** — it still lists feroxbuster/dirsearch/gobuster, removed at Q-057, so nothing gates it |
| `docs/handoff/arsenal.md` | 125 | inventory listing |
| `scripts/whole_product_rerun.py` | 102 | `PROBE_TOOLS` set-membership; a stale name there matches nothing and is harmless |

Net: **111 registered engines → 110**, and one of the five LLM-only detection engines is resolved by
subtraction.

### 2.8 The ratchet that caught the deletion, and the exact delta

A full-suite run flagged one failure, and it is the arsenal class-split ratchet doing its job:

```
tests/test_arsenal_errored_class.py::test_the_classes_still_sum_to_the_REGISTRY_DENOMINATOR
E  assert (13, 52, 30, 1, 2, 12) == (13, 53, 30, 1, 2, 12)
E    At index 1 diff: 52 != 53
```

`(blocked, never, silent, errored, skipped, productive)`. The arithmetic identity
`total == len(registered)` still held — it is the pinned SPLIT that moved. **`run_nosqlmap` lived in
`never`, so the denominator went 111 → 110 and `never` went 53 → 52: one engine, one class, every
other class byte-identical.** Re-aimed with that reason recorded at the assertion, which the test's
own comment already names as "the deliberate cost of a taxonomy change".

`test_arsenal_errored_class.py` is **not one of this lane's named files**, and is the second such
file touched (with `test_bbh.py`). Both were touched only because they pin a fact the deletion
changed, and both are named here and in the commit message rather than folded in quietly.

## 3. Slice 3 — `run_hash_id` given a deterministic trigger, after a hypothesis of mine was disproved

`wstg_catalog.PARTIAL["WSTG-CRYP-04"]` reads `"run_hash_id flags weak primitives"`. It flagged
nothing: 0 dispatches in 154 missions.

**A correction to the ticket's framing first.** WSTG-CRYP-04 is in `PARTIAL`, not `FULL`, and the
catalogue defines `partial` as *"a related tool touches it but does not confirm the specific WSTG
scenario"*. So this is a weaker over-claim than `run_mass_assign`'s (which had `asvs_model`
`"verifiable": True`) — but it is still an over-claim, because the engine did not *touch* it either.
The second `engine_descriptor.py` hit is a **comment explaining a deliberately REJECTED route**
(`:467` — `weak_secret_forgery` must not route to `run_hash_id`, which "forges nothing"). That is the
predicted false positive of a source-text scan, and it means `run_hash_id` had exactly one live
non-`tools.py` mention, not two.

### 3.1 The hypothesis I formed, and the measurement that KILLED it

Scanning the corpus for hash material with `hashid_tool.identify`, filtered to its own
**high-confidence** verdicts:

```
                        rows     bytes       tokens   HIGH-confidence hits
findings                1,773    —           13,178   {JWT: 28}
exchanges               9,691    32,542,565  15,232   {JWT: 82}
logs (tool_call/result) 55,973   —            1,809   {JWT: 115}
memory_assets           3,247       174,132   2,718   {JWT: 321}
POSITIVE CONTROL (planted)  —     —               6   {bcrypt: 1, sha512crypt: 1, MySQL: 1} + {MD5: 1, SHA-1: 2}
```

The control proves the apparatus finds a planted bcrypt / sha512crypt / MySQL / MD5 / SHA-1 in the
same pass. **Hypothesis: Apolaki observes no password hashes at all, so `run_hash_id` cannot be
deterministically triggered and the catalogue note should be deleted instead.**

**That hypothesis is FALSE, and finding out took hand-inspecting the medium-confidence bucket I had
just filtered away.** Seventeen raw-hex tokens sit in `exchanges`; printed with 90 characters of
surrounding context, three of them are this:

```
[3 len=32] "email":"bjoern@owasp.org","password":" <<9283f1b2e9669749..>> ","role":"deluxe"
[5 len=32] "username":"bkimminich",...,"password":" <<6edd9d726cbdc873..>> ","role":"admin"
[6 len=32] "username":"evmrox",...,"password":"     <<2c17c6393771ee30..>> ","role":"deluxe"
```

Juice Shop's user table, MD5, dumped through `/rest/memories`, one of them the **admin** row. They
were invisible to the high-confidence filter for a correct reason: `identify` ranks a 32-hex digest
as MD5 *and* NTLM *and* MD4, and says so. **My filter was the defect, not the data.** Had I stopped
at the first table I would have deleted a true catalogue claim.

### 3.2 The other fourteen are exactly the noise a naive trigger would have emitted

```
[8..17] name='user_token' value=' <<e6b98aa6a6586939..>> '     <- DVWA anti-CSRF nonce, ten of them
[1]     pgp_keys.asc?fingerprint= <<19c01cb7157e4645..>>       <- PGP key fingerprint in security.txt
[4],[7] "deluxeToken":" <<efe2f1599e2d9344..>> "               <- session token, same JSON object
[2]     "comment":"csaf advisory hash <<7e7ce7c65db3bf06..>>"  <- an advisory digest
```

**A trigger keyed on "a hash-shaped string appeared" would have been 77% anti-CSRF nonces**, on
every DVWA page, from an engine whose entire output is severity `info`. The discriminator cannot be
a property of the hash — it is genuinely ambiguous by construction. **It is the KEY THE APP ITSELF
BOUND IT TO**, which is an observed value, not an invented one.

### 3.3 The precondition, and why each half exists

`agent._disclosed_hashes(exchanges)`, RESPONSE bodies only — a `password` in a *request* body is the
mission's own probe value or a credential it already holds, and neither is the target disclosing
anything.

* **Rule A, self-identifying**: a crypt-style token (`$1$`, `$2[aby]$`, `$5$`, `$6$`, `$argon2`,
  `$pbkdf2`, `{SSHA}`, `*HEX`) matched whole, no key required. This is the `/etc/shadow` case, which
  has no JSON key anywhere near the hash. Measured occurrences over the corpus: zero, therefore a
  measured false-positive rate of zero.
* **Rule B, key-bound**: hash-shaped AND the key matches `passw|pwd`. **Not** `token`, **not**
  `hash`, **not** `secret` — `user_token` is the measured false positive above, and the other two
  are broad enough to re-admit it under another name.
* **JWTs are excluded on purpose.** `run_jwt` holds WSTG-SESS-10 in `wstg_catalog.FULL` with a
  confirming oracle. A second engine that says "this is a JWT" and stops is slice 2's mistake.
* `hashid_tool.identify` is the final filter in both, which is also what keeps a real plaintext
  credential out of the evidence blob: `{"password":"admin123"}` is not hash-shaped and is dropped.

### 3.4 MEASURED: the precondition run over all 9,691 real captured exchanges

```
exchanges decoded 9691
EXTRACTED 3
   9283f1b2e9669749081963be0462e466 | http://juice-shop-bench:3000/rest/memories disclosed `password` as MD5
   6edd9d726cbdc873c539e41ae8757b8c | http://juice-shop-bench:3000/rest/memories disclosed `password` as MD5
   2c17c6393771ee3048ae34d6b380c5ec | http://juice-shop-bench:3000/rest/memories disclosed `password` as MD5

--- POSITIVE CONTROL: planted shadow line + bcrypt + LDAP ---
   $6$abcdefgh$AbCdEfGhIjKlMnOpQrStUv | disclosed `a crypt-style hash` as sha512crypt (Unix)
   $2b$12$K1x8Qk9v0Zc3sB7nJ4hLPeYcQm2 | disclosed `a crypt-style hash` as bcrypt
   {SSHA}0TT88S6Xn9tMvEHXVQdPjHknHtim | disclosed `a crypt-style hash` as LDAP SHA/SSHA
```

Exactly the three credential-store rows, and nothing else. **The ten DVWA `user_token` nonces are in
that same 9,691-exchange corpus and were declined** — the negative control is live data, not a
fixture.

### 3.5 Why this is NOT a `planner.next_batch` branch, stated rather than assumed

The observation lives in **response bodies**. `planner.next_batch` state is
`{roots, recon, urls, bases, done, ...}` built from the asset graph; it has never carried a response
body, and putting one there to reach an `info`-severity engine would be the wrong trade. The real
execution path is therefore `agent._execute_plan`'s post-pass, one line after `_promote_leads` — the
same seam the XSS lead-promotion pass already uses, and the tests drive it, not a table.

### 3.6 BOTH HALVES, and the second was found by running the first

Dispatch alone was not the fix. MEASURED on the first green run of the new test:

```
{"type": "tool_call",   "tool": "run_hash_id", "input": {"hashes": ["9283f1b2...", "6edd9d72..."]}, "permission": "passive"}
{"type": "tool_result", "tool": "run_hash_id", "output": "2 hash(es) identified", "count": 1}
```

...and `self.leads` was **empty**. `run_hash_id` was not in `agent._AUTO_STORE_TOOLS`, so the engine
executed and its lead went on the floor. **That is the same defect as a step that dispatches into
`ran: False`, one level over: reach with no effect.** Both halves are now wired, and the test
asserts on mission state (`a.leads[0]["evidence"]` carrying the engine's own `MD5, NTLM, MD4`
ranking), not on the event stream.

### 3.7 The tests

`agent/tests/test_deterministic_reach.py`, **20 passed** (10 slice 1, 2 slice 2, 8 slice 3). Every
body in slice 3 is a **real recorded body copied out of the corpus**, which is what makes the
negative controls mean something.

| test | what it pins |
|---|---|
| `test_the_precondition_admits_the_credential_store_and_declines_the_nonce` | the discriminator, on the real Juice Shop + DVWA + security.txt bodies; names each measured FP individually |
| `test_a_crypt_style_hash_needs_no_key_at_all` | rule A: shadow / LDAP / MySQL formats identified with no key present |
| `test_a_jwt_is_left_to_the_engine_that_owns_it` | no second JWT engine |
| `test_a_plaintext_password_is_not_copied_into_the_evidence` | a real credential never enters a finding |
| `test_a_request_body_is_not_a_disclosure` | direction of disclosure |
| **`test_the_agent_actually_executes_run_hash_id`** | **THE DISPATCH.** Real mission, real `db.add_exchange`, real `ToolRegistry`; `_run_tool` to `tools.execute` runs the shipped engine, and the lead lands in `self.leads` |
| **`test_a_target_with_no_disclosed_hashes_gets_no_dispatch_at_all`** | **THE NEGATIVE CONTROL**, on the corpus's commonest FP: a DVWA-shaped mission emits zero events |
| `test_a_mission_with_no_exchanges_is_not_an_error` | empty input is not a failure |

The `mission_db` fixture saves and restores `db._conn`, so this lane cannot move the process-wide
connection out from under the rest of the suite.

### 3.8 For the owner of `wstg_catalog.py` — NOT this lane's file

`PARTIAL["WSTG-CRYP-04"] = "run_hash_id flags weak primitives"` is **true for the first time** as of
this commit, and could now honestly read `"run_hash_id identifies weak password-storage primitives
in credential material the target disclosed (deterministic; observed values only)"`. No edit is
required — this is an upgrade in accuracy, not a correction of a falsehood. `engine_descriptor.py`
needs nothing: its only mention is a comment recording a rejected route, and that rejection is still
right.

