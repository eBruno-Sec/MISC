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

