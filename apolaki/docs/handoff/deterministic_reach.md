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
