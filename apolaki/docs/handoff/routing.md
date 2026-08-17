# routing lane — Q-066 / Q-020 / Q-065

One root cause, one ticket. This file records what HAPPENED, in order. Every claim is MEASURED
(command + real output) or UNVERIFIED.

Apparatus for every measurement below, unless stated otherwise:

```
MSYS_NO_PATHCONV=1 docker run --rm --network apolaki_default -e PYTHONPATH=/app \
  -v "<repo>/agent:/app" -v "<scratch>:/probe" -w /app apolaki-agent python /probe/probe_join.py
```

---

## STEP 1 — does a join already exist? MEASURED: NO. But the ticket's mechanism is wrong.

**Verdict: no join exists, and Q-066's DoD stands. The ticket's headline measurement is a category
error that points the fix at the wrong pair of tables.**

### What I read (field/attribute names stated, because two probes in this thread lied about theirs)

- `tools.TOOL_PERMISSIONS` — dict, **keys** are the registered engine names. 111.
- `tools.CLAUDE_TOOLS` — list of dicts, **`["name"]`** per item. 76.
- `techniques.TECHNIQUES` — dict, **keys** are technique ids. 88.
- `engine_descriptor.PRECONDITIONS` / `.EFFECTS` / `.ALWAYS_ON` — dict **keys**. 42 / 13 / 45.
- `engine_descriptor.build()` -> `{id: descriptor}`, and `descriptor()`'s full **output keys**.
- every field name present on every technique record, enumerated rather than guessed (25 of them).
- `asvs_model` rows, **`["engine"]`**.

Positive control for the apparatus: `"run_jwt" in tools.TOOL_PERMISSIONS` -> `True`. The registry
was loaded and readable, so a zero below is a fact and not an empty instrument.

### M1 — EFFECTS and PRECONDITIONS are the SAME vocabulary. This is the ticket's error.

```
EFFECTS keys that ARE technique ids   : 13 of 13
EFFECTS keys that ARE engine names    :  0 of 13
PRECONDITIONS keys that ARE tech ids  : 42 of 42
PRECONDITIONS keys that ARE engines   :  0 of 42
technique ids that ARE engine names   :  0 of 88
EFFECTS keys NOT in PRECONDITIONS     : ['browser_persona_bola', 'graphql_introspection']
```

The ticket reads `PRECONDITIONS 42 of 42 ARE technique ids -> techniques DO bind here` against
`EFFECTS 0 of 13 are registered engine names -> nothing binds to the engine registry`. Those two
rows are measured against **different reference sets**, which makes the contrast an artifact of the
probe rather than a property of the code. Measured against the same set: **PRECONDITIONS binds to
the engine registry exactly as poorly as EFFECTS does — 0 of 42.** `jwt_forge` and
`jwt_key_confusion` are not a separate "capability vocabulary": both are technique ids and both
appear in `PRECONDITIONS` (lines 77 and 89) as well as `EFFECTS`.

So the defect is NOT "effects speak a different language from preconditions". They speak the same
one. The defect is that **the technique vocabulary as a whole has no route to the engine registry**,
and that is true for all 88 techniques, not the 13 with effects.

### M2 — no technique record carries an engine binding, in any field

Exact value equality against the 111 registered names, over every field on every record:

```
union of record field names: ['backfill_claim', 'cleanup', 'cwe', 'detect', 'evidence_requirements',
  'execution', 'exploit', 'fixture_source', 'id', 'maps_to', 'mitre', 'needs_fixture',
  'negative_control', 'oracle', 'owasp', 'pack', 'permission', 'refs', 'replayable', 'safety',
  'summary', 'transferable', 'validated_on', 'vuln_class', 'wstg']
fields whose VALUE is exactly a registered engine name: NONE
prose fields mentioning a real engine (run_*/confirm_* token): NONE
```

The prose fields name *modules* (`jwt_tool`, `sqli_tool`, `saml_tool`), never *engines*. A module is
not dispatchable.

### M5 — `descriptor()` and `build()` add nothing. This is the part the Coordinator could not see.

The ticket correctly flagged that only the public surface had been checked. I read the function
bodies. `descriptor(tech, preconditions, always_on)` emits exactly these keys:

```
['always_on','auto','establishes','id','invalidates','oracle','permission','reached_by',
 'requires','transferable','vuln_class']
```

No `engine`, `tool`, `executor` or `dispatch` key. `build()` is `{t["id"]: descriptor(...)}` over
`techniques.TECHNIQUES` — it introduces no new field. **A join is not hiding inside `build()` or
`descriptor()`.**

Positive control that the apparatus would have SEEN an engine binding: the same probe read
`asvs_model` and found **29 of 33 rows carry `["engine"]`**. The instrument detects engine bindings
where they exist.

### M3 — the one join that DOES exist, and its exact extent

`ALWAYS_ON` values are prose reasons, and 23 of them name a real engine in that prose.
`engine_descriptor.verify_always_on()` already exploits this: it extracts identifiers from the
reason and proves each is referenced from code that runs.

```
ALWAYS_ON reasons naming >=1 registered engine: 23 of 45
ALWAYS_ON naming NO registered engine: client_side_authz, client_supplied_identity_param,
  crlf_injection, dnp3_exposed, encoded_data_decode, enip_exposed, ipmi_rakp, ldap_anonymous_read,
  missing_authentication, modbus_exposed, ntp_monlist, rdp_no_nla, rsync_anon, s7comm_exposed,
  security_misconfig_errors, smb_null_session, smb_signing_disabled, snmp_default_community, ssti,
  vnc_no_auth, vulnerable_component, weak_ssh_crypto
```

### M4 — the evidence-gated half has no route at all

```
PRECONDITIONS techniques with an ALWAYS_ON engine name: 0 of 42
PRECONDITIONS techniques with NO route to any engine  : 42 of 42
```

`jwt_forge`, `jwt_key_confusion` and `weak_secret_forgery` are all in that 42.

### Independent corroboration already in the tree

`agent/report.py:1831` states the same fact, reached from the reporting side by the Q-051 lane:

> a technique record carries `maps_to`, `validated_on` and `oracle`, but NO engine binding, so
> nothing links a technique to the tools a mission dispatched

That text is rendered to the reader in both renderers (`report.py:1852` and `:3009`). So the
platform already TELLS the operator it cannot answer "which techniques ran". Q-066 is the same hole
seen from the planner side.

### A correction to Q-065's concrete case, MEASURED

The ticket pairs `run_jwt` with `weak_secret_forgery`. Those are not the same capability.
`techniques.py:832` — `weak_secret_forgery` is CWE-330, "forge a signed artifact (token/coupon/
continue-code) whose secret is weak", precondition `has_coupon`, validated on the Juice Shop
*Forged Coupon* challenge. The JWT techniques are `jwt_forge` / `jwt_key_confusion`, CWE-347,
precondition `authenticated`. Whatever emitted `weak_secret_forgery` was not naming `run_jwt`'s
capability. `codeintel.py:57` binds source-pattern rule `weak_crypto` -> technique
`weak_secret_forgery`, which is a plausible emitter of that string on a JS-heavy target.

This does not weaken Q-066 — it is another instance of the same shape (a technique id surfaced to
the operator with no route to an engine). It does mean the "`run_jwt` never fires" symptom needs its
own measurement rather than being assumed to be a routing miss; see the note under Step 2.

### Status at end of Step 1

- Q-066: **CONFIRMED, reframed.** No join exists. The gap is technique-registry-to-engine-registry,
  all 88 techniques, not effects-vs-preconditions.
- Q-020 / Q-065: still bound to Q-066, not closed separately.
- Nothing built yet. No code written at this point.
- Committed as `5583ff2`.

---

## STEP 2 — the join, derived rather than typed

### An instrument error I made and retracted, recorded because the retraction matters

My first Step-2 probe reported **14 techniques as "routed indirectly"** through
`_run_service_pack`, and I nearly wrote that up as "routing is partly indirect, which is the ticket's
second DoD branch". It was wrong. `run_service_pack` **is** in `TOOL_PERMISSIONS`; my extraction
matched the token `_run_service_pack` against the registry without stripping the leading underscore,
so 14 directly-routed ICS engines looked unroutable. `verify_always_on()` has done
`bare = tok.split(".")[-1].lstrip("_")` all along, for exactly this reason, and I did not copy it.

The corrected number is 75 routed / 13 unrouted, not 61 / 14 / 13. `_engines_named()` now carries
that normalisation, and `test_engine_routing.py` pins it as a regression test naming the bug.

### What the mapping is DERIVED from (the ticket's first trap: no hand-written table)

Two sources, both already in the tree and both already maintained for another purpose:

| source | datum | why it is legitimate |
| --- | --- | --- |
| `always_on_reason` | `ALWAYS_ON[tid]` prose | already names the reaching engine, and `verify_always_on()` already proves that name is referenced from code that runs |
| `wstg_full` | technique record `["wstg"]` -> `wstg_catalog.FULL[wstg]` | the catalog's assertion that a deterministic CONFIRMING engine exists for that test, named. Q-011 already corrected this exact table for this exact class of error |

**Two sources measured and REJECTED**, because a wrong route is worse than no route:

- `wstg_catalog.PARTIAL` — the catalog defines it as "a related tool touches it but does not confirm
  the specific scenario", i.e. the negation of an executor. Would add 13 techniques and gets them
  wrong in kind: `weak_secret_forgery` (forge a salt-less coupon) would route to `run_hash_id`, which
  identifies hash primitives and forges nothing.
- `asvs_model` technique `vuln_class` -> row `violated_by` — a family-name coincidence, not a
  binding. Measured: **disagreed with the kept sources on 22 of the 33 techniques it covered**, e.g.
  adding `run_bfla` (function-level) to `idor_bola_read` alongside the correct `confirm_idor`
  (object-level).

### MEASURED result

```
registry_size      : 111        (tools.TOOL_PERMISSIONS keys)
total / routed     : 88 / 75
unrouted           : 13
phantom            : 0
effect_producers_unrouted: default_credentials, saml_signature_bypass, soft_deleted_login,
                           weak_password_reset      (4 of the 13 EFFECTS keys)
ok                 : True

jwt_forge         -> ['run_jwt']          {'run_jwt': ['wstg_full']}
jwt_key_confusion -> ['run_jwt']          {'run_jwt': ['wstg_full']}
modbus_exposed    -> ['run_service_pack'] {'run_service_pack': ['always_on_reason']}
```

`descriptor()` now carries `engines`, `routed_by` and `routable`, so the join is on the descriptor's
**public surface** — the place the Coordinator looked and found nothing. `build()` resolves the
routing once and passes it in, so the derivation is not re-run 88 times.

### The concrete case, end to end

`jwt_forge` and `jwt_key_confusion` both declare `wstg = "WSTG-SESS-10"`; `wstg_catalog.FULL`
["WSTG-SESS-10"] is `"run_jwt (+ key confusion)"`; `run_jwt` is in `TOOL_PERMISSIONS` **and** in
`CLAUDE_TOOLS`, so both the deterministic and the agentic path can dispatch it. Asserted in
`test_engine_routing.py::test_the_concrete_case_jwt_forge_routes_to_run_jwt`.

### The guard, and the proof it can fail

`routing_audit()` returns `{registry_size, registry_readable, total, routed, unrouted, phantom,
effect_producers_unrouted, ok}`.

**`phantom` is found by SHAPE over the source prose, never by re-filtering `routes()` output.**
`routes()` only ever emits names that are already in the registry, so asserting "every routed engine
is registered" would be true by construction — the guard-that-cannot-fail trap this codebase has hit
eight times, and `test_techniques.py:17` is still a live example of it.

MEASURED mutation kill, the Q-011 phantom `run_mass_assignment` injected into the catalog:

```
--- UNMUTATED (the shipped code) ---
phantom: ['mass_assignment (wstg_full:WSTG-INPV-20) -> run_mass_assignment'] | ok: False
--- MUTANT: _engine_shaped filtered by the registry (the trap) ---
phantom: [] | ok: True        -> the negative control FAILS, as it must
```

Five negative controls ship ahead of every clean-sheet assertion in
`agent/tests/test_engine_routing.py`: phantom caught, phantom-check-not-registry-filtered, a new
technique naming nothing reported unrouted, an unreadable registry failing CLOSED, and the
underscore normalisation regression.

### Q-020, restated as a fact instead of an unfailable assertion

All **13** unrouted techniques are `auto` + `oracle` + `transferable`, which is exactly
`technique_planner.orchestration_audit()`'s population. MEASURED: the no-island guard reports
`islands: []` and classifies all 13 as reached, while nothing can dispatch any of them.

```
business_logic_abuse, crlf_injection, default_credentials, encoded_data_decode, exposed_credentials,
saml_signature_bypass, security_misconfig_errors, soft_deleted_login, vulnerable_component,
waf_bypass, weak_2fa_bypass, weak_password_reset, weak_secret_forgery
```

Pinned as an exact set (`UNROUTED_2026_08_17`), not a count, so both directions are deliberate:
adding an unroutable technique fails the suite, and fixing one also fails until the fix is recorded.
`test_every_unrouted_technique_passes_the_no_island_guard_anyway` asserts the overlap directly, so
Q-020's claim is now a failable test rather than the `execution in ("auto","operator")` assertion
that cannot fail.

Committed as `cea1e2e`.

### Q-065 half — a plan that cannot be executed now says so

`effect_search.plan()` returned `reachable: True` for paths through techniques with no executor, and
a consumer had no way to distinguish "run this" from "there is no code for this". `plan()` is now a
thin annotating wrapper over the **unchanged** search (`_plan_core`), adding `engines`, `unroutable`
and `dispatchable`; `frontier()` gains `unroutable_now`.

A descriptor with no `engines` KEY is reported as neither routed nor unroutable — absence of a
measurement is not a negative result.

MEASURED mutation kill (drop `and not unroutable` from `dispatchable`): **3 tests fail**, including
two of the negative controls. Committed as `0f735bc`.

### Does it generalise, honestly?

**Yes for 75 of 88, and I did not do only one case.** The derivation is two rules over existing
tables, not a per-technique list, and it reaches every ICS/service-pack engine, every WSTG-mapped
engine and both JWT techniques without naming any of them. **No** for the 13 above: those genuinely
have no engine the platform can derive, and 8 of them have no `wstg` value or a `wstg` whose catalog
entry names no engine. Closing those is engine work, not routing work, and is out of this lane's
scope.

### What is NOT done, stated plainly

- **Nothing consumes the new route yet.** `descriptor()["engines"]` is published and tested, but
  `planner.py`'s phase pipeline still hard-codes its dispatch names and does not read it. Wiring a
  consumer is the obvious next slice and I have not done it.
- The 13 unrouted techniques remain unrouted.
- Q-065's original symptom (`run_jwt` never firing on a JWT-authenticated target) has a **second,
  independent cause I did not fix**, recorded below.

---

## Q-065's SECOND cause — the FIFTH instance of the same defect shape

**This is not a routing problem, and fixing Q-066 does not fix it.** Found while measuring Q-066.

`planner.py:641` schedules `run_jwt` only if a JWT is found in this blob:

```python
_blob = (_json.dumps(state.get("auth_headers") or {})
         + _json.dumps(state.get("recon", {}).get("cookies") or {}))
```

MEASURED: `agent.py:3305` builds that state with exactly 13 keys, and `auth_headers` is not one of
them:

```
mode, roots, done, recon, urls, bases, zap, zap_policy, zap_speed, zap_aggression,
nmap_vuln, nuclei_heavy, intensity
```

The operator's headers are named **`session_headers`** at `main.py:554` and handed to
`ToolRegistry(session_headers=...)` as a constructor argument. They never travel through the state
dict at all. Grepping the whole tree, the string `auth_headers` appears as a dict-key access in
exactly one place outside the request model and the tests: the planner's own read.

**So `state.get("auth_headers")` is always `{}`, and only a JWT carried in a COOKIE can ever schedule
`run_jwt`.** A Bearer-token JWT — the normal case, and every SPA that keeps its token in
localStorage, which is Juice Shop's shape — cannot reach the gate.

This is the same shape as Q-066: producer and consumer name the same thing differently and never
meet. `mode`/`strategy`, ToolResult-name/dispatch-name, technique-id/engine-name, `blocked_by_mode`,
and now `session_headers`/`auth_headers`.

### MEASURED, by driving the real `planner.next_batch` through its phases

Not by reimplementing the regex — a reimplemented gate would pass while the shipped one did nothing.

```
WITH auth_headers          -> run_jwt scheduled: True  | distinct tools: 34
WITHOUT (production shape) -> run_jwt scheduled: False | distinct tools: 33
set difference             -> exactly {"run_jwt"}
```

The WITH case is the positive control: it proves the harness actually reaches phase E, without which
the WITHOUT case would pass for the trivial reason that the planner never got that far.

Pinned in `agent/tests/test_planner_jwt_gate.py` (commit `2ea0c35`). The production-shape test is
written to FAIL once the key starts being supplied, with an instruction to invert it rather than
delete it.

### PATCH FOR A FILE THIS LANE DOES NOT OWN

`agent/agent.py` holds uncommitted work from another lane, so this is written up rather than applied.
In the state literal at `agent.py:3305`, add the session headers the tool registry already holds:

```python
                state = {"mode": self.mode, "roots": g_roots, "done": done,
                         ...
                         "intensity": getattr(self.tools, "intensity", "standard"),
                         # Q-065: the planner's JWT gate reads this key and nothing wrote it, so
                         # run_jwt could only ever fire on a cookie-borne token. The registry has
                         # held the headers all along under a different name.
                         "auth_headers": getattr(self.tools, "session_headers", {}) or {}}
```

The attribute name is MEASURED, not assumed: `tools.py:1134` takes `session_headers: dict = None` and
`tools.py:1155` assigns `self.session_headers = session_headers or {}`, so `self.tools.session_headers`
is real on the instance the agent holds. After applying, flip
`test_the_production_state_shape_cannot_reach_the_gate` to assert presence.

A second, better option worth considering instead: have the gate read the token from wherever the
auth artery already stores it, so the planner does not depend on a header dict being copied into
state at all. I did not measure whether such a store exists.
