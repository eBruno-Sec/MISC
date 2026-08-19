# Q-079 — the dispatcher enforces no permission tier at all

Lane: **dispatch-guard (Builder)**. Owns `agent/tools.py`, `agent/agent.py`,
`agent/tests/test_dispatch_permission_guard.py`, this file.

Every claim below is **MEASURED** (command + real output) or **UNVERIFIED**.

---

## 1. The ticket's premise, re-measured at HEAD (928319b)

**MEASURED** — tier census after Q-052 landed (AST over `tools.TOOL_PERMISSIONS`):

```
counts {'PASSIVE': 15, 'ACTIVE': 81, 'INTRUSIVE': 15} total 111
INTRUSIVE: ['confirm_authz_write', 'confirm_create_object_idor', 'http_request', 'run_bfla',
            'run_cache_poison', 'run_deserialization', 'run_form_cmdi', 'run_hash_crack',
            'run_mass_assign', 'run_race', 'run_stored_xss', 'run_upload_test', 'run_web_probes',
            'run_workflow', 'test_numeric_abuse']
```

15 INTRUSIVE, not 40. The ticket said the set would be smaller and sharper; it is.

**MEASURED** — construction sites:

```
$ grep -rn "ToolRegistry(" agent/ --include=*.py | grep -v /tests/
agent/liveness_run.py:76:            tb = ToolRegistry(sc, lab_mode=True)
agent/liveness_run.py:84:            tb = ToolRegistry(_scope_for(check), lab_mode=True)
agent/main.py:573:    tools = ToolRegistry(scope, mission_id=session_id, lab_mode=(req.mode == "full"), ...)
agent/owasp_bench.py:146:    reg = tools_mod.ToolRegistry(sc, mission_id=None, lab_mode=True)

$ grep -rn "ToolRegistry(" agent/tests/ --include=*.py | wc -l
89
```

4 product, 89 test. The ticket said 4 and 87; the test count has grown by two since it was filed.

**MEASURED** — how many `.execute(` call sites anywhere in the tree name an INTRUSIVE engine
(regex over every `.py`, literal first argument):

```
DISTINCT literal .execute() tool names: 13
TOTAL literal .execute() sites: 32
INTRUSIVE literal .execute() call sites: 1
   ('./tests/test_mass_assign_tool.py', 608, 'run_mass_assign')
```

and that one is **inside a comment** (`#: Every field here was copied from a real run of
ToolRegistry.execute("run_mass_assign", ...)`), not a call. There are also **zero** non-literal
`.execute(` dispatches in the test tree. So the guard's refusal path touches no existing test.

---

## 2. THE DESIGN TENSION, RESOLVED — and why neither stated option was taken

The ticket framed it as REQUIRED (breaks 89 tests) vs DEFAULTED (opt-in guard = the
declaration-not-fact pattern). **Both readings assume the mode has to arrive through
`ToolRegistry.__init__`. It does not, and it should not.**

**MEASURED** — `BBHAgent.__init__` already pushes mission configuration onto the registry it was
handed, four times, as an established pattern:

```
agent/agent.py:455        self.tools.stop_event = stop_event
agent/agent.py:464-466    self.tools.zap_policy / zap_speed / zap_aggression = ...
```

The registry does not need a new constructor parameter to learn the mode. **The owner that already
knows the mode binds it**, exactly the way `stop_event` is bound — and `stop_event` is the precedent
that matters, because it is a LIVE object, not a snapshot.

That is also why this lane could resolve the tension without owning `agent/main.py`: `main.py:573`
builds the registry and `main.py:580` immediately hands it to `BBHAgent(..., mode=req.mode, ...)`.
Binding in the agent covers 100% of product missions with no edit to a file this lane does not own.

### The chosen shape

1. `ToolRegistry.__init__` gains **`mission_mode: str = None`** — defaulted, so all 89 test sites and
   all 4 product sites keep working byte-identically. `None` means **UNKNOWN**, not "passive" and not
   "active": a registry nobody bound a mission to.
2. `BBHAgent.mode` becomes a **property whose setter writes through** to `self.tools.mission_mode`.
   One place, not four. `ag.mode = "passive"` in a test or in product code cannot go stale, which is
   the failure the write-through exists to prevent — a snapshot taken in `__init__` would have gone
   stale in every test helper that assigns `ag.mode` after construction (there are several in
   `tests/test_permission_tiers.py` alone).
3. `BBHAgent.__init__` installs **`self.tools.intrusive_authorized = self._intrusive_authorized`**, a
   BOUND METHOD rather than a bool, because the HITL state mutates mid-mission (`None` →
   `approved`/`denied`). A snapshot would authorise or refuse on state from before the operator
   answered the gate.
4. The guard lives in `ToolRegistry._dispatch_engine`, immediately before the scope check, so a
   refusal is bracketed by the Q-061 ledger exactly as a `SCOPE BLOCK` is — a refused dispatch is
   VISIBLE, not silent.

### Why UNKNOWN fails OPEN, deliberately

`mission_mode is None` performs **no check at all**. This is the DoD's second half, and it is the
control this ticket predicted would be skipped. Failing closed on unknown would refuse the five
ACTIVE engines that reach `execute()` directly (`acquire_session`, `browser_navigate`, `http_probe`,
`http_read`, `run_dom_audit`), plus every one of the 89 test registries and both bench/liveness
harnesses — converting a latent permission gap into a live capability loss, which the ticket
correctly calls strictly worse than the hole.

**The opt-in problem is answered by a RATCHET, not by a default.** `test_every_product_registry_binds_a_mode`
walks the AST of every non-test `.py` file, finds every `ToolRegistry(...)` construction, and requires
each one either to be handed to a `BBHAgent(...)` in the same function or to appear in an explicit
allowlist. The allowlist entries carry their own **fact** check: an allowlisted file must contain no
`.execute(` call, so "this registry never dispatches" is verified rather than declared. A future
product site that constructs a registry, skips the binding and dispatches through it turns the suite
RED. That is the difference between this and the eleven declaration-not-fact guards this project has
hit: the ratchet checks what the file does, not what it says.

---

## 3. Why the guard is NOT "refuse INTRUSIVE whenever mode == active"

**This is the finding that changes the ticket.** Taken literally, DoD half 1 contradicts DoD half 2.

**MEASURED** — INTRUSIVE engines that product code dispatches today, in an `active` mission:

```
agent/agent.py:1046   await self._exec_internal("run_stored_xss", ...)             # INTRUSIVE
agent/agent.py:1062   await self._exec_internal("run_bfla", ...)                   # INTRUSIVE
agent/agent.py:2277   await self._exec_internal("confirm_authz_write", ...)        # INTRUSIVE
agent/agent.py:2302   await self._exec_internal("confirm_create_object_idor", ...) # INTRUSIVE
plus the agentic path: the model may name any registered tool, and `_run_tool` admits INTRUSIVE at
`active` once the HITL gate is approved.
```

`_exec_internal` (agent.py:689-706) admits these at `active` when ANY of: the HITL gate was approved,
`auto_approve`, or `authenticated_scan`. `_run_tool` (agent.py:614-623) admits them at `active` once
the gate is approved. **Both are deliberate**, and Q-052's decision text says so: "The 9 stay behind
the existing HITL gate and `auto_approve`" — an authorization gate, not a mode gate.

A dispatcher guard keyed on the mode alone would refuse four measured product call sites and the
whole agentic intrusive path **in exactly the missions where the operator had already said yes.**

**A BACKSTOP MUST NEVER BE STRICTER THAN THE LAYER IT BACKS.** The dispatcher therefore enforces the
UNION of what the two wrappers permit — the weakest necessary condition — so it can only ever refuse
a dispatch that NO gated path would have made:

```
mission_mode is None / unrecognised   -> allow  (no mission bound; see §2)
mission_mode == "passive", tier != PASSIVE      -> REFUSE
tier == INTRUSIVE and not intrusive_authorized()-> REFUSE
otherwise                                       -> allow
```

DoD half 1 is satisfied in the form that carries its meaning: **an INTRUSIVE engine dispatched
through `Tools.execute()` in a default `active` mission — no gate answered, no `auto_approve`, no
`authenticated_scan` — is REFUSED with a reason.** That is precisely the hole the ticket describes
("one new call site away"): a new direct `self.tools.execute("run_upload_test", ...)` would have run
unchecked and now cannot.

---

## 4. What landed (commit `118e858`)

| file | change |
| --- | --- |
| `agent/tools.py` | `ToolRegistry.__init__(..., mission_mode: str = None)` + `self.intrusive_authorized = None`; new `ToolRegistry._permission_refusal(tool_name)`; two lines at the top of `_dispatch_engine` that consult it |
| `agent/agent.py` | `BBHAgent.mode` is now a property whose setter writes through to `tools.mission_mode`; `__init__` installs `tools.intrusive_authorized = self._intrusive_authorized`; new `BBHAgent._intrusive_authorized()`; `_exec_internal` calls it instead of restating the expression |
| `agent/tests/test_dispatch_permission_guard.py` | new — 47 tests |

**MEASURED** — the refusal matrix, driven through the real `_permission_refusal`:

```
unbound + INTRUSIVE                    -> None                      (admitted)
active + INTRUSIVE, no auth            -> 'PERMISSION BLOCK: run_upload_test is INTRUSIVE ...'
active + INTRUSIVE, approved           -> None                      (admitted)
full   + INTRUSIVE, no auth            -> 'PERMISSION BLOCK: ...'
passive + ACTIVE                       -> 'PERMISSION BLOCK: http_probe is ACTIVE and this mission is PASSIVE ...'
passive + PASSIVE                      -> None                      (admitted)
active + ACTIVE                        -> None                      (admitted)
bogus mode ("Active") + INTRUSIVE      -> None                      (admitted — unknown, see §2)
```

**MEASURED** — the binding, through a real `BBHAgent` over a real `ToolRegistry`:

```
mission_mode after construct: active
intrusive_authorized bound: True   -> False        (no gate answered yet)
after ag.mode='passive':  passive                  (write-through)
after ag.mode='garbage':  active | ag.mode: active (both sides normalise identically)
after ag.intrusive_state='approved': True          (read LIVE, not snapshotted)
```

### The controls, named

- **Positive (DoD half 1).** 5 INTRUSIVE engines × refused at `active` with no authorization, driven
  through the real `execute()`, with `reg.admitted == []` proving the engine BODY never ran.
- **Negative (DoD half 2).** The five ungated-path ACTIVE engines dispatch **bound** (`active`) and
  **unbound** (`None`) — 10 assertions — plus 5 more proving an unbound registry does not refuse even
  an INTRUSIVE engine, which is what keeps `owasp_bench` and 89 test registries working.
- **Control ON the negative control.** `test_the_apparatus_can_observe_a_refusal_at_all` uses the
  same factory, the same `_dispatch`, the same `_is_refusal` and asserts a refusal IS seen. Without
  it, four parametrised "nothing was refused" tests would pass just as happily if `_is_refusal` were
  broken. **Every zero in this file has a positive control behind it.**
- **Control on the ratchet.** `test_the_census_finds_the_product_registry_sites_at_all` fails if the
  AST walk finds nothing — a silent-empty walker is how a guard that checks a declaration passes
  what it exists to catch.
- **Anti-widening.** `test_run_tool_keeps_its_STRICTER_rule` asserts `_run_tool` does NOT consult
  `authenticated_scan` or the shared helper. Naming the union must not loosen the strictest gate.

### Honest limit of the ratchet

`test_every_product_registry_binds_a_mode` reasons per MODULE. `liveness_run.py` holds one bound
registry (line 76 → `BBHAgent` line 78) and one unbound (line 84), and passes on the strength of the
bound one. **MEASURED**: 0 of the 3 product modules that construct a `ToolRegistry` contain any
`.execute(` call, so no unbound registry can currently dispatch. That measured fact is frozen by
`test_no_product_module_both_builds_a_registry_and_dispatches_through_it`; the day a module does
both, name-based reasoning stops being sufficient and a human has to look.

---

## 5. ANTI-IDLE — what the other unlogged `tools.execute(` sites bypass besides the tier

Q-061 fixed the LEDGER half of these sites. The question nobody had asked is what OTHER per-dispatch
policy they skip.

**MEASURED** — AST over `agent.py`, every `self.tools.execute(` call:

```
self.tools.execute( sites: 11        (Q-061 counted 12; `run_jsonp` has since moved to _exec_internal)
  line 693   <variable>   -- _run_tool      (gated wrapper)
  line 779   <variable>   -- _exec_internal (gated wrapper)
  line 991   run_dom_audit
  line 1609  acquire_session
  line 1982  http_probe
  line 2006  http_read
  line 2011  browser_navigate
  line 2039  http_read
  line 2070  acquire_session
  line 2207  acquire_session
  line 2233  browser_navigate
```

9 direct sites, 5 distinct engines, all ACTIVE — the ticket's premise re-confirmed at HEAD.

`_run_tool` performs **nine** things around a dispatch. The 9 direct sites perform **one** of them
(the dispatch). Here is each, with whether it matters, MEASURED rather than asserted:

| skipped policy | matters? |
| --- | --- |
| **1. permission tier** | **CLOSED by this ticket.** Was the whole of Q-079. |
| **2. INTRUSIVE authorization** | **CLOSED by this ticket** — a direct site can no longer dispatch an unauthorized INTRUSIVE engine. The interactive MODAL still cannot be raised from the dispatcher (it yields no events); a direct site gets a refusal, not a prompt. Correct: a code path that never asks must not be able to act. |
| **3. `_stamp_dispatch` (Q-064)** | **No loss, measured.** 8 of the 9 skip it, but all 8 DISCARD the `ToolResult` — they are called for their side effects on `tools.urls` / `tools._sessions` / harvested forms. The one site whose findings ARE persisted (`run_dom_audit`, line 991) already calls `_stamp_dispatch` explicitly at line 1000. |
| **4. `_auto_store` (Q-054)** | **One site, compensated — UNVERIFIED whether fully.** Of the 5 engines on this path only `run_dom_audit` is in `_AUTO_STORE_TOOLS`. Its findings are collected into `dom_findings` and persisted by the candidate pipeline as promoted candidates. Whether the pipeline persists EVERY finding `_auto_store` would have is not measured here. |
| **5. phase tracking (`_set_phase`)** | Cosmetic. These dispatches never advance `current_phase`, so an authenticated re-crawl does not move the phase indicator. |
| **6. the LIVE UI event stream** | **Real and open.** Q-061 fixed the persisted ledger; the live feed is built from the events `_run_tool` YIELDS, and these 9 sites yield nothing. An operator watching a mission sees the whole authenticated re-crawl and persona-login phase as dead air. Not a correctness defect; it is why "the scan looks hung" reports exist. |
| **7. `scope_block` vs `tool_error` classification** | Follows from 6. |
| **8. `store_finding` dedup** | n/a — none of these five is `store_finding`. |
| **9. stop-event honouring** | Each direct site does its own `self.stop_event.is_set()` check; verified at 991, 1982 and the crawl loops. |

### And the finding that is NOT about the tier at all

**MEASURED** — the exception handler wrapping each direct site:

```
  line 1609  acquire_session      BARE swallow (pass)
  line 2011  browser_navigate     BARE swallow (pass)
  line 2070  acquire_session      BARE swallow (pass)
  line 991   run_dom_audit        BARE swallow (continue)
  line 1982  http_probe           RECORDED via _swallow
  line 2233  browser_navigate     BARE swallow (pass)
  line 2006  http_read            BARE swallow (pass)
  line 2039  http_read            BARE swallow (pass)
  line 2207  acquire_session      BARE swallow (pass)
```

**8 of 9 dissolve their failures; 1 of 9 records.** This is Q-052 slice 1's defect (nine bare
swallows in the sweep) in a second location that the slice did not cover. It matters more here than
in the sweep, because these five engines are the AUTHENTICATION ARTERY: line 2233 is the
browser-driven login fallback, and a raise there produces a mission with no personas, no authz
matrix and no explanation anywhere — the run reads as "the target has no authenticated surface".
`ToolRegistry._swallow` exists for exactly this and the one site that uses it (1982) is the pattern
to copy.

**Not fixed under this ticket** — it is a separate defect with its own DoD (each converted handler
needs a test that a raise is RECORDED, and a negative control that a clean run records nothing) and
this lane's remit was the tier. Filed here as the next slice.

---

## 6. Status

- [x] Measured the premise at HEAD
- [x] Resolved the design tension
- [x] Implement the guard + binding — `118e858`
- [x] DoD half 1 (positive control)
- [x] DoD half 2 (negative control — the five ACTIVE engines, bound AND unbound)
- [x] Ratchet test for the opt-in half, with its own positive control
- [x] ANTI-IDLE: audited all 9 unlogged `tools.execute(` sites
- [ ] Full suite (running against an isolated snapshot of HEAD)
