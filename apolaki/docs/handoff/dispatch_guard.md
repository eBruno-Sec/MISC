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

## 4. Status

- [x] Measured the premise at HEAD
- [x] Resolved the design tension
- [ ] Implement the guard + binding
- [ ] DoD half 1 (positive control)
- [ ] DoD half 2 (negative control — the five ACTIVE engines, bound AND unbound)
- [ ] Ratchet test for the opt-in half
- [ ] Full suite
- [ ] ANTI-IDLE: audit the other 10 unlogged `tools.execute(` sites
