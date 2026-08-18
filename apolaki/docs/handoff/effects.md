# Effects lane - Q-007, the phantom that generates the whole negative-effects model

Owner: effects lane (Builder). Files written: `agent/engine_descriptor.py`, `agent/effect_search.py`,
`agent/techniques.py`, tests under `agent/tests/`, this file.

Every claim below is MEASURED (command + real output) or UNVERIFIED. Every zero carries a positive
control proving the apparatus was looking. Written as the work happened; rows are not promoted to a
verdict before the evidence exists.

---

## 0. THE APPARATUS

All probes run in a throwaway container against the WORKTREE source, never `apolaki-agent-1`:

```
MSYS_NO_PATHCONV=1 docker run --rm --network apolaki_default -e PYTHONPATH=/app \
  -v "C:/Users/voice/Desktop/GitHub/MISC/apolaki/agent:/app" \
  -v "<scratchpad>:/probe" -w /app apolaki-agent python /probe/<probe>.py
```

`PYTHONPATH=/app` is load-bearing and was an instrument error first: python puts the SCRIPT's
directory on `sys.path`, not the working directory, so `-w /app` alone gives
`ModuleNotFoundError: No module named 'engine_descriptor'` - which reads exactly like "the module is
broken" rather than "the probe cannot see it". Recorded because it is the third instrument error in
this project's probes this week.

Field/attribute names read, stated so a later reader can tell the instrument from the code:
`engine_descriptor.PRECONDITIONS`, `.EFFECTS`, `.ALWAYS_ON`, `.OBSERVATIONS`, `.routes()`,
`.routing_audit()`, `.conflicts()`, `.chains()`, `.build()`, `.validate()`;
`tools.TOOL_PERMISSIONS` (dict, keys are engine names), `tools.CLAUDE_TOOLS`,
`tools.ToolRegistry._<name>` (the implementation), `techniques.TECHNIQUES` (dict id -> record),
`wstg_catalog.FULL` / `.PARTIAL`, `technique_planner.orchestration_audit()["islands"]`.

---

## 1. BASELINE - the tail sweep reproduces exactly

MEASURED, probe `q007_baseline.py`:

```
EFFECTS entries total                 : 13
EFFECTS with NON-EMPTY invalidates    : ['weak_password_reset']
EFFECTS with NON-EMPTY establishes    : 13

conflicts() rows: 6
    ('weak_password_reset', 'authenticated', 'cache_deception')
    ('weak_password_reset', 'authenticated', 'jwt_forge')
    ('weak_password_reset', 'authenticated', 'jwt_key_confusion')
    ('weak_password_reset', 'authenticated', 'session_fixation')
    ('weak_password_reset', 'authenticated', 'session_lifecycle')
    ('weak_password_reset', 'authenticated', 'weak_2fa_bypass')
distinct producers in conflicts(): ['weak_password_reset']

POSITIVE CONTROL (same apparatus, same run): chains() = 58 rows from 12 distinct producers.
The graph walk works; conflicts() is single-sourced because the TABLE is single-sourced.
```

Executor fact, `tools.TOOL_PERMISSIONS` (111 keys) + `_run*/_confirm*` methods (96) +
`CLAUDE_TOOLS` (76), union, leading underscore stripped:

```
names containing reset        -> []
names containing passwd       -> []
names containing password     -> []
names containing sqli         -> ['run_auth_sqli','run_form_nosqli','run_nosqli',
                                  'run_path_sqli','run_sqli','run_sqli_structural']   <- POSITIVE CONTROL
```

`solver_only` present on 0 of 88 technique records - the 08-10 recommendation named a field that does
not exist. CONFIRMED, not re-derived.

---

## 2. THE MEASUREMENT THAT DECIDES IT

The ticket offers two honest resolutions and says to measure which one the code already implies.
Option B is "keep the phantom, make the planner ignore effects from engines with no executor". That
requires an automatable "has no executor" signal. The only one this module has is `routes()`, and
MEASURED (probe `q007_producers.py`), `routes()` is WRONG about two real engines:

| EFFECTS producer | routes() | registered? | `ToolRegistry._<name>`? | dispatched from |
|---|---|---|---|---|
| `default_credentials` | **NO ROUTE** | `run_default_creds` yes (`tools.py:211`) | yes (`tools.py:9286`) | `agent.py:3657` |
| `saml_signature_bypass` | **NO ROUTE** | `run_saml` yes (`tools.py:258`) | yes (`tools.py:2562`) | `agent.py:2544` |
| `soft_deleted_login` | **NO ROUTE** | `run_soft_deleted_login` **no** | **no** | - |
| `weak_password_reset` | **NO ROUTE** | `run_password_reset` / `run_weak_password_reset` **no** | **no** | - |

NEGATIVE CONTROL for that probe: `run_apolaki_not_a_tool` -> registered False, method False. The
membership test can return False, so the True rows are not the instrument agreeing with itself.

Why `routes()` misses two real engines, MEASURED rather than guessed: the derivation reads
`ALWAYS_ON` prose and `wstg_catalog.FULL`. `WSTG-ATHN-02` (default_credentials) is in
`wstg_catalog.PARTIAL`, not `FULL`; `saml_signature_bypass` has `wstg=None`
(`techniques.py:1172` records "WSTG-ATHZ-05 covers OAuth, not SAML assertion handling").

**So option B, implemented on the only signal available, would silently delete the effects of two
registered, implemented, dispatched engines in order to keep one that does not exist.** That is not a
judgement call; it is the measurement.

### DECISION: REMOVE. Stated plainly, with the reason.

`weak_password_reset` is dropped from `EFFECTS`. Three further facts, in order of weight:

1. **The table already states the rule and this entry is its only violation.** The `EFFECTS` comment
   block already refuses an effect for a catalog entry with no executor, by name:
   "NOT `find_hidden_route`: it is a lab-local catalog entry with no executor and no gate, so an
   effect declared on it could never fire. Over-declaring is worse than not declaring". The code did
   not need a new policy; it needed the policy applied to the entry that predates it.
2. **The same decision was already taken twice, deliberately, with the reason written down** -
   `mass_assignment` (Q-011, `engine_descriptor.py:59-63`) and `session_lifecycle`
   (`engine_descriptor.py:96-101`) both have a precondition and NO effects entry, each with a stated
   reason. Absence of an EFFECTS row is an existing, exercised convention here, not a gap.
3. **Option B needs a declaration field that does not exist.** `solver_only` is on 0 of 88 records.
   Keeping the phantom means inventing a new declaration to excuse it - the exact failure mode
   ("guards that check declarations, not facts") this project has shipped eight times.

### The second decision: `session_lifecycle` does NOT inherit the `invalidates`.

The 08-10 recommendation and the tail sweep both say to re-home `invalidates: ["authenticated"]` onto
`session_lifecycle`. **Measured against the engine, that is wrong, and it is wrong for the same
reason the phantom is wrong: it over-declares.**

`session_lifecycle` cannot invalidate the engagement's `authenticated` observation. Three independent
mechanisms in the shipped code, all read directly:

- `tools.py:9174 _sl_mint` creates a SACRIFICIAL account through the target's own signup, one per
  mission, under a dedicated persona label.
- `tools.py:9139 _sl_req` is a private client that deliberately does NOT merge `self.session_headers`
  (its docstring says so and says why); the shared `_http` does, so it is never used by this engine.
- `tools.py:8945 _session_kill_is_safe` re-checks the FACT before the destructive step: the
  credential about to be logged out must be value-disjoint from `session_headers` and from every
  stored persona session, else the engine returns `inconclusive` and does nothing.

The session it ends is its own. The engagement's `authenticated` observation survives, so the effect
would be a fiction - and `engine_descriptor.py:96-101` already says exactly this, in a comment
written before this lane existed. The tail sweep read `EFFECTS` and did not read the comment eleven
lines away in `PRECONDITIONS`.

**Consequence, stated rather than hidden: `conflicts()` becomes empty, and Apolaki has NO engine with
a real negative effect.** That is not a hole left by this change; it is a consequence of the
non-destructive doctrine. Every action that would delete an engagement-level observation - ending the
scan's session, rotating the scan's credential, deleting data - is exactly what that doctrine
forbids. The Sussman machinery (`successor()` applying `invalidates` after `establishes`,
`breaks()`, `conflicts()`) stays proven at the ALGORITHM level over synthetic descriptors, which is
where a mechanism with no shipped instance belongs.

---

## 3. A SECOND PHANTOM, same shape, found by the same probe

`soft_deleted_login` declares `establishes: ["authenticated"]` and has **no executor**: no registered
name, no `ToolRegistry` method, no `wstg` id, no dispatch site. Its `maps_to` is the Juice Shop "GDPR
Data Erasure" challenge and `techniques.py:1208` records a hand-written curl recipe - the same
lab-solver backfill shape as `weak_password_reset` and `mass_assignment` (Q-011).

`run_auth_sqli` exists and the technique's `exploit` text mentions an "SQLi email+comment", but it is
NOT this technique's executor: `run_auth_sqli`'s oracle is auth bypass via an OR-payload; it cannot
observe that the account it logged into was soft-deleted, which is the whole claim.

It is removed under the same one rule, in the same commit. A guard that shipped with a day-one
exception hole for the twin of the defect it exists to catch would be the eighth instance of the
failure this ticket names.

---

## 4. WORK LOG

Status is what HAPPENED. `in progress` is a real state; a row becomes a verdict only under evidence.

| slice | state | evidence |
|---|---|---|
| S0 baseline measured, decision made | DONE | sections 1-3 above |
| S1 negative control: guard fails on the real phantoms BEFORE the fix | in progress | - |
| S2 remove the two phantoms; guard green | in progress | - |
| S3 pinned tests re-pointed; full suite | in progress | - |
| S4 anti-idle audit of the remaining EFFECTS entries | in progress | - |
