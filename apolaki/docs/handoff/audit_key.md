# Q-081 - the audit-key lane: the KEY check, verified rather than inherited

Owner: audit-key lane (Builder). Files I may write: `agent/engine_descriptor.py`,
`agent/techniques.py`, `agent/effect_search.py`, tests under `agent/tests/`, this file. Patches for
files I do not own go at the bottom, unapplied.

Every claim below is **MEASURED** (command + real output) or **UNVERIFIED**. Every zero carries a
positive control naming the fields the instrument read.

---

## 0. THE FIRST THING I MEASURED WAS THE TICKET

Q-081 is marked `ready` in `docs/QUEUE.md`. **It is not open.** DoD items 1 and 2 landed one commit
before the ticket's own predecessor commit:

```
$ git log --oneline -3
29d00d2 Apolaki: Q-052 slice 2 settled by counting writes, and two new criticals filed (#123)
db150c1 Apolaki Q-074 run 4: the effects guard interrogated the engine and took the KEY on trust
0276ae0 Apolaki Q-074 run 4: run_csrf kills the session too, and the door is four engines wide
```

`db150c1` added `unknown_technique` to `effects_audit`, put it in the `ok` clause, added `bool(known)`
to the non-vacuity clause, and shipped `agent/tests/test_effects_key_is_a_technique.py` (8 tests,
including the "real technique + real engine still passes" negative control DoD 2 asks for).

So this lane's work is **not to write the fix again**. It is to (a) verify the landed fix
adversarially rather than take its commit message on trust, (b) run the corrected audit and report
the count, (c) decide `csrf_token_missing`, and (d) sweep the sibling guards for the same shape.
Re-implementing a landed fix and reporting it as new work is its own kind of declaration-versus-fact.

---

## 1. THE APPARATUS

Two other lanes are live in this tree, so every probe runs against an **ISOLATED SNAPSHOT of HEAD**,
never the shared worktree:

```
git archive HEAD apolaki/agent | tar -x -C <scratchpad>/snap        # HEAD = 29d00d2
MSYS_NO_PATHCONV=1 docker run --rm --network apolaki_default -e PYTHONPATH=/app \
  -v "<scratchpad>/snap/apolaki/agent:/app" -v "<scratchpad>/probe:/probe" \
  -w /app apolaki-agent python /probe/<probe>.py
```

**Fields and attribute names read**, stated so a later reader can tell the instrument from the code:
`engine_descriptor.EFFECTS` / `.PRECONDITIONS` / `.ALWAYS_ON` (dict KEYS);
`effects_audit()["ok" | "checked" | "unknown_technique" | "technique_table_size" | "registry_size" |
"implementations_size" | "no_engine_declared" | "unregistered" | "unimplemented"]`;
`build()` (dict keys); `conflicts()` (list of 3-tuples, element 0 = producer);
`routes()[tid]` (dict engine -> source set); `techniques.TECHNIQUES` (dict keys) and each record's
`"id"` field. Probe source: `probe/p1_key_fact.py`, grep-confirmed (4 hits on `csrf_token_missing`)
before it was allowed to run.

---

## 2. DoD 3 - THE CORRECTED AUDIT, RUN. The count is ZERO, and here is the proof it was looking.

MEASURED, probe section A:

```
A_shipped   ok                     : True
            checked                : 12          <- EFFECTS rows
            technique_table_size   : 88
            registry_size          : 111
            implementations_size   : 166
            unknown_technique      : []          <- THE COUNT: 0
            no_engine_declared     : []
            unregistered           : []
            unimplemented          : []
```

**A zero from a guard is worth nothing without a positive control**, so the same instrument, same
call, one row added:

```
B_positive_control  EFFECTS + {"csrf_token_missing": {"invalidates": ["authenticated"],
                                                      "engine": ["run_csrf"]}}
            ok                     : False
            unknown_technique      : ['csrf_token_missing']
            unregistered           : []          <- the engine half stayed silent, so the
            unimplemented          : []             failure is attributable to the KEY alone
```

**VERDICT: `csrf_token_missing` was the only bad key, and it was never in the shipped table** - it
was the Q-074 lane's probe fixture. All 12 shipped keys are real techniques. The apparatus is
demonstrably able to say otherwise.

## 2b. The three non-vacuity numbers are real, not defaults

`88 / 111 / 166` are the technique table, `tools.TOOL_PERMISSIONS`, and `ToolRegistry._<name>`
implementations. A guard scanning an empty fact table passes for free; these are the numbers proving
it did not.

---

## 3. IS `TECHNIQUES` THE FACT THAT DECIDES REACHABILITY, OR ONE HOP AWAY FROM IT?

The guard reads `set(techniques.TECHNIQUES)` - dict KEYS. `build()` keys descriptors on each record's
`"id"` FIELD and drops any record whose id is falsy (`if t.get("id")`). Those are two different
expressions, and this project has been bitten three times by an instrument reading a neighbouring
field. MEASURED, probe section C:

```
C_instrument_vs_fact
  len_TECHNIQUES_keys        : 88
  len_record_id_field        : 88
  len_build_descriptors      : 88
  keys_minus_built           : []      <- no key the guard accepts that build() drops
  built_minus_keys           : []
  records_where_key_ne_id    : []
  records_with_falsy_id      : []
```

The two expressions agree today **by construction**: `techniques.py:88` is
`TECHNIQUES: dict[str, dict] = {t["id"]: t for t in [...]}`, so the key IS the id field. That is a
real structural guarantee, not a coincidence - but it is a guarantee held by a line in a different
file, so section 6 pins it.

---

## 4. DoD 4 - WHAT HAPPENS TO `csrf_token_missing`

MEASURED, probe section F, on the shipped tree:

```
F_csrf  csrf_in_TECHNIQUES   : True     csrf_in_build      : True
        csrf_preconditions   : ['has_login']
        csrf_routes          : {'run_csrf': ['wstg_full']}
        csrf_in_EFFECTS      : False
        run_csrf_registered  : True     run_csrf_implemented : True
        csrf_record          : id=csrf  vuln_class=csrf  permission=ACTIVE  wstg=WSTG-SESS-05
                               execution=auto  transferable=True
```

So the re-key target exists and is fully reachable: `csrf` is a technique, it is evidence-gated on
`has_login`, it routes to `run_csrf`, and `run_csrf` is registered and implemented. An entry
`"csrf": {"establishes": [], "invalidates": ["authenticated"], "engine": ["run_csrf"]}` would pass
the corrected audit and WOULD become a descriptor.

**Decision and its reasoning are in section 5**, after the adversarial verification, because the
decision turns on a measurement I had not taken when I wrote this section.

---

*(sections 5+ appended as the lane proceeds)*
