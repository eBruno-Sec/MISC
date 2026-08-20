# Negative-effects lane, run 2 — Q-074: is the negative half load-bearing?

Owner: negative-effects lane run 2 (Builder). Files I may write: `agent/engine_descriptor.py`,
`agent/techniques.py`, `agent/effect_search.py`, tests under `agent/tests/`, this file. Patches for
files I do not own are at the bottom, **not applied**.

Predecessors, all left intact and all read before touching anything: `docs/handoff/effects.md`
(Q-007, removed the phantom), `effects2.md` (found `race_condition`), `effects3.md` (measured the
consumer graph), `effects4.md` (measured the door at four engines), `session_door.md` (Q-080, the
lane that FIXED the door). There was no `negative_effects.md` before this file.

Every claim below is MEASURED (command + real output) or UNVERIFIED. Every zero carries a positive
control naming what the apparatus was looking at.

---

## 0. THE APPARATUS

HEAD = `c226ae0`. Two other lanes are live in this tree, so every probe runs against an **isolated
snapshot of HEAD**, never the shared worktree:

```
git archive HEAD apolaki/agent | tar -x -C <scratchpad>/snap
MSYS_NO_PATHCONV=1 docker run --rm --network apolaki_default -e PYTHONPATH=/app \
  -v "<scratchpad>/snap/apolaki/agent:/app" -v "<scratchpad>/probe:/probe" \
  -w /app apolaki-agent python /probe/<probe>.py
```

**INSTRUMENT ERROR, sixth recorded instance of the same shape.** A `python - <<EOF` heredoc to patch
a probe on the HOST printed `Python was not found; run without arguments to install from the
Microsoft Store` — the Windows Store stub, exit non-zero, **file unmodified**. The `grep` that every
probe edit is followed by printed nothing, which is the only reason I did not re-run an unchanged
probe and read its old output as a new result. Every probe below is grepped before it is allowed to
run. `effects4.md` recorded this as the fifth instance; it is now the sixth, and it belongs in the
standing notes rather than in a seventh handoff.

---

## 1. THE PREMISE OF MY OWN BRIEF DOES NOT REPRODUCE

My dispatch said "**`run_csrf`'s effect is keyed WRONG** … the negative-effects entry for it does not
key to the thing it actually invalidates," and "roughly 6 conflict rows and 12 EFFECTS entries."

The counts are right. The entry is not. **There is no `run_csrf` entry, correctly keyed or
otherwise.** MEASURED, probe `n1_baseline.py` + `n2_keys.py` against the shipped table:

```
EFFECTS entries                        : 12
entries with NON-EMPTY invalidates     : 1
    race_condition -> {'establishes': [], 'invalidates': ['authenticated'], 'engine': ['run_race']}
POSITIVE CONTROL entries w/ establishes: 11
conflicts() rows                       : 6      (all produced by race_condition)
descriptors                            : 88

csrf-keyed EFFECTS entries             : []
every engine named in EFFECTS          : ['confirm_browser_persona_bola', 'run_auth_sqli',
    'run_default_creds', 'run_dir_harvest', 'run_exposure', 'run_graphql', 'run_js_review',
    'run_jwt', 'run_race', 'run_saml', 'run_sqli', 'run_sqli_structural']
'run_csrf' among them                  : False
POSITIVE CONTROL 'run_race' among them : True

routes()['csrf']           = {'run_csrf': ['wstg_full']}          <- `csrf` IS the right key
routes()['race_condition'] = {'run_race': [...], 'run_upload_test': [...]}
'csrf' in TECHNIQUES       : True    'csrf_token_missing' in TECHNIQUES : False
```

So the correct key for `run_csrf` **would be** `csrf` (a real technique id, routed to that engine and
no other). `csrf_token_missing` — the string my brief's lineage traces back to — is the *mutant*
Q-081 used as a negative control, never a shipped row. Section 4 says why the row must nevertheless
**not** be created.

**A wrong premise handed down in a dispatch is a result, not an obstacle**, and it is recorded here
because the same sentence will otherwise be handed to run 3.

---

## 2. THE QUESTION, ANSWERED: **NO. THE PLANNER DOES NOTHING DIFFERENTLY.**

Re-derived independently at HEAD rather than inherited from `effects3.md`, because `agent.py` and
`planner.py` both changed substantially under Q-080 since that measurement was taken.

MEASURED, probe `n4_consumers.py` — the COMPLETE production consumer graph of the effects model,
every `.py` under `/app`, tests excluded, **184 files walked**:

```
=== QUALIFIED ATTRIBUTE READS on the effects modules ===
  main.py              :1342  engine_descriptor.build
  main.py              :1343  engine_descriptor.validate
  main.py              :1344  engine_descriptor.chains
  main.py              :1344  engine_descriptor.conflicts  <-- NEGATIVE HALF
  main.py              :1349  engine_descriptor.verify_always_on
  main.py              :1426  engine_descriptor.build
  main.py              :1429  effect_search.frontier
  main.py              :1432  effect_search.plan
  scan_scope.py        :116   engine_descriptor.build
  technique_planner.py :58    engine_descriptor.routing_audit
  total qualified reads: 10

=== from-imports ===
  technique_planner.py :23  from engine_descriptor import ALWAYS_ON / OBSERVATIONS / PRECONDITIONS
  total from-imports: 3

=== NEGATIVE-HALF function readers (conflicts / breaks / successor) ===
  main.py:1344  engine_descriptor.conflicts
  count: 1

=== NEGATIVE CONTROL: the files that decide what a scan RUNS ===
  agent.py     qualified reads=0  from-imports=[]
        raw substring engine_descriptor present: False
        raw substring effect_search     present: False
  planner.py   qualified reads=0  from-imports=[]
        raw substring engine_descriptor present: False
        raw substring effect_search     present: False
  technique_planner.py  qualified reads=1  from-imports=[OBSERVATIONS, PRECONDITIONS, ALWAYS_ON]
        raw substring engine_descriptor present: True     <- POSITIVE CONTROL, the check can see one
```

**The instrument, stated so it is separable from the code.** The walk resolves each file's own module
ALIAS from its `import` statements and counts only attribute access qualified on that alias, plus
`from <mod> import <name>` bindings. A bare `ast.Name` match is deliberately NOT counted:
`effects3.md` recorded that shape reporting three *local variables* named `frontier` as consumers —
the flattering answer. The raw-substring row is the belt-and-braces control: it would catch a read
through `importlib`, a string, or an alias my resolver missed. It reports `False` for both modules in
both scan-path files.

### 2a. Three facts follow, and they are measurements

1. **`agent.py` and `planner.py` import neither module** — not by alias, not by from-import, not as a
   raw substring anywhere in the file. The mission runner and the step planner **cannot** consult the
   effects model, so no value in it can change what a scan does.
2. **The negative half reaches production at exactly ONE call site**: `main.py:1344`, inside
   `POST /orchestration/audit`, where `conflicts()` becomes the `conflict_count` / `conflicts` fields
   of a JSON report. `effect_search.plan` and `.frontier` (`main.py:1429/1432`, `POST
   /orchestration/reachability`) do read `invalidates` transitively through `successor()`, and
   section 3 measures that neither of their outputs changes when the row is deleted.
3. **`breaks()` has no caller outside `effect_search.frontier` and the test suite.** It is the
   function that most directly expresses the negative half and no production code calls it by name.

### 2b. VERDICT, in the words the ticket asks for

**With respect to the planner, the negative-effects row is DECORATION.** Not one scheduling
decision, step ordering, batch, or engine dispatch differs because it exists, and that is a
structural fact about the wiring rather than a property of this particular row: the two files that
decide what a scan runs do not import the effects model at all.

It is **not** decoration in the full island sense, and saying so would be as inaccurate in the other
direction: it changes the JSON of one shipped HTTP endpoint (`conflict_count` 0 → 6), and an operator
reading that endpoint sees a real cost where the field previously read `0` because the model was
empty. That is a gain in the honesty of a published number and nothing more.

### 2c. What I deliberately did NOT do

The tempting move is to add a consumer to `effect_search.py` — a "safe ordering" helper or a
session-risk report — so the table has a reader. **Nothing in `agent.py` or `planner.py` could call
it**, so it would be a new unreachable function declared to close a gap it cannot reach: the exact
defect this project has now shipped eleven times, and the reason the dead-code ratchet exists. An
inert entry honestly labelled is worth more than a second unwired mechanism. `effects3.md` reached
the same conclusion and it was right to.

---

## 3. WHAT THE ROW IS WORTH, PROVED BY MUTATION

MEASURED, probe `n6_mutation.py`. `ED.EFFECTS` with the `race_condition` row deleted — which is
byte-for-byte the pre-Q-074 model — against the shipped table, observations
`{has_login, authenticated, serves_js}`:

| consumer | shipped | row deleted |
|---|---|---|
| `conflicts()` | **6** | **0** |
| `breaks(d, obs, race_condition)` | **the 6 consumers of `authenticated`** | **[]** |
| `frontier()["consequences"]` | **8** | **7** |
| `frontier()["always_on_with_effects"]` | **3** | **2** |
| `chains()` | 46 | 46 |
| `frontier()["applicable_now"]` | 16 | 16 |
| `frontier()["reachable_goals"]` | 4 | 4 |
| `plan(-> authenticated)` | `['sqli_auth_bypass']` | `['sqli_auth_bypass']` |
| `plan(-> credentials_exposed)` | `[]` | `[]` |
| `build()` descriptors | 88 | 88 |

Restore check on the same process: `conflicts()` back to 6.

`plan()` being unchanged is **arithmetic, not a defect**, and it is stated rather than hidden:
`_plan_core` records a candidate only when the goal appears in a successor state, and
`race_condition` establishes nothing, so a negative-only action can never shorten a plan — it can
only add expansions. `tests/test_effects_negative_half.py::test_the_plan_search_is_deliberately_UNCHANGED_by_the_negative_effect`
already pins that so nobody later "fixes" it into looking like a win.

Everything in the CHANGED half of that table is read by one reporting endpoint or by nothing at all.
That is the mutation proof of section 2b: **the row is load-bearing for a number in a JSON report and
for nothing else.**

---

## 4. THE ROW'S OWN MEASURED BASIS WAS REMOVED BY Q-080, AND THE COMMENT IS NOW STALE

The `race_condition` entry ends with an instruction from its own author:

> **When the door is fixed, RE-MEASURE THIS ENTRY — it is expected to become false.**

The door was fixed. Q-080 (`928319b`) landed a quarantine in `planner.fresh()` and at the executor
ingress. So the re-measurement is due, and this lane owes it.

MEASURED, probe `n5_remeasure.py`, driving the **shipped `planner.next_batch`** at HEAD, drained to
exhaustion, with the `recon["forms"]` / `urls` fixture the shipped code actually produced:

```
mode=full     total steps=106
    steps AT THE KILL url     : 0  []
    POSITIVE CONTROL, ordinary: 6  ['http_probe','http_probe','run_csrf','run_form_cmdi',
                                    'run_race','run_stored_xss']
mode=active   total steps=99
    steps AT THE KILL url     : 0  []
    POSITIVE CONTROL, ordinary: 3  ['http_probe','http_probe','run_csrf']
mode=passive  total steps=29
    steps AT THE KILL url     : 0  []

is_session_kill_url(ORDINARY) = False   <- the quarantine does NOT cover it; run_race DOES run there
is_session_kill_url(KILL)     = True

NEGATIVE CONTROL -- the same probe with the quarantine predicate stubbed to False:
  quarantine OFF  mode=full   steps at KILL url: 6 ['http_probe','http_probe','run_csrf',
                                                   'run_form_cmdi','run_race','run_stored_xss']
  quarantine OFF  mode=active steps at KILL url: 3 ['http_probe','http_probe','run_csrf']
  quarantine restored, mode=full steps at KILL url: 0
```

The negative control is the load-bearing row: **stubbing one predicate restores exactly the 6 and the
3 that Q-080's handoff recorded before its fix**, and restoring it returns them to 0. The zero is the
quarantine working, not the probe failing to look.

### 4a. What that does to the row's truth value

The row's entire measured ground was: *the shipped planner emits `run_race` against a
session-destroying action carrying the mission session, and it dies.* At HEAD the planner emits **no
step at all** against such an action, in any mode. The only surface `run_race` still reaches is the
ordinary form — where `effects4.md` measured **0 of 4 engines killing anything** with the body the
planner actually builds (`"&".join(f"{f}=1" for f in fields)`, which the app rejects 403), and a kill
only when handed a body the planner never constructs.

So at HEAD there is **no measured, planner-reachable input by which `run_race` invalidates
`authenticated`.** The row is not thereby proven false — `run_race` racing an arbitrary
session-affecting action still could, and the entry's own reasoning that an over-approximated
`invalidates` costs only COMPLETENESS (never soundness) still stands. What is now **false is the
comment**, which presents a measured basis that no longer exists.

### 4b. Keep or delete — and why keep, narrowly

Deleting returns `conflicts()` to 0 and the model to the empty state Q-074 exists to escape, at the
cost of the one number section 3 shows the row is worth. Keeping it costs nothing a planner would
ever act on, because no planner reads it. **Kept**, with the comment corrected to state the
over-approximation as an over-approximation rather than as a live measurement, and with the
Q-080 outcome recorded so the next lane does not re-derive it. That is a documentation fix in a file
I own, and it is section 6's change.

---

## 5. WHY THE `csrf` ROW IS NOT CREATED

My brief says "fix the `run_csrf` key either way." Having measured section 4, creating it is the
wrong move and the reasoning is worth stating so the absence is a decision, not an oversight.

Q-080 measured `run_csrf` as one of **six** engines that ended the mission session — through the
`recon["forms"]` and `state["urls"]` doors, both now closed. A `csrf -> invalidates: ["authenticated"]`
row would therefore be a row whose *only* evidence is a behaviour that **the shipped tree no longer
exhibits**, keyed to a technique whose primary engine does not have the defect, in a vocabulary that
cannot name the real cause (the door). It would be the fifth transcription of one door defect into a
table nothing reads.

My brief is explicit that this is the wrong trade: *"Do not populate more rows to make the table look
fuller. Twelve rows nothing reads is not better than six."* The same argument applies with more force
to a row whose fact has expired. **The key is not wrong; the entry does not exist and should not be
created.**

---
