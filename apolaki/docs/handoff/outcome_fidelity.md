# I-2b OUTCOME FIDELITY — the guard, the denominator, and the three defects it found

**Lane:** outcome-fidelity (Builder). **Owns:** `agent/tests/test_outcome_fidelity.py` (new),
this file. **Baseline:** `0f2d54c` — 3445 passed / 11 skipped / 12 xfailed / 0 failed.
**Guard commit:** `aa01373`.

---

## 1. Why I-2 could not see Q-089

Q-089 (`7b82202`): `db.add_finding` has three outcomes — INSERT, reroute-to-leads (TRUTH #7),
off-scope refusal (SCOPE #8) — reported through one `str`. Only the refusal was distinguishable
(falsy). A reroute returns the **lead's** id, truthy exactly like a store, so
`sum(1 for f in findings if db.add_finding(...))` reported `stored_findings=1` against **0 rows**.

I-2 measured **0 unowned paths and was correct**. I-2 counts EDGES (producer → persistence owner);
this path has exactly one owner. The defect lives on the **return edge**, which an ownership census
does not traverse.

    I-2a  ownership          every finding-producing path reaches exactly ONE persistence owner   HOLDS
    I-2b  outcome fidelity   for every owner with MORE THAN ONE OUTCOME, every caller reporting a
                             COUNT or a STATUS must distinguish them                             BUILT (aa01373)

**An invariant that counts structure cannot see a defect that lives in a value.**

---

## 2. How the owners are DERIVED (not listed)

A hand-written owner list is the declaration-vs-fact defect this codebase has hit twelve times, so
`_multi_outcome_owners` measures instead:

1. **Effects.** Per function: direct writes (`_exec`/`execute`/`executemany`/`executescript` whose
   SQL literal starts `INSERT|UPDATE|DELETE|REPLACE` → `sql:<table>`;
   `write_text`/`write_bytes`/`writelines`/`json.dump` → `file`), unioned to a **fixpoint** over the
   production call graph. Call resolution is by AST and handles `import x`, `import x as y`,
   `from x import f`, `from x import f as g`, and a bare name bound to a def in the same module —
   because a `mod.attr(` text scan produced a confidently wrong ZERO in this repo twice this week.
2. **Outcomes.** Each `return` is labelled with the destinations **definitely** written before it on
   its own path. Deliberately conservative: an `if` without an `else` adds nothing to the
   fall-through, a loop body may not execute, a `try` body may raise partway. Over-conservatism can
   only MERGE outcomes (missing an owner), never invent one — the denominator is a **floor**.
3. **Ambiguity.** An owner is *truthiness-ambiguous* when two returns with **different** outcomes are
   both non-statically-falsy: the caller's cheapest test cannot separate "written" from "not
   written". That is Q-089's property stated generally.

### The denominator, measured 2026-08-21 on this tree

| measurement | value |
|---|---|
| production modules | **178** |
| production functions (module- + class-level defs) | **2469** |
| transitive writer functions | **88** |
| **multi-outcome owners** | **14** |
| of those, truthiness-**ambiguous** | **11** |
| violating call sites | **8** |

**`db.add_finding` is NOT the only one.** That was the question the ticket asked; the answer is no,
and the second one carries a live defect.

| owner | outcomes | ambiguous |
|---|---|---|
| `db:add_finding` | `<none>` / `sql:findings` / `sql:missions` | yes (the Q-089 anchor) |
| `db:update_finding` | `<none>` / `sql:findings` / `sql:findings+sql:missions` | **yes — Q-090** |
| `db:add_lead` | `<none>` / `sql:missions` | yes |
| `main:_run_source_review` | `sql:logs` / `sql:logs+sql:missions` | yes |
| `main:capture_finding_poc` | `<none>` / `sql:findings+sql:missions` | yes |
| `main:confirm_lead` | `sql:missions` / `sql:findings+sql:missions` | yes |
| `main:intel_review`, `intel_bulk_review`, `intel_extract_capec`, `intel_extract_prose`, `intel_feeds_refresh` | `<none>` / `file` | yes (5) |
| `asset_graph:AssetGraph.save`, `attack_chain:record`, `bench_contract:main` | `<none>` / `file` | **no** — the no-write return is a statically falsy constant |

The last row is the classifier discriminating; `test_the_multi_outcome_owner_denominator_is_derived_and_non_vacuous`
asserts `len(ambiguous) < len(owners)` so a classifier that flagged everything cannot go unnoticed.

---

## 3. Q-090 — what the guard found. **Three defects, all reproduced through the real endpoints.**

The second multi-outcome owner is `db.update_finding` (`agent/db.py:311`), which has Q-089's defect
one function over:

```python
if verdict == "reject":
    return False                      # off-scope refusal   — indistinguishable from "no such finding"
if verdict == "lead":
    ...
    delete_finding(mid, fid)          # THE ROW LEAVES THE FINDINGS TABLE
    add_lead(mid, finding)
    return True                       # REROUTE             — indistinguishable from a real UPDATE
cur = _exec("UPDATE findings SET data=? WHERE mission_id=? AND id=?", ...)
return bool(getattr(cur, "rowcount", 0))
```

### Q-090-A — `POST /leads/{sid}/{lid}/confirm` destroys an off-scope lead and reports promotion

`main.py:3926` `fid = db.add_finding(session_id, finding)`, then the lead is removed from
`ctx["leads"]` and the response says `promoted: True`. On a SCOPE (#8) refusal `fid` is `""` and
nothing was written — **so the lead is deleted and no finding exists.**

Measured (`agent/tests/test_outcome_fidelity.py::test_q090a_...`, and directly):

```
leads before: 1   findings before: 0
HTTP 200 {"ok": true, "promoted": true, "provenance": "operator-released",
          "machine_proof": true, "proof_gap": [], "finding_id": "", ...}
leads after: 0 []            findings after: 0
```

**Total data loss on the operator-attestation path, reported as success.** Highest severity of the
three: `confirm_lead` is the surface an operator uses to take responsibility for a finding.

### Q-090-B — `PUT /findings/{sid}/{fid}` answers 404 for a refusal

`main.py:3789` `if not db.update_finding(...): raise HTTPException(404, "finding not found in this
mission")`. `False` means **either** "no such finding" **or** "the write was refused as off-scope",
and the second is reported as the first.

```
row present in the table: 1
PUT /findings/q090b/f1  ->  HTTP 404 {"detail": "finding not found in this mission"}
analyst_notes after: None      (the row is still there, unedited)
```

Reached whenever the mission scope narrows after a finding was stored (retest, operator correction,
archive replay). The operator is told their finding does not exist.

### Q-090-C — `POST /findings/{sid}/{fid}/poc` attaches nothing and answers `ok`

`main.py:3825` calls `db.update_finding(session_id, fid, merged)` as a **bare statement** — the
return is thrown away — and `main.py:3826` answers a constant. Same shape as Q-089's `/restore`,
which answered `{"imported": true}` for a partial restore.

```
POST /findings/q090c/f1/poc  ->  HTTP 200 {"ok": true, "bytes": 4, "attached_to": "f1"}
poc_screenshot actually stored: False
```

### Q-090-D — `agent.py:BBHAgent._triage` writes back blind

`agent.py:4234` `db.update_finding(self.mission_id, f["id"], f)` per finding, return discarded. A
refusal or reroute removes the row mid-report with no signal; the loop continues and the report is
generated from a set that no longer matches the table. Lower severity (nothing is reported to an
operator) but the same blind write. **Not reproduced end-to-end** — recorded as MEASURED-STATIC.

---

## 4. THE PATCHES (out of lease — `main.py` / `agent.py` belong to the Codex lane)

`db.update_finding` returns `bool`, and 4 of its 5 production call sites read it as one. The
Q-089-shaped fix is the **return type**, not the counters: a `bool` subclass carrying `.verdict`,
exactly as `db.FindingWriteId` is a `str` subclass. Two options; **B is recommended.**

### Option A — minimal, per-call-site, no `db.py` change (unblocks A/B/C today)

```python
# main.py: confirm_lead, replacing `fid = db.add_finding(session_id, finding)` at 3926
    write = db.add_finding(session_id, finding)
    if not write.stored:                         # REFUSED (#8) or REROUTED (#7) — no row exists
        return {"ok": True, "promoted": False, "provenance": "operator-attested",
                "machine_proof": True, "proof_gap": [], "lead_id": _lead_key(lead),
                "title": lead.get("title", ""),
                "note": ("The proof gate accepted this lead, but the write was %s, so it is NOT a "
                         "confirmed finding and the lead has been LEFT IN PLACE. %s"
                         % (write.verdict,
                            "Its target is outside this mission's scope — widen the scope or report "
                            "it under the engagement that covers it."
                            if write.verdict == db.REFUSED else
                            "The finding gate still reads it as lead-confidence."))}
    ctx["leads"] = [l for l in leads if _lead_key(l) != _lead_key(lead)]
    ...
```

The early return happens **before** `ctx["leads"]` is rewritten, so the lead survives. Note the
second bug this exposes: on the reroute path `add_lead` appends to a **freshly read** context while
line 3927 writes back the **stale** `ctx` captured at the top of the function — so even a reroute
loses the appended copy. Returning early avoids both.

```python
# main.py: update_finding endpoint, replacing lines 3789-3791
    outcome = db.update_finding_verdict(session_id, fid, merged)     # see Option B
    if outcome == "refused":
        raise HTTPException(409, "this finding's target is outside the mission scope, so the edit "
                                 "was refused. The finding is unchanged and still in the table. "
                                 "Widen the scope or move it to the engagement that covers it.")
    if outcome == "rerouted":
        return {"ok": True, "moved_to": "leads", "note":
                "The finding gate now reads this as lead-confidence, so the edit MOVED it out of the "
                "confirmed table and into the mission's leads list. It is no longer a finding."}
    if outcome != "updated":
        raise HTTPException(404, "finding not found in this mission")
    return {"ok": True}
```

```python
# main.py: capture_finding_poc, replacing line 3825
    outcome = db.update_finding_verdict(session_id, fid, merged)
    if outcome != "updated":
        return {"ok": False, "note": "screenshot captured but NOT attached: the write was %s"
                                     % outcome, "bytes": shot.get("bytes")}
    return {"ok": True, "bytes": shot.get("bytes"), "attached_to": fid}
```

```python
# agent.py: BBHAgent._triage, replacing line 4234
            if db.update_finding(self.mission_id, f["id"], f) is not True:
                yield {"type": "warn", "phase": "report", "finding_id": f.get("id"),
                       "note": "triage annotation was not persisted; the finding left the table"}
```

### Option B — the Q-089 fix shape, applied to `update_finding` (recommended)

Add to `agent/db.py` beside `FindingWriteId`:

```python
UPDATED = "updated"     #: the row was UPDATED in place
MOVED   = "moved"       #: TRUTH (#7) — the row LEFT the findings table and became a lead
REFUSED_UPDATE = "refused"   #: SCOPE (#8) — nothing was written; the row is unchanged
ABSENT  = "absent"      #: no row with this id in this mission

class FindingUpdateResult(int):
    """What `update_finding` DID. It IS an int (so `bool(...)` and `is True`-free callers are
    byte-identical for the 4 sites that read it as a bool) carrying `.verdict`.

    `int`, not `bool`: CPython forbids subclassing `bool`. `FindingUpdateResult(1) == True` and
    `if result:` behave exactly as before — which is the point, and also why the AMBIGUITY IS NOT
    FIXED BY THE TYPE ALONE. `.updated` is the question a caller must ask; I-2b's guard is what
    proves they ask it."""
    def __new__(cls, value: bool, verdict: str):
        self = super().__new__(cls, bool(value))
        self.verdict = verdict
        return self

    def __reduce__(self):                      # copy/deepcopy/pickle rebuild through BOTH arguments
        return (self.__class__, (bool(self), self.verdict))

    @property
    def updated(self) -> bool:
        """True only when the row was UPDATED IN PLACE and is still a confirmed finding."""
        return self.verdict == UPDATED
```

and change the four returns in `update_finding` (`db.py:330/335/338/340`) to
`FindingUpdateResult(False, REFUSED_UPDATE)`, `FindingUpdateResult(False, ABSENT)`,
`FindingUpdateResult(True, MOVED)`, `FindingUpdateResult(bool(getattr(cur, "rowcount", 0)), UPDATED)`.

**Do not skip the copy/pickle control.** Q-089's back-compat control found that a `str` subclass is
rebuilt through `cls.__new__(cls, value)` and raised `TypeError`; the full suite was green *with that
break in it*. `__reduce__` above is the same fix, and it needs the same assertion, not a reviewer.

**Callers to update after Option B** (the complete set — derived by AST, not by grep):
`main.py:update_finding` (3789), `main.py:capture_finding_poc` (3825), `agent.py:BBHAgent._triage`
(4234). `db.py:337` is inside `update_finding` itself.

### Retiring the guard entries — required, in the same commit

Each landed fix must **delete** its `_KNOWN_OPEN` entry in
`agent/tests/test_outcome_fidelity.py` **and** retire the matching `xfail(strict=True)`.
`test_no_pinned_violation_is_stale` fails on a stale entry and the strict xfail fails on an
unexpected pass, so both halves are enforced. That is how Q-089 retired its own strict xfail, in the
commit that fixed the defect rather than in a later tidy-up.

---

## 5. Controls — what was proved, and how

**Planted bypasses (mandatory).** Nine, over a synthetic nested package, exercising every binding
form the resolver claims to handle and every violation shape:
`if OWNER(...)` · `sum(1 for x in xs if _s.OWNER(...))` (import-as) · `bool(OWNER(...))` (from-import)
· one-hop through a local name (from-import-as) · `OWNER(...) and 2` · `len([... if OWNER(...)])` ·
`{'ok': True}` after a call · `{'stored': 1}` after a discarded call · a bare discarded call.

**Negative controls (a guard that flags everything is also vacuous).** Four, all silent:
an ordinary `x['id'] = OWNER(...)` id use; a caller that reads `.stored` and then reports any count
it likes (**the fix shape must be accepted, or the next lane weakens the guard instead of using it**);
a same-named function in a *different* module; a single-outcome writer that must NOT be classified
multi-outcome.

**Non-vacuity floors.** 178 modules · 2400 functions · 80 writers · 12 owners · 9 ambiguous ·
8 violations · all three violation shapes still detected · `db.add_finding` still derived (the
anchor) · `db.update_finding` still derived · `len(ambiguous) < len(owners)`.

**Runtime non-vacuity of the derivation's premise.** `test_the_three_verdicts_of_the_anchor_owner_still_differ_at_runtime`
drives all three verdicts through the real `db.add_finding` and asserts against the **table** and the
**leads list**, never the return value alone — the static claim "three outcomes" is only worth
guarding if the running function really produces three.

**Semantic mutants — five, each verified landed by grep before the run was believed.**

| # | mutation | verified | killed |
|---|---|---|---|
| M1 | `_boolean_context` always returns `""` | `grep MUTANT M1` | 8 — all six boolean-read plants, the shape check, the staleness ratchet |
| M2 | ambiguity classifier always `True` | `grep MUTANT M2` | 3 — the discrimination assertion + both ratchets |
| M3 | resolver ignores the alias table (a `mod.attr` text scan) | `grep MUTANT M3` | 2 — exactly the two `import x as y` plants |
| M4 | accessor exemption marks every scope distinguished | `grep MUTANT M4` | 4 — incl. `test_every_exemption_matches_exactly_one_measured_site` |
| M6 | **Q-089's exact shipped caller reintroduced into the real `main.py`** | `grep MUTANT M6` in `main.py` | the guard, naming `main.py:_run_source_review boolean-read <- db:add_finding`; also killed 4 Q-089 tests |

M6 is the decisive one: the ticket asked for a caller that reads a multi-outcome return in boolean
context to be reintroduced and the guard watched go red. It did, on production `main.py`, not on a
fixture.

**The ratchet fired on its author.** The first run went red naming `agent.py:BBHAgent._triage`
against my pinned `agent.py:Apolaki._triage` — both directions of the ratchet, on the first attempt,
before any mutant.

---

## 6. Known limits (stated so the next lane does not over-read the number)

- **The owner denominator is a floor.** The path walk is conservative, `_exec` calls with a
  non-literal SQL argument are not counted, and nested `def`s are not indexed as owners. 14 is a
  lower bound on multi-outcome owners; it is not a proof that there are exactly 14.
- **Five `intel_*` endpoints are classified ambiguous** (`{"error": ...}` vs `{"ok": ...}`, both
  truthy dicts). They have no Python callers, so they contribute no violations, but they do inflate
  the ambiguous count from a defect-severity point of view.
- **Q-090-D is MEASURED-STATIC, not reproduced end-to-end.** The other three are reproduced.
- **`main.py:engage` and `db.py:update_finding`** are pinned as `_DISTINGUISHED`, each with a named
  reason and each required to match exactly one measured site — a second read of the same shape in
  the same function is drift, not a free extension of the exemption.
- **Violation keys are `(module, function, kind, owner)` — never line numbers**, so an unrelated edit
  that shifts `main.py` cannot fail the ratchet for the wrong reason and get it weakened to make it
  stop.

---

## 7. Suggested queue entry (Coordinator owns `docs/QUEUE.md`; not edited by this lane)

> **Q-090 — `db.update_finding` reports a reroute and a refusal through the same bool, and three
> callers publish a STATUS from it.** Owner: Codex lane (`main.py`, `agent.py`). Found by I-2b
> (`aa01373`). A: `POST /leads/{sid}/{lid}/confirm` **deletes an off-scope lead** and answers
> `promoted: true` — data loss. B: `PUT /findings/{sid}/{fid}` answers 404 for a refusal while the
> row is in the table. C: `POST /findings/{sid}/{fid}/poc` answers `{"ok": true, "attached_to": …}`
> with nothing attached. D: `agent.py:BBHAgent._triage` writes back blind. All reproduced (A/B/C) as
> `xfail(strict=True)` in `agent/tests/test_outcome_fidelity.py`; patches in
> `docs/handoff/outcome_fidelity.md` §4. Each fix must delete its `_KNOWN_OPEN` entry and retire its
> xfail in the same commit.
