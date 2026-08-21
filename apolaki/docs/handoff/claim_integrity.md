# Claim-integrity lane — Q-089, Q-088

Builder lane, release-stabilization. Baseline `186f500`: 3417 passed / 11 skipped / 13 xfailed / 0 failed.
Every number below was measured in a throwaway container against the mounted `agent/` tree, never
against `apolaki-agent-1`.

---

## Q-089 — `db.add_finding` could not tell a store from a reroute

### The defect, restated after reading the code

Not a reporting bug and not a missing owner. `db.add_finding` is a genuine chokepoint with three
genuinely different outcomes, and it reported all three through one `str`:

| gate verdict | what happens | old return | distinguishable? |
|---|---|---|---|
| admit | `INSERT INTO findings` | finding id | — |
| lead (TRUTH #7) | appended to the mission's leads list, **no row** | **the lead's id — truthy** | **NO** |
| reject (SCOPE #8) | nothing written anywhere | `""` | yes (falsy) |

So `main.py:459`

```python
stored = sum(1 for finding in findings if db.add_finding(session_id, finding))
```

counted the reroute as a store. Reproduced exactly as the ticket measured it:

```
status=complete   stored_findings=1   rejected_findings=0
findings table:   0 rows      leads list: 1
```

The reroute is correct behaviour and is unchanged.

### The fix — the return type, not the counter

`db.add_finding` now returns `db.FindingWriteId`: a **`str` subclass** carrying `.verdict`
(`db.STORED` / `db.REROUTED` / `db.REFUSED`) and `.stored`.

Why a `str` subclass and not a tuple/dataclass/second function:

* **21 production call sites read the return as an id** (`f["id"] = db.add_finding(...)`,
  `json.dumps`, sqlite binding, dict keys). 15 of them are in `agent.py` and 1 in `tools.py` —
  files this lane may not edit. A wrapper object would have broken all of them, several silently.
* `tests/test_gate_write_paths.py` (not editable by this lane) pins two structural facts:
  `_sql_writers()` requires the `INSERT INTO findings` to live in a function named in
  `_ALLOWED_SQL_WRITERS`, and `assert "_gate(" in _body("add_finding")`. Moving the body into a new
  `add_finding_result()` fails **both**. The subclass keeps the write and the gate call exactly where
  the guards expect them.
* A wrapper that re-ran `_gate` to compute a verdict would create a **second** evaluation of the
  invariants — a new source of truth for the same question, which is the defect this ticket is about.

**Truthiness is deliberately unchanged.** `tests/test_findings_gate.py:62` asserts a rerouted lead id
is truthy, so making it falsy would be a silent behaviour change dressed as a bug fix. That the old
truthiness question is asked **nowhere in production** is proved as a repository-wide absence, not
assumed from the type change.

### Call sites changed (all in `main.py`, all in-lease)

| site | was | now |
|---|---|---|
| `_run_source_review:459` | `sum(... if db.add_finding(...))` | counts `w.stored`; error names the reroute |
| `cloud_posture_ingest:3452` | `db.add_finding(...); stored += 1` | counts `.stored`; adds `findings_rerouted_to_leads`, `findings_refused_off_scope` |
| `restore:4051` | `db.add_finding(new_id, f)`, return discarded | counts; returns `findings_in_backup` / `findings_restored` / rerouted / refused |

The last two were found by the AST census, not by the ticket. `cloud_posture_ingest` published
`findings_stored` as an operator-facing number while counting **calls**; `/restore` returned
`{"imported": true}` with no number at all, so a 40-finding backup could restore 12 and read as a
success.

### Call sites NOT changed, and why (this lane cannot edit those files)

* **`agent.py` (15 sites)** — `f["id"] = db.add_finding(...)` then `self.findings.append(f)` and
  `yield {"type": "finding", ...}` **unconditionally**. This is a *different* shape from Q-089 (it
  never reads the return as a boolean, so the new guard does not flag it) but the same class: a
  rerouted lead would be appended to `self.findings` and streamed to the UI as a finding. Latent
  today because every site is behind `self._is_confirmed(...)`, i.e. protected by a caller-side
  check rather than by the writer's answer. **Proposed patch:**
  `w = db.add_finding(self.mission_id, f)` / `f["id"] = w` / `if not w.stored: self.leads.append(f); continue`.
* **`tools.py:10650` (`store_finding`)** — **not latent.** The lines immediately above it demote an
  evidence-free access-control finding to `confidence="lead"`; `add_finding` then reroutes it; and the
  function returns `ToolResult("store_finding", ..., True, "Finding stored", [inp])` regardless. The
  model is told "Finding stored" for a finding that is in the leads list. **Proposed patch:**
  ```python
  write = db.add_finding(self.mission_id, dict(inp))
  inp["id"] = write
  note = "Finding stored" if write.stored else (
      "Recorded as an UNCONFIRMED LEAD (not a finding): %s" % write.verdict)
  ...
  return ToolResult("store_finding", inp.get("target", ""), True, note, [inp])
  ```
  This shape — *claims stored unconditionally* — is **not** caught by the new guard, which only proves
  the absence of the truthiness read. Worth its own ticket.

### Controls

| control | file | result |
|---|---|---|
| positive: three verdicts, each asserted against the **table and the leads list** | `test_finding_write_verdict.py` | pass |
| back-compat: the id is still json-serialisable, sqlite-bindable, hashable | same | pass |
| back-compat: `copy` / `deepcopy` / `pickle` keep the verdict | same | **found a real break I introduced** — see below |
| end-to-end defect, through the real `/engage` | same | `stored_findings == rows == 0`, 1 lead |
| **negative control**: two genuine stores still count as 2, `status=complete` | same | pass (passed before the fix too — by design) |
| **non-vacuity**: the analyzer ran and the reroute happened | same | asserted inside the e2e test |
| **bypass control**: AST census, repo-wide, of every `add_finding` call site | same | production boolean-context uses **1 → 0** |
| census non-vacuity (≥18 sites found; measured 21 — agent.py 15, main.py 5, tools.py 1) | same | pass |
| guard mutants: 5 planted truthiness reads, one per binding form | same | all 5 flagged |
| guard anti-vacuity: an ordinary id use is **not** flagged | same | pass |
| semantic mutant 1: `stored` → `verdict != REFUSED` in `db.py` | verified landed by grep | killed 4 tests |
| semantic mutant 2: `w.stored` → `bool(w)` in `main.py` | verified landed by grep | killed 3 tests |

The AST census resolves `import db`, `import db as X`, `from db import add_finding`, and
`from db import add_finding as af`, plus one hop through a local name (`fid = db.add_finding(...)`
… `if fid:`). A `db.add_finding(` text scan misses the last three; that is the failure the ticket
warned about.

### The break the back-compat claim did not cover

Writing "byte-identical for every caller" in a docstring is a declaration. Checking it is not, and
the check found a defect **in my own fix**:

```
copy.deepcopy({"id": db.add_finding(mid, f)})
TypeError: FindingWriteId.__new__() missing 1 required positional argument: 'verdict'
```

`copy`/`pickle` reconstruct a `str` subclass by calling `cls.__new__(cls, <the string>)` with one
argument. Fixed with `__reduce__` returning `(cls, (str(self), self.verdict))`; mutant-verified
(disabling `__reduce__` fails exactly the copy control and nothing else). **No production path
deepcopies a finding today**, so the full suite was green *with the break in it* — the whole reason
this needed an assertion rather than a reviewer. It is also the exact shape of the thing this ticket
is about: an interface change whose claim about itself was broader than what anyone had measured.

**Strict xfail retired** in the same commit that fixed it —
`test_stored_findings_must_never_count_a_finding_the_table_did_not_accept`. It XPASSed on the fix,
and the two semantic mutants make it fail again, so the retirement is a fixed defect and not a
drifted measurement.

### The I-2 question — should the measurement change shape?

**Yes, and specifically: I-2 is currently one measurement of a property that has two halves.**

I-2 asks *"does every finding-producing path reach exactly one persistence owner?"* and answers by
counting **edges**: producer → owner. It measured 0 unowned and it was **correct** — this path has an
owner, reaches it, and reaches only it. The defect is on the **return edge**, which an ownership
census does not traverse: the owner performed three different actions and described them with one
value, so the *producer's belief about what happened* diverged from what happened. Ownership was
sound; the boundary was lossy.

An ownership census cannot be patched into catching this, because "how many owners" and "what did the
owner say" are different questions. The measurement should become two:

* **I-2a (ownership, unchanged)** — every finding-producing path reaches exactly one persistence
  owner. Counts edges. Already 0.
* **I-2b (outcome fidelity, new)** — *for every persistence owner with more than one outcome, every
  caller that reports a COUNT or a STATUS distinguishes those outcomes.* Measured on the return, not
  the call: enumerate the owner's distinct outcomes (here: 3), then enumerate its call sites and
  classify each as (i) uses the value as an opaque id, (ii) reads the outcome, or (iii) **asserts an
  outcome it did not read** — a boolean test, a `+= 1`, or a fixed success string. Class (iii) is the
  violation.

Run against `add_finding` today, I-2b returns: `main.py` 3 violations (all fixed here),
`tools.py:10650` 1 violation (fixed shape proposed above, out of lease), `agent.py` 15 sites in a
weaker variant of (iii) — they act on the finding unconditionally rather than claiming a count.
`test_finding_write_verdict.py` implements the *boolean-test* half of I-2b as an executable guard;
the `+= 1` and *fixed success string* halves are still measured by hand and are the natural next
guard.

The generalisable rule: **an invariant that counts structure will not see a defect that lives in a
value.** Wherever a chokepoint can do more than one thing, the vocabulary for what it did belongs in
its return type — otherwise every caller re-derives it, and they will not all derive the same thing.

---

## Q-088 — `validated_on` is a capability claim with no vocabulary

### NOT STARTED IN PRODUCTION. Blocked by the file lease, on a measured, single-line blocker.

**The ticket's premise is stale in two places, and one of them changes the plan.** Measured
2026-08-20 against the live tree, before any edit:

| ticket says | measured |
|---|---|
| "`all_labs()` derives the set FROM the claims, so a claim validates itself" | **already fixed.** `techniques.known_labs()` = `_registry_labs()` ∪ `_liveness_vouched_labs()`; `all_labs()` filters through it; `is_generalized` counts only resolvable labs; `validation_record()` reports `unresolved` separately. |
| "4 ids name a target the agent cannot resolve" | **2**, not 4. `domsource` and `openfmb` are now legitimised by the liveness ledger. `natas` and `sessionlife` remain. |
| "`main.py:/packs:2129` still runs the old rule" | **already fixed.** `/packs` calls `T.is_proven(t)`; the passing `test_packs_and_techniques_now_report_the_SAME_proven_number` is that fix's guard. |
| "`technique_model.from_registry:256`" | **true.** `"status": "proven" if validated else "catalogued"`, and `evidence` is built from raw `validated_on`. |
| "`technique_planner.registry_seed:172`" | **true.** `"status": "proven" if vo else "catalogued"`. |

So the chokepoint is built; **two** call sites remain, not four, and the whole ticket is one small patch.

### The patch, applied and MEASURED in an isolated copy (not committed)

```python
# technique_model.from_registry
import techniques as _TQ
validated = _TQ.validation_record(rec)["labs"]     # resolvable labs only -> fabricated ids yield no evidence
...
"status": _TQ.technique_status(rec),               # the shared predicate

# technique_model module level -- the canonical model must be able to SAY the two words the shared
# predicate produces, or the adapter has to invent a translation and we are back to two vocabularies
STATUSES = ("unverified", "solver_only", "proven", ...)
_STATUS_BASE = {"proven": 55, "unverified": 22, "solver_only": 15, ...}

# technique_planner.registry_seed
"status": T.technique_status(r),                   # confidence scoring UNCHANGED -- it is a function of
                                                   # lab COUNT, pinned by a passing test, and correct
```

Result on the five markers in `tests/test_validated_on.py`:

| marker | with the patch |
|---|---|
| `test_a_fabricated_validated_on_is_rejected_by_the_canonical_model` | **XPASS** — status `unverified`, tier `low`, `evidence == []` |
| `test_one_rule_for_proven_across_every_module` | **XPASS** — 64 disagreements → 0 |
| `test_every_validated_on_lab_id_names_a_target_the_agent_can_resolve` | still red (data, see below) |
| `test_packs_and_techniques_report_the_same_proven_number` | still red, **and it can never pass** (see below) |
| `test_every_validated_on_claim_is_backed_by_a_recorded_artifact` | still red (data, see below) |

### THE BLOCKER — one assertion, in a file this lane may not write

```
FAILED tests/test_technique_pipeline.py::test_from_registry_projects_canonical_shape
/app/tests/test_technique_pipeline.py:17: AssertionError: assert ('unverified' == 'proven')
```

`test_technique_pipeline.py:17` and `:20` assert `status == "proven"` and `tier == "high"` for a
synthetic record carrying `validated_on=["juiceshop","dvwa"]` and the id `sqli_auth_bypass` — which
no liveness run has confirmed. **The old rule is not only in two production call sites; it is pinned
as an assertion in a passing test.** Any commit that adopts the shared predicate must update those
two lines in the same commit, and `tests/test_technique_pipeline.py` is outside this lane's lease.
Nothing was applied to the live tree, because a half-applied propagation leaves the suite red on a
file this lane cannot repair. **This is the whole remaining cost of Q-088: two production lines, one
STATUSES/`_STATUS_BASE` addition, and two lines in `test_technique_pipeline.py`.**

`test_technique_planner.py:81` (`assert all(t["status"] == "proven" for t in lab)`) looked like a
second blocker and is **not** — measured: the precondition-gated seed contains no lab-declaring
technique, so the assertion is vacuous today. It will block the day that changes; the honest fix is
to assert against `T.technique_status` there too.

### The three markers the patch does NOT close, and what each really needs

1. **`test_every_validated_on_lab_id_names_a_target_the_agent_can_resolve`** — a DATA problem, not a
   vocabulary one. Two ids remain: `sessionlife` (`session_lifecycle`, techniques.py:144) and `natas`
   (techniques.py:417). Note that **both name things the agent really has** — `natas` has
   `natas_ladder.py`, `POST /benchmark/natas` with a fixed host family, and
   `data/natas_credentials.json`; `sessionlife` is cited by `engine_descriptor.py:226,267` as a
   shipped lab and exists as an untracked `labs/sessionlife/` directory. They are absent from the
   three registries `_registry_labs()` reads, so the claims are correctly *rejected* today by every
   derived judgement. **Do not delete the claims to make the test green.** Either register the two
   targets (the honest fix — the artifacts exist), or add the runner registries as a fourth
   independent vocabulary source. The test's own `_known_lab_ids()` deliberately reads registries
   only and must NOT be re-pointed at `known_labs()`: that would make the guard assert the
   production rule it exists to check.

2. **`test_packs_and_techniques_report_the_same_proven_number`** — **retire this marker as
   MISWRITTEN, not as fixed.** The defect it names is fixed (`/packs` calls `T.is_proven`), but the
   test does not call `/packs`; it re-implements the OLD rule inline
   (`sum(1 for t in ts if t.get("validated_on"))` = 48) and asserts it equals the view (16). That
   assertion cannot XPASS while any claimed technique lacks a liveness artifact, no matter what
   production does — it is a test of the registry data wearing a ticket about two call sites. The
   file's own passing `test_packs_and_techniques_now_report_the_SAME_proven_number` is the correct
   guard and already covers it. **A strict xfail that cannot XPASS is worse than no marker: it makes
   a fixed defect look open forever, and it will be "closed" one day by someone deleting claims.**

3. **`test_every_validated_on_claim_is_backed_by_a_recorded_artifact`** (34 of 48) — needs recorded
   artifacts, i.e. replay tests or liveness confirmations for ~30 techniques. It cannot be closed by
   any call-site change. It also cannot be closed by deleting the unbacked claims: the passing
   `test_technique_status_is_the_fixed_rule_and_still_holds` asserts `claimed > proven` precisely so
   that "collapsing the gap" is not available as a fix. This is a body of work, not a line.

**Therefore the ticket's "the four markers XPASS together and retire together" does not hold, and
that is a finding, not a shortfall.** Two markers retire on the two-line patch; one is a data
registration; one is miswritten and should be retired as such; one is ~30 techniques' worth of
evidence. Filing them as one ticket was right — they share a chokepoint — but they do not share a
closing condition.
