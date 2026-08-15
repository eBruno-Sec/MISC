# Gate lane — Q-013 (write-path bypass) and Q-014 (operator confirmation)

Owner: gate lane. Files owned: `agent/main.py`, `agent/db.py`, `agent/tests/test_gate_write_paths.py`,
`agent/tests/test_operator_attestation.py`, this file.
Off-limits and NOT touched: `agent/proof_schema.py`, `agent/report.py`, `agent/agent.py`,
`agent/planner.py`, `agent/technique_planner.py`, `scripts/whole_product_*.py`, everything else
listed in the lane brief.

Both tickets are one defect with two signs: a finding reaches a client without the proof the gate is
supposed to require. Q-013 lets an unproven finding IN without a human. Q-014 throws a human's
decision AWAY. The brief's suspicion is worth recording: `PUT /findings` is a plausible workaround for
Q-014 having made the legitimate path unusable, and the two must be fixed together or the pressure to
route around the gate stays.

---

## THE THREE INVARIANTS — established from the code, not from the ticket text

Source: `agent/findings_gate.py` module docstring + `db.add_finding`. They are numbered by the review
that introduced them (#6/#7/#8) and each guarantees something a downstream surface depends on.

| # | name | helper | what it guarantees |
|---|------|--------|--------------------|
| **SCHEMA #6** | canonical shape | `findings_gate.normalize` | `reproduction_steps` is **always a list**. SARIF export, the report renderer and the retest planner all index it as a list; a producer that emitted `"1) do a 2) do b"` broke all three. Also fills `severity`/`confidence` defaults and coerces `tags` to a list. Total function — it never rejects. |
| **SCOPE #8** | authorization | `findings_gate.off_scope` | A finding whose target host is **provably outside** the mission scope is never persisted, uniformly, from any producer. Deliberately **fail-open**: no scope configured, no target, no parseable host, or a non-`http(s)` target (cloud-posture label, `host:port`) all ADMIT — we block only what we can prove. |
| **TRUTH #7** | proof provenance | `findings_gate.is_lead` | A lead-confidence item can never sit in the confirmed-findings table. It is routed to the mission's leads list instead. A blank/absent `confidence` counts as confirmed (historical default), so only an explicit lead-like word reroutes. |

They are separate axes: SCHEMA always applies and cannot fail; SCOPE is a refusal; TRUTH is a
re-route. A write path that treats them as one boolean gets one of them wrong.

## Q-013 — REPRODUCED (measured, pre-fix)

`db.update_finding` was a raw `UPDATE findings SET data=?`. It reached the same table `add_finding`
guards, so **two API calls bypassed all three invariants**: `POST /findings/{sid}` a clean finding,
then `PUT /findings/{sid}/{fid}` with the violation. Measured on the pre-fix tree:

```
SCHEMA  update_finding rc=True  reproduction_steps='1) do a 2) do b'  type=str        BYPASS
SCOPE   update_finding rc=True  target='http://evil.example.com/p'    off_scope=True  BYPASS
TRUTH   update_finding rc=True  confidence='lead'  in confirmed table=True            BYPASS
```

Two other callers reach the same function and are legitimate: `main.capture_finding_poc` (merges a
screenshot) and `agent.py:_triage` (annotates CWE/OWASP). Both keep working — verified by a test.

### Decision: the endpoint stays; the DB layer enforces

`PUT /findings` should exist — the two legitimate callers above need it, and an operator editing a
finding's title or notes is a real workflow. What should not exist is a **second way into the table**.
The fix goes in `db.update_finding`, not in the route handler, because:

* the chokepoint is already at the DB layer (`add_finding`); putting a second copy in the route means
  the next writer (a batch import, a merge tool) inherits the bypass again;
* it fixes `agent.py:_triage` at the same time without touching a file this lane does not own.

One evaluator, `db._gate(mid, finding) -> ("admit"|"reject"|"lead", finding)`, is shared by both
writers. Callers choose the update-shaped consequence, they do **not** choose whether the invariants
are evaluated:

* **reject** (off-scope): the write does not happen; the stored row keeps its old target; returns
  `False`. Moving a finding out of scope is not an edit — it is a new finding at a target we are not
  authorized to report.
* **lead**: the row **leaves** the confirmed table and is appended to the leads list. Rewriting in
  place would leave a lead sitting in the confirmed table, which is the exact masquerade #7 forbids.
  Tenant isolation still holds on this branch: a foreign `fid` returns `False` and creates no lead.
* **admit**: normal `UPDATE` of the normalized finding.

### Controls (absence-of-bypass, `agent/tests/test_gate_write_paths.py`)

* `test_no_ungated_sql_writer_reaches_the_findings_table` — AST-walks every module in the package for
  a SQL statement that writes the `findings` table and asserts the set of enclosing functions equals
  the four known chokepoints. A fifth writer fails this **whether or not it calls the gate**.
* `test_every_finding_write_route_is_gated` — **discovers** the HTTP write routes from `app.routes`
  (not a hardcoded list), pins the discovered set, then drives each one with each of the three
  violating payloads and asserts a storage-level predicate `gate_violations(mid) == []`. Path-agnostic:
  a new ungated `PATCH /findings/...` fails it.
* the gate-consultation assertion checks that `_gate` names all three invariants and that both writers
  call `_gate` — deliberately NOT "update_finding mentions off_scope", which would be a guard on a
  declaration (a comment would satisfy it). The behavioural tests are what prove the evaluator is obeyed.

Fail-before-fix: all five failed on the pre-fix tree on **semantic** assertions (wrong stored value,
violating row present, unexpected writer), not on `ImportError`/`AttributeError` — every symbol they
use already existed. `test_update_finding_keeps_tenant_isolation_and_legitimate_merges` passed before
and after, by design: it is the "existing callers keep working" control.

STATUS: **DONE**, committed `3addb1c`. But see the next section — it was necessary and **not
sufficient**, and the second pass is what actually answers "should this endpoint exist in its present
form".

## Q-013 second pass — the three invariants do not cover `evidence`

Asked again after Q-014 landed: with the storage gate closed, does `PUT /findings` still have a
justification? Measured, on the post-`3addb1c` tree:

```
POST a weak access-control finding -> gated confidence: lead   is_confirmed: False
PUT it back with fabricated prose ("...owner record... anon -> 403 denied...", + impact)
PUT status -> 200
                                   -> gated confidence: confirmed  is_confirmed: True
```

Nothing in that PUT violates SCHEMA, SCOPE or TRUTH: `reproduction_steps` is a list, the target is in
scope, `confidence` is `"confirmed"`. The three invariants are about a finding's **confidence, scope
and shape**; none of them looks at `evidence`, which is the field `validate_confirmed` actually judges.
So an HTTP body could still author the proof and flip a gate-demoted row to confirmed with no engine
having issued a single request.

That is the same laundering Q-014 rejected on the leads path, still open on the findings path — which
makes the two tickets one defect in a stronger sense than the brief claimed.

**And a PUT-only fix is not a fix.** The UI's "Add a manual finding" form posts
`confidence:"confirmed", confirmed:true` with operator-typed evidence, so `DELETE` + `POST`
reproduces the bypass exactly. Any control written only against PUT would have passed.

### Decision: the endpoint stays, but not in its present form

The rule is stated once and applies to every route: **an HTTP write route may not mint an oracle
`confirmed`.** `confirmed` names *who observed* the proof, not which words appear in a string.

* **`PUT /findings/{sid}/{fid}` becomes annotation-only.** A whitelist — `_EDITABLE_FINDING_KEYS` —
  is merged over the stored row; a body that tries to change anything else is refused 400, naming the
  fields and pointing at the attestation path. A **whitelist, not a blacklist**, deliberately: a
  blacklist means every field `proof_schema` learns to read next is silently editable, which is
  precisely how this hole survived the first pass. Only an *actual change* is refused, so the ordinary
  read-modify-write round trip (resending proof fields unchanged) still works.
* **`POST /findings/{sid}` records an operator-authored ATTESTATION.** Every field is typed by a
  human, so no oracle observed anything; it requires `operator` + `rationale`, stamps
  `operator_attestation`, and `confidence` is set by the endpoint, never read from the body. It lands
  as an attested lead.

Deleting the routes was considered and rejected: `PUT` has a real annotation use, deleting a public
endpoint breaks unknown external clients, and a 400 that explains itself teaches the right model where
a 404 teaches nothing.

### The control (`test_no_http_write_route_can_mint_an_oracle_confirmation`)

Starting from a mission with **no engine findings**, drive **every discovered** `/findings` write route
with a fully-fabricated proof payload and assert zero rows come back confirmed from
`get_findings_gated` — then repeat via `DELETE` + `POST`. It asserts the outcome for every route at
once rather than any field-level rule, because each field-level rule is individually defeatable.
A drift guard (`test_editable_key_whitelist_contains_nothing_the_proof_gate_reads`) derives the
proof-read key set from `proof_schema` rather than retyping it, so a new proof field is covered the day
it is added.

### A gap this found in my own controls

Mutants **M9** (remove the PUT refusal) and **M10** (remove the whitelist merge) both **SURVIVED** the
outcome-level control. The two mechanisms are redundant — with either one alone the fabricated payload
still fails to mint — so the control cannot tell them apart, and a single-mechanism regression would
have gone unnoticed. Fixed by adding
`test_put_refuses_a_proof_bearing_edit_with_a_reason_and_still_allows_annotation`, which asserts each
half separately (visible refusal naming the field and changing nothing; annotation edit still lands).
M9 and M10 are now killed, and **M13** — both mechanisms removed at once, i.e. the literal pre-fix
pass-through — is killed by the outcome control, which is the case that control exists for.

Second-pass mutants: M9, M10, M11 (POST takes `confidence` from the body), M12 (`evidence` added back
to the whitelist), M13 — **all KILLED**.

---

## Q-014 — REPRODUCED (measured, pre-fix)

Two independent failures, both in `main.py`.

**(a) A gate-routed lead cannot be addressed at all.** `db.add_lead` stamps `lead["id"]`.
`confirm_lead`/`dismiss_lead` look leads up by `l.get("_lid")`, and `_record_execution` is the only
thing that writes `_lid`. So every lead produced by the TRUTH invariant (#7) — i.e. every lead the
gate itself created — is invisible to the confirm endpoint:

```
gate-routed lead keys: ['confidence','family','id','reproduction_steps','severity','target','title']
has _lid? False   has id? True
confirm_lead lookup (l.get('_lid') == lid) -> None        # 404 for every gate-routed lead
```

The UI agrees: `ui/index.html` renders the confirm/dismiss buttons only `if(l._lid)`, so those leads
appear with **no buttons at all**. The operator is not told; the affordance simply is not there.

**(b) The operator's confirmation is silently re-demoted.** `confirm_lead` builds
`confidence: "confirmed"` and stores it. Every presentation surface reads through
`db.get_findings_gated` -> `proof_schema.demote_unproven`, which re-applies `validate_confirmed` and
writes `confidence: "lead"` back. Measured:

```
raw confidence   : confirmed
gated confidence : lead   proof_gap: ['impact','evidence_signal:owner','evidence_signal:denied']
is_confirmed after round trip: False
```

The endpoint returns `{"ok": true, ...}`. The operator sees success and the report shows a lead.

**(c) Found while reproducing (b), same defect family:** `main._record_execution` runs at mission end
and does `ctx["leads"] = leads[:80]` built only from `agent.leads` — it **clobbers** the leads
`db.add_lead` wrote during the run. So gate-routed leads do not merely lack a button, they are gone
by report time.

STATUS: **DONE** (both halves; see the commit table).

### What was built

`agent/db.py`
* `add_lead` stamps the id under **both** `id` and `_lid` — the same value, so nothing that reads
  either spelling changes.

`agent/main.py`
* `_lead_key` / `_find_lead` resolve a lead by `_lid` **or** `id`, used by confirm and dismiss. Leads
  persisted by the old code (id only) stay addressable after an upgrade.
* `_record_execution` **merges** instead of rebuilding: context leads first (so a persisted lead keeps
  its id and any attestation already on it), agent-side candidates appended, deduped as before. It also
  carries `impact` through the projection — the projection used to drop it, and `impact` is part of the
  proof contract `validate_confirmed` reads, so a lead could never be released even when its own engine
  evidence was complete.
* `LeadConfirmRequest` — `operator`, `rationale` (both required), `notes`, `exchange_ids`. Note what is
  **not** on it: a `confidence` field. An operator cannot set `confidence` from the request body, which
  is what makes a gate-demoted lead un-re-confirmable by writing it back.
* `confirm_lead` returns one of three visible outcomes: **400** (no attester / no grounds / a cited
  exchange this mission never recorded — nothing written), **200 promoted=True
  provenance="operator-released"**, **200 promoted=False provenance="operator-attested"** carrying
  `proof_gap`. The old response key `promoted` changed from the lead's title (a string) to a bool; the
  only reader in the tree was `ui/index.html`, which discarded the whole response.

`ui/index.html` (not owned by another lane; kept minimal, recorded here because it is outside the file
list in the brief)
* `confirmLead` now collects operator + rationale, and **shows** the server's verdict. It previously
  sent an empty POST and threw the response away inside `catch(e){}` — so a refusal or a re-demotion
  was invisible in exactly the place the operator was looking.
* lead cards address a lead by `_lid || id` (they rendered **no buttons at all** for gate-routed
  leads), and render an attestation as its own block with the machine-proof gap.

### Controls (`agent/tests/test_operator_attestation.py`, 9 tests)

| test | what it pins |
|------|--------------|
| `..._gate_routed_lead_is_addressable_by_the_confirm_endpoint` | no 404, and `_lid` present so the UI renders the buttons |
| `test_dismiss_also_resolves_a_gate_routed_lead` | the same resolver on the dismiss path |
| `..._teardown_does_not_clobber_gate_routed_leads` | both lead sources survive `_record_execution` |
| `..._refused_without_an_attester_or_grounds` | 400, reason in the body, **nothing written** |
| `..._survives_the_round_trip` | who / why / when / verdict durable and re-readable |
| `..._prose_cannot_manufacture_machine_proof` | **the discriminator** — see below |
| `..._own_engine_evidence_proves_it_is_released_to_confirmed` | the gate is satisfiable, and the result survives `get_findings_gated` |
| `..._citing_an_unrecorded_exchange_is_refused` | a citation must point at traffic Apolaki recorded |
| `..._gate_demoted_lead_cannot_be_reconfirmed_by_writing_it_back` | Q-013 + Q-014 together: neither PUT nor assertion re-confirms it |

Fail-before-fix: all 9 failed pre-fix. Honestly: **four** failed on the defect itself (`404 lead not
found`, the teardown assertion, `200 {"ok":true}` where a 400 was required), and **five** failed on a
`KeyError` for a response/lead field that did not exist yet — which proves those tests are NEW, not
that their assertions discriminate. Every one of those five is backed by a semantic mutant below.

### Mutation check — 8 mutants, all KILLED

| mutant | killed by |
|--------|-----------|
| M1 `off_scope` verdict never rejects | scope test + route control |
| M2 the demoted row is left in the confirmed table | truth test + route control |
| M3 `normalize` skipped on the update path | schema test + route control |
| M4 **operator prose spliced into the oracle's `evidence`/`impact`** | prose test |
| M5 the attester requirement removed | refusal test |
| M6 `machine_proof` asserted (`True, []`) instead of evaluated | prose test + demoted-lead test |
| M7 `add_lead` stops stamping `_lid` | addressable test |
| M8 `_record_execution` reverts to the clobber | teardown test |

**M4 SURVIVED the first time, and that was a real defect in my test.** The lead it used carried no
`impact`, so the missing-impact gap alone blocked promotion — the test asserted the right outcome
without discriminating the cause, and would have passed while operator prose was being laundered into
the oracle's evidence field. The lead now carries a legitimate engine-supplied `impact`, so the only
remaining gap is the evidence signal groups, and the test additionally asserts
`proof_gap == ["evidence_signal:owner", "evidence_signal:denied"]` — if that list is ever anything
else, the test stops discriminating and says so. Under the re-run mutant the gap became `[]` (i.e. the
laundered prose fully satisfied the oracle) and the test failed. This is the same shape as the
"guards that check declarations" failure already logged against this project, found in my own control.

Two mutants (M2, M4) initially reported SURVIVED because their multi-line anchors never matched — the
files are CRLF. An unapplied patch is not a surviving mutant; both were re-run with single-line
anchors and an applied-diff check printed before the run.

---

## THE DESIGN QUESTION — what should it take for an operator to confirm a lead?

### Decision

**Operator confirmation is an ATTESTATION: a distinct provenance on its own axis, carrying who, when
and why. It is never a value of `confidence`, and it never promotes a finding to `confirmed`.**
`confidence` remains the **oracle's** verdict alone.

### Why, and why not the alternatives

**Rejected — launder it into `confirmed` (exempt operator rows from `demote_unproven`).** `confirmed`
is the one load-bearing word in this product. Two provenances behind one word makes every downstream
number ambiguous at once: risk score, coverage counts, benchmark TPR, the report header, the SARIF
export. This repo has already paid for that twice — `707b3b9` (report stamped a hardcoded CONFIRMED on
rows the gate had demoted) and `837b1f0` (`proof_and_retest` claimed a negative control that never ran
on 626 of 660 findings). Both were a surface disagreeing with the gate. Exempting operator rows is the
same bug moved one layer earlier, where it is harder to see.

**Rejected — let the operator satisfy `validate_confirmed` with their own evidence text.** Superficially
principled, actually worse than doing nothing. `validate_confirmed` is a **substring contract over
evidence prose** (`_FAMILY` signal groups: "owner" AND one of "denied"/"401"/"403"/…). An oracle's
evidence string is *generated by code that actually issued the request*; an operator's is typed into a
box. The two are indistinguishable to a substring check. So this awards `confirmed` for **vocabulary,
not proof** — a guard that checks a declaration instead of a fact, which is a failure mode this project
has logged and been bitten by. It would also teach operators which words to type, which is the worst
possible outcome for a tool whose differentiator is deterministic proof.

**Chosen — a second axis.** The codebase already makes exactly this move twice, and the precedent is
the argument: `proof_kind` / `control_status` split "is it proven" into the *shape* of evidence and
*whether the control ran*; `dependency_intel` splits `version_confidence` (how sure of the version)
from `component_status` (was the CVE's own behaviour seen). Two questions, two named fields, rather
than one overloaded word. An operator attestation is a third such question — *did a named human take
responsibility for this claim, and on what grounds* — and it is strictly **more** information than
`confirmed`: it carries who and why, which `confirmed` never has. It is also the only form that stays
true when a third party who did not run the scan reads the report.

The corollary is what makes it a real gate rather than a label: **an attestation is refused when it
carries no attester or no rationale**, with the reason returned to the operator. An unsigned assertion
is exactly the thing we are declining to mint.

### Consequences this design accepts

* An operator-attested lead **stays a lead** in `confidence`. That is the honest answer and it is
  deliberate. What changes is that the lead now carries a durable attestation and is no longer
  presented as an open, un-acted-on item.
* Because `confidence` is computed inside the endpoint and never taken from the request body, **a lead
  the gate demoted cannot be re-confirmed by writing it back** — not through `/leads/.../confirm` and,
  after Q-013, not through `PUT /findings` either. That is the property the two tickets share.
* An attestation may **cite exchange ids** recorded by Apolaki in this mission. Those are validated to
  exist (else refused), so the attestation is checkable without being laundered. It still does not
  auto-promote: whether a recorded exchange proves a given claim is a human judgement, and the
  attestation records that a human made it.

### Follow-on NOT built here — `agent/report.py` is off-limits to this lane

`report._leads_md` renders an attested lead identically to an un-triaged one, so the operator's
decision is durable in storage and in the UI but still invisible in the report. The storage shape is
now final (`lead["operator_attestation"] = {operator, rationale, notes, attested_at, lead_id,
exchange_ids, machine_proof, proof_gap}`), so here is the exact patch. It is additive — a lead with no
attestation renders byte-for-byte as today.

```python
# agent/report.py — _leads_md, replace the table header + row loop
    lines = ["", "## Unconfirmed Leads", "",
             "_Signals worth manual verification — NOT confirmed vulnerabilities. "
             "Confirm before reporting to a program._", "",
             "| Severity | Confidence | Lead | Target | Operator attestation |",
             "|---|---|---|---|---|"]
    for l in sorted(leads, key=lambda x: SEV_ORDER.get((x.get("severity") or "info").lower(), 5)):
        # An operator attestation is a DISTINCT provenance, not a confirmation: `confidence` stays the
        # oracle's verdict and this column carries who/why/when plus the machine-proof gap. Rendering
        # it as `confirmed` is the defect 707b3b9 already fixed once, one layer earlier.
        at = l.get("operator_attestation") or {}
        if not at:
            att = "—"
        elif at.get("machine_proof"):
            att = f"Attested by {at.get('operator','')} ({str(at.get('attested_at',''))[:10]}); machine proof satisfied"
        else:
            att = (f"Attested by {at.get('operator','')} ({str(at.get('attested_at',''))[:10]}) — "
                   f"NO machine proof; missing: {', '.join(at.get('proof_gap') or [])}")
        lines.append(f"| {(l.get('severity') or 'info').capitalize()} | {l.get('confidence','candidate')} "
                     f"| {l.get('title','')} | `{l.get('target','')}` | {att} |")
```

A second, optional one on the confirmed side: a finding released by an operator carries the same
`operator_attestation` key, and the finding renderer could state "Released by <who>: <why>" beside the
proof block. Not required for the invariants — the proof is machine-checked in that case — but it is
the honest provenance line.

---

## Measured suite state

| when | result |
|------|--------|
| brief's stated baseline | 2351 passed, 11 skipped, 1 xfailed, 0 failed |
| after Q-013 (slice 1) | 2 failed — **both** `tests/test_sweep_class_coverage.py`, which the selection lane committed RED on purpose in `2f76886` while this run was in flight. Not this lane's. |
| after Q-014 (slice 2) | 2371 passed, 11 skipped, 1 xfailed, 0 failed |
| after Q-013 second pass (slice 3) | **2374 passed, 11 skipped, 1 xfailed, 0 failed** |

2351 -> 2374 is +23: **18 from this lane** (9 in `test_gate_write_paths.py`, 9 in
`test_operator_attestation.py`) and 5 from the selection lane's commits (`cf22521`, `f9b56c5`,
`602e693`, `508885c`), which landed on `main` during this work. The single xfail (`00494`, the
proved-undecidable `(A,A,A,B)` signature) is untouched; 11 skipped is unchanged.

**No benchmark number moved**, as required — this is an API and gate path, not detection.
`tests/test_bench_product_fpr.py` and `tests/test_bench_contract.py` pass unchanged, and no benchmark
module (`benchmark.py`, `blind_benchmark.py`, `owasp_bench.py`) references `add_lead`, `_lid` or
`update_finding`; the scoring harnesses write through `db.add_finding`, whose behaviour is byte-for-byte
unchanged, and read through `db.get_findings`.

## What changes for existing callers — stated plainly, including what BREAKS

**This is the one real behaviour change in the lane.** A manually added finding no longer appears
under confirmed findings. It appears under Unconfirmed Leads carrying an operator attestation.

That is deliberate and it follows directly from the design answer: `confirmed` means an Apolaki oracle
observed the proof, and a hand-typed finding never had one. The operator loses nothing real — the
claim is durable, and it now carries *who* and *on what grounds*, which a bare `confirmed` never did —
but anyone whose workflow counted manual findings in the confirmed total will see that total drop.
Affected surfaces: the confirmed/unconfirmed counters, `risk_score` (which reads confirmed findings
only, so a manual finding no longer contributes severity weight), and the report's Findings vs
Unconfirmed-Leads split. No test asserted the old behaviour; the only caller was the UI form, updated
here. If that trade is not wanted, the alternative is to keep manual findings in the confirmed table
under a separate `authored_by: operator` label and teach every consumer to read it — strictly more
work at every surface, for a word that would still mean two different things.



* `db.update_finding` gained two `False`-returning refusals it did not have. The three callers in the
  tree — `main.capture_finding_poc`, `main.update_finding` (the route), `agent._triage` — all pass
  in-scope, confirmed-confidence findings and are unaffected; a test pins the two merge shapes.
* One deliberate behaviour change with no in-tree reader: `POST /leads/{sid}/{lid}/confirm` now returns
  `promoted` as a **bool** rather than the lead's title. The only caller was `ui/index.html`, which
  discarded the response entirely, and it is updated here.
* Legacy data: a mission whose `ctx["leads"]` were written by the old code carry `id` only. They stay
  addressable because `_find_lead` accepts either key — that is why the resolver reads both rather than
  relying on the new `add_lead` stamp.
* `agent._triage` calls `update_finding` on every stored row. If a mission's DB still holds a
  lead-confidence row in the confirmed table (only reachable via the pre-fix bypass), triage now moves
  it to the leads list. That is the repair, not a regression.

## Stop conditions NOT hit

`agent/proof_schema.py` was not modified and did not need to be. Its vocabulary
(`is_confirmed`/`UNPROVEN_CONFIDENCE`/`proof_kind`/`control_status`/`counter_example`) was sufficient
to express this design: the attestation is a new axis alongside them, in the same style, not a change
to any of them. The defect really was a write path going around the vocabulary.

## Commits

Recorded from `git log`; a row with no hash has not been committed.

| slice | what | hash |
|-------|------|------|
| 1 | Q-013 gate on the update write path + bypass controls | `3addb1c` |
| 2 | Q-014 lead identity + operator attestation | `a1cdb8d` |
| 3 | Q-013 second pass: an HTTP body may not author proof | `42e1544` |

Slices 2 and 3 of the original plan landed as ONE commit rather than two. They are not separable: the
attestation endpoint is unreachable for a gate-routed lead without the identity fix, and the identity
fix has no visible effect without an endpoint worth reaching. Splitting them would have meant
committing a half that could not be exercised, which is the opposite of "commit each green slice".
