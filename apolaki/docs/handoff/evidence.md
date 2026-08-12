# Evidence-contract lane (Builder) -- handoff

Status: IN PROGRESS. Written incrementally; whatever is here is the contribution.
Records what HAPPENED. Unmeasured rows say `in progress`, never a number. Hashes come from `git log`.

Ticket: `docs/handoff/breaker.md` OPEN ITEMS CARRIED FORWARD, item 1 --
"`poc_bundle.build()` claims a negative control that never ran", REJECTED twice (session 2 target 3b,
session 3 target 3a).

Files I own: `agent/poc_bundle.py`, `agent/report.py`, `agent/proof_schema.py`, their tests, this file.
Everything else is a patch note at the bottom, never applied across the line.

---

## 0. REPRODUCED (before any code change)

`/tmp/repro_defect.py` in `apolaki-agent-1`, built through the REAL producer
(`codereview.review_java`), not a hand-written dict:

```
finding: weak_crypto / CWE-327 / confidence=confirmed
         provenance=source-derived  lane=code-assisted  analysis=static-call-site
         line=5   target=src/main/java/com/acme/billing/Billing.java
         no 'request' key, no 'response' key

report.control_ran(f)                              -> False
report.proof_and_retest(f)['negative_control']
  -> "NO NEGATIVE CONTROL WAS RECORDED for this finding. The control that would settle it:
      A token signed with the wrong/again-modified key is REJECTED; only the forgery that
      exploits the algorithm-confusion / none / weak-secret flaw is accepted.
      -- run it before treating this as false-positive-safe."

poc_bundle.build(f)['confirmation']['negative_control']
  -> "A token signed with the wrong/again-modified key is REJECTED; only the forgery that
      exploits the algorithm-confusion / none / weak-secret flaw is accepted."     NOT GATED

poc_bundle.build(f)['confirmation']['evidence_requirements']
  -> [ "Oracle satisfied: the source selects the algorithm 'DES' at a Cipher.getInstance
        call site -- definitionally CWE-327, no runtime behaviour is in question",
       "Negative control captured showing the confirming signal is ABSENT without the trigger.",
       "Baseline + mutation request/response retained for deterministic replay." ]
```

The Breaker's report is confirmed, and the reproduction turned up **three more fabrications on the
same bundle** that the ticket did not name:

| # | surface | what it says for `Cipher.getInstance("DES")` | why it is wrong |
|---|---|---|---|
| 1 | `confirmation.negative_control` | a JWT forgery-acceptance control | the ticket. Also the WRONG VULN: `technique_model._neg_control_for` substring-matches `"crypto" in "weak_crypto"` and hands back the JWT/algorithm-confusion text. Nothing in this finding is a token. |
| 2 | `confirmation.evidence_requirements` | "Baseline + mutation request/response retained for deterministic replay" | there is no request to retain. |
| 3 | `reproduction.curl` | `curl -i -sk src/main/java/com/acme/billing/Billing.java` | `_curl()` falls back to `"curl -i -sk %s" % target`, and for this lane the target is a FILE PATH. A curl to a path on disk is not a reproduction; it is a command that cannot run. |
| 4 | `provenance` | `{tool_version, found_by: apolaki, skill_version}` | the bundle never states the LANE. A reader holding only the dossier cannot tell a SAST row from a DAST row -- which is the one distinction `codereview.py:145` says "must never be folded into a DAST figure". |

Honest halves measured at the same time, so the fix does not go looking for them:

- `report.proof_and_retest` DOES gate (`837b1f0` holds on a finding class it was never tested
  against -- a real result for that commit).
- `retest.plan(f)` -> `{"retestable": false, "reason": "no replayable http(s) target on the
  finding"}`. Honest already; `retest.py` needs no change.

---

## 1. THE QUESTION ASKED FIRST: what does the honest bundle for a source finding contain?

A negative control answers one question: **what would this look like if the finding were false, and
did we check?** The experiment that answers it is different per proof kind. It is not absent for
SAST -- it is a different experiment.

For `Cipher.getInstance("DES")` at `Billing.java:5` the honest bundle contains:

1. **The call site.** File, line, and the call as the parser resolved it -- not a text match. This
   IS the evidence; there is nothing behind it to go and observe.
2. **The resolved receiver + the matched value, and where the value came from.** `Cipher.getInstance`
   / `"DES"` / resolved from a literal (or from a `.properties` value, or a method name). The
   provenance of the VALUE is the SAST analogue of "was the response really caused by the payload".
3. **The rule that matched**, named: family + CWE + the oracle sentence.
4. **The counter-example that would falsify the rule** -- the sibling clean case. For CWE-327 that is
   `Cipher.getInstance("AES/GCM/NoPadding")`: the same rule, the same receiver, one different
   argument, and the rule must NOT fire. This is a real negative control. It is a rule-level control,
   not a request-level one, and it is exactly the discipline
   `agent/tests/test_codeassisted_negative_controls.py` already enforces on this lane (a rule that
   fires on the clean sibling is a signature, not a detector).
5. **An explicit statement that the request differential is NOT APPLICABLE**, with the reason: there
   is no request, no baseline and no mutation for a static call site, so the experiment cannot exist
   even in principle. Not "not recorded" -- "not recorded" says the experiment was available and
   skipped, which is a different (and here, false) claim.
6. **The lane**, stated in the bundle's own provenance block.

What it must NOT contain: a curl, a baseline, a mutation, a replay of an exchange, or any sentence in
the present indicative about a request that was never sent.

### The three cases, and how a reader tells them apart

A reader who did not run the scan must be able to distinguish them from the JSON alone:

| case | `confirmation.proof_kind` | `confirmation.control_status` | `confirmation.negative_control` opens with |
|---|---|---|---|
| source-derived (SAST) | `source-derived` | `not_applicable` | "NOT APPLICABLE to this proof kind:" |
| behavioural, control recorded | `behavioural` | `recorded` | the family contract text, UNCHANGED |
| behavioural, no control | `behavioural` | `not_recorded` | "NO NEGATIVE CONTROL WAS RECORDED" |

### Vocabulary: extended, not forked

`dependency_intel` already answers two different questions with two named fields rather than
overloading one word (`version_confidence` = how sure of the version; `component_status` = was the
CVE's own behaviour seen). Same move here, in `proof_schema` next to `is_confirmed` because it is a
shared predicate and three private copies of "confirmed" is how the HTML report came to stamp
CONFIRMED on demoted rows:

```
proof_schema.BEHAVIOURAL / SOURCE_DERIVED                 the proof KIND
proof_schema.CONTROL_RECORDED / NOT_RECORDED / NOT_APPLICABLE   the control STATUS (three-valued)
proof_schema.proof_kind(finding)      -> str
proof_schema.control_status(finding)  -> str
```

`report.control_ran` keeps its exact meaning ("a request-based control artifact was recorded") and
its exact return values; it delegates to `proof_schema` so the set of keys that count as an artifact
has ONE definition. A source finding still gets `control_ran -> False`, because it genuinely has no
request-based artifact -- the three-valued status is what carries the extra bit.

---

## 2. Slices

| # | slice | state |
|---|---|---|
| 1 | failing tests for all three cases | done, see section 3 |
| 2 | `proof_schema` vocabulary + `poc_bundle` per-kind contract | done, see section 3 |
| 3 | report surface states the same claim (check 7) | done, see section 4 |
| 4 | mutation check + full regression | see section 5 |

Slice 3 was FOLDED INTO the same commit as slices 1-2 rather than shipped after them. Committing
slice 2 alone would have left the dossier saying `not_applicable` while the report heading over the
same finding still said "NOT ESTABLISHED" -- a surfaces-disagree defect of exactly the kind being
fixed, committed deliberately. One composer, one commit.

Sections 3-5 are filled in from measured output only. No commit hash is written until `git log`
shows it.

---

## 3. Slice 1+2 -- results

`agent/tests/test_evidence_contract_by_proof_kind.py`, 15 tests, written and run BEFORE the fix.
Source fixtures are built by the real producer (`codereview.review_java`), never hand-written, so a
change to the producer's finding shape breaks the test instead of silently bypassing it.

```
BEFORE (pristine HEAD modules shadowing /app via /tmp/pre): 14 failed, 1 passed
AFTER  (/app with the fix)                                : 15 passed
```

The one that passes BEFORE and after is `test_control_ran_keeps_its_exact_meaning` -- the negative
control for the whole change. It is supposed to pass on both sides; a test asserting "this did not
move" that failed first would mean I had moved it.

Two of them were deliberately re-ordered after the first run: they failed on a missing key before
they reached the assertion about the defect, and a test that only fails because a new field is
absent proves nothing. Re-ordered, the first failure of each is the defect itself (MEASURED):

```
test_source_finding_does_not_claim_a_request_negative_control
  E AssertionError: 'A token signed with the wrong' is contained here:
      A token signed with the wrong/again-modified key is REJECTED; only the forgery that
      exploits the algorithm-confusion / none / weak-secret flaw is accepted.

test_behavioural_without_control_says_so_in_the_bundle_too
  E assert False
      where False = 'An inert control of the same shape but without SQL metacharacters does NOT
      reproduce the error/boolean/time differential; ...'.startswith('NO NEGATIVE CONTROL WAS
      RECORDED')
```

### What the three cases say now -- MEASURED (`/tmp/after_bundle.py` in `apolaki-agent-1`)

```
=== SOURCE-DERIVED (Cipher.getInstance("DES") at Billing.java:4) ===
confirmation.proof_kind      : source-derived
confirmation.control_status  : not_applicable
confirmation.negative_control:
   "NOT APPLICABLE to this proof kind: a source-derived (static call-site) finding has no
    request, no baseline and no mutation, so a request differential cannot exist for it. The
    control that DOES apply is the rule-level counter-example: Cipher.getInstance("AES/GCM/
    NoPadding") - the same receiver, one different argument, and the rule must not fire. If the
    same rule fired on that too, this would be a signature, not a detector."
confirmation.counter_example : Cipher.getInstance("AES/GCM/NoPadding") - ...
confirmation.evidence_requirements:
   - Oracle satisfied: the source selects the algorithm 'DES' at a Cipher.getInstance call
     site - definitionally CWE-327, no runtime behaviour is in question
   - Call site located: file + line, resolved from parsed source rather than a text match.
   - Counter-example rule-checked: Cipher.getInstance("AES/GCM/NoPadding") - ...
   - NOT APPLICABLE: baseline + mutation request/response replay - no request exists for a
     static call site.
source_evidence : {file, line: 4, analysis: static-call-site,
                   call_site: "...Billing.java:4  Cipher.getInstance(DES)",
                   rule: {family: weak_crypto, cwe: CWE-327, oracle: ...},
                   counter_example: ..., runtime_observation: "none required - the defect is
                   definitional at the call site, so there is no request, baseline or mutation
                   to record"}
reproduction.curl : ""                                    (was: curl -i -sk <a file path>)
reproduction.open : src/main/java/com/acme/billing/Billing.java:4
provenance        : {..., proof_kind: source-derived, lane: code-assisted,
                     provenance: source-derived}

=== BEHAVIOURAL, no control ===
proof_kind behavioural / control_status not_recorded
negative_control : "NO NEGATIVE CONTROL WAS RECORDED for this finding. The control that would
                    settle it: An inert control of the same shape but without SQL
                    metacharacters ... -- run it before treating this as false-positive-safe."
source_evidence  : absent

=== BEHAVIOURAL, control recorded ===
proof_kind behavioural / control_status recorded
negative_control : "An inert control of the same shape but without SQL metacharacters does NOT
                    reproduce the error/boolean/time differential; the unmodified baseline
                    behaves normally."          <- byte-identical to before
evidence_requirements / safety / cleanup : unchanged
source_evidence  : absent
```

`test_behavioural_with_control_is_unchanged` pins that third case to
`technique_model.proof_contract` -- the ORIGINAL source of truth -- rather than to a snapshot of
today's output, which would have passed even if the honest case had been changed.

The counter-example is looked up per family/CWE in `proof_schema.COUNTER_EXAMPLE`, and a producer
that supplies its own `counter_example` key on the finding beats the table (forward-compatible with
patch 6b). When neither exists the key is omitted and the prose degrades to "the sibling clean call
site the same rule must NOT match" -- it never invents a specific sibling it cannot name. Both
branches have a test.

## 4. Slice 3 -- report surface, MEASURED

Check 7 (all surfaces agree) is why `report.py` was touched at all. The claim is composed ONCE, in
`report.negative_control_claim(finding)`, and `proof_and_retest`, the markdown renderer, the HTML
renderer and `poc_bundle` all read it. `test_the_report_and_the_dossier_state_the_same_claim`
asserts string equality across the two surfaces for all three cases, so they cannot drift again.

```
report.proof_and_retest(source)['negative_control']       == bundle confirmation.negative_control
report.proof_and_retest(behavioural_bare)                 == bundle   (both "NO NEGATIVE CONTROL...")
report.proof_and_retest(behavioural_with_control)         == bundle   (both the contract text)
report.control_ran(source)              -> False     unchanged meaning: no REQUEST-based artifact
report.control_ran(behavioural_bare)    -> False
report.control_ran(behavioural_control) -> True
```

The rendered heading is three-way for the same reason the body is: "False-positive safety: NOT
ESTABLISHED" over a source finding is also false -- its FP-safety IS established, by a rule-level
counter-example rather than by a request. A two-valued heading over a three-valued fact has to be
wrong somewhere. Source rows now read "False-positive safety: rule-level counter-example (no request
applies)"; both behavioural headings are byte-identical to before.

`agent/tests/test_proof_claim_matches_artifact.py` (the `837b1f0` suite) is UNCHANGED and green --
every fixture in it is behavioural, which is the point.

## 5. Mutation check + regression

### Mutation check -- MEASURED (`/tmp/mut2.sh` in `apolaki-agent-1`)

Run against an overlay tree (`/tmp/mut`, my three files shadowing `/app` via a conftest path insert)
so no live lane's `/app` was ever mutated. Unmutated control: 15 passed.

| mutant | result | killed by |
|---|---|---|
| `proof_kind` always returns `BEHAVIOURAL` | KILLED, 11 failed | every source case + the heading + distinguishability |
| `control_status` returns `NOT_APPLICABLE` for everything | KILLED, 7 failed | both behavioural cases + `control_ran`'s unchanged meaning |
| lane label checked BEFORE the artifact | KILLED, exactly 1 | `test_a_recorded_artifact_beats_the_lane_label` |
| source branch drops the `NOT APPLICABLE` prefix | KILLED, exactly 1 | `test_source_finding_does_not_claim_a_request_negative_control` |
| `_curl` re-fabricates the curl for a file path | KILLED, exactly 1 | `test_source_finding_reproduction_is_not_a_curl_to_a_file_path` |
| `counter_example` invents a sibling when the family is unknown | KILLED, exactly 1 | `test_a_source_finding_with_no_known_counter_example_says_so_instead_of_inventing_one` |
| the honest behavioural case gets the source text | KILLED, 2 failed | `test_behavioural_with_control_is_unchanged` |
| `source_evidence` never emitted | KILLED, 3 failed | `test_source_finding_states_the_evidence_that_actually_exists` |

Every one killed by the assertion it was aimed at.

### A hole I put in myself, found before commit

The first version of `control_status` decided `NOT_APPLICABLE` from the lane label BEFORE looking for
an artifact. That is a guard reading a declaration instead of a fact -- a source-derived finding that
also carried a recorded control (a SAST lead a probe later confirmed) would have had its real
artifact suppressed by its own label, and `report.control_ran` would have flipped True -> False for
that shape. No producer emits it today, so it was latent, not live. Reordered so the artifact is
checked first: if an experiment was actually recorded then it was evidently applicable. The useful
by-product is a much stronger invariant -- `control_ran` is now byte-for-byte unchanged for EVERY
input, not just the ones in the fixtures. `test_a_recorded_artifact_beats_the_lane_label` is the
negative control, and the reordering mutant above is what proves the test can see it.

### Full regression

Both runs: `python -m pytest tests -q -p no:randomly`, `agent/tests/test_dom_audit_concurrency.py`
excluded from both (uncommitted and known-broken by its own author, per the house rules).

BASELINE -- run in an ISOLATED tree, `/app_base`, a copy of `/app` with the three files I own
restored from `HEAD` and my new test file removed. `/app` itself was never reverted, because other
lanes are live in that container. MEASURED:

```
/app_base : 2012 passed, 9 skipped, 1 xfailed, 0 failed   (2022 collected)   EXIT=0
```

Note for the Coordinator: the carried baseline is quoted as 2015 passed. I measured 2012 in the
container. I did not chase the 3-test difference and I am not claiming it is nothing -- the
container's `tests/` holds 201 files against the working tree's 202, and other lanes have been
committing test files all session. What matters for THIS change is the before/after delta measured
in the same container, minutes apart, which is below.

AFTER:

in progress

pytest 9.1.1 with `-q` prints no "N passed" summary line at all when nothing fails, which is why the
first two attempts at this measurement came back with an empty tail. The baseline counts above are
tallied from the run's own progress characters (`/tmp/tally.py`); the after-run additionally writes
`--junit-xml` so the two methods can be checked against each other.

---

## 6. Cross-lane patch notes (NOT applied -- other lanes own these files)

### 6a. `agent/codereview.py` -- emit the call site as STRUCTURED keys (owner: code-assisted lane)

`_source_finding()` folds the receiver, the matched value and its resolution origin into a prose
`evidence` string:

```python
"evidence": "%s:%s  %s(%s)%s" % (source, hit["line"], hit.get("api") or "",
                                 hit.get("spec") or hit.get("construct") or "", ...)
```

`poc_bundle.source_evidence()` therefore has to carry that string verbatim and cannot name the
receiver or say where the value was resolved from -- and parsing it back out with a regex is exactly
the failure mode this codebase already has a memory note about. The three values exist in `hit` and
are thrown away. Suggested addition to the dict `_source_finding` returns (purely additive, no
existing key changes):

```python
"call_api": hit.get("api") or "",
"call_value": hit.get("spec") or hit.get("construct") or "",
"value_resolved_from": hit.get("resolved_from") or "literal",
```

`poc_bundle` already prefers these when present (`source_evidence` reads `call_api` /
`call_value` / `value_resolved_from` and omits each key it does not find), so the patch needs no
second change on my side.

### 6b. `agent/codereview.py` -- carry the rule's own counter-example (owner: code-assisted lane)

`proof_schema.COUNTER_EXAMPLE` maps family/CWE -> the sibling clean call site. The rule that decides
what is weak lives in `codereview`, so that table is a second copy of a fact and can drift if a rule
gains an algorithm. The durable version is for the producer to state its own falsifier:

```python
"counter_example": 'Cipher.getInstance("AES/GCM/NoPadding")',
```

`poc_bundle` already prefers `finding["counter_example"]` over the table, so this can land whenever
that lane is free; the table is the fallback, not the design.

### 6c. `agent/technique_model.py` -- `_neg_control_for` substring-matches the wrong class

`"crypto" in "weak_crypto"` returns the JWT algorithm-confusion control for a `Cipher.getInstance`
finding (section 0, row 1). The per-kind contract means a source-derived finding never reaches that
text any more, so the visible symptom is gone -- but a BEHAVIOURAL `weak_crypto` finding (a TLS or
cookie-crypto probe) would still get the JWT sentence. The list is ordered and matched by `in`, so
the fix is a more specific key ahead of `("crypto", ...)`, e.g. `("jwt", ...)` on the token text and
a real entry for weak-cipher-at-rest. Not mine; recorded so it is not lost.
