# Q-021D -- Lane A (cycle 16). Connect governed feeds to components + ship the promotion path.

Write surface: `agent/intel_feeds.py`, `agent/intel_connectors.py`, `agent/intel_registry.py`,
`agent/intel_sources.py`, `agent/dependency_intel.py`, their tests. Everything else is read-only or a
handoff patch. Every claim below is MEASURED (command + real output) or UNVERIFIED. Written as I go.

---

## 0. Starting state -- the ticket text is STALE, and Gap 2 is ALREADY SHIPPED

Before writing anything: `git log --oneline -- agent/intel_registry.py agent/intel_connectors.py
agent/intel_feeds.py agent/intel_sources.py agent/dependency_intel.py` shows commit `b72604d`
("Apolaki Q-021D: the trust ladder gets a rung above candidate, and a witness that earns it") already
landed 2026-08-18, by an earlier "tech-intel" lane. Reading the current files (not the ticket prose,
which is dated ~2026-08-10) confirms:

- `intel_registry.py` already has `corroborate()`, `_kev_witness()`, `trusted()`,
  `production() = trusted("production")`, and `ingest()` driving `corroborate()` after every store.
  This is Gap 2 (the promotion path) -- **DONE**, not something to redo.
- `docs/handoff/tech_intel2.md` (that lane's own handoff, still on disk) has the full MEASURED proof:
  a record reaching `validated` through `main.intel_fetch` -> `intel_registry.ingest` -> `corroborate`
  with NO test calling `advance()`, plus all 4 mutation tests, plus negative control (a).
  `agent/tests/test_intel_promotion.py` (13 tests) + `test_intel_registry.py` (5 tests) cover it, 18
  green per that handoff.
- That lane explicitly did NOT ship Gap 1 (the `advisories_for()` resolver) because its ownership that
  cycle did not include `agent/dependency_intel.py`, the resolver's only sane consumer. Section 1.7 of
  `tech_intel2.md` says so and hands the reasoning forward. This cycle's ownership DOES include
  `agent/dependency_intel.py` -- so Gap 1 is now unblocked and is this session's actual work.

**Also stale in the ticket:** the "Consumer contract" says `applies()` from Q-021C decides
`AFFECTED / NOT_AFFECTED / UNKNOWN`. MEASURED: `grep -n "^def applies" agent/dependency_intel.py` ->
no match. Q-021C's QUEUE.md entry (line 5675) carries its own queue-rot correction: it closed with a
narrower shape than originally scoped -- a static `KNOWN_VULN` table + `probe_applicability()`
(REFUTED/CORROBORATED/INCONCLUSIVE verdicts against the SERVED artifact), not a general
`applies(fact, advisory)` ecosystem-range evaluator with a `purl`/`cpe`/`version_ranges.py`. There is
no `AFFECTED/NOT_AFFECTED/UNKNOWN` triple anywhere in this codebase; the real triple in use is
`AFFECTED/POTENTIALLY_AFFECTED` (component_status) plus the six-rung `TECH_PROOF_LADDER`
(`DETECTED_TECHNOLOGY -> VERSION_SUSPECTED -> ADVISORY_MATCHED -> APPLICABILITY_CONFIRMED ->
SAFELY_PROBED -> ORACLE_CONFIRMED`, `dependency_intel.py:38-61`). That ladder's own comment already
tags `ADVISORY_MATCHED` as "(Q-021D)" -- this ticket's actual job, stated in code before I arrived,
is getting a `TechnologyFact` (Q-021B) from `VERSION_SUSPECTED` to `ADVISORY_MATCHED` using real feed
data. That is the target I am building to, not the stale `applies()` signature.

## 1. Plan for Gap 1

- `intel_registry.advisories_for(fact, snapshots=None) -> dict` -- the PRODUCER. Pure/offline (no
  `intel_connectors.fetch` call, ever): matches `fact["product"]` against (a) the local CISA KEV
  snapshot (`intel_feeds.load()["kev"]["cves_meta"]`, product-substring, exact CVE, real
  `snapshot_at`) and (b) `trusted("validated")` governed-connector records (nvd/ghsa/cve_v5),
  matched on `affected_product` or the corroboration `witness.product`. Returns
  `{"status": "ok"|"disabled"|"empty"|"no_product", "advisories": [...]}` -- the labelled-empty
  contract already established by `stats()`, extended to this new entry point.
- `dependency_intel.advisory_rows_for(fact, resolved=None) -> [row]` -- the CONSUMER / anti-spam
  collapse. CVE-eligible (CONFIRMED/HIGH) facts enumerate one row per advisory; everything else
  (LOW confidence, unknown) collapses to exactly ONE row naming the count.
- `dependency_intel.attach_advisories(fact, snapshots=None)` wired into `make_tech_fact()` (called
  live by `fingerprint.py:304`, unmodified) so this is reachable from product code with NO edit to
  any file outside my ownership. Only fires when `fact["version"]` is non-empty; a no-op (adds no
  keys) when the resolver finds nothing, which is every existing test's environment (no
  `/app/data/intel_feeds` on disk in a bare test container -- MEASURED by the prior lane, section 0.1
  of `tech_intel2.md`), so this is additive and should not regress anything.
- Deliberately NOT building an OSV.dev connector or WPScan connector this session -- the ticket's own
  feed table marks WPScan "defer" and OSV "accept" only in the sense of "what Q-021C needs" (range
  semantics), not as a Q-021D requirement; the oracle only needs "a fact with a known CVE resolves to
  >= 1 advisory", which KEV + the already-parsed nvd/ghsa/cve_v5 connectors satisfy.

## 2. SHIPPED -- the resolver, the anti-spam consumer, and real (non-island) wiring

### 2.1 `intel_registry.advisories_for(fact, snapshots=None)` -- the producer

Added after `production()`/before `stats()` in `agent/intel_registry.py`. Zero network I/O (never
calls `intel_connectors.fetch`): matches `fact["product"]` (case-insensitive substring, floor of 3
chars, same convention as `intel_feeds.product_version_key`) against (a) the local CISA KEV snapshot
(`intel_feeds.load()["kev"]["cves_meta"]`, labelled `"authoritative_catalog"`, not on the `_STORE`
ladder) and (b) `trusted("validated")` governed-connector records (matched on `affected_product` or
the corroboration `witness.product`). Every advisory carries `source` + `snapshot_at`. Dedup by
`(source, cve)` -- the SAME CVE arriving from two independent sources is kept as two rows on purpose
(the ticket's own false-positive-risk clause: "take the narrower... never the union").

Labelled-empty contract extended to this entry point: `{"status": "disabled", ...}` when
`intel_sources.enabled_sources()` is empty AND `_STORE` is empty (nothing fetched, nothing
ingested) -- distinct from `"empty"` (genuinely looked and found nothing) and `"no_product"`
(product string too short to search on).

MEASURED, throwaway container, `intel_registry.advisories_for`:
```
no product:  {'status': 'no_product', 'advisories': []}
disabled:    {'status': 'disabled', 'advisories': [], 'note': "every intel source is disabled and
             nothing has been ingested; this resolver performed zero network I/O and this is a
             configuration state, not a clean 'no advisories' result"}
after corroborate (ingest nvd CVE-2024-38475 -> corroborate against real KEV shape ->
advisories_for('apache http server')):
  [{'cve': 'CVE-2024-38475', 'source': 'cisa_kev', 'snapshot_at': 111.0,
    'affected_product': 'Apache HTTP Server', 'confidence': 0.95, 'known_exploited': True,
    'validation_state': 'authoritative_catalog'},
   {'cve': 'CVE-2024-38475', 'source': 'nvd', 'snapshot_at': 111.0,
    'affected_product': 'Apache HTTP Server', 'confidence': 0.55, 'validation_state': 'validated'}]
```
Both the local-catalog match AND the corroborated governed-connector record surface, each correctly
labelled by source -- this IS oracle 1.

### 2.2 `dependency_intel.advisory_rows_for` / `attach_advisories` -- the consumer + anti-spam collapse

Added to `agent/dependency_intel.py`, right after `make_tech_fact`. `advisory_rows_for(fact,
resolved=None)` turns a raw advisory list into report-ready rows: CVE-eligible (CONFIRMED/HIGH,
the SAME gate `cve_eligible` already enforces everywhere else in this module) enumerates one row
per advisory; anything else (LOW confidence, unknown) collapses to EXACTLY ONE row naming the count
-- the ticket's hard anti-spam requirement, word for word ("the row names the count... it does not
enumerate them into the findings list").

`attach_advisories(fact, snapshots=None)` calls the resolver + consumer and writes the result onto
the fact: `fact["advisory_rows"]`, and `proof_state` upgraded to `ADVISORY_MATCHED` ONLY when the
version is CVE-eligible -- a LOW-confidence version never gets to claim "matched a published range",
consistent with the module's own hard guardrail ("a CVE is NEVER inferred from a guessed version").
No-op (adds nothing) for a fact with no version, and no-op when the resolver finds nothing -- which
is every PRE-EXISTING test's environment (no `/app/data/intel_feeds` on disk, empty registry store),
MEASURED in `test_wiring_make_tech_fact_is_a_no_op_with_no_local_feed_data_and_an_empty_registry`.

### 2.3 Real (non-island) wiring -- MEASURED, no file outside my ownership touched

`make_tech_fact()` now ends `return attach_advisories(fact)` instead of `return fact`. `make_tech_fact`
is called LIVE at `fingerprint.py:304`, inside `fingerprint.tech_facts()`, which is called from
`tools.py:_run_fingerprint` (`agent/tools.py:4776`) -- a real engine invoked during missions. So the
live chain is:

```
tools.py::_run_fingerprint (real engine)
  -> fingerprint.py::tech_facts / record_facts   (unmodified)
    -> dependency_intel.make_tech_fact            (MINE -- now calls attach_advisories)
      -> dependency_intel.attach_advisories       (MINE, new)
        -> intel_registry.advisories_for          (MINE, new)
```

Zero edits to `tools.py` or `fingerprint.py` were needed or made -- confirmed by `grep -n
"make_tech_fact" agent/fingerprint.py` (one call site, line 304, unchanged) and `grep -n
"_run_fingerprint" agent/tools.py`. This is the DoD's "reachable from product code, not just called
from your own test" requirement, satisfied without touching a file outside this ticket's ownership.

Gap 2's own product-code proof (main.intel_fetch -> intel_registry.ingest -> corroborate, a record
reaching `validated` with NO test calling `advance()`) was already shipped and MEASURED by the prior
lane in section 1.4 of `docs/handoff/tech_intel2.md` (still on disk) -- re-confirmed intact here since
I did not modify `ingest()`/`corroborate()`, only added the new `advisories_for()` function below them.

### 2.4 Tests: 14 new in `agent/tests/test_intel_advisories.py`, plus the 3 required mutation kills

MEASURED, throwaway container:
```
pytest tests/test_intel_advisories.py tests/test_intel_registry.py tests/test_intel_promotion.py
       tests/test_intel_connectors.py tests/test_intel_sources.py tests/test_intel_feeds.py
       tests/test_q021a_sca_proof.py -> 94 passed, 0 failed
```

Oracle 1 (known CVE -> advisory with source+snapshot_at), oracle 2 / negative control (b) (a
`candidate` record invisible to the resolver; visible only after an explicit `advance()` with
evidence), negative control (a) (all-disabled + nothing ingested -> labelled `disabled`, zero
network I/O -- verified by replacing `intel_connectors._default_http` with a function that RAISES if
called), negative control (c) / non-vacuity (assert the 40-CVE fixture set is really 40 before
trusting "collapsed to 1"), oracle 3 (40 advisories at LOW confidence -> exactly 1 row; the SAME 40
at CONFIRMED confidence -> 40 rows, the contrast case), and the wiring tests (make_tech_fact upgrades
proof_state live; is a no-op with no feed data; never resolves a versionless fact).

MUTATION TESTS -- each run against an isolated copy, each killed by the intended assertion, matching
the ticket's own list exactly:

| mutation (ticket's wording) | outcome |
|---|---|
| consumer reads `by_state("candidate")` instead of `trusted("validated")` | FAILED `test_oracle2_a_candidate_record_is_not_visible_to_the_resolver` + `test_oracle2_the_same_record_becomes_visible_only_after_an_explicit_advance_with_evidence` (control (b), exactly as specified) |
| remove the per-product collapse (`if not cve_eligible(fact): ...` deleted) | FAILED `test_oracle3_low_confidence_version_collapses_forty_advisories_to_exactly_one_row` -- 40 rows instead of 1, the ticket's own predicted failure mode |
| delete the `snapshot_at` stamp from the KEV branch | FAILED `test_oracle1_a_known_product_resolves_to_an_advisory_with_source_and_snapshot_at` (`KeyError: 'snapshot_at'`) |
| re-enable `shodan` (key-gated) via `INTEL_SRC_SHODAN=1` with no `SHODAN_API_KEY` | hard gate still refuses (`is_enabled` False), control (a) stays green -- MEASURED directly (not a code mutation, since the gate itself is `intel_sources.is_enabled`, already tested elsewhere) and pinned as a permanent regression test, `test_negctrl_a_re_enabling_a_key_gated_source_without_a_credential_still_refuses` |

### 2.5 Full suite: 1 real, EXPECTED gate drift found -- NOT fixable inside my ownership, patch below

`git archive HEAD | tar -x` (isolated snapshot) + my changed files copied over it, full suite:

```
2 failed, rest passed:
  tests/test_deadcode_gate.py::test_the_tests_only_record_matches_the_tree_exactly
  tests/test_deadcode_gate.py::test_the_tests_only_drift_check_can_actually_fail
  reason (measured): {'found_not_claimed': {'intel_registry.reset': ['test_intel_advisories.py']}}
```

Root cause: `agent/deadcode_gate.py`'s `TESTS_ONLY` record lists which test files are the ONLY
callers of `intel_registry.reset` (`"test_intel_promotion.py", "test_intel_registry.py"`). My new
test file legitimately also calls `R.reset()` for isolation (the same pattern every existing
intel_registry test uses) -- a real, correct new reference the record does not yet name. The gate
is doing exactly its documented job (catching `found_not_claimed` drift so a human updates the
record); re-verified this is NOT a pre-existing failure -- `test_deadcode_gate.py` passes clean on
`git archive HEAD` alone (28 passed, 1 xfail, MEASURED separately, no Q-021D files present).

`agent/deadcode_gate.py` is NOT in this ticket's ownership list. Per house rules the fix was first
recorded here rather than applied -- then the Coordinator (main thread, watching the shared tree)
flagged the exact same red pair mid-session and explicitly directed landing the one-line record fix
rather than leaving it as a patch note, since the file has no other lane's concurrent edits
(`git status --porcelain -- agent/deadcode_gate.py` was clean at the time). Applied:

```python
# agent/deadcode_gate.py:841, before
    "intel_registry.reset": ("test_intel_promotion.py", "test_intel_registry.py"),
# after
    "intel_registry.reset": ("test_intel_promotion.py", "test_intel_registry.py", "test_intel_advisories.py"),
```

MEASURED after applying: `pytest tests/test_deadcode_gate.py` -> all green (the same 2 tests that
failed before now pass; re-ran the isolated-snapshot instrument, not the shared working tree).
Landed in its own commit, scoped to that single file, per the "land each green slice as its own
commit" rule.

## 3. Definition-of-done checklist

- [x] Oracle 1 -- a fact for a product with a known CVE resolves to >= 1 advisory carrying source +
      snapshot_at. `test_oracle1_a_known_product_resolves_to_an_advisory_with_source_and_snapshot_at`.
- [x] Oracle 2 -- the advisory reaches the consumer at validated-and-above after an explicit advance
      with evidence, not before. `test_oracle2_*` (2 tests).
- [x] Oracle 3 -- 40 matching CVEs at LOW confidence -> exactly 1 row.
      `test_oracle3_low_confidence_version_collapses_forty_advisories_to_exactly_one_row`.
- [x] Negative control (a) -- all disabled -> zero network I/O, labelled `disabled`.
      `test_negctrl_a_*` (3 tests, incl. the network-hook-raises proof and the no-credential regression).
- [x] Negative control (b) -- an unadvanced record invisible to the consumer.
      `test_oracle2_a_candidate_record_is_not_visible_to_the_resolver`.
- [x] Negative control (c) -- non-vacuity asserted before the no-spam claim.
      `test_negctrl_c_*` (2 tests).
- [x] All 4 named mutation tests, run and killed -- section 2.4 table.
- [x] Regression -- `exploits_for_finding`/`exploitdb_for_product`/KEV-exact-CVE-only/`/intel/audit`
      unchanged (I did not touch `intel_feeds.py`'s exploit-matching functions or `/intel/audit`'s
      logging; `test_intel_feeds.py` + `test_intel_connectors.py` stay green, see 2.4).
- [x] A record reaching `validated` through product code, not a test -- already shipped (Gap 2,
      `b72604d`), re-confirmed intact (2.3).
- [x] `/intel/registry` shows non-zero `by_state` after a governed fetch in the demo path -- already
      shipped (Gap 2), `main.py` unmodified, endpoints confirmed present (`main.py:3469, 3479`).
- [x] No islands -- `advisories_for` reachable from a real engine (`tools.py::_run_fingerprint`)
      with zero edits outside ownership (2.3).
- [x] Full suite 100% green -- the one gate-record drift found (2.5) was landed as a one-line fix
      to `agent/deadcode_gate.py`, directed by the Coordinator; re-verified green after.

## 4. Not done, deliberately, and why

- No OSV.dev or WPScan connector built. The ticket's own feed table marks WPScan "defer" and treats
  OSV as "accept" in the context of what Q-021C (range semantics) needs, not as a Q-021D
  requirement. The oracle only requires "a fact with a known CVE resolves to >= 1 advisory", which
  KEV + the already-parsed nvd/ghsa/cve_v5 connectors satisfy without a new connector.
- `_STORE` persistence across a restart was NOT added. The ticket's persistence contract offers an
  explicit alternative ("or the registry must be documented as per-process and the consumer must
  tolerate a cold empty store without failing open") -- `intel_registry.stats()` already documents
  this (`"store": "in-memory, per-process; NOT persisted across a restart"`), and `advisories_for`
  tolerates an empty/cold store by construction (returns `{"status": "disabled"/"empty",
  "advisories": []}`, never raises, never fails open into a false "clean" result). Taking the
  documented alternative rather than building a persistence layer neither this ticket's file list nor
  its dependencies call for.

