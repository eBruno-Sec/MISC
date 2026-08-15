# QUEUE — the one canonical, dependency-ordered work queue

## STATE SWEEP — 2026-08-14 (second pass, same day). Authoritative.

**The first sweep went stale in under a day** — five more tickets closed while it sat. Sweeping again
is treating the symptom, so the rule that fixes the cause: **closing a ticket includes updating this
block in the same commit.** A queue whose state cannot be trusted is the same declaration-vs-fact
defect we keep finding in the code, and it is the one artifact every lane reads before choosing work.

**CLOSED, with the commit** — ignore any `ready`/`proposed` marker further down:
`Q-000` 5af0af8 · `Q-00A` 65970da · `Q-001` fc91bb0 · **`Q-013` 3addb1c + 42e1544 (two passes — the
first fixed the write path, the second found the invariants never read `evidence` at all)** ·
**`Q-014` a1cdb8d + report rendering** · `Q-019` fc91bb0 · `Q-022` 837b1f0 · **`Q-023` Codex lane 7 / 2ae0007** ·
`Q-031` 8eb42e8 · **`Q-040` cbcba79 (the real fix; the first was incomplete)** · `Q-041`/`Q-042` 9f8707a ·
`Q-043` c02208d · `Q-044` aa3a139 · **`Q-021B` 1f342c9** ·
`B-001`/`B-002`/`B-003` Codex lane 1 · `B-010` Juliet Codex lane 2 · **`B-020` a7aa700**

**IN FLIGHT**: **selection / step-cap** (selection lane — no ticket number yet; it is the successor to
the whole-product rerun and outranks everything below)

**NEW AND UNASSIGNED — raised by the rerun, currently nobody's:**
- **The published whole-product baseline cannot be re-derived.** The store returns 29 findings /
  27 cases / `ldapi 5` for `ebd96f45` against the ledgered 22/23 / `ldapi 1`; no dedup explains it and
  no subset reproduces the seal. On the store's numbers the loss is **−8, not −3**, and the "class
  coverage broadened" claim is unproven. **Every comparison against that mission is suspect.**
- **The `00494` two-call-site patch** — written up, not applied; closes the proved-undecidable residual
  by adding an after-probe sample rather than guessing from two.
- **The `_POWERED` regex yields garbage product names** (`'a MultiJuicer Kubernetes cluste'`,
  `'nothing on.'`) — found in passing during Q-021B, never ticketed.

**OPEN, ranked by value — this is the real backlog:**

| ticket | what | why it matters |
|---|---|---|
| **Q-021B–F** | Technology Intelligence chain: persist TechnologyFacts → identity/ranges → feeds → orchestration → honest UI | detected tech still drives no testing |
| **Q-032/033/034** | credential→session→persona, multi-persona differentials, report chronology | the architecture programme; `session_headers` is still one global raw dict at 50 sites |
| **Q-002/003/004** | WebSockets/CSWSH · `postMessage` source · API4 resource consumption | genuine zero-engine classes |
| **Q-011/012** | second phantom capability; six ASVS engine names resolving to nothing | declaration-vs-fact defects |
| **Q-015/016/017** | `risk_signals` unfiltered twin · `_read_controls` returns `[]` on failure · `get_logs` oldest-first | smaller, all real |
| **Q-005/006** | server-side prototype pollution (gated) · request smuggling (detection tiers only) | deliberately constrained |
| **Q-030/035/036** | canonical cycle design · the model A/B experiment · fold the 15 architecture defects in | Q-030 is designed, not built |
| **B-011+** | Juliet C/C++ (**UNSUPPORTED — no C/C++ analysis**), SARD subsets, remaining language ecosystems | matrix programme |

Roughly **28 open**. Q-023, Q-013 and Q-014 are all closed; the highest-value unstarted work is now
**Q-021B–F** (detected technology still drives no testing) and the **baseline provenance** item above,
which blocks trusting any comparison against `ebd96f45`.


**Only the Coordinator (QUEUE agent) changes state in this file.** Everyone else proposes; the
Coordinator ranks, dedupes, assigns and moves. One owner per ticket. No two agents editing the same
files concurrently.

States: `ready` · `active` · `verification` · `blocked (reason)` · `completed (commit)` ·
`rejected (reason)` · `rolled-back (reason)`

Ranking = expected capability gain × coverage gain × proof strength ÷ (risk × cost).

Related: [LEDGERS.md](LEDGERS.md) · [CODEBASE_REVIEW.md](CODEBASE_REVIEW.md) ·
[research/INBOX.md](research/INBOX.md) · [STATUS.md](STATUS.md)

---

## File ownership — this cycle

No two agents may edit overlapping files. A ticket needing a file owned elsewhere is
`blocked (file conflict)` until the owner releases it.

**Cycle 2 — assigned 2026-08-10 after the first squad was killed by API session limits.** Four lanes,
deliberately disjoint. Cross-lane needs are written here as **hand-off notes**, never applied directly.

| owner | files it may WRITE | ticket |
|---|---|---|
| **Builder · funnel** | `agent/agent.py` · `agent/crawl.py` | **Q-019** — the funnel (2756 → 36) |
| **Builder · engine** | `agent/tools.py` · `personas.py` · `register.py` · `session_lifecycle_tool.py` · `techniques.py` · `engine_descriptor.py` · `wstg_catalog.py` · `deadcode_gate.py` | **Q-001** — session lifecycle + the deadcode-gate failure it inherited |
| **Breaker** | test files only · `CODEBASE_REVIEW.md` | verify Q-00A (BIE), the 0% FPR claim, and today's four commits |
| **Watcher** | `docs/research/INBOX.md` | ZAP orchestration · the 8.5 s/call throughput ceiling · Q-021 feed quality |
| **Coordinator (main thread)** | `report.py` · `proof_schema.py` · `liveness.py` · `browser_engine.py` · `main.py` · all `docs/` | ledgers, sequencing, Codex-audit intake |

Known-conflict hand-offs, already issued:
- Q-019 may need an `_add_urls` ingress guard in `tools.py` (owned by the engine lane) → the funnel
  Builder writes the patch here instead of applying it.
- Q-001 needs a `liveness.py` CHECKS entry (owned by the Coordinator) → same rule.
- Q-001 may need an `agent.py` change (owned by the funnel lane) → same rule.

**Known failing test that belongs to the engine lane, not to anyone else**:
`tests/test_deadcode_gate.py::test_the_method_ratchet_holds`. Baseline otherwise 1670 passed,
2 skipped. Nobody but the engine-lane Builder touches it, and it must be fixed by wiring the code —
not by silencing the gate.

---

## Lane changes — 2026-08-12

**PROBE LANE STOOD DOWN.** Both of its hypotheses are falsified by its own measurements —
blind-vs-echo on cmdi (+0 over 251 cases) and carrier delivery on cmdi and xss (+0 over 120 paired
xss cases, with the carrier proven to have RUN on ~30% of them). It has nothing queued behind them,
and keeping a lane parked on a dead theory holds its files hostage. **Do not resume agent
`aff3a7dd3d2343dde`.** Its engine work is committed and keeps its value; the lane is closed, not the
code.

Released files: `agent/tools.py` · `agent/cmdi_tool.py` · `agent/xss_tool.py` · `agent/sqli_tool.py` ·
`agent/ssrf_tool.py` · `agent/dom_trace.py` · `docs/handoff/probes.md`.

**LEASED TO CODEX: Q-040 + B-010** from `aa8e26a`. `agent/sqli_tool.py` and its tests, plus all new
Juliet paths, are Codex's until it returns. Claude does not spawn or resume into them.

## Q-044 · The code-assisted lane is BENCHMARK-ONLY — 61.1% is not reachable in an engagement · **HIGH** · `ready`

**MEASURED 2026-08-13.** `codeintel.review_source_tree()` — the Java+Python call-site analyser that
scores **crypto 100% / hash 100% / weakrand 100% at 0.0% FPR**, and the entire difference between the
Java DAST-only 41.7% and the hybrid 61.1% — has **exactly one caller: `owasp_bench.py:231`.**

- `source_root` / `source_path` / `--source` appear **nowhere** in `agent/main.py` or `agent/agent.py`.
  A mission cannot supply a source tree.
- `GET /codereview?path=` exists and IS production-reachable, but it calls
  `codeintel.review()` — the **older, different** general static review, not `review_source_tree()`.
- No UI control, API parameter or planner step invokes the SAST lane.

**So the hybrid figure describes a capability no client engagement can currently invoke.** The number
is real and honestly measured; the path to it is benchmark-only. That is the island pattern for the
sixth time — after `chase_capability` returning `[]`, `untested("service")` empty by construction,
the graph planner executing nothing, `run_zap` never called in 150 missions, and `recon["zap"]` as a
dead write.

**Until this is wired, 61.1% must be described as a harness capability, not a product capability** —
the same distinction the ledger already enforces between the 41.3% harness number and the
2-findings whole-product number. Both ledgers and STATUS are being annotated accordingly.

**The ticket**: give `review_source_tree` a production entry point — a mission-level source input
and/or routing `/codereview` to it when the tree is Java/Python — and prove it with a real mission
that produces a source-derived finding, not a harness call. Note it must compose with the proof
gate: `proof_kind()` already returns `SOURCE_DERIVED` and `control_status()` already returns
`NOT_APPLICABLE` for these, so the evidence contract is ready and waiting for a producer.

## Q-043 · Apolaki does not honour `Retry-After` — and the Coordinator asserted that it did · **HIGH** · `ready`

**MEASURED by Codex lane 4**: with `Retry-After: 2` returned by the target, both concurrency widths
sent **47 requests**; width 6 started **14 requests inside the retry window**. The concurrency ceiling
held — the target-side backoff did not, because it does not exist.

**Verified independently: `Retry-After` appears NOWHERE in `agent/`.** A repo-wide grep returns zero
hits. `tools.py:3296` — which I cited as the enforcement point — is `subfinder` argument handling.

**This is a Coordinator failure, recorded as one.** I wrote *"`tools.py:3296` honours `429`/`Retry-After`
and that must survive"* into **five separate lease prompts**, to Claude lanes and to Codex. It was a
fabricated citation: a real-sounding file:line attached to a behaviour that was never implemented.
Nobody challenged it because it arrived from the Coordinator with a line number, which is exactly why
it is dangerous. Codex found it by **testing the behaviour instead of reading the claim** — the same
method that has caught every other load-bearing error in this project.

The standing rule this earns: **a Coordinator citation is a claim, not evidence.** File:line
references in briefs get verified before they are repeated, and a lane that cannot reproduce a cited
behaviour should treat the citation as the defect.

**The ticket**: a cross-cutting target-rate policy covering **both** `_http` and browser navigation —
Codex correctly declined to build it, because a generic fix touches every engine through `tools.py`
and that was its stop condition. Requirements: honour `Retry-After` (delta-seconds and HTTP-date) and
`429` on both paths; bounded and configurable; **and a negative control that fails if the policy is
removed**, since the absence of one is how this went unnoticed. No-DoS is a promise this platform has
been making in its own documentation without keeping.

## Rank 0 — five defects now PINNED by strict xfails, surfaced 2026-08-12

Each is a real defect with a written reason, held by a strict xfail so it becomes a regression test
the moment it is fixed. Removing a marker without fixing the defect is forbidden.

### Q-040 · `analyze_boolean` has no baseline-stability control · **CRITICAL** · `ready`
`tests/test_sqli_oracle_negative_controls.py::test_an_unstable_page_must_not_confirm_blind_sqli`.
**An unstable page confirms blind SQLi.** This is a false-positive path in our strongest category —
sqli is 21 of the 22 whole-product true positives, and FPR is currently 0.0% on every category of
both suites, which is the platform's single best property. Fix: the oracle must re-sample the
baseline and prove stability before crediting a boolean differential. Remove the marker only then.

### Q-041 · aliased module imports are invisible to the source lane · **HIGH** · `ready`
`import random as r` / `import hashlib as hl`. `_py_imports()` computes `modules['r'] = 'random'` and
then **throws the binding away** — `_py_binds_module` can only SUPPRESS a name, never resolve one, and
`_PY_RANDOM_CALL` / `_PY_HASHLIB_CALL` hard-code the literal receivers. The `from X import Y as Z`
half is handled correctly, so this is a half-implemented mechanism, not a missing one. Costs the
benchmark **0 cases** (no aliased imports in the suite) — it is a pure generality hole, and generality
is the whole claim of the code-assisted lane.

### Q-042 · `_PY_CLOCK_TOKEN` fires on a name that merely CONTAINS a security word · **HIGH** · `ready`
Any identifier containing a security word within 90 characters of a clock read is reported as CWE-337
"a security value derived from the clock" — so an audit or expiry timestamp is a false positive.
**Confirmed in the wild**: the single CWE-337 across 5139 files of the container's stdlib is this bug
firing on the keyword argument `token=` in `anthropic/lib/credentials/_workload.py:346`. Costs the
benchmark 0 cases; costs credibility on any real codebase. Fix: bind the value, do not pattern-match
its name — the same "receiver decides, not the name" rule that took Python weakrand from 50.2% to 100%.

## Rank 0a — Q-021A · contain the SCA proof overclaim · **CRITICAL** · `in flight`

Spec: [CODEX_AUDIT_VERDICTS.md](CODEX_AUDIT_VERDICTS.md) verdicts 1–5. Jumps the queue ahead of
Q-019: everything else is a missing capability, this one is a **wrong answer already shipping to
clients**. Owner this cycle: **Builder · SCA**, files `dependency_intel.py` · `proof_schema.py` ·
`retest.py` · `poc_bundle.py` · `candidate_pipeline.py` · `report.py` · `sarif_io.py` · tests.

Measured baseline before the first slice: **1730 passed, 9 skipped, 0 failed** (agent image,
python 3.12). The `test_t7_zero_delta` PRECONDITIONS failure noted in the hand-off is not present in
the baked image.

**Slice log** (each slice: implement → targeted test that failed first → negative control → commit):

| # | slice | state |
|---|---|---|
| 1 | `dependency_intel` — split version-certainty from exploitability-certainty | **done** |
| 2 | `proof_schema` — the proof gate must inspect `vulnerable_component` | **done** |
| 3 | `retest` — a patched component must CLOSE, not stay OPEN | **done** |
| 4 | structured `cves` on the SCA finding so KEV can match it | **done** |
| 5 | `success_oracle` vs `oracle` — one canonical key, normalised at one chokepoint | **done** |
| 6 | SARIF still un-demotes proof-gate-demoted rows (bonus) | **done** |
| 7 | stale-bundle-filename FP — contradictory fingerprints of one library | **done** |

### Slice 1 — `confidence` no longer answers two questions with one word
`vulnerable_component_finding` set `confidence=CONFIRMED` while its own `impact` said exploitability
"was NOT confirmed in this test". Fixed by separating the fields, not by deleting the claim:

* `version_confidence` — `confirmed`/`high`/`low`, how sure we are of the **served version**.
* `component_status` — `affected` / `potentially_affected`, whether the CVE's **own behaviour** was
  observed. New module constants `AFFECTED` / `POTENTIALLY_AFFECTED`.
* `confidence` — the platform-wide proof verdict. `confirmed` **only** when
  `behaviour_proof_ok()` passes; otherwise `lead` + `proof_gap` + a `needs-confirmation` tag.
* `behaviour_proof_ok(proof, cve_ids)` — pure oracle. Requires a CVE **from the matched ranges**, a
  trigger, the observed vulnerable behaviour, a structurally identical **trigger-absent control**,
  and a real differential between the two. Caller performs the requests; this only judges them.
* `CVE_ELIGIBLE` is reused (not reinvented) as the enforcement point: a `LOW` fingerprint is a guess
  and can never be `affected`, however many CVEs a feed returns.

Preserved deliberately: the MEDIUM severity cap and its scanner-inflation comment.

Hand-off note (files owned elsewhere) — none for slice 1; `tools.py:5210` calls
`vulnerable_component_finding(comp, vulns)` positionally and keeps working unchanged, now emitting a
lead instead of a false confirm.

### Slice 2 — the proof gate now inspects SCA findings
`_DEFAULT_ENFORCE` omitted `vulnerable_component`, so `demote_unproven` never looked at an SCA row
and the slice-1 defect reached the client report intact even after the producer was fixed (any other
producer, or a persisted pre-fix finding, still slipped through).

* new `_FAMILY["vulnerable_component"]` proof contract: the exact CVE **and** a behaviour
  differential / negative control **and** what was observed. Presence evidence carries none of them.
* `_CWE_FAMILY` gains `CWE-1104` / `CWE-1035`; `_ALIAS` gains `vuln_component` / `sca`, so a row
  carrying only the CWE routes to the same contract.
* `_DEFAULT_ENFORCE` widened by exactly ONE entry. The narrow default is a **sequencing** rule, not
  a permanent one — a family becomes enforceable once its producers' evidence phrasing has been
  audited. This family has one production producer, audited in slice 1, so enforcement cannot
  manufacture a false negative; the only row it can demote is a presence-only `confirmed`.

Mutation test: reverting `_DEFAULT_ENFORCE`, and separately weakening the family rule to the CVE
signal alone, both leave the stale row `confirmed` — the targeted tests fail in both cases.

### Slice 3 — retest could not tell "patched" from "still there"
`_GET_ORACLE["vulnerable_component"] = "reachable"` asked *is a file still served here*. A patched
library is served from the same URL and returns the same non-empty 2xx, so **every fix came back
OPEN**. New `component_version` oracle re-FINGERPRINTS the replacement:

| replacement | verdict |
|---|---|
| body still declares the affected version | `open` |
| body declares a newer version still inside a known-vulnerable range | `open` |
| body declares a version outside every range | `closed` |
| non-2xx / empty | `closed` |
| body declares **no** version (only the unchanged filename) | `inconclusive` |
| finding predates the structured `component` fields | `inconclusive` |

Content beats filename, deliberately: `/assets/jquery-3.4.0.js` serving 3.6.0 is a fixed finding, and
an in-place patch never renames the file. Where only the path is left as evidence the honest answer
is `inconclusive` — a false OPEN is the remediation lie this slice exists to remove, and a false
CLOSED is the failure the module was written to avoid.

Mutation test: restoring `"reachable"` makes the patched replacement report `open` again.

### Slice 4 — SCA findings reach KEV, and the KEV table stops overstating them
The finding's CVE ids lived only in `title` and `description`. `report.py`'s KEV blob is built from
`cve` / `cves` / `evidence`, so the ids were invisible to it. Fixed at the PRODUCER: the finding now
emits `cves` as a structured list of exactly the ids whose ranges the version matched. The KEV
consumer's regex was deliberately **not** widened to scrape titles — that would make every prose
mention of a CVE a KEV candidate.

Honest note: slice 1 already rewrote the evidence string to name the matched CVEs, so the KEV
*match* was incidentally working before this slice. The structured field is still the right fix —
it survives any future rewording of the prose — and the test that failed first is the one asserting
the structure, not the rendering.

Second, smaller lie fixed in the same place: the KEV table's column header read `Confirmed finding`
and every row landed under it regardless of proof state. It now reads `Finding` + `Our proof state`,
filled from the shared `_confirmed()` helper and the new `component_status`, so a potentially-
affected lead cannot read as a confirmation just because its CVE is in the catalog.

Mutation test: drop `cves` and restore the pre-slice-1 presence-only evidence -> the SCA finding
misses KEV again.

### Slice 5 — one canonical oracle key (platform-wide, not an SCA bug)
Re-measured on this tree: **38** modules mention `success_oracle`, **87** sites write a plain
`"oracle"`. Both are alive, so neither was declared dead. The real defect is that the two CONSUMERS
disagreed with each other — `poc_bundle` read only `oracle`, `report_integrity_check` read only
`success_oracle`, so each was blind to exactly the families the other could see.

* canonical key: `proof_schema.ORACLE_KEY = "success_oracle"`.
* one reader: `proof_schema.oracle_of(finding)` — canonical spelling wins, legacy accepted.
* one chokepoint: `normalize_oracle()` applied inside `demote_unproven`, which is what
  `db.get_findings_gated` (the documented "anything that PRESENTS a finding reads through here"
  accessor) already routes every consumer through. Additive and non-destructive: the legacy key is
  left in place, so both producer spellings keep working.
* consumers fixed: `poc_bundle.py` (both sites) and `report.py:1702`, the latter via a local
  `_oracle_of()` that imports through proof_schema — same discipline as `_confirmed()`, so the
  vocabulary cannot fork a third time.

**Scope note, important for whoever picks this up next**: `oracle` is *also* a key on techniques,
candidate-validation records, retest plans and evidence dicts. Those are different objects with
their own meaning and were deliberately left alone. This slice is about FINDINGS only.

**Hand-off notes — readers in files this lane must not touch:**
- `agent/bie.py:601` writes `"oracle": finding.get("oracle") or ""` into the BIE evidence block. It
  should read `proof_schema.oracle_of(finding)`. One-line change, owned by the BIE lane.
- `agent/agent.py:792` reads `already.get("success_oracle")` only; `proof_schema.oracle_of` would
  also catch legacy-spelling producers. Owned by the funnel lane.
- `agent/blind_benchmark.py:266` and `agent/liveness.py:126` both read `success_oracle` only. Both
  already fall back to `evidence`, so neither is currently wrong — worth switching for consistency.

Mutation test: restrict `_ORACLE_ALIASES` to either spelling alone -> the normalisation returns
`None` and the PoC bundle's oracle goes empty again.

### Slice 6 — SARIF stops un-demoting the proof gate (closes the last export)
`707b3b9` / `5af0af8` fixed HTML, markdown, JSON and CSV. SARIF still emitted `level=error` and
`security-severity=9.5` for a demoted row, with the demotion buried in `properties.confidence` —
which GitHub code scanning and DefectDojo do not read. They route on `level` and
`security-severity`, so that is where the demotion now appears: a demoted row is capped at
`warning` / `5.0`, via the shared `proof_schema.is_confirmed()` rather than a fourth private copy of
"what counts as confirmed".

The cap can only ever LOWER a row (a demoted `low` stays `note`), and the original claim is kept as
`properties.claimed_severity` + `properties.proof_gap` so nothing is lost — it is preserved as data
instead of as an alarm level.

Mutation test: force `_proof_state` to `True` -> the demoted row exports as `error` / `9.5` again.

### Slice 7 — contradictory fingerprints of the same library (the stale-bundle-filename FP)
`/assets/jquery-3.4.0.js` that now SERVES 3.6.0 fingerprints **twice** — 3.6.0 from the body
(CONFIRMED) and 3.4.0 from the path (HIGH). Different `(name, version)` keys, so both survive the
caller's dedupe and the stale one raises a `vulnerable_component` finding for a library that was
already patched. New pure `dependency_intel.reconcile_components()` keeps the strongest evidence per
`(name, location)`.

Two deliberate limits, both with a negative control: reconciliation is per LOCATION (one page really
can ship two versions from two bundles), and two EQUALLY strong contradictory readings are both kept
— dropping the vulnerable one would be a false negative, dropping the patched one would be the FP.

**The no-island guard earned its keep here.** The first version of this slice left
`reconcile_components` uncalled and `test_deadcode_gate.py::test_the_ratchet_holds` failed
immediately (37 -> 38). Rather than raise the baseline, the function was wired into slice 3's retest
oracle, which had been hand-rolling the same "content beats filename" preference inline — so the
rule now lives in exactly one place and the ratchet is back at 37.

**Hand-off note — `agent/tools.py:5202` (engine lane).** Detection-time reconciliation is still
missing: that line builds `comps = dep.fingerprint_js_content(text, label) + dep.fingerprint_url(label)`
and the FP above is raised there. One-line patch:

```python
comps = dep.reconcile_components(dep.fingerprint_js_content(text, label) + dep.fingerprint_url(label))
```

Until it lands, the FP is caught at RETEST (the finding closes) but is still raised at detection.

---

## Rank 0 — the funnel (supersedes everything below)

### Q-019 · ANSWERED Q-010 · 2756 URLs discovered, 36 probed · **CRITICAL** · `ready` · **take this first**
Promoted out of `proposed` — this is the measured answer to Q-010 and it retires the standing belief
that surface discovery is the gap. Full ticket below under the Distillation pass. Three compounding
root causes: hostless `https:///benchmark/...` URLs that scope correctly refuses (34 `scope_block`
events, and they are exactly the category index pages linking to all 2740 cases); `sweep_targets`
admitting a URL only if it was FETCHED and carries `?`, making coverage O(pages fetched) not
O(surface discovered); and a `depth(2) × frontier(30)` = 60-visit cap standing alone between a
2756-URL surface and the engines. **Blocked on `tools.py` until the Builder releases it.**

#### Q-019 refinements — MEASURED by the Coordinator, 2026-08-10 (read before implementing)

1. **The crawl is CLEAN. The hostless URLs come from a different producer.** Ran the surface liveness
   check standalone against the same lab:
   `VERDICT: confirmed | surface grew to 2756 URL(s) (needed 8), all addressable` — **zero** hostless
   entries out of 2756. So `_surface_crawl` is not the producer of `https:///benchmark/...`; something
   on the mission path is (candidates: `crawl.parse_sitemap`/`parse_robots` with a hostless `at`, or
   the seeding path). **Do not "fix" `_surface_crawl` — it would be a null change against a green
   test.** Find the producer first; the `_add_urls` ingress guard in the ticket is still right because
   it names whoever it is.
2. **The hard cap is `limit=20`, not the frontier.** `agent.py:175` — `sweep_targets(urls, forms,
   in_scope, limit: int = 20)` — and `agent.py:2829` calls it **without passing `limit`**. The
   deterministic injection sweep therefore probes at most **20** endpoints against a 2756-URL surface.
   That single default explains the 36 distinct URLs better than the frontier cap does.
3. **Throughput, not just selection, is a ceiling.** The probe phase ran 50 s → 3720 s for 433
   `tool_call` events ≈ **8.5 s per tool call**, ≈ 12 calls per URL, ≈ **100 s per URL**. Even with a
   perfect funnel, 2740 cases at 100 s/URL is ~76 hours. **So "raise the cap" is not by itself the
   fix, and anyone who raises it and declares victory will have built a mission that never finishes.**
   Q-019 must ship with a budget-aware selection (representative-per-signature under an explicit
   time/count budget) and a separate ticket for probe concurrency. Add both numbers — URLs probed and
   wall-clock — to the acceptance oracle, not just findings.
4. Root cause #2 stands and is the deepest one: a discovered URL that was never FETCHED can never
   become a target, because `sweep_targets` keeps a URL only when `"?" in u` or a captured form names
   it, and forms only exist for fetched pages. The 2740 cases are plain `.html`. Coverage is
   O(pages fetched) = 12, and everything downstream is arithmetic on that 12.

### Q-010 · Why does a whole-product mission find 2 things on a 1415-vuln target? — **ANSWERED by Q-019**
**MEASURED**: mission `90cee81c`, 3720s, 2 findings, neither a benchmark case, count static from
t=50s. Harness on the same target: 41.3%. Five orchestration fixes did not move it.
**This is not a new-engine problem and no new engine should outrank it.** The instruction is to
measure the funnel stage by stage — URLs discovered → URLs parameterized → probes selected → oracles
fired — and find the stage where the count collapses, rather than fixing a sixth suspected defect
blind. Assigned to the Watcher (research line 2). Any ticket claiming to fix this must state which
funnel stage it repairs and show the before/after count for that stage.

---

## Rank 1 — ready

### Q-001 · Session lifecycle invalidation (CWE-613) — WSTG-SESS-06/07/11
- **Root cause**: no engine exists, and logout is *actively avoided*. `tools.py:3074` refuses to
  admit a session-killing endpoint to the surface; `:3673-3696` passes `no_logout` to every katana
  crawl. The platform blinded itself to the one endpoint this class needs.
- **Oracle**: mint a sacrificial persona (`register.py`), capture cookie C, confirm C reaches an
  authed marker, POST logout, replay C. Confirmed iff the replay still returns the authed marker.
- **Negative control**: a freshly invented cookie must be rejected by the same endpoint (proves the
  marker is not served anonymously).
- **Non-destructive**: yes — only touches a session Apolaki itself created.
- **Files**: `agent/tools.py`, `agent/personas.py`, `agent/register.py`, `agent/techniques.py`,
  `agent/engine_descriptor.py`
- **Definition of done**: engine live in a real mission, liveness check added, secure-control lab
  proves no FP, WSTG entries move off `none`.
- **Effort**: lowest of the six. Every primitive exists; the work is a mission-safety carve-out so
  the sacrificial logout cannot kill the live scan session.

### Q-002 · WebSocket security: CSWSH (CWE-1385/346) + WS-frame injection
- **Root cause**: zero coverage. `Sec-WebSocket|websocket` appears only in a report string and the
  WSTG catalog title. WSTG-CLNT-10 is `none`.
- **Oracle**: HTTP/1.1 Upgrade carrying the persona's session cookie **plus** an attacker `Origin`.
  Confirmed iff (a) `101` with a valid `Sec-WebSocket-Accept` derived from our key **and** (b) the
  first server-pushed frame carries the same authenticated marker the HTTP session already proved.
- **Negative control**: identical handshake, cookie stripped, must fail or carry no authed data.
- **Non-destructive**: yes — read-only handshake plus one inbound frame.
- **Files**: new `agent/ws_tool.py`, wired in `agent/tools.py` (seed: `asyncio.open_connection` at
  `tools.py:2770`), `techniques.py`, `engine_descriptor.py`
- **Effort**: moderate-low. Frame injection then reuses the unchanged sqli/xss analyzers over a
  different transport.

### Q-003 · `postMessage` as a DOM-XSS source (CWE-346 → CWE-79) — WSTG-CLNT-11
- **Root cause**: `dom_tool.py` confirms canaries in real Chromium but its only sources are
  `location.hash` and query params (`dom_tool.py:134-136`). `postMessage|MessageEvent|onmessage`
  appears nowhere in `agent/`.
- **Oracle**: enumerate `message` listeners over CDP, load in a controlled parent frame,
  `postMessage` a unique canary, assert it reaches a dangerous sink and **executes** — the same
  browser-confirmed proof `dom_tool.py:250` already emits.
- **Negative control**: same canary with a mismatched `targetOrigin` must not fire.
- **Non-destructive**: yes.
- **Files**: `agent/dom_tool.py`, `agent/cdp.py`
- **Effort**: low-medium. Adding a **source** to a working confirmation engine, not a new engine.

### Q-004 · Unrestricted resource consumption (CWE-770/799) — API4:2023, WSTG-BUSL-05/07
- **Root cause**: a whole OWASP API Top 10 slot with no engine. The only `429` in the codebase is
  Apolaki respecting someone else's limit (`tools.py:3296`).
- **Oracle (preferred, zero volume)**: amplification multiplier — `limit=1` vs `limit=100000` on a
  paginated endpoint; assert row count and byte size scale linearly with the attacker-supplied
  bound. A measured ratio, not a heuristic. Secondary: N bounded idempotent requests, confirmed iff
  all N are 2xx and no `429`/`Retry-After`/`X-RateLimit-*` ever appears.
- **Negative control**: an endpoint on the same host that *does* limit, or an explicit
  "no limiter anywhere on this host" verdict.
- **Non-destructive**: yes when scoped to idempotent reads with a hard cap. Does not collide with
  the no-brute rule — nothing iterates credentials.
- **Files**: `agent/race_tool.py` (already has the synchronized-parallel primitive + status
  accounting), `agent/api_inventory.py`, `agent/tools.py`
- **Effort**: low-medium; the multiplier variant needs no concurrency at all.

### Q-021 · Technology Intelligence Engine — detected tech must drive targeted testing · **HIGH** · `ready`
*Erwin, 2026-08-10. An overlooked capability: recon fingerprints a technology and then nothing
happens to it. Detection must feed vulnerability intelligence, which must feed targeted probes.*

**This is an INTEGRATION ticket, not a new scanner.** Four of the five pieces already exist and are
disconnected. Building a fresh `tech_intel.py` beside them would be island #89 and is rejected in
advance. What exists, measured:

| piece | file | what it does today | gap |
|---|---|---|---|
| fingerprinting | `agent/fingerprint.py` (138 lines) | headers, `Set-Cookie`, `<meta generator>`, "powered by", JS-lib and body signatures → a flat tech list | shallow; no CMS plugins/themes, no evidence record, no persistence, no confidence |
| version confidence | `agent/dependency_intel.py` (266 lines) | **already has the ladder**: `CONFIRMED` (version proven from served content) / `HIGH` (from filename or CDN path) / `LOW` (heuristic), and `CVE_ELIGIBLE = {CONFIRMED, HIGH}` — LOW is **never** CVE-eligible | JS libraries only; no CMS, server, framework or plugin ecosystem |
| feeds | `agent/intel_feeds.py` (406 lines) | KEV, CAPEC, ATT&CK, ExploitDB snapshots; `exploits_for_finding()` | **no NVD/CPE, no OSV, no GHSA, no WPScan** |
| state ladder | `agent/intel_registry.py` | `candidate → validating → validated → fixture_backed → production` with confidence weights | not applied to technology facts |
| the missing piece | — | — | **nothing turns an advisory match into a scheduled probe** |

`dependency_intel.CVE_ELIGIBLE` is already the enforcement point for the proof rule below. Extend it;
do not reinvent it.

**TechnologyFact** (new, persisted, deduped across detectors): vendor · product · component/plugin ·
observed version · version confidence · detection evidence · source URL/request · authentication
state · first_seen · last_seen.

**Detect**: CMS platforms · plugins, themes, extensions · frameworks and libraries · web servers and
reverse proxies · hosting platforms and site builders · API gateways · auth products · JS packages ·
third-party services · exposed admin products. (WordPress core/plugins/themes, Drupal modules, Joomla
extensions, Magento extensions, Apache, nginx, IIS, PHP, Laravel, Rails, Django, Next.js, …)

**Enrich**: WPScan (WordPress core/plugins/themes) · NVD/CPE for general products · OSV for
open-source packages and precise version ranges · GitHub Security Advisories · CISA KEV for
exploitation priority (already loaded) · vendor advisories as authoritative confirmation.

**Orchestration — recon cycle 1**: fingerprint from headers, cookies, HTML, scripts, assets, routes,
generator metadata, error pages, **browser/CDP telemetry, ZAP**, and the existing detectors → record
evidence and confidence → query intelligence → emit **candidates, never findings** → into the
canonical graph and planner.
**Recon cycle 2**: revisit endpoints and authenticated states that expose hidden components or better
version evidence → inspect JS bundles, source maps, manifests, lockfiles, changelogs, readmes, asset
paths, API responses, plugin-specific routes (in scope only) → resolve ambiguous identities and
version ranges → trigger technology-specific **safe** probes through the planner → **recrawl** when a
discovered component introduces new routes, APIs, states or surface.

**PROOF RULE — detection or a database match is NEVER a confirmed vulnerability.** State ladder:
`DETECTED_TECHNOLOGY → VERSION_SUSPECTED → ADVISORY_MATCHED → APPLICABILITY_CONFIRMED →
SAFELY_PROBED → ORACLE_CONFIRMED`. **Version unknown ⇒ `POTENTIALLY_AFFECTED`, never proven.**
A confirmed finding still requires: reliable component identity · affected-version match or
configuration applicability · a deterministic oracle · a negative control · evidence and replay ·
false-positive-safe reporting. *A hosting platform being detected creates a lead. Only an authorized
deterministic test proves a vulnerability.* This is the same rule `proof_schema.demote_unproven`
already enforces — route technology candidates through it rather than around it.

**Planner priority**: detection confidence · version confidence · CVSS and technical impact · KEV
status · exploit prerequisites · authentication requirements · reachability · whether a deterministic
oracle exists at all · scope and safety · expected information gain.
**Anti-spam (hard requirement)**: hundreds of theoretical CVEs against an unknown version must never
flood the queue or the report. An unknown version yields at most one `POTENTIALLY_AFFECTED` row per
product, not one per CVE.

**Engine requirements**: dedupe identities across detectors · map aliases safely (`dependency_intel`
already has `_FLEX_ALIAS`/`_CDN_NAME_FIX`) · understand version ranges · record database source and
update time · handle conflicting advisories · cache feeds with provenance · **re-evaluate existing
facts when feeds update** · route actionable candidates into the planner · keep unproven matches out
of confirmed reports · show technology, version confidence, advisory match, proof status and evidence
in the UI.

**Breaker must attack**: false matches · spoofed banners · **backported patches** (Debian/RHEL ship a
patched 1.2.3 that every version-range check calls vulnerable — this is the single largest FP source
in the whole class) · ambiguous versions · duplicate CVEs across feeds · stale advisories.

**Negative controls**: (a) a target running a **patched** version of a detected product yields zero
advisory matches; (b) a product detected with `LOW` version confidence produces
`POTENTIALLY_AFFECTED` and **zero** confirmed findings, no matter how many CVEs the feed returns;
(c) a spoofed `Server:` banner claiming an ancient version, with the real behaviour of a current one,
must not confirm.

**Acceptance gate**: Apolaki detects a component, produces evidence for its identity *and* version
confidence, maps only applicable advisories, schedules an authorized targeted probe, confirms or
rejects deterministically, and never reports a database match alone as proven.

**Files**: `agent/fingerprint.py`, `agent/dependency_intel.py`, `agent/intel_feeds.py`,
`agent/intel_registry.py`, `agent/technique_planner.py`, `agent/engine_descriptor.py`, the graph and
the UI coverage view.
**Dependencies**: sequence **after Q-019** — a technology fact is worthless if the crawl only reaches
36 URLs, and cycle-2 recrawl depends on the same `_surface_crawl` path Q-019 repairs.
**Role split**: Watcher identifies trustworthy ecosystem databases (licence, update cadence,
machine-readable format, provenance) · Analyst rejects low-quality or unmaintained feeds · Coordinator
splits this into dependency-ordered sub-tickets (it is too large for one commit) · Builder integrates
into recon and the canonical graph · Breaker attacks the FP list above · Conductor verifies
fingerprinting → enrichment → planning → probing → evidence → UI → reporting is ONE pipeline.

## Rank 2 — ready, gated

### Q-005 · Server-side prototype pollution (CWE-1321)
- **Root cause**: `dom_tool.py:283-351` runs real gadget probes but every one is browser-side.
- **Oracle**: behaviour-change, byte-observable — `{"__proto__":{"json spaces":10}}` then confirm the
  **next** response's JSON is indented against a pre-pollution baseline; or
  `{"__proto__":{"status":510}}` and confirm the status changes.
- **Negative control**: the same payload via `constructor.prototype` (defeats naive `__proto__`
  string filters) plus a clean re-request proving the effect **persists** — distinguishes pollution
  from reflection.
- **Non-destructive**: **NO.** It mutates the server's `Object.prototype` for every subsequent
  request until restart. Cross-user blast radius.
- **Decision**: ship gated as `execution: "operator"` (`techniques.py` already supports the field).
- **Effort**: medium. Pure request/response.

### Q-006 · HTTP request smuggling / desync (CWE-444) — detection tiers only
- **Status**: currently a *deliberate* exclusion, not an oversight — `wstg_catalog.py:137` refuses
  WSTG-INPV-15 under the no-collateral rule. That call stands for Tier 3.
- **Tier 1 (safe)**: prove a front-end/back-end pair exists via hop-count and header-mutation
  differentials. Zero risk.
- **Tier 2 (safe-ish)**: CL.TE-shaped timing differential on our own socket with `Connection: close`
  — a repeatable multi-second delta against a control differing only in the framing header, with a
  zero-delta control.
- **Tier 3 (forbidden)**: queue poisoning captures a stranger's request. Not built.
- **Honest product answer**: a **detection** capability with a hard stop before confirmation,
  `execution: "operator"`, reported high-confidence but never "confirmed".
- **Effort**: highest of the six — needs a hand-rolled HTTP/1.1 socket client (`httpx` cannot emit a
  malformed frame). `httpx[http2]` is already a dependency for the H2-downgrade variants.

## Rank 3 — defects, ready

### Q-007 · `weak_password_reset` is a phantom capability
`techniques.py:49` and `:1250` self-admit there is **no production executor**; what fired on the labs
was the lab *solver*. `engine_descriptor.py:74,179` still declares its preconditions and effects, so
**the planner believes it is real**. Either build it for real (CWE-640 reset-token reuse /
non-expiry / predictability — `agent/prng_disclosure.py` already analyses token entropy and could be
pointed straight at a reset token) or strip the descriptor. Do not leave the planner lied to.

### Q-008 · `run_mass_assignment` referenced but does not exist
`asvs_model.py:103` names an engine absent from the `tools.py` name table. A wiring defect, not a
capability gap. Verify, then fix the reference or build the engine.

### Q-009 · Audit findings pending verification (do not act before checking)
Retest scope guard fail-open (`main.py:2578-2602`) · `PUT /findings` bypassing `findings_gate` ·
operator lead-confirmation producing an immediately-demoted finding · `get_logs` oldest-first ·
`risk_signals` unfiltered twin · `_read_controls` returning `[]` on evaluate failure.

## Rank 4 — open programme work (existing task list)

`#54` silent-failure architecture (mechanism shipped, propagation open) · `#50` Codex batch 2
(2 of 9 left: `waf_bypass` decision, `weak_session_token` carriers) · `#53` Python benchmark
(wired, 34.8%) · `#44` vulnweb · `#42` crAPI · `#45` WAVSEP · `#30` dead-code triage ·
`#52` `validated_on` enforcement · `#35` NotebookLM · `#49` research files.

---

## Distillation verification pass — 2026-08-10 (Analyst)

Q-007 / Q-008 / Q-009 were **assertions from an audit**. Every one is now settled MEASURED or
DISPROVED against the live code, the running platform (`apolaki-agent-1`) and all 151 stored missions.
Verdicts are evidence, not state — the Coordinator still owns state.

| claim | verdict |
|---|---|
| Q-007 `weak_password_reset` has no production executor | **MEASURED — true** |
| Q-008 `run_mass_assignment` absent from the name table | **MEASURED — true, and 5 more names with it** |
| Q-009 retest scope guard fails open | **DISPROVED in practice** — guard active on 151/151 missions |
| Q-009 `PUT /findings` bypasses `findings_gate` | **MEASURED — true, all three invariants, live** |
| Q-009 lead-confirmation is immediately demoted | **MEASURED — true**, plus a second defect beside it |
| Q-009 `get_logs` oldest-first | **MEASURED — true; the stated 4000-cap consequence DISPROVED** |
| Q-009 `risk_signals` unfiltered twin | **MEASURED — true** |
| Q-009 `_read_controls` returns `[]` on failure | **MEASURED — true** |

**Q-007 recommendation: STRIP, do not build.** Reasons, in order of weight.
1. Orchestration is the measured bottleneck this cycle (see Q-019). A new CWE-640 engine is the
   lowest-value thing that could be added.
2. `weak_password_reset` is the **only** `invalidates` entry in the whole `EFFECTS` table, so it is the
   sole source of every row `conflicts()` returns — the entire Sussman-anomaly demonstration rests on
   an engine that does not exist. That is worse than having no negative-effects model.
3. The honest move keeps the model: drop it from `PRECONDITIONS` and `EFFECTS`, set
   `solver_only=True` (the field exists; `technique_status()` already returns `solver_only` for it),
   and **re-home `invalidates: ["authenticated"]` onto Q-001's session-lifecycle engine**, which
   really does destroy a session. Q-001 is Rank-1 ready, so the negative-effects half of T6 survives
   on a technique with a real executor. Dependency: Q-001.

**Q-008 direction: it UNDER-reports ASVS and OVER-reports WSTG — the same missing engine, both ways.**
`_engine_ran()` returns False for an unresolvable name, so status falls to `not_tested`, which is
strictly conservative — an unresolvable name can never manufacture a "verified". But `violated_by` is
independent of `engine`, so a real finding still fails the objective. Net: ASVS under-reports.
Meanwhile `wstg_catalog.FULL["WSTG-INPV-20"] = "mass_assignment (authz)"` claims **full** coverage for
the same non-existent engine, and that entry is inside the published `full_pct: 52.3`.

---

## Rank 3b — proposed (Distillation, 2026-08-10). All `proposed`; Coordinator ranks.

**Ranking rationale, stated because the assignment demanded it.** Mission `90cee81c` ran 3720s against
1415 known-vulnerable cases and returned 2 findings, while the same target scores 41.3% when engines
are handed case URLs directly. I measured where the mission actually loses the target (Q-019) and it is
neither the engines nor — contrary to the standing belief — the crawler. **Every ticket below is
wiring, orchestration or reporting-integrity. None is a new engine. Q-019 should outrank Q-001…Q-006.**

### Q-019 · The mission discovers 2756 URLs and probes 36 of them · **CRITICAL** · `proposed`
- **MEASURED**, mission `90cee81c` (908 log rows, replayed from the persisted event log):
  ```
  Surface crawl: probed 12 page(s), surface 5 -> 2756 URL(s)
  tool_call events            : 433        scope_block events : 34
  DISTINCT URLs any tool_call aimed at : 66
  DISTINCT URLs http_probe/http_read touched : 36
  run_xss 45 · run_xpath 32 · run_ldap 32 · run_ssi 32 · run_sqli 20 · run_sqli_structural 20
  findings: 2  (jquery CVE + a credential in a comment — both from JS recon on the index page)
  ```
- **This retires the standing belief that surface discovery is the gap.** S11b/S11c/S11d are genuinely
  fixed: the crawl found all 2740 test cases plus the indexes. The surface is 2756. The scan probed 36.
- **Three compounding root causes, each independently measured:**
  1. **Hostless URLs poison the surface.** 10 of the 36 probed URLs are
     `https:///benchmark/cmdi-Index.html` — scheme `https`, **empty netloc**. Measured:
     `urljoin("https://", "/benchmark/x.html") == "https:///benchmark/x.html"`, and
     `ScopeEngine.validate()` correctly answers `(False, 'Invalid target')`. So the crawl aimed at the
     category index pages — *the exact pages that link to all 2740 test cases* — with a broken URL and
     scope refused every one. That is the 34 `scope_block` events. `crawl.parse_sitemap` reproduces the
     same shape when its `at` argument is hostless. **The scope engine is behaving correctly; the
     producer is handing it garbage, and nothing names the producer.**
  2. **A URL only becomes an injection target if it was FETCHED.** `agent.sweep_targets` keeps a URL
     only when `"?" in u`, plus pages carrying a captured form. The 2740 discovered links are plain
     `.html` with no query, so a discovered-but-never-fetched URL can never reach an engine. Coverage
     is therefore O(pages fetched), not O(surface discovered).
  3. **`_surface_crawl` is capped at `depth(2) x frontier(30)` = 60 visits** against a 2756-URL
     surface, and only 12 survived (1). The cap is defensible per-round; being the *only* gate between
     a 2756-URL surface and the engines is not.
- **Producer/consumer contract**: producer = `_surface_crawl` / `_http_probe` / `crawl.parse_*`
  writing into `tools._add_urls`; consumer = `sweep_targets` and the probe phase. The contract that
  does not exist today: *a URL admitted to the surface has a host, and a URL on the surface is a
  candidate target whether or not it was fetched.*
- **Oracle (deterministic)**: re-run the same mission against `owaspbench`; assert
  (a) **zero** surface URLs with an empty `urlparse(u).netloc`, (b) `scope_block` count drops to 0 for
  hostless causes, (c) distinct URLs reaching `http_probe` rises above 200, (d) findings > 2.
- **Negative control**: a mission against a **single-page** in-scope target must NOT gain targets —
  proves the change widens reach from real discovery and does not invent URLs. Plus: a genuinely
  out-of-scope host must still be `scope_block`ed, proving (1)'s fix did not weaken the scope gate.
- **Tests / mutations**: unit — `_add_urls` rejects `https:///x` and records it via `_swallow` naming
  the producer; mutation — reintroduce the hostless URL and the assertion must fail. Whole-product —
  the missing test named in `CODEBASE_REVIEW` S11b: engage against a standing lab, assert findings > 0
  **and** assert `probed >= N`, because findings > 0 already passes today on 2 incidental findings.
- **Files**: `agent/agent.py` (`_surface_crawl`, `sweep_targets`), `agent/crawl.py`, `agent/tools.py`
  (`_add_urls` ingress guard). Overlaps `tools.py`, owned elsewhere this cycle — sequence after it.
- **Dependencies**: none. **Definition of done**: the four oracle assertions above, both negative
  controls, and the whole-product smoke test in the suite.

### Q-020 · Technique records declare no executor, so the no-island guard checks a declaration · **HIGH** · `proposed`
- **Root cause, and it is the parent of Q-007, Q-008 and Q-011.** MEASURED: `techniques._t()` has no
  `engine` field — `_REQUIRED` is `(id, vuln_class, cwe, owasp, permission, summary, detect, exploit,
  oracle, transferable)` and none of the `setdefault`s adds one. Nothing anywhere maps a technique to
  the tool that runs it. So `orchestration_audit()` can only ask *"is this id present in
  `PRECONDITIONS` or `ALWAYS_ON`?"* — a declaration — and answers `islands: []` for 41 gated + 45
  always-on techniques including two proven phantoms.
- **The asymmetry is already half-fixed and nobody noticed.** `engine_descriptor.verify_always_on()`
  exists precisely to check the FACT behind the declaration, and MEASURED it iterates
  `sorted(ALWAYS_ON.items())` only: `checked: 45, unwired: [], ok: True`. It fact-checks 45 of 86
  techniques and **0 of the 41 evidence-gated ones**. Every phantom found so far is on the unchecked
  side. This is the recorded "guards that check declarations, not facts" failure mode, one branch deep.
- **Honest scoping — I am not accusing 39 techniques.** A name heuristic flags 33 gated techniques with
  no `run_<id>` engine, but the heuristic is wrong: `sqli_auth_bypass` -> `run_auth_sqli`,
  `idor_bola_read` -> `confirm_idor`, `xxe_file_ssrf` -> `run_xxe` all have real engines under other
  names. Exactly **2** are MEASURED phantoms (Q-007, Q-011). The other 31 are **UNDETERMINED**, and
  making them determinable is the whole point of this ticket.
- **Producer/consumer contract**: producer = the technique record gains `engine: <tool name | tuple>`;
  consumer = `orchestration_audit` and a new `verify_gated()` mirroring `verify_always_on`, plus
  `asvs_model` and `wstg_catalog` which can then resolve against ONE table instead of hand-copied
  strings (Q-011).
- **Oracle**: for every auto + oracle + transferable technique, its declared `engine` resolves to a
  name in `TOOL_PERMISSIONS` or `CLAUDE_TOOLS` **and** to a real `_<name>` method. Fails today on
  `weak_password_reset` and `mass_assignment`; must be green after Q-007 and Q-011 land.
- **Negative control, mandatory — this is the exact bug being fixed**: a **non-vacuity** assertion
  (the scan must have checked > 0 techniques; a scan over an empty set passes for free) **and** a
  mutation that points one technique's `engine` at `run_does_not_exist` and requires the guard to fail.
  `tests/test_engine_reachability.py` already carries the non-vacuity pattern — reuse it.
- **Files**: `agent/techniques.py`, `agent/engine_descriptor.py`, `agent/technique_planner.py`,
  `agent/tests/test_engine_reachability.py`. **Blocks**: Q-007, Q-011, Q-012.

### Q-011 · `mass_assignment` is the SECOND phantom — same shape, same backfill · **HIGH** · `proposed`
- **MEASURED**: no mass-assignment executor exists anywhere. `def .*assign` in `tools.py` -> nothing;
  the only code that ever over-posts a privileged attribute is `juiceshop_solvers.py:67`
  (`_register(c, ..., role="admin")  # Admin Registration`) — the **lab solver**, exactly as with
  `weak_password_reset`. And `_JUICESHOP_PROVEN["mass_assignment"] = ["Admin Registration"]` backfills
  the solver's behaviour onto the technique, again exactly as with `weak_password_reset`.
- Meanwhile it is declared live in three places: `engine_descriptor.PRECONDITIONS` (`has_api`),
  `asvs_model` ATHZ-04 (`run_mass_assignment`), and `wstg_catalog.FULL["WSTG-INPV-20"]`.
- **This reverses a standing QUEUE rejection.** The `rejected` list says "mass assignment as a
  *technique*" is already covered. Measured: the technique record is covered; the capability is not.
- **Decision, consistent with Q-007**: this one is worth BUILDING rather than stripping — unlike
  `weak_password_reset` it needs no email/reset flow, the oracle is clean, and it is a whole OWASP
  API-Top-10-adjacent property that currently reads as covered in two published catalogs.
- **Oracle (deterministic, byte-observable)**: create or update an object with an extra privileged
  attribute (`role`/`isAdmin`/`deluxeToken`), then **read the object back** and assert the injected
  attribute persisted with the injected value. Persistence on readback, not a 200.
- **Negative control**: the identical write with a **nonsense** attribute name (`apolaki_marker_xyz`)
  must NOT appear on readback — proves the server is not simply echoing every field, which is the
  single false positive this class produces. Second control: the same readback before the write.
- **Non-destructive**: NO — it writes. Ship on a self-created object only (`register.py` /
  `create_object_idor.py` already mint sacrificial objects), never on a discovered third-party object.
- **Files**: new `agent/mass_assignment_tool.py`, wired in `agent/tools.py` as `run_mass_assignment`
  (the name both catalogs already expect), `techniques.py`, `engine_descriptor.py`.
- **Dependencies**: Q-020 for the `engine` field. **Definition of done**: engine live in a real
  mission, liveness check added, ATHZ-04 reaches `verified` on a clean paired lab, WSTG-INPV-20's
  `FULL` claim becomes true rather than aspirational.

### Q-012 · Six ASVS engine names resolve to nothing; two objectives can never be verified · **MEDIUM** · `proposed`
- **MEASURED** (cross-check of `asvs_model.OBJECTIVES` against `tools.TOOL_PERMISSIONS` (111 keys) +
  `CLAUDE_TOOLS` (77 names) + 201 methods):
  ```
  UNRESOLVABLE: ['authz_matrix', 'bizlogic_graph', 'dependency_intel',
                 'header_analysis', 'run_deser', 'run_mass_assignment']
  assess(findings=[], attempted_engines=EVERY registered tool name)
    tally  {'verified': 27, 'attempted': 1, 'failed': 0, 'not_tested': 3, 'blocked': 2}
    still not_tested with a PERFECT run: ['AUTHN-04', 'ATHZ-04', 'BUSL-01']
  ```
- `authz_matrix` is the instructive one and it is why this needed measuring twice: the engine **is**
  real and **is** dispatched — as `run_authz_matrix` (`TOOL_PERMISSIONS:168`, `agent.py:1863`). It
  returns `ToolResult("authz_matrix", ...)` at `tools.py:1831,1998`, but the ledger records the
  *dispatch* name, not the ToolResult name, so the ASVS spelling never matches. A pure name drift.
- **Net effect**: ATHZ-04 (mass assignment) and BUSL-01 (business logic) are permanently
  `not_tested` — a hard **6.1-point** ceiling (2/33) on `verified_pct`, in the conservative direction.
  AUTHN-04 is `verifiable: False` so its unresolvable name is harmless.
- **The over-report half**: `wstg_catalog.FULL["WSTG-INPV-20"] = "mass_assignment (authz)"` claims
  **full** coverage for the engine that does not exist, inside the published `full_pct: 52.3`.
  Also `FULL["WSTG-IDNT-02"] = "create_account / registration engine"` — `create_account` resolves to
  no registered tool either (`register.py` exists; confirm the live name before touching this one).
- **Oracle**: a test asserting every non-`n/a` `engine` name in `asvs_model.OBJECTIVES` and every
  `run_*`/`confirm_*`/`check_*` token in `wstg_catalog.FULL` resolves against the ONE table Q-020
  introduces. Green only after the six names are corrected.
- **Negative control**: the same test must FAIL when a deliberately bogus name is injected — and a
  non-vacuity assertion, because the WSTG half of this check silently scanned 0 tokens on my first
  attempt (I pointed it at `CATALOG` instead of `FULL` and it reported a clean "none" over an empty
  set — the exact vacuous pass this control exists to catch).
- **Files**: `agent/asvs_model.py`, `agent/wstg_catalog.py`, `agent/tests/test_asvs_model.py`.
  Note `tests/test_asvs_model.py:78` already puts `run_mass_assignment` in a `ran` set — a test
  asserting behaviour for a name that can never appear in a real ledger.
- **Dependencies**: Q-020 (the table), Q-011 (so ATHZ-04/WSTG-INPV-20 become true rather than deleted).

### Q-013 · `PUT /findings` bypasses all three `findings_gate` invariants · **HIGH** · `CLOSED` 3addb1c + 42e1544
**Closed in two passes, and pass one was not enough.** `3addb1c` routed `db.update_finding` through
`db._gate`, which is the right chokepoint and covers `agent._triage` and `capture_finding_poc` too.
Then the gate lane asked whether the three invariants actually protect the proof, and measured that
**none of them reads `evidence`** — the field `validate_confirmed` judges. Post-`3addb1c`, a PUT that
put a gate-demoted row back with fabricated prose still returned `is_confirmed: True` with no engine
having issued a single request. `42e1544` made PUT annotation-only against a **whitelist** — a
blacklist leaves every future proof field editable, which is exactly how this survived pass one — and
closed the DELETE+POST route a PUT-only fix would have left open.


- **Root cause**: `db.add_finding` is documented as "the single write chokepoint" and enforces
  schema/scope/truth. `db.update_finding` (`db.py:222`) issues a raw
  `UPDATE findings SET data=?` and calls none of it. `PUT /findings/{sid}/{fid}` (`main.py:3118`)
  and `POST /findings/{sid}/{fid}/poc` both go through it.
- **MEASURED live** against the running platform on a throwaway mission scoped to
  `http://apolaki-testbox:80` (mission deleted afterwards). Each row is a paired test:

  | invariant | POST — gate runs | PUT — gate skipped |
  |---|---|---|
  | SCHEMA #6 | `"1) do a 2) do b"` -> `["do a","do b"]` | persisted as the raw string |
  | SCOPE #8 | off-scope target -> `{"id":""}`, refused | `http://evil.example.com/off-scope` persisted |
  | TRUTH #7 | `confidence:"lead"` -> routed to the leads list | lead-confidence row sits in the findings table |

  The POST column IS the negative control: all three invariants demonstrably fire on the sibling path,
  so the PUT failures are the gate being absent, not the gate being wrong.
- **Composed impact**: severity was also escalated `high -> critical` and `finding_counts()` is
  ungated, so the mission-list badge moves. An off-scope row written this way then reaches `/retest`,
  which is only stopped by the scope guard Q-018 shows is one exception away from being disabled.
- **Fix contract**: route `update_finding` through `findings_gate.normalize` + `off_scope` + `is_lead`,
  or give it an explicit `gated=True` default with the raw path renamed so a bypass must be deliberate.
- **Oracle**: the table above, as three assertions, replayed against the API.
- **Negative control**: the POST column must stay green — proving the change did not just delete the
  distinction. Plus a legitimate PUT (valid list, in-scope target, `confidence: confirmed`) must still
  succeed unchanged.
- **Files**: `agent/db.py`, `agent/main.py` (owned elsewhere this cycle — sequence it).

### Q-014 · Operator lead-confirmation is silently re-demoted, and gate-routed leads cannot be confirmed at all · **HIGH** · `CLOSED` a1cdb8d + report rendering
**The design answer, which is the durable part:** operator confirmation is an **attestation on its own
axis** — who, when, why — and never a value of `confidence`. The tempting fix was to let an operator's
own text satisfy `validate_confirmed`; the lane rejected it because that contract is a **substring
match over prose**, so it would award `confirmed` for vocabulary and teach people which words to type.
A lead is released to confirmed only when the lead's own engine-produced evidence satisfies the
oracle. What this costs, plainly: manual findings now land under Unconfirmed Leads, confirmed counts
drop, and `risk_score` no longer takes severity from them.


Two defects in the same handler. The second is not in the Q-009 list; I found it while proving the first.
- **(a) The confirmation is discarded.** MEASURED, replaying the exact dict `main.py:confirm_lead`
  builds from a realistic IDOR lead:
  ```
  operator clicked CONFIRM. stored confidence = confirmed
  proof_schema.validate_confirmed -> False ['impact', 'evidence_signal:owner', 'evidence_signal:denied']
  after db.get_findings_gated  -> confidence = lead
                                  tags = ['operator-confirmed','needs-confirmation','proof-incomplete']
  ```
  `confirm_lead` never builds an `impact` field, and never requires the lead's `evidence` to carry the
  family's proof signals — so for any family in `proof_schema._DEFAULT_ENFORCE`
  (`idor`, `access_control`, `missing_authentication`, `bola_idor`, `bfla`) the endpoint returns
  `{"ok": true, "finding_id": ...}` and the report shows a lead. The human said "I proved this" and the
  platform silently disagreed. **Negative control, run**: the same finding with `family="xss"`
  (not enforced by default) survives as `confirmed` — so the mechanism is the family gate, not a
  universal reject.
- **(b) Leads created by `db.add_lead` are unaddressable.** MEASURED live: `db.add_lead` stamps
  `lead["id"]`; `confirm_lead`/`dismiss_lead` match on `lead["_lid"]`, which only `main.py:2169` sets.
  `POST /leads/{sid}/nc-lead/confirm` -> **HTTP 404**, and `GET /leads/{sid}` still lists it. Every
  lead that reached the list via the `findings_gate` TRUTH-#7 routing path — i.e. every engine-produced
  lead-confidence finding — is permanently stuck: 404 on confirm, 404 on dismiss.
- **Fix contract**: (a) `confirm_lead` must either collect the operator's `impact` + evidence and
  re-validate before writing, or write `confidence: "operator_confirmed"` as a first-class value the
  proof gate honours — the operator IS the proof for a lead. Decide explicitly; do not paper over it.
  (b) match on `_lid` **or** `id`, and make `add_lead` stamp both.
- **Oracle**: (a) confirm an `idor` lead; `get_findings_gated` must return it confirmed. (b) confirm a
  lead created by `db.add_lead`; must return 200 and remove it from `GET /leads`.
- **Negative control**: (a) a lead confirmed with **no** operator evidence must still be demoted —
  otherwise the fix has deleted the proof gate rather than taught it about operators. (b) confirming a
  `lid` that exists in no mission must still 404.
- **Files**: `agent/main.py`, `agent/db.py`, `agent/proof_schema.py` (all owned elsewhere — sequence).

### Q-015 · `risk_signals` is the unfiltered twin of `risk_score` · **MEDIUM** · `proposed`
- **Root cause**: `report.risk_score` was fixed to filter demoted rows ("THE FILTER IS THE CONTRACT,
  and it was missing"). `report.risk_signals` computes the same quantity 40 lines later and did not
  get the filter: `conf_load = min(100, sum(_SEV_WEIGHT... for f in findings))` — no confidence test —
  and stamps `basis: f"{len(findings)} confirmed finding(s)"`, labelling demoted rows as confirmed.
- **MEASURED**, one gated list, both functions:
  ```
  risk_score(gated)       -> {'score': 0, 'label': 'No Confirmed Risk'}
  risk_signals(gated)[0]  -> {'label': 'Confirmed vulnerability load', 'pct': 25,
                              'basis': '1 confirmed finding(s), severity-weighted'}
  ```
  The same report contradicts itself: headline "No Confirmed Risk", executive dashboard "25% confirmed
  vulnerability load, 1 confirmed finding".
- **Negative control, run**: a genuinely confirmed high scores 25 in *both* — the two agree whenever
  the input is honest and diverge only on demoted rows, which localises the defect to the filter.
- **Fix contract**: both must consume one shared confirmed-only projection. `proof_schema.is_confirmed`
  already exists and was created for exactly this ("three private copies is how the HTML report came to
  stamp CONFIRMED on rows the proof gate had already demoted") — this is the fourth copy.
- **Oracle**: the two-line comparison above, as an assertion, on a demoted list.
- **Negative control**: the confirmed-input case must stay equal — proves the fix did not zero the
  signal. Mutation: re-remove the filter and the assertion must fail.
- **Files**: `agent/report.py` (owned elsewhere this cycle — sequence it).

### Q-016 · `bie._read_controls` returns `[]` on failure — BIE phase 2 cannot report that it went dark · **MEDIUM** · `proposed`
- **Root cause** (`bie.py:1475`): `except Exception: return []`. Every caller path then reads a clean
  empty result — `classify_controls([])` -> `counts.total = 0` -> `probe_targets` returns nothing ->
  phase 2 (CWE-602 client-side authz) emits **zero probes and zero findings**, and the report prints
  `control_surface.counts.total: 0`. A `page.evaluate` that threw is byte-identical to a page that
  genuinely renders no controls.
- **This is S12c at a different layer, and the fourth instance of the shape** (`DOM_SCAN_JS`,
  `parse_qsl`, S12c `localStorage`, now this). `CONTROL_SURFACE_JS` (`bie.py:934`) is a single
  dependency of exactly the kind that went missing in the `DOM_SCAN_JS` case.
- **The idiom already exists in this file**: `_fetch` (12 lines below) returns
  `... | {"error": str(e)[:160]}` on the same failure. `_read_controls` should record the same way.
- **Oracle**: force `page.evaluate` to raise; the run must report a control-surface **error**, not
  `total: 0`, and phase 2's verdict must be `lead`/inconclusive rather than silent-clean.
- **Negative control**: a page that genuinely has zero controls must STILL report `total: 0` with no
  error — the whole point is telling the two apart, and a fix that flags both is no fix.
- **Files**: `agent/bie.py` (owned elsewhere this cycle — sequence it). Composes with `#54`: the
  `tools._swallow` ledger is the natural sink.

### Q-017 · `get_logs` is oldest-first with a LIMIT, so the mission view and the backup export drop the newest events · **LOW** · `proposed`
- **MEASURED**, all 151 stored missions. The claimed consequence is **half disproved**:
  - `db.get_logs`: `ORDER BY id LIMIT ?` keeps the **oldest** n rows. Confirmed on mission `54155d4b`
    (1287 rows): `get_logs(limit=500)[-1].ts = 22:31:01` vs the true last event `22:35:20`.
  - **DISPROVED**: the 4000-row caps at `_tool_ledger` (`main.py:694`) and `asvs_coverage`
    (`main.py:1251`) have **never truncated** — the largest mission ever recorded is 1287 rows, and
    distinct tool names visible at `limit=4000` equals the unbounded count (49 = 49, 0 lost). The
    "ASVS under-reports because of log truncation" theory does not hold today.
  - **CONFIRMED and firing**: the 500-row caps at `main.py:551` (`GET /missions/{sid}` — the UI's
    mission detail) and `main.py:3304` (`GET /backup/{sid}`) truncate on **12+ missions**, dropping
    259–787 of the most recent events. For a backup that is data loss on export.
- **Adjacent, same handler, worth folding in**: `mission_detail` and `/backup` both call
  `db.get_findings` (RAW, ungated) — `get_findings`' own docstring says to prefer the gated accessor
  for "anything a human or a model will read". Needs a UI check before it is called a defect; I did
  not run one, so this half is **UNVERIFIED**.
- **Oracle**: on a mission with > 500 log rows, the newest event's timestamp appears in the response.
- **Negative control**: a mission with < 500 rows returns byte-identical output to today.
- **Files**: `agent/db.py`, `agent/main.py` (owned elsewhere — sequence it).

### Q-018 · Retest scope guard — DISPROVED as a live defect; hardening only · **LOW** · `proposed`
Filed so it is not re-raised as a CRITICAL. **Do not treat the audit's framing as fact.**
- **MEASURED**: replayed `main.py:2578-2602` verbatim against the real `scope` dict of **all 151**
  stored missions.
  ```
  element type handed to load_manual : {'str': 151}
  GUARD ACTIVE                       : 151
  GUARD OFF (load_manual raised)     : 0
  GUARD OFF (no in_scope)            : 0
  ```
  Negative control: three sampled active guards all answer
  `validate('http://evil.example.com/x') -> False`. `in_scope` is a required field on
  `EngageRequest`, so the unscoped branch is unreachable through the product.
- **What survives**: two `_eng = None` paths silently *disable* a safety guard instead of refusing to
  retest. Reachable only with a non-string element in `scope["bases"]`/`["in_scope"]` — measured:
  `load_manual([{'nested':'dict'}])` raises `AttributeError: 'dict' object has no attribute 'strip'`,
  and `main.py` turns that into an unguarded retest. Latent, never fired.
- **Fix contract**: fail **closed** — if the mission is scoped and the engine cannot be built, every
  retest returns `inconclusive: "scope engine unavailable"`. Never proceed unguarded.
- **Oracle**: inject a dict into `scope["bases"]`; every retest must return `inconclusive`, not a GET.
- **Negative control**: a normal mission's retest behaviour must be byte-identical to today.
- **Files**: `agent/main.py` (owned elsewhere — sequence it).

---

## verification

*(nothing yet — Breaker takes items from `active` as they land)*

## completed

### Q-000 · Report un-demoted findings the proof gate had rejected
`proof_schema.demote_unproven` rewrites `confidence` to `"lead"` and keeps the row; the HTML card
stamped a hardcoded `CONFIRMED` on every row, and `_counts()`/`total_conf` counted demoted rows in
the headline severity tally. Fixed: shared `proof_schema.is_confirmed()`, per-finding `_conf_badge`,
confirmed-only `_counts`, matching denominator. **Awaiting Breaker verification + commit.**

### Q-00A · BIE errored-control false positive
`_FETCH_JS` returns `{status: 0, ..., error}` on exception while `judge()` tested only `if c is None`,
so an **errored** control passed as a **satisfied** control. An errored `anon` control also already
failed `_s(anon) == 200`, so it never fired the PUBLIC rejection and fell through to `confirmed` —
tightening the condition alone did not fix it. Fixed with `_control_ran()` plus explicit
missing-control gates in `judge_client_side_authz` and `judge_param_swap`, both returning `lead`.
**Awaiting Breaker verification + commit.**

## rejected

*(Distillation records rejections here with the reason, so the same idea is not re-proposed)*

Already covered — do **not** re-propose (verified against live code): subdomain takeover
(`dns_recon.py:68-110`) · web cache poisoning (`cache_tool.py`, real clean-re-request oracle) · cache
deception · OOB collaborator (`collaborator.py`, wired into SSRF/XXE/cmdi/blind-XSS) · time-based
blind SQLi and cmdi (both with matching zero-delay controls) · mass assignment as a *technique* ·
vulnerable components (`dependency_intel.py`) · host header · JSONP/XSSI · clickjacking (header
level, correctly two-condition) · HTTP parameter pollution (excluded, FP-prone, no clean oracle) ·
padding oracle (excluded, no clean general oracle).

---

# Codex claim verification — pass 2 (Analyst, 2026-08-10)

The five claims already settled in [CODEX_AUDIT_VERDICTS.md](CODEX_AUDIT_VERDICTS.md) are **not**
re-verified here. What follows is the remaining eight, each with the command output that settles it.
Environment: `apolaki-agent-1` healthy, **no mission running**, 151 stored missions / 29,109
`tool_call` rows / 64,513 log rows in `/app/data/bbh.db` (read-only `mode=ro` connections throughout).

| # | Codex claim | verdict |
|---|---|---|
| 1 | `run_whatweb` is an isolated island | **CONFIRMED-WITH-CORRECTION** — reachable, never scheduled, output never normalized |
| 2 | `browser_engine.to_observations()` drops `framework` | **CONFIRMED** |
| 3 | `codeintel.versions` is ignored by mission code | **CONFIRMED** |
| 4 | NVD/GHSA/CVE-v5 end in an in-memory registry with no consumer | **CONFIRMED, and worse than stated** |
| 5 | `asset_graph.build_from_engagement()` never projects recon technology | **CONFIRMED, and worse than stated** |
| 6 | No `vulnerable_component` route in `candidate_pipeline._ROUTES` | **CONFIRMED, but unreachable until Q-021A** |
| 7 | `report.proof_and_retest()` asserts a control it never checked ran | **CONFIRMED — 626 of 660 stored findings** |
| 8 | `test_asset_graph.py:106` injects a synthetic version | **CONFIRMED** |

### 1 · `run_whatweb` — CONFIRMED-WITH-CORRECTION. Two of Codex's sub-claims are wrong.

Both emitter tables were checked, per the standing "wrong by nine" rule.

```
tools.py:72    TOOL_PERMISSIONS["run_whatweb"] = PermissionLevel.ACTIVE     <- table 1: present
tools.py:396   CLAUDE_TOOLS  {"name": "run_whatweb", ...}                   <- table 2: present
tools.py:3493  async def _run_whatweb(...)                                  <- getattr("_" + name) resolves
agent.py:76    PHASE_OF["run_whatweb"] = "enum"                             <- UI phase mapping
$ docker exec apolaki-agent-1 which whatweb
/usr/bin/whatweb                                                            <- the binary IS installed
$ grep -n whatweb agent/planner.py
(no output)                                                                 <- never scheduled
```

- **WRONG**: "isolated island". It is in *both* dispatch tables with a real `_run_whatweb` method, so
  an agentic model can call it. It is not unreachable.
- **WRONG**: the implied "the binary is missing". `/usr/bin/whatweb` exists in the image.
- **RIGHT, and this is the real defect**: nothing deterministic ever calls it, and its output goes
  nowhere. `_run_whatweb` returns `ToolResult("whatweb", ..., findings=[raw JSON])` and, unlike
  `_run_fingerprint` which at least writes `lh["tech"]`, **writes nothing into `self.recon`**. It is
  absent from `_AUTO_STORE_TOOLS`, from `asvs_model`, and from `wstg_catalog`.
- **MEASURED consequence**: `run_whatweb` calls across 151 missions and 29,109 `tool_call` rows = **0**
  (`run_fingerprint` = 2,641 over the same corpus).

**Correct one-line statement**: *`run_whatweb` is a model-only tool with no normalizer, so in 151
deterministic missions it has never run and could not have contributed if it had.*

### 2 · `browser_engine` drops `framework` — CONFIRMED

`browser_engine.py:53` computes it in-page (`window.angular` / React roots / `window.Vue`), `:56`
returns it, `:89` declares it in the empty-result shape. `grep -n framework agent/browser_engine.py`
returns lines **8, 53, 56, 89 only** — `to_observations()` (`:177`) never mentions it, and neither
does `agent.py:_browser_harvest_surface`. `grep framework agent/technique_planner.py
agent/asset_graph.py agent/planner.py` returns **no output**. The sensor detects the SPA framework and
no consumer exists.

### 3 · `codeintel.versions` ignored — CONFIRMED

`codeintel.py:236` `out["versions"] = sorted(versions)[:50]` (mined at `:166` by an `name@x.y.z` regex
over served JS). Consumers:

```
$ grep -rn '["versions"] | get("versions")' agent/*.py | grep -v test
agent/codeintel.py:236        <- the write
agent/intel_connectors.py:182 <- unrelated (GHSA advisory.affected[].versions)
```

`agent._recon_code_intelligence` (`agent.py:1034-1094`) reads `endpoints`, `sensitive_routes` and
`logic` and nothing else; `technique_planner.derive_observations` reads `ci["endpoints"]`,
`ci["sensitive_routes"]`, `ci["bundles"]`, `ci["counts"]`. **A component+version harvested from the
target's own JS is computed on every non-passive mission and discarded** — the same stage-2 loss the
baseline recorded for `fingerprint`, in a second producer.

### 4 · Intel connectors terminate in an in-memory registry — CONFIRMED, and the island is deeper

`intel_connectors._PARSERS` normalizes `epss / nvd / ghsa / cve_v5 / cisa_kev` (`:134-204`). The only
consumer chain in the repo:

```
$ grep -rn "intel_connectors / intel_registry" agent/*.py  (excluding the modules themselves)
agent/main.py:2785  /intel/audit
agent/main.py:2790  /intel/registry        (stats only)
agent/main.py:2803  /intel/fetch/{source}  -> _ir.ingest(...)
```

Three read-only HTTP endpoints. No scan, planner, report, SARIF or graph consumer. Three additional
facts Codex did not state, each of which makes the ticket smaller and more honest:

```
$ docker exec apolaki-agent-1 python -c "intel_sources.allowlist(); intel_registry.stats()"
allowlist: all 18 sources -> enabled=False   (cve_v5, nvd, cisa_kev, epss, ghsa, cert_cc, ... all off)
registry stats: {'total': 0, 'by_state': {}}   production: 0
```

- Every source is **disabled by default**, and `fetch()` hard-gates before any network I/O.
- `intel_registry._STORE` is a module-level dict — **not persisted**; a container restart erases it.
- `intel_registry.advance()` is called **only from `agent/tests/test_intel_registry.py`**. There is no
  endpoint and no code path that promotes a record. So `production()` — documented as "the only
  trusted knowledge safe to drive engines" — is **structurally always empty**. Even a fully wired
  consumer would read `[]`. **Q-021D must therefore ship the promotion path, not just a consumer.**

### 5 · `asset_graph` never projects recon technology — CONFIRMED, and `recon=` is a dead parameter

Every occurrence of the name `recon` inside `build_from_engagement`, dumped from the live module:

```
$ docker exec apolaki-agent-1 python -c "inspect.getsource(asset_graph.build_from_engagement)"
  1 def build_from_engagement(mission_id, *, recon: dict = None, ...)   <- the parameter
 12 recon, urls, findings = recon or {}, urls or [], findings or []      <- the default coercion
 24 25 28 30 32 34 35 79   source="recon"                                <- string literals only
```

The `recon` argument is accepted, defaulted, and **never read**. It is not merely that technology goes
unprojected — no part of `tools.recon` reaches the canonical graph through this function.

Warm start, same claim, also CONFIRMED — but note what already works, because Q-021B must not rebuild
it: `memory.py:112-119,173,185,211` **does** collect and persist `tech` across missions.

```
sqlite> select kind, count(*) from memory_assets group by kind
endpoints 3156 | tech 13 | hosts 10 | subdomains 8
```

`main.py:_warm_start` (`:199-238`) reads `assets["subdomains"]`, `assets["hosts"]`,
`assets["endpoints"]` and `db.get_prior_snapshot` — **never `assets["tech"]`**. Technology is written
to cross-mission memory and never read back.

**NEW DEFECT, not in the Codex audit — the persisted `tech` is partly garbage prose.** 6 of the 13
stored rows are English sentence fragments:

```
sqlite> select target_key, value from memory_assets where kind='tech'
('js-bench:3000',   'a MultiJuicer Kubernetes cluste')
('js-bench:3000',   'in safety mode')
('js-bench:3000',   'on.')
('juice-shop:3000', 'a MultiJuicer Kubernetes cluste')   ...
```

Producer identified and reproduced byte-for-byte offline:

```
fingerprint.py:71   _POWERED = re.compile(r"(?:powered by|built with|running)\s+([A-Za-z][\w .\-]{2,30})", re.I)
fingerprint.py:108  out.append({"name": m.group(1).strip(), ..., "category": "generic"})

>>> fp.fingerprint({}, '', "<p>You are running a MultiJuicer Kubernetes cluster instance.</p>"
...                        "<p>The application is running in safety mode.</p><p>Continue running on.</p>")
[{'name': 'a MultiJuicer Kubernetes cluste', 'source': 'powered-by text', 'category': 'generic'},
 {'name': 'in safety mode.', ...},
 {'name': 'on.', ...}]
```

The `{2,30}` bound truncates mid-word at exactly 31 characters, which is why the stored value ends
`...cluste`. **This is a hard input-quality gate for Q-021B/C/D**: a TechnologyFact keyed on
`a MultiJuicer Kubernetes cluste` would be sent to NVD/OSV as a product name.

### 6 · No `vulnerable_component` route — CONFIRMED, but it is unreachable today

`candidate_pipeline._ROUTES` (`:59-72`) has 12 keys; `vulnerable_component` is in neither `_ROUTES`
nor `PRIMARY_HANDLED` (`:77-86`), so such a lead terminates `UNSUPPORTED`.
**Scoping correction Codex could not have made without running anything**: `dependency_intel` emits
SCA at `confidence: CONFIRMED` (audit claim 1), and the candidate pipeline only ever sees *leads*.
**A `_ROUTES` entry added today would never execute.** Q-021A (demote SCA to lead) is a hard
prerequisite for the route, not a parallel item — this reverses the dependency arrow Codex drew.

### 7 · `report.proof_and_retest()` — CONFIRMED. **The priority item, and the largest of the eight.**

`report.py:1204-1219` builds a **fresh synthetic record** from the finding's family alone and never
looks at the finding's evidence:

```python
nc = _tm.proof_contract({"vuln_class": fam or str(finding.get("cwe") or ""), "oracle": ""}).get("negative_control")
```

`technique_model.proof_contract` → `_neg_control_for(vc)` → a canned per-class string
(`technique_model.py:161-166`). Rendered verbatim, present-indicative, under **"How this was confirmed
(false-positive safety)"** at `report.py:2128-2131` (HTML) and `report.py:459-461` (Markdown).

MEASURED on a finding carrying **no evidence, no controls, no request and no response**:

```
>>> report.proof_and_retest({'family':'sqli','confidence':'confirmed','target':'http://x/?id=1'})
{'negative_control': "An inert control of the same shape but without SQL metacharacters does NOT
                      reproduce the error/boolean/time differential; the unmodified baseline behaves
                      normally.", ...}
>>> report.proof_and_retest({'family':'idor', ...})       # no controls either
{'negative_control': "A negative-control request WITHOUT the trigger does NOT reproduce the confirming
                      signal (differential measured over a stable baseline)."}
```

Scale, across every stored finding in all 151 missions:

```
confirmed findings stored                                     : 660
carry ANY recorded control artifact                           :  34   (dom_link_manipulation 32, bola 2)
carry NONE, yet the report prints a declarative control claim : 626   (94.8%)
top families with no artifact: sqli 89 · backup_exposure 84 · vulnerable_component 56 · csti 56 ·
                               prototype_pollution 50 · crlf 46 · dom_data_manipulation 46 ...
```

A representative confirmed `sqli` row's entire evidence is one request and one response —
`evidence: 'SQLite error triggered by "\')"'` — **no baseline, no inert control**. The report
nonetheless tells the client the inert control was run and did not reproduce.

**Be precise about what is wrong.** Several engines DO run a differential internally (boolean-blind
compares true against false; error-recovery compares against a recovery baseline). The claim is
therefore often *true* — but it is **never checked and never evidenced**, so it is unfalsifiable from
the report, and for any engine that does not run a control it is simply false. Same defect family as
the badge bug fixed in `707b3b9`: **a surface asserting a property the gate never verified.**
Filed as **Q-022** below.

### 8 · `test_asset_graph.py:106` proves ingest, not wiring — CONFIRMED

`test_ingest_intel_gives_graph_the_full_planner_vocabulary` constructs the dict literal
`intel = {"candidates": {..., "version": ["angular@1.7.7"], ...}}`, hands it to `g.ingest_intel()`,
and asserts `has_versions` in `to_observations()`. It exercises `asset_graph.py:215`
(`for v in cands.get("version", [])`). The only production caller is `agent.py:1202`
(`_g.ingest_intel(self.tools.intel.to_dict() ...)`) and the test never touches it. The test is green
whether or not any producer ever populates `candidates["version"]` — precisely the recorded
**"guards that check declarations, not facts"** shape. Any Q-021 ticket adding a producer must add the
paired **producer-side** assertion, not extend this one.

---

## Rank 3c — Q-021 family, implementation-ready (Distillation, 2026-08-10). All `proposed`.

**Read this preamble before any of B–F.** Three constraints apply to every ticket in the family.

1. **Q-021A has LANDED** — six slices, `177cb5c`/`77ae1de`/`5c1ee66`/`2f071a8`/`fb64d7b`/`30006f4`.
   MEASURED consequences that change the scoping Codex assumed:
   - `dependency_intel.vulnerable_component_finding` now emits `"confidence": CONFIRMED if ok else
     "lead"` (`dependency_intel.py:334`) where `ok` requires a CVE-specific behaviour differential
     through `behaviour_proof_ok`.
   - `proof_schema._DEFAULT_ENFORCE` now contains `"vulnerable_component"` (`proof_schema.py:160-161`).
   - So **every SCA finding is a LEAD by default today**, and leads flow into `candidate_pipeline`.
     Q-021's remaining job is to make that lead *resolvable*, not to demote it again.
2. **PRESERVE, do not rebuild.** Fingerprinting exists and RUNS — `planner.py:277` schedules
   `run_fingerprint` for every live host, and 2,641 calls are recorded across 151 missions.
   `dependency_intel` already owns the `CONFIRMED / HIGH / LOW` ladder with
   `CVE_ELIGIBLE = {CONFIRMED, HIGH}` (`dependency_intel.py:20-23`) and `cve_eligible()` (`:205`) is
   already the enforcement point for *unknown version ⇒ POTENTIALLY_AFFECTED*. Four tier-A feeds
   already exist in `intel_feeds.py`. A new `tech_intel.py` beside any of these is rejected in advance.
3. **The reusable proof-safe shape is the cloud one**, and it is three named files, not a slogan:
   `cloud_intel.analyze()` (`cloud_intel.py:65`, pure detection from headers/CNAME/URL) →
   `agent._cloud_exposure_probe` (`agent.py:1588-1610`, orchestration that calls the gated
   `_exec_internal("run_cloud_probe", ...)`) → `tools._run_cloud_probe` (`tools.py:2606`, ACTIVE,
   scope-gated, read-only GET whose verdict comes from `cloud_intel.storage_exposure(status, body)` —
   a **content-signature** oracle, never a status-code heuristic). Q-021E copies this shape.

---

### Q-021B · Stop discarding the version — persist a canonical TechnologyFact · **HIGH** · `proposed`

**Repository-proven gap.** The version is computed and thrown away one line later, in three separate
producers, and the one place it is persisted is polluted with English prose.

| producer | computes | what survives |
|---|---|---|
| `fingerprint.fingerprint()` → `tools._run_fingerprint` (`tools.py:3521`) | `{name, version, source, category}` | `lh["tech"] = [name, ...]` — **bare strings**; `version`, `source`, `category` dropped |
| `codeintel.harvest()` (`codeintel.py:236`) | `out["versions"]` (`name@x.y.z` from served JS) | **nothing** — no reader in the repo |
| `browser_engine.observe()` (`browser_engine.py:53-56`) | `framework` (angular/react/vue) | **nothing** — `to_observations()` never reads it |
| `memory.py:112-119,173` | persists `tech` across missions (13 rows live) | written, **never read back** — `main.py:_warm_start` skips `assets["tech"]` |

**Root cause.** There is no technology *record type*. Every producer emits an ad-hoc shape and every
consumer reads the lowest common denominator, which is a display string. `dependency_intel` has the
right record (`make_component`, `dependency_intel.py:117`) but is scoped to JavaScript libraries only.

**MEASURED input-quality defect that must be fixed in the same ticket** (see verification §5): 6 of 13
persisted `tech` values are sentence fragments produced by `fingerprint._POWERED`
(`fingerprint.py:71`, `{2,30}` truncating at 31 chars). Reproduced offline byte-for-byte:
`fp.fingerprint({}, '', "...running a MultiJuicer Kubernetes cluster...")` →
`[{'name': 'a MultiJuicer Kubernetes cluste', 'source': 'powered-by text'}, {'name': 'in safety mode.'},
{'name': 'on.'}]`. **Persisting these as TechnologyFacts would send them to NVD/OSV as product names.**

**Producer/consumer contracts.**
- *Producer*: `fingerprint`, `codeintel`, `browser_engine` and `dependency_intel` all emit a
  `TechnologyFact` through **one** constructor. Extend `dependency_intel.make_component` rather than
  writing a new one — it already carries `name / version / source / confidence / evidence / location`.
  Add: `vendor`, `category`, `component` (plugin/theme/module), `authenticated` (bool), `first_seen`,
  `last_seen`, `detector`.
- *Contract A*: **a TechnologyFact with no version is legal**; it carries `confidence: LOW` and is
  therefore never CVE-eligible (`cve_eligible()` already enforces this). Do not synthesise a version.
- *Contract B*: **a fact whose `name` fails the identity gate is not admitted.** Gate = the name must
  match a known-product table or a conservative token shape (no spaces-plus-articles, no trailing `.`,
  not truncated at exactly the regex bound). `_POWERED` hits become `evidence`, never `name`.
- *Consumer*: `tools.recon["technology"]` (a list of facts, alongside the existing
  `live_hosts[i]["tech"]` display list, which is **kept** so nothing that renders it breaks);
  `asset_graph.build_from_engagement` projects them as `component` nodes; `_warm_start` re-seeds them.

**Dependencies.** Q-019 (a technology fact is worth little at 36 probed URLs) — but B is otherwise
independent and can be built in parallel with Q-019's verification.

**Likely files.** `agent/fingerprint.py` · `agent/dependency_intel.py` · `agent/tools.py`
(`_run_fingerprint` only) · `agent/asset_graph.py` · `agent/memory.py` · `agent/main.py`
(`_warm_start`) · `agent/browser_engine.py`. **`tools.py` is owned by the engine-lane Builder this
cycle — the `_run_fingerprint` change is a hand-off note, not a direct edit.**

**Deterministic oracle.** Against a standing lab with a known banner (`apolaki-testbox`, or
`owaspbench` for `Server:`):
1. `recon["technology"]` contains a fact with `name`, a non-empty `version`, `confidence in
   CVE_ELIGIBLE`, and an `evidence` string quoting the exact header/byte that proved it.
2. `asset_graph.build_from_engagement(...)` produces ≥ 1 `component` node for that fact.
3. A second mission on the same target warm-starts with that fact already present
   (`_warm_start()["technology"] >= 1`).

**Negative control (three, all mandatory).**
- **(a) Prose is refused.** Feed the exact MultiJuicer body above; `recon["technology"]` must gain
  **zero** facts and the run must record *why* (a `_swallow`-style rejection naming the detector), not
  silently drop them. A fix that merely stops *storing* them without recording the rejection has moved
  the blindness, not removed it.
- **(b) A versionless detection stays LOW.** A `Server: nginx` with no version must produce a fact
  with `version: ""`, `confidence: LOW`, and `cve_eligible(fact) is False`.
- **(c) Empty means empty.** A target that serves no identifying header, cookie, generator or script
  must produce **zero** facts and **no error** — the same "tell a real zero from a broken detector"
  requirement Q-016 exists for.

**Mutation tests.**
- Re-widen `_POWERED` to accept prose → control (a) must fail.
- Drop `version` from the fact constructor → oracle assertion 1 must fail.
- Point `_warm_start` back at the three original kinds → oracle assertion 3 must fail.
- Make `cve_eligible` return True for LOW → control (b) must fail. *(This mutation also guards
  Q-021C/D, so it belongs in a shared test module.)*

**Regression tests.** `live_hosts[i]["tech"]` keeps its current string-list shape (the UI and
`report.py:1422,2585` delta section read it); `agent/tests/test_fingerprint*.py` stay green;
`memory_assets` gains no new `kind` value that existing readers would choke on.

**False-positive risks.** Spoofed `Server:`/`X-Powered-By` banners (a fact is an *observation*, so
record the header verbatim as evidence and never call it proof); CDN-injected headers attributed to
the origin; the same product detected under two aliases (`dependency_intel._FLEX_ALIAS` /
`_CDN_NAME_FIX` already exist — reuse, do not re-implement).

**Definition of done.** All three oracle assertions and all three negative controls in the suite; a
`liveness.py` CHECKS entry (hand-off to the Coordinator) that fails when `recon["technology"]` is
empty on a target with a known banner; the 6 prose rows purged from `memory_assets` by the identity
gate on next write; **no new module created**.

**Expected benefit.** Unblocks C, D, E and F — none of them can be built on a bare string. Also
retires the 6 garbage rows currently poisoning cross-mission memory.

---

### Q-021C · Canonical identity, version ranges, and applicability · **HIGH** · `proposed`

**Repository-proven gap.** Nothing in `agent/` computes a CPE or a PURL, and nothing evaluates a
version *range*. `dependency_intel._ver_tuple` / `_vlt` (`:187-203`) implement a numeric-tuple
comparison — enough for `< 3.5.0`, wrong for `>= 1.2, < 1.4 || >= 2.0, < 2.1`, wrong for ecosystem
semantics (npm `^`/`~`, Python PEP 440 `rc`/`post`, Debian epochs and `-1ubuntu2` revisions).
Applicability validation does not exist at all (baseline stage 4).

**Root cause.** Identity and comparison were both solved *just enough* for a single ecosystem
(JavaScript CDN filenames) and were never generalised, so every other product has no way to be matched
against an advisory at all.

**Producer/consumer contracts.**
- *Producer*: a TechnologyFact (Q-021B) gains `purl` and/or `cpe` **when they can be derived
  confidently**, and `identity_confidence` when they cannot. A guessed CPE is worse than none.
- *Consumer*: a range evaluator `applies(fact, advisory) -> (verdict, reason)` returning exactly one
  of `AFFECTED / NOT_AFFECTED / UNKNOWN`, where **`UNKNOWN` is the default**, not `AFFECTED`.
- *Contract*: `applies()` must return `UNKNOWN` — never `AFFECTED` — when the ecosystem is unknown,
  the range syntax is unparsed, or the version is `LOW` confidence.

**Backported patches are the single largest FP source in this class and must be handled explicitly.**
Debian/RHEL ship a patched `1.2.3` that every naive range check calls vulnerable. Contract: when the
fact's `source` indicates a distro-packaged product (a distro revision suffix, a distro-specific
banner), the verdict is capped at `UNKNOWN` with `reason: "distro backport possible"` unless a
behaviour probe (Q-021E) resolves it.

**Dependencies.** Q-021B (needs the record). **Blocks** Q-021D and Q-021E.

**Likely files.** `agent/dependency_intel.py` (extend `_ver_tuple`/`_vlt`, add the range evaluator) ·
a small pure `agent/version_ranges.py` **is acceptable here** — it is a new *algorithm*, not a second
copy of an existing capability — provided `dependency_intel` is its only caller.

**Deterministic oracle.** A table-driven test over fixtures per ecosystem, each row
`(ecosystem, version, range, expected)`, including: `npm ^1.2.3` vs `1.2.4` → AFFECTED;
`PEP 440 2.0rc1` vs `< 2.0` → AFFECTED (rc precedes release); `1:1.2.3-1ubuntu2` vs `< 1.2.4` →
UNKNOWN (backport); an unparseable range → UNKNOWN.

**Negative control.** **(a)** A **patched** version of a detected product yields zero AFFECTED
verdicts against the same advisory set. **(b)** A spoofed `Server:` banner claiming an ancient version
while the real behaviour is current must not reach AFFECTED — with Q-021E absent it must sit at
UNKNOWN, which is the correct answer, not a failure. **(c) Non-vacuity**: the table must assert
`len(rows_evaluated) > 0`; a range test over an empty fixture set passes for free, which is exactly
the vacuous pass Q-012 recorded.

**Mutation tests.** Flip the `UNKNOWN` default to `AFFECTED` → control (a) and (b) must fail. Strip
the distro-suffix branch → the `1ubuntu2` row must fail. Make `applies()` ignore
`identity_confidence` → a LOW-confidence fact must wrongly reach AFFECTED and a test must catch it.

**Regression tests.** Every existing `dependency_intel` assertion stays green; `cve_eligible()`
semantics are unchanged (this ticket adds a *second* gate, it does not relax the first).

**False-positive risks.** Ambiguous product names across ecosystems (`jquery` the npm package vs
`jquery` the CDN bundle); a range expressed against a fork; duplicate CVEs arriving from two feeds
with different ranges — record both, take the **narrower** verdict, never the union.

**Definition of done.** The fixture table green with the non-vacuity assertion; all three negative
controls; `applies()` is the only place a version is compared to a range anywhere in `agent/`.

**Expected benefit.** Converts "a feed returned 40 CVEs for jquery" into a defensible per-CVE verdict,
and is the only thing standing between Q-021D and a report full of theoretical CVEs.

---

### Q-021D · Connect governed feeds to components — and ship the missing promotion path · **MEDIUM** · `proposed`

**Repository-proven gap, and it is two gaps, not one.**

*Gap 1 — no product→advisory resolution.* `intel_feeds.py` (406 lines) carries exactly four tier-A
sources — KEV, CAPEC, ATT&CK, ExploitDB — and matches by **exact CVE** or an exact product-version
key (`exploits_for_finding`, `exploitdb_for_product`). There is no NVD/CPE, OSV, GHSA or WPScan
resolution, so `nginx 1.18.0` cannot be turned into a CVE list at all.

*Gap 2 — the governed connectors that DO parse NVD/GHSA/CVE-v5 terminate in an unreachable store.*
MEASURED (verification §4): `intel_connectors._PARSERS` handles `epss / nvd / ghsa / cve_v5 /
cisa_kev`; the only consumers are three read-only endpoints (`main.py:2785, 2790, 2803`);
`intel_registry._STORE` is a module-level dict wiped on restart; and **`intel_registry.advance()` is
called only from `agent/tests/test_intel_registry.py`** — no endpoint, no code path. Live check:

```
allowlist: all 18 sources -> enabled=False
registry stats: {'total': 0, 'by_state': {}}   production: 0
```

`production()` is documented as "the only trusted knowledge safe to drive engines" and is
**structurally always empty**. **A consumer wired to it today would read `[]` forever.** Any ticket
that only adds a consumer is a null change against a green test — this is the same shape as Q-019
refinement #1.

**Root cause.** `#114` built the *governance* half of the connector story (allowlist, rate limit,
audit log, provenance, staged trust) and stopped before the *promotion* half, so the trust ladder has
a top rung nothing can climb to.

**Producer/consumer contracts.**
- *Producer*: a resolver `advisories_for(fact) -> [advisory]` that consults, in order, the local
  feed snapshots then the governed connectors, and **always records which source and which snapshot
  timestamp** produced each advisory.
- *Consumer*: `applies()` from Q-021C decides `AFFECTED / NOT_AFFECTED / UNKNOWN` per advisory. The
  resolver never decides applicability itself.
- *Promotion contract*: `intel_registry.advance()` gains a caller — an explicit, evidence-carrying
  step. **Do not auto-promote to `production`**; the existing rule (a human `reviewed_by`) is correct
  and stays. What must be built is the path to `validated` / `fixture_backed`, and a consumer that
  reads `validated`-and-above rather than `production`-only, with the confidence weight carried
  through (`_CONF`, `intel_registry.py:15-16`) so a `candidate` advisory can never outrank a
  `fixture_backed` one.
- *Persistence contract*: `_STORE` must survive a restart, or the registry must be documented as
  per-process and the consumer must tolerate a cold empty store without failing open.

**ANTI-SPAM, hard requirement, restated because it is the failure mode this ticket most invites.**
An unknown or LOW-confidence version yields **at most one** `POTENTIALLY_AFFECTED` row per product —
never one per CVE. The row names the count (`"jquery 2.1.4 — 41 advisories match this version range,
none applicability-verified"`), it does not enumerate them into the findings list.

**Dependencies.** Q-021B (the fact) and Q-021C (the range evaluator). Also the **Watcher's feed-quality
review** — licence, update cadence, machine-readable format, provenance. Feeds rejected in advance and
the reason, so they are not re-proposed:

| feed | verdict |
|---|---|
| NVD 2.0 API | accept — already parsed (`_parse_nvd`), allowlisted, tier A |
| OSV.dev | accept — the only source with real per-ecosystem range semantics; it is what Q-021C needs |
| GHSA | accept — already parsed (`_parse_ghsa`), carries `first_patched_version` |
| CVE Program v5 | accept — already parsed (`_parse_cve_v5`) |
| CISA KEV | already loaded twice (`intel_feeds` snapshot + `_parse_kev`) — **de-duplicate, do not add a third** |
| WPScan | **defer** — key-gated, non-commercial licence terms, and Apolaki has no WordPress plugin/theme detector yet (Q-021B does not add one). Revisit only after a CMS detector exists |
| scraped vendor advisory pages | **reject** — no machine-readable format, no provenance, unmaintained parse surface |
| "CVE aggregator" blogs / GitHub CVE-list mirrors | **reject** — no provenance, stale, duplicate |

**Likely files.** `agent/intel_feeds.py` · `agent/intel_connectors.py` · `agent/intel_registry.py` ·
`agent/intel_sources.py` · `agent/dependency_intel.py`. *(No `agent/` file in this list is held by
either Builder this cycle.)*

**Deterministic oracle.** Fully offline, using recorded feed fixtures and the injectable `http=`
hook `intel_connectors.fetch` already exposes:
1. A fact for a product with a known CVE resolves to ≥ 1 advisory carrying `source` and
   `snapshot_at`.
2. That advisory reaches the consumer at `validation_state >= validated` after an explicit advance
   with evidence, and **not** before.
3. One product with 40 matching CVEs at LOW version confidence produces exactly **1** row.

**Negative control.** **(a)** With every source disabled (the default), the resolver performs **zero**
network I/O and returns an empty result *labelled* `disabled` — not an empty result labelled clean.
**(b)** A record that was never advanced must **not** be visible to the consumer — this is the
mutation that proves the ladder is load-bearing. **(c) Non-vacuity**: assert the fixture set is
non-empty before asserting "no spam", or the anti-spam test passes over zero advisories.

**Mutation tests.** Make the consumer read `by_state("candidate")` → control (b) must fail.
Remove the per-product collapse → oracle 3 must fail with 40 rows. Delete the `snapshot_at` stamp →
oracle 1 must fail. Re-enable a source in the test env without a credential → the hard gate must still
refuse and control (a) must stay green.

**Regression tests.** `exploits_for_finding` / `exploitdb_for_product` behaviour unchanged; KEV
matching stays **exact-CVE-only, never inferred from CWE** (a preserved capability); the
`/intel/audit` log still records every outward request.

**False-positive risks.** The same CVE arriving from NVD and GHSA with different ranges (take the
narrower, per Q-021C); a stale snapshot presenting a since-withdrawn advisory (hence `snapshot_at`);
ExploitDB product-version matches being read as proof rather than as a lead (the existing distinction
is a preserved capability — do not flatten it).

**Definition of done.** All three oracle assertions plus all three negative controls; at least one
record demonstrably reaching `validated` through product code rather than through a test; the
`/intel/registry` endpoint showing a non-zero `by_state` after a governed fetch in the demo path.

**Expected benefit.** The first time a detected non-JavaScript product can be resolved to an advisory
at all — and the first time `#114`'s trust ladder has a rung above `candidate` that product code uses.

---

### Q-021E · Technology drives safe orchestration — copy the cloud pattern · **MEDIUM** · `proposed`

**Repository-proven gap, with the architecture corrected.** Codex and the baseline both frame this as
"`derive_observations` has no `recon` parameter". That framing invites the wrong fix. The module
itself says so:

```
technique_planner.py:144-146
  This entry point takes NO surface/harvest argument, so flat recon CANNOT independently drive it —
  an empty graph yields an empty plan no matter what recon found elsewhere. That is the proof the
  graph is the brain: facts must be projected INTO the graph to influence the plan.
```

**So adding a `recon=` parameter to `derive_observations` is REJECTED in advance** — it would feed the
compatibility path while the graph-authoritative path (`plan_graph_authoritative`, the one the mission
actually leads with) stayed blind. The correct wiring is Q-021B projecting TechnologyFacts into the
graph as `component` nodes; `asset_graph.to_observations()` already maps `component` → `has_versions`
(`asset_graph.py:234-235`).

**And here is the measured catch that makes this ticket necessary rather than free:**

```
$ grep -n has_versions agent/engine_descriptor.py
43:    ... "has_versions", ...        <- present in the OBSERVATIONS vocabulary
$ grep -n has_versions <PRECONDITIONS body>
(no match)                            <- gates ZERO techniques
```

`has_versions` is a **declared observation with no consumer**. Projecting facts into the graph
therefore changes nothing on its own. Q-021E's real work is (i) product-conditioned observations and
(ii) a probe that can act on them.

**Producer/consumer contracts.**
- *Producer*: `asset_graph.to_observations()` emits product-conditioned observations derived from
  `component` nodes — e.g. `wordpress_detected`, `nginx_detected`, `component_advisory_matched` —
  added to `engine_descriptor.OBSERVATIONS` (the single vocabulary) and to `PRECONDITIONS` for the
  techniques they gate.
- *Consumer*: one new engine following the cloud triplet **exactly**:
  - `dependency_intel.probe_plan(fact, advisory) -> {trigger, control, signature} | None` — pure,
    the analogue of `cloud_intel.analyze()`. Returns `None` when no safe deterministic probe exists,
    which must be the **common** answer.
  - `agent._technology_probe(session_id)` — the analogue of `agent._cloud_exposure_probe`
    (`agent.py:1588-1610`): iterates candidate facts, calls the gated
    `_exec_internal("run_tech_probe", ...)`, skipped in passive mode.
  - `tools._run_tech_probe` — the analogue of `tools._run_cloud_probe` (`tools.py:2606`):
    scope-gated, read-only, one bounded request, verdict from a **content signature**, never a status
    code.
- *Contract, non-negotiable*: `probe_plan` returning `None` leaves the finding at
  `POTENTIALLY_AFFECTED`. **Detection plus a database match is never a confirmation.** This is already
  enforced downstream by `behaviour_proof_ok` (`dependency_intel.py:223`) which Q-021A shipped — route
  through it, do not add a second gate.

**Dependencies.** Q-019 · Q-021B · Q-021C · Q-021D.

**Also in scope, because Q-021A made it live.** `candidate_pipeline._ROUTES` has no
`vulnerable_component` entry. MEASURED today:

```
>>> cp.canonical_family(sca_lead)  -> 'vulnerable_component'   (classifies correctly)
>>> 'vulnerable_component' in cp._ROUTES        -> False
>>> 'vulnerable_component' in cp.PRIMARY_HANDLED -> False
>>> cp.normalize(sca_lead)['validator'] -> None
    cp.normalize(sca_lead)['oracle']    -> 'no validator implemented yet'
```

Before Q-021A this was unreachable (SCA emitted `confirmed`, and only leads enter the pipeline).
**It is reachable now, and every SCA lead terminates `UNSUPPORTED` — 56 stored `vulnerable_component`
findings would take that path.** The `_ROUTES` entry is
`("run_tech_probe", "<CVE> behaviour differential reproduced; trigger-absent control did not", None)`
and it must land in this ticket, not a later one.

**Likely files.** `agent/dependency_intel.py` · `agent/asset_graph.py` · `agent/engine_descriptor.py`
· `agent/technique_planner.py` · `agent/candidate_pipeline.py` · `agent/agent.py` ·
`agent/tools.py`. **Both `tools.py` and `candidate_pipeline.py` are Builder-owned this cycle — those
two edits are hand-off notes.**

**Deterministic oracle.** On a lab running a product with a *behaviourally observable* CVE:
detection → advisory match → `probe_plan` returns a plan → the probe runs → the content signature is
present → the finding is `confirmed` / `AFFECTED`, carrying the trigger, the observed signature, the
control, and the control's observed value (the fields `dependency_intel.py:290-296` already
formats).

**Negative control (four).** **(a)** Structurally identical request with the trigger **absent** must
not produce the signature — this is already the shape `behaviour_proof_ok` demands, so the test is an
assertion, not new machinery. **(b)** A **patched** version of the same product on the same URL must
NOT stay `OPEN` on retest (Q-021A slice 3 fixed the retest oracle — this control proves it holds for
the new engine too). **(c)** A product detected with `LOW` version confidence produces
`POTENTIALLY_AFFECTED` and **zero** confirmed findings however many CVEs the feed returns.
**(d)** A spoofed `Server:` banner claiming an ancient version, with current behaviour, must not
confirm — the probe is the arbiter, not the banner.

**Mutation tests.** Make `probe_plan` return a plan for every advisory → control (d) must fail.
Let the probe judge on status code instead of the content signature → control (a) must fail (the
control request usually returns the same status). Remove the `_ROUTES` entry → the SCA lead must go
back to `UNSUPPORTED` and a test must catch it. **Non-vacuity**: assert the probe actually executed
(a `run_tech_probe` `tool_call` row exists), because a no-op engine passes every control above for
free — this is the Q-020/`verify_always_on` lesson and the ZAP lesson in Q-023.

**Regression tests.** Zero new confirmed findings on a clean paired lab; the mission's finding count
on `owaspbench` does not change (no product there has a behaviourally observable CVE, so the correct
outcome is *no new findings* — a ticket that "improves" that number is misbehaving).

**False-positive risks.** WAF or CDN responses matching the content signature; a probe that mutates
state (forbidden — read-only only, and `probe_plan` must return `None` for any CVE whose trigger is
not idempotent); a signature so loose it matches the patched build.

**Definition of done.** All four negative controls plus the non-vacuity assertion; the `_ROUTES`
entry; a `liveness.py` CHECKS entry; **a `run_tech_probe` `tool_call` row observed in a real mission**
— the declaration that the engine is registered is not evidence that it ran (Q-023 is the same lesson
measured at scale).

**Expected benefit.** The first path in the platform from *"we detected nginx 1.18.0"* to a defensible
confirmed-or-rejected verdict, and it closes the `UNSUPPORTED` terminal state Q-021A opened.

---

### Q-021F · Expose the technology lifecycle honestly · **LOW** · `proposed`

**Repository-proven gap.** `report.py:1422,2585` surface `("tech", "New Technology")` in the **delta**
section only — technology appears in a report only when it *changes* between scans. There is no
technology inventory, no version-confidence column, no advisory-match column, no proof-status column,
in the report or the UI. `asvs_model.py:151` maps an ASVS objective to
`("run_fingerprint", "dependency_intel")`, which is the only place the two are named together.

**Root cause.** Stage 8 was built for *findings*, and technology never became a first-class object, so
there was nothing to render.

**Producer/consumer contracts.**
- *Producer*: the TechnologyFact list (Q-021B) plus each fact's advisory verdicts (Q-021C/D) and probe
  outcome (Q-021E).
- *Consumer*: one shared projection used by **all four** surfaces — HTML report, Markdown report,
  `GET /missions/{sid}` (UI coverage view), SARIF and the PoC bundle. **One projection, not four
  private copies** — the four-copies-of-`is_confirmed` history (Q-015, `707b3b9`) is why this is
  stated as a contract rather than a suggestion.
- *Contract*: every row states its **proof status** in the six-state ladder
  `DETECTED_TECHNOLOGY → VERSION_SUSPECTED → ADVISORY_MATCHED → APPLICABILITY_CONFIRMED →
  SAFELY_PROBED → ORACLE_CONFIRMED`, and the rendered badge is computed from the stored state, never
  hardcoded. **A row above `ADVISORY_MATCHED` that carries no probe evidence must render as
  unproven** — the badge bug (`707b3b9`) and Q-022 are both instances of getting this wrong.

**Dependencies.** Q-021B through Q-021E.

**Likely files.** `agent/report.py` · `agent/sarif_io.py` · `agent/poc_bundle.py` · `agent/main.py`
(the coverage view) · `ui/`. **`report.py`, `sarif_io.py` and `poc_bundle.py` are Builder-owned this
cycle** — sequence after that lane releases them.

**Deterministic oracle.** For a mission with ≥ 1 TechnologyFact: the HTML report, the Markdown report,
the mission JSON and the SARIF export all show the **same** count of facts and the **same** proof
state per fact. A cross-surface equality assertion, not four independent ones.

**Negative control.** **(a)** A mission with zero technology facts renders the section as an explicit
"no technology identified" rather than omitting it — an omitted section is indistinguishable from a
broken renderer. **(b)** A fact at `ADVISORY_MATCHED` with no probe must render **unproven** on every
surface; mutate one surface to hardcode "confirmed" and the cross-surface equality assertion must
fail. **(c)** The existing delta section keeps working — a genuinely new technology between two scans
still appears there.

**Mutation tests.** Hardcode a badge on the HTML surface → oracle equality must fail. Point one
surface at a private copy of the projection → the same. Drop the "no technology identified" branch →
control (a) must fail.

**Regression tests.** Existing report snapshot tests; `full_pct` / `verified_pct` unchanged (this
ticket adds a view, it must not move a coverage number); SARIF schema validation still passes.

**False-positive risks.** A reader mistaking an inventory row for a finding — hence the mandatory
proof-status column and a visually distinct section. Do not let technology rows enter
`finding_counts()` or the severity tally.

**Definition of done.** Cross-surface equality assertion green; all three negative controls; the UI
coverage view shows technology, version confidence, advisory match and proof status; **no coverage
percentage changes**.

**Expected benefit.** Makes the whole Q-021 family auditable from the outside — which is the only way
a client can tell Apolaki's technology intelligence from a scanner's version-table guess.

---

## Rank 3d — new tickets from today's measurements (Distillation, 2026-08-10). All `proposed`.

### Q-022 · "How this was confirmed" is a template, not a record — 626 of 660 findings · **CRITICAL** · `proposed`

*The platform's differentiator is that its proofs are real. This is the one place the report says a
proof happened without checking that it did.*

**Repository-proven gap.** `report.proof_and_retest()` (`report.py:1204-1219`) constructs a synthetic
record from the finding's **family alone** and asks the technique model to describe a control:

```python
nc = _tm.proof_contract({"vuln_class": fam or str(finding.get("cwe") or ""), "oracle": ""}).get("negative_control")
```

`technique_model.proof_contract` (`:169`) → `_neg_control_for(vc)` (`:161-166`) → a canned per-class
string. The finding's `evidence`, `browser_evidence`, `request`, `response`, `negative_control` and
`proof_gap` fields are **never read**. The result is rendered verbatim under
**"How this was confirmed (false-positive safety)"** at `report.py:2128-2131` (HTML) and
`report.py:459-461` (Markdown).

**MEASURED** — a finding with no evidence at all still gets a confident sentence:

```
>>> report.proof_and_retest({'family':'sqli','confidence':'confirmed','target':'http://x/?id=1'})
negative_control: "An inert control of the same shape but without SQL metacharacters does NOT
                   reproduce the error/boolean/time differential; the unmodified baseline behaves
                   normally."
>>> report.proof_and_retest({'family':'idor', ...})     # no controls either
negative_control: "A negative-control request WITHOUT the trigger does NOT reproduce the confirming
                   signal (differential measured over a stable baseline)."
```

**MEASURED scale**, every stored finding across all 151 missions:

```
confirmed findings stored                                     : 660
carry ANY recorded control artifact                           :  34   (dom_link_manipulation 32, bola 2)
carry NONE, yet the report prints a declarative control claim : 626   (94.8%)
sqli 89 · backup_exposure 84 · vulnerable_component 56 · csti 56 · prototype_pollution 50 ·
crlf 46 · dom_data_manipulation 46 · broken_auth 33 · dom_xss 28 · security_misconfig 24 ...
```

A representative confirmed `sqli` row's whole evidence is one request and one response:
`evidence: 'SQLite error triggered by "\')"'`, `request: 'GET .../search?q=%27%29'`,
`response: 'HTTP 500 ... SQLITE_ERROR'`. **No baseline. No inert control.** The report tells the
client the inert control was run.

**Root cause.** Exactly the same as `707b3b9`: a **rendering surface asserting a property the gate
never verified**. `proof_contract` is a *specification* of what a technique's control ought to be —
correct for the technique registry, wrong as a per-finding statement of what happened. The two were
never distinguished, and `proof_and_retest` uses the specification as if it were a record.

**Be precise about what is false.** Several engines genuinely do run a differential (boolean-blind
compares a true-condition against a false-condition response; error-recovery compares against a
recovery baseline). For those, the sentence is *true but unevidenced and unfalsifiable from the
report*. For engines that run no control, it is *false*. Both are unacceptable in the section whose
entire purpose is false-positive safety, and the report cannot tell them apart. **The ticket is not
"delete the sentence" — it is "make the sentence a function of what was recorded."**

**Producer/consumer contracts.**
- *Producer*: an engine that runs a control **records it** on the finding, in one canonical shape.
  The shape already exists in two places — pick one and make it the contract: `browser_evidence.
  negative_controls` (a dict of `{label: {url, status, len}}`, rendered by `report.py:1157-1164`) or
  `dependency_intel`'s Q-021A fields (`control`, `control_observed`). The BIE dict is the more
  general of the two.
- *Consumer*: `proof_and_retest` reads the finding and returns one of three shapes:
  - a control **was recorded** → describe the recorded control, quoting its actual values;
  - a control **was not recorded** → *"Negative control not recorded for this finding"* plus the
    technique-registry expectation clearly labelled as **expected**, not **performed**;
  - the family is in `proof_schema._DEFAULT_ENFORCE` and no control was recorded → the finding should
    already have been demoted by `demote_unproven`; assert that, and surface the `proof_gap`.
- *Contract*: **no string in this section may be in the past or present indicative unless it is
  derived from a stored artifact.** Everything else is phrased as an expectation.

**Dependencies.** None — this is a truth-containment fix with no prerequisites, exactly like Q-021A.
It should be ranked with Q-021A's urgency for the same reason: everything else in the queue is a
missing capability; this is a **wrong answer already shipping to clients**.

**Likely files.** `agent/report.py` (owned by the Coordinator this cycle) · `agent/technique_model.py`
· `agent/proof_schema.py` (Builder-owned — the `proof_gap` read is a hand-off note) ·
`agent/tests/test_report*.py`.

**Deterministic oracle.**
1. A finding with a recorded control renders the **recorded** values (url/status/length), and those
   values appear in the output.
2. A finding with no recorded control renders the not-recorded wording, and the string
   `"does NOT reproduce"` (or any indicative claim) does **not** appear.
3. HTML and Markdown produce the same verdict for the same finding — one projection, two renderers.

**Negative control (three, all mandatory).**
- **(a) The honest case must not regress**: the 34 findings that *do* carry a control must still show
  a full control description. A fix that renders "not recorded" for everything has deleted the section
  rather than repaired it.
- **(b) A demoted finding must not display a confirmation narrative at all** — it is a lead.
- **(c) Non-vacuity**: assert the test corpus contains ≥ 1 finding of each kind (control recorded /
  control absent), because a test over a single-kind corpus passes for free.

**Mutation tests.** Restore the family-only `proof_contract` call → oracle 2 must fail. Strip the
recorded-control branch → control (a) must fail. Make the Markdown renderer use its own copy of the
projection and change it → oracle 3 must fail.

**Regression tests.** `technique_model.proof_contract` keeps its current behaviour for the **technique
registry** and its guard test (`every proven technique declares its FP-safety differential`) — that
use is correct and must not change. Report snapshot tests updated with the reason stated in the commit
message, because "the test changed" is what weakening looks like from the outside.

**False-positive risks (of the fix).** Over-flagging: an engine that records its control in a shape
the reader does not recognise would render "not recorded" on an honest finding. Mitigation: enumerate
the recorded-control shapes in one table and add a test per producer that actually records one.

**Secondary observation, UNVERIFIED — do not queue as fact.** The same function's retest string reads
*"(Apolaki auto-retests this)"*. `/retest` (`main.py:2561`) is an operator-invoked endpoint; I found
no scheduler that calls it. Whether "auto" is accurate needs a UI/behaviour check I did not run.

**Definition of done.** All three oracle assertions, all three negative controls, the two mutations;
a re-render of an existing stored mission's report showing "not recorded" on the findings that carry
no control; and the count of findings displaying an unbacked control claim measured before and after.

**Expected benefit.** Removes 626 unbacked proof claims from client-facing output and creates the
back-pressure that makes engines record their controls — which is the only route to the 34/660 figure
improving for real.

---

### Q-023 · ZAP has never executed in any mission, and three flags do not explain it · **HIGH** · `proposed`

**MEASURED, whole corpus.** `run_zap` tool calls across 151 missions and **29,109** `tool_call` rows:
**0**. (`run_fingerprint` 2,641 · `http_probe` 4,542 over the same corpus, so the counter works.)

**Three independent gates, each sufficient on its own** — all three confirmed by reading:

```
main.py:81    enable_zap: bool = False                     <- default off
main.py:336   if enable_zap and req.mode != "full": 422    <- Full mode only
tools.py:138  "run_zap": PermissionLevel.INTRUSIVE         <- outside the active/passive tiers;
                                                              planner.fresh() -> _allowed() drops it
```

**The planner branch is LIVE — measured, not assumed.** Driving `planner.next_batch` directly with
`mode=full, zap=True`:

```
urls=1     batches=8  total_steps=55   run_zap first scheduled at (batch 7, step 54)
urls=30    batches=8  total_steps=287  run_zap first scheduled at (batch 7, step 286)
urls=300   batches=8  total_steps=287  run_zap first scheduled at (batch 7, step 286)
```

Note the third row: phase E is internally capped, so **phase F is reachable in a bounded number of
steps regardless of surface size**. "The mission never gets that far on a big target" is therefore
**DISPROVED** as an explanation.

**THE RESIDUE THAT DEFINES THIS TICKET — flipping the flag is NOT a sufficient fix.** Four missions
carried `enable_zap` truthy in their stored context and fired **zero** `run_zap` calls:

```
c7bfe8e8  ginandjuice.shop              full  2026-07-26  tool_calls=222  run_zap=0
ce35b361  ginandjuice.shop              full  2026-07-26  tool_calls=222  run_zap=0
6771ec21  G&J-FULLBLOWN-26Jul2026@1243  full  2026-07-26  tool_calls=333  run_zap=0
94e8b564  OWASP-JS-FULLBLOWN            full  2026-07-26  tool_calls=375  run_zap=0
```

All four reached `status=complete, phase=report` and all four ran INTRUSIVE tools
(`run_sqlmap`, `run_ffuf`, `run_dalfox`), so `_allowed(INTRUSIVE, full)` passed and the mission was in
Full mode. `run_nuclei` (phase F1, immediately before ZAP) is also absent from all four. **There is a
fifth cause and it is unidentified.** It is `CANNOT_VERIFY_STATICALLY` today because those missions ran
on 2026-07-26 code and the plan loop has since moved to the graph-authoritative path
(`agent.py:2820-2841`, `_graph_primary_state`). Candidate hypotheses for the implementer, in order:
`self.enable_zap` not propagating from `EngageRequest` into the agent · `_zap_configured()` false at
the time (today it is `True`: `ZAP_ADDR=http://zap:8090`, `zap_client.configured() -> True`) ·
`_graph_primary_state` returning a `g_roots`/`g_urls` pair that ends the loop before phase F.

**Root cause (of the ticket's existence).** Nobody ever asserted that ZAP *ran*. `docs` and the report
describe a "ZAP Executed — Safe Active" state; no test and no liveness check requires a `run_zap` row
to exist. This is the **"guards that check declarations, not facts"** shape at the orchestration layer.

**Also in scope — three confirmed sub-defects.**

1. **`recon["zap"]` is a dead write.** `tools.py:8470`
   `self.recon.setdefault("zap", []).extend(findings)` is the sole occurrence. Repo-wide search for
   `recon["zap"]` / `recon.get("zap")` finds no reader (`planner.py:167`'s `state.get("zap")` is the
   *enable flag* on a different dict). ZAP's own alerts reach the report only via the ToolResult /
   `_AUTO_STORE_TOOLS` path, never via recon.
2. **Targeted rescan is NOT WIRED.** The planner key is `f"run_zap:{h}"` (`planner.py:601`) and
   `fresh()` (`planner.py:219-234`) drops any step whose key is in `done`. **One ZAP call per host per
   mission, ever** — a second, narrower ZAP pass against a newly discovered path is unrepresentable.
3. **The AJAX spider fails silently.** `tools.py:8413-8416`:
   ```python
   try:
       await zap.ajax_start(url, context=name)
       await zap.wait_str(lambda: zap.ajax_status(), cap=120, stop_event=self.stop_event)
   except Exception:
       pass
   ```
   A bare swallow, and the SPA crawl is exactly the part that matters on a modern target. **The correct
   idiom is 50 lines below in the same function**: the active scan's `except Exception as _ae:
   ascan_err = ...` is surfaced in the ToolResult note. Mirror it.

**MEASURED CORRECTION to the intake brief — do not use `numberOfMessages` as the oracle.** The brief
records `numberOfMessages: 0` after 10h up. Today:

```
GET /JSON/core/view/version/          -> {"version":"2.17.0"}
GET /JSON/core/view/numberOfMessages/ -> {"numberOfMessages":"4411"}
```

The daemon has now seen 4,411 messages while `run_zap` calls remain **0**, so that counter is
contaminated by something other than Apolaki's ZAP engine. **The oracle must be a `run_zap`
`tool_call` row plus a ZAP-sourced finding, never a daemon-side counter.**

**Producer/consumer contracts.** Producer = `tools._run_zap`, which must (i) write its alerts
somewhere with a reader or stop writing `recon["zap"]`, and (ii) report AJAX-spider failure in its
note. Consumer = the report's "ZAP Executed" state, which must be computed from the presence of a
`run_zap` result, not from the `enable_zap` flag.

**Dependencies.** None. Independent of Q-019 and the Q-021 family.

**Likely files.** `agent/tools.py` (`_run_zap`) and `agent/planner.py` — **`tools.py` is Builder-owned
this cycle; write the patch as a hand-off note.** Plus `agent/agent.py` (flag propagation),
`agent/liveness.py` (Coordinator-owned — hand-off), `agent/tests/`.

**Deterministic oracle — end-to-end, and nothing less counts.** Run one real mission in Full mode with
`enable_zap=True` against a standing lab, then assert **from the persisted event log**:
1. ≥ 1 `tool_call` row with `tool == "run_zap"`;
2. its paired `tool_result` is `success=True` with a note beginning with a policy token;
3. the mission's ZAP state in the report is derived from (1), not from the request flag.

**Negative control (four).** **(a)** The same mission with `enable_zap=False` produces **zero**
`run_zap` rows and a report that does not claim ZAP ran. **(b)** With the ZAP daemon **stopped**, an
`enable_zap=True` mission must degrade *visibly* — a recorded unreachable-daemon error, not a silent
skip and not a crash. **(c)** With the AJAX spider forced to raise, the ToolResult note must say so
while the passive alerts survive (mirroring the existing `ascan_err` behaviour). **(d) Non-vacuity**:
assert the mission actually completed and produced > 0 tool calls, so an aborted mission cannot pass
control (a) for free.

**Mutation tests.** Set `enable_zap=False` in the e2e fixture → oracle 1 must fail. Re-introduce the
bare `except: pass` around the AJAX spider → control (c) must fail. Remove the `run_zap:{host}` key
uniqueness change (if targeted rescan is implemented) → the second, narrower pass must be dropped and
a test must catch it.

**Regression tests.** Missions in `active`/`passive` mode still never schedule ZAP; the 422 for
`enable_zap` outside Full mode is preserved; `require_zap` still blocks when the daemon is absent.

**False-positive risks.** ZAP's own alerts are `_CONFIRMED_BY_TOOL` (`agent.py:117`) — confirmed by
construction. Turning ZAP on for the first time in 151 missions will introduce a **new false-positive
source into the report that has never been measured.** The DoD must include an FPR check on a clean
paired lab before ZAP is enabled by default anywhere, and this ticket must **not** change the default.

**Definition of done.** The three oracle assertions from a real mission's event log; all four negative
controls; the dead write and the bare swallow fixed; a `liveness.py` CHECKS entry that fails when a
ZAP-enabled mission produces zero `run_zap` rows; **and the fifth cause named, with the measurement
that identified it.** Closing this ticket by flipping `enable_zap` is explicitly not acceptable.

**Expected benefit.** Either a whole DAST capability the platform ships and has never run, or —
equally valuable — a measured decision to remove the claim. Both beat the current state, where the
product describes a capability that has executed zero times in 151 missions.
