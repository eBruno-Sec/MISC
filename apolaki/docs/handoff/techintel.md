# Handoff - technology intelligence drives testing (Q-021C-F)

Lane: TECHINTEL BUILDER. Ticket in one line: **Apolaki detects the target's technology and that
detection drives no testing.**

Writable this cycle: `agent/fingerprint.py`, `agent/dependency_intel.py`, `agent/memory.py`,
`agent/tests/test_tech_fingerprint_facts.py`, `agent/tests/test_dependency_intel.py`,
`agent/tests/test_techintel_chain.py`, this file - plus `agent/tools.py`, handed over mid-ticket
when the tiers lane closed. `agent.py` / `planner.py` / `report.py` / `retest.py` /
`mutation_gate.py` belong to other lanes and are untouched.

FILES ACTUALLY WRITTEN: `agent/dependency_intel.py`, `agent/tests/test_techintel_chain.py` (new),
`agent/tools.py` (one line, section 7d), this file. `agent/fingerprint.py` and `agent/memory.py`
were writable and were NOT needed - see section 9.

Predecessor: [tech_intel.md](tech_intel.md) (Q-021B - persist the fact, with evidence).

Every claim below is MEASURED (command + real output) or marked UNVERIFIED.

---

## 1. The premise, checked before anything was built

MEASURED. The premise holds, with one correction worth recording.

`recon["technology"]` - the evidence-carrying `TechnologyFact` records Q-021B built - is READ in
exactly one place that is not its own writer or persistence:

```
$ grep -rn 'recon\.get("technology")\|recon\["technology"\]' --include=*.py agent/ | grep -v "^agent/tests/"
agent/asset_graph.py:610:    for fact in (recon.get("technology") or []):
agent/fingerprint.py:321:    value is precisely what `_run_fingerprint` threw away. `recon["technology"]` accumulates facts
agent/fingerprint.py:332:    recon["technology"] = _di.merge_tech_facts(list(recon.get("technology") or []) + facts)
agent/main.py:239:    tools.recon["technology"] = _di.merge_tech_facts(
agent/main.py:240:        list(tools.recon.get("technology") or []) + facts)
agent/memory.py:207:        "technology": sorted((recon.get("technology") or []),
agent/tools.py:3778:        # record_facts merges TechnologyFacts by IDENTITY into recon["technology"] and records every
agent/tools.py:3787:        # recon["technology"], so the facts reach the durable graph without touching the plan.
```

`fingerprint.py` is the writer, `main.py:239` is the warm-start merge, `memory.py:207` is the
snapshot, and the two `tools.py` hits are comments. That leaves `asset_graph.py:610` as the only
consumer: `build_from_engagement` projects them into the DURABLE graph at report time.
`technique_planner` reads `graph.to_observations()` on the LIVE planning graph, which
`_run_fingerprint` deliberately does not write. `planner.py` mentions technology exactly once, and
it is an nmap/nuclei tag string (`"tags": "tech,misconfig,exposed-panels,takeovers"`), not a fact.

**Correction to the premise: detection does drive something, and it is prose.**
`guidance._rule_tech` (guidance.py:904) reads `live_hosts[i]["tech"]` - the versionless DISPLAY
strings, not the facts - and emits playbook text for a human ("Enumerate users via
/wp-json/wp/v2/users", "Search the exact version against CVE/ExploitDB"). It runs no test and
produces no observation. `tools._run_fingerprint` additionally emits a `Version disclosure: X Y`
finding at `confidence=candidate`. So the honest statement is: **detection drives ADVICE and a
disclosure note; it drives no test.**

## 2. What was actually closed

**One chain, end to end, on ONE technology: jQuery.**

```
served artifact  ->  library + VERSION (js-content-banner, CONFIRMED)
                 ->  advisory ranges from KNOWN_VULN            (which CVEs could apply)
                 ->  THE VERSION SELECTS WHICH PROBES RUN       (Q-021C, new)
                 ->  each probe READS THE SERVED BYTES for the code its CVE is about
                 ->  a presence control decides whether the library is even in that file
                 ->  CORROBORATED raises the rung / REFUTED deletes the finding / INCONCLUSIVE
                     changes nothing
                 ->  finding evidence cites the version AND what was observed in the bytes
```

**What it tests that it would not have tested without the detection.** Nothing in Apolaki ever
looked at a served jQuery file for the `__proto__` guard in `$.extend`'s deep-merge loop, or for
the self-closing-tag rewrite regex `rxhtmlTag`. Those two questions are asked only because a jQuery
version inside CVE-2019-11358 / CVE-2020-11022's range was detected, and they are asked of the
exact artifact that version was read from. A jQuery 3.6.0 is asked nothing. A jQuery 3.4.1 is asked
one of the two questions and not the other - **the version, not the library, picks the probe set.**

**Where it is dispatched from - PROVEN by execution, not by declaration.**
`agent/tools.py:5625` (`_run_js_review`) already calls `dependency_intel.fingerprint_js_content(text,
label)` with the body it just fetched over the real transport. The probes run there, at the one
moment the served artifact is in hand. `assess_component` and `vulnerable_component_finding`
(tools.py:5631-5633) consume the verdicts. **`agent/tools.py` was byte-unchanged by slice 1** - the
probes reached production through a dispatch that already existed - and no `deadcode_gate` exemption
was taken: there is no island. (Slice 2, section 7d, later changes exactly one line in that file for
an unrelated defect found while checking this one.)

`asvs_model.py:249` already names `run_js_review` as the sole engine that can emit
`vulnerable_component`, which is the same dispatch.

`tools.py` was offered to this lane when the tiers lane closed and was **not taken**. It was not
needed: the chain runs through a dispatch that already existed. Section 8 records the one thing
that WOULD need a new dispatch site, and it is not built.

### The dispatch proof - `ToolRegistry.execute`, real transport, real labs

Not a unit test and not a direct call into the module. `ToolRegistry.execute("run_js_review", ...)`
- the same entry the planner schedules - with a real `ScopeEngine`, against authorized labs on
`apolaki_default`. **4/4 checks passed.**

```
webgoat  jquery 2.1.4  success=True  reviewed 1 source(s), 6 finding(s)
   TITLE       : Potentially vulnerable component: jquery@2.1.4 (CVE-2020-11022, +2 more)
   proof_state : applicability_confirmed   confidence=lead   status=potentially_affected
   tags        : ['sca','dependency','jquery','needs-confirmation','applicability-confirmed']
   probe jquery-extend-proto-guard    corroborated  vulnerable_code_present_in_served_artifact
   probe jquery-selfclosing-rewrite   corroborated  vulnerable_code_present_in_served_artifact

webgoat  jquery 3.4.1  success=True  reviewed 1 source(s), 7 finding(s)
   TITLE       : Potentially vulnerable component: jquery@3.4.1 (CVE-2020-11022, +1 more)
   proof_state : applicability_confirmed
   probe jquery-selfclosing-rewrite   corroborated       <- the OTHER probe was never in range

dvga     bootstrap FP  success=True   vulnerable_component findings: 0     (was 1, three CVEs)
dvga     jquery 3.5.1  success=True   vulnerable_component findings: 0     (real zero)

[PASS] webgoat jquery 2.1.4   findings=1 states=['applicability_confirmed']
[PASS] webgoat jquery 3.4.1   findings=1 states=['applicability_confirmed']
[PASS] dvga    bootstrap FP   findings=0 states=[]
[PASS] dvga    jquery 3.5.1   findings=0 states=[]
4/4 checks passed
```

Three things this proves that no unit test could: the probes run inside the production engine path;
the `applicability` records and `proof_state` survive `ToolResult` construction (which Q-051 made a
finding-rewriting boundary); and the false positive is gone from the findings list a real mission
would store, not merely from a direct call into `dependency_intel`.

## 3. The false positive this removed, measured on a live lab

Not hypothetical. `dvga` (`dolevf/dvga`, on `apolaki_default`) serves
`/static/bootstrap/js/bootstrap.bundle.min.js`. Bootstrap 4.5.3 ships its own dependency check,
whose error string names a jQuery version. Run against `HEAD` before this change:

```
$ docker run --rm --network apolaki_default -v <snapshot>:/app apolaki-agent python fp_now.py
COMP: {"name": "jquery", "version": "1.9.1", "source": "js-content-banner",
       "confidence": "confirmed",
       "evidence": "'s JavaScript requires at least jQuery v1.9.1 but less than v4.0.0\")}};l.jQueryDetect",
       "location": "http://apolaki-dvga-1:5013/static/bootstrap/js/bootstrap.bundle.min.js"}
  assess: [{'ids': ['CVE-2020-11022', 'CVE-2020-11023'], ...}, {'ids': ['CVE-2019-11358'], ...}]
  TITLE: Potentially vulnerable component: jquery@1.9.1 (CVE-2020-11022, +2 more)
  sev: medium conf: lead status: potentially_affected
```

A medium-severity, three-CVE finding against a file that contains **no jQuery at all**, on a target
whose real jQuery is 3.5.1 and patched for all three. A version table cannot see this. Asking the
artifact can.

After the change, on the same live bytes: both probes return `REFUTED /
library_absent_from_artifact`, `assess_component` returns `[]`, and no finding is produced.

## 4. LIVE PROOF - five real served artifacts, four labs

Full output in section 4a. Run through `dependency_intel` against artifacts fetched over HTTP from
`apolaki_default`; no fixtures, no mocks.

| artifact (live) | version | `jquery-extend-proto-guard` | `jquery-selfclosing-rewrite` | finding |
|---|---|---|---|---|
| mutillidae `/javascript/jQuery/jquery.js` | 1.8.3 | CORROBORATED | CORROBORATED | 3 CVEs, `applicability_confirmed` |
| webgoat `/WebGoat/js/libs/jquery-2.1.4.min.js` | 2.1.4 | CORROBORATED | CORROBORATED | 3 CVEs, `applicability_confirmed` |
| webgoat `/WebGoat/js/libs/jquery.min.js` | 3.4.1 | *not in range* | CORROBORATED | 2 CVEs, `applicability_confirmed` |
| dvga `/static/jquery/jquery.min.js` | 3.5.1 | *not in range* | *not in range* | none |
| dvga `/static/bootstrap/js/bootstrap.bundle.min.js` | "1.9.1" (phantom) | REFUTED `library_absent` | REFUTED `library_absent` | **none (was 3 CVEs)** |

The 3.4.1 row is the one that proves the probes measure their own CVEs rather than "is this a new
jQuery": on a single artifact one probe is out of range and the other corroborates. The 3.5.1 row
is a real zero on a live target.

### The signature separation, measured before the probes were written

```
                     extend-locator   __proto__ guard   rxhtmlTag alternation
mutillidae 1.8.3         True             False                True
webgoat    2.1.4         True             False                True
webgoat    3.4.1         True             True                 True
dvga       3.5.1         True             True                 False
dvga bootstrap 4.5.3     False             -                   False
```

**A hypothesis of mine was falsified here and it changed the design.** The obvious library-presence
marker is `.fn.jquery`. Measured over the same six artifacts it is *inverted*: PRESENT in
`bootstrap.bundle.min.js` (which reads the host page's jQuery version) and ABSENT from the minified
jQuery 2.1.4 / 3.4.1 / 3.5.1 that three labs actually serve.

```
                       fn.init   jquery:   fn.jquery   expando
mutillidae 1.8.3        True      True      True        True
webgoat    2.1.4        True      True      False       True
webgoat    3.4.1        True      True      False       True
dvga       3.5.1        True      True      False       True
dvga bootstrap          False     False     True        False
dvga graphql.js         False     False     False       False
```

The presence control is therefore `.fn.init` AND `jquery:` (4/4 real jQuery, 0/2 non-jQuery).
`test_the_presence_control_needs_the_runtime_and_not_a_mention_of_the_name` pins the trap.

## 5. What was built

`agent/dependency_intel.py`, purely additive except three lines inside `assess_component` and the
`elif corr:` branch of `vulnerable_component_finding`.

* `CORROBORATED` / `REFUTED` / `INCONCLUSIVE`, and `APPLICABILITY_VERDICTS`.
* `APPLICABILITY_PROBES` - two probes for jQuery. Each declares `library`, `cves`, `looked_for` and
  a callable. It declares **which advisory it tests, never the boundary of that advisory**:
  `_probe_in_range` DERIVES the version range from `KNOWN_VULN` by CVE id, so the probe table and
  the advisory table cannot drift.
  `test_every_probe_names_cve_ids_that_the_advisory_table_actually_has` fails on a near-miss id.
* `_library_present(library, text)` - the negative control, an AND of two runtime markers.
  **Fails closed**: a library with no marker entry returns `(False, "no runtime marker is defined
  for this library")`, so a probe added without a presence control can never silently refute.
* `probe_applicability(component, artifact_text)` - runs every in-range probe, returns one record
  per probe with `probe / library / version / cves / looked_for / verdict / observed / reason /
  control / control_observed / evidence / location`.
* `applicability_records` / `refuted_cves` / `corroborated_records` - junk-tolerant readers.
* `fingerprint_js_content` attaches the records **at the point of detection**, because that is the
  only moment the served artifact exists. Re-deriving it downstream is the Q-046 shape.
* `assess_component` drops an advisory group only when **every** CVE id in it was REFUTED.
* `vulnerable_component_finding` gains `proof_state`, an `applicability` list, an
  `applicability-confirmed` tag, and evidence/oracle/steps that cite the probe.

### The three properties that keep this honest

1. **Absent is not a verdict.** A component with no `applicability` key is assessed byte-identically
   to before. Every existing caller - `fingerprint_url`, `make_component`, every test in
   `test_q021a_sca_proof.py` and `test_bbh.py` - is in that class.
   `test_no_applicability_record_leaves_assess_component_byte_identical` pins it, and it is the ONE
   new test that PASSES on unpatched HEAD.
2. **INCONCLUSIVE drops nothing.** A split bundle that carries the library but not the merge
   implementation returns `site_not_located`, and the advisory survives. Refuting on "I could not
   find it" is how this would have become a false-negative engine.
3. **A corroborated probe does not raise `confidence`, `severity` or `component_status`.** Locating
   vulnerable code is not observing exploitation. Only `proof_state`, the evidence text and the tag
   move. `test_a_corroborated_probe_raises_the_rung_and_nothing_else` asserts field-by-field
   equality against the unprobed finding.

## 6. What is STILL only a version reporter - stated plainly

The chain reaches `APPLICABILITY_CONFIRMED`. It does **not** reach `SAFELY_PROBED` or
`ORACLE_CONFIRMED`.

* **This probe reads bytes; it does not exercise behaviour.** It proves the CVE's code is in the
  file the target served. It does not prove the application ever reaches that code with
  attacker-controlled input. The findings still say `confidence=lead`,
  `component_status=potentially_affected`, `proof_gap=["behaviour_probe_not_run"]`, and the impact
  text still says exploitability "was NOT observed".
* **Every banner-derived technology is untouched.** `Server: Apache/2.4.7`,
  `X-Powered-By: PHP/5.5.9` and `<meta generator>` are `LOW`, `cve_eligible` excludes them, and
  nothing in this ticket changed that or should. Q-021B's live run recorded 5 versioned facts,
  0 CVE-eligible. **For the entire server/language/CMS half of the fingerprinter, Apolaki is still
  a version reporter, and this ticket did not change it** - see section 8 for why the fix there is
  a dispatch site I may not write.
* **Two probes, one library.** angular / lodash / handlebars / bootstrap / moment / dompurify are in
  `KNOWN_VULN` and have no probe; their findings are unchanged version-range leads.

## 7. Controls and mutation

Mandated order per change: reproduce -> diagnose -> implement -> targeted test that FAILS BEFORE
the fix -> negative controls -> mutation -> full regression.

**FAILS BEFORE THE FIX.** `agent/tests/test_techintel_chain.py` copied onto clean `HEAD`:

```
$ docker run ... -v <HEAD-snapshot>:/app apolaki-agent python -m pytest tests/test_techintel_chain.py -q
16 failed, 1 passed
```

The single pass is `test_no_applicability_record_leaves_assess_component_byte_identical` - the
negative control whose whole job is to be true both before and after.

### 7a. A REGRESSION I CAUSED, and the guard it bought

`test_q021a_sca_proof.py::test_retest_upgrade_that_is_still_in_range_stays_open` FAILED - a test in
a file this lane does not own, which is the best kind of catch.

`retest.evaluate` re-fingerprints a replacement body and asks `assess_component` whether the new
version is still inside a known-vulnerable range. The fixture body is 55 bytes:
`"/*! jQuery JavaScript Library v3.4.1 */ ;(function(){})();"`. My presence control found no jQuery
runtime in it, refuted both advisories, and `assess_component` returned `[]` - so an upgrade from
3.4.0 to 3.4.1, which is **still inside `<3.5.0`**, reported `verdict=closed`. A remediation lie,
and exactly the false negative the proof ladder exists to prevent.

Root cause, and it is not the fixture: `library_absent_from_artifact` is an **absence-of-evidence**
argument, and absence only argues anything when there was room for the evidence. 84kB of Bootstrap
with no jQuery runtime settles the question; 55 bytes of banner settles nothing.

Fix: `_MIN_ARTIFACT_FOR_ABSENCE = 2048`. Below it the verdict is INCONCLUSIVE, which by
construction drops nothing. The floor is measured, not guessed - the smallest real served library
artifact across the labs is 13,955 bytes (dvga `graphql.js`) and the four real jQuery files are
84kB-268kB, so 2048 sits far below every real artifact and far above every banner stub. Pinned by
`test_absence_is_only_a_refutation_when_there_was_room_for_the_evidence`, which drives the real
`retest.evaluate` and asserts `open`.

### 7b. Mutation - 14 mutants, 14 killed, 0 not-applied

Every mutant is verified APPLIED (the substitution must have changed the file) before its result is
believed. Run against `tests/test_techintel_chain.py` + `tests/test_q021a_sca_proof.py`.

| mutant | the guard it weakens |
|---|---|
| M1 presence control dropped | a version string in ANY file becomes the library |
| M2 refuted filter dropped | a refuted advisory still ships as a finding |
| M3 inconclusive counted as refuted | an undecidable probe deletes a real advisory |
| M4 guard searched across whole file | any mention of `__proto__` declares the file patched |
| M5 version range ignored | the version stops selecting the probes |
| M6 CVE ids not intersected | a probe claims a range belonging to a different CVE |
| M7 empty version probed | an empty version is treated as version 0 |
| M8 rung claimed without a probe | a version-only finding claims the applicability rung |
| M9 probe raises confidence | locating code is reported as observing exploitation |
| M10 extend window too small | an unminified patched build is reported vulnerable |
| M11 presence markers OR not AND | one weak marker is enough to call the library present |
| M12 junk records not filtered | persisted junk crashes a real assessment |
| M13 absence floor removed | a short body refutes -> still-vulnerable upgrade retests CLOSED |
| M14 too-small refutes anyway | an undecidable short read is promoted to a refutation |

**M4 SURVIVED on the first run.** The fixture meant to kill it used an *unquoted* `__proto__`
(`Widget.prototype.__proto__ = ...`), which `_JQ_PROTO_GUARD` does not match, and placed it inside
the window anyway. The test was wrong, not the code. It now pads the mention past
`_JQ_EXTEND_WINDOW` and uses the quoted form a real bundled sanitiser carries. That is the second
time in this project a mutant has exposed a vacuous test rather than a code defect.

## 7c. Full regression - MEASURED

| run | result |
|---|---|
| baseline, clean HEAD `93ca3dd` (Coordinator) | `2619 passed, 11 skipped, 9 xfailed, 0 failed` |
| slice 1 - the chain (`824e870`) | `2639 passed, 11 skipped, 9 xfailed, 0 failed` |
| slice 2 - the reconcile fix (section 7d) | `2641 passed, 11 skipped, 9 xfailed, 0 failed` |

`2639 - 2619 = 20`, exactly the number of tests in `test_techintel_chain.py` at that commit, and
`2641 - 2639 = 2`, exactly the two tests slice 2 adds. **No pre-existing test changed state in
either direction, in either run.** Skips and xfails are identical throughout, so nothing was
quietly disabled - a suite that grows by exactly the tests you wrote is the only version of "green"
worth quoting.

Rule 8c was load-bearing, not ceremonial: the shared tree carried another lane's uncommitted edits
to `agent/report.py` and `agent/tests/test_arsenal_gap.py` throughout. Every run above is against
`git archive HEAD agent` plus this lane's files only.

One measurement discipline worth recording: `agent/pytest.ini` already sets `addopts = -q`, so
passing `-q` again makes it `-qq`, which **suppresses the final count line entirely**. Two full runs
produced no total and looked ambiguous before that was diagnosed. Run the suite with no `-q`.

---

## 7d. Slice 2 - a tested guard that never ran where it mattered

Found while checking an adjacent claim rather than assuming it. `reconcile_components` exists to
remove one specific false positive, is covered by `test_q021a_sca_proof.py`, and its **only
production caller was `retest.py:123`**:

```
$ grep -rn "reconcile_components" --include=*.py agent/ | grep -v tests/
agent/dependency_intel.py:692:def reconcile_components(...)
agent/retest.py:119,123
```

`tools._run_js_review:5625` hand-rolled the same composition
(`fingerprint_js_content(...) + fingerprint_url(...)`) and did NOT reconcile. Reproduced on this
tree:

```
url  = https://t/assets/jquery-3.4.0.js       (the label an in-place patch never renames)
body = /*! jQuery JavaScript Library v3.6.0   (what is actually served, and patched)

components _run_js_review iterates: [('jquery','3.6.0','js-content-banner'),
                                     ('jquery','3.4.0','script-filename')]
findings on the SCAN path : ['Potentially vulnerable component: jquery@3.4.0 (CVE-2020-11022, +1 more)']
findings WITH reconcile   : []
```

So the guard shipped, was tested, and the false positive it removes went out on every scan - it was
only cleaned up if someone later ran a retest. Two copies of one composition rule with the guard on
only one of them.

**Fix:** `dependency_intel.components_for_artifact(content, location)` - the composition AND the
reconciliation, in the module that owns the rule. `tools.py:5625` becomes a single call to it.
`retest.py` is not this lane's file and already reconciles, so it is untouched; it could adopt the
same helper later.

**Negative control, and it is the important half:** reconciliation must be a no-op on the two shapes
every real lab artifact actually has. Measured live - webgoat serves `jquery-2.1.4.min.js` whose
body also says 2.1.4 (label and body agree) and `jquery.min.js` whose filename carries no version
at all. `test_reconciling_the_scan_path_does_not_drop_a_consistent_or_unlabelled_artifact` pins both,
and additionally pins that the Q-021C `applicability` records survive reconciliation - losing them
there would silently undo slice 1.

The live `ToolRegistry.execute("run_js_review", ...)` proof was re-run against the four labs with
this change in place: **4/4, byte-identical verdicts**. On real artifacts the label and the body
either agree or the label carries no version, so reconciliation is a no-op there - which is the
result that says this removes a false positive without touching a true one.

This is the one time `agent/tools.py` was written by this lane: one line, replacing a duplicated
rule with a call to the module that owns it.

## 8. For the Coordinator

### 8a. The report shape, since `report.py` is not mine

The chain is **already visible** in both renderers with no change, because it travels in `evidence`,
which the SCA finding has always rendered. Confirmed in the dispatch proof above - the evidence
string names the version, the CVE ids, the probe, what was OBSERVED in the bytes and the control.

Two structured fields are also on the finding now and are currently rendered by nothing. Wire them
only if you want the rung stated as a field rather than read out of prose:

| key | type | value |
|---|---|---|
| `proof_state` | str | one of `dependency_intel.TECH_PROOF_LADDER`; here `advisory_matched`, `applicability_confirmed` or `oracle_confirmed` |
| `applicability` | list[dict] | every probe that ran, refutations included: `probe / library / version / cves / looked_for / verdict / observed / reason / control / control_observed / evidence / location` |

Copy any fixture for that work from a real emitted record - the dispatch proof output above is one.
The tag `applicability-confirmed` is the exact string emitted (verified against a real record in
`test_a_corroborated_probe_raises_the_rung_and_nothing_else`); it is NOT `applicability_confirmed`,
which is the `proof_state` VALUE. Two spellings, two meanings, deliberately.

**The new fields survive persistence and export.** MEASURED, on the finding a real
`components_for_artifact` produced from webgoat's live jQuery 2.1.4:

```
JSON round-trip           : OK | 5274 bytes
proof_schema.is_confirmed : False (must be False -- still a lead)
demote_unproven keeps lead: lead
sarif level               : warning | security-severity 5.0 | confidence lead
proof_state survives      : applicability_confirmed
applicability survives    : [('jquery-extend-proto-guard','corroborated'),
                             ('jquery-selfclosing-rewrite','corroborated')]
```

The SARIF level and security-severity are IDENTICAL to the version-only finding, which is the
point: the applicability rung changed what the evidence can say, not how loudly the finding shouts.

**Name-collision check on `proof_state`, done before shipping it, because a key that already means
something else is the worst kind of near-miss.** MEASURED:

* `asset_graph.py:292` already reads `f.get("proof_state") or _di.tech_proof_state(f)` - on a
  TechnologyFact, using the SAME `TECH_PROOF_LADDER` vocabulary. Shared meaning, not a collision.
* `sarif_io.py:42 def _proof_state(f)` is a FUNCTION NAME, not a key read. It delegates to
  `proof_schema.is_confirmed`, which reads only `confidence` (verified at
  `proof_schema.py:171-176`). The new key is inert to SARIF, and since these findings keep
  `confidence="lead"` the SARIF demotion behaves exactly as before.

### 8b. The dispatch site I was offered, and what it was actually spent on

`tools.py` was freed to this lane mid-ticket. **The chain did not need it** - slice 1 reached
production through `_run_js_review`, a dispatch that already existed. The one line it was spent on
is slice 2 (section 7d): replacing a duplicated composition rule with a call to the module that
owns it, which removed a false positive that had been shipping past a guard written to stop it.

What WOULD need a genuinely new dispatch site is the server/language half - `Server: Apache/2.4.7`, `X-Powered-By: PHP/5.5.9` -
where the artifact is not a file we can read but a service we would have to ASK. That is a probe
that makes a request, and it is **not built, not tested and not designed here**. UNVERIFIED. The
honest handover is the measurement in section 6, not a design I have not run: I would rather this
lane end with one proven chain than with a second half-built one and a wiring box ticked from a
declaration.

### 8c. Two entries for the permanent mutation gate (`agent/mutation_gate.py`, not mine)

The 14 mutants above were run as a one-shot harness. Two of them guard the false-positive and
false-negative edges of this engine and belong in `MUTANTS` so they run forever. Both were
verified APPLIED and KILLED against the current tree; paste as-is.

```python
    ("dependency_intel.py", "probe_applicability: drop the library-presence control -- a version "
                            "string in ANY file becomes the library (measured: Bootstrap's "
                            "dependency-check banner raised a 3-CVE jquery@1.9.1 finding)",
     r"        if present is True:\n", "        if True:\n",
     "tests/test_techintel_chain.py::test_a_version_read_from_a_file_that_does_not_contain_the_library_is_refuted"),
    ("dependency_intel.py", "probe_applicability: remove the absence floor -- a body too short to "
                            "argue absence refutes anyway, and a still-vulnerable upgrade retests CLOSED",
     r"_MIN_ARTIFACT_FOR_ABSENCE = 2048", "_MIN_ARTIFACT_FOR_ABSENCE = 0",
     "tests/test_techintel_chain.py::test_absence_is_only_a_refutation_when_there_was_room_for_the_evidence"),
```

`test_mutation_gate.py::test_confirmed_producers_without_a_mutant_never_grow` is unaffected either
way: `dependency_intel.py` was already a confirmed producer (`CONFIRMED if ok else "lead"`), so this
ticket added no module to the uncovered set and the ceiling of 46 does not move. Adding these two
entries would *reduce* it by one.

The one structural note worth keeping: `_run_fingerprint` already calls `fp.record_facts(...)` and
already has the facts and the transport in the same scope, so a version-gated request probe has a
natural home there and would need no new state. Whoever builds it should reuse
`CORROBORATED / REFUTED / INCONCLUSIVE` and the rule that the VERSION selects the probe, so the two
halves of Q-021C speak one vocabulary.

## 9. Deliberately NOT done

* **No change to `CVE_ELIGIBLE`, `version_confidence` or the CONFIRMED/HIGH/LOW ladder.** A banner
  version still may not pull a CVE. The applicability probe operates on the artifact, which is a
  different question.
* **No change to `guidance._rule_tech`.** It reads `live_hosts[i]["tech"]` and emits advice; it is
  not this lane's file and rewriting it would move the report's playbook section.
* **`agent/fingerprint.py` and `agent/memory.py` untouched, and this was a CHOICE, not a
  constraint.** Both were writable all cycle and `tools.py` became writable mid-ticket, so a
  fact-driven request probe for banner versions was available to start. It was not started. The
  chain that could be closed AND PROVEN end to end runs entirely through `dependency_intel`, and a
  second half-built chain would have bought a wiring box ticked from a declaration instead of a
  second proof. Section 6 says exactly what that leaves undone.
* **No benchmark file, case, label, denominator or scorer touched.**
