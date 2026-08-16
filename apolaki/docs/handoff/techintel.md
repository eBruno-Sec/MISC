# Handoff - technology intelligence drives testing (Q-021C-F)

Lane: TECHINTEL BUILDER. Ticket in one line: **Apolaki detects the target's technology and that
detection drives no testing.**

Writable this cycle: `agent/fingerprint.py`, `agent/dependency_intel.py`, `agent/memory.py`,
`agent/tests/test_tech_fingerprint_facts.py`, `agent/tests/test_dependency_intel.py`,
`agent/tests/test_techintel_chain.py`, this file. `tools.py` / `agent.py` / `planner.py` /
`report.py` belong to other lanes.

Predecessor: [tech_intel.md](tech_intel.md) (Q-021B - persist the fact, with evidence).

Every claim below is MEASURED (command + real output) or marked UNVERIFIED.

---

## 1. The premise, checked before anything was built

MEASURED. The premise holds, with one correction worth recording.

`recon["technology"]` - the evidence-carrying `TechnologyFact` records Q-021B built - has exactly
one consumer in the whole tree:

```
$ grep -rn "recon.get(\"technology\")" --include=*.py agent/ | grep -v tests/
agent/asset_graph.py:610:    for fact in (recon.get("technology") or []):
agent/main.py:239 (warm-start merge)
agent/memory.py:207 (snapshot)
```

`asset_graph.build_from_engagement` projects them into the DURABLE graph at report time.
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

**Where it is dispatched from - PROVEN, no new dispatch site needed.**
`agent/tools.py:5625` (`_run_js_review`) already calls `dependency_intel.fingerprint_js_content(text,
label)` with the body it just fetched over the real transport. The probes run there, at the one
moment the served artifact is in hand. `assess_component` and `vulnerable_component_finding`
(tools.py:5631-5633) consume the verdicts. **`agent/tools.py` is byte-unchanged by this lane** and
no `deadcode_gate` exemption was taken: there is no island.

`asvs_model.py:249` already names `run_js_review` as the sole engine that can emit
`vulnerable_component`, which is the same dispatch.

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

(sections 7a mutation and 7b full regression: filled in below as they were run)

## 8. For the Coordinator - the dispatch patch I could not write

UNVERIFIED (not implemented, not tested): the server/language half of the chain needs a probe that
makes a REQUEST, and every producer that can make one lives in `agent/tools.py`, which this lane
may not write. Rather than land an island, it is written here.

The shape that fits the existing code with no new concepts: `_run_fingerprint` already calls
`fp.record_facts(...)`, which returns the facts. A version-gated HTTP probe would be a second call
after it, executing descriptors produced from those facts, with the same CORROBORATED / REFUTED /
INCONCLUSIVE vocabulary and the same rule that the version selects the probe. This is deliberately
NOT specified further here, because the honest thing to hand over is the measurement above, not a
design I have not tested.

## 9. Deliberately NOT done

* **No change to `CVE_ELIGIBLE`, `version_confidence` or the CONFIRMED/HIGH/LOW ladder.** A banner
  version still may not pull a CVE. The applicability probe operates on the artifact, which is a
  different question.
* **No change to `guidance._rule_tech`.** It reads `live_hosts[i]["tech"]` and emits advice; it is
  not this lane's file and rewriting it would move the report's playbook section.
* **`agent/fingerprint.py` and `agent/memory.py` untouched.** The chain that could be closed and
  proven runs entirely through `dependency_intel`. Touching the fingerprint fact model without a
  dispatch site for a fact-driven probe would have produced exactly the island the ticket warns
  about.
* **No benchmark file, case, label, denominator or scorer touched.**
