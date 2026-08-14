# Handoff - technology intelligence (Q-021B)

Lane: Builder, technology-intelligence. Owns `agent/fingerprint.py`, `agent/dependency_intel.py`,
`agent/intel_registry.py`, `agent/asset_graph.py` and their tests.

Scope of THIS ticket: **persist the fact**. Advisory matching (Q-021D), canonical identity /
version ranges (Q-021C) and probing (Q-021E) are explicitly out of scope and are NOT started here.

Related: [QUEUE.md](../QUEUE.md) Q-021B - [TECH_PIPELINE_BASELINE.md](../TECH_PIPELINE_BASELINE.md)

---

## 1. The defect, reproduced

Measured offline in the agent image on 2026-08-13, before any change:

```
>>> fp.fingerprint({'Server':'nginx/1.18.0','X-Powered-By':'PHP/7.4.3'}, 'PHPSESSID=x', '')
[{'name': 'nginx', 'version': '1.18.0', 'source': 'Server header', 'category': 'server'},
 {'name': 'PHP',   'version': '7.4.3',  'source': 'X-Powered-By',  'category': 'language'}]

what tools.py:_run_fingerprint persists:  ['nginx', 'PHP']
```

`version`, `source` and `category` are computed and dropped one line later. What reaches engagement
state is a list of bare display strings on `recon["live_hosts"][i]["tech"]`.

Second, independent defect reproduced in the same call - `_POWERED` admits prose as a product name:

```
>>> fp.fingerprint({}, '', 'This app is running a MultiJuicer Kubernetes cluster in safety mode. powered by nothing on.')
[{'name': 'a MultiJuicer Kubernetes cluste', ...}, {'name': 'nothing on.', ...}]
```

`'a MultiJuicer Kubernetes cluste'` is exactly 31 characters - the `{2,30}` bound of `_POWERED`
plus its leading character. Persisting that as a TechnologyFact would send it to a CVE feed as a
product name.

## 2. Status

| slice | what | state |
|---|---|---|
| B1+B2 | `dependency_intel` fact model + ladder; `fingerprint` identity gate, `tech_facts()`, `record_facts()` | landed `82538c4` |
| B3 | `asset_graph`: `observe_technology()` + `build_from_engagement` projection + save/load | landed `8b002aa` |
| B4 | `tools._run_fingerprint` producer patch + gate exemption removed | landed, proved live |

**`tools.py` was returned to this lane when Q-023 closed, so B4 is no longer a hand-off - the
producer is wired and proved against real labs (section 4a).** The chain is live end to end.

| suite | result |
|---|---|
| reference on this HEAD, without this lane | `2241 passed, 9 skipped, 3 xfailed` |
| after B1+B2 (+44 tests) | `2285 passed, 9 skipped, 3 xfailed` |
| after B3 (+15 tests) | `2300 passed, 9 skipped, 3 xfailed` |

The session opened at `2238 passed, 9 skipped`; the Breaker and the source lane committed
concurrently, which is where the other 3 passed and the 3 xfailed came from. No pre-existing test
changed state at any point.

## 3. What was built

### 3a. `dependency_intel` - the record and the ladder

* `make_tech_fact(...)` - the ONE constructor. A superset of `make_component`: `name` / `version` /
  `confidence` / `location` keep their meanings, so `cve_eligible`, `assess_component` and
  `reconcile_components` read a TechnologyFact with no second code path. Adds `vendor`, `product`,
  `component` (plugin/theme/module), `category`, `label`, `detector`, `host`, `authenticated`,
  `first_seen`, `last_seen`, `proof_state`, `component_status`, `version_conflicts`.
* `confidence` is **not a parameter**. It is derived from the detection source by
  `version_confidence(source)`, so a detector cannot assert its own trustworthiness.
* `version_confidence` fails closed: an unknown source is `LOW`, so adding a detector can never
  silently create CVE eligibility.

| source | rung | why |
|---|---|---|
| `js-content-banner` | `CONFIRMED` | the artifact declares its own version |
| `script-filename`, `cdn-path`, `script src` | `HIGH` | a label an operator can read back |
| `Server`, `X-Powered-By`, `meta generator`, cookies, HTML signatures, prose, **anything unknown** | `LOW` | a claim the target makes about itself |

  A `Server:` version is one config line to change and any reverse proxy rewrites it wholesale.
  `CVE_ELIGIBLE = {CONFIRMED, HIGH}` therefore keeps every banner-derived version out of CVE
  matching. This is the single largest false-positive source in this class.
* Proof ladder: `DETECTED_TECHNOLOGY -> VERSION_SUSPECTED -> ADVISORY_MATCHED ->
  APPLICABILITY_CONFIRMED -> SAFELY_PROBED -> ORACLE_CONFIRMED`. Q-021B tops out at
  `VERSION_SUSPECTED` by construction - nothing here can reach a higher rung.
* `tech_component_status()` returns `AFFECTED` only when a CVE-specific behaviour differential
  passes the EXISTING `behaviour_proof_ok`; otherwise `POTENTIALLY_AFFECTED`. `cve_eligible` is
  checked first, so a behaviour proof cannot upgrade a fact whose version was never established.
* `tech_fact_key()` = `host | vendor | product | component`. **Identity, never the version.**
* `merge_tech_facts()` - stronger evidence replaces weaker; a versioned reading beats a versionless
  one at equal strength; two equally strong contradictory versions keep the first and record the
  other in `version_conflicts` rather than dropping it; `first_seen` earliest, `last_seen` latest;
  `authenticated` true if the technology was ever seen authenticated.
* `_VENDOR` is a deliberately tiny CPE-style hint table. An unknown product gets `""`, never a
  guess - a wrong vendor is a wrong CPE and a wrong CPE matches someone else's CVEs. Canonical
  identity (full CPE / PURL) is **Q-021C's**, not this ticket's.

### 3b. `fingerprint` - evidence at the point of match, and an admission gate

* `detect()` is the new internal entry point: every detection now carries `evidence` - the exact
  header, cookie name, meta tag or matched signature that proved it - recorded WHERE the match
  happens rather than reconstructed afterwards.
* `fingerprint()` is unchanged in behaviour: it projects `detect()` onto the same four keys
  (`_PUBLIC_KEYS`), so `live_hosts[i]["tech"]`, `version_disclosures` and the report delta section
  see a byte-identical shape. `_POWERED` was deliberately **not** narrowed, for the same reason.
* Cookie evidence records only the matched cookie **name**. A `Set-Cookie` value is a live session
  token and evidence is quoted into reports and stored across missions.
* `name_rejection(name, source)` returns a REASON, not a bool: `empty`, `too_long`,
  `trailing_sentence_punctuation`, `prose_leading_stopword`, `too_many_tokens`, `bad_shape`,
  `prose_not_a_known_product`. A refusal that cannot say why is the same invisible drop this ticket
  removes.
* `_KNOWN_PRODUCTS` is **derived** from `_COOKIE_TECH` / `_JS_LIB` / `_BODY_SIG` / `_HEADER_TECH`
  (hoisted out of `_from_headers` for exactly this), plus the servers/languages the `Server:` regex
  extracts. Two hand-maintained lists of the same products is how a gate drifts out of step with
  its detector.
* Free-text sources (`powered-by text`) additionally require a known product. That also subsumes a
  "was this truncated at the regex bound?" check: a truncated fragment is never a known product.
* `record_facts(recon, ...)` is the persistence step - it **mutates recon**, because a return value
  is precisely what was being thrown away. Facts merge by identity into `recon["technology"]`;
  refusals accumulate in `recon["technology_rejected"]`, deduped and bounded at `MAX_REJECTIONS`
  (200), the same discipline as `tools._swallow`.

### 3c. `asset_graph` - the fact reaches the durable world model

* `observe_technology(fact)` is the single writer. The node kind is the **existing `component`**,
  with the technology detail as props - same instinct as `observe_param` putting `location` on the
  param rather than inventing a `schema` kind. A dimension on an existing node is schedulable
  through the path already built and tested; a new kind is not.
* Node key = `dependency_intel.tech_fact_key` (identity, never the version), so the same identity
  is one node in the graph and one entry in `recon["technology"]`.
* Graph confidence stops **below** the graph's `CONFIRMED` (1.0, which means VERIFIED):
  `CONFIRMED -> 0.9`, `HIGH -> 0.6`, `LOW -> 0.3`. `tested` stays `False`, so a technology node
  lands on the planner's untested worklist rather than looking settled. Detection is not a test.
* `host --runs--> component` (an existing rel, already used for host->service).
* `build_from_engagement` projects `recon["technology"]`. It deliberately does NOT read
  `live_hosts[i]["tech"]`: that display list would only add weaker, versionless duplicates of facts
  that now arrive with their evidence.
* `to_observations`: `has_versions` now requires a version to actually be known. A component node
  with **no** `version` prop is a legacy `ingest_intel` node whose KEY is the harvested version
  string, so it still counts - requiring the prop would have silently switched that long-standing
  observation off. **This is a no-op on every path that exists today**: the only two component
  writers are `ingest_intel` (no `version` prop -> legacy branch) and `observe_technology` (new,
  and inert until the producer patch lands). `technique_planner.py:106` derives `has_versions` on
  the flat path independently and is untouched.

### 3d. The gate exemption, taken and then RETURNED

While `tools.py` belonged to another lane, `agent/deadcode_gate.py` carried one
`ALLOWED_UNUSED_QUALIFIED` entry for `fingerprint.record_facts` - a persistence function whose only
production caller lived in a file this lane could not edit is an island, and the gate was right to
say so. Its own reason said to delete it when the patch landed.

**It is deleted.** The qualified dead-code count is back to exactly **37**, the pre-ticket baseline,
with no exemption carrying the difference. A gate exemption that outlives its cause is a declaration
that no longer matches the fact, which is the failure shape this project has recorded twice.

---

## 4. The producer - LANDED in `tools._run_fingerprint`

`fingerprint()` is called, its four-key projection feeds `live_hosts[i]["tech"]` exactly as before,
and then the facts are persisted. The detection now runs **once**: `detect()` produces the
evidence-carrying records, `public_view()` projects them onto the four keys the display path has
always used, so the two cannot disagree.

```python
        detected = fp.detect(r.get("headers", {}), set_cookie, r.get("body", ""))
        techs = fp.public_view(detected)
        ...                                   # live_hosts merge, unchanged
        fp.record_facts(self.recon, final, r.get("headers", {}), set_cookie, r.get("body", ""),
                        techs=detected, authenticated=bool(self.session_headers))
```

`recon` also now DECLARES `"technology": []` and `"technology_rejected": []` at construction rather
than creating them on first write, so no consumer has to tell "nothing was detected" from "the key
does not exist yet". A mutant deleting that declaration initially SURVIVED, because the test said
`in (None, [])`; the test now asserts both keys exist and are empty.

**`self.graph` is deliberately not written.** That is the graph the PLANNER reads
(`technique_planner:135` unions `graph.to_observations()`), so a technology node there would change
which techniques get scheduled. Q-021B is recon persistence, not detection - orchestration is
Q-021E. The report-time `build_from_engagement` projection already carries the facts to the durable
graph without touching the plan. `test_the_live_planning_graph_is_deliberately_untouched` pins it.

### Two things NOT to do to this code later

* Do **not** feed `lh["tech"]` (the bare display strings) into a fact. It is where the prose rows in
  `memory_assets` came from, and a fact built from it has no version, no source and no evidence.
* Do **not** widen `authenticated` to "a session existed at some point in the mission". It is the
  auth state OF THIS RESPONSE; an authenticated re-detection is a genuinely different observation
  and Q-021E depends on telling them apart.

### 4a. LIVE PROOF - real labs, real transport, real dispatch

Not a unit test. `ToolRegistry.execute("run_fingerprint", ...)` - the same dispatch `planner.py`
schedules per live host - against four authorized local labs on `apolaki_default`, through the real
HTTP transport, then the real report-time projection saved to disk and read back. **12/12 checks
passed.**

```
1. REAL dispatch
  http://apolaki-dvwa-1:80/            success=True   stack: Apache 2.4.25
  http://apolaki-juice-shop-1:3000/    success=True   stack: none
  http://apolaki-mutillidae-1:80/      success=True   stack: Apache 2.4.7, PHP 5.5.9, and that the database username
  http://apolaki-bwapp-1:80/           success=True   stack: Apache 2.4.7, PHP 5.5.9

2. recon['technology'] -- 5 TechnologyFacts, versioned 5/5, CVE-eligible 0/5
  apolaki-dvwa-1/apache         2.4.25  low  evidence='Server: Apache/2.4.25 (Debian)'
  apolaki-mutillidae-1/apache   2.4.7   low  evidence='Server: Apache/2.4.7 (Ubuntu)'
  apolaki-mutillidae-1/php      5.5.9   low  evidence='X-Powered-By: PHP/5.5.9-1ubuntu4.25'
  apolaki-bwapp-1/apache        2.4.7   low  evidence='Server: Apache/2.4.7 (Ubuntu)'
  apolaki-bwapp-1/php           5.5.9   low  evidence='X-Powered-By: PHP/5.5.9-1ubuntu4.14'

6. graph -> JSON -> reload: 5 component nodes, 5 host--runs-->component edges, versions intact
```

Three things this run proves that no unit test could:

1. **The banner control fires on genuinely ancient real software.** PHP 5.5.9 and Apache 2.4.7 are
   real and long EOL. Apolaki records the version, quotes the header verbatim, and still reports
   `cve_eligible=False` / `potentially_affected`, because a version read off a header is a claim.
   A scanner that emitted CVEs here would look more productive and be less honest. Upgrading these
   is exactly what Q-021C/D/E are for - an advisory match plus a probe, not a banner.
2. **The prose gate fired on live bytes, and the display path did not.** Mutillidae's
   database-offline page produced `'and that the database username'` from the powered-by regex. The
   same run shows it PRESENT in `live_hosts[i]["tech"]` (unchanged, by design) and ABSENT from
   `recon["technology"]`, with `reason=prose_leading_stopword detector=fingerprint.body.prose`
   recorded. That is the display path proven untouched and the fact path proven clean, in one run.
3. **Juice Shop returned a real zero.** Its root document is an Angular shell that ships no
   identifying header and no inline library, so zero facts and zero refusals - control (c), on a
   live target, distinguishing an honest zero from a broken detector.

Reproduce with `scripts`-free one-shot: mount `agent/` read-only into the agent image on
`--network apolaki_default` and run the proof script; it exits non-zero if any check fails.

### Still outstanding, in files this lane does NOT own

| where | what | owner |
|---|---|---|
| `scripts/liveness.sh` CHECKS | an entry that fails when `recon["technology"]` is empty against a target with a known banner | Coordinator |
| `agent/report.py` | a technology inventory; today only the delta section shows `("tech", "New Technology")` | Q-021F |

## 5. Deliberately NOT done

* **`intel_registry` is untouched.** Its staged trust model (`candidate -> validating -> validated
  -> fixture_backed -> reviewed -> production`) is keyed on `source | cve | source_type` (`_rid`)
  and gates INTERNET INTEL - advisory records - not observations made directly against the target.
  A TechnologyFact is a first-party observation whose trust is already stated by the
  CONFIRMED/HIGH/LOW ladder plus the proof ladder. Forcing it through a second, differently-shaped
  trust model would give this pipeline two answers to the same question, which is the exact defect
  Q-021A was raised to fix. The registry becomes relevant at **Q-021D**, when feed-derived advisory
  records arrive and need staging.
* **No advisory matching, no version ranges, no probing.** Q-021C/D/E. `TECH_PROOF_LADDER` names
  those rungs so the vocabulary is fixed, but nothing here can reach them.
* **No CMS plugin/theme enumeration.** The `component` field exists and is part of the dedupe key,
  so a plugin detector can be added without moving any node identity - but no such detector was
  written, and `_KNOWN_PRODUCTS` is derived from the tables that exist.
* **`_POWERED` was not narrowed.** Narrowing it would change `fingerprint()`'s output for every
  existing caller, including the report delta section and the benchmark path. The gate sits on the
  persistence path instead, which is why no benchmark number can move.

## 6. Controls, and the mutants that prove they bite

All five mandated controls are in the suite and each was verified failing before its fix.

| control | test |
|---|---|
| a version + source persist end to end, not just in a return value | `test_tech_facts_keep_the_version_that_fingerprint_computed`, `test_record_facts_writes_into_recon`, `test_end_to_end_a_served_version_reaches_disk` |
| the same version on two products never merges | `test_same_version_on_two_products_never_merges`, `test_two_unmapped_products_sharing_a_version_never_merge`, `test_the_node_key_is_identity_so_two_products_never_collide` |
| a spoofed `Server:` banner stays LOW and non-CVE-eligible | `test_spoofable_server_banner_stays_low_and_is_never_cve_eligible`, `test_a_spoofed_ancient_banner_is_recorded_but_never_cve_eligible` |
| no version => POTENTIALLY_AFFECTED, never proven | `test_versionless_detection_is_detected_only_and_potentially_affected`, `test_versionless_fact_stays_potentially_affected_even_with_a_behaviour_proof` |
| no benchmark number moves | `test_fingerprint_return_shape_is_unchanged`, `test_prose_still_reaches_the_display_path_unchanged`, `test_record_facts_leaves_the_display_list_alone`, `test_legacy_component_nodes_still_count_as_versions` |

### "No benchmark number moved" - measured, not argued

A differential against the pre-ticket `fingerprint.py` (extracted from `82538c4~1`), over the
cartesian product of 17 header sets x 11 `Set-Cookie` values x 21 bodies chosen to hit every
detector branch:

```
cases compared: 3927   differences: 0
RESULT: IDENTICAL
```

Both `fingerprint()` and `version_disclosures()` are byte-identical on all 3927. The harness was
itself checked: the two modules are genuinely different builds (`record_facts` / `detect` exist in
one and not the other), and the comparison does report a difference when given one.

Supporting facts, all measured:

* `agent/dependency_intel.py` across the whole ticket: **0 deleted lines**, purely additive.
* `agent/asset_graph.py`: exactly two deleted lines, the old unconditional `has_versions`.
* The only two `component`-node writers are `ingest_intel` (no `version` prop -> legacy branch,
  unchanged) and `observe_technology` (new, and inert until the producer patch lands).

28 mutants written, **28 killed**. The two that mattered most:

* `M2_key_drops_product` initially **survived**. The nginx/PHP control passed on the `_VENDOR`
  field alone, not on the product - the key could drop `product` entirely and stay green. Fixed by
  adding `test_two_unmapped_products_sharing_a_version_never_merge`, where two products with no
  vendor hint make the product the only discriminator.
* `M16b_has_versions_needs_the_prop` proves the legacy branch is load-bearing: requiring a
  `version` prop would silently switch off the `ingest_intel` observation that has always fired.
