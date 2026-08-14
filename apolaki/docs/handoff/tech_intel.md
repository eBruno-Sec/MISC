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
| B3 | `asset_graph`: `observe_technology()` + `build_from_engagement` projection + save/load | landed, suite green |
| B4 | `_run_fingerprint` producer patch (Codex-owned file) | **hand-off only, section 4** |

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

### 3d. One shared-file edit, declared

`agent/deadcode_gate.py` gained ONE `ALLOWED_UNUSED_QUALIFIED` entry for `fingerprint.record_facts`.
The gate was right: a persistence function whose only production caller lives in another lane's file
is an island until that patch lands. **Delete that entry when the producer patch lands** - the gate
flagging it again is the point. Nothing else in that file was touched.

---

## 4. HAND-OFF: the producer patch, for the owner of `agent/tools.py`

**Not applied by this lane.** `agent/tools.py` is Codex's this cycle (Q-023). Until it lands,
`recon["technology"]` is never populated in a live mission and the whole chain below it is inert -
that is the honest state of Q-021B, and it is why the dead-code gate entry above exists.

Everything else is in place: the fact model, the ladder, the identity dedupe, the rejection ledger
and the graph projection are all built, tested and reachable from `recon`.

### The patch - ONE line, in `tools._run_fingerprint` (currently at `agent/tools.py:3637`)

Immediately after the existing `for ... else:` block that updates `live_hosts` (i.e. after `final`
is defined and before `findings = []`), add:

```python
        # Q-021B: persist the version/source/evidence that the display projection above discards.
        # `record_facts` mutates recon: recon["technology"] gains identity-deduped TechnologyFacts
        # and recon["technology_rejected"] records every refused detection with a reason.
        fp.record_facts(self.recon, final, r.get("headers", {}), set_cookie, r.get("body", ""),
                        authenticated=bool(self.session_headers))
```

Nothing above it changes. `techs`, `names`, `lh["tech"]`, `fp.version_disclosures(techs)`, the
summary string and the `{"technologies": techs}` payload all keep their exact current values -
`fingerprint()` is byte-identical to what it returned before this ticket.

**Optional, only if the second regex pass over the body is worth removing** (it is one extra pass
per live host, capped at `CAP_HOSTS = 30` per mission): call `fp.detect(...)` once and hand the
records to both consumers.

```python
        detected = fp.detect(r.get("headers", {}), set_cookie, r.get("body", ""))
        fp.record_facts(self.recon, r.get("final_url") or url, r.get("headers", {}), set_cookie,
                        r.get("body", ""), techs=detected, authenticated=bool(self.session_headers))
        techs = [{k: t.get(k, "") for k in ("name", "version", "source", "category")}
                 for t in detected]
```

If you take this form, `techs=` **must** receive `detect()` records, not `fingerprint()` records -
the latter have no `evidence` key and the facts would persist with empty evidence. Passing nothing
is always safe.

### Two things NOT to do

* Do **not** feed `lh["tech"]` (the bare display strings) into a fact. It is where the six prose
  rows in `memory_assets` came from, and a fact built from it has no version, no source and no
  evidence.
* Do **not** widen `authenticated` to "a session existed at some point in the mission". It is the
  auth state OF THIS RESPONSE; an authenticated re-detection is a genuinely different observation
  and Q-021E depends on being able to tell them apart.

### Also outstanding, in files this lane does not own

| where | what | owner |
|---|---|---|
| `agent/tools.py:3637` | the patch above | Codex (Q-023) |
| `agent/main.py` `_warm_start` | re-seed `recon["technology"]` from `memory_assets` so a second mission starts with the facts (oracle 3's cross-mission half) | main.py owner |
| `agent/memory.py` | persist facts, and let the identity gate purge the 6 prose rows on next write | unassigned |
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

28 mutants written, **28 killed**. The two that mattered most:

* `M2_key_drops_product` initially **survived**. The nginx/PHP control passed on the `_VENDOR`
  field alone, not on the product - the key could drop `product` entirely and stay green. Fixed by
  adding `test_two_unmapped_products_sharing_a_version_never_merge`, where two products with no
  vendor hint make the product the only discriminator.
* `M16b_has_versions_needs_the_prop` proves the legacy branch is load-bearing: requiring a
  `version` prop would silently switch off the `ingest_intel` observation that has always fired.
