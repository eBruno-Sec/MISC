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
| B1+B2 | `dependency_intel` fact model + ladder; `fingerprint` identity gate, `tech_facts()`, `record_facts()` | landed, suite green |
| B3 | `asset_graph`: `observe_technology()` + `build_from_engagement` projection + save/load | in progress |
| B4 | `_run_fingerprint` producer patch (Codex-owned file) | hand-off note only, section 6 |

Suite after B1+B2: `2285 passed, 9 skipped, 3 xfailed`. The reference on the same HEAD without this
lane's tests is `2241 passed, 9 skipped, 3 xfailed`; the 44 added are this ticket's. (The session
opened at `2238 passed, 9 skipped` - the Breaker and the source lane committed concurrently, which
is where the other 3 passed + 3 xfailed came from.)

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

### 3c. One shared-file edit, declared

`agent/deadcode_gate.py` gained ONE `ALLOWED_UNUSED_QUALIFIED` entry for `fingerprint.record_facts`.
The gate was right: a persistence function whose only production caller lives in another lane's file
is an island until that patch lands. **Delete that entry when the producer patch lands** - the gate
flagging it again is the point. Nothing else in that file was touched.
