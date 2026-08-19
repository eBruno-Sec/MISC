# tech-intel lane 2 - Q-021D / Q-021E / Q-021F

Lane: tech-intel (Builder). Started 2026-08-18. Branch/HEAD at start: `e66f4ca`.
Write surface: `agent/intel_registry.py`, `agent/intel_extractor.py`, `agent/archive_intel.py`,
new tests under `agent/tests/`, this file. Everything else is a handoff patch, not an edit.

Rule for this file: every claim is MEASURED (command + real output) or UNVERIFIED. Written as I go.

---

## 0. Apparatus - what I read, and the positive control for each zero

Container discipline: throwaway `docker run --rm --network apolaki_default -v .../agent:/app -w /app
apolaki-agent`, plus `-v "apolaki_bbh_data:/data"` where real data is needed. `MSYS_NO_PATHCONV=1` on
every container call (Git Bash rewrites `/app` into `C:/Program Files/Git/app` and the failure reads as
an empty result, not an error - the tail sweep hit this and so did I).

Platform health before starting - MEASURED, `curl -s http://localhost:8000/missions`: returns the
mission list (top entry `57cc3b49`, Q-051 arsenal-gap run2). API up. No build run at any point.

### 0.1 The local feed snapshots are REAL and OFFLINE. This is the fixture ground.

MEASURED - the named volume, not a mount of `agent/`:

```
docker run --rm -v "apolaki_bbh_data:/data" apolaki-agent sh -c "ls -la /data/intel_feeds"
  capec.json     107571 bytes   Jul 30 21:04
  kev.json       208065 bytes   Jul 30 21:04
  manifest.json     186 bytes   Jul 30 21:04
```

NEGATIVE CONTROL for the mount, and the exact trap the house rules warn about - the same call with
only `agent:/app` mounted:

```
intel_feeds._dir()  -> /app/data/intel_feeds     exists: False
intel_feeds.load()  -> snapshot keys: []
```

That empty dict is the apparatus, not the world. Every number below that involves a feed snapshot was
taken with `-v "apolaki_bbh_data:/data"` and `load('/data/intel_feeds')`.

MEASURED - the real KEV snapshot shape, read from the volume:

```
keys: ['kev', 'capec', 'manifest']
kev keys: ['source', 'tier', 'catalog_version', 'count', 'cwes', 'cves_meta']
  count      1656
  cwes       183 entries   (e.g. CWE-1023, CWE-114, CWE-116, CWE-1173, CWE-1188)
  cves_meta  1656 entries
cves_meta['CVE-2002-0367'] = {"product": "Microsoft Windows", "date_added": "2022-03-03", "ransomware": false}
cves_meta['CVE-2024-38475'] = {"product": "Apache HTTP Server", "date_added": "2025-05-01", "ransomware": false}
manifest = {"refreshed_at": 1785445474.39,
            "feeds": {"kev": {"ok": true, "count": 1656, "tier": "A", "version": "2026.07.29"},
                      "capec": {"ok": true, "count": 559, "tier": "A", "version": ""}}}
```

Note the field names I read, because a zero from the wrong one would be an instrument fault:
`kev.cves_meta` (a dict keyed by CVE id), NOT `kev.cves` and NOT `kev.items` - both of those exist as
keys in other feeds' parse output and are **absent here**; `s['kev'].get('cves')` returns `[]` and
`s['kev'].get('items')` returns `[]`. Reading either would have produced "KEV has no CVEs".

This matters for Q-021D: it means there is a **locally held, offline, tier-A catalogue of 1656 CVEs
with per-CVE product metadata and a real snapshot timestamp** already in the product, already loaded
inside a mission (`agent.py:1284 intel_feeds.load()`). It is the corroboration source the promotion
ladder never had.

---

## 1. Q-021D - reproduced, then split. Status: promotion path SHIPPED; resolver blocked on ownership.

### 1.1 Baseline reproduced on my own instrument

MEASURED, throwaway container at worktree HEAD, before any edit of mine:

```
intel_registry.stats()        {'total': 0, 'by_state': {}}
intel_registry.production()   0
intel_sources.enabled_sources()  []   (of 18 sources)
grep -rn "advance(" --include=*.py agent/  ->  tests/test_intel_registry.py ONLY
```

POSITIVE CONTROL that the instrument was looking at a live store and not a dead import - a real
governed fetch with the connector's own injectable `http=` seam, using the REAL `nvd` parser:

```
intel_connectors.fetch('nvd', env={'INTEL_SRC_NVD':'1'}, http=<injected>, now=1.0)
  -> status ok, records 1
  -> {"source": "nvd", "source_type": "vuln_enrichment", "cve": "CVE-2024-38475",
      "confidence": 0.3, "validation_state": "candidate", "allowlisted": true, ...}
```

So the tail sweep's finding reproduces exactly: a record CAN enter, it lands at `candidate`, and
nothing in product code could move it up.

### 1.2 What was actually missing, stated precisely

Not "a caller for `advance()`". The ladder had no **witness**: no rule saying what evidence promotes
a candidate. Adding a caller without one would have been a rubber stamp.

The witness that already exists offline is the **local CISA KEV snapshot**: 1656 exact CVE ids, each
with the product CISA names, plus a real `manifest.refreshed_at` stamp, loaded inside a mission today
at `agent.py:1284`. A record from `nvd` / `ghsa` / `cve_v5` whose exact CVE is in that catalogue has
been named by a source that did not produce it.

Three rules make it evidence rather than a heuristic:

- **Exact CVE only.** Never the CWE. `intel_feeds.known_exploited_cwes` already carries the standing
  warning that a KEV-listed CWE does not make an arbitrary finding of that class KEV-listed.
- **Independence.** A record whose own `source` is `cisa_kev` can NEVER be witnessed by the KEV
  snapshot. KEV is loaded twice in this codebase (`intel_feeds` snapshot + `intel_connectors._parse_kev`)
  and without this rule the second copy would silently validate the first. That is the ticket's
  "de-duplicate, do not add a third", written as a rule instead of a comment.
- **A ceiling.** The pass stops at `validated`. `fixture_backed` still needs a regression fixture,
  `production` still needs a human `reviewed_by`. "Auto-promote internet intel into executable
  production skills" is on `intel_sources.PROHIBITED` and that rule is correct.

`validating` is load-bearing, not a waypoint: every candidate examined moves there, and a record with
no independent witness **stops** there.

### 1.3 SHIPPED - `agent/intel_registry.py`, `agent/tests/test_intel_promotion.py`

- `corroborate(snapshots=None)` - the evidence-carrying pass, offline, idempotent.
- `_kev_witness(snapshots)` - the catalogue read; returns `({}, stamp)` on a cold read so the caller
  can tell "examined nothing" from "matched nothing".
- `trusted(min_state="validated")` - the consumer contract. Reads validated-and-above, walks the rungs
  top-down out of `by_state`, and excludes `rejected` **by name**.
- `production()` now returns `trusted("production")` - one definition of "at or above this rung".
- `ingest()` drives `corroborate()` after storing (entry is still always `candidate`; the pass is a
  separate step that goes through `advance()` like any other caller).

**`rejected` is a real trap, not a hypothetical.** It is the LAST element of
`intel_sources.VALIDATION_STATES`, so its index is the HIGHEST. A plain `index >= threshold`
comparison ranks a rejected record ABOVE a production one. There is a test for exactly that.

### 1.4 THE PROOF - one record reaching `validated` through PRODUCT CODE, not through a test

MEASURED, isolated snapshot of HEAD + only my two files, real KEV volume mounted at the PRODUCTION
path (`-v apolaki_bbh_data:/app/data`), driving the FastAPI route functions `main.intel_fetch` and
`main.intel_registry_view` directly. No test helper calls `advance()`. The only injection is
`intel_connectors._default_http`, the connector's own documented seam, so the governed pipeline itself
runs untouched:

```
feed dir: /app/data/intel_feeds exists: True
KEV loaded from the PRODUCTION path: count= 1656 catalog= 2026.07.29

BEFORE: {'total': 0, 'by_state': {}, 'production': 0}
intel_fetch -> {"source":"nvd","status":"ok","records":2,"ingested_as_candidates":2}
AFTER : {'total': 2, 'by_state': {'validated': 1, 'validating': 1}, 'production': 0}

  TRUSTED validated CVE-2024-38475 conf= 0.55
    evidence: ['examined against cisa_kev 2026.07.29',
               'exact CVE CVE-2024-38475 independently listed by cisa_kev
                (catalog 2026.07.29, snapshot_at 1785445474.3897574) as Apache HTTP Server']
    witness : {'source': 'cisa_kev', 'via': 'local snapshot (intel_feeds)',
               'catalog_version': '2026.07.29', 'snapshot_at': 1785445474.3897574,
               'cve': 'CVE-2024-38475', 'product': 'Apache HTTP Server', 'ransomware': False}
  PARKED  validating CVE-2024-9999 conf= 0.35
audit log entries (outward requests recorded): 1
```

Both CVEs entered on the same fetch. The one CISA really lists climbed; the one it does not stopped
at `validating`. `production` stayed 0. That is the ticket's definition of done, items 2 and 4:
`/intel/registry` shows a non-zero `by_state` after a governed fetch, and a record reached `validated`
without a test touching it.

**NEGATIVE CONTROL (a), same apparatus, default configuration** - `intel_connectors._default_http`
replaced with a function that RAISES if called, so an outward request cannot pass silently:

```
enabled sources: [] of 18
intel_fetch(nvd) -> {"status": "disabled", "records": 0, "ingested_as_candidates": 0,
                     "note": "connector disabled; enable its allowlist entry (+ credential) to use it"}
registry: {'total': 0, 'by_state': {}, 'production': 0}
audit log (outward requests): 0
consumer sees: [] | production: []
```

Empty and **labelled `disabled`**, with zero outward I/O. Not an empty result labelled clean.

### 1.5 Tests: 13 new, and every one of them killed a mutant

MEASURED, `docker run ... pytest tests/test_intel_promotion.py tests/test_intel_registry.py` ->
**18 passed** (13 new + 5 pre-existing, all still green).

Fixtures are copied verbatim out of `/data/intel_feeds/kev.json`, values recorded at the top of the
test file. `CVE-2024-38475` was verified present in the real 1656-entry catalogue and `CVE-2024-9999`
verified absent, which is also why the two pre-existing registry tests stay green for the RIGHT
reason rather than by accident: their CVEs (`CVE-2024-9999`, `CVE-2024-7`) are genuinely not
known-exploited.

MUTATION TESTS - each mutant run against an isolated copy, each killed by the intended assertion:

| mutation | outcome |
|---|---|
| drop the same-source independence rule | FAILED `test_a_kev_sourced_record_is_never_witnessed_by_the_kev_snapshot` |
| make every examined record witnessed | FAILED `test_the_pass_is_a_real_filter_not_a_conveyor` (+3 more) |
| drop `snapshot_at` from the evidence string | FAILED `test_a_witnessed_candidate_climbs_to_validated_with_evidence` |
| `trusted()` stops excluding `rejected` | FAILED `test_trusted_reads_validated_and_above_...` |
| `ingest()` stops driving the pass (island restored) | FAILED `test_ingest_drives_the_promotion_pass` |
| consumer default `min_state="production"` | FAILED `test_the_consumer_default_is_validated_and_above_not_production_only` |

The last one is worth naming: it **survived the first time**. Every other test passed the threshold
explicitly, so the one clause the ticket is actually about - reading validated-and-above instead of
production-only - was unasserted. The test was added because the mutant lived.

### 1.6 Dead-code ratchet: measured on HEAD + my changes ONLY, and it went DOWN

The live worktree is NOT a valid instrument here: `agent/deadcode_gate.py` and
`agent/tests/test_deadcode_gate.py` are both dirty with another lane's in-flight work
(`git diff --stat` -> 261 insertions). Scanning it reported `count=62 baseline=37 ok=False`, which is
that lane's number, not mine. MEASURED against isolated snapshots instead:

```
clean HEAD                       qualified count=35  baseline=37  ok=True
HEAD + intel_registry.py + my test   count=34  baseline=37  ok=True
```

Down one: `intel_registry.advance` was in `QUALIFIED_BASELINE_SET` as known-dead and now has a
production caller. `by_state` did NOT become dead in the process - `trusted()` is built out of it on
purpose. `scan()` (bare-name) also passes with no unused and no stale allowlist entries.

### 1.7 What is NOT done, and why - the resolver, `advisories_for()`

Gap 1 of the ticket (product -> advisory resolution) is **not shipped**, and the reason is a
measurement, not an omission.

The resolver's only possible consumers are `dependency_intel.py` (the SCA path) and `report.py`.
**I own neither.** A resolver added to `intel_registry.py` with no consumer would be a new top-level
function with no production caller: `scan_qualified` would count it and the ratchet would go 34 -> 35
and eventually past the baseline. The gate would be right to fire. Shipping it would move the island
up a level rather than remove it, which is the exact reasoning the postMessage lane recorded.

So it goes in section 4 as a patch, to land in the SAME commit as its consumer.

One thing measured while scoping it, worth carrying: the `nvd` parser leaves `affected_product` as
`None` (see the real record in 1.1), so an NVD record cannot be attributed to a product on its own.
After corroboration it CAN be, because the KEV catalogue supplies the product string as an OBSERVED
value (`witness.product == "Apache HTTP Server"`). That is the difference between probing with an
observed value and probing with an invented one, and it means the resolver should match on
`affected_product` (GHSA fills it) OR `witness.product`, and count anything with neither as
`unattributed` rather than dropping it silently.
