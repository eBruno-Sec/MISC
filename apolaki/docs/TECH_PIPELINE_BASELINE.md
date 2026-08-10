# Technology pipeline — measured baseline (pre-audit)

Written **before** the Codex audit lands, so the Distillation Agent can check each audit claim
against a measured fact instead of re-deriving the repository from scratch. Every row below was
verified against live code on 2026-08-10, not read from a design doc.

Pipeline under audit:
`detection → identity/version normalization → intelligence matching → applicability validation →
planner-directed safe probing → deterministic oracle + negative control → evidence/replay →
graph/API/UI/report`

Related: [QUEUE.md](QUEUE.md) Q-021 · [CODEBASE_REVIEW.md](CODEBASE_REVIEW.md) · [LEDGERS.md](LEDGERS.md)

---

## Stage 1 — detection · **EXISTS AND IS WIRED** (preserve)

`agent/fingerprint.py` (138 lines), pure and unit-tested. Detects from response headers
(`_SERVER_VER` regex on `Server`/`X-Powered-By`-style headers), `Set-Cookie` names (`_COOKIE_TECH`),
`<meta name="generator">`, "powered by / built with / running" prose, a JS-library table (`_JS_LIB`)
and body signatures (`_BODY_SIG`), then `_dedup()`.

**It is not an island** — I checked for this specifically, because this project has already recorded
a wrong "unreachable engine" claim caused by grepping one file and missing dynamic dispatch:
- `agent/planner.py:234` schedules `run_fingerprint` for every live host (`CAP_HOSTS = 30`).
- `agent/tools.py:3508` `_run_fingerprint` does the one GET and calls `fp.fingerprint(...)`.
- `agent/tools.py:379` declares it in the tool table; `:73` gives it `PermissionLevel.ACTIVE`.
- `agent/wstg_catalog.py:97,99` maps WSTG-INFO-02/08/09 to it.

**Any audit claim that fingerprinting does not exist or does not run is FALSE.** Reject it.

**Real limits** (these are the honest gaps): no CMS plugin/theme/extension enumeration, no
reverse-proxy or API-gateway identification, no hosting-platform or site-builder detection, no
auth-product detection. Detection is a single unauthenticated GET per host — there is no second
recon cycle and no authenticated re-detection.

## Stage 2 — identity/version normalization · **THE VERSION IS COMPUTED, THEN DISCARDED**

`fp.fingerprint()` returns records carrying `name`, `version` and `source`. `_run_fingerprint` then
does, at `agent/tools.py:3521`:

```python
names = [t["name"] for t in techs]
...
lh["tech"] = list(dict.fromkeys((lh.get("tech") or []) + names))
```

**`version` and `source` are dropped one line after being computed.** What survives into engagement
state is a de-duplicated list of bare strings on `recon["live_hosts"][i]["tech"]`. There is no
persisted TechnologyFact, no vendor, no component, no version confidence, no evidence pointer, no
authentication state, no `first_seen`/`last_seen`. The only place the version escapes is a
`low`/`candidate` "Version disclosure" finding built from `fp.version_disclosures(techs)`.

This is the smallest, highest-value fix in the whole pipeline: the data the rest of Q-021 needs is
already being produced and thrown away.

**A separate, better ladder already exists** in `agent/dependency_intel.py` (266 lines) —
`CONFIRMED` (version proven from served content) / `HIGH` (from filename or CDN path) / `LOW`
(heuristic), with `CVE_ELIGIBLE = frozenset({CONFIRMED, HIGH})` so LOW is **never** CVE-eligible.
That constant is already the enforcement point for "unknown version ⇒ `POTENTIALLY_AFFECTED`".
It also already carries safe alias mapping (`_FLEX_ALIAS`, `_CDN_NAME_FIX`). It is wired at
`agent/tools.py:5193`, but it applies **only to JavaScript libraries** — not to CMS, servers,
frameworks or plugins.

**Any audit claim that Apolaki has no version-confidence model is FALSE** — it has one, scoped to JS
libraries. The gap is that the general fingerprinter does not use it.

## Stage 3 — intelligence matching · **PARTIAL, and the feed set is the gap**

`agent/intel_feeds.py` (406 lines) ingests exactly four sources, all tier A, all machine-readable:

| key | source |
|---|---|
| `kev` | CISA Known Exploited Vulnerabilities |
| `capec` | MITRE CAPEC |
| `attack` | MITRE ATT&CK (Enterprise) |
| `exploitdb` | Exploit-DB index (`files_exploits.csv`) — index only; exploit code is never fetched or run |

`exploits_for_finding()` and `exploitdb_for_product()` match by exact CVE / product-version key.

**Absent: NVD/CPE, OSV, GitHub Security Advisories, WPScan.** So there is no general
product+version → CVE resolution and no version-range semantics at all. This is a genuine gap and
audit claims about it should be accepted (subject to the Watcher's feed-quality review).

`agent/intel_registry.py` already implements a state ladder — `candidate → validating → validated →
fixture_backed → production` with confidence weights — but it is not applied to technology facts.

## Stage 4 — applicability validation · **DOES NOT EXIST**

Nothing checks whether a matched advisory actually applies: no version-range evaluation, no
configuration-applicability test, no backported-patch handling. Accept audit claims here.

## Stage 5 — planner-directed probing · **THE BREAK IN THE PIPELINE**

`technique_planner.derive_observations()` has this signature (`agent/technique_planner.py:46`):

```python
def derive_observations(surface=None, harvest=None, findings=None, leads=None, code_intel=None,
                        authenticated=False, graph=None):
```

**There is no `recon` parameter, and grepping the module for `recon.get` / `recon[` returns
nothing.** `recon["live_hosts"][i]["tech"]` — the only place detected technology lives — is
therefore structurally unreachable from the observation set that gates and ranks techniques.

**This is the measured root cause of Q-021**: technology detection terminates in a display string
and a low-severity disclosure finding. Nothing converts a detected technology into an observation,
so nothing can plan a technology-specific probe. Detection and testing are not connected.

## Stage 6 — oracle + negative control · **N/A until stage 5 exists**

There is no technology-specific probe to carry an oracle. The generic machinery is sound and must be
reused, not re-created: `proof_schema.demote_unproven` + `proof_schema.is_confirmed` already enforce
"unproven ⇒ lead" at every report surface (fixed in `707b3b9`).

## Stage 7 — evidence/replay · **generic only**

The finding-level evidence, PoC bundle and retest machinery exist and work. Nothing records
*detection* evidence: which request, which header, which byte proved the technology identity.

## Stage 8 — graph / API / UI / report · **thin**

`agent/report.py:1422,2585` surfaces `("tech", "New Technology")` in the **delta** section only —
i.e. technology appears only when it changes between scans. There is no technology inventory in the
report, and no technology/version-confidence/advisory-match/proof-status view in the UI.
`agent/asvs_model.py:151` maps an ASVS objective to `("run_fingerprint", "dependency_intel")`.

---

## How to use this during distillation

1. Claims about stages 1, 2 (ladder exists) and 3 (four feeds exist) that assert **absence** are
   false — the capability exists and must be **preserved and extended**. Reject or correct them.
2. Claims about stages 4, 5, 7-for-detection and 8 that assert absence are **consistent with what I
   measured**. Still verify independently — this baseline is evidence, not scripture.
3. The single seam that unblocks the most: **stage 2 → stage 5**. Stop discarding `version`/`source`,
   persist a TechnologyFact, and give `derive_observations` a way to see it.
4. Sequencing stands: **Q-019 before Q-021.** A technology fact is worth little while the crawl
   fetches 12 pages and probes 36 URLs of a 2756-URL surface.
