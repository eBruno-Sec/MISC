# QUEUE — the one canonical, dependency-ordered work queue

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
| 2 | `proof_schema` — the proof gate must inspect `vulnerable_component` | todo |
| 3 | `retest` — a patched component must CLOSE, not stay OPEN | todo |
| 4 | structured `cves` on the SCA finding so KEV can match it | todo |
| 5 | `success_oracle` vs `oracle` — one canonical key, normalised at one chokepoint | todo |
| 6 | SARIF still un-demotes proof-gate-demoted rows (bonus) | todo |

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

### Q-013 · `PUT /findings` bypasses all three `findings_gate` invariants · **HIGH** · `proposed`
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

### Q-014 · Operator lead-confirmation is silently re-demoted, and gate-routed leads cannot be confirmed at all · **HIGH** · `proposed`
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
