# Apolaki systematic codebase review

One file. Every sweep, every finding, every change. Append only — a finding is never deleted, it is
marked RESOLVED with the commit that resolved it, so this doubles as the reviewer's audit trail.

**Scope:** 173 shipping modules / 53,970 lines, plus 172 test files / 19,724 lines.

**Method.** Two tracks, because neither alone is honest:
- **Sweeps** — exhaustive pattern analysis across all 173 modules. Complete coverage, narrow depth.
  Doesn't fatigue, doesn't skip. This is how the silent-failure defect was found.
- **Reads** — full-depth reading of the five hot files that hold 36% of the code and essentially all
  engine execution, orchestration and reporting: `tools.py` (8184), `main.py` (3352), `agent.py` (3100),
  `report.py` (3003), `bie.py` (1725).

A claim in here is either **MEASURED** (a command and its output) or marked **UNVERIFIED**. No finding is
asserted from reading alone when it can be counted.

---

## Severity scale

| | meaning for a *scanner* specifically |
|---|---|
| **CRITICAL** | can turn a real vulnerability into a silent pass, or emit a false positive |
| **HIGH** | capability exists but cannot run, or a result cannot be trusted/attributed |
| **MEDIUM** | correctness or robustness defect with a bounded blast radius |
| **LOW** | hygiene; no effect on findings |

---

## S1 — Silent failure handlers · **CRITICAL** · PARTIALLY RESOLVED (`40f59b7`)

**Measured 2026-08-10**, `agent/` excluding tests:

```
824  except clauses
769  `except Exception` (broad)
328  followed IMMEDIATELY by a bare `pass`
 22  record anything at all
192  broad handlers in tools.py · 104 agent.py · 65 main.py · 48 juiceshop_solvers.py · 46 bie.py
```

**The defect.** Apolaki cannot distinguish *"I checked and found nothing"* from *"my check crashed."* A
swallowed exception produces no finding, and no finding is byte-identical to a clean target. This is the
worst available failure mode for a scanner and it is the root cause behind most of the individual bugs
found this session.

**Not theoretical — five instances in one session:**

| instance | consequence |
|---|---|
| `dt.DOM_SCAN_JS` never defined, eaten by bare except | 3 families silently detected nothing |
| `httpx` unimported in `_graphql_argument_injection` | whole GraphQL tool raised, eaten |
| `poc.redact` never existed behind a `hasattr` | model-visible bodies never redacted |
| my own traversal header pass used `parse_qsl` unimported | would have shipped as dead code **reporting clean** |
| `_run_form_cmdi` probed with invented values | baseline and probe failed identically; vulnerable field read clean, no exception needed |

The codebase already diagnosed this once and never generalised it — `agent.py:1204`: *"swallowed artery
error is invisible and undebuggable."*

**Why it blocks everything else.** Benchmark misses are currently unattributable. cmdi 28.6%, xpathi
40.0% — oracle-declined or crashed? Unknowable. It also partly manufactures our headline precision: when
anything goes wrong, emit nothing.

**Fix shipped (`40f59b7`)** — the *mechanism*, not a mass rewrite. Removing 328 handlers would be wrong;
most are legitimately defensive. The defect is that they are **silent**.
- `ToolRegistry.swallowed`: bounded 500-entry ledger, fields truncated.
- `ToolRegistry._swallow(exc, where, target)`: records instead of discarding.
- `_run_web_probes` reports it: `0 anomaly signal(s) — WARNING: 1 check(s) failed to execute: cookie_flags`.
- Tests both directions: a forced failure must appear; a clean run must NOT carry the warning.

**Remaining (#54):** propagate `_swallow` across all engine paths; liveness gate asserts zero swallows on
standing labs; `except: pass` in an engine path becomes a lint failure like the no-island rule.

---

## S2 — Async correctness · **CLEAN**

Swept all 173 modules for the classic event-loop killers.

| check | result |
|---|---|
| coroutine called without `await` | **none** |
| `time.sleep` inside `async def` | **none** — all 3 sites (`cloud_iam.py` ×2, `intel_feeds.py`) are in sync functions |
| sync HTTP (`urlopen`/`requests`) inside `async def` | **none** — all 5 sites are in sync functions |
| unbounded `communicate()` | 1 found → see S3 |

Conclusion: the "everything hangs" instinct is **not** an event-loop starvation problem. It is S1.

---

## S3 — Fire-and-forget task with no reference · **MEDIUM** · RESOLVED (`40f59b7`)

`main.py:3352` — `asyncio.create_task(proc.communicate())`. asyncio holds only a **weak** reference, so
the task could be garbage-collected mid-execution, and an unbounded `communicate()` on a hung child
leaks it for the life of the process.

Fixed: held in a module-level `_BACKGROUND_TASKS` set with a done-callback discard, and bounded by
`wait_for(300s)` with a kill on timeout.

---

## S4 — Engines with no possible caller · **HIGH** · RESOLVED (`pending commit`)

### First pass was WRONG — recorded because the error is instructive

I first reported **10 unreachable engines**, from: 91 engines defined in `tools.py`, 81 referenced in
`agent.py`, therefore 10 orphans. **That test is invalid.** `execute()` dispatches by
`getattr(self, "_" + tool_name)`, so an engine is reachable if *anything* emits its name — and there are
**two** emitters, not one:

1. the deterministic planner (hardcoded lists in `agent.py`) — the only one I checked;
2. the **agentic path**, via the `CLAUDE_TOOLS` spec handed to the model.

Re-measured against both: **8 of the 10 are in `CLAUDE_TOOLS`** and reachable by the agentic path.
`enumerate_ids` is reachable too — it is advertised under a bare name with a thin `_enumerate_ids`
method (line 1803) forwarding to `_run_enumerate_ids` (line 1759).

**Wrong by nine.** Same failure mode as the two "missing engine" calls earlier in the session:
concluding from one grep. The lesson is now a permanent test rather than a note.

### The real finding: exactly ONE engine

**`run_external_surface`** — implemented (~70 lines, writes `recon["external_surface"]`), registered in
`PermissionLevel` tagged `#114`, and present in **neither** `CLAUDE_TOOLS` **nor** the planner. Nothing
could invoke it. It is the completed feature from task #14 (*external attack-surface recon*): built,
marked done, and it never ran once.

**Fixed:** added to `CLAUDE_TOOLS` so the agentic path can select it.

**Guarded, both directions** (`tests/test_engine_reachability.py`):
- every defined engine has a possible caller, aliases counted;
- **every advertised spec name resolves to a real `_<name>` method** — the stronger direction, which
  catches a rename that updates the method but not the spec, i.e. a tool the model can select that then
  fails at call time;
- plus a non-vacuity assertion, because a scan over empty sets passes for free.

---

## S5 — Falsy-default substitution · **CLEAN**

98 `x or DEFAULT` sites. Refined to those replacing a falsy value with a **non-empty** default — the
shape that silently discards a meaningful empty input: **zero**. All 98 are `or []` / `or {}` / `or ""`,
empty→empty, harmless.

## S6 — Mutable default arguments · **CLEAN** — none.

## S7 — ReDoS / nested quantifiers · **CLEAN**

No true nested-quantifier regexes in shipping code. (The one real instance found earlier this session —
`crawl.py` `_TAG_RE` — was bounded at the time it was written.)

## S8 — Our own command injection (`shell=True`) · **CLEAN**

Only match is `codereview.py:93`, which is Apolaki's own *detector rule* for the pattern, not a use.

## S9 — Proof-gate coverage · **HEALTHY**

54 modules emit `confidence: confirmed`; `demote_unproven` / `get_findings_gated` are applied in
`db.py`, `report.py`, `main.py`, `agent.py` — the four real boundaries. (Regression from #51, where the
gate reached 1 of 14 consumers, has held.)

## S10 — Secret leakage · **HEALTHY**

No logging of `session_headers` / `Authorization` / cookies / passwords / api keys. Nine redaction
helpers across `bie`, `capture`, `poc`, `vault`, `sarif_io`, `field_authz`, `mitm_addon`,
`tool_provenance`, `codereview`.

---

## Standing conclusion

The codebase is **healthier than the S1 headline suggests**. Seven of ten sweeps came back clean or
healthy. There is exactly one systemic defect — **S1, silent failure** — and it is the one that matters,
because it is the mechanism by which every other bug this session stayed invisible.

Ranked by effect on findings:
1. **S1** — silent failures. Mechanism shipped; propagation outstanding (#54).
2. **S4** — one dead engine, now reachable and guarded.
3. Everything else — clean.

---

## Change log

| date | commit | change |
|---|---|---|
| 2026-08-10 | `40f59b7` | S1 mechanism: swallow ledger + `_run_web_probes` reporting; S3 orphaned task |

---

## S11 — Full-mission orchestration · **CRITICAL** · two defects, one fixed

Found by running Apolaki **as a product** (`/engage` → `/run`, deterministic, ZAP enabled) instead of
calling engines directly. Every measurement before this bypassed the orchestrator and could not see it.

**Baseline result: a real mission against a target carrying 1,415 known vulnerabilities returned ZERO
findings in 40 seconds and reported "coverage completed."** The harness scores 41.3% on the same target.
That gap was never in the engines.

### S11a — recon seeds the host root, not the scoped path · RESOLVED

```
ScopeEntry(value='owaspbench', base='https://owaspbench:8443', path='/benchmark')
validate('https://owaspbench:8443/benchmark/')  -> True
validate('https://owaspbench:8443/')            -> False
    "host is in scope, but the request path is outside the pinned scope path"
```

Recon started at the host root; scope **correctly refused it**; the crawl got nothing; the planner
scheduled nothing. Scope was right — nothing seeded a URL satisfying it.

Not a benchmark quirk: **any engagement scoped to `example.com/app/` returns zero findings and calls the
target clean.** That is the worst outcome a scanner can produce, and it was shipping.

Fixed in `agent.run()`: seed each scope entry's `base + pinned path`, validated before use, reported in
the run log. Regression tests cover all three directions — the root is refused, the pinned path IS
seeded, and a bare-host scope seeds nothing extra so this cannot invent targets.
Result: **0 → 2 findings.**

### S11c — document-relative links were silently dropped · **CRITICAL** · RESOLVED (`57afc3f`)

**The root cause of the entire orchestration failure.** `_http_probe`:

```python
if l.startswith("http") or l.startswith("/"):
    abs_links.append(urljoin(base_url, l))
```

`cmdi-Index.html`, `./x`, `../y` — discarded. **Apolaki could not crawl any site that links relatively.**
The Benchmark landing page links to all 11 category indexes relatively, so every one was thrown away
along with all 2740 test cases, and the mission reported "coverage completed".

The guard existed to fix a protocol-relative doubled-host bug — but `urljoin` *was* that fix. The guard
was redundant the moment it was written and cost the crawler most of the web. Now `urljoin` resolves
everything; only non-navigable schemes (`mailto:`, `javascript:`, `tel:`, `data:`, …) are excluded.

### S11d — robots.txt / sitemap.xml never read · **HIGH** · RESOLVED (`57afc3f`)

Found by auditing surface sources against what a mature scanner uses. Both appeared in exactly two
places: a **noise-exclusion list** (actively filtered out) and the Natas CTF solver. A general scan read
neither. `crawl.parse_robots` / `parse_sitemap` now feed `_surface_crawl`. `Disallow` is harvested as
**recon, not obeyed** — that is the entire value.

### S11b — the crawler only ran for AUTHENTICATED scans · **CRITICAL** · RESOLVED (`57afc3f`)

`crawl.bfs_frontier` has exactly one caller in the entire codebase: `_authenticated_recrawl`
(`agent.py:1572`). There is no unauthenticated crawl path at all.

So an unauthenticated mission fetches its seed URLs, mines served JS, and **never follows a link**. The
fixed mission above reached `/benchmark/` and still found only 2 incidental issues (a jQuery CVE and a
credential in a comment, both from JS recon on the index page) because it never walked to any of the
2,740 test-case pages.

Consequence: **unauthenticated black-box scanning — the default mode and the one most engagements start
with — has no surface discovery.** Coverage is whatever the operator typed in, plus JS mining.

Fix: hoist the depth-bounded BFS out of `_authenticated_recrawl` into a mode-independent crawl phase,
running for authenticated and unauthenticated missions alike, with the same depth/frontier caps
(`BBH_CRAWL_DEPTH`, frontier 30) and the same scope gate. The authenticated pass then becomes what its
name says — the persona-specific *extra* — rather than the only way surface is ever discovered.

**Why the test suite never caught either.** 1,634 tests, all green, throughout. They test engines and
pure logic; nothing asserted that a mission against a known-vulnerable target finds anything. A
whole-product smoke test — engage a mission against a standing lab, assert findings > 0 — would have
caught both instantly, and is the single highest-value test missing from this repo.

---

## S12 — The browser sensor has never worked · **CRITICAL** · mostly RESOLVED

Found while researching whether SPA/XHR discovery had the same auth-gating as S11b. It did not — but the
browser path was broken in a different and worse way.

`browser_engine.observe()` is the browser-as-sensor used by `_browser_harvest_surface` (JS-rendered
links, forms, XHR/GraphQL endpoints, CSP, storage). It drives the **browserless sidecar over CDP**, a
separate path from `bie.py`, which uses local Playwright and works fine — which is why the liveness gate
stayed green while this was dark.

Three defects, in the order they were peeled back:

| # | defect | evidence | status |
|---|---|---|---|
| a | sidecar not running by default | `CDP_BROWSER_URL=http://headless-chrome:3000`, profile `browser` opt-in → `Errno -5 No address associated with hostname` | started |
| b | script returned a bare object | browserless v2 requires a `{data, type}` envelope → HTTP 400 | FIXED |
| c | unguarded `localStorage` read | `SecurityError: Access is denied for this document` on an opaque origin → **the whole observation discarded** | FIXED |
| d | no `ignoreHTTPSErrors` | `ERR_CERT_AUTHORITY_INVALID`, `url = chrome-error://chromewebdata/` | FIXED |

**(c) is the instructive one.** One inaccessible storage object threw out of `page.evaluate()`, browserless
answered 400, `drive()` turned that into an empty result, and `observe()` reported `browser: False`. Links,
forms, scripts, CSP — all discarded because of a property read that is *expected* to fail on a blank page.

**(d) proved by measurement**, not assumption:

```
no launch params      -> err=ERR_CERT_AUTHORITY_INVALID  url=chrome-error://chromewebdata/  anchors=6
ignoreHTTPSErrors:true -> err=None  url=https://owaspbench:8443/benchmark/  anchors=11
```

The 6 "anchors" without the flag were **Chrome's own error page**. With it, 11 — exactly the 11 category
indexes. The HTTP engine already runs `verify=False`; the browser must match it or the two disagree about
what is reachable. Certificate problems are the TLS engine's job to report, not a reason to refuse to look.

`observe()` now returns `browser: True` where it previously always returned `False`.

### Still OPEN

`_OBSERVE_JS` navigates with `waitUntil: 'networkidle2'` (25s). The direct probe above used
`domcontentloaded` and got 11 anchors; `observe()` still returns 0 links on the same page, so
networkidle2 most likely never settles and the nav times out into the script's `catch (e) {}`.
**Next step:** `domcontentloaded` with a short settle, rather than waiting for network silence a busy
page may never reach.

### Pattern

S12c is S1 again at a different layer: a failure that is *expected* in normal operation, swallowed, and
reported as a clean empty result. Third instance today (`DOM_SCAN_JS`, `parse_qsl`, now this).

---

# Adversarial verification pass — 2026-08-10 (Breaker)

Three claims attacked. Every number below is MEASURED. Suite runs use a copy of the tree mounted over
the baked `/app`: `docker run --rm -v <tree>:/w -w /w apolaki-agent:latest python -m pytest`. Baseline
1670 passed / 2 skipped, plus the one known foreign failure `test_deadcode_gate::test_the_method_ratchet_holds`.

## V1 — Q-00A, the BIE errored-control false positive (`agent/bie.py`, UNCOMMITTED) · **PLAUSIBLE**

The claim is true and the fix is real. It does not reach CONFIRMED on two of the eight checks.

| check | result |
|---|---|
| 1 · failed before the fix | **PASS** — the new test file run against `git archive HEAD`: `10 failed, 6 passed`, each failure the exact `assert 'confirmed' == 'lead'` |
| 2 · mutants | **12 of 15 killed** by the intended assertion; 3 survive and are proven EQUIVALENT (below) |
| 3 · negative controls | **PASS** — the genuinely-PUBLIC resource, the SECURE param-swap and every live-control true positive keep their old verdicts |
| 4 · false positives | **PASS** — the change can only move `confirmed` to `lead`; no path gains a confirmation |
| 5 · replay | **PASS** — pure functions, identical output on repeat runs |
| 6 · clean environment | **FAIL** — `docker run apolaki-agent:latest grep -c _control_ran /app/bie.py` returns **0**. The running container returns `6` only because it was `docker cp`'d. Uncommitted and unbaked: the fix vanishes on the next rebuild |
| 7 · surfaces | **FAIL** — see V3; a BIE `lead` still exports through CSV with no confidence column, under a title containing the word "confirmed" |
| 8 · generalises | **PARTIAL** — the unseen-variant test passes, but the same defect shape is left open one line below the fix |

### The three surviving mutants are equivalent, not test holes

The previous Breaker reported "two mutants survived" and died before naming them. Re-derived by mutating
each changed line and running `tests/test_bie_errored_control.py`:

| mutant | result |
|---|---|
| M10 · `judge_param_swap` PUBLIC test reverted to `anon is not None` | SURVIVED |
| M13 · `judge_client_side_authz` PUBLIC test reverted to `anon is not None` | SURVIVED |
| M1 · `judge()._ran` isinstance guard removed | SURVIVED (a third, not previously reported) |

All three are **equivalent mutants**, proven from the producer rather than argued: `_fetch`
(`bie.py:1483`) writes an `error` key on exactly one code path, and that path hardcodes `status 0`. So
`_control_ran(x) is False` together with `_s(x) == 200` is unreachable in production, and reverting
those two guards changes no reachable verdict — exactly as the author's own comment admits ("changes
nothing at all"). M1 is unreachable for the same reason: the call site only ever passes a dict or
`None`, and `_s(None)` short-circuits to `False` before `x.get` is touched.

**Those three lines of the diff are inert.** Not harmful, but not the fix either. The fix is M5/M11/M14
— the missing-control gate and the two explicit `lead` gates — and all three of those are killed.

### RESIDUAL, and this one is live: `bie.py:292` was never converted

`judge()`'s THIRD control (requirement 6, "the attacker's own object differs from the owner's") still
reads `if control is not None and _s(control) == 200 and ...`. That is the identical fall-through the
ticket exists to close: a dead `control` has status 0, so the rejection cannot fire. MEASURED, two
personas whose objects are byte-identical (an empty basket, a default profile — a common shape):

```
control ALIVE   -> rejected  | the attacker's own object is byte-identical to the owner's
control ERRORED -> confirmed | the attacker persona's browser received the owner's object verbatim
```

`control` comes from the same `_fetch` as the other two probes (`bie.py:1590`), so a dead one is exactly
as likely. The fix closed the two MANDATORY controls and left the optional one open.
**Recommended:** `if control is not None and not _control_ran(control): return lead` — distinguish
"never attempted" (`None`, legitimately optional) from "attempted and died". Production code; the owner
fixes it, not the Breaker.

## V2 — the 0.0% FPR claim · **REJECTED**

The scorer's lead-handling is correct on both sides. The claim fails somewhere else, and worse.

**The lead question, settled.** `_detected` (`owasp_bench.py:208`) requires `c not in _UNPROVEN`, so a
lead is never a true positive; on a clean case it falls to the `tn` branch, so it stays in the FPR
denominator. Verified on both full-suite artifacts: `clean cases DROPPED from the denominator: 0`,
`clean cases that ERRORED but still counted as TN: 0`. The macro denominator is honest too — 41.3% is
divided by all 11 Java categories, with `crypto, hash, trustbound` counted as 0. No mirror-image bug.

**What is actually wrong.** `_detected` only credits a finding whose family matches the case's own
category. That is right for TPR and wrong for FPR: on the FP side it discards every cross-family
finding. On `owaspbench_java_FULLSUITE_41pct_20260810.jsonl`:

```
clean cases SCORED (the FPR denominator) : 1059   [tn=1059 fp=0]
clean cases with ANY finding of any family: 22
```

All 22 are clean `securecookie` cases carrying **CONFIRMED** `path_traversal` findings. Every one is
scored a true negative.

**They are false positives.** The oracle's own evidence string is `"../bbh-canary.txt: canary filename
reflected through file handling path"` — it confirms on REFLECTION. Negative controls against
`BenchmarkTest00404`:

```
TRAVERSAL payload ../bbh-canary.txt     status=200 reflected=True
PLAIN     bbh-canary.txt (no ../)       status=200 reflected=True   <- no traversal at all, still reflects
ARBITRARY APOLAKI-NOT-A-FILE-9182       status=200 reflected=True   <- not even a filename
REAL traversal ../../../../etc/passwd   status=200 body contains 'root:x:0:0' ? False
```

The page echoes anything; no file is ever read. Confidence is `confirmed`, so it survives the proof gate
and would appear in a client report.

**It is worse than 22 rows: the pathtraver score rests on the same oracle.** Sampling 4 of the 92
pathtraver true positives and re-running the engine live yields 22 path_traversal findings, oracle tally
`{'reflection-only': 22}`. Not one proves a file read. The category shows FPR 0.0% only because the
clean pathtraver cases happen not to echo — measured on 8 of the 135, all
`reflects-canary=False, engine-fired=False`. The oracle discriminates nothing; the benchmark's shape
does. That is a signature, not a capability.

**Restated with cross-family findings counted (same run, same key):**

| | official 11-cat macro | FPR | securecookie |
|---|---|---|---|
| as shipped (within-family only) | **41.3%** | **0.0%** | 52.8%, FPR 0.0% |
| any confirmed finding on a clean case is an FP | **34.9%** | **2.1%** | -18.2%, FPR **71.0%** |

Ignoring cross-CWE findings follows the official BenchmarkUtils convention, so 41.3% / 0.0% is
defensible *as a Benchmark number*. It is **not** defensible as the product claim in `docs/STATUS.md`,
which presents 0.0% FPR as a property of the tool. The tool emits a confirmed path traversal on 22 of 31
clean securecookie cases, and the measurement is constructed so it cannot see them.

**Recommended:** (a) fix the path-traversal oracle to require file content, a directory listing or a
filesystem error — reflection of the payload is not proof; (b) publish a second, product-level FPR
beside the Benchmark-convention one, counting any confirmed finding on a clean case; (c) re-measure
pathtraver's 69.2% once the oracle proves file access, and expect it to fall.

## V3 — the commits of 2026-08-10 · **REJECTED** (`707b3b9`, `1709f59`)

### `707b3b9` — the proof gate still does not survive two exporters

The HTML card and the markdown/JSON headline are genuinely fixed. Verified by feeding a
confirmed-but-unproven `idor` through `proof_schema.demote_unproven` (which demotes it to `lead`) into
each surface:

| surface | result |
|---|---|
| HTML card `_conf_badge` | LEAD — correct |
| `_confirmed_counts` | `{}` — correct |
| **CSV** `/report/{id}/csv` | exports as `critical` with **no confidence column at all** (`_CSV_FIELDS`, `report.py:2942`). Nothing in the file distinguishes a demoted lead from a proven finding |
| **SARIF** `/mission/{id}/sarif` | `level=error`, `security-severity=9.5`, `properties.confidence=lead`. GitHub code scanning and DefectDojo read `level`/`security-severity`, not `properties` — it ships as a full-severity error |

Both exports read through the gate (`_report_bundle`, `db.get_findings_gated`) and then discard its
verdict at render time. The same defect the commit message describes, in the two formats it did not touch.

### `_confirmed_counts` vs the other consumers — two live desyncs

`707b3b9` created `proof_schema.UNPROVEN_CONFIDENCE` so the vocabulary "can never fork". It already has:

* **`risk_score` (`report.py:1232`)** keeps a private tuple `("lead", "unconfirmed", "informational")`,
  a strict subset of the shared frozenset. MEASURED on one finding:

  | confidence | badge | `_confirmed_counts` | `risk_score` |
  |---|---|---|---|
  | candidate | LEAD | `{}` | **40 / High** |
  | info | LEAD | `{}` | **40 / High** |
  | tentative | LEAD | `{}` | **40 / High** |
  | lead | LEAD | `{}` | 0 / No Confirmed Risk |

  One report can therefore show "no confirmed findings" beside a High risk score.
  `sarif_io.import_sarif()` writes `confidence="candidate"`, so this is a live path, not a hypothetical.

* **`report.py:213`, `:1129`, `:2635`** use `str(f.get("confidence")) == "confirmed"`, which treats a
  finding with NO confidence key as unconfirmed. `proof_schema.is_confirmed` treats it as confirmed, and
  the docstring notes most engines only set the field when demoting. Same fork, opposite direction: the
  assurance panel's `n_conf` undercounts exactly the findings the badge calls CONFIRMED.

Also `bie.finding()` hardcodes `"Cross-user object read confirmed in the browser runtime"` into the
TITLE for leads as well as confirmations. With no confidence column in the CSV, a BIE lead exports as a
row whose only confidence signal is the word "confirmed" in its own title.

### `1709f59` — the `max_hostless` gate shipped with zero coverage · RESOLVED by this pass

The commit is one branch. MEASURED by deleting that branch entirely from `liveness.verdict`:

```
--- ENTIRE max_hostless BRANCH DELETED -> liveness tests: 30 passed, 1645 deselected
```

`test_liveness_surface_check.py` builds its fixture without `max_hostless`, so every case takes the
`cap is None` path and the gate is never exercised. A guard nobody can fail is a declaration, not a
guard — the pattern already recorded in this file.

Written: `agent/tests/test_liveness_hostless_negative_control.py` (7 tests). Mutation matrix, each
mutant killed by its own intended assertion:

| mutant | killed by |
|---|---|
| whole branch deleted | `test_a_hostless_url_fails_the_reach_check_DEAD` + 2 |
| cap read as a boolean (`>=`) | `test_the_cap_is_a_threshold_not_a_boolean` |
| addressability checked after the count | `test_addressability_is_judged_before_the_count...` |
| failure detail stops naming the URL | `test_a_hostless_url_fails_the_reach_check_DEAD` |
| cap applied even when undeclared | `test_a_check_with_no_cap_declared_does_not_silently_gain_one` |

**Still open on this commit:** the commit itself measured that `_surface_crawl` emits 0 hostless URLs out
of 2756, so the gate watches a producer that is already clean. Whatever produced the 10
`https:///benchmark/...` URLs on mission 90cee81c is elsewhere on the mission path and remains
unguarded. The check cannot catch the failure it was written for.

## V4 — anti-idle sweep: S11c/S11d RESOLVED, negative control never written · **two more hostless producers**

`1709f59` measured that `_surface_crawl` emits 0 hostless URLs out of 2756 and concluded the producer of
mission 90cee81c's ten `https:///benchmark/cmdi-Index.html` probes was "elsewhere on the mission path".

The PRIMARY chain has since been traced from the mission's own 908 log rows by another agent
(`test_hostless_target_guard.py`: `tools._graph_add_url` labels an endpoint with the bare path →
`agent._graph_primary_state` reads the label → `planner._b("")` returns `"https://"`). That is the
authoritative trace and this section does not compete with it.

What follows are **two further, independent producers of the same shape** that that trace does not
cover, plus the reason S11c/S11d let any of them travel.

`_browser_surface` derives its seeds from the scope table:

```python
seeds.append(s if "://" in s else "https://" + s.split("/")[0])       # agent.py:2884
```

A scope entry with no host — a path-only entry, which is exactly how this lab is scoped — makes
`s.split("/")[0]` the empty string, so the seed is the bare scheme `"https://"`. MEASURED:

```
in_scope='owaspbench:8443'  -> seed='https://owaspbench:8443' -> https://owaspbench:8443/benchmark/cmdi-Index.html
in_scope='/benchmark/'      -> seed='https://'                -> https:///benchmark/cmdi-Index.html
in_scope='/benchmark'       -> seed='https://'                -> https:///benchmark/cmdi-Index.html
in_scope=''                 -> seed='https://'                -> https:///benchmark/cmdi-Index.html
```

**S11c's fix is what lets it propagate.** Removing the `startswith("http") or startswith("/")` guard was
correct — it was costing the crawler most of the web — but the replacement is still a SCHEME check, and
a hostless URL passes every one of them:

| guard | on `https:///benchmark/cmdi-Index.html` |
|---|---|
| `agent.py:2905` `absu.startswith("http")` | **True** |
| `crawl.py:121` / `:130` / `:144` `u.startswith(("http://", "https://"))` | **True** |
| `crawl.same_origin(u, base)` | False — the only one that reads `netloc` |

**S11d ships the same hole into the surface.** `parse_robots` and `parse_sitemap` are new
(`57afc3f`) and both resolve against a caller-supplied base with no host assertion. MEASURED:

```
parse_robots("Disallow: /admin/ ...", base="https://")  -> {'urls': ['https:///admin/', 'https:///backup/']}
parse_sitemap("<loc>/secret/panel.html</loc>", "https://") -> {'urls': ['https:///secret/panel.html']}
```

Neither has a negative control asserting the parser refuses to emit an unaddressable URL, so both were
RESOLVED against tests that only ever pass a well-formed base.

**The consequence for `1709f59`.** Its `max_hostless` gate watches `_surface_crawl`, which is clean.
Neither the graph/planner chain nor `_browser_surface` nor the robots/sitemap parsers are observed by the
reach check, so it confirms `all addressable` while other parts of the mission path still manufacture
unaddressable URLs. Fixing the planner chain alone closes one of at least three producers.

**Recommended (production code, for the owners):** one shared predicate — a URL is usable only when
`urlparse(u).netloc` is non-empty — applied at `agent.py:2905`, `crawl.py:121/130/144`, and at the seed
derivation itself (`agent.py:2884` should skip a scope entry it cannot turn into an origin rather than
emit `"https://"`). Then point the reach check at the composed mission surface, not at `_surface_crawl`
alone. A scheme check is not a host check — the same class as the guards-that-check-declarations pattern
already recorded above.
