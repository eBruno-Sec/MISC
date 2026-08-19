# Q-044 source-proof lane — does the code-assisted lane ever land a finding in the DB?

**Lane**: source-proof (Breaker, read-only on product code). **Started** 2026-08-18.
**Deliverable**: one yes/no — does a real mission with `source_root` set store a finding carrying
`provenance=source-derived` in the findings table? Mission id + the query that shows it.

Every claim below is **MEASURED** (command + real output) or **UNVERIFIED**.

---

## 0. Apparatus — the DB is in a named volume, and the positive control proves it was looked at

The findings DB is NOT in the tree. `agent/db.py:21` → `DB_PATH = os.getenv("BBH_DB_PATH", "/app/data/bbh.db")`,
and `docker-compose.yml` mounts the named volume `bbh_data` at `/app/data`. A container that mounts only
`agent:/app` sees an empty `/app/data` and every count returns 0. All queries below run **inside the live
`apolaki-agent-1` container**, which has the real volume.

**MEASURED** — `docker exec apolaki-agent-1 python -c "...sqlite3('/app/data/bbh.db')..."`

```
tables: ['missions', 'findings', 'exchanges', 'logs', 'sqlite_sequence', 'notes', 'profiles', 'memory_assets', 'memory_snapshots']
findings: 1057
missions: 153
cols: ['id', 'mission_id', 'data', 'created_at']
```

**MEASURED** — marker distribution across every stored finding (the ticket's baseline, reproduced exactly):

```
POSITIVE CONTROL findings scanned: 1057  missions with findings: 113
provenance: {'None': 1057}
lane:       {'None': 1057}
analysis:   {'None': 1057}
```

The apparatus finds 1057 findings across 113 missions and reports **zero** carrying any of the three
canonical markers. The zero is a real zero, not an empty database.

---

## 1. The deployed container HAS the wiring (Q-059 check)

Q-059 warns the deployed platform lags the tree, so "the code is wired" in the tree proves nothing about
what a live mission runs. **MEASURED** — inside the running container:

```
$ docker exec apolaki-agent-1 sh -c "grep -n '_run_source_review\|source_root' /app/main.py"
106:    source_root: Optional[str] = None
369:def _source_review_state(source_root: Optional[str] = None) -> dict:
398:async def _run_source_review(session_id: str, source_root: Optional[str]) -> dict:
600:               "source_review": _source_review_state(req.source_root)}
613:    source_review = await _run_source_review(session_id, req.source_root)
```

The deployed image carries the wiring (line numbers run 7 lower than the tree's — an older but
functionally present revision). **A live mission CAN exercise this path.**

---

## 2. Where the call happens — this is why the proof is cheap

**MEASURED** — `main.py` deployed, line 613: `_run_source_review` is awaited at the **end of `/engage`**,
before `/run` is ever called. The source lane therefore runs at mission-creation time and does **not**
require the DAST scan to execute. A real, persisted mission created through the production `/engage`
endpoint exercises the whole path synchronously.

## 3. The path, read end to end (static, before running it)

| step | file:line | what must hold |
|---|---|---|
| producer | `codereview.py:594` `_source_finding` | stamps `provenance`/`lane`/`analysis` on EVERY finding, one shared builder for Java + Python + the dataflow rule |
| tree walk | `codeintel.py:304` `review_source_tree` | returns `{lane, provenance, findings:[...]}` |
| evidence contract | `main.py:392` `_canonical_source_finding` | fails closed: all three markers + `proof_schema.proof_kind() == SOURCE_DERIVED` |
| write chokepoint | `db.py:168` `add_finding` → `db.py:151` `_gate` | SCHEMA normalize, SCOPE `off_scope`, TRUTH `is_lead` |

Two boundary reads done before running, both **MEASURED by reading the code**:

* `findings_gate.off_scope` (`findings_gate.py:75`) returns `False` for any target that does not start
  `http://`/`https://`. A source finding's `target` is a relative file path, so it is admitted.
* `findings_gate.is_lead` (`findings_gate.py:32`) reroutes only lead-like `confidence`. `_source_finding`
  sets `confidence="confirmed"`, so it is not rerouted.

**HAZARD identified in advance (UNVERIFIED until the run):** `db.add_finding` returns a **truthy id**
from `add_lead` when the TRUTH invariant reroutes a finding. `_run_source_review` counts `stored` as
`sum(1 for f in findings if db.add_finding(...))`, so a rerouted finding would be counted as *stored*
while living in the mission's **leads list**, not the findings table. If the run reports
`stored_findings > 0` and the findings table still shows 0, this is the boundary.

---

---

# 4. THE ANSWER: **YES.** Mission `2fb87a3a`. The path carries findings.

## 4.1 The mission

Run through the **production `/engage` endpoint** on the live agent — no harness, no test double:

```
$ curl -s -m 900 -X POST http://localhost:8000/engage -H 'Content-Type: application/json' -d '{
    "program_name": "Q-044 source-proof code-assisted lane",
    "in_scope": ["https://owaspbench:8443/benchmark/"],
    "mode": "active",
    "strategy": "deterministic",
    "source_root": "/tmp/q044/BenchmarkJava"
  }'
```

**MEASURED** response (49.9 s wall):

```json
{"session_id":"2fb87a3a","mode":"active","strategy":"deterministic",
 "source_review":{"status":"complete","lane":"code-assisted","label":"code-assisted (SAST)",
                  "provenance":"source-derived","source_root":"/tmp/q044/BenchmarkJava",
                  "files_scanned":2766,"findings":716,"stored_findings":716,
                  "rejected_findings":0,"error":""},
 "status":"created","started":false}
```

The source tree is the **OWASP Benchmark Java v1.2 tree** the ticket named — `src/main` lifted out of the
`apolaki-owaspbench-1` container (`docker cp apolaki-owaspbench-1:/owasp/BenchmarkJava/src/main ...`) and
placed at `/tmp/q044/BenchmarkJava` inside the agent container. 2763 `.java` files. It is the *same tree*
`owasp_bench.scan_source` grades, so this is the tree behind the 61.1% figure.

## 4.2 The query that proves it is STORED

**MEASURED** — inside `apolaki-agent-1`, against the named-volume DB `/app/data/bbh.db`:

```sql
SELECT count(*) FROM findings WHERE mission_id = '2fb87a3a';
```

```
AFTER findings total: 1773  (delta +716)
findings for mission 2fb87a3a: 716
provenance=source-derived: 716
lane=code-assisted:        716
analysis=static-call-site: 716
by_cwe:    {'CWE-501': 83, 'CWE-327': 261, 'CWE-330': 219, 'CWE-328': 153}
by_family: {'trust_boundary': 83, 'weak_crypto': 261, 'weak_random': 219, 'weak_hash': 153}
```

One stored row, verbatim from the `findings` table:

```json
{"title": "Trust boundary violation: request data written into the session",
 "severity": "medium",
 "target": "java/org/owasp/benchmark/testcode/BenchmarkTest00325.java",
 "confidence": "confirmed", "family": "trust_boundary", "cwe": "CWE-501", "line": 56,
 "provenance": "source-derived", "lane": "code-assisted", "analysis": "static-call-site",
 "oracle": "the value reaching HttpSession.putValue at line 56 is request-derived
           (request.getHeaders()); this is a dataflow conclusion, not a call-site match --
           the same sink with a constant is not reported"}
```

**Q-044's DoD is met.** The code-assisted lane is no longer a path that has never carried a finding.

## 4.3 The §3 hazard did NOT fire — checked, not assumed

`stored_findings` reported 716 **and** the findings table holds 716 rows for that mission. Had the TRUTH
invariant rerouted them, `add_lead` would have returned truthy ids and `stored_findings` would still have
read 716 while the table read 0. It reads 716 in **both** places, so nothing was rerouted to leads.
The hazard stays latent (`add_finding` really does return a truthy id from `add_lead`) but it is not what
happens to a source finding today, because `_source_finding` stamps `confidence="confirmed"`.

## 4.4 DB side effect, recorded so no later lane is surprised

This mission added **716 rows** to a table that held **1057**. Corpus-wide counts move 1057 -> 1773 and
`provenance=source-derived` moves 0 -> 716. Any lane re-running the Q-044 baseline query must exclude
`mission_id='2fb87a3a'` to reproduce the pre-run numbers.

---

# 5. Does the stored finding SURVIVE into a report? Yes — checked, not assumed

Storing a row is not the same as the row reaching a reader. `proof_schema.demote_unproven` rewrites
`confidence` in place, so a source finding could be stored and then presented as an unproven lead.

**MEASURED** — inside `apolaki-agent-1`, mission `2fb87a3a`:

```
raw: 716 gated: 716
raw confidence:   {'confirmed': 716}
gated confidence: {'confirmed': 716}
gated with proof_gap: 0
proof_kind sample: source-derived | control_status: not_applicable
```

The proof gate is length-preserving here and demotes nothing. `control_status` returns
`not_applicable` rather than `not_recorded`, which is the correct answer for a lane where no request
differential can exist — the source finding is not silently penalised for lacking a control it could
never have.

---

# 6. ANTI-IDLE: `/codereview` still routes to the OLDER analyser — and the cost is now measured

The one original Q-044 claim still standing. **MEASURED** — `agent/main.py:2255-2264`:

```python
@app.get("/codereview")
async def code_review(path: str = ""):
    import codeintel
    p = path or os.environ.get("CODEREVIEW_DEFAULT", "/labsrc/juiceshop")
    return codeintel.review(p)          # <- the OLDER analyser, not review_source_tree
```

`POST /mission/{id}/codereview` (`main.py:3269`) is a third contract again: it calls
`codereview.review(src, name)` on a supplied source **string**, seeds the asset graph, and stores its
output in `context["code_review"]`, never in the findings table.

## 6.1 What an operator on the obvious endpoint actually gets — both analysers on the SAME tree

**MEASURED** — `GET /codereview?path=/tmp/q044/BenchmarkJava` (7.2 s) and, uncapped, the same call
with `max_hits=100000` (6.7 s):

| | `GET /codereview` -> `codeintel.review` | `source_root` -> `codeintel.review_source_tree` |
|---|---|---|
| total | 500 (capped; **509** uncapped) | **716** |
| rules that fire | `sql_string_build` 448, `weak_crypto` 61 | `weak_crypto` 261, `weak_random` 219, `weak_hash` 153, `trust_boundary` 83 |
| finding keys | `confirm, file, line, rule, severity, snippet, technique, why` | full finding schema + CWE + family + oracle |
| `provenance` / `lane` / `analysis` | **absent** | all three present |
| `cwe` / `family` / `confidence` | **absent** | present |
| persisted to a mission | **no** | yes — 716 rows |

**The headline is not "weaker", it is DISJOINT, and that is worse.** The two analysers detect
non-overlapping classes on the same tree:

* `codeintel.review` reports **448 SQL-string-build leads**. `review_source_tree` reports **zero**
  injection findings of any kind — `codereview.review_java` (`codereview.py:630`) has exactly four
  rule groups: trust-boundary dataflow, crypto, hash, random. There is no injection rule in the
  code-assisted lane at all.
* `review_source_tree` reports 219 weak-random, 153 weak-hash and 83 trust-boundary findings.
  `codeintel.review` reports none of those classes.

So an operator gets a **mutual blind spot** depending on which door they walk through, and neither
door tells them the other exists. This also explains the 61.1% macro figure without any appeal to
tuning: the code-assisted lane scores 100% on crypto / hash / weakrand because those are three of its
four rules, and 0% on every injection category because it has no rule to score with.

The 500-item cap on `/codereview` is real but minor — it hides 9 of 509 on this tree.

## 6.2 One more Q-044-adjacent claim that is now FALSE

`docs/QUEUE.md:3351` records Q-044 as "the code-assisted lane is benchmark-only; 61.1% is not
reachable in an engagement". Mission `2fb87a3a` reached it from `/engage` with an operator-supplied
`source_root`. The lane is **not** benchmark-only.

---

# 7. A SECOND DEFECT, MEASURED: `stored_findings` can count a finding that was never stored

Found while checking whether my own 716 was trustworthy. It was — but only because I queried the
table, not because the number is sound.

`_run_source_review` computes `stored = sum(1 for f in findings if db.add_finding(session_id, f))`.
`db.add_finding` (`db.py:168`) returns `add_lead(mid, finding)` when the TRUTH invariant fires, and
`add_lead` returns a **truthy id**. So a rerouted finding is counted as stored.

**MEASURED** against the running agent, one canonical source finding with `confidence="lead"`:

```
state: {'status': 'complete', 'findings': 1, 'stored_findings': 1, 'rejected_findings': 0, 'error': ''}
rows in findings table: 0
leads: 1
```

`/engage` and the mission context both report a stored source-derived finding. The findings table
holds none.

**LATENT, not live.** `codereview._source_finding` (`codereview.py:594`) hard-codes
`confidence="confirmed"`, so no production producer emits this shape today — which is exactly why it
is cheap to fix now. `_canonical_source_finding` constrains `provenance`, `lane` and `analysis` and
says nothing about `confidence`, so the contract that exists to fail closed does not close this door.

## 7.1 PATCH (written here, NOT applied — `main.py` is another lane's file)

In `main.py`, inside `_run_source_review`, replace:

```python
stored = sum(1 for finding in findings if db.add_finding(session_id, finding))
state["stored_findings"] = stored
if stored != len(findings):
```

with a count of what the TABLE accepted, plus an honest key for what was rerouted:

```python
before = len(db.get_findings(session_id))
rerouted = 0
for finding in findings:
    if not db.add_finding(session_id, finding):
        continue
    if str(finding.get("confidence") or "").strip().lower() != "confirmed":
        rerouted += 1                     # went to leads, not to the findings table
stored = len(db.get_findings(session_id)) - before
state["stored_findings"] = stored
state["lead_findings"] = rerouted
if stored != len(findings):
```

This neither drops the finding nor lies about it: a lead-confidence source finding still reaches the
leads list, `stored_findings` still means *rows in the findings table*, and the mismatch branch that
already exists sets `status=error` with the real numbers. The alternative — adding
`confidence == "confirmed"` to `_canonical_source_finding` — would make the contract self-consistent
but would silently discard a legitimate finding, which is the failure mode the ticket warns about.

---

# 8. Regression guard: `agent/tests/test_source_lane_persistence.py` (new, mine)

There was **no test anywhere** covering `main._run_source_review`, `main._canonical_source_finding`,
or the write into `db.findings`. The suite covered the analyser thoroughly and the persistence half
not at all — which is precisely how the lane could be "wired" for weeks with a zero in the table.

Eight tests + two strict xfails (the second is §9). **MEASURED** on the agent image (`python:3.12`):

```
$ docker run --rm -v ".../apolaki/agent:/app" -w /app apolaki-agent \
      python -m pytest tests/test_source_lane_persistence.py -q
........xx                                                               [100%]
```

## 8.1 Both mutants killed by the intended assertions

A test that passes proves nothing until it is shown it can fail. Two mutants, each applied to a
**copy** of the tree in scratch, never to the repo:

**M1 — `_canonical_source_finding` returns `True` unconditionally** (the evidence contract becomes
decoration). Killed by exactly the four contract tests, and by nothing else:

```
FAILED ...::test_a_finding_missing_one_marker_is_rejected_and_nothing_is_stored[provenance]
FAILED ...::test_a_finding_missing_one_marker_is_rejected_and_nothing_is_stored[lane]
FAILED ...::test_a_finding_missing_one_marker_is_rejected_and_nothing_is_stored[analysis]
FAILED ...::test_one_bad_finding_rejects_the_whole_batch
E       AssertionError: assert 'complete' == 'error'
```

**M2 — `stored = len(findings)` with the `db.add_finding` call removed** (the exact "counted, never
written" shape Q-044's zero was). Killed by exactly the two positive-control tests:

```
FAILED ...::test_a_real_source_tree_lands_canonical_findings_in_the_findings_table
FAILED ...::test_the_stored_rows_are_findable_by_the_query_that_reported_zero
E       assert 0 == 3
```

M2 is the important one: it is the mutant a suite that only tests the analyser cannot see, and it is
the reason the positive control asserts against `db.get_findings` rather than against the returned
count.

Each strict xfail pins a measured defect (§7, §9) as executable evidence. When a patch lands it XPASSes, the suite goes red,
and the marker has to be removed deliberately.

---

# 9. A THIRD DEFECT, and it is the ticket's own failure mode arriving through the renderer

The mission's report was rendered and read. `GET /report/2fb87a3a/md` -> 1,259,303 bytes.

## 9.1 What the report gets RIGHT

* Every source finding carries the correct proof-kind prose: *"NOT APPLICABLE to this proof kind: a
  source-derived (static call-site) finding has no request, no baseline and no mutation ... The
  control that DOES apply is the rule-level counter-example"*, with the family's real sibling
  (`Cipher.getInstance("AES/GCM/NoPadding")`, `SecureRandom()`, `MessageDigest.getInstance("SHA-256")`).
* The tool ledger names the lane honestly:
  `| codeintel.review_source_tree | executed | 1 | 716 | code-assisted (SAST): 716 source-derived finding(s) from 2766 Java/Python source file(s) |`
* Report Integrity: 10 consistency checks passed.

## 9.2 The defect: 715 of 716 findings carry a FABRICATED HTTP reproduction

**MEASURED** — from the rendered report:

```
**Steps to Reproduce**

1. Open java/org/owasp/benchmark/testcode/BenchmarkTest00325.java at line 56
2. Read the call site — no runtime observation is required

**Reproduction (copy-paste)**

```bash
curl -i -sS -k --path-as-is 'java/org/owasp/benchmark/testcode/BenchmarkTest00325.java'
```
```

The finding's own steps say no runtime observation is required, and the very next block hands the
reader a copy-pasteable curl against a **source file path**. Count of that exact shape in the report:

```
$ grep -c "curl -i -sS -k --path-as-is 'java/" report.md
715
```

`proof_schema.py:197` defines `SOURCE_DERIVED` as *"a static call site; no request exists, even in
principle"*. `report.finding_curl` (`report.py:991`) derives a command from `target` with **no
proof-kind check**:

```python
target = str(finding.get("target") or finding.get("surface") or "").strip()
if not target:
    return ""
method = str(finding.get("method") or "GET").upper()
if method == "GET" and not body:
    return f"curl -i -sS -k --path-as-is '{target}'"
```

**This is the exact failure `_canonical_source_finding` was written to prevent — a source result
presented under DAST semantics — arriving through the RENDERER instead of the STORE.** The store-side
contract fails closed and holds; the report layer has no equivalent check, so it manufactures a
request for a proof kind that cannot have one. A client reading this report would run 715 curls
against file paths and conclude the tool is broken, or worse, believe the finding was observed over
HTTP.

### PATCH (written here, NOT applied)

`report.py`, in `finding_curl`, before deriving anything from `target`:

```python
def finding_curl(finding: dict) -> str:
    if str(finding.get("curl") or "").strip():
        return finding["curl"].strip()
    # A source-derived finding has no request, even in principle (proof_schema.SOURCE_DERIVED).
    # Deriving one from `target` turns a FILE PATH into a URL and presents a static call site under
    # DAST semantics — the same confusion `main._canonical_source_finding` refuses at the store.
    import proof_schema as _ps
    if _ps.proof_kind(finding) == _ps.SOURCE_DERIVED:
        return ""
    target = str(finding.get("target") or finding.get("surface") or "").strip()
    ...
```

Both renderers already treat `""` as *omit the block* (`report.py:491` `if _curl:` and
`report.py:2582` `if not curl:`), so nothing downstream changes. A producer that sets `curl`
explicitly still wins, which keeps the door open for a SAST lead later confirmed by a probe.

Pinned as a strict xfail: `test_a_source_derived_finding_gets_no_curl_reproduction`.

## 9.3 A weaker observation, recorded but NOT called a defect

The report header reads **`Total Findings: 716`** with a severity table of `Medium | 716`, and the
strings `code-assisted` / `SAST` appear exactly **once** in 34,000 lines — in the tool ledger row.
The executive summary therefore quotes a source-derived count with no lane qualifier, on a mission
whose DAST half ran nothing. `codereview.py:588` states the rule this brushes against: *"This number
cannot be quoted next to a DAST figure."*

It is recorded as an OBSERVATION rather than a defect because nothing in this report presents it *as*
a DAST figure — the ledger attributes all 716 to `codeintel.review_source_tree`, and the DAST row is
absent rather than misreported. Whether the summary needs a per-lane split is a product decision, not
a correctness one, so it is not being asserted as a bug. It does mean **a mission that ran both lanes
would sum them into one headline**, which is worth a decision before that mission is run for a client.

---

# 10. Verdict on Q-044

| the ticket's DoD | state |
|---|---|
| a real mission produces a stored source-derived finding | **DONE** — `2fb87a3a`, 716 rows, `provenance=source-derived` |
| mission id recorded | **DONE** — `2fb87a3a` |
| the query that shows it recorded | **DONE** — §4.2 |
| `/codereview` still routes to the older analyser | **STILL TRUE**, and the cost is now measured (§6) |

**Q-044's outcome is (1) — it works.** 61.1% is no longer a harness-only figure: the lane runs from the
production `/engage` endpoint, the evidence contract admits the findings, the write chokepoint stores
them, the proof gate does not demote them, and the report renders them with the correct proof-kind
prose. **The half that matters is proven.**

Three things fall out that were not visible before the mission ran, in descending order of severity:

1. **§9 — 715 fabricated curl reproductions.** Live, in the client-facing artifact. The only one of the
   three that reaches a reader today.
2. **§6 — the two source analysers are DISJOINT.** `/codereview` sees 448 SQL-injection leads the
   code-assisted lane cannot see; the code-assisted lane sees 455 crypto/hash/random/trust-boundary
   findings `/codereview` cannot see. There is no injection rule in `codereview.review_java` at all.
   Neither endpoint tells the operator the other exists.
3. **§7 — `stored_findings` can count a finding the table never accepted.** Latent, and the reason
   §4.2's 716 was verified against the table rather than against the returned number.

## Reproducing any of this

```bash
# the mission
curl -s -X POST http://localhost:8000/engage -H 'Content-Type: application/json' \
  -d '{"program_name":"...","in_scope":["https://owaspbench:8443/benchmark/"],
       "mode":"active","strategy":"deterministic","source_root":"/tmp/q044/BenchmarkJava"}'

# the source tree, into the agent container (it is NOT vendored in the repo)
docker cp apolaki-owaspbench-1:/owasp/BenchmarkJava/src/main ./benchjava_main
docker cp ./benchjava_main apolaki-agent-1:/tmp/q044/BenchmarkJava

# the proof — note the DB lives in the named volume, so this MUST run inside the agent container
docker exec apolaki-agent-1 python -c "import sqlite3,json; \
  rows=sqlite3.connect('/app/data/bbh.db').execute( \
    \"select data from findings where mission_id='2fb87a3a'\").fetchall(); \
  print(len(rows), sum(1 for (d,) in rows if json.loads(d).get('provenance')=='source-derived'))"

# the tests
docker run --rm -v "<repo>/apolaki/agent:/app" -w /app apolaki-agent \
  python -m pytest tests/test_source_lane_persistence.py -q
```
