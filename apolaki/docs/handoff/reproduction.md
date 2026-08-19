# Q-082 reproduction lane — the report hands a client 716 FABRICATED curl reproductions

**Lane**: reproduction (Builder). **Owner of**: `agent/report.py`, `agent/tests/test_source_repro_presentation.py`,
this file. **Started** 2026-08-19.

Every claim below is **MEASURED** (command + real output) or **UNVERIFIED**. Every zero carries a
positive control proving the apparatus was looking.

---

## 0. Apparatus — the DB is in a NAMED VOLUME, and the positive control proves it was read

The findings table is not in the tree. All measurements run in a throwaway container mounting the
named volume `apolaki_bbh_data` at `/data` alongside the repo's `agent/` at `/app`:

```
MSYS_NO_PATHCONV=1 docker run --rm -e PYTHONPATH=/app \
  -v "apolaki_bbh_data:/data" \
  -v "<repo>/apolaki/agent:/app" \
  -v "<scratch>:/out" -w /app apolaki-agent python /out/measure_q082.py
```

**MEASURED** — positive control, exactly matching the brief's stated table state:

```
POSITIVE CONTROL findings: 1773 missions: 114
static-call-site findings: 716
missions holding them: Counter({'2fb87a3a': 716})
mission 2fb87a3a rows: 716
```

A container that mounts only `agent:/app` sees an empty `/app/data` and returns 0 for all of these.
The numbers above are the real table.

**Negative-control mission chosen**: `2810d5d9` — 44 findings, **0** source markers, all 44 carrying a
non-empty `target`, headed by a `confirmed` `CRITICAL` SQL-injection auth bypass with a real POST
reproduction. This is the mission that must KEEP its curls.

---

## 1. BASELINE — measured before touching a line of `report.py`

**MEASURED** — `measure_q082.py` against the real rows of both missions, both renderers:

```
POSITIVE CONTROL  source mission 2fb87a3a rows: 716   dast mission 2810d5d9 rows: 44
  source rows classed SOURCE_DERIVED : 716
  dast   rows classed BEHAVIOURAL    : 44
  dast   rows with a non-empty target: 44

finding_curl() non-empty on source rows : 716 / 716
finding_curl() non-empty on dast   rows : 44 / 44

=== mission 2fb87a3a (716 findings) ===
  MARKDOWN  '--path-as-is' occurrences      : 716
  MARKDOWN  'Reproduction (copy-paste)'     : 716
  MARKDOWN  lines starting 'curl '          : 716
  HTML      '--path-as-is' occurrences      : 4
  HTML      '<h4>Reproduction (copy-paste)' : 4
  HTML      <article class="finding"> cards : 4
  HTML      'Where in the code' blocks      : 0
  MARKDOWN  'Where in the code' blocks      : 0

=== mission 2810d5d9 (44 findings) ===
  MARKDOWN  '--path-as-is' occurrences      : 35
  MARKDOWN  'Reproduction (copy-paste)'     : 44
  MARKDOWN  lines starting 'curl '          : 44
  HTML      '--path-as-is' occurrences      : 1
  HTML      '<h4>Reproduction (copy-paste)' : 4
  HTML      <article class="finding"> cards : 4
```

### 1.1 BOTH renderers are affected — and the HTML number is 4, not 716, for a reason worth stating

`generate_html_report` calls `group_findings` (`report.py:1042`), which collapses findings sharing a
family+parameter root cause into ONE representative carrying an `instances` list. The 716 source
findings occupy four families (`weak_crypto` 261, `weak_random` 219, `weak_hash` 153,
`trust_boundary` 83), so the HTML deliverable renders **4 cards — and 4 of 4 carry a fabricated
`--path-as-is` curl against a Java source path**, with the other 712 file paths listed underneath as
"Affected instances". The markdown renderer does not group, so it prints all 716.

**So the defect rate is 716/716 in markdown and 4/4 in HTML — 100% in both.** A markdown-only fix
would leave the client-facing HTML asserting the same false thing on every card it renders.

`rep = dict(f)` in `group_findings` copies the first member's fields, so the representative keeps
`analysis`/`file`/`line`. A proof-kind check therefore binds the grouped card correctly.

### 1.2 What the reader is handed today (markdown finding 1, verbatim from the render)

```
**Steps to Reproduce**

1. Open java/org/owasp/benchmark/testcode/BenchmarkTest00325.java at line 56
2. Read the call site — no runtime observation is required

**Reproduction (copy-paste)**

```bash
curl -i -sS -k --path-as-is 'java/org/owasp/benchmark/testcode/BenchmarkTest00325.java'
```
```

The steps say no runtime observation is required; the next block hands over a request to run. The
finding's own `oracle` says the conclusion is a dataflow one. The curl is a fabrication in the
strictest sense: **there is no request, even in principle** (`proof_schema.py:197`).

### 1.3 The real stored shape — the fixture source of truth (COPIED, not invented)

**MEASURED** — `select data from findings where mission_id='2fb87a3a'`, row 0, in full, is reproduced
in `agent/tests/test_source_repro_presentation.py` as `SOURCE_FINDING`. Key union across all 716:

```
['analysis', 'confidence', 'cwe', 'description', 'evidence', 'family', 'file', 'id', 'impact',
 'lane', 'line', 'oracle', 'provenance', 'remediation', 'reproduction_steps', 'severity', 'tags',
 'target', 'title']
has file key: 716    has line key: 716    has reproduction_steps: 716
```

`file` and `line` are present on **every** source finding, so the presenter has real coordinates to
render and never has to invent one. `target` holds the same file path — which is precisely why
`finding_curl` produced a command: it read `target` as a URL.

---

# 2. THE FIX — `agent/report.py`, three commits, each measured before the next

## 2.1 The false claim: `finding_curl` now consults the proof kind

```python
    if str(finding.get("curl") or "").strip():
        return finding["curl"].strip()
    import proof_schema as _ps
    if _ps.proof_kind(finding) == _ps.SOURCE_DERIVED:
        return ""
```

The producer's own `curl` is still checked **first**, deliberately. `proof_schema.control_status`
documents the door it keeps open — a SAST lead later confirmed by a real probe carries a real
artifact, and suppressing it from its *label* rather than from the *facts* would be this same bug
pointed the other way. That door is a test, not a comment: a source-derived finding carrying
`curl -i -sk 'http://app:8080/x?p=1'` still renders it.

## 2.2 Removal is only half of it — `source_location` + `reproduction_steps_for`

A fix that deleted the block and put nothing there would trade a false claim for a useless report,
which is the trade this project has already paid for once. Two new pure functions in `report.py`:

* `source_location(finding)` → `file:line` (from the finding's own `file`/`line`, falling back to
  `target`, degrading to the bare path when `line` is missing — never guessing a number).
* `reproduction_steps_for(finding)` → the steps a renderer prints, with a fallback **matched to the
  proof kind**. The old fallback said *"Send the request shown in the reproduction command below"* —
  which, once the command below is gone, is an instruction pointing at nothing. Both renderers read
  this one function so they cannot drift apart.

`poc_bundle.build` had already solved this the same way — its `reproduction` block emits
`{"curl": "", "open": "java/.../BenchmarkTest00325.java:56"}` for a source finding. **The PoC-bundle
presenter was bound to the proof kind and the report presenter was not**, which is the Q-051 shape
exactly: two surfaces, one contract, one of them wired. `Where in the code` is the report's spelling
of the same `open` field, not a new convention.

## 2.3 BOTH renderers, and the HTML branch is ordered so a source finding cannot reach the DAST prose

Markdown (`report.py`, findings loop): `if _curl: ... elif _loc:` → `**Where in the code**`.
HTML (`generate_html_report`, card loop): `if not curl and _loc:` **before** the `dom_confirmed`
branch, so a source-derived finding can never be handed the *"confirmed in a real headless browser"*
paragraph. The two branches are mutually exclusive by construction — `finding_curl` returns `""` for
the kind `source_location` answers for — rather than by a second classification that could drift.

## 2.4 AFTER — the same command, the same two missions, the same day

**MEASURED**:

```
finding_curl() non-empty on source rows : 0 / 716      (was 716 / 716)
finding_curl() non-empty on dast   rows : 44 / 44      (unchanged)

=== mission 2fb87a3a (716 findings) ===          BEFORE -> AFTER
  MARKDOWN  '--path-as-is'                          716 -> 0
  MARKDOWN  'Reproduction (copy-paste)'             716 -> 0
  MARKDOWN  lines starting 'curl '                  716 -> 0
  MARKDOWN  'Where in the code'                       0 -> 716
  HTML      '--path-as-is'                            4 -> 0
  HTML      '<h4>Reproduction (copy-paste)'           4 -> 0
  HTML      'Where in the code'                       0 -> 4
  HTML      <article class="finding"> cards           4 -> 4     (nothing was dropped)

=== NEGATIVE CONTROL, mission 2810d5d9 (44 findings) ===
  MARKDOWN  'Reproduction (copy-paste)'              44 -> 44
  MARKDOWN  lines starting 'curl '                   44 -> 44
  HTML      '<h4>Reproduction (copy-paste)'           4 -> 4
  HTML      'Where in the code'                       0 -> 0
```

The DAST mission is byte-identical either side of the change, in both renderers, and its
`--path-as-is` count (35 markdown / 1 HTML) is *the derived-command path* — the one that was wrong
and had to survive. That is the control the ticket said would be skipped.

### What the reader gets now (markdown, verbatim from the render)

```
**Steps to Reproduce**

1. Open java/org/owasp/benchmark/testcode/BenchmarkTest00325.java at line 56
2. Read the call site — no runtime observation is required

**Where in the code**

`java/org/owasp/benchmark/testcode/BenchmarkTest00325.java:56`

This finding was derived by reading source, not by sending a request — there is no HTTP transaction
to replay. Open the file at the line above and read the call site; the false-positive control that
applies is the rule-level counter-example, stated below.
```

and in HTML, on all four cards:

```html
<h4>Where in the code</h4><pre class='ev'>java/org/owasp/benchmark/testcode/BenchmarkTest00325.java:56</pre>
<p class='sub'>This finding was derived by reading source, not by sending a request ...</p>
```

## 2.5 The pinned strict xfail — removed, which is what it was for

`agent/tests/test_source_lane_persistence.py::test_a_source_derived_finding_gets_no_curl_reproduction`
carried `@pytest.mark.xfail(strict=True)`. After the fix it XPASSed, i.e. **failed**, exactly as that
module's own docstring intends: *"a fix makes the suite go red and the marker has to be removed
deliberately."* The marker is gone and the assertion is now live.

This is the one file outside this lane's ownership that was touched, and only by deleting a decorator
— a strictly strengthening edit that the fix itself makes mandatory. The replaced reason string is
preserved in a comment above the test, with two corrections: the count was **716 of 716**, not 715,
and *"the fix is local and needs no renderer change"* was right about the false claim and wrong about
what replaces it (both renderers gained a `Where in the code` block).

## 2.6 New tests — `agent/tests/test_source_repro_presentation.py`, 22 assertions

Every fixture is **copied from the findings table**, byte for byte, with provenance stated at its
definition: `SOURCE_FINDING` is row 0 of mission `2fb87a3a`; `DAST_EXPLICIT_CURL` and
`DAST_DERIVED_CURL` are two real rows of `2810d5d9` chosen to exercise the producer-curl path and the
derived-curl path respectively. Nothing here was invented.

**BEFORE the fix**: 7 failed, 6 passed — and *which* 6 passed matters: the negative controls
(behavioural findings keeping their commands) were green on both sides, which is what makes them
controls rather than restatements of the fix.

Beyond the positive/negative pair the file pins three discriminations that a lazier fix would survive:

| test | what it kills |
|---|---|
| `a_source_finding_that_is_not_java_also_gets_no_curl` | a fix that pattern-matched the measured `java/` prefix or `.java` |
| `a_behavioural_finding_whose_target_looks_like_a_path_keeps_its_command` | a fix that keyed on "does the target look like a URL" |
| `each_source_marker_alone_is_enough_to_suppress_the_command` | a fix requiring all three markers, when `proof_schema._SOURCE_MARKERS` classifies on any one |

---

# 3. ANTI-IDLE SWEEP — where else does the presenter assert HOW a finding was obtained?

Method: run every claim-composing function in `report.py` over **all 1773 stored findings** (716
source-derived, 1057 behavioural), not over a fixture. Counts below are that population.

## 3.1 DEFECT — `proof_and_retest` bound one of its two claims and not the other · FIXED

**MEASURED**, after the curl fix, over the 716:

```
716  "Operator-driven: re-run the original confirming request + oracle
      (no replayable http(s) target on the finding)."
```

`proof_and_retest` returns two claims. `negative_control` is proof-kind-aware and correct on all 716
(*"NOT APPLICABLE to this proof kind ..."*). The `retest` half was not, so the same dict told the
reader in one paragraph that no request can exist and in the next to re-run the original request. The
parenthetical made it worse by naming the cause as a missing **replayable** target, when the truth is
that no request exists even in principle.

**This is the both-halves failure inside a single function** — the tightest instance of it this
project has recorded, since both halves are keys of one returned dict.

Fixed: the non-retestable branch now splits on proof kind and names the coordinate to re-read.
Behavioural findings are untouched (asserted per fixture, not by a count).

## 3.2 DEFECT — `validation_line` prescribes a request for a finding that never sent one · FIXED

**MEASURED** over the 716: `716` x *"Re-run the exact reproduction above and confirm the confirming
condition no longer occurs"* — there is no reproduction above.

Every entry of `_FAMILY_VALIDATION` is a request instruction (*"Re-send"*, *"Replay"*, *"Reload"*),
so the proof-kind branch is placed **before** the family map: a source-derived finding in the `sqli`
family must not be told to re-send a payload. A producer's own `validation` still wins, above both.

**Scope note, stated because it changes what "fixed" means**: `validation_line` is rendered at
`report.py:2679` in the **HTML renderer only** — markdown never prints a Validation After Fix
section at all. So this defect was 4/4 in the artifact a client reads and 0 in markdown. The function
is now correct wherever it is called; **markdown's missing Validation section is left as an
observation, not silently added — it is a product decision, not a correctness one.**

## 3.3 DEFECT — the report-time integrity gate had no proof-kind check at all · FIXED

`report_integrity_check` runs **live at report time** with ten semantic checks. **MEASURED**: fed a
source-derived finding carrying a fabricated `--path-as-is` curl, it returned only an unrelated CVSS
complaint. **Positive control** — the same finding with empty `reproduction_steps` returns *"confirmed
finding without reproduction steps"*, so the gate was capable of firing and simply had nothing to say
about the defect that was live in the client artifact.

Two checks added, reading **what the renderer actually prints** (`finding_curl`, `source_location`)
rather than which fields exist:

```
Q-082 gate violations over ALL 1773 stored findings : 0
same 716 rows, `curl` mutated back to the defect    : 716 of 716 flagged
total violations from the other ten checks          : 771  (unchanged)
```

The mutation control is what makes the zero mean something: an inert check would score 0 on both.
The http(s) carve-out keeps the legitimate door open — a SAST lead later confirmed by a real probe
carries a real request and still passes.

## 3.4 OBSERVATION, deliberately NOT called a defect — the browser-confirmation claim is a substring match

The HTML renderer decides a finding was *"confirmed in a real headless browser"* from

```python
dom_confirmed = ("dom" in (f.get("tags") or [])) or ("Chromium" in _ev_txt) or ("rendered" in _ev_txt.lower())
```

**MEASURED over all 1773**:

| | count |
|---|---|
| findings the predicate fires on | **203** |
| of those, carrying a screenshot or DOM snippet | 112 |
| of those, carrying **no** browser artifact at all | **91** |
| trigger for all 91 | `tag:dom` (0 by `Chromium`, 0 by `rendered`) |
| families of the 91 | `dom_data_manipulation` 46, `dom_link_manipulation` 32, `dom_xss` 13 |
| of the 91, whose evidence names no browser/headless/Chromium | 78 |

**Why this is not asserted as a defect.** All 91 are real DOM-audit findings tagged `runtime-canary`
whose evidence says the parameter reflects *"at runtime"*; the browser probably did run. What is
measured is narrower and still worth recording: the card says *"confirmed in a real headless browser
(see Evidence above)"* and for 78 of them the Evidence block names no browser. Proving the claim
false would mean binding each finding to its producing engine, which is the Q-042 discipline and was
not done here.

**What IS structurally weak, independent of that**: two of the three disjuncts are substring matches
on free prose. `"rendered" in evidence.lower()` fires on **0** findings today and would fire on any
future evidence string using the word; `tag:dom` is a declaration, not an artifact. A presentation
claim of that weight should read a field. Filed as an observation for the renderer's owner rather
than changed speculatively.

*(Source-derived findings can no longer reach this branch at all — the `Where in the code` branch is
ordered ahead of it — and the predicate fires on 0 of the 716 in any case.)*

## 3.5 CLEAN — measured, with the apparatus shown to be looking

| surface | source-derived findings | verdict |
|---|---|---|
| `evidence_items()` labels (Raw request / Raw response / Timing / Baseline) | `[]` — emits nothing | clean; a finding with no request artifacts claims none |
| `browser_evidence_html()` | 0 of 716 non-empty | clean |
| `graded_business_impact()['demonstrated']` | `None` on all 716 | clean; no "Confirmed on this target" prose is composed |
| `findings_json` / `findings_csv` | 0 occurrences of `curl` or `--path-as-is` | clean; the exports never carried it |
| `poc_bundle.build()` reproduction | `{"curl": "", "open": "file:line"}` | **already correct before this ticket** |
| `remediation_line()` | the producer's own `remediation` text | clean |
| `negative_control_claim()` heading | 716/716 *"rule-level counter-example (no request applies)"* | correct, and the model the retest half now follows |

The apparatus is the same script that scored 716 on the defective surfaces, so these zeros come from
a harness that demonstrably detects the shape.

**Whole-report phrase sweep, source-only render, before -> after:**

```
"re-run the original confirming request"  md 716 / html 4   ->  0 / 0
"the exact reproduction above"            md   0 / html 4   ->  0 / 0
"--path-as-is"                            md 716 / html 4   ->  0 / 0
"baseline"                                md 716 / html 4   ->  716 / 4   (unchanged, and correct:
        it is the NEGATION "has no request, no baseline and no mutation" in the counter-example prose)
```

## 3.6 OBSERVATION carried forward from `source_proof.md` §9.3, now measured here

The executive summary quotes `Total Findings: 716` with no lane qualifier. Rendering the 716 with no
tool ledger, the markdown report contains `code-assisted` x 0 and `SAST` x 0 while `source-derived`
appears 716 times inside the per-finding proof prose. With the real ledger attached the strings
appear once, in the ledger row (measured by the Q-044 lane). Unchanged by this ticket and still a
product decision: **a mission that ran both lanes would sum them into one headline.**

---

# 4. Sweep result in one line

Four surfaces asserted a request over findings whose own `analysis` field denies one — the curl
(716 md / 4 html), the retest sentence (716 / 4), the validation prescription (0 / 4), and the gate
that should have caught all three (0 of 3 detected). All four are fixed and pinned. One further
surface (the browser-confirmation predicate, 91 of 203 without an artifact) is recorded as an
observation and deliberately not claimed.

# 5. What a reviewer should re-run

```bash
# the fix + its controls (22 assertions)
MSYS_NO_PATHCONV=1 docker run --rm -v "<repo>/apolaki/agent:/app" -w /app apolaki-agent \
  python -m pytest tests/test_source_repro_presentation.py tests/test_source_lane_persistence.py -q

# the real artifact, both renderers, both missions — needs the NAMED VOLUME or every count is 0
MSYS_NO_PATHCONV=1 docker run --rm -e PYTHONPATH=/app \
  -v "apolaki_bbh_data:/data" -v "<repo>/apolaki/agent:/app" -v "<scratch>:/out" \
  -w /app apolaki-agent python /out/measure_q082.py
```

# 6. Patches for files this lane does NOT own

Nothing is required for Q-082 to be closed — all four fixes landed inside `agent/report.py`. Two
items for the owners of other files, both measured above:

1. **`agent/report.py` is not the only presenter** — `poc_bundle.build` was already correct, which is
   the useful half of the news. No patch needed; recorded so the next lane knows the convention
   (`reproduction.open = "file:line"`) already exists and was matched rather than reinvented.
2. **`agent/codeintel.py` (owned by a live lane)** — unrelated to this ticket but visible from it:
   the single non-Java row of the 716 is `webapp/js/jquery.min.js:2`, a vendored minified bundle.
   That is Q-083 and is already filed; no action taken here.
