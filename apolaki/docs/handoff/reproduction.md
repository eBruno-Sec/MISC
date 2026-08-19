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

_(Sections 2+ appended as each slice lands.)_
