# Codex Lane 6 Handoff: Q-044 SAST Production Entry

## Lease

- Branch: `codex/sast-production-entry`
- Baseline: `7eba1fbf19bf1956abb088d72c5e9849d9c1e3c5`
- Worktree: `C:/Users/voice/Desktop/GitHub/MISC-codex-lane6`
- Owned production file: `apolaki/agent/main.py`
- Owned tests: `apolaki/agent/tests/test_sast_entry*.py`

## Measured Baseline

Preflight on `http://localhost:8000/missions`: `running_missions=0`.

Command:

```text
MSYS_NO_PATHCONV=1 docker run --rm -v "C:/Users/voice/Desktop/GitHub/MISC-codex-lane6/apolaki/agent:/app" -w /app apolaki-agent python -m pytest tests/ -p no:cacheprovider -rx
```

Result:

```text
2189 passed, 9 skipped, 4 xfailed, 9 warnings in 285.88s (0:04:45)
```

The measured count matches the coordinator's expected 2189. The isolated worktree did not contain
the main worktree's dirty dataflow files or either attributed dead-code failure.

## Fail-Before-Fix

Added `agent/tests/test_sast_entry.py`, then ran it against the unchanged `main.py`:

```text
FFFF.                                                                    [100%]
4 failed, 1 passed, 3 warnings in 3.82s
```

All four failures were semantic: `/engage` returned HTTP 200 and a valid mission id, but its response
had no `source_review` state (`KeyError: 'source_review'`). There was no ImportError, fixture failure,
timeout, or unrelated assertion. The already-supported legacy `/codereview` preservation control
passed before the fix.

Controls established before production changes:

1. A real `/engage` mission over Java and Python source must persist the exact findings returned by
   `codeintel.review_source_tree`, retain source-derived proof semantics, and render the lane.
2. A confirmed analyzer row without canonical source markers must never enter the findings table or
   a report as DAST.
3. No source must be `not_run` with `no source provided`, never a clean scan.
4. An invalid source path must be an environment/input error, never a clean scan.
5. Existing `/codereview?path=` callers must continue to use `codeintel.review()` byte-for-byte.

## Implementation

Only `agent/main.py` changed in production:

- `EngageRequest.source_root` lets an operator attach an authorized Java/Python source tree to a real
  mission.
- `_run_source_review()` invokes the existing `codeintel.review_source_tree()` in a worker thread,
  after the mission row exists and before `/engage` returns.
- The adapter does not translate or decorate findings. It requires every row to retain the analyzer's
  exact `provenance: source-derived`, `lane: code-assisted`, and `analysis: static-call-site` markers,
  then passes it unchanged to the existing `db.add_finding()` chokepoint. A mixed or malformed batch
  fails closed: no rows from that batch are stored.
- Mission context, `/engage`, and `/missions/{id}` expose an explicit `source_review` state. Missing
  input is `not_run / no source provided`; an invalid directory or analyzer failure is `error`; neither
  is called clean.
- The persisted event log names `codeintel.review_source_tree` and writes the literal label
  `code-assisted (SAST)` into the report tool ledger.
- Existing `GET /codereview?path=` remains byte-for-byte routed to `codeintel.review()`. Its older
  lead-producing behavior was not changed.

No signature or behavior change was needed in the off-limits `codeintel.py`, `codereview.py`,
`proof_schema.py`, `report.py`, `poc_bundle.py`, or orchestration files.

## Real Production Mission

This was run separately from pytest in a disposable container by POSTing the production `/engage`
route with one real Java source file. It created persisted mission `4de49749`; the API and report
returned:

```json
{
  "source_review": {
    "status": "complete",
    "label": "code-assisted (SAST)",
    "lane": "code-assisted",
    "provenance": "source-derived",
    "files_scanned": 1,
    "findings": 1,
    "stored_findings": 1,
    "rejected_findings": 0,
    "error": ""
  },
  "finding": {
    "title": "Weak cryptographic algorithm: DES",
    "severity": "medium",
    "confidence": "confirmed",
    "family": "weak_crypto",
    "cwe": "CWE-327",
    "target": "RealMission.java",
    "file": "RealMission.java",
    "line": 2,
    "lane": "code-assisted",
    "provenance": "source-derived",
    "analysis": "static-call-site",
    "evidence": "RealMission.java:2  Cipher.getInstance(DES)",
    "tags": ["sast", "code-assisted", "crypto"]
  },
  "proof_kind": "source-derived",
  "control_status": "not_applicable",
  "report_has_sast_label": true,
  "report_has_source_proof": true
}
```

The report's existing proof renderer also added the canonical `success_oracle` and stated that a
request differential is not applicable to this static call-site proof. The DB row before report
normalization was equal to `review_source_tree()` output apart from its generated finding id.

## Semantic Mutations

The pre-mutation `agent/main.py` SHA-256 was
`6d15fe6a605985b58caa84f3ba1f234d5a1e4dc2c8b3a5a7b3c0df4fb9b6336c`. Every mutant failed the
exact named assertion, not by crash/import/fixture/timeout:

| mutant | exact kill |
|---|---|
| Replace `_canonical_source_finding()` with `return True` | bypass control observed `complete` instead of `error`; the DAST-shaped row would have persisted |
| Replace the `/engage` call to `_run_source_review()` with an unexecuted state | real-mission control observed `pending`, 0 files and 0 findings instead of `complete`, 2 and 2 |
| Mark absent source as `complete` | no-source control observed `complete` instead of `not_run` |
| Route legacy `/codereview` to `review_source_tree()` | byte-response preservation control failed and its tripwire recorded the wrong route |
| Remove `code-assisted (SAST)` from the tool-result note | real-mission report control could not find the required SAST label |
| Delete the no-source skipped-ledger event | no-source report control could not find the SAST lane label; the absent lane became silent again |

The pre-existing CRLF on the legacy route was restored after that mutant. The first five-mutant
campaign returned exactly to
`6d15fe6a605985b58caa84f3ba1f234d5a1e4dc2c8b3a5a7b3c0df4fb9b6336c`. The explicit no-source
report-ledger control was then added; its deletion mutant was killed and restored exactly to the new
final SHA-256 `8b1ebfc13f03647e962012e82a56e98d32bf2b2a78f875508eb3ff5cc754f82d`.

## Benchmark Identity

### Blind protocol and measured inputs

- The scanner containers received only source roots and the local benchmark HTTP network. No key was
  mounted. Key-like files in both source roots: **0**.
- Java input: **2763 `.java` files**, six properties files, **128 resolved properties**, 2740 result
  rows.
- Python input: **1236 `.py` files** (1230 cases plus five helper modules and `app.py`), 1230 result
  rows.
- Artifacts were SHA-256 sealed before keys were copied to a separate directory. Scoring containers
  used `--network none`.
- The three benchmark producers are byte-identical to baseline `7eba1fb`:

```text
owasp_bench.py  bc25d1fdfd573a43afbc5aab6fce5d839478beb8  identical=True
codeintel.py    2809927ff8953ea5a7fe4713d87fcabc5f2efbcf  identical=True
codereview.py   6a358f5298e8957429535153bd958ad17a009866      identical=True
```

### Seals and determinism

| suite | rows | before SHA-256 | after SHA-256 | byte-identical |
|---|---:|---|---|---|
| Java v1.2 code-assisted (SAST) | 2740 | `9c8bfe05da039dbf6ce0f25f9e9abe94dbd7137a6a2b9623321e849a840ce30d` | same | yes |
| Python v0.1 code-assisted (SAST) | 1230 | `25b7203338e1f7cffeebc7b415e909e54c75d9376ed4b9b8533716ee19d33256` | same | yes |

An earlier Python pair is retained as **superseded measurement setup failure**, not a result. Scanning
only the 1230 case files omitted the six cross-file provenance sources, produced seal
`b4bb3f2c5262df013a361fc5c9d049f12810a84c799e5836318cad504707206e`, and scored two trust-boundary
FPs (10.5% category FPR; 20.7% macro). Adding the six legitimate support sources restored the measured
1236-file input and 0 FPs. This was an input defect, not a detector or Q-044 code change.

### Full-denominator before/after results

Java code-assisted (SAST), both before and after:

```text
category         TP    FN    FP    TN       TPR     FPR    score
cmdi              0   126     0   125     0.0%   0.0%   0.0%
crypto          130     0     0   116   100.0%   0.0% 100.0%
hash            129     0     0   107   100.0%   0.0% 100.0%
ldapi             0    27     0    32     0.0%   0.0%   0.0%
pathtraver        0   133     0   135     0.0%   0.0%   0.0%
securecookie      0    36     0    31     0.0%   0.0%   0.0%
sqli              0   272     0   232     0.0%   0.0%   0.0%
trustbound       83     0     0    43   100.0%   0.0% 100.0%
weakrand        218     0     0   275   100.0%   0.0% 100.0%
xpathi            0    15     0    20     0.0%   0.0%   0.0%
xss               0   246     0   209     0.0%   0.0%   0.0%
OVERALL         560   855     0  1325    39.6%   0.0%  39.6%
official macro (11 categories): 36.4%
product macro  (11 categories): 36.4%
```

Python code-assisted (SAST), both before and after:

```text
category          TP    FN    FP    TN       TPR     FPR    score
cmdi               0    13     0     7     0.0%   0.0%   0.0%
codeinj            0    20     0    33     0.0%   0.0%   0.0%
deserialization    0    18     0    36     0.0%   0.0%   0.0%
hash              71     0     0    80   100.0%   0.0% 100.0%
ldapi              0    16     0    13     0.0%   0.0%   0.0%
pathtraver         0    65     0   103     0.0%   0.0%   0.0%
redirect           0    13     0    21     0.0%   0.0%   0.0%
securecookie       0    24     0    15     0.0%   0.0%   0.0%
sqli               0     5     0    11     0.0%   0.0%   0.0%
trustbound        18     0     0    19   100.0%   0.0% 100.0%
weakrand          99     0     0   227   100.0%   0.0% 100.0%
xpathi             0    51     0   135     0.0%   0.0%   0.0%
xss                0    31     0    58     0.0%   0.0%   0.0%
xxe                0     8     0    20     0.0%   0.0%   0.0%
OVERALL          188   264     0   778    41.6%   0.0%  41.6%
official macro (14 categories): 21.4%
product macro  (14 categories): 21.4%
```

No benchmark number moved. These are code-assisted SAST figures, never DAST figures. The remaining
zero-recall categories are unsupported by this source analyzer and remain in the denominator: Java
cmdi/ldapi/pathtraver/securecookie/sqli/xpathi/xss; Python cmdi/codeinj/deserialization/ldapi/
pathtraver/redirect/securecookie/sqli/xpathi/xss/xxe. Q-044 adds reachability only and does not claim
new detection behavior for them.

## Verification

Targeted after restoration:

```text
.....                                                                    [100%]
5 passed, 3 warnings in 3.87s
```

Full suite:

```text
2194 passed, 9 skipped, 4 xfailed, 9 warnings in 278.19s (0:04:38)
```

Exact delta from baseline: **+5 passed, +0 failed, +0 skipped, +0 xfailed**.

Tier-3 gate (baseline was not updated):

```text
Tier-3: 33/33 controls passed across 15 classes; semantic_sha256=ae9f8a1bc998f97001d5c478304d1b0197c2472ee3619328cf431baad65968ee; artifact_sha256=9ca7e0bc31f669a1cc97f4da98e9fd26309f85bf0d12e3212b3eb87d03b00323
gate_artifact_sha256=d02778c59b28a647d42716e803c35b0aa6f4502576773fb44531a837935d280f
33 Tier-3 control(s) pass; no regression against a baseline of 32
```

## Files and Integration

Changed only:

```text
apolaki/agent/main.py
apolaki/agent/tests/test_sast_entry.py
apolaki/docs/handoff/codex_lane6.md
```

Cherry-pick the commit from branch `codex/sast-production-entry`. No migration, image rebuild,
`validated_on` change, Tier-3 baseline update, or queue edit is required. The coordinator-owned and
live-lane files were read only.
