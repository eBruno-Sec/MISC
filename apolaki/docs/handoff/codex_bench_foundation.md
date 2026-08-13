# Codex benchmark-foundation handoff

Branch: `codex/bench-foundation`
Baseline: `fe6875b876629baaf6198748788d7ab1024c5e06`

## Baseline

Status: measured.

The first throwaway full-suite container completed with exit code 0, but its client-side command
timed out and `--rm` removed the summary before it was captured. That is recorded as an environment
interruption, not as a measured test denominator. The identical rerun produced the durable baseline:

```text
2061 passed, 9 skipped, 5 xfailed, 9 warnings in 254.58s (0:04:14)
```

This differs from the handed-off remembered number (`2045 passed / 9 skipped / 1 xfailed`) by
16 passing tests and 4 expected failures. The measured number is the only baseline used below.

No mission had status `running` before either invocation.

## M1 - B-001 Tier-3 corpus

Status: implemented and measured; commit pending.

### Before

The eleven input files collect **130 pytest nodes**. At baseline SHA `fe6875b`, `agent/tier3` does
not exist (`git ls-tree` returns no path), so executable registry coverage is **0 classes**. This is
not a claim that the tests did nothing; it is the narrower repository-proven fact that no registry
or runner could answer which controls executed by vulnerability class.

### After

Two independent full registry runs produced the same contractual result:

```text
Tier-3: 32/33 controls passed across 15 classes
semantic_sha256=9a651e709d8e430e12abed610089d26b80ddf8e12408dca16b1758b4078fb455
```

The full artifact hashes differ, as expected, because timestamps and pytest timing tails remain in
the diagnostic artifact:

```text
run C artifact_sha256=16bbf5bd55968e87950b288b971c40242c318e450f6d19d6a3a981883d8053ad
run D artifact_sha256=8c73de93649fd2a375f55206b79283304ed55f879133e7b124724d342c08f311
```

The committed baseline is run C at `agent/tier3/baseline.json`. It covers 15 classes. Eight have a
passing `SAFE` control: access_control, command_injection, evidence_contract, sqli, weak_crypto,
weak_hash, weak_random, and xss. Seven honestly remain safe-control gaps: benchmark_scoring,
code_assisted_analysis, probe_delivery, proof_gate, proof_reporting, surface_discovery, and
technique_contract.

The only non-pass is `sqli-unstable-page-noise`: `SKIPPED`, because its existing test is a strict
xfail documenting that `analyze_boolean` has no baseline-stability resampling. It remains registered
and does not count as coverage. The required implementation is in probe-lane-owned `sqli_tool.py`,
so this lane did not touch it.

### Counterexamples and mutation

- A real temporary test and a stale registered node were executed separately: real = `PASS`, stale
  = `NOT_RUN`, registry coverage = `1/2`.
- A registered node in a module with an import error produced no coverage and an environment-failure
  record.
- Semantic mutant: `_rollup` was changed from `status == PASS` to `status != FAIL`, which falsely
  credited `NOT_RUN`. The exact intended test failed with `registered == 2` and `passed == 2` where
  `passed == 1` was required. The source was restored byte-identically; SHA-256 before and after was
  `B4ECEB86E4F5CBBEF74157B0FDFC448BC1E1685C565C1D371E7DC1C92A8D62D9`.

Targeted verification:

```text
7 passed in 6.77s
```

Commit: `776dff1` (`Apolaki B-001: make Tier-3 controls executable and measurable`).

## M2 - B-002 benchmark adapter contract

Status: implemented and measured; commit pending.

`agent/bench_contract.py` is a pure contract layer, not another scanner. It supplies:

- explicit pre-key measurement states and post-key result vocabulary;
- JSONL per-case append, flush, fsync, resume, duplicate conflict detection, truncated-final-row
  recovery, and separation of a valid final row with no newline;
- mandatory `raw_evidence` on every case, including non-detections and environment failures;
- a verifiable `ArtifactSeal` token that blocks the key loader if the blind run changed;
- complete B1 TP/TN/FP/FN, precision, recall, F1, FPR, and FNR over the full denominator;
- separate official and product views, where the product view counts a confirmed foreign-family
  finding on a clean case as an FP;
- a non-publishable result when any B1 case is missing, unsupported, inconclusive, or failed due to
  the environment. The full denominator remains visible; no environment failure becomes an FN/TN.

### Unmodified OWASP adapter conformance

The measured artifact is `agent/tier3/owasp_conformance.json`:

```text
CONFORMANT 5 | PARTIAL 1 | GAP 5
semantic_sha256=27b4922459d7e84cafe4397f7142d80cce065ae1d912b82cbd36faed187a0a02
artifact_sha256=3e40dd2aa4e537cbc7a0a3c6430f94d0c98e59cf0b86ad2900c511e65205fd8a
```

| clause | measured state |
|---|---|
| dual official/product scoring | CONFORMANT |
| full-suite macro denominator | CONFORMANT |
| checkpoint flush + fsync | CONFORMANT |
| checkpoint resume | CONFORMANT |
| truncated final-row recovery | CONFORMANT |
| full B1 metric set | PARTIAL - precision, F1 and FNR absent |
| raw-evidence retention | GAP |
| enforced seal-before-key | GAP |
| explicit result vocabulary | GAP |
| environment failure excluded from scoring | GAP |
| position independence | GAP - one registry reused, budget state not recorded |

This is why `owasp_bench.py` remains untouched: it already supplies five proven behaviours, and the
new contract states the five adoption gaps for a future owner instead of silently claiming conformance.

### Tests, negative controls, and mutations

The first run was `12 passed, 1 failed`. My new evidence-retention assertion assumed input index 1
would remain case `C`, while the scorer deliberately sorts IDs for position independence. It was a
wrong test and was corrected to select by `case_id`; the retention obligation was unchanged. Final:

```text
14 passed in 1.94s
```

Fail-before-fix at `fe6875b` is only `ImportError: bench_contract` and therefore proves newness, not
discrimination. Three semantic mutants supply the actual evidence:

1. Removed `verify_seal(seal)`: the exact tamper test failed `DID NOT RAISE SealError`; the key loader
   would have run.
2. Replaced `product_hit = bool(confirmed)` with `product_hit = official_hit`: the exact product test
   failed `assert 0 == 1` for the clean cross-family FP.
3. Removed per-case `os.fsync`: the exact checkpoint test failed because the fsync call list was empty.

All three were restored before further work. `bench_contract.py` SHA-256 before the mutants and after
restoration was identical:
`D37624CC083F7390A45E9B44D77C2A1CC4612A3205B009DDF79C8146ED20FC9B`.

Commit: `d5746a4` (`Apolaki B-002: codify proof-safe benchmark adapters`).

## M3 - B-003 Tier-3 quality gate

Status: implemented and measured; commit pending.

`scripts/tier3_gate.sh` executes the real registry, retains its current artifact, and compares it
with `agent/tier3/baseline.json`. The generic runner process code is deliberately not the oracle:
the known strict xfail makes that process nonzero. `tier3.gate` instead requires every baseline PASS
to remain PASS, records loss of a class's final passing control separately, treats removed baseline
nodes as `NOT_RUN`, and fails on every current `FAIL`, `ERROR`, `NOT_RUN`, or environment failure.
The baseline file is never modified by the gate.

Unit verification:

```text
14 passed in 2.08s
```

End-to-end shell-gate output:

```text
Tier-3: 32/33 controls passed across 15 classes
semantic_sha256=9a651e709d8e430e12abed610089d26b80ddf8e12408dca16b1758b4078fb455
artifact_sha256=f2642fcaee32128ca638d8bd59868e812eefa5300f920140ae01e7da0eeddad1
gate_artifact_sha256=02a9c03d32fb7c82ed3fe9d04f713abe3a834b91abed0695b9ed6758e3c1b15e
32 Tier-3 control(s) pass; no regression against a baseline of 32
known non-passes (not credited): sqli-unstable-page-noise
```

Gate semantic SHA-256:
`64caa30c79d78282175771d9e29f9a2b08e81b0df1180a52d1e39a5607f2804c`.
Both the current and baseline registry semantic hashes are
`9a651e709d8e430e12abed610089d26b80ddf8e12408dca16b1758b4078fb455`.

Fail-before-fix is again only module absence, so three semantic mutants provide discrimination:

1. Changed regression from `current_status != PASS` to `current_status == FAIL`: exact tests lost
   regression records for `SKIPPED`, `ERROR`, and `NOT_RUN` (3 failed, 1 passed).
2. Hardcoded class regression false: removing the class's only passing node no longer reported the
   `sqli` class regression; the exact assertion failed.
3. Made only `FAIL` fatal for a newly registered control: `ERROR` and `NOT_RUN` incorrectly returned
   `ok=True`; exact tests failed (2 failed, 1 passed).

`tier3/gate.py` was restored byte-identically after the mutants. SHA-256 before and after:
`ADB18FE66131D8B0ADEF629B5C9D43FA290CCE00D44BCE049A9144C5BB90E62A`.

Commit: `a1b48c2` (`Apolaki B-003: ratchet executable Tier-3 coverage`).

## Full-suite integration catch - B-002 CLI consumer

The first post-milestone full suite was not green and is not hidden:

```text
2 failed, 2094 passed, 9 skipped, 5 xfailed, 9 warnings in 295.19s
```

Both failures were the dead-code guard doing its job:

- bare scan: `bench_contract.write_json_artifact` had no production caller;
- qualified ratchet: `37 -> 43`, with exactly six new `bench_contract.*` APIs test-consumed but not
  production-consumed.

No baseline or allowlist was changed. `bench_contract.main` now supplies real CLI paths for checkpoint
inspection, sealing, OWASP conformance artifacts, and sealed B1 scoring. The sealed scoring path calls
all six APIs and retains the run seal, key hash, key-read timestamp, and ordering verdict in its output.

Targeted contract plus the two exact dead-code assertions:

```text
17 passed in 84.78s
qualified dead-code: count=37 baseline=37 ok=True
bench_contract islands: []
```

This integration repair is pending its own commit before the final full-suite rerun.
