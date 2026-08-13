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
