# Codex Lane 2 Handoff

Branch: `codex/sqli-stability-juliet`

Baseline: `bcd3e23186fb0e76a2ca64edbb05f96a1e619a8e`

## Measured baseline

The requested throwaway-container run completed in 267.05 seconds:

```text
2097 passed, 9 skipped, 5 xfailed, 9 warnings in 267.05s (0:04:27)
```

`GET /missions` was checked immediately before the run: 100 missions existed and 0 were running.

## Q-040 status

Blocked by the lease boundary, not implemented. `agent/sqli_tool.py:analyze_boolean` receives one baseline
body, one true body, and one false body. The repeated control request required to establish stability can
only be issued by the two production callers in `agent/tools.py` (GET at line 6685 and POST at line 6750),
which is outside this lane's exclusive write paths. The strict-xfail marker that must be removed is in
`agent/tests/test_sqli_oracle_negative_controls.py`, also outside the allowed paths. A helper-only change
would either leave production unwired, keep the defect, introduce position-dependent state, or disable all
boolean SQLi confirmations. None is an acceptable implementation.

The exact integration patch is recorded below. SQLi before/after was not measured because applying
or partially applying a production change across the lease boundary would invalidate the lane.

## B-010 upstream pin

Official archive verified before source inspection:

| Field | Measured value |
|---|---|
| Name | NIST SARD Juliet Java 1.3, suite 111 |
| Maintainer/author | NSA Center for Assured Software; distributed by NIST SARD |
| Upstream | `https://samate.nist.gov/SARD/test-suites/111` |
| Archive | `2017-10-01-juliet-test-suite-for-java-v1-3.zip` |
| Archive bytes | 76,798,417 |
| Published and measured SHA-256 | `d985f4177c2bcd7b03455a05c1c8f2e755f55c9eb250accd052f05f877347e60` |
| Version/submission | 1.3 / 2017-10-01 |
| Language | Java |
| Corpus size | 28,881 test cases across 112 CWEs |
| License | Public domain in the United States; CC0 1.0 for any NIST foreign rights |
| Ground truth | CWE-labelled synthetic SAST cases; mixed files carry flaw/fix locations in the upstream manifest |

## B-010 measured result

Classification: **B1, code-assisted (SAST)**. It is not a DAST score and is not comparable to ZAP or
other black-box benchmark figures.

The blind phase scanned all 131 Java files under the three supported CWE directories, including 12
generated launcher/harness files. B1 scoring covers every direct `bad()` and `goodN()` method in all
119 actual testcase files across flow variants 01-17. Dispatch-only `good()`/`main()` wrappers and
generated launchers are excluded explicitly because they contain no oracle-bearing call site. No
case inside the declared 329-method denominator was skipped.

| CWE | TP | TN | FP | FN | denominator | precision | recall | F1 | FPR | FNR |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| CWE-327 | 34 | 0 | 60 | 0 | 94 | 0.361702 | 1.000000 | 0.531250 | 1.000000 | 0.000000 |
| CWE-328 | 51 | 90 | 0 | 0 | 141 | 1.000000 | 1.000000 | 1.000000 | 0.000000 | 0.000000 |
| CWE-338 | 34 | 60 | 0 | 0 | 94 | 1.000000 | 1.000000 | 1.000000 | 0.000000 | 0.000000 |
| **overall** | **119** | **150** | **60** | **0** | **329** | **0.664804** | **1.000000** | **0.798658** | **0.285714** | **0.000000** |

Official and whole-product views are identical for this slice; `cross_family_fp=0`. All 60 false
positives are Juliet CWE-327 safe methods that select bare `AES`. Juliet 1.3 treats that as the fix;
Apolaki intentionally reports JCE's implicit ECB mode as CWE-327. The adapter does not suppress or
special-case this ground-truth conflict. CWE-328 and CWE-338 are each 100% precision and recall here.

The other 109 Juliet CWE families are **UNSUPPORTED by this benchmark run** and are not smuggled out
of a denominator. This slice measures only the three families with existing explicit Java producers.

### Blindness and artifacts

The production scanner receives complete upstream source plus an opaque hashed `.java` filename. It
never receives the CWE category, source path, manifest, expected label, or score. The run checkpoint
was sealed before `Java/manifest.xml` was opened. NIST's pinned manifest is malformed by duplicate
`</testcase>` tags at measured lines 50084 and 66737; the structured recovery parser accepts exactly
those two lines and treats any changed recovery set as an environment failure.

| Artifact | SHA-256 / semantic SHA-256 |
|---|---|
| raw checkpoint, 131 rows | `fea6db9ead640e9d9810e137ff288e83286d89795f4e1123f7642e7252b074c3` |
| blind artifact file | `518fc5c2def272457d4f961ef51481abe1449ce81633752579ed97e561718d29` |
| blind semantic | `8f8524c76928e2b60fd329155266531c77076477453a091bf797cad39c7eb01f` |
| score artifact file | `2cc5b5eb8b37850cc2d66e41fa2646d5548f26771d450107d3c3d50cd965bd7e` |
| score semantic | `7220257d1ae17efea329e586fd58ea7399c6dab67cf892c3f74ea956cd8f6f4c` |
| archive/answer-key | `d985f4177c2bcd7b03455a05c1c8f2e755f55c9eb250accd052f05f877347e60` |

A second fresh scan produced a byte-identical checkpoint and the same blind semantic hash. A second
score produced a byte-identical score object and the same score semantic hash. Full JSON artifact
hashes differ by design because their UTC timestamps differ. Measured second-run wall times were
3.555 seconds for scanning and 3.984 seconds for scoring in the existing `apolaki-agent` image.

### B-002 contract result

The contract held under the foreign suite. `bench_juliet.py` directly consumes `CaseCheckpoint`,
`seal_run`, `ArtifactSeal`, `verify_seal`, `load_key_after_seal`, `score_b1`, and
`write_json_artifact`. It required no edit to `bench_contract.py`, `owasp_bench.py`, or `tier3/**`.
It supplied durable resume, raw evidence, seal-before-key, full B1 metrics, unresolved-case handling,
and dual official/product scoring. No contract gap was found in this consumer.

### Semantic mutations

Seven semantic mutants were run one at a time; `agent/bench_juliet.py` was restored byte-identically
afterward (SHA-256 `2448d16d69cf994ee9e2ea659495902093162185cb005215cc24586357c7681f`).

| Mutant | Exact intended control | Result |
|---|---|---|
| disable archive SHA-256 comparison | same-size changed ZIP must be environment failure | KILLED |
| pass Juliet source path instead of opaque name | scanner input must expose no CWE/good/bad label | KILLED |
| ignore completed checkpoint IDs | second invocation must not rescan completed sources | KILLED |
| attribute whole-file findings to every method | genuinely safe twins must remain TN | KILLED |
| reseal a changed checkpoint before scoring | tamper must fail before manifest loader runs | KILLED |
| accept any tolerant-parser recovery | recovery set must equal the pinned measured lines | KILLED |
| remove the 119-testcase-file ratchet | changed testcase file count must be environment failure | KILLED |

### Q-040 integration patch (not applied: paths outside lease)

Required producer/consumer contract:

```diff
--- a/apolaki/agent/sqli_tool.py
+++ b/apolaki/agent/sqli_tool.py
@@
-def analyze_boolean(baseline, true_body, false_body, thresh=0.95):
+def analyze_boolean(baseline, baseline_repeat, true_body, false_body, thresh=0.95):
+    # An unstable reference invalidates both outcomes. Prefer a false negative to a false positive.
+    if similar(baseline, baseline_repeat) < thresh:
+        return False
     st = similar(baseline, true_body)
     stf = similar(true_body, false_body)
     return st >= thresh and stf < thresh
--- a/apolaki/agent/tools.py
+++ b/apolaki/agent/tools.py
@@ GET boolean pass
+                    # Re-sample the unmodified request after the pair. If the target's own page
+                    # does not reproduce, neither branch is proof. Prefer a false negative here.
+                    base_repeat_r, _ = await get(c, url)
+                    if base_repeat_r is None:
+                        continue
-                    if sqli.analyze_boolean(base_body, rt.text, rf.text):
+                    if sqli.analyze_boolean(base_body, base_repeat_r.text, rt.text, rf.text):
@@ POST form boolean pass
+                            fbase_repeat = await _post(forig)
+                            if fbase_repeat is None:
+                                continue
-                            if sqli.analyze_boolean(fbody, rt.text, rf.text):
+                            if sqli.analyze_boolean(
+                                    fbody, fbase_repeat.text, rt.text, rf.text):
--- a/apolaki/agent/tests/test_sqli_oracle_negative_controls.py
+++ b/apolaki/agent/tests/test_sqli_oracle_negative_controls.py
@@
-@pytest.mark.xfail(strict=True, reason="LIVE DEFECT: ...")
 def test_an_unstable_page_must_not_confirm_blind_sqli():
-    assert not sqli.analyze_boolean(NOISE_A, NOISE_A, NOISE_B)
+    assert not sqli.analyze_boolean(NOISE_A, NOISE_B, NOISE_A, NOISE_B)
@@
-                assert not sqli.analyze_boolean(base, page % pair["true"], page % pair["false"]), \
+                assert not sqli.analyze_boolean(
+                    base, base, page % pair["true"], page % pair["false"]), \
@@
-    assert not sqli.analyze_boolean(same, same, same)
+    assert not sqli.analyze_boolean(same, same, same, same)
@@ nonce control
+    repeat = page % ("d113c9807e4f6a2b", "1")
-    assert not sqli.analyze_boolean(base, true_, false_)
+    assert not sqli.analyze_boolean(base, repeat, true_, false_)
@@ small dynamic block
-    assert not sqli.analyze_boolean(base, true_, false_)
+    assert not sqli.analyze_boolean(base, base, true_, false_)
--- a/apolaki/agent/tests/test_bbh.py
+++ b/apolaki/agent/tests/test_bbh.py
@@
-    assert sqli.analyze_boolean(base, t, f) is True
+    assert sqli.analyze_boolean(base, base, t, f) is True
@@
-    assert sqli.analyze_boolean(base, base, base) is False
+    assert sqli.analyze_boolean(base, base, base, base) is False
--- /dev/null
+++ b/apolaki/agent/tests/test_sqli_stability.py
@@
+import sqli_tool as sqli
+
+
+def test_unstable_page_without_injection_does_not_confirm():
+    assert not sqli.analyze_boolean("normal A", "normal B", "normal A", "normal B", 0.95)
+
+
+def test_unstable_page_with_real_differential_still_does_not_confirm():
+    assert not sqli.analyze_boolean("normal A", "normal B", "normal A", "no rows", 0.95)
+
+
+def test_stable_page_with_boolean_differential_still_confirms():
+    normal = "Product: Widget (in stock)"
+    assert sqli.analyze_boolean(normal, normal, normal, "No results found", 0.95)
+
+
+def test_stable_page_without_differential_does_not_confirm():
+    normal = "Product: Widget (in stock)"
+    assert not sqli.analyze_boolean(normal, normal, normal, normal, 0.95)
```

Only the `sqli.` calls above change; the similarly named `nosqli.analyze_boolean` contract in
`test_bbh.py` is unrelated. Add transport tests that count the unmodified GET and POST repeat request,
so the pure helper cannot pass while production remains unwired. Apply this only after leasing
`agent/tools.py` and the two existing test files, then rerun the SQLi category with its full denominator
before/after.

## Negative controls

| Control | What it proves |
|---|---|
| digest-preserving-size mutation | archive identity depends on SHA-256, not byte count alone |
| manifest-open guard during scan | ground truth cannot be read before the run is sealed |
| opaque scanner input name | production analysis receives no Juliet path/CWE/label metadata |
| resume with scanner replaced by a failure | completed cases are not position-dependently rerun |
| 131-file corpus-shape mismatch | a truncated/changed archive is an environment failure |
| missing/corrupt archive | setup failure never becomes TN, FN, or a publishable score |
| direct bad/safe pair | vulnerable methods detect and genuinely safe twins stay quiet |
| weak call inside safe twin | a safe-side detection is counted as FP, not hidden |
| Juliet legacy bare-AES safe twin | benchmark disagreement remains an FP; no answer special-case |
| changed checkpoint before key load | scoring rejects tampering before opening ground truth |
| changed manifest recovery set | tolerant parsing is exact-line bounded, not permissive |
| changed 119-testcase count | declared denominator cannot silently shrink |
| persisted method evidence | each score retains source hash, method span, manifest lines, and findings |

Fail-before-fix was verified against an exact temporary `bcd3e23` archive with these two test files
overlaid. Both failed at collection with `ModuleNotFoundError: No module named 'bench_juliet'`. That
proves only that the module is new, not that its logic is discriminating; the seven semantic mutants
above provide the required behavioral discrimination.

## Files added

No existing repository file was modified. Added:

```text
apolaki/agent/bench_juliet.py
apolaki/agent/tests/test_bench_juliet_blind.py
apolaki/agent/tests/test_bench_juliet_score.py
apolaki/labs/juliet/README.md
apolaki/labs/juliet/fetch.ps1
apolaki/labs/juliet/manifest.json
apolaki/labs/juliet/juliet_java_1_3_run.jsonl
apolaki/labs/juliet/juliet_java_1_3_blind_scan.json
apolaki/labs/juliet/juliet_java_1_3_score.json
apolaki/docs/handoff/codex_lane2.md
```

## Verification

Targeted:

```text
.x........................                                               [100%]
XFAIL tests/test_sqli_oracle_negative_controls.py::test_an_unstable_page_must_not_confirm_blind_sqli - LIVE DEFECT: analyze_boolean has no baseline-stability control, so an unstable page confirms blind SQLi. Remove this marker when the oracle re-samples the baseline.
25 passed, 1 xfailed in 3.64s
```

Full suite (baseline was 2097 passed / 9 skipped / 5 xfailed):

```text
2110 passed, 9 skipped, 5 xfailed, 9 warnings in 268.92s (0:04:28)
```

Tier-3 gate:

```text
Tier-3: 32/33 controls passed across 15 classes; semantic_sha256=9a651e709d8e430e12abed610089d26b80ddf8e12408dca16b1758b4078fb455; artifact_sha256=eb3839850da4bca643e12a2e20315d647d887f42181b4e447950395818faa52e
gate_artifact_sha256=a8ecd0421ca394c5ca063d8bcd7a798fc8804839392243542eb84ad11454592e
32 Tier-3 control(s) pass; no regression against a baseline of 32
known non-passes (not credited): sqli-unstable-page-noise
```

The checked-in `scripts/tier3_gate.sh` has CRLF line endings, so Linux bash first rejected it before
the runner executed (`set: -\r: invalid option`). This lane did not edit the shared script. The same
script was copied to container `/tmp`, line endings alone were normalized, the repository was mounted
read-only, and the gate output above is from that run. Coordinator should normalize the script to LF.

Liveness was not run or updated, no image was rebuilt, no running mission was interrupted, and no
`validated_on` value changed, per the lease.

Commits: pending.
