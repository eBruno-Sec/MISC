# Codex lane 3 - Q-040 blind-SQLi stability

Branch: `codex/sqli-stability`

Baseline: `50c8370b8f5cb5981cb2fd1a6291147226cc1c9f`

## Measured baseline

- Worktree status before work: clean.
- Mission preflight: 0 missions with status `running`.
- Full suite in the required throwaway container: `2110 passed, 9 skipped, 5 xfailed, 9 warnings in 291.29s (0:04:51)`.
- The five xfails included exactly one Q-040 control: `test_an_unstable_page_must_not_confirm_blind_sqli`.
- Shipping `sqli.analyze_boolean` call sites in `_run_sqli`: 2 (GET query and POST form).

## Work log

- Controls written before production: 7 new shipping controls plus the existing strict-xfail control, with no production edits present.
- Fail-before-fix: `8 failed, 12 passed in 3.24s`. No crash, import error, fixture error, timeout, or skip was counted. The old engine produced a confirmed finding for both the payload-agnostic unstable GET control and the genuinely injectable but unstable GET/POST controls. Stable positive/negative controls failed their exact transport assertion because the second request was already a quote or predicate probe. Both shipping call sites omitted `baseline_repeat`. The unmarked historical control failed because `analyze_boolean(NOISE_A, NOISE_A, NOISE_B)` returned `True`.
- Pre-fix OWASP Benchmark Java SQLi measurement:
  - Served denominator measured without key access: 504 cases.
  - Fully blind eight-shard run: 504 unique rows, 0 errors, sealed before key access at `886005fd37873a831fa8b6952d8a235cacd5fc15d525e5aebaf2f875aa4a069a` (161456 bytes, 2026-08-13T07:54:22.3405026Z). Score: TP 181 / FN 91 / FP 2 / TN 230, TPR 66.5%, FPR 0.9%, measured-category score 65.7%. The two clean detections were BenchmarkTest00344 and BenchmarkTest01307. This contradicts the known zero-FP baseline and is retained as a concurrency-instability diagnostic, not the authoritative before figure.
  - Single-process run: 504 unique rows, 0 errors, SHA-256 `32a06263b3a8eb64cb4a546b5b218213002e8d07587c6383e93a91dd116bae37` (233704 bytes, 2026-08-13T07:59:23.6955892Z). Score: TP 180 / FN 92 / FP 0 / TN 232, TPR 66.2%, FPR 0.0%, measured-category score 66.2%. This reproduces the known zero-FP shape and is the authoritative before figure. The scanner was key-isolated, but the operator key had already been extracted to score the earlier blind-sharded artifact; this second artifact must not be described as sealed-before-first-key-access.
- Implementation: `BOOLEAN_BASELINE_SAMPLE_COUNT = 2`; both GET-query and POST-form boolean paths issue an identical second reference request and pass it explicitly to `analyze_boolean`. A failed or unstable repeat rejects confirmation. Existing error, quote-recovery, UNION and timing paths are unchanged. Targeted result after implementation and after mutation restoration: `20 passed in 2.87s`.
- Added request cost: exactly 1 GET reference request for an `_run_sqli` endpoint with query parameters, plus exactly 1 POST reference request per tested form field. Endpoints with no query parameters pay no GET repeat. The measured sample-count constant is 2 total references (1 existing + 1 added).
- Semantic mutation:
  - Inverted stability (`< thresh` -> `>= thresh`): killed by `test_stable_page_with_real_boolean_differential_still_confirms`; exact failure was `len(result.findings) == 0`, `1 failed in 2.26s`.
  - Changed sample count (`2` -> `1`): killed by the same shipping control; exact request sequence began `['1', "1'", "1''"]` instead of `['1', '1', "1'"]`, `1 failed in 2.27s`.
  - Deleted the stability rejection branch: killed by `test_an_unstable_page_must_not_confirm_blind_sqli`; `analyze_boolean(..., baseline_repeat=NOISE_B)` returned `True`, `1 failed in 1.83s`.
  - Production files restored byte-identically after mutants: `sqli_tool.py` SHA-256 `1776375d248389df74539e97b2c94d20f693280cc4894c874fdc904f33c8a905`; `tools.py` SHA-256 `ef0d472e56aa809f8c8559293c1a8e154ca645f12af989f61094dda0998f5f59`.
- Post-fix OWASP Benchmark Java SQLi measurement:
  - Single-process run: 504 unique rows, 0 errors, sealed at 2026-08-13T08:10:32.3877451Z with SHA-256 `32a06263b3a8eb64cb4a546b5b218213002e8d07587c6383e93a91dd116bae37` (233704 bytes).
  - Score: TP 180 / FN 92 / FP 0 / TN 232; TPR 66.2%, FPR 0.0%, FNR 33.8%, precision 100.0%, measured-category score 66.2%.
  - Before/after delta over the full SQLi denominator: TP 0 / FN 0 / FP 0 / TN 0. The pre/post sequential artifacts are byte-identical. The defect closed without benchmark loss.
  - The post scanner had neither a key mount nor a route to the key container. Because the operator had already extracted the key after sealing the initial eight-shard run, this is key-isolated execution and seal-before-score, not a claim that the operator first learned the key after the post run.
  - Adversarial eight-shard replay after the fix: 504 unique rows, 0 errors, SHA-256 `e5a8b49d781f8dc550c7d232f50b0592d1ae4e45dee16b3dca1f3ee6e9368baa`; TP 181 / FN 91 / FP 1 / TN 231. The remaining clean detection was BenchmarkTest02366, not either pre-fix clean detection. Neither of its two recorded targets produced a finding in direct replay, including 64 concurrent runs. The concurrent result is therefore volatile and cannot be attributed to Q-040; it is excluded from the authoritative before/after score rather than tuned around or silently discarded.
- The strict xfail is removed and is a genuine pass. The Tier-3 runner now reports the previously skipped control as PASS, tightening the live result from the committed floor of 32 to 33.

## Verification output

Targeted, after restoring every mutant:

```text
....................                                                     [100%]
20 passed in 2.87s
```

Full suite, required throwaway container:

```text
2118 passed, 9 skipped, 4 xfailed, 9 warnings in 266.86s (0:04:26)
```

This is baseline +8 passing tests, with the same 9 skips and one fewer xfail. No dead-code failure appeared in the clean worktree.

Tier-3 gate, with generated artifacts redirected to container `/tmp` because `agent/tier3/**` is shared read-only:

```text
Tier-3: 33/33 controls passed across 15 classes; semantic_sha256=ae9f8a1bc998f97001d5c478304d1b0197c2472ee3619328cf431baad65968ee; artifact_sha256=7fde952a492f86bd6666d2c52b43c76e018d7cacfc31cd38cd4657e6f63ace46
gate_artifact_sha256=cbe0d5c05430bc2ccf047ef5e24dbd95c55f4ef37aef5994870d8d3e19148736
33 Tier-3 control(s) pass; no regression against a baseline of 32
```

Offline post-fix SQLi score:

```text
category         TP    FN    FP    TN       TPR     FPR    score
sqli            180    92     0   232    66.2%   0.0%  66.2%
OVERALL         180    92     0   232    66.2%   0.0%  66.2%
```

## Scope and integration

- Files changed: `agent/sqli_tool.py`, the blind-SQLi block of `agent/tools.py`, `agent/tests/test_sqli_oracle_negative_controls.py`, new `agent/tests/test_sqli_stability.py`, and this handoff.
- No off-limits file was edited. In particular: no Tier-3 registry/baseline, benchmark harness, queue, status, report, proof schema, planner, dataflow file, compose file, or `validated_on` value changed.
- The two legacy three-argument pure-helper calls in `test_bbh.py` remain compatible. Production cannot use that compatibility path unnoticed: the measured two-call-site AST ratchet requires `baseline_repeat`, and GET/POST behavior tests prove the request is actually sent.
- Integration: cherry-pick the single Q-040 commit from branch `codex/sqli-stability`; no generated benchmark artifact is committed.
