# Breaker (verification agent) — findings log

Status: IN PROGRESS. Written incrementally; whatever is here is the contribution.

> SESSION 2 (2026-08-11) picks up at the exact line session 1 died on: "now the mutation check on my
> own tests". Session-2 sections are appended at the bottom: MUTATION CHECK, TARGET 3 (code-assisted
> lane), and ENVIRONMENT WARNING. Session-1 findings below are unchanged.

Baseline claimed by Coordinator: 1792 passed, 9 skipped, 0 failed.
Owned by me: test files + this file. Production code is READ-ONLY to me.

## Targets
1. FP `BenchmarkTest00494` (clean cmdi, Apolaki claimed sqli) — root cause + attack the sqli oracle.
2. Is 95.7% precision real? Tally what the sqli oracle actually compared, per confirmation.
3. Attack today's commits: 837b1f0 (control_ran gate), 3d41f9a (product FPR), 0233574 (traversal oracle).

## Environment
- `curl -s http://localhost:8000/missions` — no mission RUNNING. Latest `ebd96f45` (owaspbench-q019) = complete.
  NOTE: nuclei temp dirs in `apolaki-agent-1:/tmp` timestamped 09:51-10:03 — something else is exercising
  the agent. I did NOT rebuild any image.
- Lab: `apolaki-owaspbench-1`, host `https://localhost:42095/benchmark/`, container `https://owaspbench:8443/benchmark/`.
- Answer key already in the container at `/tmp/key.csv` (expectedresults-1.2.csv, 2740 rows).

---

# TARGET 1 — the `BenchmarkTest00494` false positive: ROOT CAUSE FOUND

## What actually fired

Not `error-recovery`. It was **`boolean-blind`**, and the carrier was the **POST-form-field lane**
(`tools.py` `_run_sqli` step 4), not the query string. Stored finding (mission `ebd96f45`):

```
title   : SQL injection (boolean-blind) in 'productID'
target  : https://owaspbench:8443/benchmark/cmdi-00/BenchmarkTest00494
request : GET https://owaspbench:8443/benchmark/cmdi-00/BenchmarkTest00494 [POST productID]
evidence: TRUE~=baseline, FALSE diverged (string-comment)
payloads: true = "1' AND 1=1-- -"   false = "1' AND 1=2-- -"
```

`productID` is not a parameter of this case at all — the case's real parameter is
`BenchmarkTest00494`. `productID` came from a form on the page and the app **ignores it entirely**.

## The mechanism: an unstable response body, and an oracle with no stability control

`BenchmarkTest00494` shells out to `ping moresafe`. The DNS failure text the container's resolver
returns is **not deterministic**: the same request, byte-identical, comes back as either

```
ping&#x3a; moresafe&#x3a; No address associated with hostname
ping&#x3a; moresafe&#x3a; Name or service not known
```

MEASURED (`/tmp/brk_00494.py` in `apolaki-agent-1`, 8 identical POSTs):

```
=== 1. STABILITY: same input, 8 times ===
distinct bodies for IDENTICAL input: 2
   x4  ...<br>ping&#x3a; moresafe&#x3a; No address associated with hostname<br>
   x4  ...<br>ping&#x3a; moresafe&#x3a; Name or service not known<br>
pairwise similarity of the two stable variants: 0.9091  threshold=0.95

=== 3. DOES THE FIELD EVEN REACH THE APP? ===
body identical for '1' vs a wildly different value? True
similarity: 1.0
```

0.9091 < the oracle's 0.95 threshold. So the app's OWN NOISE, on a field the app never reads,
clears the divergence bar. `sqli_tool.analyze_boolean(A, A, B)` where A and B are the two real
recorded bodies returns **True — CONFIRMED SQLi**.

## Structural weakness (this is the part that matters)

`analyze_boolean(baseline, true_body, false_body)` is a two-sided differential in form but it
**never establishes that the baseline is reproducible**. It compares three single samples. Any
endpoint whose body varies by more than 5% between identical requests — a timestamp, a request id,
a rotating banner, a resolver message, a cache-hit marker, a load-balanced backend id — will
confirm blind SQLi with probability `P(base == true) * P(false != true)` per attempt, and the
engine retries **four contexts per field**, so one field gets four independent chances.

Same shape as the pathtraver defect: a signal that looks like a differential but is not anchored to
anything the payload caused. `_run_sqli` has no stability probe anywhere — no repeat of the
baseline, no re-test of the diverging FALSE, no check that the field is even reflected or read.

The minimal honest fix (owner's call, I do not touch production code):
- take the baseline **twice** and require `similar(base1, base2) >= thresh` before trusting any
  boolean verdict on that target — an unstable endpoint is un-testable by this oracle, not vulnerable;
- and/or re-send the FALSE payload once and require the divergence to reproduce.

Both are cheap (1-2 extra requests per target) and both kill this FP.

## Live replay caveat (honest)

Re-running the full triplet 10x live did NOT re-fire, because the two body variants do not alternate
per request — they come in runs of ~4, so base/true/false usually land in the same run:

```
  trial  1  sim(base,true)=1.0000  sim(true,false)=1.0000  -> clean
  trial  2  sim(base,true)=0.9091  sim(true,false)=1.0000  -> clean
  ... FIRED 0/10
```

That is not exoneration — it is the definition of a flaky oracle. It fired once in the scored run
and it fires deterministically when the phase lines up; feeding the oracle the two REAL recorded
bodies reproduces the confirmation every time. **A finding that appears only sometimes is not
proven** (check 5, deterministic replay): this one fails that check outright.

**VERDICT on the sqli boolean-blind oracle: REJECTED — false-positive generator on any unstable
endpoint. Check 3 (negative controls) and check 5 (deterministic replay) both fail.**

---

# TARGET 2 — is 95.7% precision real, or lucky?  ANSWER: REAL, with one named hole

Unlike pathtraver (whose whole score was one signature, `{'reflection-only': 22}`), the sqli score
splits cleanly and the two oracles behave very differently. Tally of what actually fired
(mission `ebd96f45`, all 21 sqli findings):

| oracle | findings | what it compared |
|---|---:|---|
| `error-recovery` | 15 | HTTP 200 (benign) -> 500 (single quote) -> 200 (doubled quote) — a two-sided **status** differential |
| `boolean-blind` | 6 | TRUE~=baseline vs FALSE diverged — a two-sided **body** differential |

(plus 5 `ldap_injection`, 1 `sensitive_exposure`, 1 `vulnerable_component`, 1 `dom_data_manipulation`.)

## 2a. `error-recovery` — deliberately attacked, held up

Ran the oracle's own functions against the live lab over 148 cases sampled across six categories,
vulnerable AND clean, straight off the category indexes (`/tmp/brk_sqli_sweep.py`). Every fire on a
SAFE case is an in-family FP; every fire outside `sqli` is a cross-family FP:

```
  sqli        VULN  error-recovery  15   / n=23        <- the real capability, ~65% of vulnerable sqli
  sqli        SAFE  error-recovery   0   / n=24        <- ZERO in-family false positives
  cmdi        VULN/SAFE               0   / n=15
  ldapi       VULN/SAFE               0   / n=26
  xpathi      VULN/SAFE               0   / n=23
  pathtraver  VULN/SAFE               0   / n=20
  xss         VULN/SAFE               0   / n=24
```

**0 false positives in 92 non-sqli cases and 24 clean sqli cases.** The break+recover pair is doing
real work: a page that 500s on any junk does not recover on `''`, so it never confirms. The
"generic error for any input" and "unrelated 500" attacks the brief asked for are both already
defeated by the recovery leg — I could not construct one that confirms. Attacks tried and REPELLED:

- parameter that merely echoes -> `xss` cases, 0/24 fires (echo cannot produce 200->500->200).
- generic error page -> no `''` recovery, so `quote_break_recovers` returns False.
- 500 unrelated to the payload -> same, needs the doubled-quote leg to come back <500.
- **arithmetic proof that pure reflection cannot fake `boolean-blind`**: for TRUE vs FALSE (1 char
  apart) to fall below 0.95 the page must be <6 bytes, while baseline vs TRUE (14 chars apart)
  needs >=133 bytes to stay above 0.95. The two conditions are mutually exclusive on an echo. This
  is why the pathtraver failure shape does NOT transfer to sqli.

## 2b. `boolean-blind` — the one hole, and it is exactly baseline instability

Replayed all 6 boolean-blind confirmations against the live lab, 4 identical baseline posts + 3
full independent oracle runs each (`/tmp/brk_bb_replay.py`):

| case | baseline stable? | self-similarity | oracle fired on replay | verdict |
|---|---|---:|---|---|
| BenchmarkTest00033 | yes | 1.0000 | 3/3 | genuine (len true 24 vs false 19) |
| BenchmarkTest00428 | yes | 1.0000 | 3/3 | genuine (264 vs 246) |
| BenchmarkTest00429 | yes | 1.0000 | 3/3 | genuine (264 vs 246) |
| BenchmarkTest00433 | yes | 1.0000 | 3/3 | genuine (91 vs 23) |
| BenchmarkTest00438 | yes | 1.0000 | 3/3 | genuine (264 vs 246) |
| **BenchmarkTest00494** | **NO** | **0.9091** | **0/3** | **the false positive** |

One property — does the baseline reproduce — separates the 5 true positives from the 1 false
positive **perfectly**, and costs the true positives nothing (all five sit at 1.0000). Note also
that all 6 arrived through the POST-form lane; the query-string lane produced 0 boolean-blind fires
on 23 vulnerable sqli cases in my sweep, so this lane carries the entire boolean-blind score.

**ANSWER: the 95.7% is real, not lucky.** 15/21 rest on a status differential with a measured 0/116
false-positive rate; 5/21 on a body differential that replays deterministically. 1/21 is noise, and
a two-request stability check would have caught it without touching any of the other 20.

---

# TARGET 3b — `3d41f9a` (product FPR alongside the official FPR)

## Can the two numbers silently collapse into one? — NO for collapse, YES for something worse

MEASURED, same run file (`/tmp/before.jsonl` = `owaspbench_java_FULLSUITE_41pct_20260810.jsonl`,
byte-identical, 927627 bytes), `python3 owasp_bench.py score --run ... --key /tmp/key.csv --base java`:

```
OFFICIAL SUITE SCORE (macro over ALL 11 suite categories, unmeasured = 0):  41.3%
PRODUCT SUITE SCORE (same TPR; every confirmed finding on a clean case is an FP):  34.9%
   cross-family false positives the official convention forgives: 22
```

Two distinct values, two distinct labels, both printed unconditionally inside the same block. They
converge only when `cross_family_fp == 0`, and then they are still two separately-labelled lines.
No silent collapse. **PASS.**

## Does the official figure still match the published convention exactly? — YES

Scored the identical run with the pre-commit scorer (`git show 3d41f9a^:apolaki/agent/owasp_bench.py`):

```
PRE-3d41f9a :  OFFICIAL SUITE SCORE ... 41.3%   measured-cats 56.8%   micro 62.8%
POST        :  OFFICIAL SUITE SCORE ... 41.3%   measured-cats 56.8%   micro 62.8%
```

Identical. The commit is purely additive to the official figure. **PASS.**

## But two REJECT-level defects in the same file, both live today

**D1 — a run file with no `target` key prints NEITHER number.** `suite = SUITE_CATEGORIES.get(
run.get("target") or "", [])`; when the run JSON has no `target`, `suite_macro` is None and the
whole block that prints the official AND the product score is skipped. What is left is the line the
file itself labels "NOT comparable". MEASURED on a committed artifact:

```
$ owasp_bench.py score --run docs/benchmarks/owaspbench_run8_6cat_20260810.json --key key.csv --base java
OVERALL   25 18 0 41   58.1%  0.0%  58.1%
measured-categories macro (6 cats, NOT comparable):  56.0%
micro / pooled (NOT the official number):  58.1%
   <- no OFFICIAL line, no PRODUCT line at all
```

**7 of the 8 JSON run files in `docs/benchmarks/` carry no `target`** (only
`benchmarkpython_run1_20260810.json` does). Re-score any of them today and the only number you get
is the non-comparable one — which is precisely the mistake this file's own comment records ("exactly
the mistake that made an earlier run read 58.1% when the comparable figure was 30.5%"), and 58.1% is
literally the number this file prints.

**D2 — `--base` is silently ignored whenever the run file parses as JSON.** `main()` honours
`--base` on the jsonl-fallback path (`run = {"results": rows, "target": a.base}`) but on the JSON
path the file's own `target` wins and the flag does nothing. MEASURED:

```
$ owasp_bench.py score --run benchmarkpython_run1_20260810.json --key key.csv --base java
OFFICIAL SUITE SCORE (macro over ALL 14 suite categories, ...):   1.2%
   counted as 0 (no engine / not scanned): hash, securecookie, trustbound, weakrand, xss
```

14 categories = the python suite, despite `--base java`. A flag that silently does nothing is a
wrong-number generator on a scorer whose entire job is to stop wrong numbers.

**D3 (latent, falsy-default) — `_any_confirmed`:**

```python
return any(c not in _UNPROVEN for c in confs[:len(fams)] or confs)
```

When `fams` is empty, `confs[:0]` is `[]`, which is falsy, so the `or` falls through and the
confidences are scanned anyway. A row like `{"families": [], "conf": ["confirmed"]}` is counted as a
product false positive with no finding behind it. Unreachable from `scan()` today (both lists are
built together) but this is the exact `x or DEFAULT` shape that has bitten this project twice.

**VERDICT 3d41f9a: PLAUSIBLE.** The claim it makes is true and measured (checks 1, 2, 4, 5, 6 pass;
official figure unmoved, product figure distinct). Not CONFIRMED because the file it changes has two
live wrong-number paths (D1, D2) that the commit did not introduce but does now sit on top of. I do
not own `owasp_bench.py`; D1/D2/D3 are for the owner.

---

# TARGET 3a — `837b1f0` (`control_ran` gates the confirmation claim)

## The gate itself works, and the honest findings still render

```
report.control_ran({'family':'sqli','confidence':'confirmed','target':'http://x/?id=1'}) -> False
report.proof_and_retest(...)['negative_control']
  -> "NO NEGATIVE CONTROL WAS RECORDED for this finding. The control that would settle it: ..."
```

Honest producers stay honest — `control: False`, `control: None`, `controls: []` all correctly read
as "no artifact". The BIE producers (`bie.py:373/917/1160`) build `negative_controls` with an
`if probes.get(k) is not None` filter, so a run with no controls emits `{}` and correctly gates OFF,
while a real run keeps its artifact and still renders "How this was confirmed". **That half is sound.**

## FOUND: a finding shape that still prints a confirmation claim without an artifact

`poc_bundle.build()` was not gated. MEASURED on the same artifact-free finding the commit message
uses as its own example:

```
--- report.proof_and_retest (GATED by 837b1f0) ---
NO NEGATIVE CONTROL WAS RECORDED for this finding. ...

--- poc_bundle.build -> confirmation.negative_control (NOT gated) ---
"negative_control": "An inert control of the same shape but without SQL metacharacters does NOT
                     reproduce the error/boolean/time differential; the unmodified baseline
                     behaves normally.",
"evidence_requirements": ["Negative control captured showing the confirming signal is ABSENT
                          without the trigger.", ...]
```

Present-indicative, under a key literally named `confirmation` and commented "how it was kept
honest", on a finding with no controls, no evidence, no request and no response. The bundle is the
evidence dossier (`6d99cab`), it is served over the API (`main.py:2620 poc_bundle_export`) and it is
embedded by `report.py:2195`. So **the same finding now says "NOT ESTABLISHED" in the report and "an
inert control does NOT reproduce the differential" in its own dossier.** Check 7 (all surfaces
agree) FAILS. The same one-line fix applies: `report.control_ran(finding)` is importable and pure.

## FOUND: `control_ran` is weaker than "deliberately strict"

Any non-empty container or non-blank string passes, including artifacts that state the control did
NOT run:

```
empty string in a list        {'controls': ['']}                 -> True  -> "How this was confirmed"
dict that says it did NOT run {'controls': {'ran': False}}       -> True  -> "How this was confirmed"
the literal string 'none'     {'control': 'none'}                -> True  -> "How this was confirmed"
the literal string 'not run'  {'control': 'not run'}             -> True  -> "How this was confirmed"
a zero-count summary          {'negative_controls': {'count':0}} -> True  -> "How this was confirmed"
```

No shipping producer emits these today (checked all three `bie.py` sites), so this is latent, not
live. But `{'controls': ['']}` and `{'negative_controls': {'count': 0}}` are exactly what a future
producer writes when it wants to record "I ran none", and the guard would then be checking a
declaration instead of a fact — the failure mode this codebase already has a memory note about.

**VERDICT 837b1f0: PLAUSIBLE.** The claim ("stop claiming a negative control that never ran") is
true of the two renderers it changed and its six tests are real. It is not CONFIRMED because the
claim it removes from the report is still printed verbatim by the PoC bundle for the same finding,
so the fix is incomplete on its own terms and the surfaces now disagree. Owner (`poc_bundle.py`) to
gate `confirmation.negative_control` and `confirmation.evidence_requirements` on `control_ran`.

---

# TARGET 3c — `0233574` (the rewritten traversal oracle)

## The three negative controls hold AGAINST THE LIVE LAB, not just in unit tests

The retraction's real damage was cross-family: 22 clean `securecookie` cases carrying a CONFIRMED
`path_traversal`. `after_pt.jsonl` only re-ran the `pathtraver` category, so that half was
unmeasured. I re-ran **every** case in the before-run that carried a confirmed `path_traversal`,
live, through the real `_run_web_probes` path (`/tmp/brk_traversal_live.py`):

```
BEFORE: cases carrying a CONFIRMED path_traversal: {'pathtraver': 92, 'securecookie': 45}
cross-family (non-pathtraver) path_traversal claims: 45
  of those, on cases the key marks CLEAN: 22

cross-family path_traversal claims that SURVIVE today's oracle: 0 / 45
```

The finding is still produced but is now correctly demoted. Spot-checked with the confidence
printed explicitly:

```
BenchmarkTest00016.html  path_traversal  conf=lead  sev=info  oracle=reflection
BenchmarkTest02247.html  path_traversal  conf=lead  sev=info  oracle=reflection
```

`oracle=reflection` -> `confidence=lead`, `severity=info`. That is the fix doing exactly what it
claims. **All three named negative controls (`bbh-canary.txt` with no `../`,
`APOLAKI-NOT-A-FILE-9182`, pure echo) hold live.**

## The honest before/after score

Same run file, same 2132 cases, same key. `pathtraver` rows swapped for the post-fix re-run (same
case set — verified `sorted(tests)` equal); the 45 cross-family rows carry their MEASURED post-fix
confidence (`lead`), not an assumption:

| | official suite | product suite | cross-family FP | pathtraver |
|---|---:|---:|---:|---:|
| BEFORE `0233574` | 41.3% | 34.9% | 22 | 69.2% |
| AFTER `0233574` | **41.0%** | **41.0%** | **0** | **65.4%** |

- Official score costs **0.3 pp** (41.3 -> 41.0). `pathtraver` alone drops 69.2 -> 65.4%: 5 of the
  92 pathtraver true positives were resting on reflection and are correctly gone. 87 survive on
  real evidence — so "the whole 69.2% rested on reflection" was too pessimistic; most of it was real.
- Product score **gains 6.1 pp** (34.9 -> 41.0) and `cross_family_fp` goes 22 -> **0**. The two
  numbers now coincide because there is no longer a cross-family false positive anywhere in the
  suite for the official convention to forgive.

**VERDICT 0233574: CONFIRMED.** Test-failed-before-fix is evidenced by the commit's own mutation
gate entries (three mutants, each bound to a named test); negative controls hold live on 45/45
cases; false positives went down, not up, on both scorers; replay is deterministic (`lead` on every
re-run); reproduced from the committed tree inside the baked image; all surfaces agree
(`family=path_traversal, confidence=lead, severity=info, oracle=reflection`); and it generalises to
a category it was not written against (`securecookie`, 45 unseen cases).

---
---

# SESSION 2

# MUTATION CHECK on `test_sqli_oracle_negative_controls.py` — the question session 1 died on

"Do my own tests actually kill the mutants?" Answer: **8 of 11 did; 2 of the 3 survivors were real
holes in my tests and are now closed; the third is a provably equivalent mutant.**

## Method (production code never touched)

Each mutant is a one-line weakening of an FP guard in `sqli_tool.py`, written to a scratch copy and
**mounted over** `/app/sqli_tool.py` — the repo working tree is never modified:

```
docker run --rm -v "<repo>/agent:/app" -v "<scratch>/m/<ID>.py:/app/sqli_tool.py:ro" -w /app \
  apolaki-agent:latest python -m pytest tests/test_sqli_oracle_negative_controls.py -q -rfX
```

Check 2 is graded strictly: only a FAILED/XPASS on the **named** test counts. A collection error,
import error or unrelated failure would not have been credited.

## Result matrix

| mutant | weakening | killed by | verdict |
|---|---|---|---|
| M1 `analyze_boolean` drop divergence leg (`return st >= thresh`) | TRUE/FALSE need not differ | `test_identical_responses_never_confirm_blind_sqli` + `test_a_parameter_that_merely_echoes...` | KILLED |
| M2 `analyze_boolean` drop baseline leg (`return stf < thresh`) | TRUE need not track baseline | **SURVIVED -> now killed by new `test_a_page_with_a_per_response_nonce_cannot_confirm_blind_sqli`** | HOLE, CLOSED |
| M3 threshold `0.95 -> 0.90` | | `test_an_unstable_page_must_not_confirm_blind_sqli` (strict xfail XPASSes) | KILLED |
| M3b threshold `0.95 -> 0.99` | looks like a tightening, is a weakening of leg 2 | **SURVIVED -> now killed by new `test_a_small_dynamic_block_is_not_a_diverged_page`** | HOLE, CLOSED |
| M4 `quote_break_recovers` `>=500 -> >=400` | a 4xx counts as a break | `test_a_404_or_a_400_is_not_a_break` | KILLED |
| M5 drop recovery leg | a bare 500 confirms | `test_a_page_that_errors_on_every_input...` + `test_error_recovery_needs_both_legs` | KILLED |
| M6 drop baseline leg | baseline may already be 5xx | `test_a_500_unrelated_to_the_payload...` | KILLED |
| M7 `analyze_time` drop the control differential | absolute latency confirms | `test_an_endpoint_that_is_slow_for_everything...` | KILLED |
| M8 `analyze_time` drop `sleep_elapsed >= need` | (none) | SURVIVED | **EQUIVALENT MUTANT — proven, see below** |
| M9 `error_signatures` drop baseline exclusion | pre-existing error text is evidence | `test_error_text_already_in_the_baseline_is_not_evidence` | KILLED |
| M10 `structural_confirmed` drop the ok-leg | no differential needed | `test_structural_oracle_needs_a_differential_not_just_an_error` | KILLED |

## The two holes that were real, and why they mattered

**M2 — the baseline leg was untested.** Every existing negative control used a page where TRUE and
FALSE were *too similar* to diverge, so leg 2 alone repelled all of them and leg 1 was never
load-bearing in any test. `return stf < thresh` therefore passed the whole file. That mutant is an
oracle that confirms whenever two responses merely differ from each other — on any page carrying a
per-request nonce, request-id or timestamp, that is **every** request. The new test uses exactly that
shape (MEASURED `st=0.7484`, `stf=0.8571`; both legs below threshold, so only leg 1 rejects it).

**M3b — raising 0.95 to 0.99 is a weakening, not a tightening.** `analyze_boolean` uses the same
constant for both legs in opposite directions: `st >= thresh and stf < thresh`. Raising it makes the
divergence leg *easier*, so a rotating ad slot, a "generated in 0.04s" footer or any ~2% dynamic
block starts counting as "FALSE returned a different page". MEASURED on a 2099-byte page with a
50-byte rotating block: `st=0.9969`, `stf=0.9851` — 0.95 rejects, 0.99 confirms. No existing test
pinned the constant from the false-positive side; one does now.

## M8 is equivalent, not a hole — proof

`sleep - control >= need` implies `sleep >= need` whenever `control >= 0`, and `control` is a
measured elapsed time. Brute-forced rather than argued (`/w/equiv.py` in the agent image):

```
non-negative elapsed: 804005 input triples (control 0..40s x sleep 0..40s x seconds in {1,3,5,10,30})
   disagreements between analyze_time and the mutant: 0
NEGATIVE control_elapsed (physically impossible):     disagreements: 3150
```

The only inputs that separate them cannot occur. No test is owed for it.

## Post-change state of the file

```
docker run --rm -v <repo>/agent:/app -w /app apolaki-agent:latest \
  python -m pytest tests/test_sqli_oracle_negative_controls.py -q
.x...........                                           [100%]   12 passed, 1 xfailed
```

Full suite, `--ignore=tests/test_dom_audit_concurrency.py` (uncommitted, known-broken, not mine):

```
1904 passed, 9 skipped, 1 xfailed, 9 warnings in 244.32s     EXIT=0
```

**VERDICT on `test_sqli_oracle_negative_controls.py`: CONFIRMED as a real safety net after the two
additions.** Before them it had a hole precisely where the live defect lives — the baseline leg of
`analyze_boolean`, the same leg whose *stability* is the 00494 false positive.

## GAP FOR THE OWNER — `sqli_tool.py` has ZERO entries in `agent/mutation_gate.py`

`mutation_gate.py` carries 18 mutants: 6 `bie.py`, 3 `transport_posture.py`, 3 `web_security.py`,
2 `prng_disclosure.py`, 1 each `ics_dnp3_s7`/`blind_benchmark`/`proof_schema`/`cookie_flags`.
**None for `sqli_tool.py`** — the module behind 21 of the product's 22 true positives. Its own
docstring says "Adding an oracle means adding its mutant." I did not edit the gate (not my lane),
but M1, M2, M4, M5, M6, M7, M9, M10 above are all verified-killing pairs and can be pasted in as-is,
each with the exact node id recorded in the matrix.
