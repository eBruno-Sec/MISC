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

---
---

# SESSION 3 (2026-08-11, later)

Targets: (1) the code-assisted lane `3a62c04` / `3b2e409` / `411d5d1` / `ad821d4`; (2) the Java
hybrid 61.1%; (3) anti-idle sweep of RESOLVED entries in `docs/CODEBASE_REVIEW.md`.

## LEAD FINDING FOR THE COORDINATOR: one measure-lane claim is FALSE

**REJECTED: `docs/handoff/measure.md` line 364, asserted by commit `75168e5`** ("both suites scored
end to end, DAST and hybrid, sealed"):

> securecookie | 61.1% | 14 FN, of which **8 are wrong-family**: the tool reported something else on
> a vulnerable securecookie case. Those 8 are worth reading individually - they are also the source
> of the 8 remaining cross-family FPs.

MEASURED from the raw artifact `docs/benchmarks/owaspbench_java_v12_DAST_FULL_20260811.jsonl` plus
the raw key, with my own tally that does not import `owasp_bench`:

```
securecookie vulnerable FNs total: 14
  wrong-family (tool confirmed SOMETHING ELSE): 0
  silent (tool confirmed nothing):             14
```

**Zero of the 14 are wrong-family. All 14 are silent.** And the 8 cross-family false positives are
not securecookie's at all - every one of them is a CLEAN `weakrand` case carrying a confirmed
`path_traversal`:

```
cross-family FPs (clean case, confirmed finding of ANOTHER family): 8
    BenchmarkTest00319  weakrand  ['path_traversal']
    BenchmarkTest00504  weakrand  ['path_traversal']
    BenchmarkTest01074  weakrand  ['path_traversal']
    BenchmarkTest01294  weakrand  ['path_traversal']
    BenchmarkTest01799  weakrand  ['path_traversal']
    BenchmarkTest01950  weakrand  ['path_traversal']
    BenchmarkTest02616  weakrand  ['path_traversal']
    BenchmarkTest02716  weakrand  ['path_traversal']
```

Two independent statements in that one table row are wrong: the count of wrong-family FNs (8 vs a
measured 0) and the attribution of the 8 cross-family FPs (securecookie vs a measured weakrand).
The number 8 is real; it was attached to the wrong category and then a causal link was invented
between the two.

**Does it change a published number? NO.** This is a DIAGNOSTIC statement inside the per-category
shortfall table, not a figure. Checked explicitly:

- `docs/LEDGERS.md` - the string does not appear; no ledgered figure depends on it.
- `docs/STATUS.md` - the string does not appear.
- `docs/BENCHMARK_MATRIX.md:94` carries `DAST 41.7% official / hybrid 61.1%`, both of which I
  independently recomputed and both of which are CORRECT (below).
- `cross_family_fp = 8` as a *count* is correct and reproduces. Only its attribution is wrong.

So: nothing to retract from the scoreboard. What needs correcting is one row of prose in
`docs/handoff/measure.md`, owned by the measurement lane. The reason it matters anyway is that this
row was the stated reason to go read 8 specific securecookie cases - a remediation lead pointing at
the wrong 8 cases in the wrong category. Anyone who followed it would have found nothing and had no
way to tell whether the tool or the note was wrong.

This is the failure shape the brief warned about: a summary that invents a relationship the raw
artifact does not contain. It took an end-to-end recount to see it.

## THE HEADLINE NUMBERS DO REPRODUCE - stated with the same specificity

Everything below was recomputed by me, inside `--network none` containers, from the committed raw
artifacts and the raw answer keys copied out of the lab containers. No summary was trusted.

**Seals: all five committed artifacts hash to exactly the values their documents claim.**

```
95765ac789ea20cef27c4086993f79eec4c3947da6cf161fd5db3c3c319a58fb  benchmarkpython_v01_CODEASSISTED_20260811.json
634e8270f0c80d7528dc29af44730da355dd320c46908100311911b8342c101b  benchmarkpython_v01_CODEASSISTED_MATCHED_20260811.json
23dd777bf809616e1e8a53d8e565a7592895981b1e1407ac98b36e941953c03f  benchmarkpython_v01_DAST_20260811.jsonl
0dd31d5a68e0a234756006b21eeec1e2c1d593ac9ba9667ba927e5b08c2e4d12  owaspbench_java_v12_CODEASSISTED_20260811.json
0496a8cc9593672e8362fa824e8cfe94f67804900a79df40806b367fa9259099  owaspbench_java_v12_DAST_FULL_20260811.jsonl
```

The first three match `docs/handoff/code_assisted.md`; the last three match
`docs/handoff/measure.md`. Row counts also match: 1230 / 594 / 406 / 975 / 2132.

**Java, through the project's own scorer on the committed artifacts + the key from
`apolaki-owaspbench-1:/owasp/BenchmarkJava/expectedresults-1.2.csv` (2740 rows):**

```
DAST only : OFFICIAL 41.7%   PRODUCT 41.5%   cross_family_fp 8   (0 as: crypto, hash, trustbound)
HYBRID    : OFFICIAL 61.1%   PRODUCT 60.9%   cross_family_fp 8   (0 as: trustbound)
```

All four figures reproduce exactly.

**Java, recomputed a SECOND time with my own scorer** (reads the jsonl/json rows and the CSV
directly, never imports `owasp_bench`), which is the end-to-end recount the brief asked for:

```
cmdi          TP=36   FN=90   FP=0   TN=125   score= 28.6%
crypto        TP=130  FN=0    FP=0   TN=116   score=100.0%
hash          TP=129  FN=0    FP=0   TN=107   score=100.0%
ldapi         TP=15   FN=12   FP=0   TN=32    score= 55.6%
pathtraver    TP=87   FN=46   FP=0   TN=135   score= 65.4%
securecookie  TP=22   FN=14   FP=0   TN=31    score= 61.1%
sqli          TP=180  FN=92   FP=0   TN=232   score= 66.2%
trustbound    TP=0    FN=83   FP=0   TN=43    score=  0.0%
weakrand      TP=218  FN=0    FP=0   TN=275   score=100.0%
xpathi        TP=6    FN=9    FP=0   TN=20    score= 40.0%
xss           TP=137  FN=109  FP=0   TN=209   score= 55.7%

hybrid contingency (10 measured cats): TP 960, FN 372, FP 0, TN 1282, total 2614
official macro over ALL 11 (trustbound=0): 61.1%
cross-family FPs: 8
```

Every cell matches `measure.md`'s JOB 1 table, including the contingency total 2614 and the 126
trustbound cases held in the denominator rather than dropped. **61.1% is real.**

**Python, recomputed from RAW SOURCE rather than from any artifact** - `/opt/bpy` copied out of
`apolaki-benchmarkpython-1`, 1236 `.py` files, scanned with `codeintel.review_source_tree`, scored
by my own scorer against `expectedresults-0.1.csv` (1230 rows), `--network none`:

```
files_scanned: 1236   findings: 170
findings on a BenchmarkTest case: 170 over 170 distinct cases
findings NOT on a benchmark case: 0
cross-family fires (rule category != case category): 0

category             n    TP    FN    FP    TN        TPR      FPR    score
hash               151    71     0     0    80     100.0%     0.0%   100.0%
weakrand           326    99     0     0   227     100.0%     0.0%   100.0%
trustbound          37     0    18     0    19       0.0%     0.0%     0.0%
(the other 11 categories: 0 TP, 0 FP, exactly as documented)
code-assisted-ALONE official macro (14 cats): 14.3%
```

Row for row identical to the committed table, every cell, derived without reading the lane's own
artifact or its summary. And through the project's scorer on the committed artifacts:

```
DAST only : OFFICIAL 24.5%   PRODUCT 24.5%
HYBRID    : OFFICIAL 38.8%   PRODUCT 38.8%
```

`24.5 + 100/14 + 100/14 = 38.79`. Additive as claimed. **The 0.0% -> 100.0% on both hash (151
cases) and weakrand (326 cases) at 0.0% FPR is real.**

## Environment used by every measurement above

No image was rebuilt. The committed working tree is mounted READ-ONLY over `/app`; mutants are
mounted over `/app/codereview.py` for the life of one container only:

```
MSYS_NO_PATHCONV=1 docker run --rm --network none \
  -v "<repo>/agent:/app:ro" [-v "<scratch>/m/<ID>.py:/app/codereview.py:ro"] \
  -v "<scratch>:/w" -w /app apolaki-agent:latest python -m pytest tests/test_source_lane.py -q -rf
```

Mount sanity against the empty-volume trap: `/app` = 183 entries and `import codereview` exposes
`scan_python_hash`; the benchmark tree mounts as 1236 `.py` and the scanner reports
`files_scanned: 1236`. No exit code was trusted without a file count.

---

# TARGET 1 - the code-assisted lane. VERDICT: CONFIRMED, with three named defects that cost the
# benchmark nothing, and one report-surface REJECT in a file this lane does not own.

## 1a. The mutation matrix, re-derived from scratch (NOT taken from the doc)

I wrote my own seven mutants as one-line weakenings of `codereview.py`, each anchored on a string
that occurs exactly once in the file. The harness refuses to emit a mutant whose anchor is not
unique, which caught my first M4 anchor matching `mask_source` as well as `mask_python_source`.

Baseline first: `tests/test_source_lane.py` = **69 passed, 0 failed** on the unmutated tree.

| mutant | the one-line weakening | killed by (NAMED test) | verdict |
|---|---|---|---|
| M1 | `if c == "#":` -> `if c == "#" or src.startswith("//", i):` | `test_python_mask_does_not_treat_floor_division_as_a_comment` | KILLED |
| M2 | `_PY_RANDOM_CALL` receiver dropped: `random\s*\.\s*(M)` -> `\.\s*(M)` | `test_python_system_random_is_a_csprng_not_a_weak_generator` (+3) | KILLED |
| M3 | `_PY_USEDFORSEC` -> a regex that cannot match | `test_python_usedforsecurity_false_is_not_flagged` (+2) | KILLED |
| M4 | `mask_python_source` returns `(text, {})`, so rules see raw text | `test_python_md5_named_only_in_a_comment_or_string_is_not_flagged` (+7) | KILLED |
| M5 | `_py_binds_module` -> `return True` | `test_python_a_foreign_random_module_is_not_the_stdlib_one` | KILLED |
| M6 | `_py_shadowed` -> `return False` | `test_python_a_user_defined_md5_is_not_the_stdlib_call` | KILLED |
| M7 | `_PY_HASHLIB_CALL` greps the callee name, `hashlib.` optional | `test_python_a_user_defined_md5_is_not_the_stdlib_call` | KILLED |

**7 mutants, 7 killed - count independently confirmed.** Graded strictly: in every case the failing
assertion is the one the test exists for, printed in the pytest output (M1 fails on
`assert 'n // 2' in "half = n     ..."`). No collection error, import error, fixture failure or
generic nonzero exit was credited.

M2's headline number reproduces exactly. Scoring every mutant against the real 1236-file suite:

```
BASE / M1 / M3 / M5 / M6 / M7 :  170 findings   hash 100.0%  weakrand 100.0%  macro 14.3%
M2 (receiver ignored)         :  283 findings   hash 100.0%  weakrand  50.2%  macro 10.7%
                                 weakrand FP 113, FPR 49.8%
```

**283 vs 170, +113 false positives, weakrand 100.0 -> 50.2%.** Exactly the claim, and note what the
table shows that the doc did not: M2 does not lose a single true positive. weakrand TPR stays
100.0% and only FPR moves. The receiver rule is worth nothing on the TPR side and everything on the
FPR side, which is precisely why only a negative control can catch it and why a suite-score-only
gate would have passed the mutant.

Five of the seven mutants leave the suite at exactly 170 findings and die ONLY on unit tests. That
is a stronger argument for benchmark-invisible negative controls than the doc made for itself - it
credited only M6 and M7 with that property.

## 1b. The receiver claim, attacked with shapes the implementation has never seen

This is the load-bearing decision (113 of 326 weakrand cases), so it got 45 hand-built cases with
declared ground truth. **Every CSPRNG shape I could construct stays clean.** The claim survives its
hardest form:

```
ok  B1  random.SystemRandom().getrandbits(32)                          clean
ok  B2  module-level  _RNG = random.SystemRandom()  reused in a fn     clean
ok  B3  class attribute  rng = random.SystemRandom()                   clean
ok  B4  function returning random.SystemRandom()                       clean
ok  B5  from random import SystemRandom                                clean
ok  B6  import random as r ; r.SystemRandom()                          clean
ok  B9  from random import SystemRandom as Random  (aliased to the WEAK name)   clean
ok  B10 from numpy import random                                       clean
ok  B11 import numpy.random as random                                  clean
ok  B12 self.random.getrandbits(32)   (attribute receiver)             clean
ok  B13 "random"/"md5" only in a comment, a string, a docstring        clean
ok  B14 a local `def random()`                                         clean
```

and the weak twin of each shape is still caught:

```
ok  A3  _RNG = random.Random() reused          -> random.Random()@L3
ok  A4  class attr rng = random.Random()       -> random.Random()@L4
ok  A5  function returning random.Random()     -> random.Random()@L4
ok  A6  from random import getrandbits, bare   -> random.getrandbits()@L4
ok  A7  from random import Random              -> random.Random()@L4
ok  A9  from random import getrandbits as grb  -> random.getrandbits()@L4
```

B9 is the one I most expected to break it - `from random import SystemRandom as Random`, a CSPRNG
bound to the name of the weak class - and it stays clean, because the rule reads the ORIGINAL
symbol, not the local name. The inverse (`from random import Random as SystemRandom`) is correctly
flagged. The receiver claim is real.

`usedforsecurity=False` is honoured in all four spellings tested, including on `hashlib.new`, split
across lines, and NOT leaking to a second `md5()` call on the same line (H16 still fires).
Floor division does not blank the rest of the line (H17). All 17 hash cases behave.

### DEFECT 1 (FALSE NEGATIVE) - an aliased module import is silently invisible

```
import random as r    ; r.getrandbits(32)   -> NOT FLAGGED   (should be CWE-330)
import random as rnd  ; rnd.choice(xs)      -> NOT FLAGGED
import hashlib as hl  ; hl.md5(d)           -> NOT FLAGGED   (should be CWE-328)
```

Root cause, and it is the ugly kind: `_py_imports()` **computes the binding and throws it away**.
`import random as r` correctly produces `modules["r"] = "random"`, but `scan_python_random` only
consults `modules` through `_py_binds_module`, which is a SUPPRESSION test - it can decide that the
name `random` is not the stdlib, and it can never decide that the name `r` IS. The detection
regexes hard-code the literal receiver:

```python
_PY_RANDOM_CALL  = re.compile(r"(?<![\w.])random\s*\.\s*(%s)\s*\(" % _PY_RANDOM_METHODS)
_PY_HASHLIB_CALL = re.compile(r"(?<![\w.])hashlib\s*\.\s*([A-Za-z0-9_]+)\s*\(")
```

The `from X import Y as Z` half is handled properly (A9 passes). Only the `import X as Y` half is
missing. It is the same shape as the defect this lane was created to fix - a capability thrown away
by a name check - one level down.

**Measured cost to the claimed numbers: ZERO.**
`grep -rlE "^[ \t]*import[ \t]+(random|hashlib)[ \t]+as" <suite>` returns **0 files**. The
100.0%/100.0% stands. This is a generality defect, not a wrong number, and the benchmark cannot see
it by construction.

### DEFECT 2 (FALSE POSITIVE) - `_PY_CLOCK_TOKEN` flags timestamps, not tokens

```python
_PY_CLOCK_TOKEN = re.compile(
    r"(?<![\w.])(\w*(?:token|session|nonce|otp|secret|salt|apikey|password|guid|uuid)\w*)"
    r"\s*=[^\n]{0,90}?" + _PY_CLOCK, re.I)
```

Any identifier merely CONTAINING one of those words, followed within 90 characters by a clock read,
is reported as CWE-337 "a security value derived from the clock":

```
session_start = time.time()          -> FLAGGED  "clock -> session_start"    FALSE POSITIVE
token_expiry  = time.time() + 3600   -> FLAGGED  "clock -> token_expiry"     FALSE POSITIVE
```

Neither is a security value derived from the clock. Both are a clock reading stored under a name
that mentions one. Recording when a session began is not weak randomness.

Confirmed in the wild, not only in my fixtures. Scanning the container's own
`/usr/local/lib/python3.12` (5139 files) produced exactly one CWE-337, and it is this bug:

```
site-packages/anthropic/lib/credentials/_workload.py:346
  return AccessToken(token=_unwrap_secret(token), expires_at=int(time.time()) + expires_in)
```

The regex matched the keyword argument `token=`, then found `time.time()` 60 characters later on
the same line. It is not even an assignment statement. `expires_at` comes from the clock; the token
does not.

**Measured cost to the claimed numbers: ZERO.** The `<securityword> = <clock>` shape appears in 0
of the suite's testcode files. Invisible to the benchmark, same as Defect 1.

### DEFECT 3 (minor, under-reporting only) - `.seed(` is effectively dead in `_PY_CLOCK_SEED`

`(?<![\w.])(?:random\s*\.\s*seed|\.\s*seed|Random)\s*\(\s*<clock>` applies the lookbehind to the
whole alternation, so the `\.\s*seed` branch can only match when the character before the dot is
NOT a word character. `rng.seed(time.time())` therefore does not match it, and neither does
`random.Random(time.time())` (the `Random` branch is blocked by the preceding dot). The stronger
CWE-337 is silently downgraded to a plain CWE-330 for the qualified-constructor spelling. No false
positive; a missed severity.

## 1c. Generality - reproduced, and extended to a third codebase

Apolaki's own tree, from the committed working tree:

```
files_scanned: 174   findings: 4
  guidance.py:401           CWE-328  SHA1             hashlib.sha1("|".join(parts).encode())   REAL
  juiceshop_solvers.py:771  CWE-330  random.choice()  random.choice("bcdfghjklmnpqrstvwxz")    REAL
  owasp_bench.py:140        CWE-330  random.Random()  rng = random.Random(seed)                REAL
  sarif_io.py:71            CWE-328  SHA1             hashlib.sha1("|".join(...).encode())     REAL
```

All four verified by reading the source at those exact lines. 4/4 true call sites, 0 misidentified.
The claim reproduces.

**Third codebase, neither the benchmark nor Apolaki**: `/usr/local/lib/python3.12` - CPython's
stdlib plus site-packages, **5139 files**, a corpus with no relationship to either.

```
findings: 100     CWE-330: 66    CWE-328: 33    CWE-337: 1
```

Spot-checked against the real source: `uuid.py:620` (`random.getrandbits(48)`), `tempfile.py:146`
(`self._rng = _Random()` via `from random import Random as _Random` - the aliased SYMBOL import the
detector does handle), `cryptography/.../rsa.py:275` (`a = random.randint(2, n - 1)`),
`httpx/_auth.py:309` (`hashlib.sha1(s)`), `smb/ntlm.py` MD4/MD5, `ldap3/.../digestMd5.py` MD5. All
real call sites.

**99 of 100 are true call sites; the single false positive is Defect 2.** One borderline worth
naming: `starlette/_compat.py:19` is `hashlib.md5(data, usedforsecurity=usedforsecurity)` - the
kwarg is a VARIABLE, so the literal-`False` guard cannot fire and the call is flagged. Conservative
rather than wrong, but a reader should know the guard is literal-only.

**Conclusion: it is a detector, not a signature.** It transfers to a 5139-file corpus it was never
written against at roughly a 1% false-positive rate, and that 1% has a named regex behind it.

## 1d. What `411d5d1` was honest about, settled

The lane recorded that its seven negative controls all fail pre-fix with `AttributeError`, which
proves the tests are NEW and not that their assertions discriminate, and offered the mutation run
as the real evidence. **That is the correct reading, and the mutation run does carry the weight.**
I re-derived it independently: 7/7, named assertion each time. Check 1 is satisfied only in its
weak form; check 2 is satisfied in its strong form, which is the one that matters. The lane graded
its own evidence correctly, which is rare enough to record.

## TARGET 1 VERDICT: CONFIRMED

| check | result |
|---|---|
| 1. failed before the fix | PASS, weak form (AttributeError). The lane said so itself and did not overclaim. |
| 2. exact assertion kills the mutant | PASS, strong. 7/7 re-derived from scratch, named test each time, nothing generic credited. |
| 3. negative controls stay clean | PASS. 20 CSPRNG/clean shapes including 12 unseen receivers, all clean. |
| 4. false positives anywhere | PASS on both suites (0 FP in 1230 Python cases, 0 cross-family; 0 FP in the Java run). Two FP shapes exist (Defects 1-2) but measure 0 on both suites and 1 in 5139 files on a third codebase. |
| 5. deterministic replay | PASS. 170 findings on every re-run; pure text analysis, no network, no clock, no ordering input. |
| 6. clean environment | PASS. Read-only mount of the committed tree, `--network none`, nothing copied in, no rebuild. |
| 7. all surfaces agree | PASS for this lane's files - every finding carries `lane: code-assisted` and `provenance: source-derived`, and the scorer prints both banners. See the Target 2 REJECT for `owasp_bench.report`, which is not this lane's file. |
| 8. generalises | PASS. 5139-file third corpus at 99/100 true call sites; 4/4 on Apolaki; 12 unseen receiver shapes correct. Three named defects filed. |

**The 100.0% / 100.0% at 0.0% FPR is real, and I could not make it wrong.** Two full categories at
100.0% is exactly the number that has been wrong here before; this one is not.

**For the owner of `agent/codereview.py`** (I do not edit production code):
- Defect 1: consult the `modules` map `_py_imports` already builds, so `import random as r` and
  `import hashlib as hl` resolve. The binding is computed today and discarded.
- Defect 2: `_PY_CLOCK_TOKEN` must require the clock value to BE the security value, not merely
  share a line with it. As written it reports an audit timestamp as CWE-337.
- Defect 3: hoist the lookbehind into each alternative of `_PY_CLOCK_SEED`.

---

# TARGET 2 - the Java hybrid 61.1%. VERDICT: the FIGURES are CONFIRMED; the REPORT SURFACE is
# REJECTED, and one prose claim in `measure.md` is REJECTED (see the lead finding at the top).

The four figures and all five seals reproduce - recorded in full at the top of this session. What
follows is the part Target 2 actually asked about: can a reader conflate them, and is the
code-assisted contribution labelled SAST everywhere it appears.

## 2a. REJECTED - the scorer's own output contradicts itself on a hybrid run

`agent/owasp_bench.py`, `report()` lines 532-540, prints these annotations UNCONDITIONALLY whenever
`suite_macro is not None`, with no reference to the lane. On the HYBRID Java run the operator sees,
in one uninterrupted block:

```
!! MIXED LANES IN ONE RUN (HYBRID RESULT): code-assisted, dast
   ...
   printed next to the DAST-only figure. It may NEVER be compared against a published
   DAST score (ZAP 17.99%, best-published 26%) -- those tools were never given source.

CODE-ASSISTED (SAST) LANE - findings are SOURCE-DERIVED from operator-supplied code.
   This is not a DAST result. Do NOT fold it into a DAST figure and do NOT compare it
   against a published DAST score ...

   [ the table ]

OFFICIAL SUITE SCORE (macro over ALL 11 suite categories, unmeasured = 0):  61.1%
   ^ comparable to a PUBLISHED tool score (official CWE-matching convention: ...)

PRODUCT SUITE SCORE (same TPR; every confirmed finding on a clean case is an FP):  60.9%
   ^ THIS is the number to quote when the question is 'how good is Apolaki'
```

**"It may NEVER be compared against a published DAST score" and "^ comparable to a PUBLISHED tool
score" are eleven lines apart, about the same number.** The second annotation is also the one that
sits directly under the figure, which is the line that survives a copy/paste - the exact failure
mode `_lane_banner`'s own docstring says it exists to prevent ("A percentage travels; the sentence
explaining what produced it does not").

`PRODUCT SUITE SCORE ... ^ THIS is the number to quote when the question is 'how good is Apolaki'`
has the same problem: on a hybrid run it tells the reader to quote 60.9% as the product number with
no lane qualifier attached to that sentence.

The banner is a real improvement and it is doing most of the work. But a banner that is contradicted
by the caption under the number is check 7 (all surfaces agree) failing inside a single command's
output. **REJECTED.** `agent/owasp_bench.py` is not my file; the fix is to make lines 535-536 and
540 lane-aware - on a run whose `lanes` is anything but `["dast"]`, the "comparable to a PUBLISHED
tool score" claim is false and must not print.

## 2b. Is the code-assisted contribution labelled SAST everywhere it appears? Mostly YES

MEASURED sweep of every occurrence of 61.1 / 60.9 / 38.8 in `docs/`:

| surface | labelled? |
|---|---|
| `docs/handoff/measure.md:22-23` | YES - "HYBRID (DAST + code-assisted)" in the row |
| `docs/handoff/code_assisted.md:24-25,329` | YES - "HYBRID (DAST + code-assisted)" |
| `docs/LEDGERS.md:89-92` | YES - and carries the never-compare sentence |
| `docs/STATUS.md:14` | YES - "hybrid (DAST + code-assisted SAST)" |
| `docs/BENCHMARK_MATRIX.md:94-95` | WEAK - "DAST 41.7% official / hybrid 61.1%". The word "hybrid" is present; "SAST"/"code-assisted" is only in the neighbouring clause ("2132 DAST + 975 code-assisted") |
| every finding object | YES - `lane: code-assisted`, `provenance: source-derived`, `analysis: static-call-site`, `tags: ["sast","code-assisted"]` (verified by constructing one) |
| the scorer's stdout | banner YES, caption under the number NO - see 2a |

## 2c. FOUND - `docs/STATUS.md` still shows the RETRACTED Java numbers

The Java hybrid does not appear on the scoreboard at all, and the DAST row is stale:

```
docs/STATUS.md:12  OWASP Benchmark Java v1.2 - product claim   34.9%  ...  FPR 2.1%
docs/STATUS.md:13  OWASP Benchmark Java v1.2 - harness, official conventio 41.3%  FPR 0.0%
```

34.9% / 2.1% is the figure the pathtraver retraction produced, superseded by `75168e5`. The measured
and now independently verified values are **41.7% official / 41.5% product DAST-only** and
**61.1% / 60.9% hybrid, FPR 0.0%**. Neither appears in `STATUS.md`, and `grep` finds no 41.7 / 61.1
in `LEDGERS.md` either - so the file's own tie-break rule ("if they disagree, the ledger wins") does
not help, because the ledger has not been updated for Java at all. The Python rows ARE current.

Coordinator: both files are yours. This is understated, not overstated - the board shows Java worse
and dirtier than the sealed measurement says it is.

---

# TARGET 3 - anti-idle. Two results: one earlier REJECT re-confirmed and made worse, one
# RESOLVED entry I attacked and could NOT break.

## 3a. Session 2's `poc_bundle` REJECT is STILL LIVE, and the code-assisted lane makes it worse

Session 2 found that `837b1f0` gated `report.proof_and_retest` but not `poc_bundle.build()`. Still
true, and the code-assisted lane supplies a harder instance of it. MEASURED on a real finding built
by `codereview.review_python`:

```
finding: weak_hash / CWE-328 / confidence=confirmed / lane=code-assisted
         no 'request' key, no 'response' key

report.control_ran(f)                    -> False
report.proof_and_retest(f)['negative_control']
   -> "NO NEGATIVE CONTROL WAS RECORDED for this finding. ..."          HONEST

poc_bundle.build(f)['confirmation']['negative_control']
   -> "A negative-control request WITHOUT the trigger does NOT reproduce the confirming
       signal (differential measured over a stable baseline)."          NOT GATED
poc_bundle.build(f)['confirmation']['evidence_requirements']
   -> ["...", "Negative control captured showing the confirming signal is ABSENT without
       the trigger.", "Baseline + mutation request/response retained for deterministic replay."]
```

This is worse than the SQLi instance session 2 recorded. There, the claim was merely unproven. Here
it is **categorically inapplicable**: a static call-site analysis has no request, no mutation, no
baseline and no differential, so "a negative-control request ... differential measured over a stable
baseline" and "baseline + mutation request/response retained for deterministic replay" describe an
experiment that could not exist for this finding class. The dossier is the visible moat (`6d99cab`),
it is served over the API (`main.py` `poc_bundle_export`) and embedded by `report.py`.

Same one-line fix session 2 named: `report.control_ran` is importable and pure. **REJECTED, second
time, owner of `agent/poc_bundle.py`.**

Note the honest half: the report gate itself DOES hold for this finding shape, which is a real
result for `837b1f0` - a finding class it was never tested against still gates correctly.

## 3b. S11c / S11d attacked on an angle V4 did not cover - COULD NOT BREAK

V4 already recorded the hostless-URL hole in these two, so I attacked the other side: **scope
escape**. Removing S11c's `startswith("http") or startswith("/")` guard means `urljoin` now resolves
protocol-relative links, and S11d's parsers resolve attacker-controlled robots.txt/sitemap content
against a caller-supplied base. Both should be able to walk off-origin.

The parsers do emit off-origin URLs. MEASURED, base `https://target.example:8443/app/`:

```
parse_robots("Disallow: https://evil.example/admin\nDisallow: //evil.example/x\nDisallow: /real/\n
              Sitemap: https://evil.example/sitemap.xml")
  urls     -> ['https://evil.example/admin', 'https://evil.example/x',
               'https://target.example:8443/real/']       same_origin: [False, False, True]
  sitemaps -> ['https://evil.example/sitemap.xml']

parse_sitemap("<loc>https://evil.example/p</loc><loc>/ok/p</loc>")
  urls -> ['https://evil.example/p', 'https://target.example:8443/ok/p']

urljoin(base, '//evil.example/x') -> 'https://evil.example/x'
   startswith("http") = True   <- passes the S11c replacement guard
   same_origin        = False
```

**But it never reaches the network.** Two independent downstream guards catch every one:

```
agent.py:1661   _new = [u for u in _got.get("urls", []) if self.scope.validate(u)[0]]
crawl.bfs_frontier(['https://evil.example/x', 'https://target.example:8443/app/ok'], base, set())
   -> ['https://target.example:8443/app/ok']        the off-origin candidate is dropped
```

And a robots.txt that is really an HTML error page - the common 200-with-HTML case - yields **0**
URLs, so the parser does not invent a surface either.

**Verdict: S11c and S11d hold. I tried to break them and could not.** Recorded because a negative
control that was never written is not the same as a fix that does not work, and this one works. The
residual is latent and identical in shape to V4's: neither parser asserts a host itself, so both are
one new caller away from being a live scope escape. The predicate V4 recommended
(`urlparse(u).netloc` non-empty) does NOT cover this case - `https://evil.example/x` has a netloc.
The parsers need `same_origin(u, base)`, not a netloc check.

One capability gap noticed in passing, MEASURED: `agent.py:1661` reads `_got["urls"]` and never
reads `_got["sitemaps"]`, so a `Sitemap:` directive in robots.txt is parsed and discarded. Only
`/sitemap.xml` at the root is ever fetched.

---

# WHAT I ADDED: `agent/tests/test_source_lane_breaker.py` (16 tests, the only file I wrote)

Prose in a hand-off document is not a regression guard. The three defects are now executable.

**4 strict xfails**, one per defect spelling. Strict means that when the owner fixes the rule the
test XPASSes, the suite goes red, and the marker has to be removed deliberately - the defect cannot
be quietly re-introduced later:

```
test_an_aliased_random_module_import_is_still_the_stdlib_generator   xfail  (Defect 1)
test_an_aliased_hashlib_import_is_still_the_stdlib_digest            xfail  (Defect 1, hash half)
test_a_timestamp_named_after_a_session_is_not_weak_randomness        xfail  (Defect 2)
test_a_token_expiry_timestamp_is_not_weak_randomness                 xfail  (Defect 2, expiry)
```

**12 passing tests**, and these are the ones that actually earn their place. The lane's own suite
proves the receiver claim for exactly ONE spelling, `random.SystemRandom().getrandbits(32)`. The
four INDIRECT spellings are untested and all four are one careless improvement away from breaking:

```
test_a_system_random_instance_bound_to_a_name_is_still_a_csprng
test_a_class_attribute_holding_a_system_random_is_still_a_csprng
test_a_factory_returning_a_system_random_is_still_a_csprng
test_system_random_reached_through_an_aliased_module_is_still_a_csprng
test_a_csprng_aliased_to_the_name_of_the_weak_class_is_not_flagged
test_an_attribute_named_random_is_not_the_random_module
```

**This is the guard rail for the fix to Defect 1.** The obvious way to resolve `import random as r`
is to treat any name bound to the `random` module as a receiver. Done without care, that fix starts
reporting `_RNG = random.SystemRandom()` call sites - which IS the M2 mutant, 113 false positives,
weakrand 100.0% -> 50.2%. Nothing in the existing suite would have caught it. Now something does.

Each of those is paired with its own mirror so the rule cannot be satisfied by going silent:

```
test_the_inverse_alias_is_still_caught                          from random import Random as SystemRandom -> flagged
test_indirect_weak_generators_are_still_reported_at_their_construction_site   the three shapes on random.Random()
test_a_bare_from_import_of_a_weak_method_is_reported
test_a_security_value_actually_derived_from_the_clock_is_still_reported       Defect 2 must be narrowed, not deleted
test_usedforsecurity_false_is_honoured_on_hashlib_new_and_across_lines
test_usedforsecurity_false_does_not_excuse_a_second_call_on_the_same_line
```

Measured: `tests/test_source_lane_breaker.py` = **12 passed, 4 xfailed, 0 failed**.

## Regression, and a correction to the stated baseline

Run on a writable COPY of the working tree (the repo itself was never written to). The
read-only-mount run reported three failures in `tests/test_mutation_gate.py`
(`test_the_gate_restores_every_file_it_touches` and two siblings) - that is my mount, not a
regression: the gate writes files to restore them and a `:ro` mount forbids it. On a writable copy
those three pass. **Recorded so nobody inherits a phantom failure from this session.**

```
full suite, writable copy, --network none, my file included:
  2000 passed, 9 skipped, 5 xfailed, 0 failed, 0 XPASSED
```

Counted from the progress characters because this tree's pytest configuration does not print a
summary count line - worth someone's attention on its own, since "0 failed" is currently something
you have to derive rather than read.

**Two corrections to the brief's stated baseline of 1993/9/1/0:**

1. `agent/tests/test_dom_audit_concurrency.py` is described as "uncommitted and known-broken by its
   own author". Both halves are stale. It IS committed (`128c8cd`), and MEASURED today it is
   **18 passed, 0 failed**. Excluding it from the baseline is no longer justified, and doing so
   understates the suite by 18 tests.
2. The working tree carries two other lanes' in-flight test files that any full-suite run picks up:
   `test_cmdi_shapes.py` (modified, probe lane) and `test_service_discovery_graph.py` (untracked).
   Any absolute total quoted from this tree includes them.

My own delta is the only thing I can be accountable for and it is exact: **+16 tests, +0 failures,
+0 xpasses.**

## PROCESS INCIDENT for the Coordinator - another lane committed my staged files

While this section was being staged, `6c9582f` ("Apolaki probe lane slice 4: the request-header
carrier for XSS") landed and swept up BOTH of my files:

```
6c9582f  apolaki/agent/tests/test_cmdi_shapes.py           <- probe lane's own
         apolaki/agent/tests/test_source_lane_breaker.py   <- MINE
         apolaki/agent/tools.py                            <- probe lane's own
         apolaki/docs/handoff/breaker.md                   <- MINE
         apolaki/docs/handoff/probes.md                    <- probe lane's own
```

**No content was lost** - `git diff HEAD` for both files is empty, so what is committed is exactly
what I wrote. What was lost is the commit message, which carried the reasoning for the four strict
xfails and the M2 blast-radius argument for the twelve passing tests. It is reproduced in this
section instead, which is why this file is the durable record and the commit log is not.

The real issue is not my message. That lane staged files it does not own, which means it is running
`git add -A` or `git commit -a` - the one git rule this project has written down. The next time it
fires it will commit another lane's half-finished working tree under a message that does not
describe it, and a bisect across that commit will be meaningless. Worth a word to that lane.

---

# OPEN ITEMS CARRIED FORWARD - re-checked today, still unfixed

Everything this lane has rejected across three sessions, with today's status. Nothing here is
new; the point is that none of it has been closed, and each was re-measured rather than assumed.

| # | item | owner file | re-checked today |
|---|---|---|---|
| 1 | `poc_bundle.build()` claims a negative control that never ran | `agent/poc_bundle.py` | STILL LIVE, and now worse - see 3a. The claim is categorically inapplicable to a source-derived finding, not merely unproven. |
| 2 | `owasp_bench.report()` prints "comparable to a PUBLISHED tool score" under a hybrid banner that says never compare | `agent/owasp_bench.py` | STILL LIVE, reproduced on both the Java and Python hybrid runs today. |
| 3 | `_any_confirmed` falsy default (`confs[:len(fams)] or confs`) | `agent/owasp_bench.py:391` | STILL LIVE. MEASURED today: `_any_confirmed({'families': [], 'conf': ['confirmed']})` returns **True** - a row with no finding behind it books a product false positive. Latent only (both lists are built together in `scan()`), but this is the `x or DEFAULT` shape that has bitten this project twice. |
| 4 | `owasp_bench.py` D1/D2 - a run file with no `target` prints NEITHER suite score; `--base` silently ignored on the JSON path | `agent/owasp_bench.py` | Not re-run today (session 2 measured both). |
| 5 | `control_ran` accepts artifacts that state the control did NOT run (`{'controls': ['']}`, `{'negative_controls': {'count': 0}}`) | `agent/report.py` | Not re-run today. Latent - no shipping producer emits those shapes. |
| 6 | `sqli_tool.py` has ZERO entries in `agent/mutation_gate.py` despite being the module behind most true positives | `agent/mutation_gate.py` | Not re-checked. Session 2 left 8 verified killing pairs ready to paste. |
| 7 | boolean-blind SQLi oracle has no baseline-stability control | `agent/sqli_tool.py` | Not re-run today. Session 1's REJECT stands. |
| 8 | Defects 1-3 in the code-assisted lane (aliased import FN, clock-token FP, dead `.seed(` branch) | `agent/codereview.py` | NEW today. Now pinned by 4 strict xfails, so the suite will announce the fix. |

Items 1, 2 and 3 are all in the reporting path rather than the detection path, which is the pattern
worth naming: this project's detection has been getting steadily harder to fool, and every
outstanding rejection is now about a surface that describes a finding rather than the oracle that
found it. That is where the next honest-numbers failure will come from.



---
---

# SESSION 4 (2026-08-14) — the whole-product −3

Brief: discriminate three candidate causes for `recall 22/1415 -> 19/1415`, close the harness gap
that makes candidate (3) unanswerable, reproduce two live sqli false positives, and decide whether
−3 is a stable delta or run-to-run variance.

Written incrementally. Everything below is MEASURED unless it says otherwise.

## Environment for this session

Lab up (`apolaki-owaspbench-1`, 15 h). Baseline mission `ebd96f45` still in the agent store and
readable over the API. No image rebuilt, nothing `docker cp`'d into `apolaki-agent-1`. All analysis
runs in throwaway `--network none` containers with a **key-free** work dir
(`<scratch>/brk4`) mounted at `/w` — the session scratchpad root holds `key.csv` and
`wpout/key.csv` and is therefore never mounted anywhere a scanner or a scored run can see it.

---

# TARGET 1 — the three candidates. RESULT: (1) and (2) are DEAD ON ARITHMETIC. (3) survives.

## 1a. The −9 sqli is NOT one oracle. It is 5 error-recovery + 4 boolean-blind.

The brief's proposed shortcut ("take the baseline's 20 sqli confirmations and ask whether the
stability gate would now reject them") assumes the 20 are boolean-blind confirmations. **They are
not.** Pulled the baseline mission's raw findings straight from the store and split them by oracle
tag — no summary trusted:

```
$ curl -s http://localhost:8000/missions/ebd96f45   ->  29 findings
by family        : {'sqli': 21, 'ldap_injection': 5, 'dom_data_manipulation': 1,
                    'sensitive_exposure': 1, 'vulnerable_component': 1}
sqli oracle split: {'error-recovery': 15, 'boolean-blind': 6}
```

The 15 error-recovery confirmations all arrive through the **request-header carrier**
(`GET .../sqli-00/BenchmarkTestNNNNN [request header BenchmarkTestNNNNN]`, evidence
`HTTP 200 (benign) -> 500 (single quote) -> 200 (doubled quote)`). The 6 boolean-blind arrive
through the **POST-form-field carrier**.

Diffing the baseline claim set against the sealed rerun claim set, with the harness's own
`case_ids()` extractor on both sides:

```
LOST   (in baseline, not in rerun): 00335 00337 00339 00341 00342   <- error-recovery, header carrier
                                    00428 00429 00433 00438         <- boolean-blind, POST-form carrier
                                    00494                           <- boolean-blind, THE false positive
GAINED (in rerun, not in baseline): 00023 (weakrand case)  02189 (xpathi case)
KEPT: 17
```

So the nine lost sqli-category cases are **five error-recovery + four boolean-blind**.

**CANDIDATE 1 (the blind-SQLi stability gate) — REJECTED, and it cannot be rescued.**
`sqli_tool.analyze_boolean` is the *only* function the gate touches. `quote_break_recovers` — the
oracle behind 15 of the baseline's 21 sqli findings and 5 of the 9 losses — takes three integers
(`base_status`, `single_status`, `double_status`) and has no baseline-repeat parameter, no body
comparison and no reference to the gate at all. **The gate is arithmetically incapable of removing
more than 4 of the 9.** "We traded ~9 findings for 0 FP" is false on the artifact alone; at most
4 findings were even eligible, and 1b below shows the gate does not reject those four either.

**CANDIDATE 2 (the target-rate policy) — REJECTED on the code and on the clock.**
`browser_engine.TargetRatePolicy` is not a throughput limiter. Read in full: it is a purely
*reactive* per-origin cooldown that adds delay only when a response carries a status in
`_RETRY_STATUSES = frozenset({429, 503})` **and** a parseable `Retry-After` header
(`observe()` returns `None` on any other status). With no 429/503+Retry-After from the target it
adds exactly zero seconds and cannot cut request volume. Two independent reasons it cannot be the
cause:
  * it can only ever ADD wall-clock time, and the rerun's wall clock went **down 64%**
    (5329 s -> 1893 s). A policy that slowed the run cannot also have shortened it.
  * probe volume is not scheduled against a rate; the loop is bounded by steps, not by seconds.

**CANDIDATE 3 (the run simply probed less) — SURVIVES, and the shape of the loss supports it.**
The five lost error-recovery cases are a contiguous later block of `sqli-00`
(00335/337/339/341/342) while the ten survivors are the earlier block (00018, 00192-00204). The
four lost boolean-blind cases (00428-00438) are later still. The rerun kept the *front* of the
sqli-00 case list and lost the *tail* — that is what a truncated sweep looks like, not what an
oracle change looks like. An oracle change would remove cases by their response shape, not by
their position in the queue.

## 1b. The gate does not reject the four eligible losses. It rejects ZERO of nine.

The brief's pure-function test, run properly: replay the PRODUCTION POST-form lane
(`tools._run_sqli` step 4 — GET the case page, `form_xss.parse_forms`, POST the field's OWN value
twice for `fbody`/`fbody_repeat`, then POST each `boolean_payloads` pair) against the live lab, and
evaluate BOTH forms of the decision on the same bodies:

```
ungated = analyze_boolean(fbody, true, false)
gated   = analyze_boolean(fbody, true, false, baseline_repeat=fbody_repeat)
```

`<scratch>/brk4/bb_gate.py`, run in a throwaway on `apolaki_default`, repo mounted `:ro`,
3 independent trials per case:

| case | in rerun? | baseline stability | ungated | GATED |
|---|---|---:|---|---|
| BenchmarkTest00033 | kept | 1.0000 | True 3/3 | **True 3/3** |
| BenchmarkTest00428 | **LOST** | 1.0000 | True 3/3 | **True 3/3** |
| BenchmarkTest00429 | **LOST** | 1.0000 | True 3/3 | **True 3/3** |
| BenchmarkTest00433 | **LOST** | 1.0000 | True 3/3 | **True 3/3** |
| BenchmarkTest00438 | **LOST** | 1.0000 | True 3/3 | **True 3/3** |
| BenchmarkTest00494 | LOST (was the FP) | 0.9091 / **1.0000** | True | **True on 3 of 4 fields** |

**The gate rejects 0 of the 4 eligible cases.** Every one of them has a byte-identical baseline on
repeat (`similar(b1,b2) = 1.0000`), which is precisely the condition the gate passes. The four
losses are therefore NOT the gate, and the five error-recovery losses were never reachable by it.

**Candidate 1 final: REJECTED. 0 of 9, not ~9 of 9.** There is no "deliberate trade" to record —
nothing was traded. The gate is still worth having (see 2b) but it did not buy the precision and it
did not cost the recall.

## 1c. Corollary the gate's authors will want: it does not fix `BenchmarkTest00494` either

`BenchmarkTest00494` still returns **CONFIRMED with the gate on**, on 3 of its 4 form fields, in
trial 0 and trial 1 above. The gate was session 1's recommended minimal fix for exactly this case,
and it does not close it — because 00494's instability is a two-state alternation that arrives in
runs, so two consecutive baselines usually land in the SAME state and look perfectly stable.
Quantified in TARGET 2 below: taking one extra sample halves the false-positive rate, it does not
remove it.

---

# TARGET 2 — the two sqli false positives. VERDICT: **STRUCTURAL, one shared cause, not two coincidences.**

Oracle variant, both times: **`boolean-blind`**, via the **POST-form-field carrier**. Not
error-recovery, not UNION, not quote-recovery. (`BenchmarkTest00023` rerun claim row:
`sqli | SQL injection (boolean-blind) in 'BenchmarkTest00023' | .../weakrand-00/BenchmarkTest00023`.)

## 2a. The shared cause, in one line: **a response body that changes between IDENTICAL requests.**

Dumped three responses to three byte-identical POSTs (`<scratch>/brk4/bodies.py`):

```
BenchmarkTest00023  (key: weakrand, VULNERABLE)
  [0] 'Floyd00023 has been remembered with cookie: rememberMe00023 whose value is: 99437195<br/>
       Weak Randomness Test java.util.Random.nextFloat() executed'
  [1] '... whose value is: 7079971<br/> ...'
  [2] '... whose value is: 4957906<br/> ...'

BenchmarkTest00494  (key: cmdi, CLEAN)
  two alternating DNS-failure strings, session 1's measurement, still live
```

`00023` is a **weak-randomness case**. Its whole point is to emit a fresh `java.util.Random` value
on every response. The body is 147-150 bytes and the varying digit run moves
`SequenceMatcher.ratio()` around **0.9495-0.9766** — straddling the oracle's 0.95 threshold. So the
app's own noise is the same size as the signal the oracle is looking for.

That is the identical mechanism as `00494` (non-deterministic resolver text, 0.9091). **One defect,
two spellings.** It is not a coincidence and it is not two bugs.

## 2b. Negative control: the oracle CONFIRMS SQLi on responses to identical requests, gate on

The honest negative control is to hand the oracle four responses to the SAME request with the SAME
value and no payload at all. Every `True` is a false positive by construction. 12 identical POSTs
per field, all 400 ordered 4-tuples (`<scratch>/brk4/bb_negctl.py`):

```
case                 field                  n  distinct  pairwise sim        FP/attempt ungated  GATED
BenchmarkTest00023   productID             12    12      0.9495..0.9764          0.045          0.045
BenchmarkTest00023   secure/foo/00023      12    12      0.9530..0.9766          0.000          0.000
BenchmarkTest00494   secure                12     2      0.9091..1.0000          0.203          0.090
BenchmarkTest00494   productID             12     2      0.9091..1.0000          0.225          0.150
BenchmarkTest00494   foo                   12     2      0.9091..1.0000          0.280          0.155
BenchmarkTest00494   BenchmarkTest00494    12     2      0.9091..1.0000          0.235          0.077
BenchmarkTest00428   email/password/00428  12     1      1.0000..1.0000          0.000          0.000
BenchmarkTest00033   secure/productID/...  12     1      1.0000..1.0000          0.000          0.000
```

Read it as three facts:

1. **The gate helps and does not fix.** `0.203 -> 0.090`, `0.280 -> 0.155`, `0.235 -> 0.077`. It
   roughly halves the rate because `00494`'s two states arrive in runs, so one extra sample agrees
   with the first about half the time. `0.045 -> 0.045` on `00023`: for a body that is different
   every single time but only *slightly*, the extra sample lands above 0.95 as often as the
   baseline does, and the gate contributes **nothing at all**.
2. **The true positives pay nothing.** `00428` and `00033` are byte-identical across 12 requests
   (1 distinct body) and score **0/400** in every field, ungated and gated. Baseline stability
   separates the true positives from the false positives perfectly, exactly as session 1 found —
   it is just that a *two-sample* test is not a strong enough estimator of it.
3. **This is a per-attempt rate, and the engine takes many attempts.** 4 boolean contexts x every
   text field on the form. On `00494` that is ~16 attempts at 8-16% each; a confirmation is close
   to certain over a full field sweep, which is why it fired in the baseline mission and fires
   again today.

## 2c. Why this is bigger than two cases: an entire benchmark category is exposed

`weakrand` cases emit a fresh pseudo-random value per response **by definition**. That is 493 cases
in the Java suite of which roughly 275 are CLEAN. The boolean-blind oracle has a systematic
cross-family false-positive exposure across the whole category, and which field it lands on is
chance — in my 3 live trials the fire moved between `foo`, `productID` and neither.

**This downgrades the rerun's headline.** `precision 100.0% (19/19)` includes `BenchmarkTest00023`,
which is an sqli claim on a weakrand case with no sqli in it. It scored as a TRUE POSITIVE only
because the LOOSE convention credits any claim on a genuinely-vulnerable case and this particular
weakrand case happens to be vulnerable *to weak randomness*. Had the same coin landed on any of the
~275 clean weakrand cases, the rerun would have scored a false positive and the 100.0% would not
exist. The class-matched 89.5% is the honest number and the 10.5% gap is exactly this.

## 2d. The fix that would actually work (owner's call — `agent/sqli_tool.py` is mine to write, but
## this changes a shipped oracle's behaviour, so it is proposed, not adopted)

The two-sample gate estimates stability with n=2 and compares against the *same* constant the
divergence leg uses. Two independent strengthenings, both cheap:

* **Sample the baseline more than twice and require the observed noise floor to be BELOW the
  divergence being claimed.** The correct predicate is not "baseline repeats" but
  `similar(true,false) < min(pairwise baseline similarity)` — i.e. the payload must move the page
  by MORE than the page moves on its own. On `00494` the noise floor is 0.9091 and the claimed
  divergence is 0.9091: identical, so the claim is worth nothing. On `00428` the floor is 1.0000
  and the divergence is 0.9373: a real difference. This one predicate separates all six cases
  measured above with no threshold tuning.
* **Re-send the FALSE payload and require the divergence to reproduce.** Kills any single-sample
  straddle.

Both are 1-3 extra requests per field. Neither weakens the oracle: the four lost true positives and
`00033` all pass both.

---

# TARGET 3 — is −3 real? PART ONE: **the baseline it is measured against is not reproducible.**

Before asking whether the rerun varies, ask whether the "before" number can be re-derived. It
cannot. `docs/LEDGERS.md` (lines 147-186) records mission `ebd96f45` as:

```
total findings: 25   by family: {'sqli': 21, 'ldap_injection': 1, 'dom_data_manipulation': 1,
                                 'sensitive_exposure': 1, 'vulnerable_component': 1}
distinct cases claimed: 23    SEAL sha256: a95670f9c7560b227a234ebeb23c0fba0872cb3100f87e52d0c4d878988660f5
TRUE POSITIVES: 22   FALSE POSITIVES: 1
```

The agent store returns something else for that same mission id today
(`curl -s http://localhost:8000/missions/ebd96f45`, MEASURED 2026-08-14):

```
findings: 29   by family: {'sqli': 21, 'ldap_injection': 5, 'dom_data_manipulation': 1,
                           'sensitive_exposure': 1, 'vulnerable_component': 1}
distinct cases claimed (harness's own case_ids extractor): 27
seal over those 27: fab8a46e13633f6a418a05742b4a49a588acd8e5fb34aa00ceb03f0dedeb9051
```

Everything matches except `ldap_injection`: **1 in the ledger, 5 in the store.** The store's five
are on `BenchmarkTest00630 / 00695 / 01242 / 01490 / 01568`, and the mission's own log has
`run_ldap` executing at `00:47:13` and `00:48:21` inside the mission window, so they are that
mission's findings, not something appended later. Checked and ruled out:

* **Dedup does not explain it.** `memory.finding_fp` over the 29 findings yields **29 distinct
  fingerprints** — nothing collapses, and the five ldap findings differ in both param and path.
* **A later mission did not write into it.** No mission in the store carries
  `parent_id = ebd96f45`; the mission is `status: complete, phase: report, recon_cycles: 1`.
* **The seal does not reconcile.** Brute-forced every removal of up to 5 cases from the 27; none
  reproduces `a95670f9`. The recorded seal is not the seal of any near-subset of what the mission
  holds, so the two numbers cannot be reconciled by "the capture dropped these four".

**Why this matters for the −3.** The rerun's headline gain is `ldapi 1 -> 5 (+4)` — offered as
evidence that "class coverage genuinely BROADENED". The baseline mission has all five. On the
store's numbers the comparison is **27 claimed -> 19 claimed**, the ldapi "gain" is zero, and the
loss is **−8, not −3**. On the ledger's numbers it is −4/−3 with a +4 ldapi gain. One of those two
is wrong and nothing in the repository can currently say which.

**This is the most important thing in this section.** Every published whole-product delta rests on
a baseline that cannot be re-derived from the artifact it names. The rerun side is fine — it is
sealed, hashed, and I reproduced its score byte for byte. The baseline side is a number in a
markdown table. `scripts/whole_product_score.py` now carries that provenance and caveat in the
`BASELINE` dict and in the JSON it writes, so nothing downstream can quote 22/23 without it.

**Owner action (`docs/LEDGERS.md` is not mine):** either re-extract the baseline from the store and
restate it as 27 claimed / 26 TP (which makes the delta −8 and removes the ldapi gain), or record
exactly what the 08-11 capture filtered out and why. Until one of those happens, "recall fell by 3"
is a claim about two numbers produced by two different procedures.

## 3-aside. What "class coverage broadened" actually reduces to

With the baseline mission's real family counts in hand, the claimed broadening is:

```
ldapi   baseline 5 (00630 00695 01242 01490 01568)  ->  rerun 5 (the same five)   +0
xpathi  baseline 0                                  ->  rerun 1 (02189)           +1
```

The rerun's five ldapi cases are **the baseline's five ldapi cases**, case for case. So the
broadening the body-parameter work is credited with is **one xpathi case**, not five ldapi plus one
xpathi. That does not make the work wrong — `xpathi` genuinely went 0 -> 1 and those sinks do take
body input only — but the evidence for it is one case, and the other four-fifths of the claim is
the ledger discrepancy above.

---

# TARGET 2 (cont.) — `BenchmarkTest00407`: the third shape, and it is one this project already fixed once

Both runs claim `dom_data_manipulation` on `BenchmarkTest00407`, a `cmdi` case. Read the producer
(`agent/dom_trace.py:158-161`, `classify`):

```python
if s.get("in_attr") or s.get("in_text"):
    where = s.get("in_attr") or "DOM text"
    hits.append({"family": "dom_data_manipulation", ...,
                 "evidence": "%s reflects into rendered DOM content at runtime (%s)" % (...)})
```

and `finding()` — "Build a CONFIRMED finding from a trace hit" — stamps `CWE-79` on it
(`_CWE["dom_data_manipulation"] = "CWE-79"`). The stored evidence on both runs is exactly
`query parameter 'BenchmarkTest00407' reflects into rendered DOM content at runtime (DOM text)`.

**The signal is reflection and nothing else.** No breakout, no execution, no sink beyond "the text
appeared". That is the same signal that made the path-traversal oracle a false-positive generator,
and commit `0233574` fixed it there by demoting a reflection-only hit to `confidence=lead,
severity=info` (verified CONFIRMED in session 3, 45/45 cross-family claims correctly demoted). The
DOM lane still stamps `confirmed` + `CWE-79` on the same evidence class. Every OWASP Benchmark case
that echoes its parameter — which is most of them — is eligible.

**Verdict: PLAUSIBLE, not CONFIRMED.** The code path and the stored evidence are measured and
unambiguous, and the parallel to `0233574` is exact. I did not run the live DOM sweep across
categories to measure how many cases it fires on, because a browser sweep against the lab would
have perturbed the variance runs in flight (TARGET 3). That breadth measurement is the missing
check. `agent/dom_trace.py` is not mine.

---

# TARGET 1 (cont.) — 1d. Candidate 3 has a *mechanism*, and it is a hard cap of 25

Reading the deterministic sweep end to end (`agent/planner.py`, `agent/surface.py`, `agent.py`):

```
planner.py:38-46   CAP_HOSTS = 30   CAP_ENDPOINTS = 25   CAP_REST = 30   CAP_FORM_PAGES = 10
                   CAP_JS = 40      CAP_DOM = 6          CAP_SQLMAP = 8
planner.py:434     param_eps = [e for e in inv if e.get("parameterized")][:CAP_ENDPOINTS]
planner.py:486-498 per endpoint: run_xss, run_sqli, run_nosqli, run_injection_probes,
                                 run_web_probes (+ run_ssrf / run_cmdi when the param name matches)
agent.py:3160      MAX_STEPS = 220
agent.py:1670      BBH_SURFACE_PAGES default 250, BBH_SURFACE_DEPTH default 4
```

So against a 2740-case corpus one deterministic cycle crawls **at most 250 pages**, keeps the
**first 25 parameterized endpoints** `surface.build_inventory` returns, and fetches **10** pages for
form discovery. `build_inventory` preserves the INSERTION ORDER of `tools.urls`
(`surface.py:55-77`, an `order` list, not a set), and `tools._add_urls` appends in discovery order,
so **which 25 endpoints get probed is decided entirely by crawl order**.

That is the ceiling on whole-product recall — 25 endpoints against 1415 vulnerable cases is at most
~1.8% before any oracle runs — and it is also the mechanism candidate 3 needs. Nine specific sqli
cases did not "stop being detectable"; they are 9 cases outside the 25/10 this run's ordering
selected. Consistent with the loss shape: the survivors are the front of `sqli-00` and the losses
are its tail.

**What this does NOT yet settle** is whether crawl order is stable between two runs of the same
code. If it is, the −3 is a real consequence of a code change that shifted the ordering; if it is
not, −3 is noise. That is exactly the measurement in TARGET 3 PART TWO, in flight now.

**Recorded for the harness owner:** `effort.plan_steps` vs `step_cap` will now say which of the two
bounds actually bit — 220 steps or 25 endpoints — and `coverage.cases_probed` says which cases the
ordering picked. Neither number existed before today.

## 1d-CORRECTION — I named the wrong cap. The binding bound is the CRAWL, not `CAP_ENDPOINTS`.

Committed at `a17b6f3` and wrong on one point, corrected here rather than edited away: I wrote that
the sweep "probes the FIRST 25 parameterized endpoints". `CAP_ENDPOINTS = 25` bounds the
**planner's** `param_eps` (`planner.py:434`) — but the sqli engine is not scheduled only from
there. `agent.py:3424` runs a **planner-independent** deterministic sweep:

```
agent.py:182   SWEEP_TARGET_CAP = int(os.getenv("BBH_SWEEP_TARGETS", "400"))   # 400, not 25
agent.py:188   _SWEEP_HTTP_ENGINES = ("run_sqli", "run_sqli_structural", "run_xpath", "run_ldap", ...)
agent.py:3424  targets = sweep_targets(self.tools.urls, recon["forms"], in_scope, limit=SWEEP_TARGET_CAP)
agent.py:3462  for _i, u in enumerate(targets): for tool in _SWEEP_HTTP_ENGINES: ...
```

`sweep_targets` (agent.py:238-295) takes every query-bearing URL, one representative per
`(path, param-signature)`, **plus the page carrying each captured POST form**, then
`_spread_by_shape(...)[:400]`. It is explicitly documented as order-stable. So run_sqli reaches up
to 400 endpoints, not 25, and the boolean-blind POST-form lane is reached through the *form pages*
half of that selection.

**The real ceiling is one level up: the crawl.**

```
agent.py:1669-1670   BBH_SURFACE_DEPTH default 4, BBH_SURFACE_PAGES default 250
```

**250 pages** are fetched out of a 2740-case corpus, and `sweep_targets`, the form store and the
inventory can only ever see pages that were fetched — the module's own docstring says exactly this
("the entire mission's coverage was arithmetic on those 12 pages"). Which 250 the BFS reaches, in
which order, decides which cases are testable at all. That is still candidate 3's mechanism, and it
is a stronger one: a ~9% ceiling on reachable cases before any oracle runs, set by a BFS frontier
over an index tree.

The corrected statement: **the run probes what the crawl reached, the crawl reaches 250 of 2740
pages, and nothing in the artifact recorded which 250.** `coverage.cases_probed` records it now.

---

# SESSION 4 — VERDICTS SO FAR (the eight checks, per claim)

## Claim: "the blind-SQLi stability gate cost ~9 findings and that was the right trade"

| check | result |
|---|---|
| 1. failed before the fix | n/a — this is a claim about a shipped change, not a new test |
| 2. exact assertion kills the mutant | n/a |
| 3. negative controls stay clean | **FAIL.** The gate still confirms on responses to identical requests: 00494 at 7.7-15.5% per attempt, 00023 at 4.5%. 400 ordered 4-tuples per field, 12 live samples. |
| 4. false positives anywhere | The gate reduced FP rate but did not remove it; and `00023`, a NEW false positive of the same shape, appeared in the rerun. |
| 5. deterministic replay | **PASS for the losses**: all four eligible cases fire gated in 3/3 independent trials. |
| 6. clean environment | PASS. Throwaway container on `apolaki_default`, repo mounted `:ro`, no image rebuilt, no `docker cp`. |
| 7. all surfaces agree | n/a |
| 8. generalises | n/a |

**VERDICT: REJECTED.** The gate rejects **0 of the 9** lost cases: 5 were confirmed by
`quote_break_recovers`, which the gate cannot reach, and the other 4 have baseline
self-similarity 1.0000 and confirm with the gate on. No trade was made, so none should be recorded.

## Claim: "the target-rate policy cut requests per unit time"

| check | result |
|---|---|
| 6. clean environment | PASS — read from the committed tree. |
| the mechanism | **FAIL.** `TargetRatePolicy.observe` returns `None` for any status outside `{429, 503}` and for any response without a parseable `Retry-After`. It is a reactive cooldown, not a rate limiter, and it has no other pacing anywhere: the only `asyncio.sleep` on a target path in `tools.py` is GitHub-recon dork spacing. |
| the arithmetic | **FAIL.** It can only ADD wall-clock time. The rerun's wall clock fell 64%. |

**VERDICT: REJECTED**, twice over.

## Claim: "the two sqli false positives are two coincidences"

| check | result |
|---|---|
| 3. negative controls | Run and decisive — identical-request 4-tuples, 400 per field, gate on. |
| 4. false positives | Measured per-attempt rates, and 0/400 on both stable true positives. |
| 5. deterministic replay | The FP is stochastic *by construction*; that is the finding, and the negative control measures its rate instead of chasing a single fire. |
| 8. generalises | The mechanism is "unstable response body", and an entire benchmark category (`weakrand`, ~493 cases, ~275 of them clean) has one by definition. |

**VERDICT: one structural defect, CONFIRMED.** Not two coincidences. Pinned by three strict xfails
in `agent/tests/test_sqli_boolean_noise_floor.py`.

## Claim: "the rerun scored 100.0% precision"

Arithmetically true and reproduced byte for byte. **But it includes `BenchmarkTest00023`, an sqli
claim on a weakrand case**, credited as a true positive only because the LOOSE convention counts any
claim on a genuinely-vulnerable case and this weakrand case happens to be vulnerable to weak
randomness. The same oracle firing on any of the ~275 CLEAN weakrand cases would have scored a false
positive. **The class-matched 89.5% is the honest number**, and the 10.5% gap is exactly
`00023` (sqli on weakrand) and `00407` (dom_data_manipulation on cmdi).

---

# TARGET 3 PART TWO — is −3 variance? The measurement design, stated before the result

Two whole-product runs of **identical code**, so the only thing that can differ is the run itself.

* **Code frozen once**, copied out of the working tree at `HEAD = 6c9907a` into
  `<scratch>/brk4/snap`, sha256 over the sorted per-file hashes of every `.py`:
  `a02c4b318a3abe1f8a2443c0a6da90ad2c723d5fe46c8bf67d7e78c08d9d5f6d`. Both runs mount that
  snapshot, not the repo — Codex is live in `agent/tools.py` / `main.py` / `zap_client.py` and a
  mid-run edit would silently make the two runs different products.
* Same harness (`wp_run.py` from the snapshot), same target, same mode, `BBH_DATA_DIR=/tmp/wpdata`
  so neither touches the shared store, `/out` mounted to a **key-free** directory.
* Neither container can see a key. The seal is computed by the harness at the end, as before.

**Stated in advance, so it cannot be fitted afterwards.** Two predictions:

1. The deterministic selection path is order-stable at every step I read
   (`crawl.bfs_frontier` first-occurrence, `surface.build_inventory` explicit `order` list,
   `_spread_by_shape` dict insertion order, `sweep_targets` documented "order-stable"). If the crawl
   is stable too, the two claim sets should be **identical**.
2. Against that, the boolean-blind oracle on an unstable body is **stochastic by measurement** —
   `BenchmarkTest00023` fires at ~4.5% per attempt and 00494-shaped pages at 8-16%. So any claim
   resting on an unstable body is a coin flip, and I expect the differences (if any) to be
   concentrated exactly there.

**Caveat recorded before the numbers, not after:** the two runs are executing CONCURRENTLY against
the same lab, to fit inside one session. Contention can only ADD noise. If the claim sets come out
identical, the determinism conclusion is safe *a fortiori*. If they differ, the honest reading is
"inconclusive between run-to-run variance and contention" unless the differences fall exactly on
the unstable-body cases, and the right follow-up is a sequential repeat.
