# Dataflow lane - hand-off

Question this lane answers: **`trustbound` is 126 Java + 37 Python cases scoring an honest 0.0%.
Can a deterministic analysis separate the vulnerable cases from their laundered clean twins at
0.0% FPR, or is the honest 0 the right answer?**

Status legend: [READ] read from benchmark source. [MEASURED] scored against the key after sealing.

---

## THE ANSWER

**Yes. Measured, sealed, on the full populations of both suites, with no sampling.**

| suite | category | TP | FN | FP | TN | TPR | FPR | score |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| Java v1.2 | trustbound | 83 | 0 | 0 | 43 | **100.0%** | **0.0%** | **100.0%** |
| Python v0.1 | trustbound | 18 | 0 | 0 | 19 | **100.0%** | **0.0%** | **100.0%** |

**FPR on the clean twins is 0.0% on both suites.** 43 Java and 19 Python clean twins - the
constant-folded branches, the safe map slots, the safe list index, the constant-returning helper,
the route-pinned path - and not one of them is reported.

Code-assisted (SAST) suite macro, over ALL suite categories with unmeasured counted as 0:

| suite | before | after | delta |
|---|---:|---:|---:|
| Java v1.2 | 27.3% | **36.4%** | **+9.1** |
| Python v0.1 | 14.3% | **21.4%** | **+7.1** |

The arithmetic is exactly additive and nothing else moved: 100.0/11 = 9.09 and 100.0/14 = 7.14.
crypto, hash and weakrand are unchanged at 100.0% TPR / 0.0% FPR on both suites.

**Official macro equals product macro on both suites, and cross-family false positives are zero.**
There is no clean case anywhere in either suite where this lane would hand a client anything.

**This is a CODE-ASSISTED (SAST) number.** It may never be folded into a DAST figure or compared
against ZAP's 17.99% or best-published-DAST 26%; those tools were never given the source.

---

## The mutation test, which is the actual evidence

A negative control is only worth the mutant it survives. **M1 is the plausible implementation of
this rule: flag the sink.** It is what a call-site matcher would ship, and it passes every positive
assertion in the test file.

| | Java trustbound | Python trustbound | Java product macro | Python product macro |
|---|---|---|---:|---:|
| M1 provenance-blind | 83 TP / 43 FP - **100.0% TPR, 100.0% FPR, score 0.0%** | 18 TP / 19 FP - **100.0% TPR, 100.0% FPR, score 0.0%** | 18.2% | 7.1% |
| shipped analysis | 83 TP / 0 FP - 100.0% TPR, **0.0% FPR**, score 100.0% | 18 TP / 0 FP, **0.0% FPR**, score 100.0% | **36.4%** | **21.4%** |

**M1 has identical recall.** Every vulnerable case is found. It scores **0.0%** on the category
anyway, because it also flags every clean twin - and it costs the whole product macro half its
value (Java 36.4% -> 18.2%, Python 21.4% -> 7.1%) through **275 Java and 227 Python cross-family
false positives** on clean cases of OTHER categories.

That last number is the point, and the corpus supplied it for free: **619 of 2740 Java cases carry
a session sink and only 126 are `trustbound`.** The other 493 are the `rememberMe` boilerplate on
every securecookie and weakrand case, where the value stored is a class name and a `SecureRandom`
output. This is the exact shape of the code-assisted lane's `random.SystemRandom()` finding - a
name-matching implementation that scores full recall and passes every positive test.

---

## Verdict on the standing decision: two thirds right, one third wrong [READ]

`agent/owasp_bench.py` said the clean twins launder through a collection, a StringBuilder, or a
constant-folded ternary. Checked against all 163 cases:

| claim | verdict |
|---|---|
| collection `map.get("keyA-")` launders | **CONFIRMED**, and understated |
| constant-folded ternary launders | **CONFIRMED**, the sharpest discriminator |
| StringBuilder launders | **WRONG for this category** |

**All 19 StringBuilders in Java `trustbound` are constructed from `param`** - 11 literally
`new StringBuilder(param)` and 8 from a local that is `param`. There is not one constant-only
StringBuilder in the category. Here the StringBuilder is a *propagator*, and treating it as a
launderer would have produced false NEGATIVES, not the false positives the comment feared.

The collection claim is understated because the clean twin **reads the tainted key first**:

```java
map.put("keyA-N", "a-Value");
map.put("keyB-N", param);
bar = (String) map.get("keyB-N");   // <- BOTH twins have this line
bar = (String) map.get("keyA-N");   // <- clean twin only; last write wins
```

4 Java cases have both gets (clean), 4 have only the `keyB` get (tainted). A rule phrased as "does
`get("keyB")` appear" flags both.

---

## What the twins actually differ by [READ]

The sink carries no signal: **163 of 163 cases call a session sink**, and the tainted argument is
the KEY in some (`setAttribute(bar, "10340")`) and the VALUE in others
(`setAttribute("userid", bar)`), so argument position is no help either.

The sharpest pair is character-identical in its predicate:

```java
// vulnerable                              // clean
int num = 106;                             int num = 86;
bar = (7*42) - num > 200 ? CONST : param;  if ((7*42) - num > 200) bar = CONST; else bar = param;
// 294-106 = 188, false arm -> param       // 294-86 = 208, true arm -> constant
```

Folding table across the Java category: `(7*42)-num>200` is **true at num=86 and false at
num=106**; `(7*18)+num>200` is true at 106; `(500/42)+num>200` is true at 196, where `500/42` is
**11** under integer division. Two things must be computed, not one - which arm is taken, and which
arm holds the parameter. The suite writes both directions.

Two sources read exactly like request reads and are not:

1. **`SeparateClassRequest.getTheValue(p)` returns the constant `"bar"`** - 8 Java cases; the
   Python twin `request_wrapper.get_safe_value` is 3 more. The call site is indistinguishable from
   `getTheParameter(p)`; the difference lives in another file.
2. **`request.path.split("/")[1]` is the literal `'benchmark'`** under a converter-free Flask
   route - 3 Python cases. All 112 uses of that source in the whole Python suite index `[1]`.

---

## The five negative controls [MEASURED - 39 tests, all green, all failed before the code existed]

`agent/tests/test_dataflow_lane.py`. Each control is **paired with a twin** where the only
difference is provenance, so a control cannot pass because nothing resolved:

| # | control (must NOT flag) | paired twin (MUST flag) |
|---|---|---|
| 1 | value from a constant-returning helper | same receiver, the request-reading method |
| 2 | `map.get("keyA")` after both gets | `map.get("keyB")` only |
| 3 | folded branch taking the constant arm | same predicate, different constant |
| 4 | StringBuilder of only constants | StringBuilder built from `param` |
| 5 | - | request parameter through all 7 launderers |

Plus: the sink with no request provenance (the `rememberMe` shape), an unfoldable condition keeping
the taint, an unresolved call propagating rather than dropping it, integer division, switch/match on
a folded character, list index arithmetic after a removal, the route-pinned path AND its converter
counter-case, and escaping NOT sanitizing.

All 39 failed before the analysis existed. As in the code-assisted lane, that is the weakest useful
form of fail-first - it shows the tests are new, not that they discriminate. **The mutation table
above is what shows they discriminate.**

---

## Encoders are not sanitizers here, and that was pre-registered

`escapeHtml` / `ESAPI.encodeForHTML` / `HtmlUtils.htmlEscape` (17 Java cases) and
`markupsafe.escape` / `escape_for_html` (2 Python) are modelled as **taint-preserving**. CWE-501 is
about trust; CWE-116 output encoding is about a rendering context, and a session is not one -
`session[escapeHtml(attacker_string)]` is still an attacker-chosen key.

This was written into this file and committed (`39573bc`, `e366446`) **before any key was fetched**,
precisely so it could not be back-fitted. The measurement agrees with it: the benchmark labels those
cases vulnerable, and treating them as sanitized would have cost 19 true positives.

---

## Sealed measurement

### Blindness

1. Source moved container-to-container with `tar --exclude='expectedresults*'`. Verified in the
   scanning container: **0 key files**, against 2763 Java and 1236 Python sources.
2. Artifacts sha256-sealed on the host **before** any key was fetched. Seal time
   **2026-08-13T13:56:57Z**.
3. Scored in `apolaki-scorer`, started `--network none`, with the hashes re-verified inside it and
   matching the host seals exactly.

| artifact | rows | sha256 |
|---|---:|---|
| `java_ca3.json` | 2740 | `239ff8e7fe9ba4997a431da93ebb1ae8a6bfc24d480d598d8299fed93a4f2ac5` |
| `py_ca3.json` | 1230 | `8023e1598a5057e3f6062fde7cebdc6a5d082a70b123d434a0cabe5dbfc4ac6a` |

Two earlier seals were taken and are **superseded, not hidden**: `38d09e9b...` (Java, invalid - see
the setup error below) and `a46b5f7f...` (Java, valid but before the arity fix; it scored trustbound
80.7%).

### Java v1.2, code-assisted, full suite

```
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
official macro (11 cats): 36.4%    product macro: 36.4%    cross-family FP: 0
```

### Python v0.1, code-assisted, full suite

```
trustbound       18     0     0    19   100.0%   0.0% 100.0%
hash             71     0     0    80   100.0%   0.0% 100.0%
weakrand         99     0     0   227   100.0%   0.0% 100.0%
(the other 11 categories are 0.0% - this lane has no rule for the injection classes)
OVERALL         188   264     0   778    41.6%   0.0%  41.6%
official macro (14 cats): 21.4%    product macro: 21.4%    cross-family FP: 0
```

---

## Two defects the MEASUREMENT found that the tests did not

Both were caught by the first sealed run scoring 80.7% instead of 100%, then diagnosed from the 16
misses - which were **all one shape**.

1. **A same-named method with a different signature was being inlined.** A file that defines
   `doSomething(request, param)` and also calls `thing.doSomething(param)` on an interface from
   another file has two methods with one name. The local one was inlined for the foreign call,
   binding the taint to `request` and `param` to nothing, so the taint was **dropped**. All 16
   misses were this. Arity checking took Java trustbound from 80.7% to 100.0%.
2. **`merge_summaries` treated "undecided" as agreement.** A name resolved `const` in one file and
   left undecided in another was applied tree-wide, letting one accidental constant helper vouch
   for every same-named method. `summarize_units` now reports undecided units so the merge can
   retract.

## And one measurement-setup error, recorded because it produced a convincing wrong answer

The first Java export copied `src/main/java` and left `src/main/resources` behind, so
`properties_resolved` was **0** and every `getProperty(key, DEFAULT)` fell back to its default
literal. That read as **crypto 23.3% FPR and hash 69.0% TPR** - a plausible-looking regression in
two categories this lane never touched.

What settled it was not reasoning, it was a **row-for-row diff against the pre-change code over the
same 2763 files: 0 differing files**. That proved the code innocent and sent me to the harness. Re-
exported with resources, `properties_resolved` 128, both categories back to 100.0%.

The general lesson is the one already in this project's memory: `getProperty(key, DEFAULT)` with the
properties file missing does not fail, it silently analyses a different codebase. **Check the
resolved-input count, not just the file count.**

---

## What this lane does NOT claim

- Not DAST. Every finding carries `lane: code-assisted`, `provenance: source-derived`.
- The 8 zero rows in the Java table and 11 in the Python table are real. This lane has no rule for
  the injection classes.
- 100% TPR at 0% FPR means every case was called correctly, not that the category is easy - the
  provenance-blind mutant gets the same recall and scores 0.0%.
- The analysis is intra-file plus whole-tree return summaries. It is not a full interprocedural
  points-to analysis, and a launderer built from constructs outside the five modelled mechanisms
  would fall back to taint-preserving (a false positive risk, not a false negative one).

## Files

Owned and changed: `agent/codereview.py` (the analyser), `agent/codeintel.py` (pass 1 wiring),
`agent/tests/test_dataflow_lane.py` (39 tests), `agent/tests/test_source_lane.py` (the standing
assertion inverted, not deleted), `agent/owasp_bench.py` (**the `FAMILIES["trustbound"]` entry
only**), this file.

Regression: full suite green in a clean container off the working tree, exit 0, 0 failures.

---

## Q-041 and Q-042 [MEASURED - both fixed, both cost the benchmark exactly 0]

Both were strict xfails pinning measured defects. The markers are gone because the facts changed;
every assertion the Breaker wrote is intact and four negative controls were added.

**Q-041 - the binding was computed and thrown away.** `_py_imports` produced
`modules['r'] = 'random'`, and every rule then matched a hard-coded literal receiver. So
`from random import getrandbits as g` worked and `import random as r; r.getrandbits(32)` was
invisible. Half a mechanism - the same shape this project keeps finding - and the missing half is
the one real code is likelier to use. `_py_module_aliases` resolves the binding rather than only
suppressing it.

Widening the receiver must not widen the verdict, so the controls are the deliverable:
`import numpy.random as r` and `from numpy import random` still report nothing, and
`r.SystemRandom().getrandbits(32)` - the 113 clean twins, through an alias - is still a CSPRNG.

**Q-042 - the rule matched a substring of a name.** `_PY_CLOCK_TOKEN` fired on any identifier
merely CONTAINING a security word within 90 characters of a clock read. Fixed structurally, not
with a longer word list:

1. an assignment is at **paren depth 0** - `f(token=x)` is a keyword argument, not an assignment;
2. a compound identifier means its **head noun** - `token_expiry` is an expiry, `session_start` is
   a start, and `expiry_token` really is a token.

The Java twin `_CLOCK_TOKEN` had the identical defect and got the identical fix.

### Evidence

| check | result |
|---|---|
| benchmark cost, both suites | **0 cases** - re-scan produced artifacts **byte-identical** to the sealed trustbound run (`239ff8e7...`, `8023e159...`), 0 differing cases of 2740 and 1230 |
| the in-the-wild false positive | **gone**: CWE-337 across 5150 files of the container's own Python goes **1 -> 0**, and the one removed is exactly `token=` at `anthropic/lib/credentials/_workload.py:346` |
| true positives lost | **none** - on the stdlib and on Apolaki's own `agent/` tree the only old/new difference is that single false positive |

Byte-identical artifacts are a stronger claim than an unchanged score: the score *cannot* have
moved, because the input to the scorer did not.

**Honest note on Q-041's measured gain: it is zero on all four corpora, and that is the correct
answer rather than a disappointment.** Only two stdlib files alias these modules, and the sole
aliased digest call is `_hashlib.new(digestmod, ...)` in `hmac.py`, where the algorithm is a
caller-supplied variable and no verdict is available. The fix is proven by construction and by unit
tests, not by a corpus that happens to exercise it. Claiming a measured improvement here would be
inventing one.

## Next in this lane

**Q-044 is the one that matters now**: `codeintel.review_source_tree()` - this analyser, scoring
100/100/100/100 - has exactly one caller, `owasp_bench.py`. No mission can supply a source tree and
`/codereview` calls the older `codeintel.review()`. The capability is benchmark-only, which is why
Q-042's false positive was theoretical; the moment it gets a production entry point, it stops being.
