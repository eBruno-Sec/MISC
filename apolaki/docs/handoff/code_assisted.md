# Code-assisted (SAST) lane - hand-off

Question this lane answers: **the code-assisted analyzer measured 100% TPR / 0% FPR on Java and
contributed exactly nothing to Python. Why, and what is it worth once it does?**

Answer: it was gated by a file extension, not by a capability. `review_source_tree` walked only
`*.java`. Removing that gate and writing the Python half of the same call-site discipline moves the
Python v0.1 hybrid macro from **24.5% to 38.8%**, with **0.0% FPR under both conventions** and
**zero cross-family false positives**.

Every number below is MEASURED and sealed. Status legend: [DONE] scored and sealed.

Commit: `3a62c04` (implementation + 30 tests). Artifacts and this document: see "Committed
artifacts" below.

---

## HEADLINE

| suite | lane | convention | macro | denominator |
|---|---|---|---:|---|
| Python v0.1 | DAST only (unchanged baseline) | official | 24.5% | 14 categories |
| Python v0.1 | DAST only (unchanged baseline) | product | 24.5% | 14 categories |
| **Python v0.1** | **HYBRID (DAST + code-assisted)** | **official** | **38.8%** | 14 categories |
| **Python v0.1** | **HYBRID (DAST + code-assisted)** | **product** | **38.8%** | 14 categories |
| Python v0.1 | code-assisted ALONE, full 1230 cases | official | 14.3% | 14 categories |
| Java v1.2 | code-assisted, re-run after the change | (3 mapped cats) | 100.0 / 100.0 / 100.0 | crypto, hash, weakrand |

**+14.3 points on Python, and the arithmetic is exactly additive**: hash 0 -> 100 contributes
100/14 = 7.14, weakrand 0 -> 100 contributes 100/14 = 7.14, and 24.5 + 14.29 = 38.8. Nothing else
moved by a single point, which is the measurement that proves there were no side effects.

**THIS IS A CODE-ASSISTED (SAST) CONTRIBUTION.** The hybrid figure may never be compared against
ZAP's 17.99% or best-published-DAST 26%; those tools were never given the source. The only
Python number in this document comparable to a published DAST score is the DAST-only 24.5%,
and this lane did not change it.

---

## The defect

`agent/codeintel.py`, `review_source_tree`:

```python
for fn in filenames:
    if not fn.endswith(".java"):
        continue
```

The analyzer behind that line scores crypto 100.0% / hash 100.0% / weakrand 100.0% at 0.0% FPR on
the Java suite. On the Python suite the same three classes are **514 of 1230 cases (41.8%)** and
scored **0.0%**, not because the analysis is Java-specific but because a walk of the tree was.

A language gate on a language-independent analysis is a capability thrown away by an extension
check. It is the cheapest defect shape in the catalogue and the most expensive to leave in place.

## The fix

Three pieces, in `agent/codereview.py` and `agent/codeintel.py`.

1. **`_Dialect`** splits out the only two things value-resolution needs from a language: where
   externalized configuration is fetched (`getProperty` in Java, `os.environ.get` in Python) and
   where a statement ends (`;` versus a newline). Java passes exactly the objects it always did,
   so its code path is byte-identical. Proven below, not asserted.
2. **`mask_python_source`** is the Python twin of the masker every rule depends on. Same contract:
   `(skeleton, literals)`, length-preserving so offsets still map to real line numbers.
3. **`scan_python_hash` / `scan_python_random` / `scan_python_crypto`**, plus `review_python` and a
   `review_source` dispatcher. `codeintel._SOURCE_EXTS` replaces the extension gate.

### What Python moves, and what each move would have cost

| trap | the naive port | measured cost of getting it wrong |
|---|---|---|
| `//` is FLOOR DIVISION, not a comment | carry the C-family masker over | blanks the rest of every line containing an integer division, then reports the file clean |
| `#` starts a comment; docstrings span lines | reuse `mask_source` | every docstring mentioning md5 becomes a call site |
| an f-string is half literal, half CODE | blank it whole, or keep it whole | a weak call inside `f"{...}"` is missed, or the prose is read as code |
| the receiver decides the verdict | match the method name | **+113 false positives on the real suite (measured)** |
| `from numpy import random` rebinds the name | trust the name | numpy reported as CWE-330 |
| `usedforsecurity=False` | ignore the kwarg | flags the case the language explicitly carved out |

The fourth row is the whole ticket:

```python
random.getrandbits(32)                  # Mersenne Twister, CWE-330
random.SystemRandom().getrandbits(32)   # reads os.urandom, a CSPRNG
```

Same module, same method name, opposite verdict. **113 of the suite's 326 weakrand cases are the
second line.** This is the exact Python twin of Java's
`java.util.Random numGen = SecureRandom.getInstance("SHA1PRNG")`, where the declared type is the
weak class and the object is a CSPRNG.

## trustbound stays UNMAPPED, deliberately [DONE, and it stays 0]

`trustbound` is 37 Python cases (18 vulnerable / 19 clean) and it is left at an honest 0 on both
languages. Its clean twins launder the tainted value through a collection, an f-string, or a
ternary whose branch is decided by constant folding. Separating them needs real dataflow, not a
call-site match, and a conservative approximation flags the clean twins.

Mapping it would have bought 37 more cases and up to 7.1 more macro points. Those points would be
fabricated. The measured code-assisted run scores trustbound `0 TP / 18 FN / 0 FP / 19 TN` and the
report says so.

---

## Negative controls [DONE - all green, all failed before the code existed]

Written first, and re-verified against the pre-fix code afterwards: `codereview.py` and
`codeintel.py` restored from `3a62c04^` with the new test file in place, all seven controls run.

```
test_python_sha256_and_sha512_are_not_flagged                       FAILS (pre-fix)
test_python_usedforsecurity_false_is_not_flagged                    FAILS (pre-fix)
test_python_secrets_and_os_urandom_are_not_flagged                  FAILS (pre-fix)
test_python_md5_named_only_in_a_comment_or_string_is_not_flagged    FAILS (pre-fix)
test_python_random_named_only_in_a_comment_or_string_is_not_flagged FAILS (pre-fix)
test_python_a_user_defined_md5_is_not_the_stdlib_call               FAILS (pre-fix)
test_python_system_random_is_a_csprng_not_a_weak_generator          FAILS (pre-fix)
```

**Be precise about what that proves.** Every one of them fails with
`AttributeError: module 'codereview' has no attribute 'scan_python_hash'`. That is an unambiguous
fail-first, and it is the WEAKEST useful form of one: it shows the test is new, not that its
assertion discriminates. A test asserting `1 == 2` would fail the same way.

The evidence that these assertions actually catch something is the MUTATION TEST below, which puts
a plausible implementation in place and shows each control still kills it. A negative control is
only worth the mutant it survives.

| # | control | test |
|---|---|---|
| 1 | `hashlib.sha256` / `sha512` / `sha3_256` / `blake2b` / `new('sha384')` are not weak | `test_python_sha256_and_sha512_are_not_flagged` |
| 2 | `hashlib.md5(data, usedforsecurity=False)` is not a finding (and `=True` still is) | `test_python_usedforsecurity_false_is_not_flagged` |
| 3 | `secrets.*`, `os.urandom`, `uuid.uuid4` are not weak randomness | `test_python_secrets_and_os_urandom_are_not_flagged` |
| 4 | "md5" / "random" in a comment, a string, a docstring or a print is not a call site | `test_python_md5_named_only_in_a_comment_or_string_is_not_flagged`, `test_python_random_named_only_in_a_comment_or_string_is_not_flagged` |
| 5 | a user-defined `md5()` is not the stdlib call, even when hashlib IS imported and a local `def md5` shadows it | `test_python_a_user_defined_md5_is_not_the_stdlib_call` |

Two more that a naive port dies on and the brief did not ask for:

- `test_python_system_random_is_a_csprng_not_a_weak_generator` - the 113 clean twins.
- `test_python_a_foreign_random_module_is_not_the_stdlib_one` - `numpy.random.random()` and
  `from numpy import random`.

30 tests total, in `agent/tests/test_source_lane.py`.

## Mutation test [DONE - 7 mutants, 7 killed]

A guard nobody can break is a guard nobody has tested. Each mutant is the naive implementation of
one rule, and the named test is the assertion that exists to catch it. "suite findings" is what the
mutant reports over the real 1236-file Python benchmark tree, attributed by the route path the app
itself serves, never by the answer key.

| mutant | verdict | suite findings |
|---|---|---:|
| M1 masker treats `//` as a comment (the Java rule carried over) | KILLED | - |
| M2 weakrand matches the METHOD NAME, receiver ignored | KILLED | **283** (vs 170) |
| M3 `usedforsecurity=False` ignored | KILLED | - |
| M4 rules run on RAW TEXT instead of the masked skeleton | KILLED | - |
| M5 the import binding is not consulted | KILLED | - |
| M6 a local `def` does not shadow the import | KILLED | 170 |
| M7 hash rule greps for the digest NAME instead of a hashlib call site | KILLED | 170 |

M2 is the number to remember: **283 findings instead of 170**. The 113 extra are precisely the
`random.SystemRandom()` clean twins, which would have taken weakrand's FPR from 0.0% to 49.8% and
its category score from 100.0% to 50.2%. That mutant passes every positive test in the file.

M6 and M7 leave the suite at 170 because the OWASP suite contains no user-defined `md5()`. They die
only on the unit test. That is the entire argument for writing negative controls the benchmark
cannot see.

## Generality: it is a detector, not a signature [DONE]

Nothing in the rules names a case id, a file name or a fingerprint. Evidence, on a large Python
codebase with no relationship to the suite - **Apolaki's own `agent/` tree, 174 files**:

| file:line | finding | verified |
|---|---|---|
| `juiceshop_solvers.py:771` | `random.choice()` | real call site, `random.choice("bcdfg...")` |
| `guidance.py:401` | SHA-1 | real call site, `hashlib.sha1(...)` in `_gid()` |
| `owasp_bench.py:140` | `random.Random()` | real call site, the sampling RNG |
| `sarif_io.py:71` | SHA-1 | real call site, `hashlib.sha1(...)` in `_sha()` |

Four findings on 174 files, **all four true call sites, zero misidentified**. All four are identity
or sampling digests rather than security ones, which is exactly the class `usedforsecurity=False`
exists to declare; the detector cannot know the intent and correctly reports the call.

## Java did not regress [DONE - proven, not asserted]

The Java code-assisted scan was re-run through the new dispatcher over the same 2763-file tree and
compared **row for row** against the sealed artifact from the measurement lane:

```
sealed rows 975 | new rows 975
IDENTICAL row-for-row: True
differing cases: 0
files_scanned  sealed/new: 2763 / 2763
props_resolved sealed/new: 128 / 128
```

Scored:

```
category         TP    FN    FP    TN       TPR     FPR    score
crypto          130     0     0   116   100.0%   0.0% 100.0%
hash            129     0     0   107   100.0%   0.0% 100.0%
weakrand        218     0     0   275   100.0%   0.0% 100.0%
```

---

## Sealed measurement

### Blindness

1. The Python source was moved into the scanning container by
   `docker exec ... tar -cf - --exclude='expectedresults*'`, container to container. The key never
   touched the host and never entered the scanner: `find /src -name 'expectedresults*'` returned
   **0**, against 1236 `.py` files transferred.
2. Every artifact was sha256-sealed on the host BEFORE any key was consulted. Seal time
   2026-08-11T21:10:34Z.
3. Scoring ran in `apolaki-scorer`, started `--network none`. Its hashes were re-checked inside
   that container and match the host seals exactly.
4. The union rule for the hybrid artifact was stated and applied in the SCANNING container, with no
   key present: keep a code-assisted row when the DAST lane measured that same case, or when the
   DAST lane never sampled that category at all. Nothing is selected on outcome, only on which lane
   looked.

| artifact (`docs/benchmarks/`) | rows | sha256 |
|---|---:|---|
| `benchmarkpython_v01_CODEASSISTED_20260811.json` | 1230 | `95765ac789ea20cef27c4086993f79eec4c3947da6cf161fd5db3c3c319a58fb` |
| `benchmarkpython_v01_CODEASSISTED_MATCHED_20260811.json` | 594 | `634e8270f0c80d7528dc29af44730da355dd320c46908100311911b8342c101b` |
| `benchmarkpython_v01_DAST_20260811.jsonl` (unchanged, measurement lane) | 406 | `23dd777bf809616e1e8a53d8e565a7592895981b1e1407ac98b36e941953c03f` |

### Code-assisted lane ALONE, FULL suite (all 1230 cases, no sampling)

```
category         TP    FN    FP    TN       TPR     FPR    score
cmdi              0    13     0     7     0.0%   0.0%   0.0%
codeinj           0    20     0    33     0.0%   0.0%   0.0%
deserialization   0    18     0    36     0.0%   0.0%   0.0%
hash             71     0     0    80   100.0%   0.0% 100.0%
ldapi             0    16     0    13     0.0%   0.0%   0.0%
pathtraver        0    65     0   103     0.0%   0.0%   0.0%
redirect          0    13     0    21     0.0%   0.0%   0.0%
securecookie      0    24     0    15     0.0%   0.0%   0.0%
sqli              0     5     0    11     0.0%   0.0%   0.0%
trustbound        0    18     0    19     0.0%   0.0%   0.0%
weakrand         99     0     0   227   100.0%   0.0% 100.0%
xpathi            0    51     0   135     0.0%   0.0%   0.0%
xss               0    31     0    58     0.0%   0.0%   0.0%
xxe               0     8     0    20     0.0%   0.0%   0.0%
OVERALL         170   282     0   778    37.6%   0.0%  37.6%
official macro (14 categories): 14.3%   product macro: 14.3%
```

**hash and weakrand are both 100.0% TPR at 0.0% FPR on their entire populations** (151 and 326
cases), matching the Java result exactly. **Zero false positives in any category, under both
conventions.** The 11 zero rows are honest: this lane has no rule for injection classes, which is
what the DAST lane is for.

### Python v0.1, before and after

Per category, official convention. The DAST column is the sealed baseline, untouched by this work.

| category | BEFORE (DAST only) | AFTER (hybrid) | delta |
|---|---:|---:|---:|
| cmdi | 76.9% | 76.9% | - |
| codeinj | 0.0% | 0.0% | - |
| deserialization | 0.0% | 0.0% | - |
| **hash** | **0.0%** (151 cases, no lane could see them) | **100.0%** | **+100.0** |
| ldapi | 0.0% | 0.0% | - |
| pathtraver | 55.6% | 55.6% | - |
| redirect | 0.0% | 0.0% | - |
| securecookie | 100.0% | 100.0% | - |
| sqli | 40.0% | 40.0% | - |
| trustbound | 0.0% (unmeasured) | 0.0% (measured, unmapped by design) | - |
| **weakrand** | **0.0%** | **100.0%** | **+100.0** |
| xpathi | 37.5% | 37.5% | - |
| xss | 33.3% | 33.3% | - |
| xxe | 0.0% | 0.0% | - |
| **MACRO (14 cats)** | **24.5%** | **38.8%** | **+14.3** |

FPR is 0.0% on every category, before and after, under both conventions. `cross_family_fp = 0`:
the Python detectors fired 170 times across the whole 1236-file tree and every single one landed on
a case of its own category. Measured before the key was consulted, by attributing each finding to
the route path the app itself serves.

### Denominator notes, so nobody has to guess

- The AFTER run scores 594 cases: the DAST lane's 406-case sample, plus the full `hash` (151) and
  `trustbound` (37) populations, which the DAST lane never sampled at all because neither has a
  DAST engine mapped. Per-category denominators differ; that is what a macro-average is for, and
  the official suite already has categories ranging from 37 to 326 cases.
- The `weakrand` component is 100.0% on the 40 sampled cases AND 100.0% on all 326. The two agree,
  so the sample size is not carrying the result.
- The code-assisted-alone figure (14.3%) is the number to quote if someone asks what this lane is
  worth on its own. It is not a tool score and it is not comparable to anything published.

---

## What this lane does NOT claim

- It is not DAST. Every finding carries `lane: code-assisted`, `provenance: source-derived`,
  `analysis: static-call-site`, and the report prints a banner above the table.
- It did not improve any injection category. Those eleven zeros in the code-assisted-alone table
  are real.
- `trustbound` is still 0 and will stay 0 until somebody ships dataflow.
- The Python suite's vulnerable fraction in these two categories is lower than a reader might
  assume (71 of 151 hash, 99 of 326 weakrand). 100% TPR at 0% FPR means every one of them was
  called correctly, not that the categories are easy.

## Regression

Full suite in a clean container off the agent image, current working tree:

```
BEFORE (this tree at HEAD): 1913 passed,  9 skipped, 1 xfailed, 0 failed
AFTER  (with this change) : 1943 passed,  9 skipped, 1 xfailed, 0 failed
```

+30 is exactly the 30 new tests. `tests/test_dom_audit_concurrency.py` is excluded from both runs:
it is uncommitted and known-broken by its own author.

## For the Coordinator

Numbers to fold into the ledger, with the labels attached:

- Python v0.1 DAST-only official macro: **24.5%** (unchanged; this lane did not touch the DAST lane).
- Python v0.1 HYBRID (DAST + code-assisted) official and product macro: **38.8%**.
- Python v0.1 code-assisted-alone official macro: **14.3%**, hash 100.0%, weakrand 100.0%, both at
  0.0% FPR on full populations.
- Java v1.2 code-assisted: **unchanged**, row-for-row identical to the sealed artifact.

Files owned and changed by this lane: `agent/codereview.py`, `agent/codeintel.py`,
`agent/tests/test_source_lane.py`, `docs/benchmarks/benchmarkpython_v01_CODEASSISTED*.json`,
this file. Nothing else was touched. `agent/owasp_bench.py` was CALLED, never modified.
