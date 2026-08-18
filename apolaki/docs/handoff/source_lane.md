# Source lane hand-off -- Q-041, Q-042, and the audit that followed

Lane: source-lane (Builder). Files owned: `agent/codereview.py`,
`agent/tests/test_source_lane_breaker.py`, `agent/tests/test_source_lane_js.py`.

Every claim below is marked MEASURED (command + real output) or UNVERIFIED.

---

## 1. Q-041 and Q-042 were ALREADY FIXED before this lane started

MEASURED. The assignment described both tickets as measured-but-unfixed, pinned by strict xfails.
That is stale. Both were fixed and committed in `9f8707a` ("Apolaki: Q-041 and Q-042 -- resolve the
binding, and judge the name by its head noun"), dated 2026-08-13. `HEAD` at the start of this lane
was `b242405`, 12 commits later.

```
git log --oneline --all | grep 9f8707a
9f8707a Apolaki: Q-041 and Q-042 -- resolve the binding, and judge the name by its head noun (#123)
```

MEASURED. No xfail marker for either ticket survives:

```
grep -n "xfail" agent/tests/test_source_lane_breaker.py agent/tests/test_source_lane_js.py
```

returns only prose references in docstrings -- no `@pytest.mark.xfail` decorator. The markers were
retired by INVERSION, which is the pattern the assignment asked for: the historical measurement is
kept in the module docstring, the assertions are the Breaker's originals, and negative controls were
added alongside.

MEASURED, targeted suite on the committed tree, before any change of mine:

```
docker run --rm --network apolaki_default -v ".../agent:/app" -w /app apolaki-agent \
  python -m pytest tests/test_source_lane_breaker.py tests/test_source_lane_js.py \
  tests/test_source_lane.py -p no:cacheprovider -q
118 passed
```

So there was nothing to fix. What was missing was PROOF the fix is load-bearing rather than
coincidentally green. That is section 2.

### Stale queue rows -- patch wanted, file not owned

`docs/QUEUE.md` is not in this lane's write set. Two rows are stale and should be closed:

* line 1152 `### Q-041 ... **HIGH** ... ready` -> `done 9f8707a`
* line 1160 `### Q-042 ... **HIGH** ... ready` -> `done 9f8707a`

---

## 2. Mutation testing -- 5 mutants, 5 killed, every mutant verified as APPLIED

The assignment warned that a Python-based mutation silently no-opped on this workstation and
reported the same green as a passing test. Guard used: `mutate.py` requires the target text to occur
**exactly once**, prints `APPLY-FAILED` and exits non-zero otherwise, and the runner then greps the
mutated file and prints the hit before running pytest. Every run below printed both `APPLIED` and a
grep line, so no mutant was a no-op.

Mutants were applied to a **throwaway copy** of the tree in a scratch directory, mounted into an own
`--rm` container. The committed tree was never mutated.

| # | mutant | what it restores | result |
|---|--------|------------------|--------|
| M1 | head-noun check -> substring containment | the Q-042 defect exactly | **killed**, 4 tests |
| M2 | drop the paren-depth check | `f(token=x)` reads as an assignment | **killed**, 1 test |
| M3 | `_py_module_aliases` returns no resolved names | the Q-041 defect exactly | **killed**, 2 tests |
| M4 | resolve EVERY alias regardless of binding | the credulous over-fix | **killed**, 1 test |
| M5 | head noun = first segment, not last | inverts the head-noun rule | **killed**, 5 tests |

MEASURED, the kills:

* M1 -> `test_a_timestamp_named_after_a_session_is_not_weak_randomness`,
  `test_a_token_expiry_timestamp_is_not_weak_randomness`,
  `test_the_java_clock_rule_got_the_same_fix`,
  `test_clock_derived_secrets_use_the_same_head_noun_rule_as_q042`
* M2 -> `test_a_keyword_argument_named_token_is_not_an_assignment`
* M3 -> `test_an_aliased_random_module_import_is_still_the_stdlib_generator`,
  `test_an_aliased_hashlib_import_is_still_the_stdlib_digest`
* M4 -> `test_an_alias_does_not_resurrect_a_foreign_module`
* M5 -> the four M1 tests plus `test_the_head_noun_decides_not_the_substring`

**The two error classes are pinned in opposite directions, which was the point of the ticket.**
M3 is the under-match (false negative) and M4 is the over-match (false positive), and both die. So
the fix did not trade one error class for the other: widening the receiver to follow an alias did
not widen the verdict. M1 kills across all three dialects (Python, Java, JS), which confirms the
Q-042 fix is applied at ONE chokepoint rather than three times by hand -- see the A2 count below.

---

## 3. ANTI-IDLE audit -- the same two shapes elsewhere in `codereview.py`

Scope MEASURED: `agent/codereview.py`, 3799 lines, **99 `re.compile` sites**. Two shapes hunted:

* **shape A (Q-042 family)** -- a matcher that keys on a SUBSTRING of a name, not a token.
* **shape B (Q-041 family)** -- a construct that defeats the matcher SILENTLY (false negative).

**Every probe below is paired with a positive control that FIRED**, so each zero is a measured
absence and not an apparatus that was not looking.

### Shape B -- false negatives found: 4 (one FIXED here, three reported)

| id | construct | positive control | probe | state |
|----|-----------|------------------|-------|-------|
| B1 | Java `import static java.lang.Math.random` -> bare `random()` | 1 | **0** | open |
| B1 | Java `import static java.lang.System.currentTimeMillis` | 1 | **0** | open |
| B4 | Python `from random import *` then bare `getrandbits(32)` | 1 | **0** | open |
| B5 | Python `importlib.import_module('random')` | n/a | **0** | open, low value |
| B6 | JS ESM `import { createHash as mk } from 'crypto'` | 1 | **0** | **FIXED, see 4** |

B1 root cause: **there is no Java import resolver at all.** `grep -n "import static\|_JAVA_IMPORT\|
def _java_imports" agent/codereview.py` returns nothing, while Python has `_py_imports` /
`_py_module_aliases` and JS has `_js_bindings`. Java has no `import X as Y`, but `import static` is
its alias-equivalent and it defeats every rule that requires a qualified receiver. Java is the
dialect carrying the OWASP Benchmark score, so this is the highest-value remaining item in the lane.

B2 checked and CLEAN: fully-qualified inline `new java.util.Random()` is caught (1 hit).
B3 checked and CLEAN: single-type import then `MessageDigest.getInstance("MD5")` is caught (1 hit).

B4 is deliberate -- `_py_imports` skips the `*` specifier. It is a real blind spot but a star import
gives no list of names to bind, so closing it means treating the module as wholly imported. Cheap,
and worth doing with a control that `from numpy import *` does not resurrect numpy.

### Shape A -- false positives found: 1 site, 4 of 5 alternatives unguarded

`agent/codereview.py:80`, the DOM-source rule inside `scan_sinks`:

```
(?:hash|search|location|referrer|\bname\b)
```

Only `name` carries a word boundary. The other four match on containment, which is the Q-042 defect
verbatim -- and the inconsistency inside a single alternation is itself the evidence it was
unintentional rather than a deliberate widening.

MEASURED, `scan_sinks`, filtering for `location <- URL source`:

| input | hits | verdict |
|-------|------|---------|
| `location.href = location.hash` | 1 | positive control, correct |
| `location = document.referrer` | 1 | positive control, correct |
| `location.href = searchless` | 1 | **false positive** (`search`) |
| `location.href = hashless` | 1 | **false positive** (`hash`) |
| `location.href = noreferrerLink` | 1 | **false positive** (`referrer`) |
| `location.href = referrers[0]` | 1 | **false positive** (`referrer`) |
| `location.href = relocationPath` | 1 | **false positive** (`location`) |
| `location.href = surname` | 0 | the GUARDED alternative, correct |
| `location.href = '/home'` | 0 | true negative |

`noreferrerLink` matters: `rel="noreferrer"` is ordinary in real markup and script.

**Patch NOT applied, deliberately.** `scan_sinks` feeds the DOM-XSS surface, not this lane's
weak-crypto rules, and narrowing it changes a finding count another lane measures. The one-line fix
is to give the four bare alternatives the same boundary `name` already has:

```
(?:\bhash\b|\bsearch\b|\blocation\b|\breferrer\b|\bname\b)
```

Whoever takes it must re-measure the DOM category before and after, because unlike Q-041/Q-042 this
one can move a number.

### A2 -- the Q-042 chokepoint is complete (no gap)

MEASURED by introspecting the module source: **3 `_clock_token_hits(skel, ...)` call sites for 3
`CLOCK_TOKEN` rules defined** (Java `_CLOCK_TOKEN`, Python `_PY_CLOCK_TOKEN`, JS `_JS_CLOCK_TOKEN`).
The three containment regexes `\w*(?:token|session|...)\w*` still exist, but they are now a
PREFILTER only -- the verdict is made by `_identifier_head` + `_paren_depth` inside the shared
`_clock_token_hits`. That is why M1 and M5 each killed tests in all three dialects at once.

---

## 4. FIXED this lane: B6, Q-041 surviving in the JS dialect

`agent/codereview.py`, `_js_destructured`.

Found by auditing the JS test file's own claim. Its module docstring says the aliased-module control
is "Q-041's lesson applied as a PRECONDITION" -- but it was only ever exercised on the CommonJS
spellings. Enumerating all eight import spellings against the committed tree:

MEASURED, `scan_js_hash`, before the fix:

| spelling | hits |
|----------|------|
| `const c = require('crypto')` | 1 |
| `const { createHash } = require('crypto')` | 1 |
| `const { createHash: mk } = require('crypto')` | 1 |
| `import * as c from 'crypto'` | 1 |
| `import c from 'crypto'` | 1 |
| `import { createHash } from 'crypto'` | 1 |
| `import { createHash as mk } from 'crypto'` | **0** |
| `import c, { createHash as mk } from 'crypto'` | **0** |

Seven of eight resolved; exactly the ESM RENAME did not. Root cause: `_js_destructured` parsed only
object destructuring's colon (`{ createHash: mk }`), while an ESM named import renames with the
keyword `as`. **Two of that function's three call sites feed it the ESM spelling.** Same shape as
Q-041: the specifier IS parsed, the rename IS computed, and the binding is thrown away -- so an
aliased dangerous symbol read clean. False negative.

Fix: one shared splitter, `_JS_RENAME = re.compile(r"\s*:\s*|\s+as\s+")`.

`as` is matched as a TOKEN, never a substring. `{ hasOwn }` contains the letters "as"; requiring
whitespace on both sides is what makes the split safe, because an identifier cannot contain
whitespace. Fixing an under-match by committing an over-match is not a fix -- that is precisely the
Q-041/Q-042 pair pulling in opposite directions.

### Tests added -- `agent/tests/test_source_lane_js.py`, 8 new

Positive: `test_an_esm_renamed_import_resolves_to_the_symbol_it_binds`,
`test_the_default_plus_named_rename_spelling_resolves_too`,
`test_a_weak_generator_reached_through_an_esm_rename_is_reported`.

Negative controls (mandatory, and the point):

* `test_a_csprng_renamed_to_the_name_of_a_weak_api_is_not_flagged` -- `randomBytes as createHash`
  binds a SAFE symbol to a dangerous-looking LOCAL name. The rule must read the imported symbol,
  not the local name. MEASURED 0.
* `test_a_rename_does_not_resurrect_a_foreign_module` -- `{ createHash as mk } from './myutil'`
  is not Node crypto. MEASURED 0.
* `test_as_is_a_token_not_a_substring` -- `hasOwn` must not be shredded. MEASURED
  `_js_destructured("hasOwn") == [("hasOwn", "hasOwn")]`.
* `test_a_strong_digest_through_a_rename_is_still_strong` -- sha256 through the rename, MEASURED 0.
* `test_the_commonjs_spellings_did_not_regress` -- the four that already worked, through the
  function that changed.

### Mutation of the new fix -- 2 mutants, 2 killed, both verified APPLIED

| # | mutant | direction | result |
|---|--------|-----------|--------|
| M6 | `_JS_RENAME` -> colon only (the pre-fix state) | under-match | **killed**, 4 tests |
| M7 | `_JS_RENAME` -> `as` as a SUBSTRING | over-match | **killed**, 6 tests |

M6 is the "did the test fail before the fix" control: the three new positive tests plus
`test_as_is_a_token_not_a_substring` all fail with the colon-only splitter.

M7 is the over-fix control, and it kills more than the new tests -- it also breaks the
PRE-EXISTING `test_a_destructured_require_must_resolve`, `test_esm_imports_resolve_the_same_way`
and `test_the_commonjs_spellings_did_not_regress`. So the existing suite already refuses the
substring spelling of this fix.

MEASURED after the fix, targeted suite: **126 passed** (118 before, +8 new).
