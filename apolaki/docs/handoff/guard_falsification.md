# Guard falsification lane — I-5 and I-9 (Breaker)

Baseline `6c7ed00` (3512 passed / 11 skipped / 12 xfailed / 0 failed). Scope: prove the two
remaining Codex release guards CANNOT fail, the way `test_runtime_control_invariant.py` (I-4) was
shown unfalsifiable at `f4bbd16`.

    agent/tests/test_silent_failure_invariant.py     I-5   8 tests
    agent/tests/test_cap_ordering_invariant.py       I-9   8 tests

## Verdict

| Guard | Defect it exists to catch | Verdict |
|---|---|---|
| **I-5** | a load-bearing failure swallowed into a clean result | **CANNOT FAIL** for the shape that matters — see M5-HUNT |
| **I-9** | a cap that cuts in discovery order instead of value order | **CANNOT FAIL** for a contracted cap — see M9-HUNT |

Both guards *can* fire — each killed its positive control, naming the exact planted site. Neither
fires on the same defect expressed one token differently. Both are pinned inventories wearing the
grammar of invariants, the same failure mode as I-4.

## Method

Every run is a throwaway container over an immutable copy of the agent tree. `apolaki-agent-1` was
never touched, nothing was `docker cp`-ed in, no image was built.

```
MSYS_NO_PATHCONV=1 docker run --rm --network apolaki_default \
  -v "<scratch>/<snapshot>/agent:/app" -w /app apolaki-agent \
  python -m pytest tests/ -p no:cacheprovider -rfE
```

Each mutant gets its **own** copy; a copy is never edited while a container has it mounted. Every
mutant is applied as an exactly-once byte replacement (CRLF preserved), then subjected to three
landing checks **before any test is run**, because a mutant that did not land is not a surviving
mutant:

1. `ast.parse` on the mutated file — no SyntaxError / IndentationError.
2. `difflib` against the pristine copy — the diff is the mutation and nothing else.
3. **the guard's own artifact count is re-measured**, and for the two hunt mutants, the change is
   confirmed *through the imported module* (`inspect.getsource`) and then *behaviourally*, by
   executing the mutated path.

`grep` counts are labelled LINE counts; everything else is an AST **node** or **owner** count.

### Pristine control

```
tests/test_silent_failure_invariant.py tests/test_cap_ordering_invariant.py  ->  16 passed, EXIT=0
```

I-5 census at `6c7ed00`, re-measured here (AST nodes over 178 production modules):

```
MODULES 178 | ALL_HANDLERS 918 | optional 388 | control-plane 77 | load-bearing 0
```

Both ratchet ceilings sit at **exactly** their asserted limit — `optional <= 388` with 388,
`control-plane <= 77` with 77. **Headroom is zero**, which means the prior lane's claim that "any
*added* silent handler trips something" is correct *as far as it goes*: any net-new handler the
predicate can SEE trips a ceiling. Everything below turns on what the predicate cannot see.

## M5-POS — I-5 fires, and names the site (positive control)

`tools.py:3854` `_traversal_differential`, the four-request traversal oracle:

```
-            except Exception as exc:
-                self._swallow(exc, "web_probes.traversal_differential", target)
-                return out
+            except Exception:
+                return None
```

Landed: `web_probes.traversal_differential` absent from the imported module; census moved
`load-bearing 0 -> 1`.

```
FAILED tests/test_silent_failure_invariant.py::test_partition_is_non_vacuous_and_matches_the_measured_rebased_tree
E   AssertionError: ['tools.py:3855:_traversal_differential']
E   assert 1 == 0
```

The apparatus works and the guard is not vacuous.

## M5-HUNT — the same deletion, one token different, is invisible

Same site, same deleted recorder. The only difference from M5-POS is `out` instead of `None`:

```
-            except Exception as exc:
-                self._swallow(exc, "web_probes.traversal_differential", target)
+            except Exception:
                 return out
```

Landing check 3 (census): `optional 388 | control-plane 77 | load-bearing 0` — **byte-identical to
pristine**. Landing check 2 (imported module): the recorder is gone; the string
`web_probes.traversal_differential` no longer occurs anywhere in `tools.py`.

Behavioural proof — `_traversal_differential` driven with a `send` that raises:

```
pristine   returned []   swallow ledger: ['web_probes.traversal_differential']   -> RECORDED
M5-HUNT    returned []   swallow ledger: []                                      -> INVISIBLE
```

A crashed traversal oracle is now byte-indistinguishable from a completed traversal scan that found
nothing. No log, no re-raise, no status write, no `DEGRADED` marker. That is precisely the defect
I-5 exists to catch.

```
tests/test_silent_failure_invariant.py tests/test_cap_ordering_invariant.py  ->  16 passed, EXIT=0
```

### Why it is invisible — the predicate is asymmetric

`_swallowed()` classifies a handler by its body. The Assign branch calls `_constant()`; the Return
branch does not:

```python
if isinstance(stmt, ast.Return):
    return stmt.value is None or (
        isinstance(stmt.value, ast.Constant) and stmt.value.value in (None, False))
if isinstance(stmt, (ast.Assign, ast.AnnAssign)):
    return stmt.value is not None and _constant(stmt.value)   # <- List/Dict/Tuple/Set accepted here
```

MEASURED on hand-built handlers, `True` = the census sees it:

```
pass True | return None True | return False True | return 0 True
return [] False | return {} False | return () False | return "" False | return {'ok': False} False
out = [] True | out = {} True
```

`out = []` is swallowed; `return []` is not. `return 0` is caught only by the accident that
`0 == False` in Python. And a handler ending in a bare `return <name>` — M5-HUNT — is not
classified at all, so it is counted in **no** category and constrained by **no** ceiling.

### The consequence at HEAD, unmutated

**MEASURED, `6c7ed00`, no mutation applied:** 89 production handlers discard an exception into a
literal fallback that `_swallowed()` cannot see. Partitioned by the guard's own classifier:

```
optional 61 | control-plane 13 | load-bearing 15
```

So `assert counts["load-bearing"] == 0` does not mean there are no load-bearing silent handlers. It
means there are none *of the shape the Return branch happens to match*. Under the definition the
guard's own docstring states — "assign literal fallback values" — the honest number at HEAD is
**15**, not 0. Named:

```
  bie.py:1401             session_fingerprint        return {}                     <- c.get
  dns_recon.py:130        doh                        return []                     <- httpx.AsyncClient / c.get
  enip_audit_tool.py:84   _list_identity_tcp         return b''                    <- socket.create_connection
  tools.py:3409/3425      _socket_service_probe      return {'confirmed': False..}  <- asyncio.open_connection
  tools.py:4773           _discover_params           return []                     <- self._http / page.get
  tools.py:5472           _form_xss_browser_confirm  return (False, '')            <- rate_limited_goto
  tools.py:2457/3608/6586/8416   _fetch/_send/send/q return (0, '')                <- self._http_send / c.get
  tools.py:2874           _get                       return {'status': 0, ...}     <- self._http_send
  tools.py:5678/7608      _send/worker               return {'status': 0, ...}     <- c.get / c.request
  tools.py:7582           read_state                 return {}                     <- c.get
```

**Honest split, because not all 15 are defects.** `return (0, '')` and `return {'status': 0, ...}`
are *typed degraded results* — a caller can test `status == 0`, which is exactly the escape the
`_OPTIONAL_LOAD_OWNERS` table grants by hand for the Assign branch. The ones that are genuinely
indistinguishable from a clean result are `dns_recon.doh -> []` ("no DNS records"),
`tools._discover_params -> []` ("no parameters, so nothing downstream to probe"),
`bie.session_fingerprint -> {}`, `tools.read_state -> {}`, `enip._list_identity_tcp -> b''` and
`tools._form_xss_browser_confirm -> (False, '')` ("XSS not confirmed"). The point is not that all 15
are bugs. The point is that **the guard has no opinion on any of them**, and cannot acquire one,
because they are outside its predicate.

### And the deletion itself is unratcheted

**MEASURED (AST nodes / owners, 178 production modules):** 160 `_swallow(...)` call nodes across 80
distinct `(module, function)` owners, in 2 modules. Nothing in the suite pins that set. M5-HUNT
deletes one of the 160 and the tree stays green — and because the deletion also removes the handler
from the census, the ceilings that would catch an *addition* are silent on a *removal*.

## M9-POS — I-9 fires, and names the tuple (positive control)

`planner.py:743`, tightening a contracted cap:

```
-        + [_ex(e) for e in param_eps[:8]]))[:12]
+        + [_ex(e) for e in param_eps[:6]]))[:12]
```

```
FAILED tests/test_cap_ordering_invariant.py::test_raw_production_work_caps_have_an_explicit_ordering_contract
E   AssertionError: raw first-N work caps without the measured contract: [('planner.py', 'next_batch', 'param_eps', '6')]
```

The static inventory is a genuine two-way ratchet over `Name[:upper]` cuts. It fires.

## M9-HUNT — a contracted cap made to cut in discovery order, invisibly

Contract entry, verbatim from the guard:

```python
("planner.py", "next_batch", "dom_pages", "CAP_DOM"):
    "operator-ranked roots precede globally ranked parameter endpoints",
```

The mutant swaps the two comprehensions that feed `dom_pages`. One line, entirely plausible:

```
-    for u in [_b(h) for h in host_bases] + [_ex(e) for e in param_eps]:
+    for u in [_ex(e) for e in param_eps] + [_b(h) for h in host_bases]:
```

The cut `dom_pages[:CAP_DOM]` is **not touched**. Landing check 3: the inventory is 20 tuples before
and 20 after, `param_eps` entries `3` and `8` unchanged — byte-identical. Landing check 2: the
imported `planner.next_batch` source carries the inverted feed order.

Behavioural proof — one operator root `t.test` plus 25 parameterized endpoints, `CAP_DOM = 6`:

```
pristine  run_dom_audit targets: https://t.test, /shop/item00..04     operator root REACHES the audit
M9-HUNT   run_dom_audit targets: /shop/item00..05                     operator root DROPPED by the cap
```

The operator's authorized host root — the one page the DOM audit most needs — is silently evicted
from the headless audit by six catalogue pages, and the written contract that forbids exactly this
is still sitting in the test file, still asserted, still green.

```
tests/test_silent_failure_invariant.py tests/test_cap_ordering_invariant.py  ->  16 passed, EXIT=0
```

### Why it is invisible

`test_raw_production_work_caps_have_an_explicit_ordering_contract` asserts two things:
`measured == set(contracted)`, and that every reason string is non-empty. **A reason string is not a
test.** The 20 contracts are prose. Nothing executes the ordering claim any of them makes, so any
edit that leaves the `(module, function, name, upper)` tuple intact — reordering a feed, dropping a
sort key, inserting instead of appending — passes.

The five execution tests in the file cover paths that are **disjoint from the contract table**:
`_rank_endpoints`/`CAP_ENDPOINTS`, `_ma_views`/`CAP_REST`, `_surface_crawl`'s page budget,
`sweep_targets`' shape spread and `read_views`. Not one of those cuts appears in the 20 contracted
tuples — they are all slices over a `Call`, which is exactly why the static inventory cannot see
them. The two halves of I-9 do not overlap; each covers what the other misses, and neither covers
`dom_pages`.

The sharper, measured statement, and the one M9-HUNT actually establishes: `planner.py:720` **is
executed** by these tests — `_drain` calls `next_batch`, which is what produces the `run_dom_audit`
steps the behavioural probe printed. So the line is not merely uncovered. It is *executed, mutated,
and still green*: execution without an ordering assertion is not coverage.

## Cross-controls

Each hunt mutant is also a negative control for the other: `beh_m5` leaves the DOM-audit ordering
correct and `beh_m9` leaves the swallow ledger recording, so neither behavioural result is an
artifact of the harness.

## Full-suite runs — NOT ESTABLISHED, and why that is being said out loud

Three concurrent containers (pristine / M5-HUNT / M9-HUNT), one snapshot each, identical command.
**All three were killed at ~10–18% with exit 137 — SIGKILL, the container OOM killer.** Three
full-suite containers plus a probe container did not fit in the Docker VM's memory.

```
EXIT=137 snap | EXIT=137 mut_m5_hunt | EXIT=137 mut_m9_hunt
```

**Exit 137 is not a pass and it is not a fail. It is not a result at all**, and it is recorded here
as UNVERIFIED rather than quietly re-run until convenient. The prior lane's two-container run was
within budget; three is not. Anyone re-running this must run them **sequentially**.

This does not weaken the verdict. The claim "these guards cannot fail" is a claim about
`test_silent_failure_invariant.py` and `test_cap_ordering_invariant.py`, and both of those ran to
completion, green, on both hunt mutants (16 passed, EXIT=0, twice). What is NOT established is the
broader statement the I-4 write-up was able to make — that *no test anywhere* notices. For M5-HUNT
and M9-HUNT that remains **UNVERIFIED**.

## Repairs — both shipped, both verified against the mutant that beat the original

Both follow the I-4 shape and deliberately do **not** assert the strong claim, because in both cases
the strong claim is false: 15 load-bearing handlers already discard silently, and 19 of 20 cap
contracts have no executable witness. Each repair is a measured inventory that ratchets in the
**deletion direction only** — adding is never blocked, removing is red, and the message names the
owner.

### I-5 — a deletion ratchet over the degradation recorders

`_SWALLOW_RECORDERS`, measured by AST (not transcribed by hand — generated from the tree and pasted):
**160 nodes across 80 `(module, function)` owners**, counted per owner so that thinning a function
from 3 recorders to 2 is caught, not just erasing the last one. Plus:

* `_literal_return_swallow`, a predicate for the shape `_swallowed` misses, kept **strictly
  disjoint** from it, with the 89 sites capped as ceilings (`optional <= 61`, `control-plane <= 13`,
  `load-bearing <= 15`, the 15 named on failure). Ceilings, not equalities, so *fixing* one of the
  15 never turns the file red and adding a 90th does.
* `test_the_shipped_census_predicate_is_asymmetric_between_assign_and_return` pins the hole itself
  (`out = []` seen, `return []` not, `return out` not) so it cannot silently re-open.
* A synthetic negative control for the ratchet arithmetic — partial deletion caught, total deletion
  caught, additions ignored.

**Two defects were found in this repair by running it, not by reading it**, and both are recorded
because they are the same class of error the lane exists to catch:

1. `_literal_return_swallow` initially double-counted `return None` / `return False`, which satisfy
   *both* predicates. Census came out 134 rather than the measured 89 and the ceiling failed **on a
   pristine tree**. Fixed by making the predicate disjoint.
2. The ratchet's negative control was built from the *live* census, so it went red on M5-HUNT — the
   very mutant it exists to describe. A control that fails whenever the thing it controls for
   happens is not a control. Rebuilt synthetically.

### I-9 — one contract promoted from prose to execution

`test_dom_audit_cap_spends_its_slots_on_the_operator_root_first` drives `planner.next_batch` with a
saturating fixture and asserts the operator root survives `CAP_DOM`. It has two anti-vacuity guards
of its own (the fixture must produce DOM steps at all, and must actually saturate the cut).

`_WITNESSED_CONTRACTS` records which contracts have an executable witness and asserts that each
named witness test exists and still guards a cut that exists in production. **Honest boundary,
stated rather than papered over: 20 contracted caps, 1 executed, 19 still prose-only.** I-9 should
be recorded in the matrix as *"cap shapes are ratcheted; one cap's ordering is tested"*, not as
*"caps preserve highest-value ordering"*.

### Verification of the repairs

Sequential runs, one container each, same command:

| snapshot | result |
|---|---|
| pristine `6c7ed00` + repairs | **23 passed, EXIT=0** |
| M5-HUNT + repairs | **1 failed**, `test_swallow_recorders_are_never_silently_deleted`: `{('tools.py', '_traversal_differential'): (1, 0)}` |
| M9-HUNT + repairs | **1 failed**, `test_dom_audit_cap_spends_its_slots_on_the_operator_root_first`: names the evicted root and the six endpoints that displaced it |

Each mutant is killed by exactly one assertion, the intended one, and the message names the owner.

### Ship gate

Full suite on the pristine tree **with the repairs applied**, single container (the OOM above is why
this one ran alone):

```
3519 passed, 11 skipped, 12 xfailed, 9 warnings in 884.39s (0:14:44)   EXIT=0
```

| run | passed | skipped | xfailed | failed | exit |
|---|---|---|---|---|---|
| `6c7ed00` baseline (lease) | 3512 | 11 | 12 | 0 | — |
| `6c7ed00` + repairs | **3519** | 11 | 12 | **0** | **0** |

`3519 - 3512 = 7`, which is exactly the number of tests this lane added (5 to I-5, 2 to I-9).
Skips and xfails are unchanged. No `^FAILED` and no `^ERROR` lines in the log.

**Instrument note.** A character-frequency "dot census" was run over the log as a cross-check and
returned `FAILED=2, ERROR=5`. That is **wrong and was discarded**: it counts the letters `F`, `E` and
`s` wherever they occur, including inside the DeprecationWarning prose and test names, so it is not
an instrument for test outcomes at all. The figures quoted above come from pytest's own summary line
— which, contrary to the standing note in the lane brief, *did* survive the redirect on this run —
corroborated by the captured exit code and the absence of `^FAILED`/`^ERROR` lines. Three agreeing
signals; the fourth was a bad ruler and is recorded here so nobody re-derives it.

## What is left open

* **M5-HUNT / M9-HUNT survival against the full suite is UNVERIFIED** (OOM, above). Re-run
  sequentially to close it.
* **19 of 20 I-9 cap contracts remain prose-only.** Each is a candidate for the same treatment
  `dom_pages` just received; `_confirm_create_object_idor`'s `specs[:6]` ("explicit proven app specs
  precede target-derived speculative specs") is the next most security-relevant — changing
  `specs.append(spec)` to `specs.insert(0, spec)` at `tools.py:2649` would spend the cap on
  speculation and leave the inventory byte-identical. Not planted; UNVERIFIED.
* **The 15 named load-bearing literal-return handlers** are now capped but not fixed. Six look like
  genuine defects (`dns_recon.doh`, `tools._discover_params`, `bie.session_fingerprint`,
  `tools.read_state`, `enip._list_identity_tcp`, `tools._form_xss_browser_confirm`); the rest return
  typed degraded results and are probably fine. Production code is not writable by this lane; the
  patch would be to route each through `_swallow`.
* **This is the sixth guard in this repo that could not fail.** The pattern across I-4, I-5 and I-9
  is identical: a measured inventory of the sites someone thought of, asserted with the grammar of a
  universal. The ceilings and tuple-equalities are real ratchets for *additions* and blind to
  *deletions* and to *anything outside the predicate*. A guard should be assumed to cover its
  enumerated sites and nothing else until a mutant says otherwise.
