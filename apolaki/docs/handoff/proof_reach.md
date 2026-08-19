# proof-reach lane - Q-076

`agent/tests/test_proof_gate_reach.py` had 3 slack and named ZERO of its findings.

Owned files: `agent/tests/test_proof_gate_reach.py`, `docs/handoff/proof_reach.md`. Nothing else is
edited by this lane; product-code changes are PATCHES below.

---

## 1. Baseline, MEASURED at HEAD `e66f4ca`

`git status --porcelain agent/` is empty, so the worktree agent tree IS HEAD. Scan run in a throwaway
container against the real `agent/` mount, replicating `_raw_call_count()` exactly:

```
COUNT 11
  agent.py:3889   main.py:745    main.py:792    main.py:1078   main.py:1640   main.py:2033
  main.py:2115    main.py:2223   main.py:3434   main.py:3783   main.py:4023
```

11 raw `db.get_findings(` sites against `_KNOWN_UNGATED = 14`. **Slack 3, confirmed.**

## 2. `file:line` is the wrong key, MEASURED

The ticket says `_raw_call_count()` "has every `file:line` in hand and throws it away". It does - but
`file:line` cannot be the recorded baseline key. Ten of the eleven sites are in `main.py`; inserting
one function near the top of that file renumbers every site below it and the whole set becomes a
false `newly_raw`. That is the exact rot direction Q-075 forbids ("rot runs one way only, into
`resolved`, never into a false `newly_raw`").

So the key is the ENCLOSING SCOPE, which is stable under line drift and is also what a human needs -
the name of the consumer, not a coordinate. MEASURED, same run:

```
SITES 11   DISTINCT SCOPES 11   (no scope holds two sites)
  agent.py  3889  BBHAgent._triage
  main.py    745  get_status              main.py   792  _report_bundle
  main.py   1078  _tool_ledger            main.py  1640  asvs_coverage
  main.py   2033  blind_benchmark_run     main.py  2115  technique_plan
  main.py   2223  attack_graph_view       main.py  3434  cloud_posture_ingest
  main.py   3783  capture_finding_poc     main.py  4023  backup
```

The mapping is 1:1 today, but the baseline is recorded as a MULTISET (`key -> n`) rather than a set
anyway. With a plain set, a second raw call added inside an already-recorded scope is invisible to
`newly_raw`, which is the same blind spot in a smaller box. `file:line` is still printed in the
message - as diagnostics, not as identity.

## 3. SECOND DEFECT FOUND: `_RAW_IS_CORRECT` is a dead allowlist

MEASURED - `grep -rn "_RAW_IS_CORRECT" agent/` returns exactly two hits, both inside the same file:
its own definition, and the word appearing inside the failure-message string. **No code reads it.**

Both of its entries are also non-sites, so it does not describe the measured world:

- `"db.py"` - db.py's two raw calls (`db.py:235`, `db.py:290`) are bare-name `get_findings(mid)`
  calls, excluded STRUCTURALLY by the scanner's `if fname == "db.py" and isinstance(f, ast.Name)`
  branch. The exclusion is real; the dict entry is not what implements it.
- `"agent.py:_close_autonomy_loop"` - MEASURED, `grep -n "get_findings" agent/agent.py` returns two
  lines: 3859 `get_findings_gated` and 3889 `get_findings`. Both are in `BBHAgent._triage`.
  `_close_autonomy_loop` (agent.py:1326) holds NO `get_findings` call at all. The entry is stale.

Consequence for the failure message: it advised "if it is [raw-correct], add it to `_RAW_IS_CORRECT`
with a reason", and doing that changed **nothing** - the count is unaffected by the dict, so the only
way to make the gate pass was to raise the ceiling. The gate told the reader to do a thing that does
not work. This is the guards-that-check-declarations shape.

**Deliberately NOT fixed by making `_RAW_IS_CORRECT` an exclusion.** Excluding an entry would remove
its name from the diff, and Q-017 established that a gate may annotate a reader, never hide it. Every
site stays counted and named; `_RAW_IS_CORRECT` becomes an ANNOTATION printed beside a name, and the
message now says what actually clears the gate.

## 4. The slack decision (DoD item 4): ceiling comes DOWN, 14 -> 11

Measured, not preferred. Three independent reasons:

1. **No documented reason for slack exists.** The file's own comment says the opposite, twice:
   "Lower this as each is moved to `get_findings_gated()`" and "Lower this every time a reader is
   migrated." 14 is stale bookkeeping from the 20 -> 15 -> 14 ratchet, not a deliberate allowance.
2. **Slack 3 is the exact window that let SARIF sit raw**, which the file records in its own comment.
3. The set-diff and the ceiling are **complementary, not redundant**. The set diff catches a SWAP at
   constant count. It does not catch three silent ADDITIONS on its own if the additions are permitted
   to pass under a ceiling - so the ceiling has to be the true count for the two to agree.

The ceiling is LOWERED, never raised. With the count ratchet at the measured 11, the set ratchet and
the count ratchet fire on the same event, which is the point.

## 5. Design: two ratchets, one direction each

Mirrors `liveness.py::evaluate()` (`regressions = base - confirmed`, named, and `gained` never
fails). Here the polarity is inverted because the baseline records what is RAW:

- `newly_raw = now - base`  -> **FAILS**. A new ungated reader is the regression this gate exists for.
- `resolved  = base - now`  -> **NEVER fails**. That is another lane gating a site, i.e. green work.
  There is deliberately no staleness test on the recorded set, for the reason Q-075 gives.
- count `<=` ceiling        -> unchanged in shape, threshold lowered to the measured 11.

`len(BASELINE) <= CEILING` is asserted, which is what makes a firing alarm provably non-empty.

## Status

- [x] baseline measured (11 sites, 11 scopes) at HEAD
- [x] `_RAW_IS_CORRECT` staleness measured
- [x] set-diff implementation + message
- [x] self-read positive control
- [x] mandatory negative control (resolve one + add one at constant count)
- [x] full suite green on an isolated HEAD snapshot
- [x] anti-idle: `test_mutation_gate.py` assessed
