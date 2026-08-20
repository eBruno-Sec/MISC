# Codex Q-085 handoff

Branch: `codex/q085`

Baseline: `256ed8ef90d66416f287969ad967db3fb8ef1b82`

## Clean baseline

The source was exported with `git archive HEAD apolaki/agent` and mounted read-only-by-convention
into a throwaway `apolaki-agent` container on `apolaki_default`. The primary tree and
`apolaki-agent-1` were not used.

Command:

```text
docker run --rm --network apolaki_default \
  -v "C:\Users\voice\AppData\Local\Temp\apolaki-q085-baseline-256ed8e\apolaki\agent:/app" \
  -w /app apolaki-agent python -m pytest tests/ -p no:cacheprovider
```

Result:

```text
3289 passed, 11 skipped, 12 xfailed, 9 warnings in 676.69s (0:11:16)
```

This is 16 passes above the brief's expected 3273. The worktree HEAD and archived source both resolve
to the exact requested SHA; skipped and xfailed counts match. The expected pass count was stale, so
the measured green denominator above is the lane baseline.

## Part 2 independent verification

### Q-050 claim: CONFIRMED

An AST census over `agent.py` and `planner.py` found zero exact code-string references for all six
claimed engines. Positive controls were nonzero:

```text
exact word refs={'run_external_surface': {'agent.py': 0, 'planner.py': 0},
 'run_hash_crack': {'agent.py': 0, 'planner.py': 0},
 'run_hash_id': {'agent.py': 0, 'planner.py': 0},
 'run_mass_assign': {'agent.py': 0, 'planner.py': 0},
 'run_nosqlmap': {'agent.py': 0, 'planner.py': 0},
 'run_sqli': {'agent.py': 3, 'planner.py': 1},
 'run_ws_hijack': {'agent.py': 0, 'planner.py': 0},
 'run_xss': {'agent.py': 4, 'planner.py': 1}}
dynamic scheduler arguments:
agent.py:4176 tc.function.name
agent.py:4234 call.name
agent.py:3626 step["tool"]
agent.py:3853 tool
agent.py:3927 tool
planner.py:447 tool
```

The zero argument is sound after tracing every dynamic site:

* `tc.function.name` and `call.name` are the OpenAI/Anthropic model-selected paths, not deterministic
  scheduling.
* `step["tool"]` comes only from `planner.next_batch()` or the two literal graph-action maps in
  `agent.py`.
* The two `tool` loop variables in `agent.py` resolve to `_SWEEP_HTTP_ENGINES`,
  `_SWEEP_BROWSER_ENGINES`, or the literal `_htools` list.
* The `planner.py` loop variable resolves to the literal phase-A recon tuple.
* No first argument at a deterministic dispatch site is assembled with `getattr`, an f-string, string
  concatenation, or a dict imported from elsewhere.

The six engines remain model-selectable through `CLAUDE_TOOLS`; the confirmed claim is specifically
that deterministic scheduling cannot select them.

The named-volume positive control also matched the brief:

```text
missions=154
findings=1773
tool_calls=29945
logs=66395
```

### Q-084 claim: CONFIRMED

Command shape: import `wstg_catalog` and `engine_descriptor`, inspect `coverage()`'s signature, then
resolve registered engine tokens from every `FULL` and `PARTIAL` prose value.

```text
coverage_signature=() -> 'dict'
catalog/full/partial=(109, 60, 25)
FULL rows with registered engine token=50/60
FULL rows without registered engine token=10 rows
PARTIAL rows with registered engine token=12/25
PARTIAL rows without registered engine token=13 rows
coverage_tally={'full': 60, 'partial': 25, 'none': 24, 'excluded': 5}
```

`coverage()` accepts no findings, tool ledger, mission id, or attempted-engine set. Ten `FULL` rows
and thirteen `PARTIAL` rows name concepts such as `header analysis`, `crawl`, and `business-logic
graph`, not registered engines. `engine_descriptor.routes()` can extract a useful lower-bound route
for some rows, but it reads the same prose assertion and cannot recover the missing rows or prove a
mission performed the WSTG scenario. An honest evidence-driven tally is therefore not derivable from
`wstg_catalog` as written. Fixing the sentence rather than inventing a mission number was justified.

## Q-085 slice 1: repository-wide guard

`tests/test_rate_policy.py` now scans every top-level production Python module for raw HTTP clients,
`urlopen`, and target `page.goto` calls. Control-plane and third-party calls are explicit one-site
exemptions; the policy implementation and a locally wait+observe-wrapped call are separate facts.

Measured at the baseline before any production fix:

```text
raw target-capable transport inventory: 39
ungated TARGET call sites:              25
modules with ungated TARGET calls:      13
```

The 39 denominator excludes the literal `about:blank` browser bootstrap. The first apparatus run
reported 31 and failed its non-vacuity floor; the cause was an import-normalization defect that turned
`urllib.request.urlopen` into `urllib.request.request.urlopen`. The instrument was corrected and the
full 39/25/13 measurement was rerun. The floor was not lowered to the bad reading.

The unresolved zero-bypass assertion is a strict xfail carrying 25/13. Separate ratchets prevent
either count rising. Negative control: a synthetic `brand_new_engine.py` containing raw
`httpx.AsyncClient` is reported as a bypass; its clean twin using
`browser_engine.rate_limited_async_client` is not. This proves a module outside the old
`tools.__file__` boundary is visible.

Targeted verification:

```text
.x....................                                                   [100%]
XFAIL tests/test_rate_policy.py::test_every_target_transport_uses_the_shared_rate_policy - Q-085 LIVE GAP: repository-wide AST census measures 25 ungated target calls across 13 modules; registration is not compliance, and SKIPPED/NOT SEEN is not a pass
21 passed, 1 xfailed in 11.82s
```

## In progress

* Juice Shop's four raw target transports, including the ten-thread review race
* bare-429 wait provenance and Coordinator default ruling
* audit of the engine-reachability, session-identity, and ZAP guard scopes
* full suite, Tier-3 gate, queue gate, rebase, and final integration instructions
