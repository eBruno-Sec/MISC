# Orchestration lane -- Q-036 step 1 (D3, D5, D6, D13)

Builder lane for the four defects in `handoff/architecture.md` 6.1 that revive machinery which is
already written, already registered, and measurably dead. Written as the work happens; every claim is
MEASURED (command + real output) or marked UNVERIFIED.

Owned files: `agent/agent.py` `agent/asset_graph.py` `agent/planner.py` `agent/technique_planner.py`
`agent/engine_descriptor.py` + their tests + this file.
Not touched: `agent/tools.py` `agent/cmdi_tool.py` `agent/sqli_tool.py` `agent/collaborator.py`
`agent/codereview.py` `agent/codeintel.py` `agent/rules/` `docs/LEDGERS.md` `docs/QUEUE.md`
`docs/STATUS.md`.

Iteration method: `docker cp <f> apolaki-agent-1:/app/<f>` -- the image was NOT rebuilt. Other lanes
are live in the container; `curl -s http://localhost:8000/missions` showed no running mission (all
`complete` / `interrupted`) before any file was copied in.

Rule 8b, in force here: **this file records what HAPPENED, never what is expected to happen.** An
unmeasured row says `in progress`, never a number. A commit hash is copied from `git log` or omitted.

Corollary learned on U1: **a count is only as good as the point it is sampled at.** A tool's
`ToolResult.count` is sampled BEFORE `_auto_store` grades the result, so it measures routing, not
capability. Capability claims come from the graded outcome set (`findings` + `leads`), diffed --
never from a dispatch count.

| defect | status |
|---|---|
| D3 -- planner delivers one parameter per endpoint | **FIXED** -- `141669f` |
| D5 -- `chase_capability` dead: findings projected without `enables` | **FIXED** -- `7bcbe8d` |
| D13 -- `_seed_and_project_graph` writes no edges | **FIXED** -- `7bcbe8d` (same function, same slice as D5) |
| D6 -- `run_service_pack` dead: service node never exists untested | **FIXED** -- `49310a6`, in lane in `agent/agent.py`; `tools.py` not touched |
| U1 -- execute the ranked actions instead of reporting them | **WIRED + MEASURED** -- code `92e678b`, measurement `b295dae`. Dispatch **0 -> 4**; graded outcome **+1 lead, +0 confirmed findings**; two runs identical. Two of three tiers wired but unexercised. |

All four defects are landed, and U1 is wired and measured on top of them.

The single most important thing to read out of this lane, stated with both numbers kept apart because
they are different claims:

- **Wiring: real and complete.** The graph ranked 4 actions and dispatched **0**; it now dispatches
  **4**, drains to a fixpoint, and reaches object endpoints the tool planner never schedules.
- **Capability: one lead, no confirmed finding.** The set diff against an unranked run on the same
  target is **+1 lead, +0 confirmed findings**, nothing lost, identical across two runs.

The D6 follow-up below ("nothing consumes the ranked output") described the state before `92e678b`
and is kept as the record of what U1 was fixing -- it is no longer current.

---

## D3 -- the planner knew every parameter and delivered one

`agent/planner.py`. FIXED.

### The measurement, before

`surface.build_inventory` unions the parameter NAMES per endpoint but keeps a single `example` URL.
Every phase-E per-endpoint step took its probe URL from that example, so any parameter that did not
happen to ride on the example URL was never probed by any engine.

```
$ MSYS_NO_PATHCONV=1 docker exec apolaki-agent-1 python /tmp/d3_measure.py
INVENTORY (planner knows):
   t.local:3000/fetch           ['cmd', 'target']
   t.local:3000/search          ['lang', 'term', 'url']
   t.local:3000/x               ['id', 'q']

DELIVERED (what the engine will actually test):
   t.local:3000/fetch    run_ssrf    tests=['cmd']     NEVER-TESTED=['target']
   t.local:3000/fetch    run_sqli    tests=['cmd']     NEVER-TESTED=['target']
   t.local:3000/search   run_sqli    tests=['term']    NEVER-TESTED=['lang', 'url']
   t.local:3000/x        run_sqli    tests=['id']      NEVER-TESTED=['q']
   ... (12 rows)

SUMMARY
  steps carrying an explicit params= input : 0
  (param, engine) pairs the planner knew about and never delivered: 16
```

The `run_ssrf` row is the sharpest form of it: run_ssrf is scheduled *because* the inventory saw the
URL-ish parameter `target` (`planner.py:_URLISH_PARAM`), and is then handed a URL carrying only `cmd`.
The engine's own `ssrf_tool.ssrf_params(url)` then falls back to the non-URL-ish parameter.

### The obvious fix is inert -- MEASURED, and this is the finding

`architecture.md` 6.1 prescribes: *"add `params=ep["params"]` to the existing step dicts -- `_run_sqli`
already reads `inp["params"]`"*, and 6.5 calls it one line for an immediate coverage gain. It is not.

`_run_sqli` (`tools.py:6583`), `_run_nosqli` (7005), `_run_cmdi` (7112) and `_run_xss` (4107) all build
every probe target with `xss_tool.set_param(url, p, payload)`, which REPLACES an existing parameter and
returns the URL **unchanged** when the parameter is absent:

```
$ MSYS_NO_PATHCONV=1 docker exec apolaki-agent-1 python /tmp/d3_trap.py
xss_tool.set_param  (used by _run_sqli/_run_nosqli/_run_cmdi/_run_xss)
   present param 'id' -> http://t.local:3000/x?id=PAYLOAD
   absent  param 'q'  -> http://t.local:3000/x?id=1
   payload delivered for absent param? False
   probe URL == baseline URL? True

ssrf_tool.set_param (used by _run_ssrf)
   absent  param 'q'  -> http://t.local:3000/x?id=1&q=PAYLOAD
   payload delivered for absent param? True
```

So iterating a `params=` list would send the **baseline URL as the probe**: baseline and probe fail
identically and the endpoint is reported clean. That is this repository's recorded
*"probe with observed values"* failure mode, reintroduced by the fix for it. A test asserting
`step["input"]["params"] == ['id','q']` would have passed while no payload was ever delivered. The two
`set_param` implementations also disagree with each other, which is its own latent defect -- recorded
as a follow-up below.

Two further reasons the `params=` route is wrong even where it would work:

- `_run_xss:4108` only runs `self._discover_params(url)` **when `params` is NOT supplied**. Passing
  `params=` would switch hidden-parameter discovery off -- a coverage *regression* inside the coverage
  fix.
- `run_injection_probes`, `run_web_probes`, `run_sqlmap`, `run_dalfox` and `run_xxe` never read
  `inp["params"]` at all, so a `params=` patch cannot reach them without a `tools.py` change.

### What was implemented instead

Carry the parameters **on the URL**. Two pure module-level helpers in `planner.py` plus one closure:

- `observed_param_values(urls) -> {(netloc, path): {param: value}}` -- recovers the value each
  parameter was actually observed with, across every discovered URL for that endpoint. First
  observation wins; a real value beats a blank one. **Observed values only, never invented ones.**
- `merge_observed_params(url, values)` -- the example URL plus every observed parameter it is missing,
  appended in sorted order (deterministic). Parameters already on the URL keep their own value.
- `_ex(ep)` inside `next_batch` -- replaces the expression
  `_b_url(ep.get("example")) or (_b(ep['host']) + ep['path'])` at the seven phase-E per-endpoint sites
  (dom_audit, param_mine, anomaly_scan, the injection loop, xxe, deserialization/bfla, dalfox).

Deliberately unchanged: the phase-D `http_probe` site (its job is form capture, not injection) and the
`run_auth_sqli` site (it does `.split("?")[0]`, so a merge there is discarded anyway).

### The measurement, after

```
$ MSYS_NO_PATHCONV=1 docker exec apolaki-agent-1 python /tmp/d3_measure.py
   t.local:3000/fetch    run_sqli    tests=['cmd', 'target']         NEVER-TESTED=[]
   t.local:3000/fetch    run_ssrf    tests=['target']                NEVER-TESTED=['cmd']
   t.local:3000/search   run_sqli    tests=['lang', 'term', 'url']   NEVER-TESTED=[]
   t.local:3000/x        run_sqli    tests=['id', 'q']               NEVER-TESTED=[]

SUMMARY
  (param, engine) pairs the planner knew about and never delivered: 3
```

**16 -> 3 on a 7-URL surface.** The three remaining are `run_ssrf` correctly narrowing to the URL-ish
parameters (`ssrf_params`' prone-else-all rule), which is the engine's intended behaviour, not a
defect -- and `/fetch` now reaches `target`, the parameter that caused the step to be scheduled at all,
instead of `cmd`.

### Negative control

`agent/tests/test_planner_param_delivery.py::test_probe_url_carries_every_param_so_a_payload_actually_lands`
asserts the OLD behaviour is gone, in two independent ways:

1. the delivered parameter set is no longer `xss_tool.params_of(ep["example"])` -- the pre-fix rule,
   recomputed inside the test;
2. `xt.set_param(probe_url, p, "APOLAKI_PAYLOAD") != probe_url` for every formerly-unreachable
   parameter, i.e. a payload actually lands on the wire.

Assertion 1 alone would pass on a `params=`-only fix that never delivers a payload. Assertion 2 is what
makes the test unfoolable by the inert patch.

Pre-fix run (fixed `planner.py` stashed, old file `docker cp`'d back):

```
FAILED test_every_parameter_the_inventory_knows_reaches_the_probe_url
FAILED test_probe_url_carries_every_param_so_a_payload_actually_lands
FAILED test_ssrf_is_handed_the_urlish_param_that_caused_it_to_be_scheduled
FAILED test_observed_param_values_groups_by_endpoint_and_prefers_a_real_value
FAILED test_merge_observed_params_keeps_existing_values_and_sorts_the_additions
5 failed, 3 passed
```

The 3 that pass pre-fix are the invariants (no invented values, determinism, no churn on an endpoint
whose example is already complete) -- correct, they are guards, not defect assertions.

### Mutation check -- 3 mutants, 3 killed

| mutant | result |
|---|---|
| `merge_observed_params` returns `url` unconditionally (the pre-fix behaviour restored) | 4 failed |
| additions carry an invented `"1"` instead of the observed value | 2 failed, incl. the no-invented-values guard |
| the example URL's own values are clobbered by the observed map | 1 failed |

### Regression

`1984 passed, 9 skipped, 1 xfailed, 0 failed in 306s`
(`docker exec -w /app apolaki-agent-1 python -m pytest tests -p no:randomly`). Baseline was 1943 + 8
new here; the container also carries other lanes' uncommitted tests, which accounts for the rest.
Zero failures.

### Follow-ups this uncovered (NOT done here, `tools.py` is off-limits)

1. **`xss_tool.set_param` and `ssrf_tool.set_param` disagree.** One appends a missing parameter, the
   other silently no-ops. Any future code that assumes "set this parameter" works will be wrong half
   the time, silently, in the direction of reporting clean. Worth collapsing onto one helper.
2. `_run_web_probes` (5647), `_run_injection_probes` (5860) and `_run_sqlmap` (8800) still never read
   `inp["params"]`. They are fixed here only because they now receive a fuller URL. If a parameter set
   ever needs to travel out-of-band (body params, headers), those three need the read added.
3. `M3` in architecture.md 6.2 (how many endpoints per real mission lose parameters to D3) is still
   UNVERIFIED -- the numbers above are a synthetic 7-URL surface, not a mission.

---

## D5 + D13 -- the live graph projected findings that recommended nothing

`agent/agent.py:_seed_and_project_graph`. Both FIXED in one slice: they are the same function, and
D13's edges are what make D5's finding reachable from the asset it was found on.

### The measurement, before

Driving the REAL `BBHAgent._seed_and_project_graph` (not the audit's hand copy) over two CONFIRMED
findings -- a SQL injection and a leaked AWS secret:

```
$ MSYS_NO_PATHCONV=1 docker exec apolaki-agent-1 python /tmp/d5_measure.py
projection error : None
stats            : {'nodes': 6, 'edges': 0}
by_kind          : {'host': 1, 'endpoint': 3, 'finding': 2}
finding.enables  : [[], []]
chase candidates : 0
next_best_actions: []
edges            : []
```

**Two confirmed findings, zero recommended actions.** `next_best_actions` (`asset_graph.py:288`)
builds the `chase_capability` tier by iterating `f["enables"]`; the live projector observed findings
with `family=` and no `enables=`, so the candidate list was empty **by construction** and the
highest-utility tier could never fire during a scan. `edges: 0` is D13 -- host, endpoint and finding
landed unconnected, so nothing downstream could walk from a finding to its asset.

Note this is *worse* than the audit recorded: architecture.md 2.2 shows `next_best_actions:
['cross_user_test ...']`, but only because its `m5.py` hand-added an `object` node that
`_seed_and_project_graph` never writes. Driving the real function, the list is empty outright.

The mapping the tier needed already existed and was already tested -- `_FINDING_ENABLES` +
`_content_enables` (`asset_graph.py:420-441`) -- and the report-time `build_from_engagement` already
used it. Only the live path skipped it, so the planner reasoned over a strictly poorer world model
than the report rendered.

### What was implemented

In `_seed_and_project_graph`:

- **D5** -- `enables=sorted(set(_FINDING_ENABLES[family]) | set(_content_enables(f)))` passed into the
  existing `g.observe("finding", ...)` call. Same two helpers `build_from_engagement` calls, so the
  live graph and the report agree; a test asserts that equality directly.
- **D13** -- `host -serves-> endpoint` for every projected endpoint, and
  `endpoint|host -found_on-> finding` for every projected finding. Same relation names
  `build_from_engagement` uses (one step toward D12's convergence, which stays out of scope here).
- Two new resolver helpers, `_graph_host_node` and `_graph_finding_anchor`, which look a node up under
  each of the three identity conventions that already coexist in this graph (D12: whole-URL,
  `netloc+path`, bare hostname) and return `""` rather than creating anything. Minting a fourth
  identity just so an edge had somewhere to land would have made D12 worse; there is a test for that.

Deliberately unchanged: the live finding key rule (`id` or `title[:40]`), which differs from
`build_from_engagement`'s (`title[:40] + "@" + target`). That divergence is D12 and is a separate
ticket -- changing it here would move node identities under the report.

### The measurement, after

```
projection error : None
stats            : {'nodes': 6, 'edges': 5}
finding.enables  : [['database_read'], ['credential_material']]
chase candidates : 2
next_best_actions: ['chase_capability', 'chase_capability']
edges            : [('serves', 'host:t.local', '->', 'endpoint:http://t.local:3000'),
                    ('serves', 'host:t.local', '->', 'endpoint:http://t.local:3000/rest/basket/1'),
                    ('serves', 'host:t.local', '->', 'endpoint:http://t.local:3000/x?id=1'),
                    ('found_on', 'endpoint:http://t.local:3000/x?id=1', '->', 'finding:f1'),
                    ('found_on', 'endpoint:http://t.local:3000/rest/basket/1', '->', 'finding:f2')]
```

- `finding.enables`: `[[], []]` -> `[['database_read'], ['credential_material']]`
- `chase_capability` candidates: **0 -> 2**
- `next_best_actions`: **`[]` -> 2 entries**
- `edges`: **0 -> 5** (3 `serves`, 2 `found_on`), node count unchanged at 6

### Negative controls

`agent/tests/test_live_graph_projection.py`, 10 tests. The two that carry the defect:

- `test_the_chase_capability_candidate_list_is_no_longer_empty_by_construction` -- asserts the
  always-`[]` state is gone AND that `chase_capability` is actually **emitted**. The first assertion
  alone is not enough: a finding can carry `enables` and still produce no action if the capability is
  already held, so a test that only checks the node property would pass while the tier stayed dead.
- `test_projected_nodes_are_no_longer_unconnected` -- asserts `edges > 0` AND walks the specific
  `host -serves-> endpoint -found_on-> finding` path, so no unrelated edge can satisfy it.

Both drive the real `_seed_and_project_graph` through a real `BBHAgent` and a real `ScopeEngine`.

Pre-fix run (fixed `agent.py` stashed, old file `docker cp`'d back): **8 failed, 2 passed.** The 2 that
pass pre-fix are the guards (no fourth host identity, idempotence) -- correct, they are invariants.

### Mutation check -- 5 mutants, 5 killed by the intended assertion

| mutant | result |
|---|---|
| `enables` computed then passed as `[]` (D5 restored exactly) | 5 failed |
| the `found_on` link dropped | 2 failed |
| the `serves` link dropped | 2 failed |
| only `_FINDING_ENABLES`, `_content_enables` dropped | 1 failed -- `test_the_content_signal_is_wired_not_only_the_family_table` |
| `_graph_host_node` mints a host node instead of returning `""` | 1 failed -- `test_linking_mints_no_fourth_host_identity` |

### Regression

`2006 passed, 9 skipped, 1 xfailed, 0 failed in 396s`. Baseline 1993 + 10 new here; the container also
carries other lanes' uncommitted tests.

### Follow-up this uncovered

`architecture.md` 2.2's `next_best_actions: ['cross_user_test ...']` overstates what the live graph
produces, because `m5.py` seeds an `object` node by hand that no live producer in
`_seed_and_project_graph` writes. Objects reach the live graph only via `tools._graph_add_url`. Worth
correcting in the audit so the next reader does not assume `cross_user_test` is armed by projection.

---

## D6 -- ownership re-check: it is fixable in lane, `tools.py` is not needed

The brief said D6 requires an off-limits `tools.py` change, citing `tools.py:2810-2812`. Reading the
code says otherwise, and the distinction changes the fix.

`_run_service_pack` (`tools.py:2695`) does its `observe` + `mark_tested` at the **end** of the function,
after the pack has already executed (`tools.py:2806-2816`). So the node is not "marked tested too
early" -- it is **created too late**. The `service` node never exists in the untested state at all,
which is why `untested("service")` is empty by construction.

The fingerprint step that discovers the ports lives in `agent/agent.py:_run_service_packs:1512-1548`
(`service_router.parse_nmap_ports` plus the self-contained socket sweep) -- an owned file. Writing the
node there, untested, is exactly the audit's prescription ("write the node at fingerprint time"), and
`tools.py` needs no edit at all: `AssetGraph.observe` is idempotent by `(kind, key)` and its merge
branch never clears `tested`, so the existing `observe` + `mark_tested` at the end of
`_run_service_pack` correctly transitions the same node to tested when the pack completes.

Recorded here because "this needs the other lane" would have been the wrong call, and the reason it
was the wrong call is a code read, not a preference. Re-verified against `tools.py` at `4250422`
(the probe lane's committed work): the block is unchanged, still at 2810-2812, still at the end of
the function.

### The measurement, before

Driving the real `BBHAgent._run_service_packs` with ssh:22 and redis:6379 already discovered by a
prior nmap, capturing the graph state at the moment the packs are dispatched -- the only window in
which the planner could act on the fact:

```
$ MSYS_NO_PATHCONV=1 docker exec apolaki-agent-1 python /tmp/d6_measure.py
services discovered by fingerprint : [22, 6379]
--- AT DISPATCH (the only window the planner could act in) ---
service nodes in graph  : []
untested('service')     : []
next_best_actions       : []
```

Two services fingerprinted, **zero service nodes in the graph**. Not "empty by construction" in the
sense of being observed and instantly retired -- the discovery step wrote nothing at all.

### What was implemented

In `_run_service_packs`, immediately after `_targets` is computed and before the packs are
dispatched: `self.tools.graph.observe("service", "host:port", ..., source="fingerprint")`, untested,
with `enables` taken from the same `service_router.route` the report-time `build_from_engagement`
uses so the tier's impact ranking matches the report instead of defaulting.

Seeded for `_targets` only -- the pack-eligible services. A web or unknown service has no pack
(`pack_for` returns `{}`), so arming `run_service_pack` for one would produce an action the executor
cannot honour. A graph write failure goes to the existing `tools._swallow` ledger, not to a silent
`except: pass`, because a silent one would put the tier straight back to dead with no trace.

`agent/tools.py` was NOT modified.

### The measurement, after

```
--- AT DISPATCH ---
service nodes in graph  : ['t.local:22', 't.local:6379']
untested('service')     : ['t.local:22', 't.local:6379']
next_best_actions       : ['run_service_pack']
```

- service nodes at dispatch: **0 -> 2**
- `untested('service')`: **`[]` -> 2 entries**
- `next_best_actions`: **`[]` -> `['run_service_pack']`**

### Negative controls -- and the second half

`agent/tests/test_service_discovery_graph.py`, 7 tests.

- `test_a_discovered_service_is_untested_in_the_graph_before_its_pack_runs` -- the arming control.
  The middle state (observed, not yet tested) IS the fix. A test asserting "a service node exists"
  passes on the broken code, because the broken code also produces a service node -- just never an
  untested one. A test asserting the end state passes too.
- `test_the_pack_still_marks_the_same_node_tested_when_it_completes` -- **the other half**, and the
  one that matters most for a fix that spans two files. It drives the REAL
  `ToolRegistry._run_service_pack` over the node this fix seeds and asserts (a) exactly two service
  nodes still exist, so the pack MERGED rather than creating a second identity, and (b) the redis
  node is now tested while ssh is not. Arming a tier that nothing disarms recommends the same pack
  forever; seeding under a key `tools.py` does not use leaves the first node untested forever.
  Neither failure is visible from the arming test.

Pre-fix run: **4 failed, 3 passed.** The 3 that pass pre-fix are guards (no node for a pack-less
service, nothing in passive mode, idempotence).

### Mutation check -- 5 mutants, 5 killed by the intended assertion

| mutant | result |
|---|---|
| the node is seeded with `tested=True` (the defect, relocated into the new code) | 2 failed |
| every discovered service seeded, including web/unknown | 1 failed |
| `enables` dropped | 1 failed |
| the graph-write failure swallowed silently instead of recorded | 1 failed |
| seeded under key `host/port` instead of `host:port`, diverging from `tools.py` | 3 failed -- incl. the composition test, which catches the second-identity failure |

### Regression

`2013 passed, 9 skipped, 1 xfailed, 0 failed in 322s`.

### Follow-up this uncovered

`untested("service")` is now populated, but nothing CONSUMES `next_best_actions()` inside the
execution loop -- U1 / architecture.md 1.8: `plan_next()` and `apply_result()` still have no non-test
callers, and `_close_autonomy_loop` runs after the loop finishes. So all three tiers are now armed
(`chase_capability` from D5, `run_service_pack` from D6, `cross_user_test` which already worked) and
the ranked output still only reaches the report. **Arming the producer was steps 1-3 of the build
order; U1 is what makes it act.** Worth stating plainly so the next reader does not mistake "the tier
fires" for "the scan does the work".

---

## U1 -- execute the ranked actions (`92e678b` = code only, measurement NOT taken)

`agent/agent.py` + `agent/asset_graph.py`. **Code is green and committed; U1 is NOT done.** The
capability claim is unproven until the measurement below exists, and the commit says so.

### The routing catch -- why the first number was thrown away

The first paired run on VAmPI produced what looked like the right shape:

```
BEFORE  ranked actions produced: 4   dispatched: 0
AFTER   ranked actions produced: 4   dispatched: 4   (2 of them reported findings=1)
```

That `findings=1` is **not a finding.** `_run_tool` yields `count` straight off the ToolResult, and
`run_bfla` IS in `_AUTO_STORE_TOOLS`, so `_auto_store` ran and graded the results -- and graded
results without `confidence == "confirmed"` are routed to `self.leads`, not `self.findings`. The
mission's `findings` total was `0` in both runs. So the number I was about to report measured the
**routing of a tool result**, not a capability the scan gained.

This is the same class of error as the per-process latch found earlier this cycle: a count that
depends on where in the pipeline it is sampled rather than on what the scan actually achieved. A
tool-level `count` is sampled before the grader; a capability claim has to be sampled after it.

Recorded BEFORE re-running, so the correction is not something the next number quietly absorbs.

### The only question U1 has to answer

Not "did the tier fire" and not "how many actions dispatched" -- both were already true of a producer
that fed a report. The question is:

> does a ranked action, once dispatched, produce a finding **the scan would not otherwise have made**?

So the measurement is a SET DIFF of the graded outcome (findings AND leads, each identified by
title+target) between an unranked run and a ranked run on the same target with the same seed -- not a
count of dispatches.

Two constraints held while measuring:

- **Determinism.** Two ranked runs, finding sets diffed. `decayed_confidence` moves with wall-clock
  for untested nodes, so ranked ORDER can drift; the executor therefore DRAINS the ranked set rather
  than taking the top item, making order a preference and membership stable. That design claim is
  exactly what the repeat run tests.
- **Bounded.** `CAP_GRAPH_ACTIONS = 24` per mission, ranked order preserved so a budget cut-off drops
  the least valuable first. Graph steps run through the same `done` dedup, the same hostless guard,
  the same `MAX_STEPS`, and the same `_run_tool` passive/HITL gates as planner steps.

An honest "+0 -- the ranked actions dispatched and found nothing the unranked run did not" is a
complete result: it would mean the ranking is correct but the surface is already covered, which is a
different ticket from wiring it. Same standard as the cmdi +0 reported against a predicted +5.

### Status

Measurement in progress. No capability claim until the set diff is recorded here.
cat >> docs/handoff/orchestration.md <<'EOF'

### MEASURED -- the U1 gap, and what closing it bought

Target `http://vampi:5000/` (VAmPI), mode `active`, deterministic executor, seed
`http://vampi:5000/openapi.json` IDENTICAL in every run. "Before" is the pre-U1 code extracted from
`92e678b^` and `docker cp`'d into the container; "after" is `92e678b`. Nothing else differs.

**Two numbers, reported separately, because they are not the same claim.**

#### 1. WIRING -- 0 dispatched -> 4 dispatched

```
$ MSYS_NO_PATHCONV=1 docker exec apolaki-agent-1 python /tmp/u1_diff.py
  before  ranked_dispatched=0  still_open=4  tool_dispatches=52  untested=33
  after1  ranked_dispatched=4  still_open=0  tool_dispatches=56  untested=25
  after2  ranked_dispatched=4  still_open=0  tool_dispatches=56  untested=25
```

**This is the measured statement of the gap.** The graph ranked four actions and **zero reached
dispatch** -- every prior description of U1 was an audit reading; this is a number from a real run.
The ranking was computed and discarded, exactly as `architecture.md` 1.8 said, and the four actions
were still sitting unexecuted when the scan ended (`still_open=4`).

After: all four dispatch, `tool_dispatches` rises by exactly 4 (so the graph actions are the *only*
new tool calls -- that is what makes the outcome diff below attributable), and the ranked list drains
to `still_open=0`. The loop closes: `apply_result` marks the tested nodes, so the actions stop being
suggested and the run reaches a fixpoint rather than re-recommending forever. `untested` 33 -> 25.

All four were `cross_user_test -> run_bfla` on the four object endpoints
(`/books/v1/1`, `/users/v1/1`, `/users/v1/1/email`, `/users/v1/1/password`). The tool planner
schedules `run_bfla` only for PARAMETERIZED endpoints; these carry no query params, so the planner
never covered them. This is surface the graph could name and the planner could not.

#### 2. CAPABILITY -- +1 lead, +0 confirmed findings

```
  before findings=0 leads=1
  after  findings=0 leads=2
  NEW in after (not in before):
     + Side-channel BOLA (resource existence oracle) | resource-id
  LOST in after (regression check):
     (none)
  new CONFIRMED findings: NONE
```

**The honest answer to the only question U1 had to answer:** a dispatched ranked action produced one
graded outcome the unranked run did not -- a side-channel BOLA lead on VAmPI's object endpoints --
and produced **zero new confirmed findings**. Nothing was lost.

A lead is not a finding, and this result must not be quoted as one. What is established is that the
ranking pointed at real untested surface and the dispatch reached it; what is NOT established is that
it converts to a confirmed finding, on this target or in general. One lead on one lab is a single
data point, not a capability curve.

**Attribution, verified rather than assumed** -- "it appeared in the after run" is a coincidence
argument, so both halves were checked:

- the lead is produced by `authz_tool.analyze_side_channel`, called at `tools.py:6099`, which sits
  inside `_run_bfla` (`tools.py:6060`) -- so only a `run_bfla` call can emit it;
- `tool_dispatches` rose by exactly 4, and the four graph actions were the four `run_bfla` calls, so
  no other new tool ran in the after scan that could have produced it.

Those two together make the lead attributable to a graph-dispatched ranked action, not to run-to-run
noise.

#### 3. DETERMINISM -- two ranked runs, identical

```
  findings / leads / graded_outcomes / graph_dispatched /
  ranked_actions_at_end / tool_dispatches_total / graph_stats   ALL IDENTICAL
  => two ranked runs produce the same finding set: True
```

This was the design risk: `decayed_confidence` moves with wall-clock for untested nodes, so ranked
ORDER can drift between runs. The executor therefore DRAINS the ranked set rather than taking the top
item, which makes order a preference and membership stable. The repeat run confirms the finding set
does not move.

#### What this does and does not settle

- **Settled:** the producer now has a consumer, bounded (`CAP_GRAPH_ACTIONS = 24`, ranked order kept
  so a cut-off drops the least valuable first), gated (same `done` dedup, hostless guard, `MAX_STEPS`
  and `_run_tool` passive/HITL checks as planner steps), and convergent (drains to a fixpoint).
- **Settled:** it reaches surface the tool planner does not schedule, and it is deterministic.
- **NOT settled:** whether that surface yields confirmed findings at any rate worth the dispatches.
  `+1 lead / +0 findings` on one lab is the whole evidence base. The `chase_capability` and
  `run_service_pack` tiers were NOT exercised by this run at all -- VAmPI produced no finding with
  `enables` and no non-web service -- so two of the three mapped tiers are wired and unmeasured.
- **Follow-up, separate ticket:** `run_bfla`'s results grade below `confirmed` and route to leads.
  Whether that grading is correct for a resource-existence oracle is a probe-lane question, not a
  wiring question, and it is the difference between this result reading `+1 lead` and `+1 finding`.
- **Follow-up found while measuring:** the planner only fetches an OpenAPI spec it has already
  DISCOVERED (`planner.py:372`). VAmPI publishes one at a documented path and links it from no
  crawlable page, so an unseeded run finds 3 endpoints instead of 27 and produces no object nodes at
  all. A well-known-spec-path probe would arm the whole tier autonomously. That is why the seed above
  exists, and it is stated rather than hidden.

### Island check on the new event -- half-wired, and the missing half is not mine

U1 emits a new event type, `graph_action`, one per dispatched ranked action (action, tool, target,
capability, utility, findings). Registration is not rendering, so both consumers were checked:

- **API / persistence: OK.** `main.py:2423` logs every event with
  `db.add_log(session_id, event.get("type", "info"), event)` and appends it to `sess["events"]`
  regardless of type, so `graph_action` reaches the DB and the mission event feed.
- **Live UI: DROPPED.** The event switch in `ui/index.html` (~1376-1412, and the replay switch at
  ~1412) is a `case` list with **no `default:` branch**, so an unrecognised type is silently
  discarded. The per-action outcome line is invisible to an operator watching a run.

Partial mitigation already in place: the batch announcement is an `info` event
("Graph-directed execution -- the world model ranked N action(s)..."), and `info` IS rendered. So the
operator sees THAT graph-directed execution happened and how many actions were ranked; they do not
see each action's target and result.

### Island CLOSED -- and it was not only my event

`ui/index.html`, taken on the Coordinator's explicit direction to close this. It is not otherwise this
lane's file and nothing else in it was touched.

Fixing my own `graph_action` case meant reading the switch, and the switch held a second, worse
instance of the same defect:

- **`degraded`** (`agent/agent.py:3066`) is a **HALT of primary execution** -- the graph projection
  failed, so the planner must stop selecting actions. It reached the report via `ctx["degraded"]`
  (`main.py:2254`) but **never the live feed**, so an operator watching a run saw the scan simply
  stop, with no message. Strictly more serious than a missing info line.

Both are now cased, in the live switch AND the replay switch, so a mission and its replay cannot
disagree about what happened. The root cause is fixed rather than the two symptoms: **each switch now
has a `default:`** rendering an unhandled type as a visible, labelled UI gap (`unrendered event X --
the mission log has it; this view has no case for it`), with a small `UI_SILENT_EVENTS` set for types
that are deliberately not log lines. The next event type someone adds cannot vanish.

**A bug I introduced and caught before committing.** The first placement put `default:` BEFORE
`case "error"` with no `break`. JavaScript falls through, so every unhandled event would have rendered
its own line and then run the error case -- which in the live switch calls `finishHunt("s-err","Error")`,
i.e. an unknown event type would have marked a healthy mission FAILED. Moved last, with `break`. The
verification below is what caught it: each event must add exactly ONE line, and a fall-through adds two.

MEASURED in the real browser against the served UI, both switches:

```
handleEvent()      [live switch]
  graph_action      added=1  "graph -> cross_user_test via run_bfla on http://vampi:5000/users/v1/1/email (1)"
  degraded          added=1  "Error  Execution halted - graph_projection_failed ..."
  totally_new_type  added=1  "unrendered event totally_new_type - the mission log has it; ..."
  ai_budget         added=0  (deliberately silent)

renderLogEntry()   [replay switch]
  same four, same results, plus
  error             added=1  "Error  a real error"      (the error case still works)
```

Negative control, run on the same page before the fix: an unrecognised type added **0 lines** while a
handled one added 1 -- which is exactly what `graph_action` and `degraded` were doing in every mission
until now.

---

# Q-031 -- Section 2, the rediscovery trigger table

Starting at row 4 (`schema`), which the audit calls the highest-value gap, rather than at the top of
the list. Standing rule held throughout: **a trigger the graph cannot express is a design gap, not a
rule** -- so this says where the gap is instead of inventing a representation.

## Row 4, `schema` -- MEASURED, and the audit's diagnosis is one layer off

The audit says schema has **NO** representation because "`fetch_openapi` / `run_graphql` results reach
`tools.recon`/`tools.urls` only". Measured against VAmPI's real published spec:

```
$ MSYS_NO_PATHCONV=1 docker exec apolaki-agent-1 python /tmp/schema_gap.py
SPEC DECLARES
  operations            : 14 {'GET': 8, 'POST': 3, 'DELETE': 1, 'PUT': 2}
  query parameters      : 0
  header parameters     : 0
  BODY parameters       : 9

endpoints_from_openapi RETURNS
  urls                  : 12
  urls carrying a query : 0
  body params carried   : 0
  methods preserved     : 0
```

**Every testable parameter on this API is a body parameter, and not one reaches the planner.** 100% of
the declared parameter surface is lost. This is also why D3 cannot help here: D3 fixed the delivery of
QUERY parameters, and this target declares zero.

Three separate losses, all in `surface.endpoints_from_openapi` (`surface.py:94-133`):

1. **`requestBody` is never read.** The parameter loop is `if p.get("in") == "query"`
   (`surface.py:123`), so OpenAPI 3 `requestBody` and Swagger 2 `in: body` are both skipped.
   9 declared body parameters, 0 extracted.
2. **The method collapses to a bool.** `testable = True` (`surface.py:118`) records only THAT some
   method exists; the URL is then emitted GET-shaped. 6 of 14 operations here are POST/PUT/DELETE, so
   even the endpoints that ARE imported get probed with the wrong verb.
3. **Declared values are discarded.** Query params, when present, are emitted as `f"{n}=test"`
   (`surface.py:131`) while the spec's own `example` / `default` / `enum` are ignored -- the same
   invented-value shape D3 was about, in the importer this time.

### Why this row is not fixable from this lane's files -- the real blocker

The audit's phrasing implies the spec reaches `tools.recon` and merely fails to reach the graph. It
does not. `_fetch_openapi` (`tools.py:3766-3781`) parses the spec into a local `spec` variable,
converts it to URLs, calls `self._add_urls(endpoints)`, and returns. **The spec object is then
garbage-collected.** `tools.recon` never receives it, and no projector can project a fact that no
longer exists.

So the honest statement for the trigger table is:

> Row 4 is **NOT blocked by the graph's expressiveness.** `AssetGraph` already has a `param` kind with
> `has_param` edges (`asset_graph.py:475-477`), and `observe(**props)` takes arbitrary props, so
> `location` / `type` / `required` / `method` need no new node kind at all; a `schema` kind is a
> one-word addition if it is even wanted. The row is blocked because **the fact is destroyed at the
> tool boundary before any consumer can see it.**

That distinction decides which file the fix lives in. This is not a graph-design problem to solve in
`asset_graph.py`; it is a one-line persistence problem in `tools.py` followed by ordinary projection
work in `agent.py`. Sized honestly:

- `tools.py` -- `_fetch_openapi` keeps the parsed spec, e.g.
  `self.recon.setdefault("openapi", {})[base_url] = spec`. One line. **`agent/tools.py` is unowned but
  I have NOT taken it** -- flagged here for the Coordinator rather than reached into.
- `surface.py` -- read `requestBody` / `in: body`, keep the method, prefer declared
  `example`/`default`. Also not this lane's file.
- `agent.py` + `asset_graph.py` (mine) -- project `param` nodes carrying
  `props{location,type,required,method}` and arm the body-capable engines. This half is ready to write
  the moment the fact survives the tool call.

### What the trigger would then be

On record, **NOT implemented**, and deliberately expressed in the existing vocabulary:

- **fact selector:** `param` nodes with `props["location"] == "body"` whose `first_seen` is newer than
  the last iteration -- the same `first_seen` predicate 2.1 already specifies, no new mechanism.
- **armed actions:** the body-carrying probes, aimed at the endpoint the `has_param` edge points at.
- **dedup scope:** the planner's own key namespace, exactly as U1's graph steps already use, so a
  schema trigger cannot re-probe what the tool planner already covered (the D2 lesson).
- **termination:** unchanged. `apply_result` marks the param tested, the selector stops returning it,
  and the loop reaches the same deterministic fixpoint U1 already drains to. No pass count.

### Rows still unexamined

Rows 1-3 and 5-15 have **not** been re-measured in this lane. The audit's readings stand as written,
with this caveat: row 4's diagnosis was one layer off when checked against the code, and 2.2's repro
was wrong (corrected in `7ffc576`). Two of the three things this lane checked in Section 2 were
inaccurate, so the remaining rows should be verified against the code before anything is built on
them, not taken as given.
