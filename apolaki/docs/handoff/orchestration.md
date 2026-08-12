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

| defect | status |
|---|---|
| D3 -- planner delivers one parameter per endpoint | **FIXED** -- `141669f` |
| D5 -- `chase_capability` dead: findings projected without `enables` | **FIXED** -- `7bcbe8d` |
| D13 -- `_seed_and_project_graph` writes no edges | **FIXED** -- `7bcbe8d` (same function, same slice as D5) |
| D6 -- `run_service_pack` dead: service node never exists untested | **FIXED** -- in lane, `agent/agent.py`; `tools.py` not touched |

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
