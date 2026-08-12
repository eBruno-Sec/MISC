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

| defect | status |
|---|---|
| D3 -- planner delivers one parameter per endpoint | **FIXED** |
| D5 -- `chase_capability` dead: findings projected without `enables` | in progress |
| D13 -- `_seed_and_project_graph` writes no edges | in progress |
| D6 -- `run_service_pack` dead: service node never exists untested | in progress -- see the ownership note below, it turned out to be fixable IN LANE |

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
was the wrong call is a code read, not a preference.
