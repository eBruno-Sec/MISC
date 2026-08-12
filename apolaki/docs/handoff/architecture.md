# Apolaki execution architecture -- design for Q-030 .. Q-034

ARCHITECT lane, read-only. No production code was written for this document. Every claim below is
either **MEASURED** (command + real output reproduced inline) or **UNVERIFIED** (stated as such).
Ticket: [QUEUE_ARCH.md](../QUEUE_ARCH.md).

Standing rule honoured here: no proposal in this document was adopted from a sketch. Section 1 first
describes what the code does today, from the code; the proposal in 1.10 is derived from that and
explicitly says where it agrees with Erwin's instinct and where it does not.

---

# SECTION 1 -- the cycle as it exists

## 1.0 One-paragraph answer

There is **no loop at the top level**. `BBHAgent.run()` is a straight-line pipeline of about fifteen
fixed stages. There is exactly **one real loop in the whole engagement**: the inner `while` inside
`_execute_plan`, which re-projects the graph, re-derives world state, re-plans and executes until the
planner returns an empty batch. That loop is already graph-driven, already terminates on a fixpoint,
and already has a budget -- it is closer to what Q-030 asks for than the conversation assumed. The
thing that is broken is the *outer* construct that everybody calls "cycles": it is a hardcoded pass
count wrapped around an already-saturated planner, and **it is measurably inert** -- one extra
`generate_playbook` call per extra cycle and nothing else. Separately, the graph-authoritative planner
(`plan_graph_authoritative` / `next_best_actions` / `plan_next` / `apply_result`) is fully implemented,
correct, and **never executed** -- its output is written to `self._next_best` and read only by an HTTP
endpoint. The architecture's problem is not a missing loop. It is one inert loop, one unexecuted
planner, and a fixed pipeline between them.

## 1.1 The top-level flow is a fixed pipeline

`agent/agent.py:2458-2617`, `BBHAgent.run()`. Straight-line, no loop, no re-entry:

| # | line | stage |
|---|------|-------|
| 1 | 2466-2477 | seed scoped base URLs (pinned-path scope fix) |
| 2 | 2500 | `_surface_crawl` -- HTTP crawl |
| 3 | 2507 | `_recon_code_intelligence` -- served-JS mining |
| 4 | 2512 | `_run_service_packs` -- beyond-web service packs |
| 5 | 2519 | `_do_transport_posture` |
| 6 | 2524 | `_do_header_trust` |
| 7 | 2529 | `_do_saml` |
| 8 | 2534 | `_acquire_scan_auth` -- **the only authentication point in the engagement** |
| 9 | 2550/2553/2556 | strategy dispatch -> `_run_deterministic` / `_run_low_ai` / floor + ReAct |
| 10 | 3148 | (inside deterministic) `_browser_harvest_surface` -- JS-rendered crawl |
| 11 | 3154 | (inside deterministic) `_execute_plan` -- **the loop** |
| 12 | 3160 | (inside deterministic) `_inject_sweep_surface` -- coverage backstop |
| 13 | 2598 | `_probe_cloud_storage` |
| 14 | 2602 | `_technique_advisor` |
| 15 | 2606 | `_close_autonomy_loop` -- computes next-best actions, executes none |
| 16 | 2613 | `_validate_candidates` |
| 17 | 2616 | `_triage` |

Consequences that matter for Q-031/Q-032, visible from the ordering alone:

- Stage 8 (authentication) is **before** stages 10-12. Any credential discovered *during* the scan
  arrives after the only stage that could use it. There is no path back to stage 8.
- Stages 2, 3, 10 are three separate discovery mechanisms that each run **once**, at fixed positions.
  A new hostname or route learnt in stage 11 never re-enters stages 2/3/10.
- Stage 15 produces the ranked plan the graph recommends, and stage 16/17 do not consume it.

## 1.2 The only real loop: `_execute_plan`

`agent/agent.py:2774-2867`. Two nested loops:

```
2781   done, steps = set(), 0            # <-- created ONCE, outside both loops
2782   MAX_STEPS = 220
2783   cycles = self.recon_cycles
2784   for cyc in range(1, cycles + 1):          # OUTER
2793       done.discard("generate_playbook")
2794       while steps < MAX_STEPS:              # INNER
2809           self._seed_and_project_graph(g)   # project engagement state -> graph
2821           g_roots, g_urls, g_recon = self._graph_primary_state(g)   # derive world state FROM graph
2838           batch = planner.next_batch(state)
2839           if not batch: break               # <-- planner fixpoint
2841           for step in batch: ... execute ...
2853       if cyc < cycles and self._surface_size() <= before: break
```

**The inner loop is the cycle.** Each iteration re-projects everything the previous batch discovered
into `tools.graph`, re-derives `roots`/`urls` from the graph, and re-plans. New URLs produce new
planner keys, so the loop continues; when no new keys exist the planner returns `[]` and it stops.
That is discover -> graph update -> replan -> act -> repeat, already implemented, already deterministic.
It is unnamed, uncounted, and not surfaced anywhere in the UI or the report.

**The outer loop cannot do anything.** `done` is created at line 2781, *outside* the `for cyc` loop, so
every key from cycle 1 is still in `done` on entry to cycle 2. Line 2793 discards exactly one key.

## 1.3 MEASURED: the outer cycle loop contributes one step per cycle

Method: drive `planner.next_batch` to fixpoint against a fixed world state (nothing new discovered
between batches -- the exact case the outer loop claims to help with), then re-enter as
`_execute_plan` does: keep `done`, discard only `generate_playbook`.

```
$ cd /tmp && MSYS_NO_PATHCONV=1 docker cp m1.py apolaki-agent-1:/tmp/m1.py \
  && MSYS_NO_PATHCONV=1 docker exec apolaki-agent-1 python /tmp/m1.py
CYCLE1 batches=7 steps=59
CYCLE2 batches=1 steps=1 tools=['generate_playbook']
CYCLE3 batches=1 steps=1 tools=['generate_playbook']
```

(script: 7-phase drive against roots `t.local`, 2 seed URLs, mode `full`, intensity `standard`;
reproducible from `agent/planner.py` alone -- it imports nothing from the agent.)

In the real `_execute_plan` it is worse than "one step": the early-stop at line 2853 fires at the end
of cycle 2, because `generate_playbook` adds no surface, so `_surface_size() <= before` holds. With
`recon_cycles=3` the third cycle **never runs at all**.

> **VERDICT: "3 cycles" is not an architectural thing. It is a parameter nobody revisited.**
> In the deterministic / low-AI / agentic-floor paths, `recon_cycles=1`, `2` and `3` differ by at most
> one redundant `generate_playbook` call. The iterative behaviour operators believe they are buying
> with `recon_cycles=3` is delivered by the inner loop, unconditionally, at `recon_cycles=1`.

## 1.4 What `recon_cycles` actually controls -- three unrelated things

`recon_cycles` is clamped to 1..3 twice (`agent/agent.py:346`, `agent/main.py:396`) and then means
three different things:

1. **`_execute_plan`'s outer counter** (`agent.py:2783`). Measured inert, above.
2. **A sentence in the LLM system prompt.** `_recon_note()` (`agent.py:3269-3281`) returns "" at 1 cycle
   and otherwise appends "ITERATIVE RECON: Perform up to N recon cycles ...". This is a *request to a
   model*, not a control-flow construct. It affects only `strategy == "agentic"`.
3. **A chat label.** `_run_tool` (`agent.py:471-476`) emits a `{"type":"cycle"}` event on entry to the
   recon phase, gated on `strategy == "agentic" and recon_cycles > 1`, counting `self._recon_passes`
   (`agent.py:382`). Unrelated to (1).

So "cycle" in the code means an inert counter, a prompt string, or a phase-entry label -- never the
thing it means in conversation. The construct that behaves like a cycle in conversation is the
inner `while`, which has no name and no counter.

## 1.5 What changes between iterations

**Inner iteration (real):** `_seed_and_project_graph` (`agent.py:2620-2648`) re-observes scope roots,
`tools.recon["subdomains"]`, `tools.recon["live_hosts"]`, every `tools.urls` entry and every finding
into `tools.graph`; `_graph_primary_state` (`agent.py:2681-2743`) re-derives `roots` from graph host
labels and `urls` from graph endpoint keys resolved through `scope.base_map()`, then re-attaches
parameterized URLs from the live surface for paths the graph already holds. `next_batch` therefore
sees a strictly larger world each iteration. This is genuine graph-driven replanning.

**Outer iteration:** nothing changes. Same `done`, same tools, same graph. Measured in 1.3.

## 1.6 What already prevents duplicate work -- and why the key is wrong

`planner.fresh()` (`planner.py:219-234`) is the mechanism. It drops a step when:

- `s["key"] in done` -- cross-batch dedup; `done` is owned by `_execute_plan` (`agent.py:2781, 2845`);
- `s["key"] in seen` -- intra-batch dedup (same key generated twice in one phase);
- `not _allowed(s["tool"], mode)` -- permission tier gate;
- `not _addressable(s)` -- the Q-019 host-less-URL chokepoint (`planner.py:125-144`).

The mechanism is sound. **The key it dedups on is not the right key.** Three measured problems:

### 1.6.a The key is namespaced by call site, not by resolved target -- MEASURED

`http_probe` is emitted from four places under four key prefixes: `http_probe:{h}` (2266),
`http_probe:{host}{path}` (314), `http_probe:page:{host}{path}` (329), `http_probe:rest:{host}{path}`
(349). The same absolute URL therefore survives `fresh()` more than once.

```
$ MSYS_NO_PATHCONV=1 docker exec apolaki-agent-1 python /tmp/m2.py
http_probe duplicate URLs (same URL, different keys):
  x2 http://t.local:3000
  x2 http://t.local:3000/rest/user/whoami
  x2 http://t.local:3000/rest/basket/1
total http_probe steps: 8 distinct URLs: 5
```

8 scheduled fetches for 5 distinct URLs -- a 60% amplification on the cheapest, most-scheduled tool in
the planner, against the ticket's explicit "zero duplicate work". Dedup on `(tool, resolved target)`
would remove all three without changing coverage.

### 1.6.b The key drops the parameter set, and the step drops it too -- MEASURED

```
$ MSYS_NO_PATHCONV=1 docker exec apolaki-agent-1 python /tmp/m3.py
{'host': 't.local:3000', 'path': '/x', 'params': ['id', 'q'], 'parameterized': True,
 'body_sink': False, 'content_type': '', 'example': 'http://t.local:3000/x?id=1'}
```

`surface.build_inventory` correctly unions the parameters (`['id','q']`) but `example` carries only
one. The planner emits `_step("run_sqli", {"url": u}, f"run_sqli:{host}{path}")` (`planner.py:414`) --
one key for the endpoint, and **no `params` key in the input**. `_run_sqli` (`tools.py:6583`) computes
`params = (inp.get("params") or xt.params_of(url))`:

```
$ MSYS_NO_PATHCONV=1 docker exec apolaki-agent-1 python /tmp/m4.py
params_of(example): ['id']
```

So parameter `q` on `/x` is **never SQLi-probed**, although the inventory knows it exists. `_run_xss`
partially compensates by calling `self._discover_params(url)` (`tools.py:4109`); `_run_sqli`,
`_run_nosqli`, `run_injection_probes` and `run_web_probes` do not. This is a coverage hole that looks
like a dedup issue and is actually a lost-input issue: the planner has the fact and does not pass it.
This is also the recorded "probe with observed values" failure mode -- the engine probes the one value
it happened to receive and reports clean on the endpoint.

### 1.6.c `run_httpx` keys on a count, not on content

`planner.py:259`: `f"run_httpx:{len(targets)}"`. Two different target sets of equal size collide; an
add-one/drop-one change never re-runs; the comment on the line ("key on target count so a later recon
cycle re-runs httpx") documents the intent, and the intent is wrong for the same reason a hardcoded
pass count is wrong -- it is a proxy for "did the facts change", not the facts.

## 1.7 Where the loop terminates, and on what criterion

Four exits exist. Ranked by which actually fires:

| exit | line | criterion | assessment |
|------|------|-----------|------------|
| `batch == []` | 2839 | **fixpoint** on the planner's step-key set | the normal exit; correct in shape |
| `steps >= MAX_STEPS` | 2794 | **budget**, hardcoded 220 | not configurable, not surfaced, and the inner `for step in batch` at 2841 does not re-check it, so a batch overshoots by up to `len(batch)-1` |
| graph empty / missing / projection error | 2803-2823 | fail-closed | correct, and deliberately loud |
| `for cyc in range(...)` | 2784 | **hardcoded pass count** | exactly what Q-030 forbids -- and inert (1.3) |
| `_surface_size() <= before` | 2853 | surface-delta | a proxy fixpoint over four flat counters, not over graph facts |
| `stop_event` | 2785/2795/2842 | operator | correct |

So Apolaki **already terminates on a fixpoint plus a budget** in the loop that matters. Two things are
wrong: the fixpoint is over the *planner's key set* rather than over *graph facts* (so a fact that
produces no new planner key -- a new credential, a new persona, a new privilege -- cannot restart the
loop), and the loop that everyone points at as "the cycle model" is the hardcoded pass count.

`_surface_size()` (`agent.py:3295-3297`) is
`len(tools.urls) + len(recon["subdomains"]) + len(recon["live_hosts"]) + len(findings)`. It cannot see
a new persona, session, capability, object type, tenant, technology, param or schema. As a
convergence signal it is blind to most of the fact classes Q-031 lists.

## 1.8 The loop that is not closed

`_close_autonomy_loop` (`agent.py:1151-1256`) does everything right and then stops:

- records findings/leads into `attack_chain` memory (1167-1184),
- ingests intel into the live graph (1199-1207),
- calls `TP.plan_graph_authoritative(_g, _seed, kev_cwes=kev)` (1214) -- the graph-only planner,
- ranks with `learning.class_weight` (1230-1239) and annotates with `attack_chain` (1240-1243),
- writes `self._graph_plan` (1215) and `self._next_best` (1245).

MEASURED -- nothing executes the result:

```
$ grep -rn "_next_best\|_graph_plan" --include=*.py agent/ | grep -v tests/
agent/agent.py:1215:            self._graph_plan = gplan
agent/agent.py:1245:            self._next_best = nxt
agent/main.py:2229:                                "next_best": getattr(ag, "_next_best", []) or []}

$ grep -rn "plan_next\|apply_result" --include=*.py agent/ | grep -v tests/
agent/asset_graph.py:319:    def plan_next(self):
agent/asset_graph.py:327:    def apply_result(self, action: dict, ...):
```

`AssetGraph.plan_next()` and `AssetGraph.apply_result()` -- the plan/act/update/replan pair the
docstring at `asset_graph.py:328` describes as "the close-the-loop step" -- have **no non-test
callers**. `next_best_actions` is called from `main.py:2248` and `main.py:2530` (endpoints) and from
`technique_planner.py:154`. The autonomy loop is a report section.

This is the single largest architectural gap in the repository, and it is a *wiring* gap, not a
missing capability: the ranked-action producer exists and is deterministic; nothing consumes it.

## 1.9 Two graph-construction paths with different node identities

- **Live graph:** `tools.graph = AssetGraph(mission_id)` (`tools.py:1081`), grown by `_graph_add_url`
  (`tools.py:3113-3128`) and `_seed_and_project_graph` (`agent.py:2620-2648`). This is what the scan
  loop reads.
- **Rebuilt graph:** `asset_graph.build_from_engagement` (`asset_graph.py:444-541`), called only from
  `agent/main.py` (2090, 2245, 2521, 2549, 2699) -- endpoints and report assembly. MEASURED by grep;
  no call site inside the scan path.

The two disagree on endpoint identity, and that disagreement has already cost a mission: the docstring
at `agent.py:2650-2679` records it as MEASURED on mission `90cee81c` -- `_graph_add_url` keys an
endpoint by `host+path` but labels it with the bare `path`, while `_seed_and_project_graph` keys *and*
labels with the whole URL, which produced `https:///benchmark/...` and ten `scope_block` events per
mission. The fix (`_endpoint_url` reading the key) is correct but treats the symptom. Two projections
of the same facts into the same node kinds, with different key rules, is the underlying defect.

`build_from_engagement` is also strictly richer than the live projection: it creates `param` nodes,
`object` nodes via `authz_matrix.is_object_path`, `service` nodes, `persona`/`session` nodes,
`capability` nodes and `finding.enables` edges. The live scan graph gets **hosts, endpoints and bare
findings only** (plus objects via `_graph_add_url`). So the planner that reads the live graph is
reasoning over a materially poorer world model than the one the report renders.

## 1.10 The canonical model, derived

Erwin's instinct, restated: DISCOVER -> ENUMERATE -> GRAPH UPDATE -> PLAN -> SCAN -> PROBE -> ORACLE ->
GRAPH UPDATE -> evaluate newly unlocked information -> targeted rediscovery -> replan -> until
deterministic convergence or budget.

**Assessment: the instinct is right about the shape and wrong about the novelty.** Sections 1.2 and 1.5
show that DISCOVER -> GRAPH UPDATE -> PLAN -> ACT -> GRAPH UPDATE -> REPLAN already exists and already
converges. Three things are genuinely missing, and only three:

1. the fixpoint is computed over planner keys, not over graph facts, so non-URL facts cannot re-arm it;
2. the pipeline stages outside `_execute_plan` (crawl, code-intel, authentication, JS-rendered crawl,
   service packs) are **not reachable from inside the loop**, so "targeted rediscovery" has nothing to
   call;
3. the ranked-action output of the graph planner is not executed.

So the proposal is not a new loop. It is: make the existing loop's convergence test graph-based, make
the fixed stages callable as loop-schedulable actions, and wire the graph planner's output into the
same executor the tool planner uses.

### The model

```
  bootstrap: seed scope -> project scope roots into graph
  |
  +--> ITERATE (single loop, no pass count):
  |      1. PROJECT   every producer's output into AssetGraph (idempotent observe/link)
  |      2. SNAPSHOT  fact-signature F_n = deterministic digest of the graph's fact set
  |      3. PLAN      union of:
  |                     a. planner.next_batch(world derived from graph)      [tool steps]
  |                     b. graph.next_best_actions()                         [capability steps]
  |                     c. rediscovery actions armed by new fact classes     [Section 2]
  |                   minus everything already in the dedup ledger
  |      4. EXECUTE   through the one scoped/HITL-gated pipeline (_run_tool)
  |      5. ORACLE    confirm/deny; write findings + capabilities back into the graph
  |      6. CONVERGE  F_{n+1} == F_n  ->  STOP (deterministic fixpoint)
  |                   budget exhausted ->  STOP (recorded as budget-limited, not converged)
  +----'
  finalize: promotion -> validation -> triage -> report
```

**Convergence criterion (mandatory, replaces the pass count).** A deterministic *fact signature* over
the graph, not a count of anything:

```
F = sha256 over sorted( (kind, key, tested, sorted(enables), sorted(props keys that gate planning)) )
```

An iteration that leaves `F` unchanged has added no new graph facts and is the fixpoint. This is
strictly stronger than `_surface_size()` (1.7) because it sees personas, sessions, capabilities,
params, objects, services, components and tested-flags -- exactly the classes Q-031 enumerates. It is
also cheap (one pass over `_nodes`) and it is *recordable*: the report can state "converged at
iteration 7, fact signature stable" or "stopped at budget, 3 fact classes still growing", which is a
claim the timeline in Section 5 can back with evidence.

**Budget.** Replace the bare `MAX_STEPS = 220` with an explicit, operator-visible budget object
`{steps, wall_seconds, iterations_max}` carried on the agent and surfaced in the mission record. The
iteration cap exists only as a runaway guard and must be recorded as an abnormal termination when it
fires, never as convergence. `recon_cycles` is retired as a control (see below).

**Zero duplicate work.** One dedup ledger keyed on `(tool, canonical_target, salient_input_digest)`
where `canonical_target` is the resolved absolute URL and `salient_input_digest` covers the inputs that
change the test (param set, method, body fields, persona id) and excludes the ones that do not
(intensity labels, cosmetic flags). This subsumes `fresh()`'s `done` set and fixes 1.6.a and 1.6.b in
one place. Persona is *part of the key*: the same probe under persona A and persona B is two distinct
units of work, and today's key cannot express that, which is why Section 4's differentials have to be
driven by a separate subsystem (`bie.py`) instead of by the planner.

**What about "3 cycles"?** Retire it. Concretely: keep the API field for compatibility, ignore it in
`_execute_plan`, and emit an honest info event when a caller passes >1 ("iterative depth is now
governed by graph convergence; recon_cycles no longer affects the run"). Deleting the outer `for cyc`
loop is a behaviour-preserving change today -- 1.3 measured that it contributes one redundant
`generate_playbook`. The UI at `ui/index.html:1326, 2641` and the API at `main.py:65, 396` will need to
follow; that is Coordinator sequencing, not a blocker.

### Where this disagrees with the three sketches offered

- `recon x3 -> enum -> scan -> probe` -- rejected. Any fixed multiple of anything is a pass count, and
  1.3 shows the repo already contains a dead one.
- A fully repeated pipeline -- rejected. Re-running stage 2-7 wholesale is duplicate work by
  construction; the ledger would suppress most of it, which means the passes are theatre. Rediscovery
  must be *targeted* by fact class (Section 2), not wholesale.
- Recon/enum interleaved -- this is already true inside `_execute_plan` (phases A-D of `next_batch` are
  re-entered every inner iteration), so it is not a change; it is a description of the status quo.

### Minimum viable change set for a Builder (extension, not rebuild)

| # | change | file to EXTEND | why not a new module |
|---|--------|----------------|----------------------|
| 1 | `AssetGraph.fact_signature()` | `agent/asset_graph.py` | the graph already owns `stats()`/`to_dict()`; a signature is one more pure reader |
| 2 | dedup ledger keyed on resolved target + salient inputs + persona | `agent/planner.py` `fresh()` + the `done` set in `agent/agent.py:2781` | `fresh()` is already the single chokepoint every planner step passes through |
| 3 | pass `params=ep["params"]` on the injection steps | `agent/planner.py:409-421` | the step dict already supports it; `_run_sqli` already reads `inp["params"]` |
| 4 | delete the outer `for cyc` loop; loop on `fact_signature` + budget | `agent/agent.py:_execute_plan` | same function, fewer lines |
| 5 | execute `graph.next_best_actions()` through `_run_tool` | `agent/agent.py:_execute_plan` + `agent/asset_graph.py` action->tool mapping | `_close_autonomy_loop` already builds the list; move the call inside the loop instead of after it |
| 6 | make the fixed stages loop-schedulable | `agent/agent.py` (existing `_surface_crawl`, `_browser_harvest_surface`, `_recon_code_intelligence`, `_acquire_scan_auth`) | they are already `async` methods on the agent; they need trigger predicates, not rewrites |
| 7 | one graph projection | fold `_seed_and_project_graph` onto `asset_graph.build_from_engagement` | 1.9 -- two key rules for the same node kinds already cost one mission |

Item 5 is the highest value per line: the producer exists, is deterministic, is tested, and is
currently discarded.

## 1.11 The finding that reframes Sections 2-4: there are two planners

`agent/planner.py` imports exactly this:

```
$ grep -n "^import\|^from\|^    import" agent/planner.py | sort -u
21:from __future__ import annotations
23:from urllib.parse import urlparse, urlunparse
25:import dns_recon
26:import surface as surface_mod
27:from scope import PermissionLevel
28:from tools import TOOL_PERMISSIONS
56:import re as _re
563:    import json as _json
```

No `technique_planner`, no `engine_descriptor`, no `asset_graph`. **The planner that executes knows
nothing about observations, preconditions, effects, techniques, capabilities or personas.** It selects
by path regex (`_INTERESTING_EP`, `_XML_SINK`, `_LOGIN_SINK`, `_CHAT_SINK`, `_URLISH_PARAM`, ...) over
`surface.build_inventory`.

Meanwhile the reasoning stack -- `engine_descriptor` (OBSERVATIONS / PRECONDITIONS / EFFECTS / ALWAYS_ON),
`technique_planner.plan` and `plan_graph_authoritative`, `effect_search` (forward search with negative
effects), `asset_graph.next_best_actions` -- is complete, deterministic, tested, and executes nothing:

```
$ grep -rn "effect_search" --include=*.py agent/ | grep -v tests/
agent/main.py:1033:    import effect_search as ES
```

One caller, an HTTP endpoint. Same story as `_next_best` (1.8) and `plan_next`/`apply_result` (1.8).

This is why Q-031's triggers cannot simply be "added to the planner": the planner that runs has no
place to put them, and the planner that could reason about them is not in the execution path. Every
proposal in Sections 2-4 therefore has the same shape -- **connect the existing reasoning stack to the
existing executor** -- and none of them is a new subsystem.

---

# SECTION 2 -- rediscovery triggers, from the graph

## 2.1 The rule

A discovery pass is armed by a **new fact class appearing in the graph**, not by a loop index. Formally,
each trigger is a pure predicate over the graph fact set, evaluated once per iteration in step 3c of
the model in 1.10:

```
trigger := (fact_selector, armed_actions, dedup_scope)
```

`fact_selector` is a query over `AssetGraph` returning nodes that are new-since-last-iteration
(cheap: `first_seen > last_iteration_ts`, already stored on every node, `asset_graph.py:94`).
`armed_actions` are steps handed to the same executor as planner steps. `dedup_scope` is the ledger key
so a trigger firing twice on the same fact is free.

**A trigger the graph cannot express is a design gap, not a rule.** Table 2.3 marks each one.

## 2.2 What the LIVE scan graph actually contains -- MEASURED

The live graph (`tools.graph`) is written by only four producers during the execution loop:

| producer | file:line | node kinds written |
|---|---|---|
| `_seed_and_project_graph` | `agent.py:2626-2643` | `host`, `endpoint`, `finding` (no `enables`, **no edges at all**) |
| `_graph_add_url` | `tools.py:3113-3128` | `host`, `endpoint`, `object` (+ `serves`/`exposes` edges) |
| `_run_service_pack` | `tools.py:2810-2816` | `service` (marked tested immediately), `finding` |
| `archive_intel` / `cloud_intel` | `tools.py:1555, 3358, 3447` | `credential`, `cloud_account`, archived `endpoint` |

`AssetGraph.ingest_intel` -- the method that creates `param`, `component`, `coupon` and harvest
`credential` nodes -- has **one caller**, `agent.py:1202`, inside `_close_autonomy_loop`, which runs
*after* the loop finishes. `codereview_graph.seed` is reachable only through `build_from_engagement`
(endpoint-time). `persona`, `session` and `capability` nodes are created only in
`build_from_engagement` (`asset_graph.py:504-529`) and in `apply_result` (no callers).

Consequence, measured by reproducing exactly what the live producers write and asking the graph what it
recommends:

```
$ MSYS_NO_PATHCONV=1 docker exec apolaki-agent-1 python /tmp/m5.py
stats: {'nodes': 5, 'edges': 0, 'by_kind': {'host': 1, 'endpoint': 1, 'object': 1, 'finding': 1, 'service': 1}, 'untested': 4}
observations: ['has_api', 'has_object_id', 'sql_error_seen']
next_best_actions:
   cross_user_test /rest/basket/1 None
untested services: []
finding.enables: [[]]
```

> **CORRECTION (Q-036 step 1).** `m5.py` above is a hand copy of the producers, and it **overstates
> what the live graph produces**. It seeds an `object` node by hand; no producer inside
> `_seed_and_project_graph` writes one (objects reach the live graph only via
> `tools._graph_add_url`, from a URL that happens to match `authz_matrix.is_object_path`). Driving
> the REAL `BBHAgent._seed_and_project_graph` over two CONFIRMED findings, the recommendation list is
> **empty outright** -- `cross_user_test` was not "the one live tier that works", it was an artifact
> of the repro:
>
> ```
> $ MSYS_NO_PATHCONV=1 docker exec apolaki-agent-1 python /tmp/d5_measure.py
> stats            : {'nodes': 6, 'edges': 0}
> finding.enables  : [[], []]
> chase candidates : 0
> next_best_actions: []
> ```
>
> Two confirmed findings, zero recommended actions. The three defects below are all real and were all
> fixed (D3 `141669f`, D5+D13 `7bcbe8d`, D6 `49310a6`); only this repro's `object` node was wrong. Row
> 10 of the trigger table in 2.3 inherits the same error and is corrected there.
>
> The D6 diagnosis below also needs one word changed, and the word decides which file the fix lives
> in. `_run_service_pack`'s `observe` + `mark_tested` block sits at the **end** of the function, after
> the pack has already run -- so the node is not marked tested too early, it is **created too late**
> and never exists untested at all. The fix therefore belongs at fingerprint time in
> `agent.py:_run_service_packs`, and `tools.py` needed no change. See `handoff/orchestration.md`.

Three separate dead branches, all VERIFIED DEFECTS:

- **`chase_capability` is dead live.** `next_best_actions` iterates `f.get("enables")`
  (`asset_graph.py:291`). `_seed_and_project_graph` observes findings with `family=` and **no
  `enables=`** (`agent.py:2642-2643`), so the list is always empty. The highest-utility action tier --
  "a confirmed finding enables X, chase it" -- cannot be produced during a scan.
- **`run_service_pack` is dead live.** The tier reads `self.untested("service")`
  (`asset_graph.py:300`), but the only live writer creates the node and calls `mark_tested` two lines
  later (`tools.py:2810-2812`), so the set is empty by construction.
- **`authenticated` is unreachable from the live graph.** `to_observations` requires a
  `capability:session_acquired` node (`asset_graph.py:238-241`); capabilities are written to
  `investigation.InvestigationState` via `tools.state.add_capability` (13 call sites) and **never** to
  the graph. `derive_observations(authenticated=bool(tools._sessions))` (`agent.py:1219`) papers over it
  in the flat compatibility path -- inside `_close_autonomy_loop`, which executes nothing.

So today exactly one of the fifteen trigger classes below can influence a graph-driven decision.

## 2.3 Trigger table

Legend for "representable today": **YES** = a node/edge kind exists AND a live-scan producer writes it;
**PARTIAL** = the kind exists but nothing writes it during the loop, or it is expressed outside the
graph; **NO** = no representation.

| # | new fact class | representable today | evidence | what it should arm | change needed |
|---|---|---|---|---|---|
| 1 | hostname | **YES** | `host` nodes, `agent.py:2629-2633`; become `roots` via `_graph_primary_state`, and phase A re-fires per root (`planner.py:239`) | passive recon set, `run_httpx`, `http_probe`, `run_katana` on the new host | none -- this is the one trigger that already works end to end. Note the amplification: every discovered subdomain becomes a full recon root |
| 2 | route / endpoint | **YES** | `endpoint` nodes, `tools.py:3120`, `agent.py:2637-2640` | phases C/D/E for the new inventory entry | none for URLs; see 1.6.b for the parameter loss |
| 3 | API | **YES (by accident)** | `to_observations` sets `has_api` from an endpoint label substring (`asset_graph.py:255`), which feeds only the advisory planner; the executor fires on `_INTERESTING_EP` (`planner.py:83`) | `fetch_openapi`, `run_graphql`, REST authz sweep | unify: one API-detection fact, consumed by both planners |
| 4 | schema (OpenAPI / GraphQL / JSON body) | **NO** | no `schema` node kind; `fetch_openapi` / `run_graphql` results reach `tools.recon`/`tools.urls` only | derive `param` nodes with type + required + location(body/query/header) and arm the injection engines on **body** params | new kinds `schema`, and `param.props{location,type,required}`. Highest-value gap in the table: body parameters are the largest untested surface class and the planner cannot currently name one |
| 5 | application state | **NO** | `workflow.py:161` writes capabilities to `tools.state`, not the graph | re-crawl in the new state; re-run workflow-abuse and business-logic engines | new kind `app_state` with `props{reached_by, persona}`; edge `persona -[reached]-> app_state` |
| 6 | privilege / role | **PARTIAL** | `role` + `permission` nodes exist but are written only by `cloud_iam.py:521-527` (AWS IAM). Application privilege lives in `Persona.rank`/`proven_privilege` (`personas.py:118-127`) and never reaches the graph | BFLA sweep, admin-surface discovery, privilege differential | reuse the existing `role`/`permission` kinds for app roles rather than inventing new ones |
| 7 | persona | **PARTIAL** | `persona` node exists (`asset_graph.py:504`) but only in `build_from_engagement` | authenticated re-crawl as that persona; every differential in Section 4 | write personas into the LIVE graph at mint time (Section 3) |
| 8 | credential | **PARTIAL** | `credential` nodes exist and are hashed (`asset_graph.py:218`, `archive_intel.py:57`); `ingest_intel` runs post-loop; `_do_scan_auth` writes **no** graph node at all | validation attempt -> persona mint -> authenticated discovery | write a `credential` node (vault ref, never the secret) at discovery time, from inside the loop |
| 9 | authenticated session | **PARTIAL** | `session` node only in `build_from_engagement`; `capability:session_acquired` never written live -- MEASURED 2.2 | unlock everything gated on `authenticated`; authenticated re-crawl; session-lifecycle engine | mirror `PersonaManager.capabilities()` into `capability` nodes at the moment they become true |
| 10 | object type | **YES (instance-level)** | `object` nodes per URL via `authz_matrix.is_object_path` (`tools.py:3126`) -- from `_graph_add_url` ONLY; `_seed_and_project_graph` writes none, so 2.2's `cross_user_test` row was a repro artifact (see the correction there) | `cross_user_test` -- the one live tier whose input a producer actually writes | add `props["object_template"]` (e.g. `/rest/basket/{id}`) so one confirmed BOLA generalizes to the type instead of re-testing every instance |
| 11 | tenant | **NO** | `Persona.tenant` exists (`personas.py:45`) and `tenant_pair()` (`personas.py:180`); neither reaches the graph | cross-tenant differential | `tenant` kind, or `persona.props["tenant"]` + an edge `persona -[belongs_to]-> tenant` |
| 12 | technology / component | **PARTIAL** | `component` kind exists but only via post-loop `ingest_intel`; `run_fingerprint` results never become nodes | version-specific nuclei templates, known-CVE probes, `vulnerable_component` | have `run_fingerprint` write `component` nodes directly |
| 13 | protocol / service | **PARTIAL -- and inverted** | `service` node is written *after* the pack runs and marked tested in the same breath (`tools.py:2810-2812`), so `untested("service")` is always empty -- MEASURED 2.2 | `run_service_pack` for the discovered protocol | write the `service` node at **fingerprint** time (untested), mark tested when the pack completes. Two-line change, revives a whole action tier |
| 14 | attack-path prerequisite | **PARTIAL** | `capability` + `finding.enables` exist; live findings carry no `enables` -- MEASURED 2.2 | `chase_capability` | pass `enables=` in `_seed_and_project_graph`, reusing `asset_graph._FINDING_ENABLES` + `_content_enables` (`asset_graph.py:420-441`) which already compute it correctly |
| 15 | probe result exposing new surface | **YES** | new URLs from any probe go through `_add_urls` -> `_graph_add_url`; findings become nodes | whatever classes 1-14 the new facts belong to | none, once 1-14 are representable |

## 2.4 What STOPS rediscovery

Nothing in this section overrides the convergence rule in 1.10. A trigger arms actions; the actions
produce facts; if an iteration produces no new facts the signature is unchanged and the loop stops.
Three additional dampers, all necessary and all derivable from data the graph already holds:

- **Per-fact-class arming budget.** A trigger fires at most N times per class per engagement (default
  from the existing `CAP_*` family in `planner.py:38-48`, which is the right precedent -- do not invent
  a second cap vocabulary).
- **Confidence floor.** `decayed_confidence` (`asset_graph.py:181-193`) already exists and is already
  used for ranking. Use it as a gate too: a fact below a floor arms nothing. This is what stops a
  low-confidence permuted subdomain (`recon_expand.py:138` observes at confidence 0.2) from triggering
  a full recon root, which is trigger #1's amplification risk.
- **Negative effects.** `engine_descriptor.EFFECTS[*]["invalidates"]` (`engine_descriptor.py:175-208`)
  already encodes that e.g. `weak_password_reset` destroys `authenticated`. A trigger that would run an
  action invalidating a capability another armed action requires must be ordered after it --
  `effect_search.plan` already implements exactly this and is unwired (1.11).

---

# SECTION 3 -- credential -> validated session -> persona, event-driven

## 3.1 Audit: what exists (and it is a lot)

### `agent/personas.py` -- keep as the canonical identity model, extend only

This module is the strongest piece of the auth stack and needs almost nothing:

- Persona 0 exists by construction: `PersonaManager.__init__` seeds `anonymous` at rank 0
  (`personas.py:79`), and `add()` protects it -- `if role == ANON: rank = RANK_ANON` (`personas.py:90-91`).
- Privilege is **proven, never asserted**: `add()` caps at `RANK_USER` (`personas.py:92-93`); only
  `prove_privileged(role, evidence)` reaches rank 2, and it refuses without evidence
  (`personas.py:118-127`).
- Secrets are already segregated: `headers` and `account` are marked SERVER-SIDE ONLY
  (`personas.py:47-48`) and `safe()` / `to_dict()` emit role / rank / identity-label / method /
  has_session only (`personas.py:66-72, 255-257`).
- `tenant` is already a first-class field (`personas.py:45`) with `tenant_pair()` (`personas.py:180-191`).
- The sacrificial-persona carve-out for CWE-613 is already correct and already reasoned about in two
  places (`personas.py:32-38, 150-157, 224-253`).
- `capabilities()` (`personas.py:194-208`) already computes exactly the capability vocabulary Section 2
  wants in the graph: `session_acquired`, `account_created`, `second_persona_available`,
  `privileged_persona_available`, `tenant_boundary_available`, `object_ownership_mapped`.

### `agent/register.py` -- account minting

`parse_register_form` / `adapt_password` / `gen_account` / `build_registration_payload` / `register`
(`register.py:91-261`), plus `detect_blockers` (`register.py:40`) which names captcha/MFA/email/invite
walls rather than failing silently. Feeds `Persona.blocked`. No change needed.

### `agent/session_lifecycle_tool.py` -- CWE-613, shipped this week

Pure-function engine: `build_discriminator` / `still_authenticated` / `logout_accepted` /
`password_change_accepted` / `declared_lifetime` (`session_lifecycle_tool.py:217-350`), plus
`invented_headers`/`invented_cookies` (176-215) as the negative control. It already models the exact
thing Q-032 calls "lifecycle-aware". The design below should treat this module as the **session
validity oracle**, not just as a finding producer -- `still_authenticated(resp, disc)` is precisely the
"is this handle still live?" predicate a session store needs before every replay.

### `agent/vault.py` -- secret storage by reference, already built

`Vault.put(mission_id, role, secret) -> ref`, `get(ref)`, `ref()` / `parse_ref()` / `is_ref()` /
`redact()` (`vault.py:131-205`), encrypted at rest. Already used for cross-mission credential reuse
(`agent.py:1447, 1763, 1854`; `main.py:2068`). The reference format is the secret-safe handle Q-032
asks for. It exists.

### `agent/bie.py` -- runtime persona swap

`object_candidates` / `param_candidates` build owner-vs-attacker pairs from two personas' observed
URLs; `judge` / `judge_param_swap` are the differential oracles with anon and nonexistent-id controls;
`redact_headers` (`bie.py:47`) already exists. Detail in Section 4.

## 3.2 Audit: how a session actually reaches the wire today -- the core defect

```
$ grep -c "self.session_headers" agent/tools.py
50
```

`ToolRegistry.session_headers` is **one global dict of raw headers** (`tools.py:1029`), splatted into
requests at 50 sites in `tools.py` in the form
`headers = {"User-Agent": _UA, **(self.session_headers or {})}` (e.g. 1194, 1249, 1415, 1500, 3160,
3853, 4110, 4399, 4498, 4577, 4623 ...). It is set once, at `agent.py:1422`:

```
1421   if self.authenticated_scan and verified:
1422       self.tools.session_headers = {**sh, **sess}
```

This is, precisely and literally, the pattern Q-032 rules out: **one captured session sprayed through
every scanner**. Concretely:

- **Not persona-bound.** There is one session for the whole registry. `_sessions[role]` exists
  (`personas.py:238-247`) and is honoured only by the handful of tools that accept `session=role`;
  the other 50 sites use the global.
- **Not origin-bound.** No site checks the target's origin against the origin the session was issued
  for. A scope containing two hosts will send host A's cookie to host B. (MEASURED by code read of all
  50 sites; not exercised at runtime, so the *impact* is UNVERIFIED -- but the absence of the check is
  not.)
- **Not lifecycle-aware.** Nothing re-validates the session before a replay, although
  `session_lifecycle_tool.still_authenticated` is sitting right there. A session that expires mid-scan
  turns every subsequent authenticated probe into a silent false negative that reads exactly like a
  clean result -- the recorded "guards that check declarations" failure shape.
- **Raw, not a handle.** `Persona.headers` is a plain dict; `_sessions[role]` is a plain dict;
  `self._scan_credential = "%s:%s" % (user, pw)` (`agent.py:1332`) and
  `tools._fixation_credential = (user, pw)` (`agent.py:1335`) hold plaintext on live objects. The vault
  is used for *persistence* (`main.py:2068`) but not for *in-flight* handling.

## 3.3 Audit: the timing defect

`_acquire_scan_auth` runs at `agent.py:2534` -- pipeline stage 8, before every discovery stage that
could find a credential (1.1). Its own credential sources are:

```
1308   creds = list((intel.with_sources("credential") or {}).keys())   # this engagement's harvest so far
1310-1320                                                              # a prior engagement's snapshot
1322   creds = await self._probe_for_creds(base)                       # a bounded probe of likely pages
1327   user, pw = creds[0].split(":", 1)                               # <-- ONE candidate, the first
```

So a credential produced *later* by `run_sqli`'s UNION extract (which calls
`state.add_capability(PASSWORD_HASH_OBTAINED, ...)`, `tools.py:6573`), by `exposed_files_harvest`
(`tools.py:1453`), by `run_js_review`, by a source-map, or by the cloud packs
(`tools.py:6191, 6221`) **can never be used**. There is no path back to stage 8. This is the exact
thing Q-032 forbids ("credentials found in iteration 1 unlock authenticated work as soon as
validated") -- except the repository's version is worse than a cycle-number gate: it is a
one-shot gate at a fixed pipeline position, and it consumes only `creds[0]`.

What it does do well, and must be preserved: it *verifies* before claiming (`acquire_session`, then
`verified = bool(sess)`, `agent.py:1340-1348`), it grades the finding on that verification
(`"confidence": "confirmed" if verified else "candidate"`, line 1375), it redacts the password out of
the reproduction (`<REDACTED_PASSWORD>` at 1361-1362, "held only in the vault" at 1366), and applying
the session to the scan is an explicit operator opt-in (`self.authenticated_scan`, line 1421) rather
than an automatic behaviour.

## 3.4 Design: the event-driven credential artery

Nothing below is a new subsystem. Every box names the existing module it extends.

```
  [any producer, any iteration]                 EXTEND: nothing -- these already exist
    intel harvest / js_review / sourcemap / sqli UNION / exposed-files / cloud pack /
    prior-mission snapshot / operator-supplied
        |
        |  emits CREDENTIAL CANDIDATE {identity, secret, observed_at, source, evidence_ref}
        v
  [1] VAULT ON ARRIVAL                          EXTEND: agent/vault.py (put/ref exist)
        secret -> vault.put(mission, key) -> ref "vault://mission/key"
        the raw value NEVER leaves this call; every downstream structure holds the ref
        |
        v
  [2] GRAPH FACT                                EXTEND: asset_graph.observe (kind exists)
        observe("credential", sha256(identity+origin)[:12],
                label="credential:<identity>", source=<producer>,
                props={vault_ref, origin, identity, validated=False})
        -> this is the fact that ARMS trigger #8 in Section 2. Writing it is what makes the
           whole artery event-driven; nothing else in the design needs a schedule.
        |
        v
  [3] DETERMINISTIC VALIDATION                  EXTEND: tools acquire_session + _do_scan_auth 1340-1348
        ONE login attempt per (credential, origin) -- the existing anti-brute discipline.
        Oracle = a session artefact is issued AND an authenticated-only request loads as that
        identity (the oracle _do_scan_auth already writes into success_oracle, agent.py:1404).
        Outcome is recorded either way: validated | rejected | blocked(<named wall>).
        |
        +-- rejected/blocked -> graph props{validated:False, outcome} ; STOP. No persona.
        |
        v
  [4] AUTH-MECHANISM IDENTIFICATION             EXTEND: tools._session_shapes (already captured)
        _session_shapes[role] already records {method, action, content_type, user_field,
        pass_field, auth_kind} (agent.py:1354-1364). Promote it from a report input to a
        first-class SessionRecipe stored by ref -- it is the refresh instruction.
        |
        v
  [5] ISOLATED AUTHENTICATION CONTEXT           EXTEND: personas.PersonaManager
        Each persona authenticates in its own context: own cookie jar, own browser context
        (bie.py already opens per-persona browser contexts), own storage. Never the global.
        |
        v
  [6] IDENTITY VALIDATION                       EXTEND: session_lifecycle_tool.build_discriminator
        build_discriminator(authed, control, identity_markers) already produces the exact
        artefact needed: a deterministic test that THIS response belongs to THIS identity.
        Store the discriminator with the persona. It is reused in [8] and in Section 4.
        |
        v
  [7] SESSION HANDLE                            NEW, but ~40 lines, on top of vault + personas
        SessionHandle = {handle_id, persona_role, origin_scope, vault_ref, recipe_ref,
                         discriminator, issued_at, declared_lifetime, last_validated_at,
                         state: live|stale|dead}
        declared_lifetime comes from session_lifecycle_tool.declared_lifetime (line 318).
        NOTHING outside the transport layer ever sees the header values.
        |
        v
  [8] BIND persona + identity + tenant + role   EXTEND: personas.add / prove_privileged
        rank stays PROVEN-only. tenant from the app's own tenant marker, never guessed.
        |
        v
  [9] WRITE CAPABILITY INTO THE GRAPH           EXTEND: asset_graph (kinds exist, writer missing)
        observe("persona", role, props={rank, tenant, identity_label, handle_id})
        observe("session", handle_id, props={origin_scope, state})
        link(persona, session, "authenticated_as")
        for cap in PersonaManager.capabilities():        # personas.py:194-208, already correct
            observe("capability", cap, tested=True, confidence=CONFIRMED)
        -> to_observations() now yields `authenticated` (asset_graph.py:239-241), which is the
           single line that unblocks every precondition gated on it. This is the fix for the
           MEASURED dead branch in 2.2.
        |
        v
  [10] PLANNER SEES THE UNLOCKED SURFACE        EXTEND: the loop from 1.10
        The new facts change the fact signature -> the loop does not converge -> it re-plans.
        No cycle number is consulted. This is the whole point.
        |
        v
  [11] AUTHENTICATED DISCOVERY, PERSONA-SCOPED  EXTEND: _authenticated_recrawl (agent.py:1691)
        already crawls per-persona. Endpoints discovered are attributed to the persona that
        saw them (Section 4).
        |
  [12] ANONYMOUS TESTING CONTINUES              EXTEND: nothing -- guaranteed by design
        Persona 0 is never replaced (personas.py:79-91) and is never bound to a handle.
        Because the dedup ledger key includes persona (1.10), an anon probe and an authed
        probe of the same endpoint are two distinct work units and neither suppresses the other.
```

### Transport rule (this is the change that retires the global)

Every outbound request resolves headers as `resolve(handle_id, target_url)`:

1. refuse if `urlparse(target).netloc` is not in `handle.origin_scope` -> **origin binding**;
2. refuse if `handle.state != live`; if `now - last_validated_at > revalidate_interval`, run the
   discriminator once and update state -> **lifecycle awareness**;
3. on `stale`, re-run the stored recipe to mint a fresh handle -> **refreshable**;
4. only then read the vault and materialize headers, inside the transport call.

`tools.session_headers` stays as a deprecated compatibility shim mapping to the anonymous-or-default
handle, so the 50 call sites migrate incrementally rather than in one commit. **A Builder must not
create a parallel HTTP path**: the resolution belongs in the existing header-building chokepoints in
`tools.py`, and the 50 sites should collapse onto a single `self._headers_for(url, persona=...)`
helper rather than each learning the new rule.

### Replayability

A finding's reproduction cites `handle_id` + `recipe_ref`, never a header value. Re-running the recipe
regenerates a session; `bie.retest_recipe` / `retest_verdict` (`bie.py:581-686`) already implement
recipe-driven retest and are the model to follow. The existing redaction discipline
(`vault.redact`, `bie.redact_headers`, `_do_scan_auth`'s `<REDACTED_PASSWORD>`) is retained and becomes
enforceable rather than per-call-site discipline, because the raw value no longer exists outside the
transport layer.

---

# SECTION 4 -- multi-persona coexistence and differential testing

## 4.1 What `bie.py` already gives us -- do not rebuild any of this

`_confirm_browser_persona_bola` (`tools.py:2506-2546`) + `bie.run_persona_swap`:

- **Real per-persona browser isolation, already implemented.** "Two personas get their own real browser
  context (separate cookie jar + storage + session, seeded with the app's OWN login-response state)"
  (`tools.py:2509-2510`); storage is carried per role in `self._session_state[role]` (`tools.py:2531`).
  Section 4's "isolate browser context / cookies / storage per persona" is **done** for the pair BIE
  runs on.
- **Hypotheses from observation, not id-spraying.** The object requests the app itself makes at runtime
  become the candidates (`tools.py:2511`), via `bie.object_candidates` / `param_candidates`
  (`bie.py:196, 774`). This is the recorded "probe with observed values" discipline, already enforced.
- **A deterministic oracle with three negative controls.** `bie.judge` / `judge_param_swap`
  (`bie.py:236, 817`) compare owner baseline vs attacker mutation against anonymous, an implausible id,
  and the attacker's own object; "the browser never gets a vote" (`tools.py:2514`).
- **Three differentials already covered**: `browser_persona_bola` (userA<->userB object read),
  `client_side_authz` (rendered control surface per persona), `client_supplied_identity_param`
  (identity-param tampering) -- all three declared and wired in `engine_descriptor.ALWAYS_ON`
  (`engine_descriptor.py:117-122`).
- **Evidence and replay.** `browser_evidence`, `replay_script`, `retest_recipe`, `retest_verdict`,
  `redact_headers`, `drive_report`, `classify_failure` (`bie.py:47, 319, 352, 581, 610, 687, 705`).
- **No island.** BIE's runtime traffic joins the one engagement ledger tagged `engine="browser"`
  (`tools.py:2536-2546`).

`_do_persona_authz` (`agent.py:1835-2212`) additionally already delivers: persona reacquisition from
vaulted recipes (step 0), signup minting with named blockers (step 1), **per-persona authenticated
re-crawl** (step 3, `agent.py:1977-1983`), the operation set (step 4), the HTTP authorization matrix
including anon baseline (step 5, `agent.py:2007-2016`), create-object IDOR and read-object BOLA (5c/5d),
and BIE (5e).

## 4.2 What is genuinely missing

| # | gap | evidence | severity |
|---|-----|----------|----------|
| 1 | **Personas exist for one phase, not for the engagement.** Everything above happens inside `_do_persona_authz`, at pipeline stage 8. The main execution loop (stage 11) runs afterwards with a single global `session_headers` and no persona concept at all (3.2). Every probe the planner schedules is single-identity. | `planner.py` has no persona vocabulary (1.11); `tools.session_headers` is one dict (3.2) | HIGH -- this is what caps the differential coverage at whatever `_do_persona_authz` thought of |
| 2 | **Personas are invisible to the graph.** `pm.capabilities()` is written to `tools.state`, not the graph -- and the comment says otherwise: `# 6) record the capabilities this phase unlocked (feeds the planner + attack graph)` (`agent.py:2159`) followed by `self.tools.state.add_capability(...)` (`agent.py:2163`). The planner and the attack graph never see it. | MEASURED 2.2 | HIGH -- this is a declaration that is not a fact, the recorded failure shape |
| 3 | **BIE runs on ONE pair, once, capped at 3 candidates.** `pair = pm.same_privilege_pair()` (`agent.py:2009`), fired once at 5e (`agent.py:2126`), `max_candidates=3` default (`tools.py:2533`). The user<->admin, tenantA<->tenantB and owner<->non-owner pairs never reach it. | `agent.py:2126-2135`, `tools.py:2533` | MEDIUM -- the engine generalizes; the invocation does not |
| 4 | **Discovered surface is not attributed to the persona that saw it.** `_authenticated_recrawl` merges every persona's discoveries into one flat `tools.urls` (`agent.py:1980-1983`). "Endpoint X is reachable by user_a but not by user_b" -- the raw material of authz differentials -- is destroyed at merge time. | `agent.py:1977-1983` | HIGH -- this is a *fact class* being discarded, not just an untested endpoint |
| 5 | **Object ownership is persona-local, not graph-global.** `Persona.objects` (`personas.py:50, 129`) records what a persona owns; the graph's `object` nodes carry no owner. | `personas.py:129-132` vs `tools.py:3126` | MEDIUM |
| 6 | **Tenant never reaches the graph.** `Persona.tenant` and `tenant_pair()` exist; no tenant fact is ever written. | Section 2 trigger #11 | MEDIUM |
| 7 | **No pre/post transition record.** Nothing marks "this endpoint was tested at anon and again after auth". Section 5 cannot render a transition that was never recorded. | Section 5 | MEDIUM |

## 4.3 Design: persona as a first-class dimension of the work ledger

The single structural change, from which every differential falls out:

> **The dedup ledger key includes the persona** (already stated in 1.10). A probe of endpoint E is not
> one work unit; it is one work unit *per persona in the applicable persona set*.

That one change turns the differentials from bespoke engines into a property of scheduling:

| differential | how it arises | already have | need |
|---|---|---|---|
| anon <-> auth | persona 0 is always in the set; persona 0 is never replaced (`personas.py:79-91`) | matrix anon baseline (`personas.py:210-221`) | ledger keyed by persona |
| userA <-> userB | `same_privilege_pair()` (`personas.py:159`) | matrix + BIE | run on every object endpoint, not 3 |
| user <-> admin | `privileged_role()` (`personas.py:174`), proven only | BFLA in the matrix | route the admin persona through BIE too |
| tenantA <-> tenantB | `tenant_pair()` (`personas.py:180`) | pair selection exists | tenant fact in the graph (#6) |
| owner <-> non-owner | `Persona.objects` (`personas.py:50`) | `add_object` | object ownership as a graph edge (#5) |
| pre/post-auth | the same ledger entry under persona 0 and under persona N | -- | transition record (#7) |
| pre/post-privilege | `prove_privileged` is a timestamped event | -- | emit it as a recorded event (Section 5) |

### Per-persona isolation contract

Each persona owns, and never shares:

| dimension | today | proposal |
|---|---|---|
| browser context | isolated inside BIE only (`tools.py:2509`) | promote BIE's per-persona context to an engagement-level `PersonaContext`; BIE becomes a consumer, not the owner |
| cookies / session | `_sessions[role]` (raw) | `SessionHandle` per persona (Section 3 step 7) |
| token handles | none | `handle_id`, vault-backed |
| storage | `_session_state[role]` (`tools.py:2531`) -- exists already | move alongside the handle |
| identity / tenant / role | `Persona.identity/tenant/rank` (`personas.py:42-52`) -- exists | mirror into the graph |
| discovered states | not tracked | `app_state` nodes (Section 2 #5), edge `persona -[reached]-> app_state` |
| reachable endpoints | **merged and lost** (#4) | edge `persona -[can_reach]-> endpoint` with the observed status; the differential is then a graph query, not a bespoke engine |
| object ownership | `Persona.objects` (#5) | edge `persona -[owns]-> object` |

### Where this must NOT go

Do not build a "persona-aware scanner". The persona set belongs in the *plan* (which units of work
exist) and in the *transport* (which handle a unit resolves), not inside each of the ~60 engines. An
engine keeps taking a URL; the executor decides which persona it runs as. That is what keeps this an
extension of `_run_tool` + `fresh()` rather than 60 edits.

---

# SECTION 5 -- report chronology and provenance

## 5.1 The constraint that shapes the design

`report.py` was corrected twice in the last week for asserting things it had not verified:

```
$ git log --oneline -12 -- agent/report.py
837b1f0 Apolaki: stop claiming a negative control that never ran (#123, Codex claim 7)
...
707b3b9 Apolaki: the proof gate did not survive the renderer (#123, Q-000)
5af0af8 Apolaki: one definition of "confirmed", all four forks (#123, Q-000 follow-up)
```

So the timeline must be **incapable** of asserting an event that was not recorded. The design rule:

> **The renderer may only read the event log. It may never derive an event.**
> If an event is not in the log, the timeline shows a gap, not an inference.

A derived timeline -- "we authenticated, therefore a session was created at about this time" -- is the
same defect class as 837b1f0, and it would be *harder* to catch because a plausible timeline looks
correct.

## 5.2 The substrate already exists

```
CREATE TABLE IF NOT EXISTS logs(
    id INTEGER PRIMARY KEY AUTOINCREMENT, mission_id TEXT,
    etype TEXT, data TEXT, created_at TEXT);
CREATE INDEX IF NOT EXISTS ix_log_mid ON logs(mission_id);
```
(`agent/db.py:49-51, 68`)

Append-only, per-mission, typed, timestamped, indexed, with `db.add_log(mid, etype, data)` /
`db.get_logs(mid, limit)` (`db.py:271-281`). Currently only five event types are emitted:

```
$ grep -rhon 'add_log([^,]*, *"[a-z_]*"' --include=*.py agent/ | grep -v tests/ | sed 's/.*, *"//;s/"//' | sort | uniq -c | sort -rn
      8 tool_call
      5 tool_result
      3 tool_error
      2 scope_block
      1 error
```

**A Builder must add event types to this table. Building a second timeline store would be an island.**

## 5.3 Event vocabulary to add

Every event: `{iteration, ts, producer, evidence_ref, ...typed payload}`. `iteration` is the loop index
from 1.10 -- which is a *real* number in the new model, unlike `recon_cycles`.

| etype | payload (all redacted-by-construction) |
|---|---|
| `iteration_begin` / `iteration_end` | `{n, fact_signature, facts_added, converged: bool}` |
| `fact_observed` | `{kind, key, source, confidence}` -- one per new graph node; this is what makes "discovery iteration" a fact rather than a narrative |
| `credential_found` | `{identity_label, origin, source_producer, vault_ref, evidence_ref}` -- **never the secret** |
| `credential_validated` | `{identity_label, origin, outcome: validated\|rejected\|blocked, wall, oracle, evidence_ref}` |
| `persona_created` | `{role, rank, method, identity_label, tenant, sacrificial}` -- exactly `Persona.safe()` (`personas.py:66-72`), which is already the redacted view |
| `authentication` | `{role, handle_id, mechanism, origin_scope, discriminator_id}` |
| `privilege_proven` | `{role, from_rank, to_rank, evidence}` -- emitted from `prove_privileged` (`personas.py:118`), the only place rank can rise |
| `session_state_change` | `{handle_id, from, to, reason}` -- live/stale/dead/refreshed |
| `capability_unlocked` | `{capability, by_event_id}` |
| `surface_unlocked` | `{persona, endpoints_added, first_3}` |
| `finding_enabled_by` | `{finding_id, enabling_event_id}` -- the link that answers "which transition made this finding possible" |
| `attack_path_changed` | `{added, removed, top_utility}` from `next_best_actions` |

## 5.4 Redaction, enforced structurally rather than by discipline

Three layers, two of which already exist:

1. **Nothing raw is ever produced.** After Section 3 step 1, the only representation of a secret
   outside `vault.py` is a ref. An event physically cannot carry a secret it does not have.
2. **`vault.redact()`** (`vault.py:203`) applied on the write path of `add_log`, as a belt-and-braces
   pass, plus `bie.redact_headers` (`bie.py:47`) for header maps.
3. **A negative-control test**: assert that for a mission where a known credential value was used,
   that byte string appears in **zero** rows of `logs`, `findings`, `exchanges`, the HTML report, the
   Markdown report and the JSON export. This is the guard that would actually catch a regression --
   a test that only checks "the redaction function was called" is the declaration-checking failure
   shape this project has already been bitten by.

## 5.5 What the report renders

Two views over the same log, both read-only:

**A. Capability timeline** -- one row per recorded event, columns: iteration, timestamp, producer,
event, subject (role / identity label / handle id), evidence reference. Gaps are shown as gaps.

**B. Coverage, split by identity.** Anonymous and authenticated coverage reported **separately**, never
summed. `coverage_rollup` (`report.py:269`) and `coverage_gaps` (`report.py:1368`) already exist and
already take an `authenticated` argument -- extend those, do not add a third coverage computation.

**C. Attack-path evolution** -- the `attack_path_changed` series, so the report shows the graph's
recommendation set changing as capabilities unlocked, rather than only its final state.

## 5.6 The honesty precedent to follow

`auth_requests_note` (`report.py:1603-1623`) is the model. It takes the raw counters and, when
`attempted > 0 and succeeded == 0`, distinguishes "session rejected (401/403)" from "session worked but
every candidate returned 4xx -- **this is NOT an authentication failure**" from "no authenticated
request reached a candidate endpoint". It refuses to let a bare number be misread, and it says
"unknown" when the status distribution does not support either reading.

Every timeline row needs the same treatment: an event that was recorded but whose *outcome* was not
observed must render as "attempted, outcome not observed", never as success and never as failure.
`_artery_with_note` (`report.py:1626-1635`) shows the wiring pattern -- annotate the record on the way
out, do not annotate at the render site.

---

# SECTION 6 -- defect classification

`file:line` on every entry. Each proposal names the module to EXTEND.

## 6.1 VERIFIED DEFECTS

| id | defect | file:line | evidence | extend |
|----|--------|-----------|----------|--------|
| D1 | The outer `recon_cycles` loop is inert -- it contributes one redundant `generate_playbook` per cycle and the third cycle never runs | `agent/agent.py:2781-2793, 2853` | MEASURED 1.3 | `_execute_plan` -- delete the loop, keep the inner one |
| D2 | Dedup key is namespaced by call site, so the same URL is fetched more than once. 8 `http_probe` steps for 5 distinct URLs | `agent/planner.py:266, 314, 329, 349` | MEASURED 1.6.a | `planner.fresh()` -- key on resolved target |
| D3 | The planner knows an endpoint's full parameter set and passes only one; `_run_sqli` therefore never tests the others | `agent/planner.py:409-421` vs `agent/tools.py:6583` | MEASURED 1.6.b (`params: ['id','q']`, `params_of(example) == ['id']`) | add `params=ep["params"]` to the existing step dicts -- `_run_sqli` already reads `inp["params"]` |
| D4 | `run_httpx` dedup key is the target **count** | `agent/planner.py:259` | code read | same ledger as D2 |
| D5 | `chase_capability` -- the highest-utility action tier -- can never fire during a scan, because live findings are projected without `enables` | `agent/agent.py:2642-2643` vs `agent/asset_graph.py:291` | MEASURED 2.2 (`finding.enables: [[]]`) | pass `enables=` in `_seed_and_project_graph`, computed by the existing `_FINDING_ENABLES` + `_content_enables` (`asset_graph.py:420-441`) |
| D6 | `run_service_pack` tier can never fire, because the `service` node is created and marked tested in the same breath | `agent/tools.py:2810-2812` vs `agent/asset_graph.py:300` | MEASURED 2.2 (`untested services: []`) | write the node at fingerprint time; `mark_tested` when the pack completes |
| D7 | The `authenticated` observation is unreachable from the live graph -- capabilities go to `InvestigationState`, never to the graph | `agent/agent.py:2163`, `agent/tools.py` (13 `add_capability` sites) vs `agent/asset_graph.py:238-241` | MEASURED 2.2 | mirror `PersonaManager.capabilities()` into `capability` nodes |
| D8 | A comment asserts a wiring that does not exist: `# 6) record the capabilities this phase unlocked (feeds the planner + attack graph)` immediately above a write to `tools.state` | `agent/agent.py:2159-2163` | code read; D7 is the same bug seen from the graph side | fix with D7, and fix the comment |
| D9 | One global raw-header session sprayed through 50 call sites; not persona-bound, not origin-bound, never re-validated | `agent/tools.py:1029` + 50 sites; set at `agent/agent.py:1422` | MEASURED (`grep -c` = 50) | collapse onto one `_headers_for(url, persona=)` chokepoint; back it with `SessionHandle` + `vault` |
| D10 | Authentication is a one-shot pipeline stage before every discovery stage, and consumes `creds[0]` only | `agent/agent.py:2534` (position), `agent/agent.py:1327` (`creds[0]`) | code read of `run()` ordering | make it graph-triggered (Section 3), fire per credential fact |
| D11 | Per-persona reachability is destroyed at merge: every persona's authenticated crawl lands in one flat `tools.urls` | `agent/agent.py:1977-1983` | code read | `persona -[can_reach]-> endpoint` edges in the existing graph |
| D12 | Two graph-construction paths with different endpoint identities, one of which has already cost a mission | `agent/tools.py:3120` vs `agent/agent.py:2637-2640`; documented MEASURED in `agent/agent.py:2650-2679` | the repo's own recorded measurement (mission `90cee81c`) | fold `_seed_and_project_graph` onto `build_from_engagement` |
| D13 | `_seed_and_project_graph` writes no edges at all -- host/endpoint/finding land unconnected | `agent/agent.py:2626-2643` (no `g.link` call) | MEASURED 2.2 (`edges: 0` when reproducing its writes) | reuse `build_from_engagement`'s linking (D12) |
| D14 | `MAX_STEPS` is not re-checked inside the batch execution loop, so the budget overshoots by up to `len(batch)-1` | `agent/agent.py:2794, 2841-2848` | code read | one condition in the existing loop |
| D15 | Convergence is measured by `_surface_size()`, four flat counters that cannot see personas, sessions, capabilities, params, objects, services or components | `agent/agent.py:3295-3297`, used at `2791, 2853` | code read | `AssetGraph.fact_signature()` |

## 6.2 MISSING EVIDENCE (assert nothing until measured)

| id | claim that needs a measurement | how to measure |
|----|-------------------------------|----------------|
| M1 | Whether the origin-unbound global session has ever actually leaked a cookie cross-origin on a real multi-host scope. The **absence of the check** is measured (D9); the **occurrence** is not | replay a two-host scope with a session for host A and grep the exchange ledger for the cookie on host B requests |
| M2 | Whether the 60% `http_probe` amplification (D2) reproduces at real-target scale, and what fraction of wall-clock it costs | count `http_probe` `tool_call` log rows vs distinct URLs on a completed mission |
| M3 | How many endpoints per real mission lose parameters to D3 | on a completed mission, compare `build_inventory` param counts to the params actually delivered to injection engines |
| M4 | Whether trigger #1's amplification (every discovered subdomain becomes a full recon root) is already causing waste | count phase-A steps per mission against distinct registrable domains |
| M5 | Whether any engine outside the persona-authz phase currently benefits from `session_headers` at all -- i.e. what authenticated coverage would actually be lost by removing the global before the handle exists | run one authenticated mission with the global forced empty and diff the finding set |
| M6 | The real distribution of credential-producing events across the pipeline, which sizes D10's value | instrument the producers named in 3.3 and count |

## 6.3 UPGRADE OPPORTUNITIES

| id | opportunity | extend |
|----|-------------|--------|
| U1 | Execute `graph.next_best_actions()` instead of only reporting it. The producer is complete, deterministic and tested | move the `_close_autonomy_loop` call **inside** the loop; map action -> tool once |
| U2 | Wire `effect_search` into planning. It gives goal-directed search with negative effects; it has one caller, an HTTP endpoint | `agent/effect_search.py` + the loop; no new module |
| U3 | `schema` nodes from `fetch_openapi` / `run_graphql`, yielding typed **body** params. The largest untested surface class the planner cannot currently name | `asset_graph` kinds + the two existing tools |
| U4 | Object *templates* (`/rest/basket/{id}`) instead of object instances, so one confirmed BOLA generalizes | `props` on the existing `object` node; `authz_matrix.is_object_path` already parses the shape |
| U5 | Use `session_lifecycle_tool.still_authenticated` as the pre-replay liveness predicate, not only as a finding oracle | `session_lifecycle_tool.py:254` |
| U6 | Use `decayed_confidence` as a trigger gate, not only as a ranking factor -- stops low-confidence permuted subdomains arming full recon roots | `asset_graph.py:181-193` |
| U7 | Route the admin and tenant persona pairs through BIE, and lift `max_candidates=3` | `agent.py:2126-2135`, `tools.py:2533` |
| U8 | Add the Section 5 event types to the existing `logs` table | `db.py:271` |
| U9 | Report iteration count and convergence status honestly ("converged at iteration 7" vs "stopped at budget with 3 fact classes still growing") | `report.py` `_exec_note` / `coverage_gaps` |
| U10 | Retire `recon_cycles` from the UI and API after D1 lands | `ui/index.html:1326, 2641`; `main.py:65, 396` -- Coordinator sequencing |

## 6.4 Rules honoured

- **No parallel subsystem is proposed.** Every item names an existing module. The three things that do
  not exist today -- `fact_signature`, `SessionHandle`, the trigger table -- are respectively a pure
  reader on `AssetGraph`, a struct over `vault` + `personas`, and a dict consumed by the existing loop.
- **No hardcoded pass count survives.** Termination is `fact_signature` fixpoint or an explicit,
  reported budget.
- **Maximum throttle** is delivered by (a) removing the measured duplicate work in D2/D3, (b) arming
  discovery on facts rather than on a counter, and (c) making persona a ledger dimension so authenticated
  and anonymous coverage are both complete without either repeating the other.

## 6.5 Recommended build order for Q-030..Q-034

Cheap, independently shippable, each provable by a negative control:

1. D3 (one line, immediate coverage gain), D5, D6, D13 -- all small, all revive dead machinery.
2. D1 + D15 + D14 -- the loop: delete the pass count, add `fact_signature`, fix the budget check.
3. D2 + D4 -- the ledger key.
4. U1 -- execute the ranked actions. Q-030 is complete at this point.
5. Section 2 trigger table (needs 1-4).
6. Section 3 handle + event-driven credential artery (D7, D9, D10).
7. Section 4 persona-as-ledger-dimension (D11).
8. Section 5 events + timeline (U8), rendered last so it can only report what the earlier steps record.

Each of 1-8 needs the negative control that proves the *old* behaviour is gone, not only that the new
one exists -- D5, D6 and D7 are all cases where a mechanism was declared present and was measurably
absent, and a test that checks the declaration would have passed on all three.

---

# APPENDIX -- reproduction scripts for every MEASURED claim

Run pattern (container `apolaki-agent-1`, `/app` on the path; nothing is rebuilt):

```
cd /tmp && MSYS_NO_PATHCONV=1 docker cp mN.py apolaki-agent-1:/tmp/mN.py \
  && MSYS_NO_PATHCONV=1 docker exec apolaki-agent-1 python /tmp/mN.py
```

**m1.py -- 1.3, the outer cycle loop is inert**

```python
import sys; sys.path.insert(0, "/app")
import planner
state = {"mode": "full", "roots": ["t.local"], "done": set(),
         "recon": {"subdomains": ["t.local"], "live_hosts": [{"url": "http://t.local:3000"}]},
         "urls": ["http://t.local:3000/x?id=1", "http://t.local:3000/rest/user/whoami"],
         "bases": {"t.local": "http://t.local:3000"}, "intensity": "standard"}
done = set(); state["done"] = done
def drive(tag):
    b, s, names = 0, 0, []
    while True:
        batch = planner.next_batch(state)
        if not batch or b > 50: break
        b += 1
        for st in batch:
            done.add(st["key"]); s += 1; names.append(st["tool"])
    print("%s batches=%d steps=%d tools=%s" % (tag, b, s, sorted(set(names))[:4]))
drive("CYCLE1")
done.discard("generate_playbook"); drive("CYCLE2")   # exactly what _execute_plan:2793 does
done.discard("generate_playbook"); drive("CYCLE3")
```

**m2.py -- 1.6.a, duplicate `http_probe` under different key namespaces**

```python
import sys; sys.path.insert(0, "/app")
import planner
from collections import Counter
state = {"mode": "full", "roots": ["t.local"], "done": set(),
         "recon": {"subdomains": ["t.local"], "live_hosts": [{"url": "http://t.local:3000"}]},
         "urls": ["http://t.local:3000/rest/user/whoami", "http://t.local:3000/rest/basket/1",
                  "http://t.local:3000/x?id=1", "http://t.local:3000/x?q=a"],
         "bases": {"t.local": "http://t.local:3000"}, "intensity": "standard"}
done = set(); state["done"] = done; urlcount = Counter(); keys = []
while True:
    b = planner.next_batch(state)
    if not b: break
    for s in b:
        done.add(s["key"]); keys.append(s["key"])
        if s["tool"] == "http_probe": urlcount[s["input"]["url"]] += 1
print({u: c for u, c in urlcount.items() if c > 1})
print("total http_probe:", sum(urlcount.values()), "distinct:", len(urlcount))
print("xss keys:", [k for k in keys if k.startswith("run_xss")])
```

**m3.py / m4.py -- 1.6.b, the parameter set is known and not passed**

```python
import sys; sys.path.insert(0, "/app")
import surface, xss_tool as xt
print(surface.build_inventory(["http://t.local:3000/x?id=1", "http://t.local:3000/x?q=a"]))
print(xt.params_of("http://t.local:3000/x?id=1"))
```

**m5.py -- 2.2, three dead branches in the live-shaped graph**

```python
import sys; sys.path.insert(0, "/app")
from asset_graph import AssetGraph
# exactly what the live producers write:
#   _seed_and_project_graph  agent.py:2626-2643  (finding WITHOUT enables, no links)
#   _graph_add_url           tools.py:3113-3128
#   _run_service_pack        tools.py:2810-2812  (observe + mark_tested together)
g = AssetGraph("live")
g.observe("host", "t.local:3000", label="t.local:3000", source="scope")
g.observe("endpoint", "t.local:3000/rest/basket/1", label="/rest/basket/1", source="live-recon")
g.observe("object", "t.local:3000/rest/basket/1", label="/rest/basket/1", source="live-recon")
g.observe("finding", "f1", label="SQL injection", source="scan", family="sql_injection")
sid = g.observe("service", "t.local:22", label="ssh", source="service_pack", scope_asset="t.local")
g.mark_tested(sid, ok=False)
print(g.stats()); print(sorted(g.to_observations()))
print([(a["action"], a.get("target")) for a in g.next_best_actions()])
print("untested services:", [n["key"] for n in g.untested("service")])
print("finding.enables:", [n["enables"] for n in g.nodes("finding")])
```

**Grep-only measurements (run from the repo root):**

```
grep -c "self.session_headers" agent/tools.py                     # 50            -> D9
grep -n "^import\|^from\|^    import" agent/planner.py | sort -u  # no TP/ED/AG   -> 1.11
grep -rn "_next_best\|_graph_plan" --include=*.py agent/ | grep -v tests/          -> 1.8
grep -rn "plan_next\|apply_result" --include=*.py agent/ | grep -v tests/          -> 1.8
grep -rn "effect_search" --include=*.py agent/ | grep -v tests/   # 1 caller       -> 1.11
grep -rn "build_from_engagement" --include=*.py . | grep -v tests/                 -> 1.9
grep -rn "ingest_intel" --include=*.py agent/ | grep -v tests/    # 1 caller, post-loop -> 2.2
grep -rhon 'add_log([^,]*, *"[a-z_]*"' --include=*.py agent/ | grep -v tests/ \
  | sed 's/.*, *"//;s/"//' | sort | uniq -c | sort -rn            # 5 etypes       -> 5.2
git log --oneline -12 -- agent/report.py                                           -> 5.1
```

**Disproved along the way (recorded as results, not omissions):**

- *Hypothesis:* the outer cycle loop re-runs the pipeline and therefore causes the duplicate work.
  **Disproved** -- `done` is created outside it (`agent.py:2781`), so it re-runs nothing. The duplicate
  work is inside a single cycle and comes from key namespacing (D2).
- *Hypothesis:* `generate_playbook` re-running in cycle 2 grows `_surface_size()` and so cycle 3 does
  run. **Disproved** -- `guidance` grades entries with a numeric confidence, `_is_confirmed`
  (`agent.py:614-620`) therefore returns False, and `_auto_store` (`agent.py:648-654`) routes them to
  `self.leads`. `_surface_size()` counts `self.findings` only (`agent.py:3295-3297`), so the early-stop
  at `agent.py:2853` fires and cycle 3 never runs.
- *Hypothesis:* `_graph_primary_state` drops query strings, so parameterized endpoints never reach the
  probes. **Disproved** -- `agent.py:2723-2732` re-attaches parameterized URLs for paths the graph
  already holds. The parameter loss is one layer further in (D3), at the `example`-URL selection.
- *Hypothesis:* `AssetGraph` cannot represent personas or sessions at all. **Disproved** -- the kinds
  exist and `build_from_engagement` writes them (`asset_graph.py:504-509`); the gap is that no
  live-scan producer does.
