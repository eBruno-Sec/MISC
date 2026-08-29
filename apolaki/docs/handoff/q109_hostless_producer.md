# Q-109 - what mints the 30 hostless graph endpoint nodes

LANE C (Breaker, READ-ONLY). No product code changed this cycle. Every claim below is either
MEASURED (command + real output shown) or explicitly UNVERIFIED.

Repo: `C:\Users\voice\Desktop\GitHub\MISC\apolaki`. Git root is the PARENT `MISC`.

---

## 0. The symptom, restated only to fix the vocabulary

```
graph_primary_state.hostless_endpoint | failed | DEGRADED: swallowed exception at
graph_primary_state.hostless_endpoint: ValueError: 30 graph endpoint node(s) carry no host, so no
absolute URL exists for them
```

The REPORTER is `agent/agent.py:3415-3460` (`AgentBrain._graph_primary_state`), and it is correct.
It drops an endpoint node it cannot resolve to an absolute URL, and records the drop with a count
and the first offenders. Nothing in this document proposes relaxing that drop.

The resolver it calls is `agent/agent.py:_endpoint_url`, whose whole contract is the refusal:

```python
        if "://" in s:
            return s if _up(s).netloc else ""
        host, sep, rest = s.partition("/")
        if not host:                     # a bare path - no host was ever recorded for this node
            return ""
```

So a node is "hostless" iff its KEY is a **bare path** (`/rest/user/login`) or a scheme-only URL.
That single line is the whole definition of the offender shape, and it is what the hunt below uses.

---

## 1. Recovering the three recorded offenders: UNVERIFIED, and why

**They could not be recovered from any store on this machine.** Two independent reasons, both
measured.

### 1a. The persisted mission database holds ZERO rows for this swallow

`ToolRegistry._swallow` (`agent/tools.py:4262-4300`) persists every swallow durably:

```python
                db.add_log(mission_id, "tool_error", {
                    "tool": active_tool or rec["where"],
                    "error": "DEGRADED: swallowed exception at %s: %s" %
                             (rec["where"], rec["error"]),
                    "target": rec["target"],
                })
```

MEASURED against the live mission DB (140 MB, inside the `apolaki_bbh_data` volume, mounted
read-only):

```
$ MSYS_NO_PATHCONV=1 docker run --rm -v apolaki_bbh_data:/d:ro apolaki-agent python -c "
import sqlite3
c=sqlite3.connect('file:/d/bbh.db?mode=ro',uri=True)
print('LOGS', c.execute('select count(*) from logs').fetchone())
print('tool_error', c.execute(\"select count(*) from logs where etype='tool_error'\").fetchone())
print('hostless', c.execute(\"select count(*) from logs where data like '%hostless%'\").fetchone())
print('graph_primary', c.execute(\"select count(*) from logs where data like '%graph_primary_state%'\").fetchone())
print('maxdate', c.execute('select max(created_at) from logs').fetchone())
"
LOGS (71536,)
tool_error (612,)
hostless (0,)
graph_primary (0,)
maxdate ('2026-08-24T20:19:29.721750+00:00',)
```

Zero. And more broadly, this DB contains **no `_swallow`-written row at all**:

```
$ ... print('DEGRADED', ...like '%DEGRADED%'); print('swallowed', ...like '%swallowed%')
DEGRADED (1,)
swallowed (0,)
```

The single `DEGRADED` hit is an unrelated `run_zap` `tool_result` string
(`b226bc05`, `active scan degraded, passive alerts kept`), not a swallow. So the
`_swallow -> db.add_log` path has produced nothing in this volume, and the operator's snapshot must
have come from a mission store that is not present here.

The Shopify missions themselves ARE in this DB, and their `tool_error` rows are all ordinary tool
failures, none of them the graph swallow:

```
$ ... select data from logs where mission_id='351e163d' and etype='tool_error'
http_probe                   | [Errno -2] Name or service not known      (x15)
fetch_openapi                | [Errno -2] Name or service not known      (x30)
run_zap                      | ZAP was enabled but no run_zap tool_call was persisted; ...
```

Mission rows for reference (`missions` has no `target` column; the program name carries it):

```
('351e163d', '24Aug2026_1019_shopify_DF3', 'full', 'failed', 'report', ...)
('d9ce9f0a', '24Aug2026_1019_shopify_DF3', 'full', 'failed', 'report', ...)
('80c76f01', '24Aug2026_shopify',          'full', 'failed', 'report', ...)
('30555296', '24Aug2026_shopify',          'full', 'failed', 'report', ...)
('07710343', '23Aug2026_shopify',          'full', 'failed', 'report', ...)
```

The host-side copy `apolaki/agent/data/bbh.db` is empty (`logs (0,)`), so there is no second store.

### 1b. Even where the row EXISTS, only the FIRST offender survives - the other two are truncated

This is a real defect in the ticket's own premise ("`_swallow` carries the first three offenders
VERBATIM in the mission record"). It does not.

`_swallow` truncates the exception text at 160 characters:

```python
        rec = {"where": str(where or "unknown")[:160], "target": str(target or "")[:200],
               "error": "%s: %s" % (type(exc).__name__, str(exc)[:160])}
```

The ValueError's message prefix, before the offenders begin, is:

```
30 graph endpoint node(s) carry no host, so no absolute URL exists for them; they cannot be probed and were NOT faked onto a bare scheme. First: 
```

MEASURED, reconstructing the exact message the code builds:

```
$ MSYS_NO_PATHCONV=1 docker run --rm apolaki-agent python -c "
msg = ('%d graph endpoint node(s) carry no host, so no absolute URL exists for '
       'them; they cannot be probed and were NOT faked onto a bare scheme. '
       'First: %s' % (30, ', '.join(['/rest/user/login','/api/v1/orders','/assets/app.js'])))
pre = msg.split('First: ')[0] + 'First: '
print('prefix_len', len(pre)); print('full_len', len(msg))
print(repr('ValueError: ' + msg[:160]))
"
prefix_len 145
full_len 193
'ValueError: 30 graph endpoint node(s) carry no host, so no absolute URL exists for them; they cannot be probed and were NOT faked onto a bare scheme. First: /rest/user/logi'
```

The prefix is **145 characters** for a 2-digit count, so `str(exc)[:160]` leaves **15 characters**
for the offender list. Offenders 2 and 3 are unreachable by construction, and offender 1 is cut
mid-token (`/rest/user/logi`) inside `error`.

`target` is a separate field capped at 200 and is set to `_unresolved[0]`, so **the first offender
is fully recoverable from `target`** - but only the first.

> HANDOFF NOTE (not part of the Q-109 patch): if the operator wants all three, either widen the
> `str(exc)` cap or move the offender list into a dedicated field. Filing this separately rather
> than folding it into the producer fix.

---

## 2. Search space covered

Every writer of an `endpoint` node in `agent/`, found with a tree-wide grep (not a single-file
grep - see "failure modes" in the lane brief):

```
$ grep -rn '"endpoint"' --include=*.py agent/ | grep observe
agent/agent.py:3242   g.observe("endpoint", ep_key, ...)            source="openapi"
agent/agent.py:3282   g.observe("endpoint", ep_key, ...)            source="form-capture"
agent/agent.py:3334   g.observe("endpoint", u, ...)                 source="recon"   (live_hosts)
agent/agent.py:3337   g.observe("endpoint", str(u), ...)            source="recon"   (tools.urls)
agent/archive_intel.py:34  graph.observe("endpoint", (h+path) if h else path, ...)  source="wayback"
agent/archive_intel.py:50  graph.observe("endpoint", val, ...)                      source="github"
agent/asset_graph.py:330   self.observe("endpoint", str(r), ...)                    source=<harvest>
agent/asset_graph.py:592   g.observe("endpoint", (host+path) if host else path, ...) source="recon"
agent/codereview_graph.py:68 graph.observe("endpoint", pfx+path, ...)               source="code_review"
agent/tools.py:4084   self.graph.observe("endpoint", (host+path) if host else path, ...) source="live-recon"
```

Three distinct key CONVENTIONS are in use, which is the root of the whole class:

| convention | key shape | writers | resolves? |
|---|---|---|---|
| A | absolute URL `https://h/p` | `agent.py:3334`, `agent.py:3337` | yes |
| B | `netloc + path` (`h/p`) | `agent.py:3242`, `agent.py:3282`, `tools.py:4084`, `asset_graph.py:592`, `archive_intel.py:34` (when `h`) | yes |
| C | **bare path** (`/p`) | `asset_graph.py:330`, `archive_intel.py:50`, `archive_intel.py:34` (when `h` empty), `codereview_graph.py:68` (when `pfx` empty) | **NO - dropped** |

Convention C is the offender class.

> LINE NUMBERS. Everything below is pinned to the blobs at commit `899e768`. Verified identical to
> my `git archive` snapshot before use (other lanes were mid-commit in the shared tree, and I did get
> one torn read early on - my first pass cited `agent.py:3452/3458`, which is a stale numbering):
>
> ```
> $ for f in agent/agent.py agent/asset_graph.py agent/tools.py agent/intel.py; do ... md5sum ...
> agent/agent.py      snap=bbbb615e376ab8223f90007752f89ba6 head=bbbb615e376ab8223f90007752f89ba6 SAME
> agent/asset_graph.py snap=73f956ea9556121a50b287d7416e2711 head=73f956ea9556121a50b287d7416e2711 SAME
> agent/tools.py      snap=f393329ad10ff803a6f0f134017f538d head=f393329ad10ff803a6f0f134017f538d SAME
> agent/intel.py      snap=e6b48644b1987d6adc7956bbb7e9759c head=e6b48644b1987d6adc7956bbb7e9759c SAME
> ```

---

## 3. THE PRODUCER - `AssetGraph.ingest_intel`, `agent/asset_graph.py:329-330`

```python
309:    def ingest_intel(self, intel: dict, source: str = "harvest") -> int:
...
329:        for r in (cands.get("route", []) or []) + (cands.get("endpoint", []) or []):
330:            self.observe("endpoint", str(r), label=str(r), source=source)
```

The `route` and `endpoint` candidates come out of `IntelStore`, and every writer of them produces a
**bare path by construction**:

| writer | line | what it stores |
|---|---|---|
| `intel.harvest_text` | `intel.py:269` | `_PATH` regex, anchored on a leading `/` (`intel.py:45`) |
| `intel.harvest_js` | `intel.py:327` | `store.add("route", "/" + m.lstrip("/"), source)` |
| `intel._add_ref` | `intel.py:365` | `store.add("route", "/" + base.lstrip("/"), source)` |
| `intel.harvest_html` | `intel.py:387` | `store.add("endpoint", <form action>, source)` - relative for most real forms |

`observe` keys the node on that string unchanged, so the node key is `/rest/user/login`, and
`_endpoint_url` refuses it at `agent.py:3495` (`if not host: return ""`) exactly as designed.

The live call site is `agent/agent.py:1769`, inside `_close_autonomy_loop`:

```python
1769:                    _g.ingest_intel(self.tools.intel.to_dict() if hasattr(self.tools.intel, "to_dict") else {})
```

`_g` is `self.tools.graph` - the SAME `AssetGraph` object `_graph_primary_state` reads
(`tools.py:1620` constructs it; `agent.py:3785` fetches it with `getattr(self.tools, "graph", None)`).

### 3a. MEASURED - the producer actually produces the offenders

Not "it could". Driven on the authorized local lab (`apolaki-juice-shop-1`, `juice-shop:3000` on
`apolaki_default`) through the REAL `_surface_crawl`, `_recon_code_intelligence`,
`_seed_and_project_graph`, `_endpoint_url` and `_graph_primary_state` - no monkeypatching of the
projection or the resolver, `mission_id=None` so nothing is written to the shared mission DB.
Harness: `scratchpad/q109/q109_repro.py`.

```
$ MSYS_NO_PATHCONV=1 docker run --rm --network apolaki_default \
    -v "<SNAP>/agent:/app" -v "<SCRATCH>/q109:/work" -w /app \
    -e PYTHONPATH=/app -e BBH_DATA_DIR=/tmp/q109 apolaki-agent python /work/q109_repro.py

scope base_map: {'juice-shop': 'http://juice-shop:3000'}
surface crawl visited=18  tools.urls=38
after code-intel  tools.urls=59
tools.urls entries with NO scheme (0): []
[live graph, after crawl+codeintel (pre-projection)] endpoint nodes=38  HOSTLESS=0
[after _seed_and_project_graph  <= THIS is the state _execute_plan sees] endpoint nodes=97  HOSTLESS=0
_graph_primary_state -> roots=2 urls=59
intel candidates: route=3 endpoint=0 url=10
  sample route: ['/juice-shop/build/routes/fileServer.js', '/juice-shop/node_modules/express/lib/router/index.js', '/juice-shop/node_modules/express/lib/router/layer.js']
ingest_intel added 6 node(s)
[after ingest_intel (what _close_autonomy_loop does)] endpoint nodes=100  HOSTLESS=3
     source=harvest                  count=3
     key='/juice-shop/build/routes/fileServer.js' sources=('harvest',)
     key='/juice-shop/node_modules/express/lib/router/index.js' sources=('harvest',)
     key='/juice-shop/node_modules/express/lib/router/layer.js' sources=('harvest',)
   SWALLOW where=graph_primary_state.hostless_endpoint target='/juice-shop/build/routes/fileServer.js'
           error='ValueError: 3 graph endpoint node(s) carry no host, so no absolute URL exists for them; they cannot be probed and were NOT faked onto a bare scheme. First: /juice-shop/buil'
DELTA hostless: 0 -> 3
```

Four things this establishes, all measured:

1. **Every hostless node carries `source='harvest'`**, which is `ingest_intel`'s default `source=`
   argument and is used by no other endpoint writer. The provenance names the producer.
2. **The count goes 0 -> 3 across exactly one call to `ingest_intel`** and nothing else. A negative
   control is built in: the same graph, same target, same projection, measured immediately before.
3. The real swallow reproduces with the production message, and its `target` field carries the
   first offender in full.
4. The `error` string is truncated at `First: /juice-shop/buil`, confirming section 1b empirically.

### 3b. What the offenders actually ARE - and why this is not simply "30 lost endpoints"

Two of the three offenders on juice-shop are **server-side filesystem paths mined out of a stack
trace** (`/juice-shop/node_modules/express/lib/router/index.js`), not URLs on the target at all.
They are real intel, but they are not addresses.

This matters for the fix. "30 endpoints per run are never probed" assumes all 30 are URLs that
should be probed. At least on a measured target they are not - and minting
`https://<base>/juice-shop/node_modules/express/lib/router/index.js` to make the count go to zero
would be the SAME class of error as `https:///path`: claiming an address nobody observed. The
patch in section 6 therefore reclassifies rather than absolutizes.

---

## 4. Hypotheses I DISPROVED

Every one of these was a plausible producer. All are eliminated, so the next lane does not re-walk
them.

**H1. `tools._graph_add_url` (`tools.py:4077`) mints `path` when a crawled URL is relative.**
DISPROVED. The line is `(host + path) if host else path`, so the shape is there - but its only
caller is `_add_urls` (`tools.py:4096`), which reaches it only after `surface_mod.clean_url(u) and
self.scope.validate(u)[0]`. MEASURED, both gates reject a bare path:

```
$ ... apolaki-agent python -c "import scope as S, surface; sc=S.ScopeEngine(); sc.load_manual(['juice-shop:3000'],[],'lab'); ..."
'/rest/user/login'             validate=(False, 'Invalid target') clean_url=False
'//evil.com/x'                 validate=(False, 'Invalid target') clean_url=True
'rest/products'                validate=(False, 'rest not in scope') clean_url=False
'https://juice-shop:3000/x'    validate=(True, 'In scope via juice-shop:3000') clean_url=True
'#/search'                     validate=(False, '# not in scope') clean_url=False
'src:/api/foo'                 validate=(False, 'src not in scope') clean_url=False
```

**H2. Something else writes `tools.urls` past `_add_urls`, and `_seed_and_project_graph` keys an
endpoint node on it.** DISPROVED as a HOSTLESS producer, though the bypass is real. There are
exactly two writers in the whole tree:

```
$ grep -rn "\.urls\.append\|\.urls\.extend\|\.urls +=\|urls\.insert\|self\.urls =" --include=*.py agent/ | grep -v tests
agent/agent.py:1625:                self.tools.urls.append(u)
agent/tools.py:4129:                self.urls.append(u)
```

`tools.py:4129` is inside `_add_urls` (gated, see H1). `agent.py:1625` is the code-intelligence
bypass, and its own comment admits it bypasses `_add_urls`. But the value it appends is
`base.rstrip("/") + ep if str(ep).startswith("/") else str(ep)` - so a `/`-leading mined endpoint
becomes ABSOLUTE, and a relative one keeps a non-empty first segment. Measured on juice-shop:
`tools.urls entries with NO scheme (0): []`. It is not a hostless producer.

> Not a hostless bug, but worth its own ticket: the else-branch appends the raw string. A mined
> `ep` of `rest/products` would enter `tools.urls` UNVALIDATED (no `clean_url`, no `scope.validate`,
> no session-kill quarantine) and would then key an endpoint node `rest/products`, which
> `_endpoint_url` resolves to the PHANTOM host `https://rest/products`. That resolves, so no
> swallow ever names it.

**H3. `archive_intel.ingest_repo_findings` (`archive_intel.py:50`) mints a bare repo route.**
DISPROVED on the live path. The branch is real (`if kind == "route" and val:` -> `observe("endpoint",
val, ...)`) but the only production caller, `tools.py:4470`, constructs its items as
`{"kind": "secret", ...}` only:

```python
            secrets = [{"kind": "secret", "value": f.get("evidence", ""), "ref": None}
                       for f in findings if "secret-leak" in (f.get("tags") or [])]
```

No live caller ever passes `kind == "route"`. The route branch is reachable only from tests.

**H4. `archive_intel.ingest_archived_endpoints` (`archive_intel.py:34`) falls back to a bare path
when the host is unknown.** DISPROVED on the live path. `h = p.netloc or host`, and its only
production caller `tools.py:4380` feeds it a list every element of which already passed
`self.scope.validate(u)[0]` inside `_run_wayback` - which, per H1, is impossible for a hostless
string. `p.netloc` is therefore always non-empty.

**H5. `codereview_graph.seed` (`codereview_graph.py:68`) mints a bare path.** DISPROVED.
`pfx = (repo + ":") if repo else "src:"`, so the key is `src:/api/foo`; `partition("/")` yields a
non-empty head and `_endpoint_url` returns `https://src:/api/foo`. It is not hostless.

> Again a separate defect rather than this one: that node RESOLVES to a fabricated host and enters
> the planner's probe surface. Worth a ticket; it is not Q-109.

**H6. Warm start replays hostless rows out of `memory_assets` (the Q-111b precedent).** DISPROVED,
twice over.
- The graph itself is never replayed: `tools.py:1620` builds a FRESH `AssetGraph(mission_id)` every
  mission. `AssetGraph.load` has no production caller (`grep -rn "AssetGraph.load"` -> tests only),
  and the only `.save()` in the tree is `main.py:2600`, which saves the REPORT-TIME
  `build_from_engagement` graph, not the live one.
- The stored endpoint rows cannot be hostless anyway: `memory.py:163` derives them from
  `surface.build_inventory(tools.urls)` as `f"{e['host']}{e['path']}"`, and `main.py:_warm_start`
  re-admits them through `tools._add_urls`, which re-validates (H1).

**So, unlike Q-111b, a producer-only fix IS sufficient here. There is no poisoned history to clean.**

**H7. The persisted mission graphs would show the offenders.** DISPROVED as an evidence source, and
this is worth recording because it looks like it should work. I scanned every persisted graph:

```
$ MSYS_NO_PATHCONV=1 docker run --rm -v apolaki_bbh_data:/d:ro apolaki-agent python -c "...scan /d/graph/*.json..."
graph files scanned 491 endpoint nodes 26827 HOSTLESS 0
```

Zero hostless nodes in 26,827 endpoint nodes. Not because there are none - because
`/app/data/graph/*.json` is the REPORT-TIME graph from `build_from_engagement`
(`main.py:2600-2601`), whose endpoints come from `surface.build_inventory(urls)` and are all
`host+path`. **The live `tools.graph`, the one that carries the defect, is never persisted at all.**
A future lane looking for live-graph evidence will not find it in that directory.

---

## 5. Ordering: when the offenders exist relative to when they are read

This is the one part of the picture that does NOT line up cleanly, and I am flagging it rather than
papering over it.

Static call order inside `BBHAgent.run()` (`agent.py:3216-3276`):

```
run()
  -> strategy branch          _run_deterministic (4378) / _run_low_ai (4415) / agentic floor (3234)
       -> _execute_plan (3881)
            -> loop:  _seed_and_project_graph (3425)  ->  _graph_primary_state (3520)   [the swallow]
  -> _probe_cloud_storage
  -> _technique_advisor
  -> _close_autonomy_loop (3271)
       -> ingest_intel (1769)                                                 [the producer]
  -> _validate_candidates       (does not touch the graph)
  -> _triage
```

`_execute_plan` has exactly three call sites (3234, 4378, 4415), all reached from the strategy
branch, all BEFORE 3271. `_close_autonomy_loop` has exactly one production call site (3271).
`main._drive_mission` runs `agent.run()` exactly once per mission (`main.py:3016`, guarded by
`_ensure_run_started`). So on THIS build, in a single mission, the producer fires after the last
read - and the swallow should not fire at all.

### 5a. MEASURED on a complete real mission

`scratchpad/q109/q109_fullrun.py` runs the REAL `BBHAgent.run()` end to end against juice-shop and
records the order in which the two sites are reached. Both wrappers call straight through to the
real implementation; nothing else is changed, `mission_id=None` so the shared DB is untouched.

```
$ MSYS_NO_PATHCONV=1 docker run --rm --network apolaki_default -v "<SNAP>/agent:/app" \
    -v "<SCRATCH>/q109:/work" -w /app -e PYTHONPATH=/app -e BBH_DATA_DIR=/tmp/q109 \
    -e BBH_SURFACE_PAGES=40 apolaki-agent python -u /work/q109_fullrun.py

EV complete Deterministic scan complete - 182 step(s). See Playbooks for cURL-ready leads and the report.
events=819
CALL ORDER: graph_primary_state x14 -> ingest_intel x1
hostless swallows recorded during the run: 0
END-OF-RUN live graph: endpoints=628 hostless=113
   source=harvest              count=113
   key='/' sources=('harvest',)
   key='/#' sources=('harvest',)
   key='/#/bee-haven' sources=('harvest',)
   key='/#/complain' sources=('harvest',)
   key='/#/contact' sources=('harvest',)
   key='/#/forgot-password' sources=('harvest',)
   key='/#/search?q=OWASP' sources=('harvest',)
   key='/#recycle' sources=('harvest',)
   key='/${e}' sources=('harvest',)
   key='/${this.snapshot.routeConfig&&this.snapshot.routeConfig.path||' sources=('harvest',)
```

Four measured facts:

1. **113 hostless endpoint nodes on one ordinary mission, 113 of 113 attributed to `source='harvest'`.**
   Same magnitude class as the operator's 30, and the attribution is total - not a majority, all of them.
2. **The order is `graph_primary_state x14 -> ingest_intel x1`.** The producer fires once, after all
   fourteen reads.
3. **Zero hostless swallows during the run.** On THIS build, in a single mission, the reporter never
   sees what the producer makes.
4. The offenders are SPA hash-routes (`/#/forgot-password`) and **minified-JS garbage**
   (`/${this.snapshot.routeConfig&&this.snapshot.routeConfig.path||`). The latter is not a path at
   all; it is a fragment of an Angular expression that the `_PATH` regex matched. Binding those to a
   base would put junk on the probe surface.

### 5b. What that means for the operator's ledger row - stated honestly

The row plainly appeared on the Shopify runs, and on the build those runs used. I checked:

```
$ C=$(git rev-list -1 --before="2026-08-24T20:30:00-07:00" HEAD); git show $C:apolaki/agent/agent.py | grep -n ...
commit-at-shopify-run=02d66dc  2026-08-24 12:55:32 -0700
3087:            async for ev in self._run_deterministic(session_id):
3090:            async for ev in self._run_low_ai(objective, session_id):
3105:                async for ev in self._execute_plan(session_id):
3142:        async for ev in self._close_autonomy_loop(session_id):
```

Same ordering. So "their build ordered it differently" is DISPROVED, and I could not reproduce the
row in a single mission. The remaining explanation I could not test is that the live graph was read
a second time after `_close_autonomy_loop` - a re-driven or resumed session. Circumstantial support,
not proof: two of the five stored Shopify missions (`351e163d`, `d9ce9f0a`) carry the same program
name and byte-identical log profiles (928 logs / 46 tool_error each), which is what a duplicated
drive of one engagement looks like.

**This does not weaken the producer finding.** `ingest_intel` is the only writer in the tree that
can key an endpoint node on a bare path on the LIVE graph (sections 3 and 4 enumerate and eliminate
all nine others), and it is measured minting 113 of them.

### 5c. A SECOND defect the ordering exposes, which is arguably the bigger one

Because `ingest_intel` is the last thing to touch the graph, **nothing the intel harvest learns can
influence the plan of the mission that learned it.** The write at `agent.py:1769` lands after all 14
planner decisions - and it carries far more than endpoints: `object_id`, `param`, `version`,
`credential` and `coupon` candidates all arrive at the same moment (`asset_graph.py:316-328`).

Its comment says the feed exists "so the planner reads a complete world model FROM the graph
(graph-as-brain)". Measured, the only in-mission consumer is `plan_graph_authoritative` twelve lines
below it, which produces the ADVISORY next-best-action list. The executor never sees it. That is a
separate ticket and I am not folding it into the Q-109 patch, but it should be filed: the
graph-as-brain feed is real and it is wired one phase too late to steer anything.

---

## 6. THE PATCH

One file, two hunks. Applied and validated in an isolated snapshot of `899e768`; the diff below is
`diff -u` of that snapshot against HEAD, so it applies cleanly as-is.

### Hunk 1 - `agent/asset_graph.py`, replacing lines 329-330

```diff
@@ -326,8 +326,39 @@
                          label="exposed-credential", source=source)
         for cp in cands.get("coupon", []) or []:
             self.observe("coupon", str(cp)[:24], label="coupon-code", source=source)
+        # Q-109. A harvested route is a PATH, never an ADDRESS. `intel` stores these as bare paths by
+        # construction (intel.py:269/327/365 each prepend "/"), so keying an `endpoint` node on the
+        # candidate minted a node with no host. `_endpoint_url` (agent.py:3490) then correctly refused
+        # to resolve it and `_graph_primary_state` dropped it and RECORDED the drop -- the reporter was
+        # right, and this line was the producer.
+        #
+        # NOT "absolutize it onto the mission base". MEASURED on juice-shop, two of the three
+        # candidates a real run produced are server-side FILESYSTEM paths lifted out of a stack trace
+        # (/juice-shop/node_modules/express/lib/router/index.js). Pinning those to the base would
+        # manufacture an address nobody ever observed -- the same defect as `https:///path`, one step
+        # further from the evidence.
+        #
+        # So the FACT is kept and its CLAIM is corrected: a candidate that carries a host stays an
+        # `endpoint` keyed netloc+path (the convention `_graph_add_url` and `_project_body_params`
+        # already use), and a bare path becomes a `route` node -- known, provenance-tagged, and never
+        # promoted to probe surface. `to_observations` reads both kinds, so no observation is lost.
+        from urllib.parse import urlparse as _up
         for r in (cands.get("route", []) or []) + (cands.get("endpoint", []) or []):
-            self.observe("endpoint", str(r), label=str(r), source=source)
+            s = str(r).strip()
+            if not s:
+                continue
+            if "://" in s:
+                p = _up(s)
+                if p.netloc:
+                    self.observe("endpoint", p.netloc + (p.path or "/"), label=(p.path or "/"),
+                                 source=source)
+                elif p.path:
+                    # `https:///x` -- a scheme with an EMPTY netloc, the exact string Q-019 was filed
+                    # for. It is a path, so it is recorded as one; it is not an address, so it is
+                    # never faked into a node the planner would probe.
+                    self.observe("route", p.path, label=p.path, source=source)
+                continue
+            self.observe("route", s, label=s, source=source)
         return len(self._nodes) - n0
```

### Hunk 2 - `agent/asset_graph.py`, line 371 - THE OTHER HALF

```diff
@@ -368,7 +399,13 @@
             # means a param written before locations existed, which was always a query param.
             if (props.get("location") or "query") == "body":
                 obs.add("has_body_params")
-        for e in self.nodes("endpoint"):
+        # Q-109, the OTHER half. A `route` node is the same knowledge as an endpoint minus an
+        # address, so these keyword observations have to read it too. Without this line the ingest
+        # fix above would trade a false probe target for a REAL blind spot: a harvested
+        # /rest/user/login would stop contributing has_login/has_api at all. Both existing tests
+        # (test_asset_graph.py:106, test_technique_planner.py:100) fail without it, which is what
+        # makes them the positive control for this half rather than a formality.
+        for e in self.nodes("endpoint") + self.nodes("route"):
             low = (e.get("label") or e.get("key") or "").lower()
             if any(k in low for k in ("/login", "/signin", "/sign-in", "/auth", "/session")):
                 obs.add("has_login")
```

### Why NOT the two obvious alternatives

- **Absolutize onto the mission base.** Rejected on measurement: 113 of 113 candidates on a real
  juice-shop run include `/#/forgot-password` (an SPA hash-route, not a server path) and
  `/${this.snapshot.routeConfig&&this.snapshot.routeConfig.path||` (a fragment of a minified Angular
  expression the `_PATH` regex matched). Pinning those to the base manufactures addresses and spends
  probe budget on 404s. The caller does have a base available (`_close_autonomy_loop` computes
  `self._primary_base()` and returns early when it is empty, `agent.py:1726`), so this alternative is
  cheap to write - which is exactly why it needs the explicit refusal.
- **A new `route`-only node with no `to_observations` change.** That is hunk 1 without hunk 2, and it
  fails four existing assertions (measured below). It would make the ledger row disappear by making
  the knowledge disappear, which is the failure mode this project keeps filing tickets about.

### Blast radius

- `route` is a NEW node kind. `asset_graph.py`'s own docstring calls the kind list an "open set", the
  node store is generic, and `graph_export._ns` falls back to `str(kind).title()` for an unknown kind
  (`graph_export.py:51`), so it exports as `Apolaki_Route` rather than raising.
- No existing code reads `nodes("route")`:
  `grep -rn 'nodes("route")' --include=*.py agent/` returns nothing outside this patch.
- `ingest_intel`'s only production caller is `agent.py:1769`; the signature is unchanged, so no call
  site needs editing.

---

## 7. THE GATE (new test file, ready to drop in)

`agent/tests/test_q109_hostless_producer.py` - six tests. Written to FAIL on HEAD, and written so
that both halves are load-bearing.

MEASURED against HEAD (unpatched snapshot):

```
$ docker run --rm --network apolaki_default -v "<SNAP-HEAD>/agent:/app" -w /app \
    apolaki-agent python -m pytest tests/test_q109_hostless_producer.py -p no:cacheprovider -q
FAILED tests/test_q109_hostless_producer.py::test_ingest_intel_mints_no_hostless_endpoint_node
FAILED tests/test_q109_hostless_producer.py::test_the_knowledge_is_kept_as_a_route_never_discarded
FAILED tests/test_q109_hostless_producer.py::test_an_addressable_candidate_is_still_an_endpoint_keyed_netloc_path
FAILED tests/test_q109_hostless_producer.py::test_a_scheme_with_no_host_is_recorded_as_a_path_never_as_an_address
```

MEASURED against the patched snapshot, together with the whole Q-019 guard file it must not break:

```
$ docker run --rm --network apolaki_default -v "<SNAP-PATCHED>/agent:/app" -w /app \
    apolaki-agent python -m pytest tests/test_q109_hostless_producer.py \
    tests/test_hostless_target_guard.py -p no:cacheprovider -q
.....................                                                    [100%]
```

The two tests that pass on HEAD are deliberate: `test_the_planner_observations_survive_the_
reclassification` and `test_the_reporter_still_fires_when_a_hostless_node_reaches_the_graph_some_
other_way` are controls on the FIX, not on the defect - they catch a fix that silences the row by
throwing the knowledge away, or by disabling Q-019's recorder.

### Mutation evidence for hunk 2

Hunk 2 is not decoration. With hunk 1 applied and hunk 2 omitted, the EXISTING suite breaks:

```
$ docker run --rm --network apolaki_default -v "<SNAP-HUNK1-ONLY>/agent:/app" -w /app \
    apolaki-agent python -m pytest \
    tests/test_asset_graph.py::test_ingest_intel_gives_graph_the_full_planner_vocabulary \
    tests/test_technique_planner.py::test_planner_is_graph_authoritative_flat_recon_cannot_drive_it \
    -p no:cacheprovider -rfE
E       AssertionError: assert {'has_login',...search_param'} <= {'has_object_...search_param'}
E         Extra items in the left set:
E         'has_login'
FAILED tests/test_asset_graph.py::test_ingest_intel_gives_graph_the_full_planner_vocabulary
FAILED tests/test_technique_planner.py::test_planner_is_graph_authoritative_flat_recon_cannot_drive_it
2 failed in 4.54s
```

The full test file body is in section 9.

