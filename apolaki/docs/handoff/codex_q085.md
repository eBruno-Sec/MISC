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

Commit: `1c085eb`

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

## Q-085 slice 2: Juice Shop no-DoS breach

All four raw transports in `juiceshop_solvers.py` now route through one sync policy factory:

* `solve()` and `conquest()` construct clients with
  `browser_engine.rate_limited_sync_client()`.
* The ten `_multiple_likes()` workers use that client instead of calling `urlopen` directly.
* `_api_and_header_xss()` uses the same client instead of a second raw transport.
* The sync factory installs a wait hook before every request and an observation hook after every
  response, preserving caller-supplied hooks after the safety hooks.

Fail-before-fix was semantic, not an import error:

```text
AssertionError: the lab solver promises no DoS but still has raw target transports:
['juiceshop_solvers.py:1149:conquest:httpx.Client',
 'juiceshop_solvers.py:304:_like:urllib.request.urlopen',
 'juiceshop_solvers.py:355:_api_and_header_xss:urllib.request.urlopen',
 'juiceshop_solvers.py:826:solve:httpx.Client']
1 failed in 4.93s
```

Measured after the fix:

```text
production modules scanned:             179
raw target-capable transport inventory: 35
ungated TARGET call sites:              21
modules with ungated TARGET calls:      12
```

The ratchets were tightened from 25/13 to 21/12. Non-vacuity is pinned to the 179-module corpus,
not to a raw-call floor: the first version incorrectly failed when removing raw calls reduced 39 to
35. Fewer bypass-capable calls are an improvement, not an instrument failure.

Controls:

* A 429 with `Retry-After: 2` makes the sync client's next request begin at fake-clock 2.0 rather
  than 0.0, and the response is counted as one observation and one wait.
* The real `_multiple_likes()` function launches ten threads through an `httpx.MockTransport`; all
  ten review POSTs cross `wait_sync` and all ten responses cross `observe`.
* The repository-wide AST assertion reports zero Juice Shop bypasses.

Semantic mutants, all killed by the exact intended assertions:

1. Replaced the sync request hook's `policy.wait_sync(...)` with `return None`.
   `starts == [0.0, 2.0]` observed `[0.0, 0.0]`, and the ten-worker wait count observed 0 instead
   of 10. Two intended assertions failed; no crash or unrelated failure counted.
2. Replaced the response hook's `policy.observe(...)` with `return None`.
   The second request again began at 0.0 and the ten-worker observation count was 0 instead of 10.
3. Replaced `solve()`'s sanctioned factory with raw `httpx.Client`.
   The widened wiring guard failed on exactly
   `juiceshop_solvers.py:825:solve:httpx.Client`.

Post-restore targeted result:

```text
.x.......................                                                [100%]
XFAIL tests/test_rate_policy.py::test_every_target_transport_uses_the_shared_rate_policy - Q-085 LIVE GAP: after the Juice Shop fix, 21 ungated target calls remain across 12 modules; registration is not compliance, and SKIPPED/NOT SEEN is not a pass
24 passed, 1 xfailed in 15.37s
```

## Audit of the other three one-file guards

The Coordinator's premise was checked rather than inherited. All three files do read
`tools.__file__`, but that fact has three different consequences.

### Engine reachability: partial false assurance

`tests/test_engine_reachability.py::_defined_engines()` parses only `tools.py`, which is consistent
with the current `ToolRegistry.execute()` dispatch contract. The misleading half is
`_planner_names()`: it parses quoted `run_*` strings from `agent.py`, never `planner.py`, while the
module header calls that set the "deterministic planner." It therefore establishes **possible
model-or-agent caller**, not deterministic scheduler reachability.

Measured by importing the test's own helpers:

```text
defined=91 specs=76 agent_literal_planner_names=83
six_in_specs=['run_external_surface', 'run_hash_crack', 'run_hash_id', 'run_mass_assign', 'run_nosqlmap', 'run_ws_hijack']
six_in_agent_literals=[]
six_missing_from_possible_callers=[]
```

This explains why the guard is green while Q-050 is true: all six have an LLM tool spec, so the
guard correctly proves they are *invocable*, but it cannot prove they are *deterministically
selected*. Widening this test into a deterministic-scheduler guard requires reading owned
`planner.py`; no patch was made.

### Session identity: narrow, but aligned with its stated mechanism

`tests/test_session_identity.py::_tools_ast()` parses only `tools.py`. Its two ratchets explicitly
guard raw `self._sessions` reads and session-header dict merges on `ToolRegistry`, the object that
owns both `_sessions` and `_http_send`. Production has external reads in `agent.py` and writes in
`personas.py`; inspection found the reads are used to test minting success or copied into the
persona manager/vault, not passed directly to a target transport as a competing identity.

Verdict: **not the same current defect**. The scope is narrow and a future helper in another module
could evade it, but the test names/docstrings do not claim a repository-wide raw-session census.
Calling this a codebase-wide identity guard would overstate it; calling it a `ToolRegistry`
contamination guard is accurate. No production violation was found and no test was weakened.

### ZAP invocation: false assurance, current fact happens to be clean

`test_zap_target_drivers_remain_inside_one_guarded_function()` slices only the body of
`tools.ToolRegistry._run_zap` and asserts that `zap.access_url`, `zap.spider`, `zap.ajax_start`, and
`zap.ascan` each occur there. It never scans outside that body. Its name says those drivers
"remain inside" the guarded function, but the assertion proves presence, not absence elsewhere.
A duplicate unguarded ZAP target driver in another function or module would leave it green.

The current production fact was checked separately:

```text
rg -n --glob '*.py' --glob '!tests/**' \
  'zap\.(access_url|spider|ajax_start|ascan)\(' agent

tools.py:10340  zap.access_url(...)
tools.py:10369  zap.spider(...)
tools.py:10383  zap.ajax_start(...)
tools.py:10432  zap.ascan(...)
```

So the repository is currently clean on this exact call shape, but the named guard cannot preserve
that fact. A real fix needs a repository-wide AST absence check. That likely belongs with the next
ZAP lease because deciding what receiver aliases count requires `zap_client.py` and the production
call contract; this lane records the defect rather than landing a noisy grep guard.

All four guard files, including the widened rate guard, were then run together:

```text
.x..............................................                         [100%]
XFAIL tests/test_rate_policy.py::test_every_target_transport_uses_the_shared_rate_policy - Q-085 LIVE GAP: after the Juice Shop fix, 21 ungated target calls remain across 12 modules; registration is not compliance, and SKIPPED/NOT SEEN is not a pass
47 passed, 1 xfailed, 3 warnings in 24.54s
```

## Bare 429 Coordinator ruling: blocked at the owned-file boundary

The default remains deliberately unchanged:

```text
RATE_POLICY_BARE_DEFAULT_SECONDS = 0.0
```

Turning it on safely requires provenance in the durable machine-readable `tool_backoff` row. The
producer can distinguish `header` from `inferred` inside `TargetRatePolicy.observe()`, but
`tools.py::_ledger_outcome()` constructs the typed row with a closed schema:

```text
{tool, seconds, waits, truncated, origins}
```

`tools.py` is explicitly off-limits. Adding provenance only to `describe_wait()` would decorate
some prose `tool_result`/`tool_error` notes while leaving the durable typed row unable to distinguish
the two sources (and classified negative/scope-block outcomes are intentionally not decorated).
That would produce two ledgers with different epistemics. Encoding the source into `origins` or
`truncated` would corrupt an existing field rather than add provenance.

Per the lease's explicit ruling, the safe action is therefore to leave the default at `0.0` and
report the atomic patch. These changes must land together:

```diff
--- a/apolaki/agent/browser_engine.py
+++ b/apolaki/agent/browser_engine.py
@@
-RATE_POLICY_BARE_DEFAULT_SECONDS = 0.0
+RATE_POLICY_BARE_DEFAULT_SECONDS = 2.0
@@
-    return {"waits": 0, "seconds": 0.0, "truncated": 0, "origins": []}
+    return {"waits": 0, "seconds": 0.0, "truncated": 0, "origins": [],
+            "sources": []}
@@ class TargetRatePolicy:
-        self._deadlines = {}
+        self._deadlines = {}
+        self._deadline_sources = {}
@@ def clear(self, url=None):
             if origin:
                 self._deadlines.pop(origin, None)
+                self._deadline_sources.pop(origin, None)
             else:
                 self._deadlines.clear()
+                self._deadline_sources.clear()
@@ def observe(self, url, status, headers):
         delay = retry_after_seconds(lowered.get("retry-after"), now=self._wall_clock())
+        source = "header"
@@
         if delay is None:
+            source = "inferred"
             delay = self._bare_wait()
@@
         with self._lock:
-            self._deadlines[origin] = max(deadline, self._deadlines.get(origin, 0.0))
+            previous = self._deadlines.get(origin, 0.0)
+            if deadline > previous:
+                self._deadlines[origin] = deadline
+                self._deadline_sources[origin] = {source}
+            elif deadline == previous:
+                self._deadline_sources.setdefault(origin, set()).add(source)
@@
+    def _sources_for(self, url):
+        origin = _origin(url)
+        with self._lock:
+            return set(self._deadline_sources.get(origin, ()))
@@ def remaining(self, url):
             if not remaining and origin in self._deadlines:
                 self._deadlines.pop(origin, None)
+                self._deadline_sources.pop(origin, None)
@@
-    def _record_wait(self, url, waited, truncation):
+    def _record_wait(self, url, waited, truncation, sources=()):
@@
         if origin and origin not in box["origins"]:
             box["origins"].append(origin)
+        for source in sorted(set(sources)):
+            if source not in box["sources"]:
+                box["sources"].append(source)
@@ def wait_async(self, url):
-        waited, iterations = 0.0, 0
+        waited, iterations, sources = 0.0, 0, set()
         while True:
+            sources.update(self._sources_for(url))
@@
-                self._record_wait(url, waited, truncation)
+                self._record_wait(url, waited, truncation, sources)
@@ def wait_sync(self, url):
-        waited, iterations = 0.0, 0
+        waited, iterations, sources = 0.0, 0, set()
         while True:
+            sources.update(self._sources_for(url))
@@
-                self._record_wait(url, waited, truncation)
+                self._record_wait(url, waited, truncation, sources)

--- a/apolaki/agent/tools.py
+++ b/apolaki/agent/tools.py
@@ def _ledger_outcome(self, session_id: str, tool_name: str, res, rate_wait=None):
                             "waits": rate_wait["waits"], "truncated": rate_wait["truncated"],
-                            "origins": rate_wait["origins"][:8]})
+                            "origins": rate_wait["origins"][:8],
+                            "sources": rate_wait.get("sources", [])[:2]})
```

Required controls in the same atomic slice:

* Update `test_backoff_bounds.py::test_a_response_without_retry_after_is_never_recorded_as_a_wait`
  rather than deleting it: bare `429` waits exactly 2 seconds and records `sources == ["inferred"]`.
* Add the paired non-429 control: `200`, `404`, and `500` with no `Retry-After` record no wait and no
  source.
* Header-supplied waits record `sources == ["header"]`.
* `Retry-After: banana` records `inferred`, never `header`.
* The typed `tool_backoff` row persists `sources`; a semantic mutant deleting the new `tools.py`
  field must fail that exact assertion.
* A semantic mutant swapping `header`/`inferred` must fail both source assertions without crashing.

The proposed `2.0` seconds is the bottom of the independently recommended 2-5 second range and has
already been measured through both HTTP and real Chromium paths using the existing opt-in knob. It
remains bounded by `BBH_RETRY_AFTER_MAX_SECONDS`. This lane did not claim the default was changed.

## Proposed Coordinator-owned queue text

Do not mark Q-085 fully closed. Suggested header:

```text
### Q-085 · Repository-wide rate-policy guard landed; Juice Shop no-DoS breach closed;
###          21 calls / 12 modules remain under a strict ratchet · HIGH · partial
```

Suggested Q-043 note: bare-429 default remains `0.0` because provenance requires an atomic
`browser_engine.py` + `tools.py` typed-ledger change. The exact producer/consumer patch and controls
are above; do not flip the constant alone.

## Remaining verification

* full suite, Tier-3 gate, queue gate, rebase, and final integration instructions
