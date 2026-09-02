# Q-163 - discover param-bearing SPA routes (Lane C)

Status: IN PROGRESS. Written as I go; every claim is MEASURED (command + real output) or UNVERIFIED.

Write set: `agent/spa_routes.py`, `agent/tests/test_spa_routes.py`, this file. Nothing else.

## The gap being closed

`ToolRegistry._spa_hash_routes` (tools.py:5074) renders the page and harvests
`document.querySelectorAll('a[href]')` where the href starts with `#`. That finds the routes an
ANCHOR points at. On juice-shop those five routes carry no parameter, and the sweep only probes
PARAMETERIZED endpoints, so the chain that Q-161/Q-159/Q-153 built never gets an input.

`#/search?q=` has no anchor anywhere. A user reaches it by TYPING in the search box and submitting.

## Mechanism chosen: (1) drive the rendered controls

Justification, and why the other two were rejected:

- **(2) runtime router table cannot satisfy the acceptance test.** Angular's `router.config` is a
  list of PATH patterns. `q` is a QUERY parameter, not a path segment - it is not in the route
  table at all. Extracting the table yields `#/search` with zero parameters, which the sweep
  correctly skips for exactly the reason the ticket describes. It would move the problem, not
  solve it. (Bundle scraping was already disproved upstream: juice-shop's chunks yield no
  `path:"..."` matches.)
- **(3) seed-probing invented param names is refused on principle here** (memory:
  "Probe with observed values" - never probe with an invented value). It would also be a
  benchmark-specific signature the moment the seed list is tuned to make juice-shop pass.
- **(1) is the only mechanism where the APPLICATION supplies the parameter name.** We type a
  benign marker into a control the app rendered, the app decides where to navigate, and we read
  `location.hash` back. The route AND the parameter name are both observed facts. The marker is a
  discovery vehicle, not a probe value: no oracle reads it, and no verdict depends on it.

## Measurements

### M1. The home page renders exactly ONE typeable control, and it is 4px wide (MEASURED)

Throwaway container, `--network apolaki_default`, playwright + chromium, `http://juice-shop:3000/`,
after a bounded wait for `a[href^="#"]`:

```
hash: "#/"
INPUTS:
   {"tag":"input","type":"text","id":"","name":"","ph":"","aria":"","w":4,"h":50,
    "disp":"block","vis":"visible","parent":"div","gp":"app-mat-search-bar"}
```

One input on the whole page. It is DISPLAYED (`display:block`, `visibility:visible`) but collapsed
to a 4px box because juice-shop's `app-mat-search-bar` is closed. This is load-bearing: any
"visible" test stricter than BIE's (displayed AND a non-empty box) discards the only control that
matters and the module would report "no controls" on the very application it was written for.
`spa_routes.control_js()` therefore uses BIE's exact definition.

### M2. Typing into it and pressing Enter navigates to `#/search?q=` (MEASURED)

```
target http://juice-shop:3000/ inputs: 1 hash0: #/
  [0] before=http://juice-shop:3000/#/
      after=http://juice-shop:3000/#/search?q=apolakimark1  changed=True
```

The application chose the route AND the parameter name. Neither was supplied by us.

### M3. ACCEPTANCE TEST - the route list for `http://juice-shop:3000/`, no hand-supplied URL

```
$ docker run --rm --network apolaki_default -v .../agent:/app ... python show.py http://juice-shop:3000/ 1

note: 1 route(s), 1 parameterised, from 1 control attempt(s)
pages: [{"url": "http://juice-shop:3000", "settle": "networkidle+controls"}]
urls: ["http://juice-shop:3000/#/search?q="]
routes:
   {"url": "http://juice-shop:3000/#/search?q=", "path": "#/search", "params": ["q"],
    "parameterized": true, "observed_url": "http://juice-shop:3000/#/search?q=apolakirt7"}
attempts:
   {"ctl": {"tag":"input","type":"text","id":"","aria":"","width":4,"height":50},
    "before": "http://juice-shop:3000/#/",
    "after":  "http://juice-shop:3000/#/search?q=apolakirt7", "changed": true, "failure": ""}
errors: []
inventory: [{"host":"juice-shop:3000","path":"#/search","params":["q"],"parameterized":true,
             "body_sink":false,"content_type":"","example":"http://juice-shop:3000/#/search?q="}]
```

`#/search` WITH its `q` parameter, discovered from the origin alone. The last line is
`surface.build_inventory` fed with this module's own output: the planner files it as a
PARAMETERIZED page, which is the input the Q-161/Q-159/Q-153 chain has been waiting for.

### M4. Test suite for this module: 28 passed, 0 skipped

```
$ docker run --rm --network apolaki_default -v .../agent:/app -w /app apolaki-agent \
    python -m pytest tests/test_spa_routes.py -p no:cacheprovider -q
............................                                             [100%]
```

Includes four LIVE tests against juice-shop (acceptance, re-drive proof, password negative
control, scope gate). They call `pytest.skip("... lab unreachable ...")` only on a connection
failure, which `tests/conftest.py` converts into a hard session failure - so this file cannot
silently shrink on a networkless run.

## Design notes worth carrying forward

- **`parameterized` is COMPUTED, never asserted.** It is the single field the sweep keys on. A
  record that declared it would push every param-free route into the probe queue and the module
  would look like it worked. `test_route_record_refuses_to_call_a_bare_route_parameterized` is the
  negative control.
- **`inventory_path` is cross-checked against `surface.build_inventory`, not restated.** If the two
  ever drift, this module reports a discovery the planner never receives - exactly the Q-161
  failure. Two tests pin it, one of them on a sub-directory app (`/app#/report`).
- **READ-ONLY BY MECHANISM.** `input[type=password]` is never typed into, and while the drive runs
  every non-GET/HEAD request is aborted at the route layer, so a login POST or a comment POST
  cannot leave the browser. The gate calls `route.fallback()` (not `continue_()`) on safe methods
  so `browser_engine`'s rate gate further down the handler chain is not shadowed.
  HONEST LIMITATION: an app that navigates only AFTER a successful write will not be followed.
  That is a false negative, and it is the correct side to fail on.
- **No fixed sleeps.** Every wait is `wait_for_function` / `wait_for_load_state` with a bound.
  `test_module_issues_no_fixed_sleep` asserts this over the AST (a substring check would fire on
  the docstring that explains the rule, and would pass a `getattr`-built call), and carries a
  POSITIVE CONTROL - the same walk must still find the condition waits, so an empty banned-list is
  "no sleeps" and not "the walk found nothing".
- **No route literal anywhere in `spa_routes.py`.** No "/search", no seed parameter list. The test
  names what juice-shop answers; the module only asks.
