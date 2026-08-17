# provenance lane - cycle 8, 2026-08-17

Tickets, in order: **Q-060** (two engines cannot test any target on a non-standard port),
**Q-064** (`ledger_finding_disagreement()` raises a false integrity alarm).

Files this lane may WRITE: `agent/agent.py`, `agent/report.py`, new tests under `agent/tests/`,
this file. Patches for anything else are recorded at the bottom, not applied.

Written as I go. A row with no number is `in progress`, never a claim.

---

## Q-060 - an origin rebuilt from a scope entry invents a port the operator never authorised

### Status

| slice | state | commit |
|---|---|---|
| reproduction in isolation | MEASURED | - |
| failing test written (10 cases) | MEASURED - 7 of 10 failed before the fix | - |
| fix in `_do_transport_posture` / `_do_header_trust` / `_browser_harvest_surface` | MEASURED - 10 of 10 pass | in progress |
| mutation test | in progress | - |
| full suite | in progress | - |

### The defect, reproduced (MEASURED)

```
$ docker run --rm --network apolaki_default -v .../agent:/app -w /app apolaki-agent python -c "..."
in_scope     ['juice-shop']
bases        ['http://juice-shop:3000']
transport reconstructed -> https://juice-shop  validate: (False, 'juice-shop:443 not in scope (host is in scope, but the operator pinned a different port)')
headertrust reconstructed -> http://juice-shop validate: (False, 'juice-shop:80 not in scope (host is in scope, but the operator pinned a different port)')
base_urls   -> http://juice-shop:3000          validate: (True, 'In scope via juice-shop:3000')
```

`ScopeEngine.load_manual` calls `_split_scope_entry`, which stores the BARE HOST in
`ScopeEntry.value` and parks the scheme+port in `ScopeEntry.base`. `to_dict()["in_scope"]` is the
bare-host list. Re-adding a default scheme to it therefore invents `:443` (or `:80`), and SEC-1 port
pinning correctly refuses the origin the driver itself built.

The last line is the fix in one row: `base_urls()` already returns the operator's own origin and
already validates. It was in the file the whole time - `_primary_base`, the API sweep
(`agent.py:3492`) and the model's TARGET BASE URLS block (`agent.py:3823`) all read it. These
drivers were the ones deriving their own.

### A THIRD caller, found by auditing for the shape rather than by the ticket

The ticket named `_do_transport_posture` and `_do_header_trust`. Grepping `agent.py` for `in_scope`
turned up 8 sites; a third carries the identical line:

```
agent.py:3411  _browser_harvest_surface
    seeds.append(s if "://" in s else "https://" + s.split("/")[0])
    ...
    if u in seen or not self.scope.validate(u)[0]:   # <- drops every seed it just built
        continue
```

That is the JS-rendered crawl. On a non-standard-port target the frontier is empty before the first
render, the harvest returns 0, and **0 is indistinguishable from an app with no client-rendered
surface** - so this failed silently rather than loudly. Gated on `CDP_BROWSER_URL`, which Q-062
established is set and consumed, so this is a live path and not a dormant one.

The other five `in_scope` sites are CORRECT and were left alone, which matters because "fix them
all" would have been wrong:

| site | what it does | verdict |
|---|---|---|
| `agent.py:2599` | reads `e.base` + `e.path` to seed a pinned sub-path | correct - carries |
| `agent.py:2913` | `e.value` as a graph host node | correct - host-level by intent |
| `agent.py:3261` | `e.value` as a base-root string for dedup | correct - host-level by intent |
| `agent.py:3762` | `in_scope` inside an AI prompt payload | correct - not a URL |
| `agent.py:318`  | `sweep_targets(in_scope=...)` is a PREDICATE, not the list | correct - different thing |

### The fix

One helper, `BBHAgent._scope_origins()`, used by all three drivers. It reads `scope.base_urls()`,
normalises to `scheme://netloc`, dedupes, and drops anything without both. It does not pre-filter on
`validate()`: a scope block is correct enforcement and must stay VISIBLE in the ledger (the Q-067
argument), so the driver keeps dispatching and the scope engine keeps refusing.

Two behaviour changes fall out of using `base_urls()` and both are improvements, recorded because
neither is forced by the ticket:

1. **Wildcards contribute no origin.** The old code built `https://*.example.com`, which
   `_matches` ACCEPTS (`'*.example.com'.endswith('.example.com')`) and DNS can never resolve - a
   real dispatch spent on a guaranteed failure. `base_urls()` skips wildcards. Pinned by
   `test_a_wildcard_asset_is_not_turned_into_a_hostname`.
2. **A bare host in `_do_header_trust` now defaults to `https://` rather than `http://`.** Same
   default the rest of `agent.py` already uses. Both validate identically (a bare entry pins no
   port), so no scope behaviour moves; only the scheme probed does. Pinned by
   `test_a_bare_host_still_gets_an_origin`.

### Tests - `agent/tests/test_scope_origin_carry.py`, 10 cases

Real `ToolRegistry` + real `ScopeEngine`; only the leaf engine body is substituted, so scope
validation, dispatch and the Q-061 ledger writes are all under test. Same construction as
`test_ledger_records_dispatch.py`.

BEFORE the fix - **7 failed, 3 passed** (`FFF..FFFF` plus one added later):

```
FAILED test_transport_posture_audits_the_port_the_operator_authorised
FAILED test_header_trust_audits_the_port_the_operator_authorised
FAILED test_the_browser_harvest_seed_carries_the_port_too
FAILED test_an_out_of_scope_host_is_still_refused_by_header_trust
FAILED test_an_explicitly_out_of_scope_host_never_becomes_an_origin
FAILED test_a_wildcard_asset_is_not_turned_into_a_hostname
FAILED test_no_driver_rebuilds_an_origin_from_a_bare_scope_host
```

with the headline message reproducing the live row exactly:

```
AssertionError: transport posture was handed []; the operator authorised 'http://juice-shop:3000'.
```

AFTER the fix: `..........  [100%]` - 10 passed.

The negative controls are the point of the module, since the wrong fix here is to widen scope:

- `test_the_scope_engine_still_refuses_the_invented_port` - `validate("https://juice-shop")`,
  `validate("http://juice-shop")` and `validate("http://juice-shop:3001")` must all stay False, with
  `validate("http://juice-shop:3000")` True as the positive control. If any of the first three ever
  flips, SEC-1 port pinning was traded away for this ticket.
- `test_an_out_of_scope_host_is_still_refused_by_header_trust` - the driver's other input is
  discovered URLs; an out-of-scope one is dispatched, never reaches the engine, and leaves a
  `scope_block` row. The in-scope origin running in the same pass is the positive control that the
  apparatus was looking.
- `test_an_explicitly_out_of_scope_host_never_becomes_an_origin` - deny-overrides-allow still wins
  when the same host appears on both lists.
- `test_a_bare_host_still_gets_an_origin` - the fix must not restrict the drivers to operators who
  happened to type a scheme.

### The ratchet, and the false positive it started with

`test_no_driver_rebuilds_an_origin_from_a_bare_scope_host` fails when any function in `agent.py`
both reads a scope entry and concatenates a scheme. Its first version was a line regex and it
flagged `_url_from_graph_key` (`agent.py:2984`), which consults `scope.base_map()` FIRST and falls
back only for a host the scope has never heard of - the CORRECT pattern, and itself a prior fix of
this same class. Recorded because a ratchet that fires on the fix is a ratchet that gets deleted.

Rewritten over the AST, per function, with docstrings stripped. Stripping is not cosmetic: the new
`_scope_origins` quotes the broken line verbatim to explain what it replaced, so a prose-reading
detector flags the fix as the defect - it did, on the first run. `test_the_ratchet_can_actually_see_
the_defect` is the paired positive/negative control: the detector must fire on the real source shape
and must NOT fire on a function whose docstring merely describes it.

---

## Q-064 - `ledger_finding_disagreement()` raises a false integrity alarm

Not started.

---

## Patches for files this lane does not own

None yet.
