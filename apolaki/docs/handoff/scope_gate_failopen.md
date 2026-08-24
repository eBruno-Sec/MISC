# Q-099 — `findings_gate.off_scope` FAILS OPEN where scope is least trustworthy

Lane handoff. Written as I go; if this lane dies, this file is the contribution.

Baseline at start (stated by Coordinator, to be re-measured): **3604 passed / 11 skipped / 12 xfailed / 0 failed**.

---

## 1. What the defect actually is (READ)

`agent/findings_gate.py:off_scope(finding, scope) -> bool` returns **True to BLOCK**. So every
`return False` **ADMITS** the finding. Five `return False` arms exist; the ticket names two:

| line | condition | comment in code | ticket? |
|---|---|---|---|
| 83  | `not in_scope` | "no scope configured -> nothing to enforce" | no |
| 91  | target is not `http(s)://` | cloud/network namespace, not web scope | no |
| 93  | `not _host_of(target)` on an http(s) URL | "no host to judge -> admit (fail-open)" | **YES** |
| 104 | `except Exception` around `load_manual` + `validate` | "scope engine unavailable -> do not block" | **YES** |

Q-096 made `scope.load_manual` **raise `ScopeConfigurationError`** on an all-pattern scope. The
stored mission dict's `scope["in_scope"]` for such a mission is NON-empty (`ScopeEngine.to_dict`
at `scope.py:398` concatenates `in_scope + in_scope_patterns`), so line 83 does not catch it —
execution reaches line 94, `load_manual` raises, line 104 swallows it, and **every** finding from a
mission whose boundary could not be built is admitted.

## 2. Consumers of the return contract (SEARCHED — before changing anything)

`off_scope` is called from exactly **one** production site:

- `agent/db.py:278` inside `db._gate(mid, finding)` → verdict `"reject"` → `add_finding` returns
  `FindingWriteId("", REFUSED)`; `update_finding` returns `UPDATE_REFUSED`. `_gate` is the single
  chokepoint for BOTH write paths (`tests/test_gate_write_paths.py` pins that).

Test-side readers: `tests/test_findings_gate.py:36-48`, `tests/test_gate_write_paths.py:59`.

Downstream consumers of the REFUSED verdict already exist and already report it, so a refusal is
NOT invisible at the API surface:
- `main.py:3497` cloud-ingest → `results.findings_refused_off_scope`
- `main.py:4137` `/restore` → `findings_refused_off_scope`
- `main.py:3796` `PATCH` finding → `HTTPException(409, "the edit was refused: …")`
- `main.py:3969` lead promotion → `HTTPException(409, …)`

**Conclusion: the bool contract does not need to change.** `True` already means "refuse, do not
write", and every consumer already handles it. Q-099 is a change of DIRECTION on two arms plus a
new way to ask WHY, not a change of type. That keeps the blast radius at the two arms named.

`db.py` is NOT writable by this lane, so the mission-level error must be surfaced from
`findings_gate.py` (a reason function) and `main.py` (the surfaces), not from `_gate`.

## 3. Decisions

### D1 — reverse both arms, block on unknown

Both become `return True`. Rationale is the ticket's and `main.py:3081`'s: an engine failing
closed loses a finding; a SCOPE gate failing open puts an out-of-scope finding into a report
submitted to a bug bounty program. "Unknown is not permission."

### D2 — `scope_refusal(scope) -> str`, a new public helper in `findings_gate.py`

`off_scope` returning a bare `True` cannot tell an operator WHY. `scope_refusal` builds the same
throwaway `ScopeEngine` and returns `""` when the boundary is enforceable, or an actionable
sentence naming the exception type and the entry when it is not. `off_scope` is implemented in
terms of it, so there is ONE decision, not two that can drift.

### D3 — `main.py:_scope_for()` surfaces `HTTPException(409)`, not a 500 (the UX question)

**Chosen: 409 Conflict with an actionable message, no fallback engine, no tolerant re-parse.**

Rejected alternatives and why:
- *Return a permissive engine* — re-creates the exact fail-open this ticket exists to close, one
  layer up. Any of the five `_scope_for` consumers (`/workbench/*/replay`, `/fuzz`, `/diff`,
  `/curl/*`, `/access-check/*`) would then send live traffic under a boundary nobody can state.
- *Return an empty engine that refuses everything* — safe, but indistinguishable at the UI from
  "you typed an off-scope URL" (`_scope_guard` raises `400 Off-scope: …`). The operator would
  chase their own URL instead of the mission's stored scope.
- *404* — untrue; the mission exists.
- *422* — untrue; the REQUEST is well-formed. The stored mission scope is what is invalid.
- *500 / unhandled* — the status quo the ticket calls poor UX.

409 matches the precedent already set for this exact condition at `main.py:3115` (the retest scope
guard refusal) and at `main.py:3796`/`3969`. Same vocabulary, same direction, one story.

---

## 4. RED gate — MEASURED before the fix

`agent/tests/test_scope_gate_fails_closed.py`, 11 tests, run in a throwaway container:

```
docker run --rm --network apolaki_default -v ".../agent:/app" -w /app apolaki-agent \
  python -m pytest tests/test_scope_gate_fails_closed.py -p no:cacheprovider -q --tb=line
6 failed, 5 passed
```

The six failures, verbatim, with the headline first:

```
E AssertionError: a mission with no enforceable boundary published 7 finding(s)
E AssertionError: all-pattern            (off_scope returned False -> ADMIT)
E AssertionError: http://                (no parseable host -> ADMIT)
E AttributeError: module 'findings_gate' has no attribute 'scope_refusal'
E AssertionError: a mission whose scope cannot be parsed reports no scope_error at all
E scope.ScopeConfigurationError: no in-scope entry can be a target: "^.*\.shopify\.com$", ...
                                        (escaped _scope_for; the TestClient re-raises it)
```

**Seven of seven findings published, including `http://evil.example.com/p` and
`https://www.shopify.com/x`, from a mission whose boundary could not be built at all.**

The five PASSING tests are the negative controls, and they pass BEFORE the fix on purpose — they
pin behaviour the fix must not change:

```
test_a_wellformed_scope_still_stores_every_in_scope_finding        (5/5 stored)
test_a_wellformed_scope_still_blocks_a_genuinely_off_scope_finding (REFUSED, 0 rows)
test_a_non_web_target_is_never_judged_by_the_web_scope_broken_or_not
test_the_409_is_a_new_state_and_not_the_ordinary_off_scope_refusal (400 Off-scope stays 400)
test_scope_for_still_returns_a_working_engine_for_a_wellformed_mission
```

Also MEASURED directly at HEAD, the raw predicate:

```
off_scope({"target": "http://evil.example.com/x"}, ALL_PATTERN_SCOPE)  -> False   (ADMIT)
off_scope({"target": "https://www.shopify.com/x"},  ALL_PATTERN_SCOPE) -> False   (ADMIT)
_host_of("http://")     -> ''      _host_of("http:///p") -> ''
_host_of("https://^.*\.shopify\.com$") -> '^.*\.shopify\.com$'   <- NOT empty; the pattern URL
                                        reaches the engine arm, not the no-host arm
```

## 5. Progress log

- [x] Read Q-099 + Q-096 tickets, `findings_gate.py`, `db.py` gate, `scope.py`, `main.py` guards.
- [x] Searched every consumer of the `off_scope` contract (section 2).
- [x] RED gate committed.
- [ ] Fix committed.
- [ ] Full suite green at >= baseline.
