# Sessions lane — Q-032/033/034

Ticket: `session_headers` is a single global raw dict referenced at ~50 sites, so Apolaki cannot
hold two identities at once without them contaminating each other.

Status legend: MEASURED = command + real output in this file. UNVERIFIED = not yet proven.

---

## Slice 1 — the measurement (what the global actually costs)

### The count, MEASURED

```
$ grep -rn "session_headers" --include=*.py . | wc -l
83
$ grep -rn "session_headers" --include=*.py . | cut -d: -f1 | sort | uniq -c | sort -rn
     54 ./agent/tools.py
      6 ./agent/tests/test_bbh.py
      5 ./agent/main.py
      5 ./agent/agent.py
      4 ./agent/tests/test_tech_producer.py
      4 ./agent/tests/test_session_lifecycle.py
      1 ./agent/tests/test_sweep_class_coverage.py
      ... (4 more test files, 1 each)
```

"~50 sites" is CONFIRMED for `agent/tools.py` (54). Total across the codebase is 83, of which 19
are in tests and 10 in `main.py`/`agent.py`.

**But the site count is the wrong number.** Of the 54 sites in `tools.py`, 45 are the read-only
shape `{"User-Agent": _UA, **(self.session_headers or {})}` — a probe deliberately made AS THE
MISSION, with no caller identity involved. Those are correct today and need no change. The cost is
concentrated in **two transport choke points that merge the global into headers a caller supplied**:

| line | function | shape |
|---|---|---|
| 1613 | `_http_send` | `h = {"User-Agent": _UA, **(self.session_headers or {}), **(headers or {})}` |
| 3279 | `_http` | `req_headers = {"User-Agent": _UA, **(self.session_headers or {}), **(headers or {})}` |

### Mutation of the global mid-mission, MEASURED

```
$ grep -rn "session_headers\s*=" --include=*.py . | grep -v "==" | grep -v "session_headers: dict"
./agent/agent.py:1527:            self.tools.session_headers = {**sh, **sess}      <-- REBIND, mid-mission
./agent/main.py:554,567                                                            <-- construction
./agent/tools.py:1134:        self.session_headers = session_headers or {}         <-- construction
(remaining hits are test files)

$ grep -rn "session_headers\.\(update\|pop\|clear\|setdefault\)\|session_headers\[" --include=*.py .
./agent/main.py:563:            session_headers.update(res.get("headers", {}))     <-- pre-construction only
```

VERDICT: exactly **one** mid-mission write, `agent/agent.py:1527`, inside `_do_scan_auth`, gated on
`self.authenticated_scan and verified`. It is a REBIND, not an in-place mutation, so a reference
captured earlier is not retroactively changed. Every engine dispatched AFTER the auth artery runs
as a different identity than engines dispatched before it. That is by design and is announced in an
event, so it is not itself the defect — but it means the global is genuinely non-constant during a
mission, which is what makes the contamination below reachable in a real run.

### Contamination, MEASURED at the wire

Two shapes. Both are ORACLE defects, not tidiness defects.

**Shape 1 — the anonymous control row is not anonymous.** `_authz_matrix._headers_for`
(`tools.py:2018`) returns `{}` for rank 0 to mean "as nobody", then hands it to `_http_send`, which
merges the mission session straight back in.

**Shape 2 — cross-scheme bleed.** A Cookie-authenticated mission and a Bearer-authenticated persona
do not collide on a dict key, so BOTH ride the same request and the server chooses which identity
served it.

Proven by `agent/tests/test_session_identity.py`, which patches `tools._target_client` — i.e. BELOW
`_http_send`, so the merge under test still executes:

```
$ docker run --rm -v <HEAD-snapshot>/agent:/app -w /app apolaki-agent \
    python -m pytest tests/test_session_identity.py -p no:cacheprovider
E  AssertionError: the anonymous control row carried the mission session; ...
E    {'User-Agent': 'Mozilla/5.0 (compatible; Apolaki/2.0; +authorized-testing)',
E     'Cookie': 'sid=THE-MISSION-SESSION'}
E  AssertionError: the attacker persona's request also carried the mission's cookie ...
E    {'User-Agent': '...', 'Cookie': 'sid=THE-MISSION-SESSION',
E     'Authorization': 'Bearer ATTACKER-TOKEN'}
2 failed, 2 passed
```

### Why shape 1 is expensive, MEASURED by reading the oracle

`authz.build_matrix` reads the anon row THREE ways (`agent/authz.py:77-114`), and
`tools.py`'s horizontal-IDOR gate reads it a fourth way:

1. `missing_authentication` fires WHEN anon accessed the object (`authz.py:80`) -> a contaminated
   anon row accesses everything the mission can, so this **over-fires (FALSE POSITIVE, severity
   high) on every protected endpoint**.
2. `bfla` requires `not anon_got` (`authz.py:111`) -> **never fires (FALSE NEGATIVE)**.
3. horizontal IDOR requires `not _authz._accessed(sn, bn)` (`tools.py`, the `pair and anon_role`
   block) -> **every cross-user confirmation is suppressed (FALSE NEGATIVE)**.

So ONE contaminated row produces false positives in one gap type and false negatives in two others,
and it only does so when `authenticated_scan` is on — i.e. precisely on the runs that matter most.

### Why the suite was green on a real defect, MEASURED

Every existing authz/IDOR test monkeypatches `reg._http_send` itself
(`agent/tests/test_authz_matrix_driver.py:48` `reg._http_send = protected`, and the same pattern in
`test_bbh.py`). `_http_send` **is** the function that performs the contaminating merge, so the
defective line is never executed under test. The suite is not weak here; it is patched exactly at
the contamination boundary. Any test for this class of defect must patch below it — these do, at
`tools._target_client`.

### A site that got it RIGHT, MEASURED

`_run_bfla` (`tools.py`) computes the same anonymous baseline (`anon_results[m] = await send(c, m, {})`)
and is NOT contaminated: it builds its own `_target_client` and sends
`headers={"User-Agent": _UA, **h}`, never merging the global. The defect is not "anonymous baselines
are hard" -- it is specific to engines that route through `_http_send`/`_http`. Two engines with the
same requirement, one safe by having its own transport, one contaminated by sharing the mission's.

### Falsified sub-hypothesis

"Two personas contaminate each other." NOT REPRODUCED. Persona-to-persona is clean: both go through
`_role_headers`, they collide on the same key when they use the same auth scheme, and the caller's
headers win the merge. `test_two_personas_do_not_contaminate_each_other` PASSES on HEAD and is kept
as a negative control. The contamination is specifically **mission -> persona**, one direction.

---

## Slice 2 — the fix: `Identity`, a marked header dict

### The change

`tools.Identity(dict)` — a dict subclass meaning "these headers COMPLETELY specify who this request
is made as". Because it IS a dict, it flows through `**h`, `.get`, `.items` and every existing call
site unchanged; nothing had to be rewritten to accept it.

```
Identity()                 -> anonymous. A REAL input meaning "as nobody".
Identity({"Cookie": ...})  -> exactly this persona, nothing inherited.
{} / None / a plain dict   -> no opinion. Inherits the mission session, exactly as before.
```

One decision point, `ToolRegistry._merge_identity(headers)`:

```python
if isinstance(headers, Identity):
    return {"User-Agent": _UA, **headers}
return {"User-Agent": _UA, **(self.session_headers or {}), **(headers or {})}
```

Both transports (`_http_send` line 1613, `_http` line 3279) now call it instead of open-coding the
merge. One read accessor, `ToolRegistry._identity(role)`, returns `Identity(dict(self._sessions.get(role) or {}))`.

**Why the mission session is dropped WHOLESALE for an Identity, rather than filtering
credential-looking keys off it:** `session_headers` is built only from the operator's
`req.auth_headers` and from a login response's headers (`main.py:554,563`; `agent.py:1527`), so it
is an identity bundle by construction. A denylist of credential header names would be a guess that
fails silently on the first name it does not know -- the same shape as the defect being fixed.

**Why an unknown role returns `Identity()` and not the mission session:** a persona that failed to
mint must degrade to "as nobody" (a control row that proves nothing), never to "as the mission" (a
row that silently proves the wrong thing). This is the `x or DEFAULT` trap the codebase has paid
for four times; here the wrong default is an identity.

### Sites migrated vs left, MEASURED

| | count | disposition |
|---|---|---|
| `self.session_headers` in `tools.py` | 54 -> 52 | the 2 open-coded transport merges became `_merge_identity` |
| ...of which read-only mission probes | 45 | **LEFT UNCHANGED** - correct today; they act as the mission on purpose |
| persona header producers | 3 | `_resolve_headers`, `_role_headers`, `_authz_matrix._headers_for` -> return `Identity` |
| raw `self._sessions` role reads | 7 -> 0 | all routed through `_identity()` |
| `self._sessions` membership / whole-dict reads | 4 | **LEFT** - `in` tests and `_session_kill_is_safe`'s `.items()` sweep reveal no headers and send no request |
| files touched | 2 | `agent/tools.py`, `agent/tests/test_session_identity.py` |

`agent/bie.py` was NOT touched and needs no patch: `grep -n "session_headers\|_sessions\|_identity"
agent/bie.py` returns nothing, so the BOLA engine has no identity touchpoint of its own.

### The guard, and proof it is not checking a declaration

Two AST ratchets over `tools.py` source, both mutation-tested:

1. `test_self_sessions_is_read_through_exactly_one_accessor` - flags `self._sessions[role]` (Load)
   and `self._sessions.get(role)` outside `_identity`. Deliberately does NOT flag `role in
   self._sessions` or `.items()`: a rule broad enough to flag those would have been silenced as
   noise. First draft DID flag all four and was narrowed to the real shape.
2. `test_the_mission_session_is_merged_with_caller_headers_in_one_sanctioned_place` - flags any dict
   literal unpacking `session_headers` followed by a further unpack, outside `_merge_identity` and
   the allowlisted `_run_race` (a mission-identity probe that resolves no persona role).

Plus the behavioural guard `test_the_real_authz_matrix_drives_a_genuinely_anonymous_control_row`,
which drives the REAL `_run_authz_matrix` with a wiretap at `_target_client` and asserts on wire
headers -- a fact, not a declaration.

### Verification, MEASURED

Negative control (the guard must fail on the unfixed code):
```
$ git archive 22cbff1~1 | tar -x -C <head>   # HEAD before the fix, + the new test file
$ docker run ... pytest tests/test_session_identity.py::test_the_real_authz_matrix_drives_a_genuinely_anonymous_control_row
E  AssertionError: the matrix's anonymous control row reached the wire carrying the mission session:
E    {'User-Agent': '...', 'Cookie': 'sid=THE-MISSION-SESSION'}
1 failed
```

Mutation A - reintroduce a raw `_sessions` read (verified applied: `grep -c` returned 2):
```
E  assert not ['_confirm_create_object_idor (line 2274)', '_confirm_browser_persona_bola (line 2702)']
1 failed, 8 passed      <- ratchet 1 KILLED it and named both functions
```

Mutation B - make `_merge_identity` ignore `Identity` (`if isinstance(...)` -> `if False:`,
verified applied: `grep -c '        if False:'` returned 1):
```
FAILED test_an_anonymous_persona_request_carries_no_mission_session
FAILED test_the_real_authz_matrix_drives_a_genuinely_anonymous_control_row
FAILED test_a_bearer_persona_request_does_not_also_carry_the_missions_cookie
3 failed, 6 passed      <- KILLED by the behavioural tests including end-to-end
```
Snapshot restored and byte-compared to the working tree before the regression run.

Full suite, isolated snapshot of HEAD + this change (Rule 8c):
```
2659 passed, 11 skipped, 11 xfailed, 9 warnings in 497.30s
```
Ticket baseline was 2641/11/9. The delta is fully accounted for: +9 from this lane's new test file,
and +9 passed / +2 xfailed already present at HEAD from the islands lane's commit b49ce80 (its
message states "two MEASURED defects pinned as strict xfails"). **0 failed.**

---

## Coordinator side-task: delete the run_ferox / run_dirsearch / run_gobuster specs — BLOCKED, needs a decision

Attempted, MEASURED, and REVERTED unlanded. The two halves of the instruction ("delete the three
`CLAUDE_TOOLS` entries" and "leave the `_run_*` methods and `TOOL_PERMISSIONS` alone") are mutually
exclusive, and an existing gate proves it rather than merely suggesting it.

I removed the three spec entries and ran the tests named in the request:

```
$ pytest tests/test_bbh.py tests/test_engine_reachability.py tests/test_deadcode_gate.py \
         tests/test_island_soundness.py
2 failed, 275 passed, 2 xfailed in 223.20s
```

- **`test_engine_reachability.py::test_no_engine_is_defined_without_any_possible_caller`** FAILS:
  ```
  E  AssertionError: engines with no possible caller (implemented but unrunnable):
  E    ['run_dirsearch', 'run_ferox', 'run_gobuster']
  ```
  This gate is CORRECT and is the whole point of the no-islands rule: `reachable = _spec_names() |
  _planner_names()`, and these three engines are in neither once the specs go. The specs were the
  only thing making the methods reachable, so removing the specs converts them from "advertised and
  always failing" into "implemented and unrunnable". Both are defects; the gate refuses to trade one
  for the other.
- **`test_bbh.py::test_new_optional_binaries_and_permissions`** FAILS on
  `assert t in specs and hasattr(tools.ToolRegistry, "_" + t)` for all three names.
- `test_deadcode_gate.py` PASSED - no opinion.
- `test_island_soundness.py` PASSED, including its `("run_ferox", "recon")` parametrization: it
  tests `_is_confirmed` lead-routing by family, not spec presence. That lane's file is unaffected
  either way, and I did not touch it.

Not landed, and I did not delete further or adjust a ratchet baseline, per the instruction. Reverted
with `git checkout -- agent/tools.py`; the Identity work from 4982d3b is unaffected and
`tests/test_engine_reachability.py` + `tests/test_session_identity.py` are green (13 passed).

**The decision is yours, and it is a real one.** The subtractive framing ("purely subtractive, needs
no oracle argument") does not survive contact with the reachability gate: there is no edit that
removes the advertisement and leaves the implementation, because this codebase forbids exactly that
state. Three coherent options:

1. **Delete the specs AND the three `_run_*` methods AND their `TOOL_PERMISSIONS` entries.** The only
   option that is genuinely subtractive and leaves every gate green as written. Also requires
   updating the three names out of `test_bbh.py::test_new_optional_binaries_and_permissions`, whose
   purpose is "every advertised tool has a spec and a transport" - dropping names for tools that are
   deliberately no longer advertised is a correct update, not a weakening, but it is still a test
   edit and `test_bbh.py` is not in my write set.
2. **Keep the specs, fix the false advertisement instead.** Leave reachability untouched and rewrite
   the three descriptions to stop promising a capability the image cannot deliver - in particular
   drop "Recursive" from `run_ferox` (contradicted by the `--no-recursion` flag at `tools.py:1483`)
   and state that the native `run_content_discovery` + `run_ffuf` are preferred and carry a soft-404
   baseline these do not. This addresses the stated harm ("the product advertises a capability it
   cannot perform") with no gate conflict.
3. **Install the binaries** in the agent image, making the advertisement true. Costs image size for
   a capability the lane measured as a worse duplicate of a working native one; recorded for
   completeness, not recommended.

My read, offered as input rather than a decision: option 1 is what the request actually wants, and
its blocker is only that it needs one more file than the request allowed. Option 2 is the smaller
change and fixes the stated harm, but leaves three dead adapters in the tree.

## For the Coordinator

`agent/mutation_gate.py` is not mine. If `Identity` counts as a confirmed-producing path, the
mutant that belongs in `tests/test_mutation_gate.py` is the one proven above:

> In `ToolRegistry._merge_identity`, change `if isinstance(headers, Identity):` to `if False:`.
> Expected to be killed by `tests/test_session_identity.py` (3 tests, including the end-to-end
> `test_the_real_authz_matrix_drives_a_genuinely_anonymous_control_row`).

## Observations for other lanes (NOT acted on -- outside this ticket)

- `_run_bfla` builds `test_headers` from `inp["headers"]` only and never merges the mission session.
  Its "authenticated" row is therefore authenticated ONLY if a caller passed headers explicitly. On
  an `authenticated_scan` run where the caller passes none, both its rows are anonymous and
  `authz.analyze_methods` compares anonymous to anonymous. UNVERIFIED whether any caller passes
  them; worth a lane. This is the mirror image of the Q-032 defect (there the anon row was
  authenticated; here the authed row may be anonymous).
- `agent/agent.py:1527` rebinds `self.tools.session_headers` mid-mission, so engines dispatched
  before and after the auth artery run as different identities. Announced in an event and gated on
  `authenticated_scan and verified`, so not a defect on its own -- but it is what makes the
  contamination above reachable in a real run, and it means "which identity did this finding come
  from" is not recoverable from a finding record. Binding the identity into the finding at
  construction (the Q-051 shape) would close that.

