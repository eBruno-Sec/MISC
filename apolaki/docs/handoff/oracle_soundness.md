# Oracle soundness lane — Q-040, Q-041, Q-042

Baseline `505ed1c` (3366 passed / 11 skipped / 12 xfailed / 0 failed). All runs on the `apolaki-agent`
image, python 3.12.14, in a throwaway container. Every claim below is MEASURED (command + real
output) or explicitly marked UNVERIFIED.

## Verdict in one line

**All three tickets were already CLOSED before this lane started.** Q-040 by `cbcba79`, Q-041 and
Q-042 by `9f8707a`. The strict xfails the brief told me to find as specifications **do not exist** —
they were correctly retired in the same commits as their fixes. That is three disproved tickets, and
per the lane's own rule a disproved ticket is a full result.

The work that remained, and what this lane actually delivered, is one rung up: **the three fixes were
verified to be load-bearing by mutation, and Q-040's defect shape was then hunted across every
sibling oracle in the codebase. It is still alive in one of them.**

## How the tickets were confirmed closed

The queue is not evidence — it says `ready` at lines 2013/2020/2028 and `CLOSED` at line 1124, which
is exactly the declaration-vs-fact rot the queue itself keeps warning about. So each defect was
reproduced against the shipped functions.

    docker run --rm --network apolaki_default -v ".../agent:/app" -w /app apolaki-agent python probe.py

### Q-040 · `analyze_boolean` baseline stability — CLOSED, verified

`sqli_tool.analyze_boolean` now has a third outcome (`Inconclusive`, falsy so un-updated callers
degrade safely) and refuses any endpoint whose reference requests do not reproduce **byte-exactly**.

| input | result |
|---|---|
| flapping reference (`baseline_repeat` differs) | `Inconclusive("the reference request did not reproduce (1 of 2 …)")` |
| **stable reference + real differential** (negative control) | `True` — **still confirms** |
| stable reference, no differential | `False`, and `is False` still holds |
| reference request failed (`None`) | `Inconclusive` |
| no reference asked for (legacy call) | `True` — **the gate only runs when a caller supplies a sample** |

That last row is the important one and is the subject of the residual below.

### Q-041 · aliased module imports — CLOSED, verified

`_py_module_aliases` now resolves the binding `_py_imports` already computed, instead of matching a
hard-coded literal receiver.

| source | result |
|---|---|
| `import random` → `random.getrandbits(32)` (positive control) | CWE-330 |
| `import random as r` → `r.getrandbits(32)` | CWE-330 |
| `import hashlib as hl` → `hl.md5(...)` | CWE-328 |
| `import numpy.random as random` (negative control) | silent |
| `from numpy import random` (negative control) | silent |

Resolving the alias did **not** make the rule credulous — both numpy spellings stay silent, which is
the trade Q-041 and Q-042 were explicitly told not to make.

### Q-042 · `_PY_CLOCK_TOKEN` substring match — CLOSED, verified

Two structural facts replaced the substring match: an assignment is at bracket depth 0 (so `f(token=…)`
is a keyword argument, not a binding), and a compound identifier means its **head noun**.

| source | result |
|---|---|
| `session_token = time.time()` (positive control) | CWE-337 |
| `expiry_token = time.time()` (positive control) | CWE-337 |
| `token_expiry = time.time() + 3600` | silent |
| `session_start = time.time()` | silent |
| `f(token=time.time())` — the wild instance from `anthropic/lib/credentials/_workload.py:346` | silent |

## The fixes are load-bearing — mutation results

A passing test may pin nothing. Each fix was reverted in an isolated snapshot, **every mutation
grepped to prove it landed before the run** (a mutation that never applied is a false all-clear).

| mutation | reverts | tests killed |
|---|---|---|
| `r != refs[0]` → `similar(r, refs[0]) < thresh` | Q-040 reproduction gate → old threshold | **2** — `test_a_weak_random_page_must_not_confirm_blind_sqli`, `test_weak_random_noise_must_not_confirm_at_scale` |
| `names = {…}` → `names = set()` | Q-041 alias binding discarded | **2** — `test_an_aliased_random_module_import_is_still_the_stdlib_generator`, `test_an_aliased_hashlib_import_is_still_the_stdlib_digest` |
| head-noun check → `if False:` | Q-042 back to substring | **4** — incl. `test_the_java_clock_rule_got_the_same_fix` and the JS sibling, so the fix is pinned in **three dialects** |
| paren-depth check → `if False:` | Q-042 kwarg check | **1** — `test_a_keyword_argument_named_token_is_not_an_assignment` |

Zero surviving mutants. All snapshots restored and verified clean (`grep -c MUTANT` → 0).

## NEW — Q-040's shape is alive in a third oracle · `username_enum_tool.enumerable`

Having confirmed Q-040 closed, the shape was hunted across every module carrying a similarity
differential: `sqli_tool`, `nosqli_tool`, `header_trust_tool`, `web_security`, `username_enum_tool`.
The first four carry the discipline explicitly. The fifth does not.

**This is not a missing control — the control is present, correct, and skipped.** `enumerable`
receives two different non-existent usernames precisely so it can measure the endpoint's own noise
floor, and on the body path it does exactly that (`signal < noise - _MARGIN`). But the status-oracle
branch sits **above** the floor and returns first:

    s_pres, s_abs = int(present.get("status") or 0), int(absent1.get("status") or 0)
    …
    if s_pres and s_abs and s_pres != s_abs:
        return (… "status oracle", "CWE-204")

`absent2["status"]` is never read on any path.

MEASURED 2026-08-20, calling the shipped function directly:

* `absent2.status` varied over **200 / 302 / 401 / 500 / 503**, all else held constant → **the
  verdict never changed.** The second reference is structurally ignored.
* `absent1=200, absent2=500, present=500`, all three bodies **byte-identical** → **CONFIRMED**
  `"the existing account returns HTTP 500 while a non-existent one returns HTTP 200 (status oracle)"`.
  A false positive on an endpoint whose own second reference proves it is unstable.
* Negative control, same run: the **body** noise floor does hold, and a real status oracle on a
  stable endpoint still confirms. So the defect is confined to the one branch.

**Why it is reachable in production, not merely constructible.** The three probes are sent
sequentially to a login endpoint with deliberately wrong passwords, and `present` is sent **last**.
The ordinary mechanisms that change a login's status mid-sequence — a rate limiter or lockout
tripping, an intermittent 5xx — therefore land precisely on the sample that is read as signal.

**Honest negatives, recorded because a zero needs a positive control.**

* 30 identical-shape failed logins each against juice-shop, dvwa and bwapp gave one status apiece
  (`{401: 30}`, `{200: 30}`, `{200: 30}`) and one distinct body apiece. **This flap was not observed
  on our three standing login labs** and nothing here claims it was.
* The findings corpus (named volume `apolaki_bbh_data`, `db.init('/data/bbh.db')`) holds **1773
  findings across 154 missions** — positive control **101 CWE-89 rows**, matching the brief exactly,
  so the apparatus was looking — and contains **zero CWE-204 findings**. There is no stored
  production instance either. That cuts both ways and is recorded rather than argued.

The pin therefore rests on the **structural** measurement (the second reference is provably never
read), which does not depend on catching a flap in the wild.

**Pinned, not fixed.** `agent/username_enum_tool.py` has no owner in the QUEUE ownership table and is
not this lane's file, so this follows the protocol `test_boolean_oracle_stability.py` used for the
inert nosqli gate: a strict xfail plus a patch here.

Pin: `agent/tests/test_username_enum_stability.py::test_the_status_oracle_must_consult_both_reference_samples`
(commit `9fecdd1`). Its fixture is the **verbatim live `apolaki-juice-shop-1`** response to
`POST /rest/user/login` with a wrong password — HTTP 401, body `Invalid email or password.`,
byte-identical for an absent and a present account. Not invented.

### The patch — `agent/username_enum_tool.py`, zero extra requests

`absent2` is already fetched and already an argument, so requiring the two references to agree costs
nothing. In `enumerable`, after the existing `s_pres, s_abs = …` line:

    +    s_abs2 = int(absent2.get("status") or 0)   # the second reference, already fetched

and the status branch:

    -    if s_pres and s_abs and s_pres != s_abs:
    +    if s_pres and s_abs and s_pres != s_abs and s_abs == s_abs2:

**VERIFIED against the patch in a snapshot**, both directions:

* the pin becomes `XPASS(strict)` → the marker must be removed in the same commit;
* the mandatory negative control (`a real status oracle on a stable endpoint still confirms`) stays
  green — the fix does **not** trade a false positive for a false negative;
* the existing `tests/test_username_enum.py` suite: **18 passed**, no regression.

## Residual carried, not closed — the nosqli gate is still inert

`nosqli_tool.analyze_boolean` accepts `baseline_repeat`/`baseline_samples`, but its **only** caller,
`tools.ToolRegistry._run_nosqli` at `agent/tools.py:8373`, calls it positionally with no reference
sample. The control cannot run in production. This is already correctly pinned by a strict xfail in
`agent/tests/test_boolean_oracle_stability.py:378` with the patch in
`docs/handoff/boolean_oracle.md` section 5a — it is another lane's file and is **not** re-filed here.

Two corrections for whoever lands it:

* **Section 5a's line numbers have drifted.** It cites `agent/tools.py:7846` and `:7880`; today
  `7846` is a `sqli.union_hit` check. The patch **text** still applies verbatim; only the line
  numbers are stale. Measured anchors:

  | anchor | line | occurrences in `tools.py` |
  |---|---|---|
  | `base_r = await get(c, url)` | **8339** | **1 — unique, anchor on this** |
  | `if ns.analyze_boolean(base_body, op_r.text, ctl_body, miss_body):` | **8373** | **1 — unique** |
  | `base_body = base_r.text if base_r is not None else ""` | 7909 / **8340** / 8452 | **3 — NOT unique** |

  **Do not anchor the first hunk on the `base_body = …` line**: it appears three times and two of
  them are the sqli carrier. Anchor on `base_r = await get(c, url)`, which is unique, and insert
  after the `base_body` line that follows it.
* The xfail's own reason string repeats the stale `tools.py:7846`. Its *assertion* is derived from
  the AST (`_boolean_calls(tools.ToolRegistry._run_nosqli, "ns")`), so the pin itself is robust; only
  the prose misleads.

By contrast the **sqli** side is fully wired: `tools.py:7963` and `:8036` pass
`baseline_samples=base_samples[1:]`, the full N-sample form. The `analyze_boolean` docstring's claim
that "`tools.py:7463` forwards only `base_samples[1]`" is **stale** — that gap has since been closed.

## Files this lane touched

* `agent/tests/test_username_enum_stability.py` — new, the pin plus three controls.
* `docs/handoff/oracle_soundness.md` — this file.

Nothing else. `agent/sqli_tool.py`, `agent/nosqli_tool.py` and `agent/codeintel.py` were in the write
set but needed **no change** — their tickets were already closed and their fixes verified sound.
Every commit staged by explicit path after `git status --short`; other lanes were concurrently
modifying `asvs_model.py`, `test_zap_*` and `docs/handoff/zap_reach.md`, none of which were staged.
