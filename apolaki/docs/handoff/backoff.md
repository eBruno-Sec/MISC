# Q-043 -- target `Retry-After` policy. Backoff lane handoff.

Written as the work happens. Every row is MEASURED (command + real output) or UNVERIFIED.
An unmeasured row says `in progress`; it never carries a number.

Run commands below from the repo root with `$AGENT` = `<repo>/apolaki/agent`:

    docker run --rm --network apolaki_default -v "$AGENT:/app" -w /app apolaki-agent <cmd>

---

## 0. The first finding: the ticket's premise is out of date, and I checked before believing it

Q-043 says *"Verified independently: `Retry-After` appears NOWHERE in `agent/`."* That was true when
the ticket was filed. **It is no longer true.** `c02208d "Honor target Retry-After across leased
transports"` landed a real per-origin policy, and `docs/QUEUE.md:785` already lists `Q-043 c02208d`
among the closed tickets.

    git log --oneline -S "retry_after_seconds" -- apolaki/agent/
    7ed1f5e Wire ZAP execution with proof and rate guards
    c02208d Honor target Retry-After across leased transports

So this lane is **not** "implement Retry-After". It is "verify the implementation and close the gaps
it left". The ticket instructed me to establish which files READ the header versus merely mention it,
and that answer is now:

| file | reads it to decide a wait? | evidence |
|---|---|---|
| `agent/browser_engine.py` | **YES -- this is the implementation** | `retry_after_seconds()` + `TargetRatePolicy` (lines 51-160); also an in-page JS gate injected by `_instrument_script` |
| `agent/tools.py` | **YES -- it is the consumer** | `_target_client` (l.34), `_http_send` (l.1759), ZAP rate guard (l.9814-9890) |
| `agent/zap_client.py` | **YES -- feeds observations in** | `observe_rate_limits` docstring l.165; ZAP originates traffic outside the httpx hooks so it reports history rows back into the shared policy |

None of the three is a bare mention. The mention/implementation split the ticket warned about is
**not** the defect here; the defects are elsewhere, and they are below.

---

## 1. MEASURED -- current behaviour of the production transport

Not an inference. A local server that really answers `429`/`503` with a real `Retry-After`, driven
through the real `browser_engine.rate_limited_async_client` (the factory `tools._target_client`
wraps). No lab was used to provoke this: the house rules forbid provoking rate limiting on a
third-party host, and no local lab returns `429` on demand, so the smallest honest harness is a
loopback `ThreadingHTTPServer`. Two sequential requests; the gap between them is the whole
measurement.

    docker run ... python -u /measure/probe_backoff.py

| case | req 1 | req 2 | gap between requests | verdict |
|---|---|---|---|---|
| `Retry-After: 2` (delta-seconds) | 429 | 200 | **2.006 s** | honoured |
| `Retry-After: <HTTP-date +2s>` | 429 | 200 | **1.295 s** | honoured (date has 1s resolution, so a sub-2s gap is correct, not a miss) |
| `503` + `Retry-After: 2` | 503 | 200 | **2.004 s** | honoured |
| `429`, header ABSENT | 429 | 200 | **0.003 s** | correctly does not wait |
| `429`, `Retry-After: banana` | 429 | 200 | **0.002 s** | correctly does not wait, no crash |
| `200` carrying `Retry-After` | 200 | 200 | **0.003 s** | correctly does not wait |

**Positive control**: rows 1-3 are the proof the apparatus was looking. Every zero in rows 4-6 is
measured against that same harness, so the zeros mean "no wait", not "no instrument".

Cap, same run:

    "cap_default_max_wait_s": 30.0
    "observed_delay_for_Retry_After_86400": 30.0     <- 86400 clamped to 30
    "hard_max_s": 300.0

**Conclusion: done-items 1, 2, 3(partly) and 5 were ALREADY satisfied by `c02208d`.** I did not build
them and I am not claiming them. Both header forms parse, both limiting statuses are covered, the
negative controls are clean, and a single absurd value is clamped.

---

## 2. MEASURED -- the two real gaps `c02208d` left

    docker run ... python -u /measure/probe_bounds.py

### GAP-1 -- the cap bounds ONE OBSERVATION, not the wait. A caller was parked 270 s under a 30 s cap.

The deadline is extend-only and shared per origin, and `wait_sync`/`wait_async` re-read it after every
sleep. A sibling worker that meets a fresh `429` while another caller is already waiting **pushes the
deadline out from under it**. Eight such extensions, each individually capped at 30 s:

    "B_per_observation_cap_s":        30.0
    "B_single_caller_total_wait_s":   270.0
    "B_sleep_calls":                  9
    "B_exceeds_cap":                  true

270 s against a documented 30 s bound. This is exactly the failure done-item 3 exists to prevent --
"an unbounded honour is a denial-of-service against your own mission" -- and it survives the cap
because the cap is applied in `observe()` (per header) and never in the wait loop (per caller).
A target under sustained load, or a hostile one with a few parallel-request paths, parks the scan.

### GAP-2 -- the wait is INVISIBLE. Nothing records it, so a backoff and a slow engine are identical.

The policy's entire public surface, measured by reflection:

    "C_policy_public_surface": ["clear", "observe", "remaining", "wait_async", "wait_sync"]

No counter, no event, no accounting. `wait_sync`/`wait_async` do return the seconds waited, and
**every one of the call sites discards that return value** -- `tools.py` lines 1759, 3487, 6900,
6912, 6919, 8516, 9847, 9876, 9890, 9939 and `browser_engine.py` l.410. So a mission that spent
minutes parked on target cooldowns reports exactly what a healthy fast mission reports. This is
done-item 4, and it is unmet.

The ZAP path is the one exception and it is already correct: `tools.py:9835` turns a target cooldown
into a ToolResult error that says *"ZAP stopped on target rate limit ... No clean or vulnerability
verdict was produced."* That is the right shape -- a cooldown abort is not a clean scan.

### GAP-3 (robustness, found by being bitten) -- `wait_sync` has no iteration bound

    "A_frozen_clock_spins": 50001

`wait_sync` loops `while remaining > 0: sleep(remaining)`. If the injected sleep does not advance the
clock it busy-loops with no bound. This is not reachable with the production `time.sleep`, but it ate
my own first measurement run, and it is a live trap for any future test that injects a no-op sleep --
which the house rules explicitly require tests to do.

---

## 3. FIX 1 -- the gate crossing is bounded, and the bound is proved by killing the mutant

`agent/browser_engine.py`, `agent/tests/test_backoff_bounds.py`.

**The number is 30 seconds, and it is the same number as the per-observation cap**
(`RATE_POLICY_DEFAULT_MAX_SECONDS`, env `BBH_RETRY_AFTER_MAX_SECONDS`, hard ceiling 300 s). One gate
crossing now waits at most that in total, however many times the deadline moves underneath it.

Why 30 s: it is long enough to ride out the cooldown that real rate limiters actually ask for
(`Retry-After: 1`-`10` is the common case, and all three measured honour-rows above are inside it),
and short enough that a hostile `Retry-After: 86400` costs the mission half a minute per request
instead of a day. Reusing the existing cap rather than inventing a second knob keeps one number for
an operator to reason about.

**What happens at the bound**: the request GOES OUT, and the truncation is recorded. Two reasons.
Stopping the mission is a worse failure than one request sent inside a cooldown -- that is the false
negative this ticket is about. And the deadline SURVIVES the crossing, so the next request waits
again: the target is still honoured on every request, we simply refuse to be parked indefinitely on
any one of them. A test pins that (`..._survives_a_truncated_crossing_so_the_next_request_waits_again`),
because without it the bound would quietly decay into "ignore Retry-After after the first 30 s".

Also fixed, GAP-3: `_WAIT_ITERATION_CAP = 64` bounds the re-read loop.

### MEASURED -- the mutation check

The pre-fix `wait_sync`/`wait_async` bodies restored verbatim, new tests run against them:

    docker run ... python -u /measure/mutant_backoff.py

    KILLED    GAP-1 moving deadline  <- AssertionError: a sibling's 429 extended the deadline
                                        out from under a waiting caller
    KILLED    GAP-1 truncation token  <- AssertionError
    KILLED    GAP-2 attribution  <- AssertionError
    KILLED    GAP-2 process counters  <- AssertionError
    SURVIVED  POSITIVE CONTROL ordinary cooldown
    SURVIVED  NEGATIVE CONTROL no rate limiting
    MUTANT total wait under a 30s cap: 270.0s in 9 sleeps

The four defect-holding tests fail against the old code, so they hold the defect rather than
describing the fix. The two controls pass against BOTH -- they must, because they describe behaviour
`c02208d` already had right, and a control that only passes after the change is not a control.

    docker run ... python -m pytest tests/test_backoff_bounds.py tests/test_rate_policy.py \
        tests/test_zap_rate_policy.py -q
    39 passed

No test sleeps for real; the clock and both sleepers are injected.

## 4. FIX 2 -- the wait is visible in the tool ledger

`agent/tools.py`, `agent/tests/test_backoff_ledger.py`. **`agent/main.py` was NOT edited.**

`ToolRegistry.execute()` opens a `rate_wait_scope()` around exactly the span the ledger rows already
bracket, so the cooldown a dispatch paid for is the cooldown its row reports. A ContextVar, not a
global counter read either side of the dispatch: engines run concurrently and a global delta bills
one engine for another's wait. A test pins that (`..._not_billed_for_each_others_cooldowns`).

`_ledger_outcome` then does two things:

1. **PREPENDS** `[backoff 4.0s x1]` (or `[backoff 30.0s x2, truncated at cap]`) to the `output` the
   ledger already aggregates into its note. Prepended because `_tool_ledger` cuts the note at 140
   characters and a suffix on a real engine's output is a report nobody can read -- a test pins it
   against a 400-character output. This is why no `main.py` change is needed to see it today.
2. Writes a typed `tool_backoff` row -- `{tool, seconds, waits, truncated, origins}` -- which
   `_tool_ledger` ignores (it filters on known types), so it is inert today and durable in the event
   log from now. The producer patch that consumes it is in section 6.

**Zero backoff changes nothing.** `describe_wait()` returns `""` when nothing waited, so a mission
that met no rate limiting logs byte-for-byte what it logged before. That is the compatibility
guarantee and it has its own test; it is also why this did not move any existing ledger assertion.

**The Q-067 hazard, and the control for it.** `_tool_ledger` splits a verdict from a fault by
PREFIX (`err.startswith(NEGATIVE_RESULT_TOKEN)`). Prepending to a verdict would report a correct
"not present" as a broken engine -- re-breaking precisely what Q-067 landed to fix. So the error
path is decorated ONLY for a plain fault; a Q-067 verdict and a scope block are left byte-identical,
each with its own test, and `test_a_plain_fault_IS_decorated` is the positive control that stops
those two passing because the feature does nothing at all.

    docker run ... python -m pytest tests/test_backoff_ledger.py -q
    9 passed

The end-to-end assertions run the REAL `main._tool_ledger` over a real sqlite mission, so "visible in
the ledger" is measured at the rendered row, not at the log call.

---

## 5. ANTI-IDLE -- the mirror-defect audit, with counts

The brief asked for other server-directed controls that are READ but not ACTED on. Measured against
the real transport, with a positive control first so the zeros are meaningful:

    docker run ... python -u /measure/probe_audit.py

| control the server sent | gap before the next request | acted on? |
|---|---|---|
| `429` + `Retry-After: 2` (POSITIVE CONTROL) | **2.006 s** | yes |
| `429` with NO `Retry-After` | **0.003 s** | **no** |
| `429` + `RateLimit-Remaining: 0` / `RateLimit-Reset: 2` | **0.003 s** | **no** |
| `Retry-After: 2` on a `307` redirect | **0.006 s** | **no** |

**Three unacted controls, and one bypass class:**

1. **A bare `429`/`503` produces ZERO backoff.** `Retry-After` is OPTIONAL in RFC 9110 -- the status
   is itself the instruction to slow down. `observe()` returns `None` with no header, so the most
   common real-world rate limit is honoured not at all. This is the largest of the four and the same
   false-negative shape as the original ticket.
2. **`RateLimit-*` / `X-RateLimit-*` are never read.** Occurrences in `agent/` (excluding tests):
   **0**. GitHub, most API gateways and every RFC-9239-style limiter use these.
3. **`Retry-After` on a `3xx` is ignored.** `_RETRY_STATUSES = frozenset({429, 503})`; RFC 9110
   permits the header on a 3xx and Apolaki parses it only for those two statuses.
4. **7 target-traffic modules bypass the shared policy entirely**: `auth.py`, `authz.py`,
   `register.py`, `replay.py`, `bwapp_solvers.py`, `codeintel.py`, `mutillidae_solvers.py` -- each
   builds a raw `httpx` client and never references `browser_engine`. Counted by grep; all seven are
   outside this lane's write scope. `proxy.py` (`wait_sync` + `observe`) and `juiceshop_solvers.py`
   (via `browser_engine.drive`) are correctly covered, and `zap_client.py` / `cdp.py` talk to the
   ZAP daemon and browserless -- control plane, not target -- so they are correctly exempt.

**Deliberately NOT fixed here, and why.** Each of items 1-3 changes when Apolaki slows down against
every target, which moves scan timing platform-wide and would land unmeasured inside a ticket about
a different defect. The brief scoped this item to "audit and report with counts". Recommendation, in
priority order: item 1 with a small fixed default (2-5 s) so a bare `429` is not free; item 2 reading
`RateLimit-Reset` through the SAME cap; item 3 by widening `_RETRY_STATUSES` to any 3xx carrying the
header. Item 4 is a lane of its own -- seven modules, one owner each.

---

## 6. PATCH WANTED -- `agent/main.py`, not editable by this lane

The `tool_backoff` rows are already being written. To surface them as a first-class ledger column
rather than a note prefix, `main._tool_ledger` needs three small changes. Consistent with Q-067/Q-069:
a backoff is neither "ran and concluded" nor "broke", so it must NOT touch the status heuristic.

1. Line ~959, admit the type:

        if not t or l.get("type") not in ("tool_call", "tool_result", "tool_error",
                                          "scope_block", "tool_negative", "tool_backoff"):

2. Line ~964, two more accumulator keys: `"backoff_s": 0.0, "backoff_waits": 0`.

3. In the type ladder, before the `else:` that handles faults:

        elif typ == "tool_backoff":
            a["backoff_s"] += float(l.get("seconds") or 0.0)
            a["backoff_waits"] += int(l.get("waits") or 0)

   and in the row dict, `"backoff_s": round(a["backoff_s"], 1)`. A `tool_backoff` row must not
   increment `calls`, `ok`, `errors` or `negatives` -- it is not an outcome, it is time spent inside
   one. `test_the_typed_row_does_not_disturb_the_rendered_ledger` already pins that from this side.

Until it lands, the note prefix carries the information and nothing is lost.

---

## 7. Status

| item | state |
|---|---|
| 1. measurement of current behaviour | **MEASURED** -- section 1 |
| 2. both header forms | **MEASURED already working** (`c02208d`, not this lane) |
| 3. a cap, stated and explained | **MEASURED fixed** -- 30 s, now bounding the wait and not only the header; mutant parked 270 s, fix holds at 30 s |
| 4. the wait is visible in the ledger | **MEASURED fixed** -- section 4, asserted at the rendered row via the real `main._tool_ledger` |
| 5. negative controls | **MEASURED** -- `c02208d`'s three still hold, plus five new ones (no-wait compatibility, Q-067 verdict, scope block, no-header, cross-dispatch billing) |
| anti-idle: mirror-defect audit | **MEASURED** -- section 5, 3 unacted controls + 7 bypassing modules |
| full suite | in progress |
