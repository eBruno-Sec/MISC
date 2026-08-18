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

## 3. Status

| item | state |
|---|---|
| 1. measurement of current behaviour | **MEASURED** -- section 1 |
| 2. both header forms | **MEASURED already working** (`c02208d`, not this lane) |
| 3. a cap, stated and explained | **half** -- per-observation cap measured at 30 s; cumulative wait measured UNBOUNDED at 270 s. GAP-1. |
| 4. the wait is visible in the ledger | **in progress** -- measured absent (GAP-2) |
| 5. negative controls | **MEASURED already working** (`c02208d`, not this lane) |
| anti-idle: mirror-defect audit | in progress |
