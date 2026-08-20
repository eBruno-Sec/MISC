# Q-062 — two browser worlds: which one should Apolaki have?

Lane: browser-worlds (Breaker). Baseline `8c7065c` (3362 passed / 11 skipped / 12 xfailed / 0 failed).
Every number below was MEASURED on the live stack on 2026-08-20; nothing here is inferred from reading
code alone. Where a claim is a zero, the control that proves the apparatus was looking is stated next
to it.

---

## 0. The one-line answer

**Both worlds are real, both are consumed, and they serve different consumers.** The sidecar is not
dead infrastructure and must not be removed. What *is* wrong is that the tree says three different
things about which world is in play, and one capability row is true by accident.

The corrected statement of the situation:

| world | how it is reached | who calls it | proven by |
|---|---|---|---|
| local chromium (`pw.chromium.launch`) | Playwright, browsers baked into the agent image | the **engines** — `tools.py` (9 sites), `bie.py` (2 sites) | §2, §4 |
| browserless sidecar (`POST /function`) | `CDP_BROWSER_URL` over HTTP | the **API endpoint surface** — `/browser/observe`, `/cdp`, `/plan/{id}`, `/graph/attack/{id}`, `/findings/{id}/{fid}/poc`, plus one Juice Shop solver | §3, §5 |

Q-062's headline ("the sidecar served 0 sessions") is true of the window it measured and **false as a
statement about the sidecar**. See §5: the retained counter shows **509 sessions over the last ten
days**.

---

## 1. Apparatus, and why the first control was wrong

`GET /metrics` on browserless returns an array of **completed 5-minute periods**. The period in
progress is not in it — the container logs `Current period usage: …` and *then* saves. So a probe that
drives the sidecar and immediately re-reads `/metrics` sees **no change**, and would be recorded as a
zero.

MEASURED (this is the trap, reproduced deliberately):

```
counter BEFORE: 509
observe browser=True note='' links=0 scripts=0
counter AFTER sidecar observe: 509 delta= 0        <-- FALSE ZERO
```

The request had in fact landed. The sidecar's own ingress log, timestamped:

```
2026-08-20T21:47:35.872Z  Handling inbound HTTP request on "POST: /function?launch={"ignoreHTTPSErrors": true}"
2026-08-20T21:46:34.108Z  Current period usage: {...}   <-- period opened 61s BEFORE the request
```

**Therefore the counter is a lagging instrument (up to 300 s) and the ingress log is the immediate
one.** Every session claim below is taken from the ingress log and cross-checked against the counter
once the period flushed.

## 2. The local chromium is real and baked in

MEASURED, in a throwaway container on the shipping image:

```
PLAYWRIGHT_BROWSERS_PATH=/opt/pw-browsers
/opt/pw-browsers/chromium-1234
/opt/pw-browsers/chromium_headless_shell-1234
/opt/pw-browsers/ffmpeg-1011
```

So the engines' world needs no sidecar and no network hop. This also retires the guess that the local
launch works by accident.

## 3. The sidecar is reachable, healthy, and running a NEWER Chrome than the engines

MEASURED from the lab network:

```
GET /json/version  ->  Chrome/151.0.7922.34, Protocol-Version 1.3
GET /pressure      ->  isAvailable true, maxConcurrent 2, maxQueued 10, running 0
GET /config        ->  concurrent 2, timeout 30000, token null
```

## 4. The two worlds are disjoint — negative control at the sidecar's own ingress

Run back to back in one process, `CDP_BROWSER_URL` set, against authorized local labs:

```
browser_engine.observe("http://domsource:8080/hash")     -> browser=True
   sidecar ingress:  1x POST /function        <-- POSITIVE control fires
bie.available()                                          -> (True, 'playwright + chromium')
bie.run_persona_swap(base="http://clientauthz:8080", …)  -> ran=True browser=True findings=2
   sidecar ingress:  no request               <-- NEGATIVE control silent
```

A real BIE engine drove a real browser and confirmed **2 findings** without the sidecar seeing a single
byte. That is the disjointness, proven at the ingress rather than inferred from a counter.

## 5. The sidecar's real usage history: 509 sessions, then a cliff

`GET /metrics` retains **2922 five-minute periods — 2026-08-10 15:56Z .. 2026-08-20 21:41Z**, i.e. the
whole ten-day window. **68 of them are non-zero. Total successful sessions: 509.**

```
2026-08-10 15:56Z .. 2026-08-13 21:37Z   503 sessions across 66 periods   (heavy, daily)
2026-08-17 09:52Z                          1 session                       (Q-062's own manual control)
2026-08-20 03:06Z                          5 sessions                      (see below)
```

So the honest shape is a **cliff on 2026-08-13**, not an empty service. Q-062 sampled 12 consecutive
periods (60 minutes) during one mission and read the flat part of that curve.

The 2026-08-20 03:05:27–03:05:45Z cluster is five `POST /function` calls carrying
`launch={"ignoreHTTPSErrors": true}` — the byte-for-byte signature of `browser_engine.drive()`
(`agent/browser_engine.py:687`), and distinct from the mitmproxy-args variant that appears earlier in
the log. So product code, not a hand-rolled curl, called the sidecar **19 hours before this lane
started**.

## 6. Why a MISSION never touches it — the precise reason

Not "not selected". Every sidecar call site is an **HTTP endpoint handler or a lab solver**, and none
of them is on the autonomous mission path:

| call site | file:line | reached by |
|---|---|---|
| `/plan/{session_id}` | `agent/main.py:2136` | operator/API request |
| `/graph/attack/{session_id}` | `agent/main.py:2241` | operator/API request |
| `/browser/observe` | `agent/main.py:2189` | operator/API request |
| `/cdp` → `cdp.collect` | `agent/main.py:2362` | operator/API request |
| `/findings/{id}/{fid}/poc` → `screenshot` | `agent/main.py:3794` | operator/API request |
| Juice Shop browser solve | `agent/juiceshop_solvers.py:693` | lab solver, gated on `CDP_BROWSER_URL` |

Every other module that imports `browser_engine` — `tools.py`, `agent.py`, `auth.py`, `authz.py`,
`bie.py`, `codeintel.py`, `proxy.py`, `register.py`, `replay.py`, the solvers — imports it for the
**Q-043 rate policy** (`target_rate_policy`, `rate_limited_*`), which happens to live in the same
module. MEASURED: grepping those files for `browser_engine.(drive|observe|screenshot)` returns exactly
one hit outside `main.py` (`juiceshop_solvers.py:693`); every other hit is
`_browser_engine.target_rate_policy.observe(...)`.

**That co-location is the actual root cause of the confusion.** `browser_engine.py` is read as "the
browser world" because of its name, while eleven of its thirteen importers use it as "the rate-policy
module". A reader counting importers concludes the sidecar is load-bearing everywhere; a reader
counting `drive()` callers concludes it is dead. Both were reading the same file.

## 7. Cost of keeping it

MEASURED, `docker stats --no-stream`, idle after 7 days up:

```
apolaki-headless-chrome-1   CPU 0.31%   MEM 430.5 MiB (2.71% of host)
```

For comparison in the same snapshot: `apolaki-zap-1` 1.206 GiB, `apolaki-owaspbench-1` 1.848 GiB,
`apolaki-agent-1` 171.7 MiB. The sidecar is the 4th-largest idle consumer of 24 containers, and it is
`profiles: ["browser"]` — **opt-in, not part of the default stack** (`docker-compose.yml:393-401`). It
is running here because somebody opted in seven days ago, which is a different fact from "the default
stack ships an unused service".

---

## 8. The capability row is TRUE BY ACCIDENT — measured with a mutant that provably applied

`capability_preflight.headless_browser` reads (`agent/capability_preflight.py:72`):

```python
lambda: bool(__import__("bie").available()[0]) or bool(_env("CDP_BROWSER_URL")),
```

and `bie.available()` (`agent/bie.py:1204`) returns `(True, "playwright + chromium")` **whenever the
`playwright` package imports**. It never checks that a chromium binary exists.

MUTANT: `PLAYWRIGHT_BROWSERS_PATH=/tmp/no-browsers-here` (an empty directory), `CDP_BROWSER_URL` unset.

```
CDP set,   browsers baked in       available=True
CDP unset, browsers baked in       available=True
CDP unset, browsers ABSENT (mutant) available=True          <-- FALSE POSITIVE
   bie.available() with no binaries: (True, 'playwright + chromium')
   real launch with no binaries: FAILED -> Error BrowserType.launch:
       Executable doesn't exist at /tmp/no-browsers-here/chromium_headless_shell-1234/...
```

**Proof the mutation applied**, and not a survived-mutant false all-clear: the real
`p.chromium.launch()` failed with an error naming the mutated path. The mutant was live.

And the engine agrees with the launch, not with the preflight:

```
bie.run_persona_swap(...)  ->  ran=False browser=False findings=0
    note="browser runtime unavailable: BrowserType.launch: Executable doesn't exist at
          /tmp/no-browsers-here/chromium_headless_shell-1234/chrome-headless-shell"
```

So the engines are HONEST — they wrap the launch and report a labelled failure. The comment added at
`capability_preflight.py:65` claims the row "can no longer disagree with what the platform will
actually do". MEASURED: **it can, and it does.** `available()` is not what makes the engines work; the
launch is. `available()` is a pre-check that predicts nothing, because importing a package is a
declaration and having a binary is a fact — the same class of defect this project has logged eleven
times in code and had not yet looked for in a capability claim.

This matters more than an ordinary false positive: `capability_preflight` is the module whose stated
purpose is to stop a reader mistaking silence for safety (WYSIATI, per its own docstring). A false
"available" there is that module failing at the one job it exists to do.

## 9. The second limb is false by default too, and it costs 8.75 s a call

`docker-compose.yml:47` sets `CDP_BROWSER_URL=${CDP_BROWSER_URL:-http://headless-chrome:3000}` on the
agent **unconditionally**, while the sidecar is `profiles: ["browser"]` — **not in the default stack**.
So on a default `docker compose up`, the variable is set and points at a host that does not resolve.

MEASURED, in a container with no lab network (the default-stack shape):

```
preflight headless_browser available = True
observe() with sidecar ABSENT: 8.751s  browser=False
    note='headless browser unreachable: [Errno -2] Name or service not known'
```

Decomposed, so the cost is attributed to the right component:

```
socket.getaddrinfo("headless-chrome", 3000) failure   8.586s   <-- the whole cost is DNS
raw httpx.post, no rate policy                        4.117s
browser_engine.target_rate_policy.wait_sync (cold)    0.000s   <-- Q-043 policy NOT implicated
```

`agent/main.py:2136` and `:2241` gate the browser sensor on `os.environ.get("CDP_BROWSER_URL")` — a
variable compose always sets — so on a default stack **every `/plan/{id}` and `/graph/attack/{id}`
request pays ~8.75 s of DNS failure** for a browser that is not there. Same gate at
`agent/juiceshop_solvers.py:689`. (`main.py` is out of this lane's write set; recorded as a follow-up
in §12.)

**So `CDP_BROWSER_URL` being set is not evidence of anything.** It is a compose default, not an
observation. Both limbs of the capability row are declarations.
