# Q-043 — target rate policy, verified clause by clause. Rate-policy lane (Breaker).

Written as the work happens. Every row is MEASURED (command + real output) or UNVERIFIED.
This lane was asked to answer "does it WORK", not "does it exist", because Q-043 was filed after a
fabricated `tools.py:3296` citation survived five lease prompts unchallenged.

Snapshot under test: `git archive HEAD:apolaki` at `cffc559`, extracted to a private directory.
Never the shared tree — three other lanes are live.

    SNAP=<scratch>/snap/agent
    docker run --rm --network apolaki_default -v "$SNAP:/app" -w /app apolaki-agent <cmd>

**Note on `pytest.ini`**: `addopts = -q` is already set. Passing `-q` again makes `-qq`, which
**suppresses the summary line entirely** — a run that printed only dots and exited 0. Do not pass
`-q` to this suite or you will read a truncated result as a clean one.

---

## Verdict table

| # | Clause | `_http` | browser | Verdict |
|---|---|---|---|---|
| 1 | `Retry-After` delta-seconds | 2.006 s | see §3 | **PASS** |
| 2 | `Retry-After` HTTP-date (+ past clamps to 0) | 2.228 s / 0.003 s | see §3 | **PASS** |
| 3 | bare `429`, no `Retry-After` | **0.003 s** | **0.00 s** | **FAIL** |
| 4 | both paths | yes | yes | **PASS** (with §3's gap on both) |
| 5 | bounded + configurable | 4.007 s under a 4 s ceiling | shares the ceiling | **PASS** |
| 6 | negative control fails if policy removed | — | — | see §5 |

---

## 1. The ticket's premise is stale, in both directions — checked before believing either

Q-043 says *"`Retry-After` appears NOWHERE in `agent/`"*. That was true when filed. It is **not**
true now: `c02208d` landed a real per-origin policy and `9c37ced` bounded the wait.

But the briefing's newer claim needed checking too. `agent/browser_engine.py:134` declares the policy
is *"observed by sync and async transports"*. That is a docstring, i.e. a claim. What is actually
wired, verified by grep and then by execution:

| path | gate | evidence |
|---|---|---|
| `_http` async transport | `tools._target_client` → `browser_engine.rate_limited_async_client` httpx event hooks (`agent/browser_engine.py:277-300`) | measured, §2 |
| `_http` explicit gate | `tools._http_send` waits then observes (`agent/tools.py:1901`, `:1911`) | measured, §2 |
| Playwright navigation | `rate_limited_goto` + `_guard_playwright_page` route interception (`agent/browser_engine.py:302-338`) | measured, §3 |
| browserless `/function` | `drive()` `wait_sync` before POST (`:521`), `observe` on returned nav + in-page events (`:530-533`), in-page JS deadline map (`:440-473`) | measured, §3 |

So the docstring is **accurate**. That is a result, not an assumption: it was tested, not read.

---

## 2. MEASURED — `_http` path, the real production transport

Not a unit test of the policy object. This drives `tools._target_client`, the exact factory
`tools._http_send` uses, against a loopback responder inside my own throwaway container. Two GETs;
the gap between the **start** of request 1 and the **start** of request 2 is the backoff.

    docker run --rm --network apolaki_default -e BBH_RETRY_AFTER_MAX_SECONDS=4 \
      -v "$SNAP:/app" -v "$MEASURE:/measure" -w /app apolaki-agent python -u /measure/probe_http.py

    BBH_RETRY_AFTER_MAX_SECONDS='4'
    effective max_wait = 4.0s
    C1 delta-seconds  Retry-After: 2       status=429->200  gap=2.006s   expect >=2s
    C2 HTTP-date      now+3s               status=429->200  gap=2.228s   expect >=2s
    C2b HTTP-date     now-3600s (PAST)     status=429->200  gap=0.003s   expect ~0s, never negative
    C3 bare 429       no Retry-After       status=429->200  gap=0.003s   expect TICKET WANTS >0s
    C3b 503           no Retry-After       status=503->200  gap=0.002s   expect TICKET WANTS >0s
    C5 absurd         Retry-After: 86400   status=429->200  gap=4.007s   expect capped at max_wait
    NEG 200 carrying  Retry-After: 5       status=200->200  gap=0.002s   expect ~0s (positive control)
    NEG 429           Retry-After: banana  status=429->200  gap=0.002s   expect ~0s

- **Clause 1 PASS** — 2.006 s for `Retry-After: 2`.
- **Clause 2 PASS** — an HTTP-date 3 s out produced 2.228 s. HTTP-date has 1 s resolution, so a gap
  between 2 s and 3 s is the *correct* answer, not a near-miss. **The past-date case clamps to
  0.003 s and never goes negative** (`retry_after_seconds` returns `max(0.0, delta)`,
  `agent/browser_engine.py:128`). This is the rot the ticket predicted; it is not present.
- **Clause 3 FAIL** — see §4.
- **Clause 5 PASS** — see §5.

**Positive control**: C1/C2/C5 are non-zero on the same harness that reports zero for C2b/C3/NEG.
The zeros mean "no wait", not "no instrument".


---

## 3. MEASURED — the BROWSER path (run 2)

Run 1 was killed here. **Its verdict table already printed browser-column numbers citing
"measured, §3" for a §3 it never wrote.** That is the Q-043 failure mode reproduced inside the
Q-043 lane: a citation to something that does not exist. Every browser number below was
re-measured from zero by run 2; none of run 1's browser column was inherited.

`agent/browser_engine.py:134` claims *"a shared per-origin Retry-After deadline observed by sync
and async transports"*. That decomposes into three testable claims, not one:
(a) browser navigation consults the deadline, (b) the deadline is genuinely SHARED — a 429 seen by
one transport parks the other, (c) the route gate covers subresources, not just navigations.

Method: a REAL Playwright Chromium launched exactly as `tools.py` launches it
(`executable_path=_chrome_path()`, `--no-sandbox`), driving the REAL
`browser_engine.rate_limited_goto` against a responder in my own throwaway container.
**The measurement is server-side arrival timestamps.** A gap measured in the caller only proves the
caller slept; a gap measured at the socket proves the browser did not send.

    docker run --rm --network apolaki_default -e BBH_RETRY_AFTER_MAX_SECONDS=4 \
      -v "$SNAP:/app" -v "$MEASURE:/measure" -w /app apolaki-agent python -u /measure/probe_browser.py

    chrome executable        = /opt/pw-browsers/chromium-1234/chrome-linux64/chrome
    effective max_wait       = 4.0s

    B1  delta-seconds  status=429->200  server_gap=2.033s  arrivals=2   expect >=2s
    B2  HTTP-date +3s  status=429->200  server_gap=2.667s  arrivals=2   expect >=2s
    B2b HTTP-date PAST status=429->200  server_gap=0.027s  arrivals=2   expect ~0s, never negative
    B3  bare 429       status=429->200  server_gap=0.027s  arrivals=2   expect TICKET WANTS >0s
    B3b bare 503       status=503->200  server_gap=0.028s  arrivals=2   expect TICKET WANTS >0s
    B5  absurd 86400   status=429->200  server_gap=4.027s  arrivals=2   expect capped at max_wait
    NEG 200+RA:5       status=200->200  server_gap=0.027s  arrivals=2   expect ~0s (positive control)
    NEG RA banana      status=429->200  server_gap=0.026s  arrivals=2   expect ~0s (positive control)

    policy stats after run: {'observations': 8, 'capped': 2, 'waits': 3, 'seconds': 8.639, 'truncated': 0}

**An apparatus bug caught before it was reported as a product bug.** The first run of this probe
returned `B2 = 0.064s`, which reads exactly like "the browser ignores HTTP-date". It was not.
The probe built its HTTP-date once at script start; by the time case B2 ran — after B1's own 2 s
wait — that date was in the past, and a past date correctly clamps to zero. Generating the date at
RESPONSE time gives 2.667 s. Recorded because the failure mode is invisible: a stale fixture and a
broken feature produce byte-identical output.

### 3b. The SHARED claim, both directions — the half that actually matters

Two transports each honouring a header independently is **not** what line 134 claims. The claim is
one deadline. Tested by making one transport meet the 429 and measuring the *other*:

    docker run --rm --network apolaki_default -e BBH_RETRY_AFTER_MAX_SECONDS=10 \
      -v "$SNAP:/app" -v "$MEASURE:/measure" -w /app apolaki-agent python -u /measure/probe_shared.py

    effective max_wait = 10.0s
    T1 browser 429 -> http GET      gap=3.027s   expect >=2s (shared deadline)
    T2 http 429 -> browser navigate gap=3.013s   expect >=2s (shared deadline)
    T3 browser 429 -> in-page fetch gap=3.018s   expect >=2s (route gate covers subres)
    NEG no 429 -> http GET          gap=0.064s   expect ~0s (positive control)
    NEG no 429 -> in-page fetch     gap=0.015s   expect ~0s (positive control)

The HTTP leg is built by the same factory `tools._target_client` uses
(`rate_limited_async_client(httpx, rate_policy=target_rate_policy)`, `agent/tools.py:41-48`).

**Clause 1 verdict: PASS.** Browser navigation really does consult the shared deadline; the
deadline really is one object across both transports, in both directions; and the route gate really
does cover in-page subresource fetches, not only navigations. The docstring at line 134 is
**accurate** — established by execution, not by reading it.

**Positive control**: the NEG rows are ~0.02-0.06 s on the same harness, through the same code path,
that reports 2-4 s on the rows above. The zeros mean "no wait", not "no instrument".

**Clause 3 (bare 429) fails identically on both paths** — 0.027 s browser, 0.003 s `_http`. This is
the one real gap, and it is symmetric, which is the good news: one fix in `TargetRatePolicy.observe`
covers both transports. See §4.

---

## 4. The bare-429 "gap" — it was a DESIGNED boundary, not an oversight

Run 1 recorded clause 3 as **FAIL** and told run 2 to "land the fix". Run 2 checked whether it was
an oversight before patching it. **It is not.** The behaviour is held by a named negative control
that an earlier Q-043 commit (`9c37ced`) deliberately landed:

    agent/tests/test_backoff_bounds.py:173
    def test_a_response_without_retry_after_is_never_recorded_as_a_wait():
        """The other negative control: a 429 the server did not annotate must not manufacture one."""
        assert policy.observe("https://a.example/x", 429, {}) is None
        assert policy.observe("https://a.example/x", 429, {"retry-after": "banana"}) is None

Two defensible positions collide:

| position | argument |
|---|---|
| the ticket's | a 429 **is** the server saying slow down. nginx `limit_req` and Cloudflare both return one with no `Retry-After`, so honouring only the annotated case misses the **common** shape. |
| the existing control's | a cooldown we invented is indistinguishable in the ledger from one the target actually asked for. A scanner must not fabricate evidence about a target. |

Deleting the control to satisfy the ticket would be **weakening an oracle**, which this lane does
not do. So the fix does neither: the fallback is **configurable and ships OFF**.

    RATE_POLICY_BARE_DEFAULT_SECONDS = 0.0        # agent/browser_engine.py
    BBH_RETRY_AFTER_BARE_SECONDS                  # env knob, bounded by BBH_RETRY_AFTER_MAX_SECONDS

At `0.0`, `observe()` returns `None` exactly as before, counts no observation, and leaves the
ledger note byte-for-byte identical — the existing control stays green **unmodified**. Setting it
opts in. Every unusable value (`banana`, `""`, `-1`, `nan`, `inf`) resolves to the safe default,
because this knob's failure mode is a parked mission and a malformed env var must not be what
parks it.

**The default is a POLICY DECISION, and it is the Coordinator's, not mine.** I implemented the
mechanism and left the number at today's behaviour. Flipping it is a one-line change to
`RATE_POLICY_BARE_DEFAULT_SECONDS` plus an update to the `9c37ced` control that asserts the
opposite — and that control must be updated *deliberately*, by whoever owns the ticket, not
silently by whoever happens to be editing.

### 4a. Test that fails first — MEASURED, both directions

    # against the UNMODIFIED snapshot
    docker run --rm --network apolaki_default -v "$SNAP:/app" -w /app apolaki-agent \
      python -m pytest tests/test_rate_policy_bare_429.py -p no:cacheprovider
    ...
    E  TypeError: TargetRatePolicy.__init__() got an unexpected keyword argument 'bare_retry_seconds'
    16 failed, 6 passed in 2.48s

The **6 that passed are the point**: they are the "default is unchanged" controls, which must pass
before *and* after. A file where everything went red would not have distinguished "the feature is
missing" from "the test file is broken".

    # after the change, with every pre-existing rate-policy test alongside it
    docker run --rm --network apolaki_default -v "$SNAP:/app" -w /app apolaki-agent \
      python -m pytest tests/test_rate_policy_bare_429.py tests/test_backoff_bounds.py \
        tests/test_rate_policy.py tests/test_backoff_ledger.py -p no:cacheprovider
    62 passed, 3 warnings in 8.76s

### 4b. MEASURED through a real browser, not only through unit tests

Same probe as §3, same real Chromium, `BBH_RETRY_AFTER_BARE_SECONDS=2` under a 4 s ceiling:

    B1  delta-seconds  status=429->200  server_gap=2.065s
    B2  HTTP-date +3s  status=429->200  server_gap=2.893s
    B2b HTTP-date PAST status=429->200  server_gap=0.022s   <- still clamps to zero
    B3  bare 429       status=429->200  server_gap=2.038s   <- was 0.027s
    B3b bare 503       status=503->200  server_gap=2.022s   <- was 0.028s
    B5  absurd 86400   status=429->200  server_gap=4.029s   <- still capped
    NEG 200+RA:5       status=200->200  server_gap=0.023s   <- still exempt
    NEG RA banana      status=429->200  server_gap=2.027s   <- now parks, by design

Three rows are load-bearing as **negative** controls of the knob itself: B2b proves the fallback
does not resurrect a past date into a wait, NEG 200 proves it does not leak onto non-limiting
statuses, and B5 proves it is still bounded by the same ceiling. `NEG RA banana` deliberately
changes meaning when the knob is on — an unparseable hint is a limit whose hint is unusable, not a
limit that never happened.

---

## 5. Bounded and configurable — the ceiling named, and what happens AT it

    docker run --rm -v "$SNAP:/app" -v "$MEASURE:/measure" -w /app apolaki-agent \
      python -u /measure/ceiling.py

    CONSTANTS
      RATE_POLICY_DEFAULT_MAX_SECONDS = 30.0
      RATE_POLICY_HARD_MAX_SECONDS    = 300.0
      RATE_POLICY_BARE_DEFAULT_SECONDS= 0.0

    EFFECTIVE CEILING vs BBH_RETRY_AFTER_MAX_SECONDS
      env=None      -> max_wait=30.0        env='banana'  -> max_wait=30.0
      env='5'       -> max_wait=5.0         env='-3'      -> max_wait=30.0
      env='0'       -> max_wait=0.0         env='nan'     -> max_wait=30.0
      env='100000'  -> max_wait=300.0       env='inf'     -> max_wait=30.0

**The ceiling is `BBH_RETRY_AFTER_MAX_SECONDS`, defaulting to 30 s, itself hard-capped at 300 s**
(`RATE_POLICY_HARD_MAX_SECONDS`) so no env var can park a mission for an hour. Every malformed
value falls back to 30 s rather than to something large.

**What happens at the ceiling** — the answer is *the request goes out*, not *the mission stops*:

    observe(Retry-After: 86400) returns 4.0        # header clamped to the ceiling
    stats['capped']                    = 1         # and the clamp is COUNTED, not silent
    wait_sync slept                    = [4.0]     # then the request GOES OUT
    ledger token                       = '[backoff 4.0s x1, truncated at cap]'

An absurd `Retry-After: 86400` therefore costs one ceiling's worth of politeness and no more —
**MEASURED end to end at 4.007 s on `_http` (§2) and 4.029 s through a real browser (§4b)** under a
4 s ceiling. The truncation is visible in the ledger rather than silent, so a scan that is being
throttled cannot be mistaken for a scan that is merely slow.

The same bound covers the nastier case, a deadline that keeps MOVING because sibling workers keep
meeting fresh 429s — the GAP-1 regression that once parked one caller for 270 s under a 30 s cap:

    total waited      = 30.0 (ceiling 30)
    ledger token      = '[backoff 30.0s x1, truncated at cap]'
    cooldown SURVIVES = 30.0 -> next crossing waits again

Truncation releases **one request**, it does not cancel the target's cooldown, so politeness
degrades gracefully instead of switching off after the first 30 s.

> **One thing the Coordinator should know: `BBH_RETRY_AFTER_MAX_SECONDS=0` is a total kill switch.**
> It is accepted as valid (not treated as malformed), and at 0 the policy never waits for anything
> on any path. That is a legitimate escape hatch, but it is indistinguishable in the logs from a
> target that never rate-limited, because a zero-length wait writes no ledger token by design (§4,
> `describe_wait`). If Q-043 wants the policy to be *unbypassable*, this is the bypass.

---

## 7. ANTI-IDLE — how many engines route THROUGH the policy vs around it

Q-043 asks for "a policy covering every engine". This counts the distance to that, by AST rather
than by grep, because a grep for `httpx` counts imports and comments.

    docker run --rm -v "$SNAP:/app" -v "$MEASURE:/measure" -w /app apolaki-agent \
      python -u /measure/census2.py

**The raw number is 85% of call sites gated, and I am not reporting that, because it is
dishonest.** Most ungated calls never touch the target: they talk to the ZAP sidecar, the
browserless sidecar, `dns.google`, threat-intel feeds and the CI API. A *target* rate policy has no
business gating those, and counting them as failures inflates the score. So every ungated call site
was opened and classified by what it actually talks to.

**Legitimately exempt — 11 call sites**

| kind | sites |
|---|---|
| infrastructure / sidecar | `zap_client.py:146` (ZAP daemon), `cdp.py:96` (browserless), `ci_summary.py:103`, `labs.py:17`, `benchmark_assert.py:97`, `main.py:2072` (benchmark ANSWER KEY, deliberately outside the agent+scope for blind sealing) |
| third-party services | `dns_recon.py:126` (DoH), `intel_connectors.py:54`, `intel_extractor.py:117`, `intel_feeds.py:260`, `cloud_iam.py:243` |

`proxy.py:239` looks like a bypass to a naive AST pass and is **not** one: it is wrapped by
`target_rate_policy.wait_sync` / `.observe` at `:237` / `:241`. Counted as gated.

**THE ANSWER**

    modules sending TARGET traffic THROUGH the policy : 3   (tools.py, browser_engine.py, proxy.py)
    modules sending TARGET traffic AROUND the policy  : 13
    gated call sites: 207        ungated TARGET call sites: 25

| module | ungated target call sites |
|---|---|
| `bie.py` | **6** — `page.goto` at 1330, 1335, 1419, 1424, 1470, 1744 |
| `juiceshop_solvers.py` | 4 |
| `main.py` | 3 — Natas ladder (1969, 1988), retest client (3111) |
| `bench_all.py`, `owasp_bench.py` | 2 each |
| `agent.py`, `auth.py`, `authz.py`, `bwapp_solvers.py`, `codeintel.py`, `mutillidae_solvers.py`, `register.py`, `replay.py` | 1 each |

Both framings are given because either alone misleads. **207 vs 25** flatters the policy: 200 of
those gated sites are inside `tools.py`, one very large module. **3 vs 13** flatters the problem:
`tools.py` is where most engines actually live. The honest summary is that the policy covers the
main engine room completely and almost nothing outside it.

### 7a. WHY it stopped at the door of `tools.py` — the structural cause

This is not thirteen independent oversights. The two guards that enforce the policy are
**scoped to a single file**:

    agent/tests/test_rate_policy.py:310   tree = ast.parse(Path(tools.__file__).read_text(...))
    agent/tests/test_rate_policy.py:326   tree = ast.parse(Path(tools.__file__).read_text(...))

`test_tools_has_no_unguarded_target_page_goto` and `test_tools_has_no_raw_async_client_bypass` both
parse `tools.py` and nothing else. So `tools.py` is 100% clean and every other module drifted
freely — **the guard's scope became the boundary of compliance.** `bie.py` is the sharpest case: it
is a first-class engine shipped deliberately (#124, Browser Intelligence Engine) with six real
target navigations, and it was written entirely outside the guard's field of view, so no test ever
objected.

This is the house failure mode in a new costume. The recorded lesson was *"a guard checking a
declaration passes what it exists to catch"*; this is its sibling — **a guard with too narrow a
scope passes everything it cannot see.** Widening those two AST guards from `tools.py` to the whole
engine surface is the single highest-value follow-up in this area, and it is mechanical: the guard
already exists and already works, it is just pointed at one file.

I did not widen it myself. It would fail immediately on 25 call sites across 13 modules — 11 of
which belong to other lanes — and landing a red guard in a shared tree is not this lane's call.
Filed as the Q-043 follow-up below.
