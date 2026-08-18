# Q-003 -- `postMessage` as a DOM-XSS source (CWE-346 -> CWE-79), WSTG-CLNT-11

Lane: postMessage (Builder). Written as the work happens. Every claim is MEASURED (command + real
output) or UNVERIFIED.

## 1. Ground truth BEFORE building -- is the ticket real?

The ticket's root cause claims `postMessage|MessageEvent|onmessage` appears nowhere in `agent/`.

MEASURED:

    $ grep -rn "postMessage\|MessageEvent\|onmessage" agent/ --include=*.py | wc -l
    0

Positive control that the apparatus was looking (the same grep with a token that MUST exist):

    $ grep -rn "addEventListener" agent/ --include=*.py
    agent/tests/test_client_request_source.py:16: ...addEventListener("submit", ...)

So the zero is a real zero, not a broken probe. **Q-003 is CONFIRMED OPEN.** `message` is not a
tracked source anywhere in the codebase.

Existing DOM sources, MEASURED by reading `agent/dom_tool.py:build_probes` and
`agent/dom_trace.py`:

| engine | sources it drives |
|---|---|
| `run_dom_audit` (`dom_tool.py`) | URL fragment (`location.hash`), query parameters |
| `run_dom_trace` (`dom_trace.py`) | query parameters, URL fragment |

Neither reaches a `message` handler, and no handle-obtaining context (iframe / `window.open`) is
constructed anywhere in the product.

## 2. Where the capability goes -- and why it is NOT a new engine

Q-003 says "adding a SOURCE to a working confirmation engine, not a new engine". That is also the
NO-ISLANDS answer: `run_dom_audit` is already in `TOOL_PERMISSIONS` (ACTIVE), already dispatchable
via `getattr(self, "_run_dom_audit")`, and already advertised in `CLAUDE_TOOLS`. Extending it adds
zero registration risk. This project has 32 engines that never executed across 151 missions; this
lane does not add the 33rd.

## 3. Real-world fixture material (COPIED, NEVER INVENTED)

Sweep of every running local lab for a window `message` listener:

    $ for p in 42080 42084 42088 42089 42091 42092 42093 42094 42001 42097; do ...; done
    -> no lab root HTML registers a `message` listener

    $ curl -s http://127.0.0.1:42000/main.js | grep -c 'addEventListener("message"'
    0
    $ curl -s http://127.0.0.1:42000/main.js | grep -c 'onmessage'
    1

**The one Juice Shop hit is a FALSE POSITIVE TRAP, and it is the most valuable fixture found.**
Extracted verbatim from the live bundle:

    ...this.ws.onopen=function(){a.onOpen()},this.ws.onclose=function(){a.onClose()},
    this.ws.onmessage=function(e){a.onData(e.data)},this.ws.onerror=...

That is socket.io's WebSocket transport -- `ws.onmessage`, NOT `window.onmessage`. A naive regex on
`onmessage` reports a web-message vulnerability on Juice Shop that does not exist. This shape is
carried into the tests as a real, copied negative fixture.

## 4. Status

- [x] Ground measured; ticket confirmed open
- [x] Slice 1: pure detection + origin grading in `dom_tool.py` + tests (run 1, UNCOMMITTED at handoff)
- [ ] Slice 2: browser confirmation phase in `tools.py`
- [ ] Slice 3: live measurement + honest ceilings

---

# RUN 2 -- wiring the island

## 5. What run 2 inherited, MEASURED before touching anything

Run 1's five helpers were on disk and untested against the ratchet's own instrument. First act was
to run it, because the brief's claim had to be checked, not assumed:

    $ docker run --rm -v ".../agent:/app" -w /app apolaki-agent python -c \
        "import deadcode_gate as dg; r=dg.scan_qualified(); print(r['count'], r['baseline'], r['ok']); \
         print([n for n in r['unused'] if 'wm_' in n])"
    40 37 False
    ['dom_tool.wm_family', 'dom_tool.wm_finding', 'dom_tool.wm_lead_finding',
     'dom_tool.wm_payloads', 'dom_tool.wm_reportable']

CONFIRMED: five newly-dead qualified functions, ratchet red at 40 against a baseline of 37.

**THE RATCHET UNDER-COUNTS THE ISLAND, and I nearly believed its list was the whole of it.**
`find_message_listeners` and `wm_scan_hint` are ALSO uncalled by production, and neither appears in
the failure list. `scan_qualified` treats *any* mention inside the defining module as a use, and its
regex does not exclude comments -- both names appear in the explanatory comment block at
`dom_tool.py:429-430`. So the true island was **seven** functions, not five. A comment describing
what a function is for makes that function look wired. Wiring all seven, not just the five the gate
could see, is what "green because the code is REACHABLE" has to mean.

## 6. New engine vs. extending `run_dom_audit` -- decided on REACHABILITY, measured

Run 2's brief asks for "a real engine that dispatches these helpers, registered in
`TOOL_PERMISSIONS`, dispatchable, and reachable". Two candidate shapes, and the deciding evidence is
what actually dispatches an engine in this codebase:

    $ grep -rn "run_dom_audit" agent/ --include=*.py | grep -v tests/ | grep -v "^agent/tools.py"
    agent/agent.py:916    r = await self.tools.execute("run_dom_audit", {"url": page}, session_id)
    agent/agent.py:3776   async for ev in self._run_tool("run_dom_audit", {"url": u}, session_id):
    agent/planner.py:448  e_steps.append(_step("run_dom_audit", {"url": u}, f"run_dom_audit:{u}"))
    agent/candidate_pipeline.py:60-63   dom_xss / csti / prototype_pollution / eval_sink -> run_dom_audit
    agent/asvs_model.py:196,229 ; agent/wstg_catalog.py:84 ; agent/engine_descriptor.py:117-118

`run_dom_audit` is fired **deterministically** from the agent sweep and the planner. A brand-new
name in `TOOL_PERMISSIONS` + `CLAUDE_TOOLS` is only *model-selectable*; making it deterministic
requires editing `agent.py`/`planner.py`, which this lane is forbidden to touch. **Registering a new
engine I cannot dispatch is the exact shape of the 32 engines that never executed** -- it would move
the island up one level rather than removing it. So the capability is added as a PHASE of
`run_dom_audit`, which is also what Q-003's own text asks for ("adding a **source** to a working
confirmation engine, not a new engine"), and what run 1 planned in section 2 above.

## 7. What was built

`run_dom_audit` gains a third SOURCE beside `location.hash` and query params, as three methods in
`agent/tools.py`:

| piece | what it does |
|---|---|
| `_wm_audit(browser, url)` | DETECT + GRADE + decide. Fetches the page and its same-origin app scripts, applies `wm_scan_hint` as a cheap text gate, runs `find_message_listeners` + `wm_reportable`, then either confirms or emits `wm_lead_finding`. Never raises. |
| `_wm_confirm(browser, url, rec)` | CONFIRM. Frames the target from a real foreign origin, posts `wm_payloads` one at a time, grades the runtime with `wm_family`, runs the mismatched-`targetOrigin` negative control, and returns `wm_finding` or `None`. |
| `_wm_harness_server()` | the attacker page, served by a REAL loopback listener on an ephemeral port. |

All seven helpers are now CALLED from `tools.py` or from something `tools.py` calls. The tier is
declared `ACTIVE` as a bare token on BOTH surfaces (docstring and `CLAUDE_TOOLS` description).

## 8. FOUR DEFECTS THE LIVE RUN FOUND, none of which any unit test could have

The first live run reported `lead` for **every** case, including `eval(e.data)` with no origin check
at all -- a page that is trivially exploitable -- and `swallowed` was EMPTY. A green test file and a
composed engine, producing a confident wrong answer.

**(a) Silent returns made an apparatus failure look like a safe target.** `_wm_confirm` returned
`None` on goto failure, on `evaluate` failure and on nothing-fired, all identically and all without
recording anything. Fixed: every exit records through `_swallow`, and `_post` now returns the
DELIVERY STATUS beside the family, because `''` means two different things -- "the handler was driven
and did not fire" (a real negative) and "the message was never delivered" (an apparatus failure
wearing a negative's clothes).

**(b) `rate_limited_goto` silently defeated the route interception.** MEASURED:

    "where": "dom_audit.web_message.harness",
    "error": "Page.goto: net::ERR_NAME_NOT_RESOLVED at http://bbh-evil.example/wm-harness"

`browser_engine._guard_playwright_page` installs a PAGE-level `route("**/*")` whose gate calls
`route.continue_()` unconditionally. Playwright resolves the most recently registered route first and
page routes ahead of context routes, so a context-level `fulfill` registered BEFORE it never ran.

**(c) THE ONE THAT MATTERED: a route-intercepted origin is classified PUBLIC, and Chromium's Local
Network Access then blocks it from reaching any loopback or private target.** MEASURED:

    reqfailed: http://127.0.0.1:8099/eval net::ERR_BLOCKED_BY_LOCAL_NETWORK_ACCESS_CHECKS
    frames: ['http://bbh-evil.example/wm-harness', 'chrome-error://chromewebdata/']

My first fix was to move the harness host into the target's own address space (`127.0.0.2`). **It was
blocked identically** -- and that failure is what proved the mechanism: the classification comes from
the CONNECTION, and a fulfilled request never opens one, so no hostname can fix it. The harness had
to become a real listener. With `_wm_harness_server` the same probe gives
`frames: [harness, http://127.0.0.1:8099/eval]`, no failed requests, and the sink fires.

**A HYPOTHESIS I HELD AND FALSIFIED, recorded because acting on it would have been a rewrite for
nothing.** I predicted Chromium suppresses `alert()` from a cross-origin iframe (the Chrome 92
change) and was ready to switch the whole oracle to `window.open`. Tested instead:

    H0 positive control (top-level alert): ['bbhwm8842-TOP']
    H5 iframe alert: posted -> dialogs: ['bbhwm8842-IFRAME']
    H6 iframe request oracle: ['http://127.0.0.1:8098/bbhwm8842-IMG']
    H7 window.open -> opened new pages: 1 ; dialogs: ['bbhwm8842-POPUP']

The alert DOES fire from a cross-origin iframe in this build. The only real blocker was (c). H0 is
the positive control that makes H5 mean anything at all.

**(d) The evidence sentence was FALSE on a TRUE finding.** `wm_finding` hardcoded "from the foreign
origin https://bbh-evil.example/" while the post actually came from the loopback harness. The origin
is now a parameter. Evidence naming the wrong actor is not cosmetic -- it is the part a human re-runs
to check the claim.

## 9. LIVE MEASUREMENT -- the real engine, real Chromium, real labs

`_run_dom_audit` driven against handler shapes copied from PortSwigger/MDN and served over HTTP, plus
the running Juice Shop lab, from a throwaway container on `apolaki_default`.

| target | handler | result | why that is the right answer |
|---|---|---|---|
| `/eval` | `eval(e.data)`, no origin check | **CONFIRMED** `dom_xss` CWE-79 | `alert("bbhwm8842")` EXECUTED |
| `/innerhtml` | `innerHTML = e.data`, no check | **CONFIRMED** `dom_xss` CWE-79 | executed via `<img onerror>` |
| `/jsonparse` | `JSON.parse` + `switch(d.type)` | **CONFIRMED** `dom_xss` CWE-79 | payload `{'type':'load-channel','url':'javascript:alert(...)'}` -- the gate literal was READ OFF THE TARGET, not guessed |
| `/strict` | MDN equality check, **same eval sink** | **LEAD, not confirmed** | PAIRED SECURE CONTROL: identical source and sink, only the origin check differs |
| `/inert` | no `message` listener | nothing | true negative |
| Juice Shop (live `main.js`) | `this.ws.onmessage` | **0 findings, 0 browser spend** | real-world false-positive control |

The `/strict` row matters most, and its ledger entry proves it was DRIVEN rather than skipped:

    "where": "dom_audit.web_message.silent", "target": "http://127.0.0.1:8099/strict",
    "error": "no payload fired [js=posted; json:data=html=posted; object:data=html=posted;
              json:data=js-url=posted; object:data=js-url=posted]"

All five payloads were delivered and none fired. That is a MEASURED negative, not a gap.

Confirmed evidence, verbatim:

    Framed http://127.0.0.1:8099/eval from the foreign origin http://127.0.0.1:34543 and called
    postMessage('alert("bbhwm8842")', "*"); alert("bbhwm8842") EXECUTED in the page.
    NEGATIVE CONTROL: the identical message posted with targetOrigin="http://127.0.0.1:34543"
    (an origin the target does not have) was refused delivery by the browser and nothing fired.

## 10. Ratchet, measured with the real instrument

    $ docker run --rm -v ".../agent:/app" -w /app apolaki-agent python -c \
        "import deadcode_gate as dg; r=dg.scan_qualified(); print(r['count'], r['baseline'], r['ok']); \
         print([n for n in r['unused'] if 'wm_' in n])"
    35 37 True
    []

Green because the functions are USED, at a count BELOW the baseline. `QUALIFIED_BASELINE` was not
touched. `scan_methods`: 0 flagged against a baseline of 14, `ok True`.

`agent/tests/test_web_message_source.py` is 46 tests. The engine-half tests assert reachability with
an AST reader that ignores comments and docstrings -- strictly stronger than the ratchet, which
counted two of these helpers as used because a COMMENT named them.

## 11. HONEST CEILINGS -- what this does NOT do

1. **Framing only.** If the target sends `X-Frame-Options: DENY` or a restrictive `frame-ancestors`,
   the handler is not reachable this way; the fact is recorded to the swallowed ledger and the
   finding degrades to a lead. `window.open` MEASURED working (H7) but is deliberately NOT
   implemented -- it would ship unverified against a real XFO target, and unverified code is worse
   than absent code. This is the obvious next slice.
2. **Static discovery.** Listeners are found by reading the page and its same-origin scripts. A
   handler registered only after a runtime event, or in a lazily-loaded chunk, is not seen. CDP
   listener enumeration (`getEventListeners(window)`) would close this.
3. **Bounded.** 2 records per page, 5 payloads per record, one iframe load each.
4. **Cross-site cookies.** The target loads in a cross-site iframe, so `SameSite=Lax` session cookies
   are not sent. A handler that only registers post-login may be missed. This mirrors real attacker
   conditions rather than working around them.
5. `origin_check` is a STATIC PREDICTION. The runtime overrules it in both directions.

## 12. NOT MINE, AND CURRENTLY RED: `test_engine_descriptor.py::test_the_verifier_catches_an_unwired_reason`

Found while establishing my own baseline, in files this lane must not touch. Reported rather than
fixed, with the attribution measured rather than assumed.

The Q-075 lane added `QUALIFIED_BASELINE_SET` to `agent/deadcode_gate.py`, a frozenset of dead-code
names recorded as strings. It contains `"bie.resolve_locator"`. `engine_descriptor.verify_always_on`
counts a bare-name match in any non-prose `.py` file as a REFERENCE, so that string literal now makes
`resolve_locator` look wired, and the negative control asserting it is NOT wired fails:

    assert r["ok"] is False
    E   assert True is False

Attribution, measured four ways:

* `git archive` of the HEAD BEFORE that lane landed, plus only my three files -> the test PASSES.
* the current tree -> FAILS, `assert r["ok"] is False` / `E assert True is False`.
* the offending literal is at `agent/deadcode_gate.py:164`, in a hunk I did not write.
* `git log -S "bie.resolve_locator" -- apolaki/agent/deadcode_gate.py` -> **`4c50007`**, the Q-075
  lane's commit. It is now committed on `main`, so the suite is red for everyone until it is fixed.

**That lane already found this exact defect shape one level down** -- their own docstring records that
recording `METHOD_BASELINE_SET` in `deadcode_gate.py` made `scan_methods` read its own record and
report 0 uncalled methods instead of 13, so they excluded the file from its own scan. The same fix is
needed for the CROSS-MODULE reader: either `deadcode_gate.py` joins `engine_descriptor._PROSE_FILES`,
or the recorded sets stop being readable as identifiers. **A record of what a checker found must
never be readable BY a checker** -- including a different one.

## 13. The SECOND confirmation family, measured separately

Section 9's six cases all confirmed (or correctly refused to confirm) `dom_xss`. That left
`open_redirect` -- the other branch of `wm_family` -- shipped but UNVERIFIED, which is the kind of
gap that survives a green suite. So it was isolated with a handler that allowlists the scheme, and
therefore CANNOT become XSS:

    window.addEventListener('message', function(e) {
      if (/^https?:/.test(e.data)) { location.href = e.data; }
    });

MEASURED, live:

    /navsink -> confidence=confirmed family=open_redirect cwe=CWE-601
    Framed http://127.0.0.1:8099/navsink from the foreign origin http://127.0.0.1:36039 and called
    postMessage('https://bbh-evil.example/bbhwm8842', "*"); the page navigated to
    https://bbh-evil.example/. NEGATIVE CONTROL: the identical message posted with
    targetOrigin="http://127.0.0.1:36039" ... was refused delivery and nothing fired.
    swallowed: []

Both families of `wm_family` are now driven end to end. The `javascript:` payload was correctly
rejected by the handler's own scheme test, so the finding is CWE-601 and not CWE-79 -- the grade
follows what the target actually did.

## 14. ANTI-IDLE: is Q-005 (server-side prototype pollution, CWE-1321) genuinely open?

Asked to MEASURE rather than start it. **CONFIRMED OPEN.** Every probe below was run against the
live tree, with a positive control proving the apparatus was looking.

POSITIVE CONTROL first -- a token that MUST exist if the grep works at all:

    $ grep -rlc "PP_KEY" agent/*.py
    agent/dom_tool.py   agent/exposure_tool.py   agent/tools.py

So the greps below are reading real files.

**Probe 1 -- every `__proto__` occurrence in production, classified.** 22 hits across 10 files, and
not one of them sends a polluting key to a SERVER and observes a behaviour change:

| where | what it actually is |
|---|---|
| `dom_tool.py:133-134, 313-314` | URL probes `?__proto__[KEY]=VAL` (hash + query), confirmed **in the browser** |
| `codereview.py:83-86` | a static SOURCE-review regex, labelled "client-side prototype pollution" |
| `dependency_intel.py:409-512` | jQuery `$.extend` CVE-2019-11358 guard analysis -- reading a library, not probing a server |
| `defense_mapping.py`, `technique_model.py:107`, `blind_benchmark.py`, `candidate_pipeline.py`, `techniques.py` | prose: remediation text, a negative-control sentence, family mapping |

**Probe 2 -- the confirmation channel the pipeline declares for this family:**

    agent/candidate_pipeline.py:60
    "prototype_pollution": ("run_dom_audit",
        "browser prototype-pollution canary (__proto__ write observed at runtime)", "browser")

The channel is literally `"browser"`. There is no server-side channel for CWE-1321.

**Probe 3 -- the technique record says so itself:**

    agent/techniques.py:772  id="prototype_pollution" ... validated_on=["ginandjuice"]
        maps_to={"ginandjuice": ["Client-side prototype pollution (DOM, query)"]}

**Probe 4 -- the two things Q-005's own oracle and negative control require are ABSENT:**

    $ grep -rn "constructor\.prototype\|constructor\[.prototype" agent/*.py   -> 0 hits
    $ grep -rn "json spaces\|json_spaces" agent/ --include=*.py               -> 0 hits

So the ticket's stated oracle (`{"__proto__":{"json spaces":10}}`, then confirm the NEXT response's
JSON is indented) and its stated negative control (the same payload via `constructor.prototype`, to
defeat naive `__proto__` string filters) are both unimplemented.

**Probe 5 -- no engine surface:** no `TOOL_PERMISSIONS` key and no `CLAUDE_TOOLS` entry contains
`proto`. `mass_assign_tool.py` -- the closest engine, since it also posts attacker-chosen object
keys -- contains no prototype keys at all.

**Verdict: Q-005 is OPEN, and it is NOT partially covered.** What exists is a complete CLIENT-side
capability that shares the CWE. The distinction matters for whoever picks it up: this is not
"extend the browser probe", it is a new request/response capability, and the ticket's own
`Non-destructive: NO` still stands -- polluting `Object.prototype` server-side persists for every
subsequent request until restart, which is why the ticket already specifies `execution: "operator"`.
One caution for that lane: `techniques.py` has exactly one `prototype_pollution` record and its
`maps_to` says "Client-side". Adding a server-side technique under the SAME id would make one record
claim two capabilities with one `validated_on`; it needs its own id.

## 15. A GATE I TRIPPED, and why routing through it was the right fix

The full suite caught `test_rate_policy.py::test_tools_has_no_unguarded_target_page_goto`. My harness
navigation used `page.goto` directly, which that gate forbids for every navigation in `tools.py`.

The tempting reading was that the harness is OUR OWN loopback server, so rate-limiting it is
meaningless and the gate is over-broad here. That reading is wrong, and the mechanism says why:
`rate_limited_goto` does not only wait -- it calls `_guard_playwright_page`, which installs the
per-page request gate. Skipping it for the harness would leave every SUBRESOURCE THE TARGET FRAME
LOADS unguarded, because the gate is installed per page and the harness navigation is the first one.
So the direct `goto` was not a harmless exemption, it was a hole in the target's rate limiting.

Routed through the helper. MEASURED after the change: `/eval` confirmed, `/strict` still a lead,
`/navsink` confirmed, `/inert` silent -- behaviour identical, hole closed.
