# Probe-repertoire lane - hand-off

Question this lane answers: **388 of 401 Java false negatives are SILENT - the engine ran, produced
nothing, no error. Which probe SHAPES are missing?**

The premise (measured elsewhere, not re-derived here): the recall ceiling is probe/signal generation,
not oracle strictness. Only 5 cases in the whole 2132-case suite were lost to the proof gate being
strict. So this lane adds probe shapes and never touches an oracle threshold.

Status legend: [MEASURED] live numbers - [SHIPPED] committed and tested - [DISCARDED] tried, rejected.

---

## DISCARDED SHAPES - read this before re-testing anything

A discarded shape that is not written down gets re-tested by the next lane. Each entry below cost a
measurement run.

### D. env-differential via PATH - [DISCARDED: it is a reflection detector in disguise]

**Shape.** 77 of the 251 Java cmdi cases route the tainted value into the child process's ENVIRONMENT
(`Runtime.exec(cmdarray, envp)` where `envp = {param}`), not into its command line. The idea was a
general, name-independent probe: `PATH=/nonexistent-zq` vs `PATH=/usr/bin:/bin`, confirming on the
two-sided differential, because PATH is universal to POSIX process execution and needs no knowledge of
the app's own variable names.

**Measured, 50-case sample:** it fired on **20 of 50** cases - 4x the current engine's reach, and
easily the most attractive number this lane has produced.

**Why it was killed.** The two probe VALUES are different strings. Any endpoint that reflects the
value at all produces different bodies for them, so `bad != good` is satisfied by pure reflection and
has nothing to do with the environment. Confirmed by construction on the sink shape that dominates
this category: `Runtime.exec("echo " + bar)` tokenises argv and prints the value back, so the
differential is the echo and only the echo.

This is the same defect that put a 69.2% path-traversal score into a retraction: **a confirmation
that a merely-reflecting endpoint satisfies.** 20 of 50 with a ~50% vulnerable rate means it was
already confirming on clean cases. Not shippable at any threshold - the flaw is the oracle's shape,
not its strictness.

**Do not resurrect it without a reflection-immune differential** (e.g. the two probe values must be
byte-identical in everything except a part the response cannot echo).

### C. environment-variable injection by name - [DISCARDED: it is a suite signature]

**Shape.** The same 77 env-carrier cases are exploitable if you know the child's variable name: the
Benchmark's helper script does `eval $FOO`, so `FOO=<command>` executes. **Measured: 5 of 50, and the
same 5 cases the shipping append payloads already catch** - so it buys literally nothing even before
the ethics of it.

**Why it was killed even if it had paid.** `FOO=` is tuned to this benchmark's helper script. A
payload that works because of a constant in the target's own source is a signature, whatever the
score. Rule stands: never hardcode a per-suite fingerprint.

### E. time-based blind through shell metacharacters - [DISCARDED for cmdi on this suite: 0 of 50]

**Shape.** `agent/cmdi_tool.py:86-101`, already shipping: `<v>; sleep 5` etc. with matching
`sleep 0` controls, six separator variants.

**Measured: 0 additional cases out of 50**, tested across all four carriers on every case the output
oracle did not already catch.

**Why, and this is the load-bearing finding of the lane.** The time payloads use the SAME shell
metacharacter separators as the output payloads. They therefore need the SAME reach: a context where a
shell parses the value. If `;` does not split, neither `echo` nor `sleep` runs. Blind-vs-echo was never
the axis of failure on this category - **shell reach was.**

So the standing hypothesis "the untested cmdi shapes are blind/time-based and OOB" is falsified for
the metacharacter form of both. Any OOB payload built from the same separators
(`agent/cmdi_tool.py:104-112`) inherits the identical ceiling and is expected to measure 0 for the
same reason.

### B. HTML-entity-decoded matching, appended payloads - [DISCARDED alone: 0 additional of 50]

**Shape.** `analyze_output` matches the RAW body. Java apps routinely ESAPI-encode command output, so
`uid=0(root) gid=0(root)` arrives as `uid&#x3d;0&#x28;root&#x29;` and the `id` / `/etc/passwd`
signatures can never match. Measured on this suite: entity decoding on its own adds **0** cases,
because the computed-echo marker (`cmi260599`) is alphanumeric and already survives encoding.

**Not resurrected as a standalone change, but it is a REAL prerequisite** for the argv-sink shape
below, whose only proof is `id` / passwd output. Recorded here so the zero is not mistaken for
"decoding is pointless".

---

## WHY cmdi IS AT 28.6% - the diagnosis, [MEASURED]

Sink shapes across the 251 cmdi cases, from the served application's own source:

| construction | cases | shell parses the value? |
|---|---:|---|
| `getOSCommandString(...)` -> `exec(String)` or `exec(String[]{sh,-c,cmd+bar})` | 111 | **only** the 3-element array form |
| `getInsecureOSCommandString(...)` -> `exec(cmdarray, envp={param})` | 77 | no - value is the child's ENVIRONMENT |
| other / laundered clean twins | 63 | - |

The decisive distinction is Java's, not the benchmark's:

* `new String[]{"sh", "-c", cmd + bar}` - the value is inside a single shell script argument.
  **Shell-injectable.** This is the shape the shipping payloads catch.
* `Runtime.exec(cmd + bar)` **as one String** - Java tokenises on whitespace and runs argv directly.
  There is no shell. `; echo x` merely adds three more argv words. **Metacharacter injection is
  structurally impossible here**, and no threshold change can recover it.

`getOSCommandString("echo")` returns `"echo "` on Linux - no `sh -c` prefix at all - so the
`exec(String)` cases are plain argv sinks that print their arguments back.

**Consequence.** A large part of the 90 silent cmdi false negatives are cases the Benchmark labels
vulnerable because taint reaches an exec sink, where no general black-box payload can prove execution
through a shell, because no shell is involved. The remaining reachable shape is the argv sink itself:
replace the value with a bare command instead of appending to it.

### Carrier reach, [MEASURED] 50-case sample

Live carriers (a unique token in the value changes the response): query 8, body 7, header 3,
cookie 4, none 36. The shipping `_run_form_cmdi` probes query + body + discovered custom headers.
**It has no cookie carrier at all**, and cookie is a live carrier on this suite.

---

## THE SHAPE THAT WORKS: argv-sink, value-REPLACING payloads - [SHIPPED]

**Shape.** Where the launcher is handed the value as the command line itself, the value must be
REPLACED by a bare command rather than appended to. `id` and `cat /etc/passwd`; the proof is that
command's own output.

**Reflection-immunity, which is why it is shippable.** `uid=0(root) gid=0(root)` is absent from the
payload `id`, exactly as the computed product is absent from the echo payloads. An endpoint that
merely reflects the payload therefore cannot satisfy `analyze_output`, and no threshold was moved to
make the shape fire. `test_argv_proof_strings_are_absent_from_the_payloads` asserts the property for
every payload in the list, so it cannot be lost by someone adding a payload later.

### THE ENGINE NUMBER IS +0, AND IT OVERRIDES THE SAMPLE BELOW - [MEASURED, full category]

Output shapes only on both sides (blind budgets zeroed, so the comparison is like with like),
all 251 cmdi cases, per-case diff against the sealed `owaspbench_java_v12_DAST_FULL_20260811`:

    cases 251 | before 36 | after 36 | NEW 0 | LOST 0 | errors 0

**The hand-sweep predicted +5. The shipping engine delivers +0.** Report the engine number.

The difference is DELIVERY, not the payload. The sweep put each payload in a parameter *named after
the test case*, across four carriers (query, body, header, cookie). `_run_form_cmdi` puts payloads in
the fields it discovers in the page's form, plus up to two discovered request headers, and has no
cookie carrier at all. When the form's input name is not the name the handler reads, the payload
never arrives - so the shape is correct and simply never reaches the sink.

Second reason the output shape cannot pay here: the dominant echoing sink is
`Runtime.exec("echo " + bar)`, which tokenises argv and prints `id` back as the literal string `id`.
Only a sink where the value is argv[0] executes it, and those mostly do not echo - which is why the
confirmations that DO land (`01610`, `02146`) come from the argv TIME-BLIND shape, not this one.

**So the remaining cmdi headroom is carrier delivery, not payload repertoire** - the same conclusion
the xss analysis reached independently (87 of 455 xss cases are header-carried and unreachable by a
query-only engine). That is the next thing to build, and it is worth more than any further payload.

**[MEASURED] 50-case hand-sweep - kept for the shape analysis, NOT as a gain estimate:**

| shape | hits / 50 |
|---|---:|
| append (ships today) | 5 |
| **bare argv (new)** | **5, disjoint from the above** |
| union | **10** |
| bare non-command control (`zqnotacmd`), all 4 carriers | **0** |

Live, on cases the append shape cannot touch, a bare `id` returns
`uid=0(root) gid=0(root) groups=0(root)` straight out of the handler. That is command execution
proven by output, not a differential.

Disjointness is expected by construction, not luck: the two shapes address structurally different
sinks (a 3-element `sh -c` array vs a tokenised `exec(String)`), and an endpoint is one or the other.

---

## STRUCTURAL DEFECTS FOUND BY READING THE ENGINE - [SHIPPED, fixed]

1. **The blind/time oracle in `_run_form_cmdi` is latched off after ONE case per process.**
   `agent/tools.py:7252` guards on `self._timing_cmdi_done`, set on the ToolRegistry. The benchmark
   harness (`agent/owasp_bench.py:139`) builds ONE registry for the whole run, so across 251 cmdi
   cases the time-based shape runs at most once. Same defect on `_timing_cmdi_hdr_done`
   (`agent/tools.py:7301`). The latch is correct as a no-DoS bound for a form-heavy crawl and wrong
   as a per-target gate; the fix has to keep the bound while making it per-endpoint.
2. **`_run_form_cmdi` has no OOB path.** `_run_cmdi` (query-string carrier) has one at
   `agent/tools.py:7161-7178`; the form/header engine the harness actually maps `cmdi` to has none.
3. **No cookie carrier** in either cmdi engine.

Given finding E above, fixing 1 and 2 was **not** expected to move this suite's number much - both
inherit the metacharacter ceiling. They were fixed as real defects for targets that DO have shell
reach, and the honest claim for them is a capability claim, not a benchmark claim.

**How they were fixed.**

1. The latch became **per-endpoint with an explicit global budget** (`_timing_cmdi_seen` +
   `_timing_cmdi_budget`, intensity-scaled 6/16/32). The bound the old flag was protecting is kept
   and made explicit; what is removed is the accident that one registry driving many endpoints got
   the shape once. Both blind shapes are now tried - three append separators and the two argv forms -
   because an endpoint is one sink or the other.
2. `_run_form_cmdi` gained the **OOB path** it never had, with the same per-endpoint budget, both
   payload shapes, and a single poll after all probes are sent rather than one dead 3s wait per
   field. Gated on `collaborator.reachable_from(target)`, so it is never attempted when a callback
   could not arrive even in principle.
3. A **repeat gate on every time-based confirmation**: the control/probe pair must reproduce the
   delay before anything is reported. This is strictly additive precision - `analyze_time` itself is
   untouched - and it exists because one slow response is something an endpoint under load produces
   for free, and a finding here costs the 0.0% false-positive rate.

Negative controls shipped as tests for each: an endpoint slow for EVERY input does not confirm; a
delay that does not reproduce does not confirm; an OOB probe whose callback never arrives is a
non-detection; and each control asserts the probe WAS SENT before asserting nothing was reported, so
it cannot pass by the engine simply never trying.

### The native collaborator is IN-PROCESS, so OOB cannot confirm from the CLI harness

Correlation in `agent/collaborator.py` is a module-level dict in the interpreter that registered the
token, and the inbound callback is recorded by the FastAPI `/oob` route in the SERVER process. When
the tools run inside that server -- a real mission -- the two are the same interpreter and OOB works.
When the caller is a separate process, as `owasp_bench.py` is, the shard registers a token in its own
memory, the target's callback lands in the server's memory, and `hits(token)` is empty forever.

So the OOB shape contributes exactly **0** to any benchmark number produced through the CLI harness,
and that zero is a property of the harness, not of the target or the engine. It is a non-detection,
which is the correct behaviour -- but it must never be read as "the target has no OOB sink". Anyone
scoring OOB has to drive the engines in-process.

---

## WHY THE FULL-CATEGORY cmdi NUMBER DID NOT MOVE - it is my own no-DoS budget

**No cmdi suite figure is published here, because the one this lane produced cannot be defended.**
Three full-category rescans returned **exactly 36**, the baseline number. The cause is now MEASURED
and it is neither staleness nor the engine:

`BenchmarkTest01610` is confirmed by the **argv TIME-BLIND** shape, not the output shape:

    title    OS command injection (argv-time-blind) in 'BenchmarkTest01610'
    evidence 5.0s vs control 0.0s (injected 5s)
    tags     ['cmdi', 'rce', 'argv', 'blind', 'time']

and the blind shape is bounded to `self._ni(6, 16, 32)` **endpoints per process**. The harness builds
ONE `ToolRegistry` for the whole run, so at standard intensity the blind shape is spent after 6
endpoints and every case after that is silently un-probed. `01610` sits at roughly case 150 of 251.

This is why the same case flips: scanned in a short run it CONFIRMS, scanned at position 150 it
reports empty. Verified by deleting two rows from the checkpoint and re-running only those - both
came back `['cmdi']` where the full run had `[]`. **A result that depends on a case's position in the
run is not a measurement**, and publishing the 36 would have reported a working shape as a failure.

The tension is real and it is not a bug to paper over: one timed endpoint costs up to
2 fields x 5 shapes x 2 requests x 5 s = 100 s, so 251 endpoints of blind probing is hours, and the
budget is exactly what stops a form-heavy crawl filling with sleeps. Options, none free:

1. Raise intensity for a benchmark run (`deep`/`insane` -> 16/32). Still not 251.
2. Make the blind probe cheaper - shorter sleep, stop at the first shape that shows any delay.
3. Give the harness a fresh registry per case, which changes what is being measured (a real mission
   does not get one).

**The honest split:** the argv OUTPUT shape is unbudgeted and its gain is real; the argv TIME shape
is budgeted and its gain does not survive a 251-case single-process run. A future measurement must
report which of the two produced each confirmation, or it will keep re-discovering this.

## A MEASUREMENT THAT CANNOT SEE ITS OWN CODE IS WORTHLESS - gate it

Two consecutive full-category rescans of `cmdi` returned **exactly 36 findings, the baseline number**,
while a fresh process in the SAME container, driving the SAME harness code path, confirmed four cases
those runs had reported empty (`BenchmarkTest01610`, `01936`, `02146`, `02154`). The engine was
correct; the runs were measuring code that was not loaded. There was no stale `__pycache__` and no
error in any row - the runs were silently, confidently stale.

That failure is indistinguishable from "the change did not work", and it would have been reported as
such. The fix is not more care with `docker cp`; it is to make the run refuse to produce a number it
cannot vouch for:

    _src = inspect.getsource(tools_mod.ToolRegistry._run_form_cmdi)
    missing = [n for n in ("argv_payloads", "_timing_cmdi_seen", "argv_oob_payloads")
               if n not in _src]
    if missing:
        sys.exit("ABORT: loaded engine is missing %s -- this run would measure stale code" % missing)

**Every future before/after run in this lane should carry that gate.** It is the same lesson as
"guards that check declarations, not facts", applied to the measurement instead of the engine: assert
the thing you are about to measure is actually there, and fail loudly when it is not.

## `set_param` - one contract, and the control that would have caught the divergence

Handed to this lane by the orchestration lane (D3). Three modules define `set_param` and every
injection engine probes through one: `xss_tool` (used by `_run_sqli`, `_run_nosqli`, `_run_cmdi`,
`_run_xss`), `ssrf_tool`, `dom_trace`. They disagreed about a MISSING parameter - `ssrf_tool` and
`dom_trace` appended it, `xss_tool` returned the URL **unchanged**.

Why it is a silent false negative: when an engine probes a parameter it DISCOVERED rather than one
already on the URL, the dropped parameter means the probe URL IS the baseline URL. The engine sends
the baseline, compares it against the baseline, finds no difference, and reports clean. The probe was
never sent, and the result is shaped exactly like a correct non-detection.

Fixed by making `xss_tool` append, and documented at the definition. The load-bearing part is the
control in `agent/tests/test_set_param_contract.py`:

    assert mod.set_param(BASE, param, "PAYLOAD") != BASE   # a probe that equals its baseline is not a probe

asserted for all three modules over present AND absent parameters, plus a cross-module agreement
test. Mutation-tested both ways: making `ssrf_tool` drop a missing parameter kills 4 tests, making
`xss_tool` append the wrong value kills 5.

**Effect on this lane's cmdi work: CHECKED, UNAFFECTED.** The benchmark maps `cmdi` to
`_run_form_cmdi`, which contains zero `set_param` calls - it builds bodies with `urlencode` and
carries headers directly. Verified by counting call sites inside the function's line range. The
query-string engine `_run_cmdi` does use it and was exposed, but is not on the measured path.

## Files this lane owns

`agent/tools.py` (cmdi/sqli/xss engines only) - `agent/cmdi_tool.py` - `agent/sqli_tool.py` -
`agent/collaborator.py` - their tests - `docs/handoff/probes.md`.
The Coordinator folds numbers into the ledger; this lane does not write it.

---

## CARRIER DELIVERY - the ticket this lane's own measurement produced

The cmdi `+0` proved the shapes were fine and the DELIVERY was not. Both categories reached the same
conclusion independently, which is the strongest evidence this lane has:

| engine | doors it had | doors it lacked |
|---|---|---|
| `_run_form_cmdi` | query string, form body, 2 discovered headers | **cookie (none at all)** |
| `_run_xss` | query string, URL fragment | **request header, cookie** |

[MEASURED] carrier mix from the served application's own source:
* cmdi, 251 cases: 28 param, 27 header, 24 querystring, 19 cookie, 153 other/laundered
* xss, 455 cases: 220 param, **87 request header**, 60 querystring, 88 other

### Shipped
* **cmdi cookie carrier** (slice 6). Candidate names are the ones the page already reveals - its form
  fields and its declared header names. Output shapes only; the blind shapes stay on the budgeted
  per-endpoint path, so widening a carrier cannot widen the sleep count.
* **cmdi header carrier widened** from a hardcoded 2 to intensity-scaled 4/8/12.
* **xss request-header carrier** (slice 4), reusing the breakout oracle unchanged.

### The two controls every NEW carrier must carry
A new door is a new place for two already-proven failures to reappear, so both are asserted per
carrier rather than once:

1. **The probe must differ from its baseline.** This is the `set_param` defect wearing different
   clothes: if the probe request is byte-identical to the baseline, the differential is zero and the
   endpoint reports clean whatever it does.
2. **A carrier that makes an endpoint ECHO is not a carrier that makes it EXECUTE.** This is the
   filter that killed the PATH env-differential at 20/50, and it is the defect that put a 69.2%
   traversal score into a retraction.

### Still open
* **xss cookie carrier** - not built. 
* **cmdi/xss body content-type shapes** (JSON, multipart) the form path misses - not investigated.
* No suite re-measurement has been run since slice 6. The cmdi `+0` figure above predates the cookie
  carrier and does NOT describe it. Any new figure must use the `inspect.getsource` gate, must zero
  or fix the blind budget so results do not depend on case position, and must report the silent-FN
  count next to the score.
