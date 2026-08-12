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

## STRUCTURAL DEFECTS FOUND BY READING THE ENGINE (not yet fixed at time of writing)

1. **The blind/time oracle in `_run_form_cmdi` is latched off after ONE case per process.**
   `agent/tools.py:7252` guards on `self._timing_cmdi_done`, set on the ToolRegistry. The benchmark
   harness (`agent/owasp_bench.py:139`) builds ONE registry for the whole run, so across 251 cmdi
   cases the time-based shape runs at most once. Same defect on `_timing_cmdi_hdr_done`
   (`agent/tools.py:7301`). The latch is correct as a no-DoS bound for a form-heavy crawl and wrong
   as a per-target gate; the fix has to keep the bound while making it per-endpoint.
2. **`_run_form_cmdi` has no OOB path.** `_run_cmdi` (query-string carrier) has one at
   `agent/tools.py:7161-7178`; the form/header engine the harness actually maps `cmdi` to has none.
3. **No cookie carrier** in either cmdi engine.

Given finding E above, fixing 1 and 2 is not expected to move this suite's number much - both inherit
the metacharacter ceiling. They are still real defects for targets that DO have shell reach and are
worth fixing on that basis, not on a benchmark basis.

---

## Files this lane owns

`agent/tools.py` (cmdi/sqli/xss engines only) - `agent/cmdi_tool.py` - `agent/sqli_tool.py` -
`agent/collaborator.py` - their tests - `docs/handoff/probes.md`.
The Coordinator folds numbers into the ledger; this lane does not write it.
