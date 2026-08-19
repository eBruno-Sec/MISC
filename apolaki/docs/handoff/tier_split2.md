# Q-052 slice 2 · the two engines slice 1 deferred

Lane: **Builder · tier-split, slice 2**. Ticket **Q-052**. Slice 1 (`280ce13`) moved 25 engines
INTRUSIVE -> ACTIVE and held two: `run_form_cmdi` and `run_web_probes`. This slice settles them.

Every claim is **MEASURED** (command + real output) or **UNVERIFIED**. Written as the work happens.

---

## VERDICT — both stay INTRUSIVE. Both WRITE, and here is what they write.

| engine | POSTs per run (1 page, 1 form) | persisted objects created | findings |
|---|---|---|---|
| `run_form_cmdi` | **58** | **58 guestbook entries** | 0 |
| `run_web_probes` | **28** | **28 guestbook entries** | 1 (a cookie flag, from the baseline GET) |

Not "a POST that might change state" — persisted rows, counted before and after, on a target that
never had to be vulnerable to anything.

---

## BASELINE — MEASURED before any edit, on an isolated snapshot of HEAD

```
$ git archive HEAD apolaki/agent | tar -x -C $SNAP        # HEAD only: two other lanes have
$ docker run --rm --network apolaki_default \             # uncommitted work in this tree
    -v "$SNAP/apolaki/agent:/app" -v "$SCR:/scratch" -w /app apolaki-agent \
    python /scratch/tiercount.py
TOTAL registered: 111
by tier: {'PASSIVE': 15, 'ACTIVE': 81, 'INTRUSIVE': 15}
selectable at passive: 15 of 111
selectable at active: 93 of 111
selectable at full: 111 of 111
INTRUSIVE selectable at active (must be []): []
run_form_cmdi -> PermissionLevel.INTRUSIVE | active=False
run_web_probes -> PermissionLevel.INTRUSIVE | active=False
```

**Reconciled with slice 1's `96 of 111`:** PASSIVE + ACTIVE = 15 + 81 = **96 by tier**, and
`planner._allowed` returns **93** because slice 1's own `_HEAVY_FULL_ONLY` holds `run_sqlmap`,
`run_zap` and `run_nmap_vuln` at `full` on the COST axis, not the consent axis. Two different
questions, two different numbers, both correct. This slice measures `planner._allowed`, the predicate
the planner actually uses.

---

## APPARATUS — a write-observing lab, because "does it write" is not answerable by reading alone

`writelab.py` (scratchpad, not shipped): a guestbook on the `apolaki_default` network.
`GET /` serves one ordinary HTML form; `POST /post` **appends an entry**; `GET /_entries` returns the
persisted state; `GET /_log` returns every request the server received. Nothing in it is vulnerable.
The question under test is not "does the engine find a bug", it is "does the engine WRITE".

`drive.py` runs the **shipping** engine off the HEAD snapshot against that lab with the real
transport — no stub, no fixture — resets state first, and counts entries before and after.

---

## `run_form_cmdi` — MEASURED: 58 POSTs, 58 persisted entries, 0 findings

```
$ docker run ... python /scratch/drive.py run_form_cmdi http://writelab:8080/?id=1
ENGINE           : run_form_cmdi
result ok/output : True | no body command injection in the page's forms
findings         : 0
requests seen    : 60 {'GET': 2, 'POST': 58}
POSTs sent       : 58
ENTRIES BEFORE   : 0
ENTRIES AFTER    : 58    <-- PERSISTED STATE CREATED BY THE ENGINE
   wrote: name=127.0.0.1&comment=1&submit=1
   wrote: name=127.0.0.1%3B+echo+cmi%24%28%28+421+%2A+619+%29%29&comment=1&submit=1
   wrote: name=127.0.0.1+%7C+echo+cmi%24%28%28+421+%2A+619+%29%29&comment=1&submit=1
   ... and 52 more
```

**The answer to the ticket's question is yes.** One page, one form, one run: fifty-eight rows. The
engine ran correctly and reported honestly ("no body command injection") — the writes are not a
failure mode, they are the *method*. It baselines the form (1 write), then sends every output payload
and every argv payload into each of the first 6 fields (`tools.py:8474`), and captures a
confirming re-send on a hit. Every one of those is a form submission.

`agent/tools.py:8448` is where the discovery happens, and it is worth reading closely:

```python
for fm in csrf.parse_forms(r0.get("body", ""), r0.get("final_url") or url):
    if (fm.get("method") or "").upper() == "POST" or fm.get("inputs"):
```

**The method check is vacuous.** The `or` means any form carrying inputs qualifies, so a form the
application itself declared `method="GET"` is submitted as a POST anyway. MEASURED on a page whose
only form is `<form method="GET" action="/post">`:

```
$ docker run ... python /scratch/drive.py run_form_cmdi http://writelab:8080/getform?q=shoes
requests seen    : 32 {'GET': 2, 'POST': 30}
ENTRIES AFTER    : 30    <-- PERSISTED STATE CREATED BY THE ENGINE
   wrote: q=127.0.0.1&submit=1
```

Thirty writes through a form the app declared safe and idempotent. This engine does not merely fail
to know whether the form writes — it overrides the one declaration the application made about it.

The caller-supplied-`fields` path (what `planner.py:576` uses for a pre-captured form) reaches the
same POST loop through `forms.append((url, fields))` at `tools.py:8444`, so it writes identically.

---

## `run_web_probes` — MEASURED: 28 POSTs, 28 persisted entries. Slice 1 never established what it does; here it is.

Seven checks in one engine (`tools.py:6758-6990`). **Four are read-only, three write:**

| check | carrier | writes? |
|---|---|---|
| CWE-614 cookie flags | baseline GET + **submits up to 2 discovered forms** | **YES** |
| CWE-330 PRNG disclosure | reads the baseline body | no |
| traversal, query parameter | GET probes + GET differential | no |
| traversal, **POST body field** | **POSTs discovered forms**, budget 12 | **YES** |
| traversal, **request header** | **POSTs** the form action / the URL, budget 8 | **YES** |
| IDOR | GET probes | no |
| dangerous methods | OPTIONS + TRACE only | no |

```
$ docker run ... python /scratch/drive.py run_web_probes http://writelab:8080/?id=1
requests seen    : 47 {'GET': 17, 'OPTIONS': 1, 'POST': 28, 'TRACE': 1}
ENTRIES AFTER    : 28    <-- PERSISTED STATE CREATED BY THE ENGINE
   wrote: (empty body)                                    <- the cookie-flags form submit
   wrote: name=anon&comment=hello&submit=Sign             <- the POST-body traversal baseline
   wrote: name=..%2Fbbh-canary.txt&comment=hello&submit=Sign
```

The comment above the cookie carrier (`tools.py:6796`) states the engine's own theory of safety:

> Only a form the APP ITSELF advertises is submitted; never a blind POST to a discovered URL,
> which on a real target could change state.

**MEASURED, the theory is wrong.** A form the app advertises is exactly what a comment box, a
registration form, a "leave feedback" box and a "delete my account" button all are. Advertising the
form is how the app *invites* the write. The distinction the comment draws — advertised form vs blind
POST to a discovered URL — is not the distinction between reading and writing.

The first entry it created is an **empty-body POST** to the form action. On this lab that is a blank
guestbook row; on a real target it is whatever that endpoint does with a submission carrying no
fields, chosen by nobody.

Its traversal carrier is better behaved than `run_form_cmdi`'s: `form_xss.parse_forms` (`form_xss.py:30`)
drops any form not declared `method="post"`, so the GET-form page produced only **1** POST — the
cookie carrier, which uses `crawl.extract_forms` and applies no such filter.

```
$ docker run ... python /scratch/drive.py run_web_probes http://writelab:8080/getform?q=shoes
requests seen    : 19 {'GET': 16, 'OPTIONS': 1, 'POST': 1, 'TRACE': 1}
ENTRIES AFTER    : 1
```

**One write is still a write.** Nothing here is close to the line.

---

## The SPLIT was considered and is BLOCKED BY LANE OWNERSHIP, not by judgement

`run_web_probes` is the costliest of the two to leave at INTRUSIVE, and the cost is already on the
record at `agent/agent.py:240-258`: at the default `active` mode it cannot be scheduled at all, and a
whole-product OWASP Benchmark mission booked **56 vulnerable cases** (weakrand 18, pathtraver 16,
securecookie 22) as a detection shortfall for an engine that never ran. Four of its seven checks are
read-only and would recover that surface at `active`.

Three split designs, all rejected on evidence:

1. **A new INTRUSIVE engine for the write carriers** (mirroring the existing `run_cmdi` ACTIVE /
   `run_form_cmdi` INTRUSIVE split, which is already a split by carrier). Registering an engine
   requires entries in `agent/agent.py`, and **`agent/agent.py` is not this lane's file.** The
   consequences of shipping the registry half without them were checked rather than assumed:
   * `PHASE_OF` (`agent.py:73`) is read as `PHASE_OF.get(tool_name)` (`agent.py:562`) — a missing
     key degrades the UI phase bar, it does not crash.
   * `_AUTO_STORE_TOOLS` (`agent.py:95`) is read as `if not result.error and tool_name in
     _AUTO_STORE_TOOLS` (`agent.py:657`). **A new engine absent from that set finds things and
     drops them on any deterministic / low-AI run** — the exact Q-054 finding-sink shape. That is
     the blocker, and it is not one this lane can fix from `tools.py`.
2. **A runtime mode check inside the engine** — "write only if the mission is running at `full`".
   `ToolRegistry.__init__` (`tools.py:1198-1235`) carries `scope`, `lab_mode`, `stealth`, `intensity`,
   `session_headers`, `budget` — and **no permission level**. Threading one in means changing the
   caller in `agent.py`. Same blocker.
3. **An opt-in input parameter** (the `run_bfla` `allow_delete` precedent). Rejected on the merits,
   not on ownership: the tier is what an operator authorises, and a tool registered ACTIVE that
   writes when a parameter is set is not read-only. These tools are model-facing, so the parameter
   could be set by a model inside an `active` mission — which is precisely the harm the taxonomy
   exists to prevent.

**The split is the right change and it belongs to whoever owns `agent/agent.py`.** Filed below as
Q-052-b with the measurement already done.

---

## WHAT SHIPPED

Neither engine's tier changed, so the description gate did not fire and nothing was re-worded. Two
surfaces were wrong or silent and are now accurate:

* **`_run_web_probes` had no docstring at all.** It declared its tier nowhere in the code — the
  Q-058 case where "silence is a documentation gap, and a gap is invisible to a gate that looks for
  contradictions". It now opens `INTRUSIVE:` and says which three of its seven checks write.
* **`_run_form_cmdi`'s docstring named no tier** (only the model-facing spec description did). It now
  opens `INTRUSIVE:` and states the measured write count.

Neither edit reworded a description to dodge a gate; both add the tier the engine is already
registered under, as a bare token.

---

## THE GUARD — `agent/tests/test_tier_write_facts.py`

A guard that checks the **fact**, not the declaration. It drives both shipping engines through a
recording transport and asserts they issue non-safe-method requests, then asserts they are registered
INTRUSIVE. Re-tiering either to ACTIVE without first removing the writes fails the test.

```
$ docker run ... python -m pytest tests/test_tier_write_facts.py tests/test_description_gate.py -q
..........................                                               [100%]
26 passed
```

**MUTATION TEST — the mutant is killed by the exact intended assertion.** Both engines re-tiered to
`PermissionLevel.ACTIVE` in the snapshot with the writes left in place:

```
FAILED tests/test_tier_write_facts.py::...[run_form_cmdi]
FAILED tests/test_tier_write_facts.py::...[run_web_probes]
E  AssertionError: run_web_probes sends 28 state-changing request(s) against an inert page and is
E  registered ACTIVE. ACTIVE means READ-ONLY. Remove the writes before re-tiering it, or leave it
E  INTRUSIVE.
2 failed, 3 passed
```

The stub-driven count is **28**, identical to the 28 rows the live lab recorded — the fast in-suite
apparatus reproduces the live measurement rather than approximating it.

**NEGATIVE CONTROL, measured both ways.** The same engines against a **form-less** page:

```
$ docker run ... python /scratch/drive.py run_form_cmdi http://writelab:8080/plain?id=1
requests seen    : 2 {'GET': 2}          POSTs sent: 0      ENTRIES AFTER: 0
$ docker run ... python /scratch/drive.py run_web_probes http://writelab:8080/plain?id=1
requests seen    : 19 {'GET': 17, 'OPTIONS': 1, 'TRACE': 1}   POSTs sent: 0   ENTRIES AFTER: 0
```

Zero. So the writes are caused by the form, not by the recorder, and a zero from this apparatus is a
real zero. The same control runs in the suite.

Worth noting from that control: `run_web_probes` **still produced its cookie-flag finding with zero
writes**. The read-only half is not hypothetical — it works, and it is what Q-052-b would recover.

---

## ANTI-IDLE — the remaining 13 INTRUSIVE engines, audited in the direction nobody checked

Slice 1 proved the list was wrong four times in ONE direction (engines listed for ACTIVE that write).
The other direction — engines held at INTRUSIVE that change nothing — had never been measured.
Every one was driven **at the wire** against the write lab, not through a stub: several of these
engines build their own httpx client and bypass `self._http`, and a stub would report a comfortable
zero for exactly those.

```
ENGINE                             reqs  WRITES  entries  methods                error
run_race                             61      60       60  OPTIONS,POST
run_bfla                              9       6        6  GET,PATCH,POST,PUT
test_numeric_abuse                    5       5        5  POST
run_stored_xss                        2       1        0  GET,POST
confirm_authz_write                   0       0        0  -
confirm_create_object_idor            0       0        0  -   TypeError (bad test input)
http_request                          1       0        0  GET
run_cache_poison                      6       0        0  GET
run_deserialization                   1       0        0  GET
run_hash_crack                        0       0        0  -
run_mass_assign                       0       0        0  -
run_upload_test                       1       0        0  GET
run_workflow                          0       0        0  -
```

### The apparatus was wrong first, and the fix is the reason to trust the table

The first run of this audit scored `run_bfla` at **2 writes**. The lab had no `do_PUT`/`do_PATCH`/
`do_DELETE`, so it answered 501 and **never recorded** — an apparatus that could not see three of the
four write methods, reporting zeros as though they meant something. With the handlers added,
`run_bfla` measures **6 writes across POST, PUT and PATCH** — exactly the "3 methods x 2 identities"
slice 1 derived by reading, arrived at independently. Slice 1's reading of `test_numeric_abuse`
("up to 5 writes per probed field") also lands exactly: **5**.

**Four engines confirmed state-changing at the wire.** That is the positive control for every zero
below it.

### FOUR ZEROS ARE INCONCLUSIVE, NOT CLEAN — the engine never reached its own behaviour

`run_mass_assign`, `run_workflow`, `confirm_authz_write` and `confirm_create_object_idor` sent
**nothing at all**: each bailed on a missing precondition (a spec, a pack, owner/attacker sessions) or
crashed on the test input. A zero from an engine that never started is not evidence of anything.
Slice 1's reading of `run_mass_assign` (N+2 persistent objects, never deleted) stands unchallenged;
`_confirm_authz_write`'s own docstring says it "has a DIFFERENT user attempt a bounded change" and
restores it, which is a write with a cleanup, not a read.

### THE METHOD ORACLE IS NOT THE STATE ORACLE — `run_cache_poison` proves it

`run_cache_poison` sent **6 requests, all GET, zero non-safe methods** — and it is correctly
INTRUSIVE. Its state change is not in the request method: it makes a **shared cache store and serve**
an injected canary, and its own confirmation oracle is that a *subsequent clean request still receives
it*. A cached poisoned entry is changed state that other clients receive, and no HTTP method reveals
it.

This is a real limitation of the guard shipped above, recorded rather than hidden: **an engine can
change state without ever sending a non-safe method.** The guard is sound in the direction it fires
(a non-safe request IS a state change) and unsound as a clearance certificate (a safe-method run is
NOT proof of read-only). It is written as a one-way ratchet for that reason.

`run_upload_test` (1 GET — my lab advertises no upload form) writes a **file** on the target when it
reaches its behaviour; `run_deserialization` (1 GET — no serialized blob to corrupt) sends payloads
whose success condition is deserialization on the server. Both INTRUSIVE-justified on reading, both
inconclusive at the wire because this lab does not offer them their precondition.

### ONE GENUINE MISFILE FOUND — `run_hash_crack` changes nothing, and is filed rather than moved

**MEASURED: 0 requests. Not zero writes — zero contact with the target.** Its own docstring
(`tools.py:1607`) says so: *"INTRUSIVE (offline)... Offline analysis of a hash already held — never
contacts a live auth endpoint, never brute-forces credentials over the network."* Against the rule
slice 1 wrote into `scope.PermissionLevel` — *if the run were interrupted halfway, would the target
need cleaning up?* — the answer is no. It is not state-changing under the settled taxonomy.

It does not merely fail the INTRUSIVE test — **it matches the PASSIVE definition slice 1 wrote, by
that definition's own named example** (`scope.py:28`):

> PASSIVE  Observes. Sends NOTHING to the target. Third-party sources (crt.sh, wayback, DNS,
> GitHub), **offline computation over data already in hand (hash identification**, dork generation,
> decoding a SAMLResponse already captured). If it opens a socket to the target, it is not PASSIVE.

And the codebase already agrees with itself elsewhere: **`run_hash_id` is registered PASSIVE**
(`test_bbh.py:3898`). Two engines with the identical target-state footprint — zero — sit three tiers
apart. Whatever separates them, it is not what the tier axis says it measures.

**It is deliberately NOT moved in this slice, for two reasons, one of them hard.**
First, the INTRUSIVE tier is doing double duty: the HITL gate is keyed on it (`agent.py:131`,
*"INTRUSIVE tools require operator approval unless the run is pre-authorized"*, and `scope.py:47`
*"INTRUSIVE rides the HITL approval gate and `auto_approve`; ACTIVE does not"*). Re-tiering
`run_hash_crack` on the state-change axis alone would silently remove the operator-approval prompt
from **offline credential cracking** — a sensitive capability whose consent requirement has nothing to
do with target state.

Second, and decisively for this lane: **`test_bbh.py:3903` pins it** —
`assert tools.TOOL_PERMISSIONS["run_hash_crack"] == PermissionLevel.INTRUSIVE` — and `test_bbh.py`
is not this lane's file. Moving the engine would red a test I am not permitted to re-aim, which is
the correct outcome: a pinned tier is a decision someone recorded, and unpinning it is their call. That is the same shape as the cost-vs-consent split slice 1 had to name
(`_HEAVY_FULL_ONLY`), one axis further out: **sensitivity is a third axis, and it is currently
riding on the tier.** Deciding that is a product question, exactly like Q-052 itself was. Filed as
Q-052-c below, with the measurement already done.

---

## FILED

**Q-052-b · split `run_web_probes` — four read-only checks at ACTIVE, three write carriers at
INTRUSIVE.** Measured above: the read-only half produces findings with zero writes, and
`agent.py:240` already measures the cost of the current all-or-nothing tier at **56 benchmark cases**.
Blocked here only by lane ownership — registering the second engine needs `PHASE_OF` and
`_AUTO_STORE_TOOLS` in `agent/agent.py`. Whoever owns that file should take it; the guard already
pins the property, and the three carriers to lift are contiguous blocks:

| carrier | lines (post-slice-2 `tools.py`) | swallow key |
|---|---|---|
| cookie-flags form submit | **6800–6812** (`import crawl as _ccr` … ) | `web_probes.cookie_form_submit` |
| POST-body traversal | **6857–6901** (`import form_xss as fx` … ) | *(bare `except Exception: pass`)* |
| request-header traversal | **6902–6934** (`import header_vector as _hv` … ) | `web_probes.traversal_header` |

Everything else in the engine is read-only and stays. Note in passing: the POST-body carrier's
handler is a bare `except Exception: pass` while its two neighbours both call `self._swallow` — so a
crash in the one carrier that writes the most is the only one that leaves no trace in the
"check(s) failed to execute" warning the engine prints. Not this slice's ticket, but it is on the
same lines whoever lifts them will be editing.

**Q-052-c · `run_hash_crack` is INTRUSIVE for sensitivity, not state change.** Measured: 0 requests.
Needs the sensitivity axis separated from the tier before it can move, or the HITL prompt for offline
credential cracking disappears with it. Also pinned by `test_bbh.py:3903`, so the move needs that file's owner. Its PASSIVE sibling `run_hash_id` is the control: same zero footprint, three tiers away.

**Q-052-d · two more engines declare no tier in code** — `_run_cache_poison` (`tools.py:8777`) and
`_run_deserialization` (`tools.py:7493`) have docstrings that name no tier and none at all
respectively. Same Q-058 silence gap `_run_web_probes` had, invisible to a gate that looks for
contradictions.

**`_confirm_authz_write` declares `"ACTIVE, INTRUSIVE (opt-in)"`** (`tools.py:2935`) — a WRITING
engine whose docstring opens by calling itself ACTIVE. It passes rule B because the registered tier
appears as a bare token somewhere in the declaration, which is the compound-declaration allowance
working as designed and being wrong here. Corrected in slice B below.

---

## REVERT CONDITIONS — pre-registered in Q-052, checked here

**1. No state-changing engine may become selectable at `active`.** HOLDS, and this slice is the
strongest evidence yet for it: the two candidates were driven and both write, so neither moved.
MEASURED after the edits, identical to the baseline above:

```
by tier: {'PASSIVE': 15, 'ACTIVE': 81, 'INTRUSIVE': 15}
selectable at active: 93 of 111
INTRUSIVE selectable at active (must be []): []
```

**2. Benchmark macro must not drop on any suite category.** UNAFFECTED BY CONSTRUCTION, and
**NOT re-run** — said plainly rather than dressed up as a measurement. No engine changed tier, no
engine changed behaviour, the planner is untouched, and the shipped diff is two docstrings plus a new
test file. There is no path from this change to a benchmark number. Benchmarks are immutable and a
moved number would be a re-measure to report; nothing here can move one.

**3. Mission wall-clock at `active` must not rise more than 2x.** UNAFFECTED BY CONSTRUCTION: zero
engines were added to `active` (93 before, 93 after), so the set of work an `active` mission performs
is byte-for-byte the same.

**4. Classification by reading is the likeliest way this is wrong.** This is the condition that
governed the whole slice. It fired FOUR times on slice 1, so slice 2 classified nothing by reading:
both engines were driven against a real server and their writes counted as persisted rows. It also
caught **my own apparatus** — the first audit run scored `run_bfla` at 2 writes because the lab could
not answer PUT/PATCH/DELETE. Reading was used only to explain measurements, never to produce them.

---

## APPARATUS FAILURE, RECORDED — the first full-suite run was INVALID and was thrown away

The first full-suite run reported **3 failures, all in `tests/test_deadcode_gate.py`**. It would have
been easy and wrong to write them off as "another lane's known-RED file" and commit anyway. Checked
instead:

```
$ git show HEAD:apolaki/agent/deadcode_gate.py | grep -c resolve_named_caller
0
$ grep -c resolve_named_caller  $SCR/snap/apolaki/agent/deadcode_gate.py      # my snapshot
3
$ grep -c resolve_named_caller  apolaki/agent/deadcode_gate.py                # the shared worktree
3
$ ls -l  ... snap/deadcode_gate.py   worktree/deadcode_gate.py   HEAD-archive/deadcode_gate.py
45197                45197               34473
```

**My "isolated snapshot of HEAD" contained the other lane's uncommitted 45197-byte file** — exactly
one file out of 185, and exactly the file whose uncommitted state is RED. `engine_descriptor.py` and
`tests/test_deadcode_gate.py`, also dirty in the worktree, were correctly at their HEAD versions, and
two fresh `git archive HEAD` extractions of the same tree produced the clean 34473-byte file. **The
mechanism is UNVERIFIED** — I could not reproduce the contamination, and saying so is more useful
than inventing a cause.

Consequence, stated plainly: **that run measured nothing and is not reported as a result.** A clean
snapshot was rebuilt from current HEAD, verified by content and byte count before use, and the suite
re-run. Two side facts fell out of the check:

* the pristine HEAD run of `tests/test_deadcode_gate.py` alone is **green** (33 passed, 1 xfail), so
  the 3 failures were the uncommitted file's, not HEAD's and not mine;
* **HEAD moved twice** during this slice (`280ce13` -> `0276ae0` -> `db150c1`). `git log 280ce13..HEAD
  -- apolaki/agent/tools.py` returns **nothing**, and `git diff HEAD -- apolaki/agent/tools.py` is
  exactly my two docstring hunks, so this lane is not carrying anyone else's file backwards.
