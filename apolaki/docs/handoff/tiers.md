# Q-052 -- the permission tiers: consent, not coverage

TIERS lane. Owns `agent/agent.py`, `agent/planner.py`, `agent/tests/test_permission_tiers.py`,
this file.

Every claim below is MEASURED (command + real output) or marked UNVERIFIED. Two of the three things
the ticket asked me to check turned out differently than the ticket predicted, and both are recorded
as disproofs rather than quietly fixed.

Test baseline for this lane, on an isolated snapshot of HEAD `2c7d0f8` plus this lane's changes
only (rule 8c -- the shared tree has two other live lanes):

```
docker run --rm -v ".../snap/agent:/app" -w /app apolaki-agent \
    python -m pytest tests/ -p no:cacheprovider -q
-> 2566 passed, 11 skipped, 8 xfailed, 0 failed
```

(The ticket quoted 2562 passed; the other lanes had landed 4 tests by the time I snapshotted.)

---

## SLICE 1 -- the sweep no longer swallows engine failures (LANDED, `b8cf4ef` + `15a3bf8`)

### What was ticketed, and what was actually there

The ticket named ONE bare swallow, at the sweep's main dispatch loop. MEASURED, there were NINE
`except Exception: pass` blocks in `_inject_sweep_surface`, eight of them wrapping a `_run_tool`
dispatch and one wrapping `_discover_params`:

```
$ awk '/except (Exception|BaseException)/{l=NR; e=$0; getline;
       if ($0 ~ /^[[:space:]]*pass[[:space:]]*$/) print l}' agent/agent.py
-> 64 sites in agent.py overall; 9 inside _inject_sweep_surface
```

Fixing only the ticketed one would have moved the blindness rather than removed it. All nine now
record through `ToolRegistry._swallow`:

| site | label | what it dispatches |
|---|---|---|
| `agent.py:3464` | `sweep.fetch_openapi` | OpenAPI spec seeding, 5 paths x 6 bases |
| `agent.py:3470` | `sweep.run_graphql` | GraphQL discovery + introspection |
| `agent.py:3490` | `sweep.run_path_sqli` | REST path-parameter SQLi |
| `agent.py:3514` | `sweep.run_encoded_cookie` | encoded cookie/param injection |
| `agent.py:3528` | `sweep.run_default_creds` | vendor-default credential check |
| `agent.py:3547` | `sweep.<engine>` | **the 92% site** -- the HTTP+browser battery loop |
| `agent.py:3617` | `sweep.html.<engine>` | HTML-page form/DOM battery |
| `agent.py:3626` | `sweep.discover_params` | param discovery |
| `agent.py:3634` | `sweep.run_dom_audit` | CSTI / prototype-pollution audit |

`sweep.discover_params` is the one worth naming separately. It was not a `_run_tool` dispatch and
so was not in the ticket, but its failure mode is worse than the others: `disc` falls back to `[]`,
which SKIPS `run_dom_audit` entirely. A crash there silently removed the whole
CSTI/prototype-pollution class from the mission and the run still reported clean. That is this
project's own "falsy default hides behaviour" shape, sitting inside the swallow it was hiding behind.

### The test, red before the fix

`agent/tests/test_permission_tiers.py` drives the REAL `_inject_sweep_surface` with a `_run_tool`
that raises, and asserts on `tools.swallowed` -- a fact about what happened, not a declaration that
a handler exists. MEASURED before the fix:

```
$ pytest tests/test_permission_tiers.py
8 failed, 5 passed
FAILED test_a_crashing_sweep_engine_is_recorded_not_dissolved
FAILED test_the_record_names_the_engine_and_the_target
FAILED test_every_sweep_dispatch_site_records_its_failures[fetch_openapi]
FAILED test_every_sweep_dispatch_site_records_its_failures[run_graphql]
FAILED test_every_sweep_dispatch_site_records_its_failures[run_path_sqli]
FAILED test_every_sweep_dispatch_site_records_its_failures[run_encoded_cookie]
FAILED test_every_sweep_dispatch_site_records_its_failures[run_form_xss]
FAILED test_active_and_full_are_distinguishable_at_the_dispatcher
```

Negative controls that were green both before and after, so the fix is not the thing making them
pass: `test_a_clean_sweep_records_nothing` (a healthy sweep records zero entries, so the ledger
stays usable as evidence) and `test_a_crash_does_not_abort_the_sweep` (recording must not change
control flow -- the engines after the crashing one on the same target still run).

### Did it reveal engines that have been failing silently?

**NOT ESTABLISHED, and the reason is worth stating rather than papering over.** `_swallow` records
into `ToolRegistry.swallowed`, which is per-mission and in-memory. The 151 historical missions in
the store ran the bare-`pass` code, so their failures were destroyed at the time and cannot be
recovered from any artifact. The recording starts with `b8cf4ef`; the question "which engines have
been failing silently all along" is answerable only by the NEXT whole-product mission, not by this
one. I have not run one, so I am not going to guess at an answer.

UNVERIFIED / next action for whoever runs wp4: read `ToolRegistry.swallowed` at mission end and
diff the `where` labels against `_SWEEP_HTTP_ENGINES`. Any label appearing at the sweep's full
target count is an engine that has never worked on this target class.

---

## SLICE 2 -- the tier decision

### The measured defect

`_run_tool`'s entire mode enforcement is `if self.mode == "passive" and perm != PASSIVE: block`.
MEASURED by driving the real `_run_tool` with a probe registered at each tier
(`test_active_and_full_are_distinguishable_at_the_dispatcher`):

```
`active` and `full` are indistinguishable at the dispatcher: both admit
['active', 'intrusive', 'passive']. The mode the operator selects has no effect above `passive`.
```

`planner._ALLOWED` does honour the tier. So the ticket's framing is confirmed: two mechanisms, one
decorative. The test is currently a **strict xfail** carrying that measurement in its reason, landed
by the Coordinator so the defect is pinned in the suite while the decision is made.

### The census

```
$ python -c "import tools, collections; ..."
census: {'passive': 15, 'active': 56, 'intrusive': 43}  total 114
```

### Cost of narrowing `active` to {PASSIVE, ACTIVE} at the dispatcher

MEASURED by running the REAL `_inject_sweep_surface` over a 44-URL surface (40 parameterized
endpoints + login/api/account/search pages) with a recording `_run_tool`, then classifying every
dispatch by `TOOL_PERMISSIONS`:

```
TOTAL sweep dispatches: 477
by tier: {'active': 229, 'intrusive': 236, 'passive': 12}

if `active` excluded INTRUSIVE: 236 of 477 dispatches (49.5%) disappear from the sweep
engines that would stop running entirely (7):
    run_encoded_cookie, run_injection_probes, run_ldap, run_path_sqli,
    run_sqli, run_sqli_structural, run_xpath
engines that survive (11):
    fetch_openapi, run_client_checks, run_css_injection, run_dom_audit, run_dom_trace,
    run_form_xss, run_graphql, run_session_token, run_ssi, run_waf_bypass, run_xss
```

**So: 7 of 18 sweep engines move, 49.5% of sweep dispatches vanish, and a default `active` mission
loses ALL of its SQL injection detection** -- `run_sqli`, `run_sqli_structural` and `run_path_sqli`
are the entire SQLi surface of the sweep, and the sweep is the only path to them in `active`
(the planner already refuses INTRUSIVE, `agent.py:227-233`). XPath and LDAP injection go with them.

That is not a safety fix. That is a trade, and it has to be priced as one.

### Does the ticket's reading survive contact? NO.

The hypothesis was: `active` should exclude engines that modify state or carry exploitation risk.
That is a coherent product rule. The problem is that **the existing INTRUSIVE tier is not that set**,
so re-using it as the consent boundary does not deliver the property. MEASURED, there are
counterexamples in BOTH directions, taken from the engines' own docstrings:

**INTRUSIVE but incapable of touching the target at all:**

```
run_hash_crack   "INTRUSIVE (offline): dictionary-crack a SUPPLIED hash with hashcat/John against
                  a LOCAL wordlist. Offline analysis of a hash already held -- never contacts a
                  live auth endpoint, never brute-forces credentials over the network."
```

An engine that makes zero network contact is gated by the tier that supposedly gates aggression
against the target. Under the proposed rule it should be freely permitted in `active`. It is not.

**ACTIVE and permanently state-modifying:**

```
run_session_lifecycle  "ACTIVE: ... Mints a SACRIFICIAL account through the target's own signup ...
                        logout / password change / declared expiry ..."
run_session_fixation   "ACTIVE: ... Drives ONE real client with a KNOWN-GOOD credential through the
                        login boundary ..."
run_default_creds      "ACTIVE: ... tries exactly ONE documented vendor-default pair ... and
                        confirms via the product's authenticated-view marker."
run_form_xss           "Reflected XSS through POST FORM fields ... CONFIRM in a real browser by
                        filling + submitting the form ... ACTIVE"
```

`run_session_lifecycle` **creates an account on the operator's application and changes its
password**. It is ACTIVE today, and it would still be ACTIVE after the proposed narrowing. So an
operator who selected `active` expecting "non-intrusive testing" would, after the change, still get
account creation, credential rotation, a real login, a vendor-default credential attempt and form
submissions -- while having lost every SQL injection check. The change costs half the sweep and
does not buy the property it was proposed to buy.

The tiers also disagree with themselves. MEASURED by comparing each engine's docstring tier label
against its `TOOL_PERMISSIONS` entry:

```
confirm_authz_write         doc says ACTIVE    registry says INTRUSIVE
confirm_create_object_idor  doc says ACTIVE    registry says INTRUSIVE
run_external_surface        doc says PASSIVE   registry says ACTIVE
run_param_mine              doc says ACTIVE    registry says INTRUSIVE
```

Grouped by what they actually do, today's INTRUSIVE tier is a union of at least three unrelated
concerns:

- **state modification** -- `confirm_authz_write`, `confirm_create_object_idor`, `run_mass_assign`,
  `run_stored_xss`, `run_upload_test`, `run_race`, `run_workflow`, `http_request`
- **exploitation risk without necessary state change** -- `run_sqli`, `run_xpath`, `run_ldap`,
  `run_cmdi`, `run_xxe`, `run_ssrf`, `run_nosqli`, `run_deserialization`
- **volume / noise / runtime, with no side effect at all** -- `run_ferox`, `run_gobuster`,
  `run_dirsearch`, `run_dir_harvest`, `run_content_discovery`, `run_ffuf`, `run_param_mine`,
  `run_nmap_vuln`, `run_zap`, and `run_hash_crack`, which is not even networked

A single ordinal axis cannot express "may write to your database", "may crash your app", and "will
send 50,000 requests" at once, and an operator's consent question is different for each.

### THE DECISION

**The tier NAMES are wrong, and `active` should be RENAMED rather than narrowed.** This is the
outcome the ticket explicitly allowed for, and it is where the evidence points.

Reasoning, stated so it can be attacked:

1. Narrowing `active` costs 49.5% of sweep dispatches and all SQLi detection (MEASURED).
2. It does not deliver the safety property, because ACTIVE still contains an engine that registers
   an account and rotates a password (MEASURED, from that engine's own docstring).
3. The set it would exclude includes an engine that cannot contact the target (MEASURED).
4. Therefore the current tier is not a consent axis. It behaves as an **aggression/cost** axis, and
   it is roughly honest as one.

Concretely, what I recommend and why it is cheap:

- **Rename the axis to what it measures.** `passive` / `active` / `full` become a statement about
  scan aggression, which is what they already encode. No dispatch changes, no benchmark re-measure,
  no engine moves. The lie stops being told.
- **Add a SEPARATE, orthogonal consent flag for side effects** -- one boolean, "may this scan write
  to the target". `_exec_internal` already has exactly this concept in `authenticated_scan`
  (`agent.py:629-642`), described in its own comment as "the operator's explicit opt-in to
  state-changing AUTHENTICATED testing". The consent mechanism the product needs already exists on
  one dispatch path; the defect is that `_run_tool` does not consult it and that no per-engine
  "writes to target" fact exists to consult it against.
- **The dispatcher must still stop being decorative.** Whatever the axis means, `_run_tool` should
  enforce the same table the planner does, so that two mechanisms stop disagreeing. If the axis is
  aggression, then `active` excluding INTRUSIVE is the *consistent* reading -- and it costs what is
  measured above. That cost is a product call about the default, not a correctness call: the fix is
  to make the DEFAULT mode `full` if the current dispatch behaviour is the desired behaviour, which
  changes one word and zero dispatches, rather than to leave `active` meaning "full" in silence.

The minimal honest change, if only one thing is done: **change the default from `active` to `full`
(`main.py:56`, `main.py:111`, `agent.py:377`, `agent.py:415`) and make `_run_tool` honour
`planner._ALLOWED`.** Every mission that runs today keeps dispatching exactly what it dispatches
today, because today's `active` already behaves as `full`. The operator who wants less can then
select `active` and actually get less. Nothing published moves.

> **RETRACTED 2026-08-16 -- see "The decision does not survive implementation" below. The
> "nothing moves" claim above is WRONG on two independent counts, both MEASURED. It is left in
> place, struck, because the correction is the result.**

### What moves if the decision goes the other way (narrow `active`)

Recorded so the option is priced, not so it is recommended:

- 7 engines stop running in the default mode; 49.5% of sweep dispatches disappear.
- `run_cmdi` is UNAFFECTED either way. Its zero dispatches in 151 missions are not a tier problem:
  nothing is tier-blocked in `active` today, and it is absent from the 8-entry
  `_SWEEP_HTTP_ENGINES` tuple that the planner will not supplement. Tuple membership is the gate.
  This confirms the ticket's own correction of the QUEUE text.
- Every whole-product benchmark artifact would need its reproduction line changed from
  `WP_MODE=active` to `WP_MODE=full` (`scripts/whole_product_rerun.py:91`,
  `docs/handoff/orchestration.md:998`). The artifacts stay VALID -- the runs happened, the numbers
  are what they were -- but their reproduction instructions would no longer reproduce them.

### The OWASP Benchmark harness does NOT need to declare `full`

The ticket asked whether it must. **It must not, because it does not declare a mode at all.**
MEASURED, `agent/owasp_bench.py` constructs a `ToolRegistry` directly and calls the engine method
by name:

```
owasp_bench.py:146   reg = tools_mod.ToolRegistry(sc, mission_id=None, lab_mode=True)
owasp_bench.py:197   res = await getattr(reg, method)(inp)
```

There is no `BBHAgent`, no `_run_tool`, no `mode`, and no `TOOL_PERMISSIONS` lookup anywhere on that
path. The OWASP Benchmark harness has never been subject to the permission gate, and no tier
decision can change a single dispatch it makes. Its scores are unaffected by any outcome here.

The whole-product harness is the one that IS affected: `scripts/whole_product_rerun.py:91` reads
`MODE = os.environ.get("WP_MODE", "active")` and passes it to `BBHAgent(mode=MODE, auto_approve=True)`
(line 333). That is the harness that produced wp1 and wp3.

---

## SLICE 4 -- the decision does not survive implementation, and I am not applying it

I was told to apply my own decision. I went to implement it, measured the two things it depends on,
and both were false. Recording the disproof instead, because landing it would have shipped a
regression I had just finished arguing against.

### Retraction 1 -- flipping the default does not reach any real mission

The "nothing moves" claim assumed missions rely on the Pydantic default. MEASURED, they do not.
`ui/index.html:340-344` is the mode selector:

```html
<option value="passive">Passive -- recon + playbook only</option>
<option value="active" selected>Active -- + scanning (1 approval gate)</option>
<option value="full">Full -- + deep probing (gated)</option>
```

and `ui/index.html:1327` sends `mode: document.getElementById("mode").value`. **Every UI-launched
mission sends `"active"` explicitly.** `main.py:56`'s default is never consulted on that path. So
changing the defaults and making `_run_tool` honour `_ALLOWED` would NOT be a no-op -- it would cut
49.5% of the sweep, and every SQLi check, from every mission launched from the product's own UI.
The fix would have to include `ui/index.html`, which nobody's file list mentioned.

### Retraction 2 -- `full` is not `active` plus INTRUSIVE

The recommendation assumed `full` is a superset differing only in permitted tiers. MEASURED, `full`
is differentiated by four ad-hoc checks that have nothing to do with the tier table:

```
main.py:566     lab_mode=(req.mode == "full")            -> ToolRegistry.lab_mode = True
agent.py:2169   if self.mode == "full" and pair:         -> the horizontal WRITE test
agent.py:2202   "allow_write": (self.mode == "full" or self.authenticated_scan)
planner.py:212  intrusive = 15 if mode == "full" else 0  -> planner intrusive budget
planner.py:230  nuclei_heavy ... and mode == "full"
```

`lab_mode` reaches `tools.py:6151` and changes how traversal probes are BUILT and how their verdicts
are ANALYSED (`ws.build_traversal_probes(..., lab_mode=lab)`, `ws.analyze_traversal_pair(...,
lab_mode=lab)`). So defaulting missions to `full` would turn lab-calibrated traversal semantics on
against production targets, and turn ON a state-changing horizontal write test.

**The consent fix would have enabled writes by default.** That is the exact trade the ticket was
written to prevent, arrived at from the opposite direction.

### What that leaves, and the premise it disproves

`full` and `active` ARE distinguishable in the product -- through those five checks -- just not in
`_run_tool`. The strict xfail's reason stays accurate as written because it says "at the dispatcher".

More importantly, the ticket's consent premise itself does not hold. It states that "an operator who
selects `active` expecting non-intrusive testing gets SQL, XPath and LDAP injection fired at their
application today". MEASURED by driving the real `_run_tool`, that is FALSE for an interactive run:

- `active` + `auto_approve=False` + an INTRUSIVE tool reaches `_await_gate`, which yields
  `approval_required` and BLOCKS the mission until the operator answers. The engine does not run.
- A denied gate never executes the engine.
- `_await_gate` sets `self.intrusive_state = self._approval_result or "denied"`, so a timeout is a
  REFUSAL. The gate is fail-closed.
- `auto_approve=True` skips the modal and says so ("Intrusive phase pre-authorized (autonomous
  run)"). That flag IS the operator's pre-authorisation, and it is what wp3 set.

So the 700 `run_sqli` dispatches in wp3 were consented to by `auto_approve=True`, not smuggled past
a broken tier check. And the mode selector's own label for `active` is "**+ scanning (1 approval
gate)**" -- one approval gate is precisely what `_run_tool` implements. The dispatcher matches the
product's operator-facing contract; `planner._ALLOWED` is the mechanism that contradicts it.

Note on my earlier measurement: `_dispatch_perms` sets `auto_approve = True`, so
"`active` admits INTRUSIVE" was measured under pre-authorisation. That qualification was missing
from the first version of this handoff and it matters.

Four characterisation tests now pin all of this (`test_active_mode_ASKS_before_running_an_intrusive_engine`,
`test_a_denied_gate_stops_the_intrusive_engine`, `test_an_autonomous_run_pre_authorises_and_says_so`).
They were GREEN on unmodified HEAD `a22ee43` -- they are not fix-driven tests, they record a
disproof and stop the behaviour from drifting.

### Revised recommendation

The evidence now points at **loosening `planner._ALLOWED["active"]` to include INTRUSIVE**, which
the ticket explicitly forbade as "deleting the honest half". I am not doing it unilaterally, but I
am obliged to report that the evidence no longer supports the planner being the honest half:

1. The UI contract for `active` is "scanning, 1 approval gate". The gate exists, is fail-closed, and
   is what `_run_tool` runs. The planner's table forbids what that contract promises.
2. `full`'s real meaning is carried by the five checks above, not by the tier table -- so the table
   is not what separates the modes today, and making it authoritative would change the modes'
   meanings rather than enforce them.
3. The planner's exclusion is the direct cause of the Q-050 coverage defect: `run_cmdi`,
   `run_web_probes`, `run_ssrf`, `run_nosqli`, `run_bfla` and `run_content_discovery` cannot be
   SCHEDULED in the default mode, which is why `run_cmdi` has 0 dispatches in 151 missions.
4. The INTRUSIVE tier is not a consent set anyway (`run_hash_crack` / `run_session_lifecycle`).

If the tier model is to be the consent mechanism, the ordering is: split the overloaded couplings
off `full` FIRST (lab_mode from an explicit lab flag, writes from an explicit write consent --
`authenticated_scan` already is one), THEN make the table authoritative, THEN move the default and
the UI's `selected` attribute in the same change. Doing step two alone is the 49.5% regression.

### Whole-product harness patch (scripts/ is the Coordinator's -- NOT edited)

If the default ever moves, `scripts/whole_product_rerun.py:91` must stop defaulting:

```python
# was: MODE = os.environ.get("WP_MODE", "active")
# A whole-product artifact is only comparable to fab8a46e / 951dc0a0 if its mode is RECORDED
# rather than inherited from a default that has since moved. Fail loudly instead.
MODE = os.environ.get("WP_MODE") or ""
if MODE not in ("passive", "active", "full"):
    raise SystemExit("WP_MODE must be set explicitly (passive|active|full) -- a whole-product "
                     "artifact inherits no default, or it stops being comparable to earlier seals.")
```

`docs/handoff/orchestration.md:998` carries the reproduction line `-e WP_MODE=active` and would need
the same treatment.

### Docstring vs registry disagreements -- their own ticket, on the record

Four engines' docstrings contradict their own `TOOL_PERMISSIONS` entry. This is the
declaration-vs-fact defect written in prose: the docstring is the declaration an engineer reads, the
registry is the fact the gate enforces.

| engine | docstring says | registry says |
|---|---|---|
| `confirm_authz_write` | ACTIVE | INTRUSIVE |
| `confirm_create_object_idor` | ACTIVE | INTRUSIVE |
| `run_external_surface` | PASSIVE | ACTIVE |
| `run_param_mine` | ACTIVE | INTRUSIVE |

`run_external_surface` is the one to look at first: it is declared PASSIVE, registered ACTIVE, and
has NO dispatch site at all (below), so all three of its facts disagree.

---

## SLICE 2b -- a third consequence, found while measuring, NOT fixed (not my file)

`report.arsenal_gap()` computes a `blocked_by_mode` list and `_arsenal_md()` renders it as
"**Of those, unable to run at this permission tier**". MEASURED, that line has never appeared in a
real report, and if it did it would be wrong.

```
report.py:1641   mode = str((ledger or {}).get("strategy") or (ledger or {}).get("mode") or "").lower()
main.py:1001-4   return {"tools": ..., "zap_status": ..., "authenticated": ...,
                          "strategy": ex.get("strategy") or ctx.get("strategy") or "",
                          "ai_calls": ...}
```

The real `tool_ledger` has **no `mode` key**, and its `strategy` value is
`deterministic` / `agentic` / `low_ai` -- never a mode. MEASURED against the exact dict
`main._tool_ledger` returns:

```
REAL ledger shape  -> blocked_by_mode = [] | not_dispatched = 113
   run_cmdi classified as: not_dispatched
TEST fixture shape -> blocked_by_mode = 42 engines; run_cmdi in it: True
strategy+mode      -> blocked_by_mode = 0 (strategy is read FIRST, so mode is ignored)
_ALLOWED.get('deterministic') = None
rendered section contains the tier line: False
```

Three findings in one:

1. `_ALLOWED.get("deterministic")` is `None`, so `allowed` is `None`, so `blocked_by_mode` is
   unconditionally `[]` in every real mission. The feature is dead on arrival.
2. `test_arsenal_gap.py:18` builds its fixture as `{"strategy": "active", ...}` -- it puts the MODE
   string into the STRATEGY key. That shape is not produced anywhere in the product. The three tier
   tests in that file are green only against data no ledger has ever contained. This is the
   project's own "guard that checks a declaration" shape: the test passes and the behaviour it
   asserts has never occurred.
3. Adding a `mode` key to the ledger would NOT fix it, because `strategy or mode` reads `strategy`
   first and `strategy` is always truthy. The fix is two-part.

**Suggested patch, for whoever owns `report.py` and `main.py` (NOT this lane):**

```python
# main.py:1001 -- carry the mission's MODE, which the ledger currently does not record at all
return {"tools": tools, "zap_status": zap,
        "authenticated": bool(ctx.get("authenticated")),
        "mode": (m or {}).get("mode") or ctx.get("mode") or "",
        "strategy": ex.get("strategy") or ctx.get("strategy") or "",
        "ai_calls": ex.get("ai_calls", 0)}

# report.py:1641 -- read the mode key, and NEVER the strategy key. `strategy` is
# deterministic/agentic/low_ai; it has never been a mode, and reading it first is what
# made `blocked_by_mode` unconditionally empty.
mode = str((ledger or {}).get("mode") or "").lower()
```

and `test_arsenal_gap.py`'s `_ledger()` helper must move its mode string from the `strategy` key to
a `mode` key, or the tests will keep passing on a shape the product does not produce.

**Do not apply that patch before the tier decision lands.** Today the dispatcher ignores the tier,
so a working `blocked_by_mode` would print "unable to run at this permission tier" next to engines
that `_run_tool` would happily have run. Fixing the plumbing before the semantics would replace a
silent falsehood with a loud one.

---

## Q-050 part (b) -- selection gaps, DIAGNOSED (not fixed)

Method: for each named engine, search every non-test module for the name appearing in a dispatching
construct (`_run_tool("x"`, `_exec_internal("x"`, `planner._step("x"`, a sweep tuple, or a
declarative pack entry). An engine whose only references are its `TOOL_PERMISSIONS` row and its
`CLAUDE_TOOLS` schema has no dispatch site: nothing in the product can ever call it except the model
choosing it by name in agentic mode.

The three causes the ticket asked me to separate are all present, and they are three different
repairs.

### Cause A -- NO DISPATCH SITE AT ALL (islands). 6 engines.

Registry row + tool schema and nothing else. These cannot be selected because there is no selector.

| engine | tier | only references |
|---|---|---|
| `run_external_surface` | ACTIVE | `tools.py:220` registry, `tools.py:461` schema |
| `run_dirsearch` | INTRUSIVE | `tools.py:206` registry, `tools.py:938` schema |
| `run_ferox` | INTRUSIVE | `tools.py:205` registry, `tools.py:934` schema |
| `run_gobuster` | INTRUSIVE | `tools.py:207` registry, `tools.py:942` schema |
| `run_metadata` | ACTIVE | `tools.py:203` registry, `tools.py:920` schema (+ a name-list at `agent.py:103`) |
| `run_workflow` | INTRUSIVE | `tools.py:234` registry, `tools.py:1058` schema |

`run_external_surface` is confirmed still a pure island, matching the Coordinator's recollection.
The dirsearch/ferox/gobuster trio are three adapters for one capability (directory brute force) and
none of the three is wired -- so the gap is one capability, not three engines.

`run_metadata`'s `agent.py:103` mention is a membership list, not a call. Naming an engine in a list
is the declaration; having a dispatch site is the fact.

**Second-order island:** `enumerate_ids` (INTRUSIVE) IS reachable -- but only through
`workflow.py:18`'s handler map, which is only driven by `run_workflow`, which is itself an island.
It is reachable from an unreachable thing, so it never runs. A reachability gate that treats
"referenced by some dispatcher" as reachable would pass it; that is the shape this project calls a
guard checking a declaration.

### Cause B -- DISPATCH SITE EXISTS, PRECONDITION NEVER SATISFIED. 4 engines.

These are correctly wired. They do not run because their guard is rarely or never true. This is a
precondition problem and a coverage question, NOT a permission or ranking one.

| engine | dispatch site | precondition |
|---|---|---|
| `run_jwt` | `planner.py:645` `_step("run_jwt", {"token": ...})` | a JWT must have been OBSERVED (regex match); no token, no step |
| `run_default_creds` | `agent.py:3524` sweep | `default_creds_tool.match(path)` -- only a recognised Tomcat Manager / JBoss jmx-console path |
| `run_saml` | `agent.py:2424` `_exec_internal` | SAML URLs present |
| `run_session_lifecycle` | `agent.py:1905` `_exec_internal` | `agent.py:1900`: `if not self.authenticated_scan or self.mode == "passive": return` |

`run_default_creds` is the clearest: its guard is a two-product allowlist, so on any target that is
not Tomcat or JBoss it correctly never fires. That is not a defect, and "wire it harder" would be
wrong. `run_session_lifecycle` requires an authenticated scan by design -- it mints a sacrificial
account, so gating it behind explicit auth opt-in is correct.

### Cause C -- planner ranking. 0 engines found.

No engine in the named list is blocked by ranking or budget. I looked for it and did not find it;
recording the negative result so the next lane does not re-search the same ground.

### `run_jsonp` -- reclassified

The ticket listed it as never-selected. MEASURED, it HAS a dispatch site (`agent.py:969`, the
candidate-validation pipeline) and it DOES run -- the defect was that it ran through the UNGATED
`self.tools.execute`, including in passive mode. Fixed in slice 3 (`2707caa`). It belongs to the
consent ticket, not the selection one.

### What the repairs are, and what they are NOT

Three different repairs, and the constraint carried forward from the Coordinator applies to all of
them: do NOT fix any of this by adding engines to `_SWEEP_HTTP_ENGINES`. wp1 measured what an
unproven engine on the always-on path costs -- a false positive that took two days and three dead
hypotheses to explain.

- **Cause A (islands)** needs a dispatch site with a real precondition, engine by engine, each with
  the evidence that the engine's oracle is sound enough to be trusted first. The trio also needs a
  product decision: one directory-brute-force capability with three interchangeable adapters wants a
  single selection point that picks whichever binary is installed, not three separate wirings.
- **Cause B** needs no code change. It needs the report to distinguish "precondition not met" from
  "never dispatched", which is `arsenal_gap`'s job and which is broken for an unrelated reason
  (slice 2b).
- **`enumerate_ids`** is fixed by whatever fixes `run_workflow`; it should not be wired separately.

**Unblocking note:** all six Cause-A repairs need a dispatch site in `agent.py` or `planner.py`,
which are this lane's files, but each also needs an oracle-soundness argument that this lane has not
made and cannot make from static reading alone. Landing six new always-on dispatch sites on that
basis is precisely the wp1 mistake. They are diagnosed and left for a lane that can measure each
engine against a lab.
