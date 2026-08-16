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
select `active` and actually get less. Nothing published moves. This converts a silent
misrepresentation into an explicit default, which is the whole of the consent defect.

`main.py` and `agent.py:377/415` -- the default-mode literals -- are the Coordinator's and mine
respectively; I have not changed either, because the choice of default is the product decision this
handoff exists to hand back.

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

## Q-050 part (b) -- selection gaps

NOT STARTED. Slice 2 consumed the available budget. The diagnosis question is stated in the ticket
(preconditions never satisfied vs planner ranking vs no dispatch site at all) and is unanswered here.
One fact already collected that bears on it: `run_external_surface` is registered ACTIVE while its
own docstring declares PASSIVE, which is a tier/declaration disagreement independent of whether it
has a dispatch site.

Constraint carried forward from the Coordinator: do NOT fix any of this by adding engines to
`_SWEEP_HTTP_ENGINES`. wp1 measured that cost.
