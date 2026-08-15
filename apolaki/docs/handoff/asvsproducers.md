# Q-048 - ASVS objectives that are structurally incapable of failing

Lane: ASVSPRODUCERS BUILDER. Owns `agent/asvs_model.py`, `agent/tests/test_asvs_model.py`, this file.

Every claim below is MEASURED (command + real output) or marked UNVERIFIED.

The defect: `assess()` records `verified` when an objective's engine ran and no finding in its
`violated_by` set exists. That inference is sound ONLY if the engine can actually EMIT one of those
families. Where it cannot, the objective reads `verified` in every possible run and the model asserts
a property nothing tested.

---

## 1. Method - the producer map is derived from SOURCE, never hand-listed

`scripts` used for the measurement live in the lane scratchpad; the shipped form is
`_family_producers()` in `agent/tests/test_asvs_model.py`. It walks every non-test `.py` in
`agent/` with `ast` and computes, per function/method, the set of `family` string values it can emit,
then closes that over the call graph so an engine method inherits the families of the helpers it calls.

A hardcoded allowlist of "which engine emits what" would be the same declaration-vs-fact defect one
level up, which is the whole point of this ticket.

Family literals are recognised in the four forms the tree actually uses:

* `{"family": "xss"}` dict literal (incl. a NAME bound to a literal, module- or function-level)
* `f(..., family="xss")` keyword
* `d["family"] = "xss"` subscript assign, and `d.setdefault("family", "xss")`
* a literal passed POSITIONALLY into a callee parameter named `family`

Call-graph edges resolve `import x as y` (including imports written INSIDE a function, which is how
`tools.py` imports nearly every helper), `from x import f`, and `self._method(...)` within a class.

### 1a. Two analyser defects I had to fix before the map could be trusted (MEASURED)

Both made the map UNDER-report, which is the dangerous direction: it invents never-fail objectives
that are actually fine.

1. **Ternary family expressions.** `transport_posture.py:397` is
   `"family": "transport_posture" if kind in ("tls", "cert") else "security_misconfig"`.
   Reading only `ast.Constant` reported **0 families** for `run_transport_posture`, an engine that
   emits two. Fixed by resolving `ast.IfExp` and `or`-chains to the union of their branches.

2. **Inter-procedural family arguments.** `dom_tool` builds every DOM finding through
   `_base(url, title, sev, desc, evidence, family, cwe, ...)` with the family as a POSITIONAL literal;
   inside `_base` the dict literal is `{"family": family}`, which is dynamic. Reading only the dict
   literal reported **0 families** for `run_dom_audit` - an engine whose docstring says it confirms
   prototype pollution, DOM XSS, DOM open redirect and CSTI. Fixed by propagating literal arguments
   into a callee parameter named `family` (plus one hop of `fam = returns_a_literal()`).

**This disproved one of my own earlier findings.** Before fix 2 the map listed VAL-08
(prototype pollution) as never-failable. It is not: `run_dom_audit` emits `prototype_pollution`.
VAL-08 is a dead-ENGINE case only (see 3b), not a never-fail objective.

Vacuity check on the map (MEASURED): 182 modules parsed, 93 distinct family literals, fixpoint in 4
rounds, and **0 engine methods** have an unresolved (dynamic) family expression - so the map is not
silently under-reporting at the engine layer.

---

## 2. Baseline before any change (MEASURED)

```
MSYS_NO_PATHCONV=1 docker run --rm -v ".../apolaki/agent:/app" -w /app apolaki-agent \
  python /scratch/tally.py
```

```
PERFECT-RUN tally: {'verified': 27, 'attempted': 2, 'failed': 0, 'not_tested': 0,
                    'not_applicable': 0, 'blocked': 2, 'not_implemented': 2}
verified_pct: 81.8  total: 33
```

---

## 3. THE MEASUREMENT

### 3a. Objectives that can NEVER FAIL - 6 of the 27 "verified"

No engine named by the objective can emit any family in its `violated_by`. Each of these reads
`verified` on a perfect run while nothing in the product could contradict it.

| cid | violated_by (declared) | engines named | what those engines ACTUALLY emit |
|---|---|---|---|
| AUTHN-01 | `default_creds` | `run_default_creds` | `default_credentials` |
| AUTHN-02 | `auth_bypass`, `broken_auth` | `run_auth_sqli`, `run_authz_matrix` | `sqli` / `excessive_data_exposure`, `idor` |
| AUTHN-03 | `username_enum` | `run_username_enum` | `username_enumeration` |
| SESS-01 | `weak_session`, `predictable_token` | `run_session_token` | `weak_session_token` |
| SESS-02 | `cookie_flags` | `run_transport_posture`, `run_encoded_cookie` | `security_misconfig`, `transport_posture` / `base64_param` |
| COMM-04 | `takeover` | `check_takeover` | nothing at all |

Four of the six are NEAR-MISS NAMES: the objective names a family that reads correctly in English but
is not the string the producer emits (`default_creds` vs `default_credentials`, `username_enum` vs
`username_enumeration`, `weak_session` vs `weak_session_token`, `cookie_flags` vs `insecure_cookie`).
These are worse than a phantom engine: a REAL finding, produced by the RIGHT engine on a genuinely
vulnerable target, fails to map, and the objective still reads verified.

Every family named in some objective's `violated_by` that has ZERO producers anywhere in the non-test
tree (MEASURED):

```
auth_bypass  broken_access_control  cleartext_transport  cookie_flags  default_creds
information_disclosure  ldap  nosql_injection  predictable_token  privilege_escalation
takeover  username_enum  weak_session  xpath
```

14 of the ~50 families the model can fail on are strings nothing in the product ever emits. Several are
harmless (a dead alias sitting beside a live sibling - `ldap` next to a live `ldap_injection`... except
`ldap_injection` is NOT in VAL-07's set, see 3b). The six in the table above are the ones where the dead
string is the ONLY thing that could fail the objective.

`mass_assignment` is NOT in that list any more: `mass_assign_tool.py` exists and emits it
(`mass_assign_tool.py:502,559`). There is still no `_run_mass_assignment` method in `tools.py`, so no
engine reaches it - the massassign lane's engine has not landed yet. ATHZ-04 stays `not_implemented`
and untouched by this lane (see 6).

`COMM-04` is a different shape from the other five: `_check_takeover` (`tools.py:5669`) returns
`dns_recon.match_takeover()` candidate dicts, which carry `subdomain`/`service`/`cname`/`severity`/
`reason` and **no `family` key at all** (`dns_recon.py`). They are appended to
`self.recon["takeover_candidates"]`, never to findings. So no takeover violation can exist as a
finding, by construction.

### 3b. Dead ENGINES - 16 pairs across 14 objectives

`assess()` marks an objective verified when **ANY** named engine ran (`_engine_ran` is `any(...)`).
So an engine that cannot emit a violating family is, on its own, a false-verify path even when a
SIBLING engine in the same tuple is fine. The 6 above are the subset where EVERY engine is dead.

```
  AUTHN-01  run_default_creds        emits=['default_credentials']
  AUTHN-02  run_auth_sqli            emits=['sqli']
  AUTHN-02  run_authz_matrix         emits=['excessive_data_exposure', 'idor']
  AUTHN-03  run_username_enum        emits=['username_enumeration']
  SESS-01   run_session_token        emits=['weak_session_token']
  SESS-02   run_transport_posture    emits=['security_misconfig', 'transport_posture']
  SESS-02   run_encoded_cookie       emits=['base64_param']
  ATHZ-03   run_content_discovery    emits=['exposure']
  VAL-03    run_dalfox               emits=[]
  VAL-07    run_ldap                 emits=['ldap_injection']
  VAL-08    run_injection_probes     emits=['cors','crlf','host_header','open_redirect','ssti']
  VAL-09    run_web_probes           emits=['http_methods','idor','idor_path','idor_query',
                                            'insecure_cookie','path_traversal','weak_random']
  CONF-01   run_fingerprint          emits=['fingerprint']
  COMM-02   run_client_checks        emits=['permissive_crossdomain','reverse_tabnabbing']
  COMM-04   check_takeover           emits=[]
  BUSL-01   run_workflow             emits=[]
```

`run_dalfox` emits nothing because `_run_dalfox` appends raw dalfox JSON lines as findings, with no
`family` key. `run_workflow` returns `ToolResult(..., [])` by design - its docstring says confirmed
findings come from the `confirm_*` steps inside it.

### 3c. The ticket's two instances, checked

* **SESS-02 - CONFIRMED never-fail.** The detail differs from the brief: the brief says it reads
  verified "purely because `run_encoded_cookie` ran", but BOTH of its engines are dead for it. The
  brief is also right that cookie hardening is genuinely tested, and I found a second tester it did
  not mention: `cookie_flags.py` emits family **`insecure_cookie`** (CWE-614, Secure attribute on
  session-ish cookies) and is called from `_run_web_probes` (`tools.py:5781`). So cookie hardening has
  TWO real producers, `run_web_probes` -> `insecure_cookie` and `run_transport_posture` ->
  `security_misconfig`, and `cookie_flags` is not one of them.

* **CONF-01 - PARTLY DISPROVEN.** `run_fingerprint` is indeed a dead engine (emits `fingerprint`
  only), so the pair is a false-verify path. But the OBJECTIVE can fail: `run_js_review` is already in
  its engine tuple, added by Q-012, and it emits `vulnerable_component`. The repair the brief asks for
  ("CONF-01 -> add `run_js_review`") was already made yesterday. What remains is the dead sibling.

---

## 4. A third analyser defect, found while repairing (MEASURED)

Over-attribution, this time - the direction that makes the ratchet WEAKER by letting a dead engine look
live. `browser_navigate` appeared to produce `broken_auth`. Traced:

```
browser_navigate -> broken_auth   tools.ToolRegistry._browser_navigate => saml_tool.*
```

`_browser_navigate` does not mention SAML anywhere. The cause: `tools.py` binds
`import saml_tool as st` INSIDE `_run_saml` (tools.py:2347), and the alias map was collected by walking
the whole module tree, so that function-local binding leaked into every other method - any unrelated
method with a local `st` variable calling `st.foo()` resolved to `saml_tool` and inherited its families.
Fixed by scoping module aliases to module-level statements only (`_module_level_imports`), with
per-function imports gathered per function.

Negative control after the fix: **no objective verdict changed**. All repairs already made were valid
under the stricter map, so none of them depended on the over-attribution.

---

## 5. Repairs - what was done to each of the 6, and why

Three legitimate outcomes were available per objective. Which one applies was decided by measurement,
not preference.

| cid | outcome | what changed | why this one |
|---|---|---|---|
| AUTHN-01 | re-point `violated_by` | `default_creds` -> `default_credentials` | same property exactly; the string was simply wrong |
| AUTHN-03 | re-point `violated_by` | `username_enum` -> `username_enumeration` | same property exactly |
| SESS-01 | re-point `violated_by` | `weak_session`,`predictable_token` -> `weak_session_token` | same property exactly |
| SESS-02 | re-point BOTH | engine -> `run_web_probes`; family -> `insecure_cookie`; summary narrowed | the only cookie weakness that becomes a distinguishable finding is CWE-614 |
| AUTHN-02 | re-point engine | -> `run_saml` (dropped `run_auth_sqli`, `run_authz_matrix`) | `run_saml` is the one dispatchable engine emitting `broken_auth` |
| COMM-04 | declare unverifiable | `NO_ENGINE` + `not_implemented_reason` | takeover candidates carry no family and never become findings |

Mirror-defect check on every re-pointed family (MEASURED - engines able to emit it):

```
default_credentials    ['run_default_creds']       username_enumeration  ['run_username_enum']
weak_session_token     ['run_session_token']       insecure_cookie       ['run_web_probes']
ldap_injection         ['run_ldap']                permissive_crossdomain['run_client_checks']
mass_assignment        ['run_mass_assign']
```

Every one has exactly ONE producing engine - the same engine the objective names - so none of these can
now fail spuriously from an unrelated engine.

**Two candidate families were REJECTED for exactly that spurious-FAIL risk:**

* `security_misconfig` for SESS-02. transport_posture really does emit it for its cookie checks, but the
  family is chosen by `"transport_posture" if kind in ("tls","cert") else "security_misconfig"`
  (transport_posture.py:397) and `kind` is also `"header"` and `"methods"`. A missing security header or
  a permitted TRACE would then FAIL "session cookies carry Secure". Consequence, stated plainly: the
  SESS-02 summary was NARROWED from "Secure/HttpOnly/SameSite" to "Secure (CWE-614)", because
  HttpOnly/SameSite are tested but not separably failable. Patch to widen it back is in section 8.
* `sqli` for AUTHN-02. `run_auth_sqli` genuinely CONFIRMS full authentication bypass, but shapes it
  through `sqli_tool._base`, which stamps `"family": "sqli"` on every SQLi alike. Adding `sqli` here
  would make every SQLi from `run_sqli`/`run_path_sqli`/`run_graphql` fail "authentication cannot be
  bypassed". `auth_bypass` is KEPT in `violated_by` with no producer today, because it is the family the
  section-8 patch would introduce.

### ATHZ-04 - a correction to the brief, twice over

Both the original ticket and the resume message told me "ATHZ-04 currently names `run_mass_assignment`".
It did not: it carried `NO_ENGINE` + `not_implemented_reason`. What HAS changed is that Q-011 shipped the
engine under a different name, `run_mass_assign` (tools.py:5790, TOOL_PERMISSIONS:107, CLAUDE_TOOLS:515),
and it emits `mass_assignment` via `mass_assign_tool`. ATHZ-04 now names it and is verifiable again.

Recorded honestly: this asserts STRUCTURAL producibility only - the engine can emit the family that
fails the objective. It is NOT a claim of live-validated detection capability; that belongs in
`validated_on`.

---

## 6. The 16 dead engine/objective pairs - repair now, or file a ticket?

The split the Coordinator asked for. **12 were model errors and are repaired. 4 are real product
capability gaps** - the model is now honest about them, but the underlying hole is still there and
should be its own ticket.

### Repaired now - the model was wrong, the product is fine (12)

| pair | fix |
|---|---|
| AUTHN-01/`run_default_creds` | family re-point |
| AUTHN-03/`run_username_enum` | family re-point |
| SESS-01/`run_session_token` | family re-point |
| VAL-07/`run_ldap` | added `ldap_injection` |
| COMM-02/`run_client_checks` | added `permissive_crossdomain`, summary broadened |
| AUTHN-02/`run_authz_matrix` | engine dropped - emits `idor`/`excessive_data_exposure`, which are AUTHORIZATION failures, wrong property |
| SESS-02/`run_encoded_cookie` | engine dropped - emits `base64_param`, unrelated property |
| ATHZ-03/`run_content_discovery` | engine dropped - discovers content, does not test traversal |
| VAL-08/`run_injection_probes` | engine dropped, `run_js_review` added |
| VAL-09/`run_web_probes` | engine dropped - emits seven families, none `crlf` |
| CONF-01/`run_fingerprint` | engine dropped - emits `fingerprint` only |
| BUSL-01/`run_workflow` | engine dropped - returns `ToolResult(..., [])` BY DESIGN; findings come from the `confirm_*` steps inside the pack, so this is correct behaviour, not a gap |

### Real capability gaps - file these (4)

**GAP-1 (COMM-04) - subdomain takeover is detected but can never be reported.**
`_check_takeover` (tools.py:5669) finds dangling CNAMEs, but `dns_recon.match_takeover` returns candidate
dicts with no `family` key; they go to `self.recon["takeover_candidates"]`, whose only consumer is
`guidance.py:629`. A confirmed takeover cannot become a finding. Model now says `not_implemented`.

**GAP-2 (VAL-03) - dalfox findings have no family at all.**
`_run_dalfox` appends raw dalfox JSON lines as findings. With no `family` key they map to NO objective
and are invisible to `map_findings` entirely - not just for VAL-03. Worth checking whether they reach
the findings pipeline at all.

**GAP-3 (AUTHN-02) - a confirmed authentication bypass is labelled as generic SQLi.**
`sqli_tool.auth_bypass_finding` ("sign in as any user without credentials") is built through
`sqli_tool._base`, which sets `"family": "sqli"`. The distinction survives only in `tags`. So the single
most severe outcome the SQLi engine can produce is, by family, indistinguishable from a reflected error
in a search box.

**GAP-4 (SESS-02) - cookie hardening findings share a family with unrelated misconfigs.**
`transport_posture.finding` gives cookie, header and methods issues all the same `security_misconfig`
family, so HttpOnly/SameSite failures cannot fail a cookie objective without also letting a missing
header do it.

---

## 7. Tally, before and after (MEASURED, against an isolated `git archive HEAD` snapshot)

```
BEFORE  {'verified': 27, 'attempted': 2, 'failed': 0, 'not_tested': 0,
         'not_applicable': 0, 'blocked': 2, 'not_implemented': 2}   verified_pct 81.8
AFTER   {'verified': 27, 'attempted': 2, 'failed': 0, 'not_tested': 0,
         'not_applicable': 0, 'blocked': 2, 'not_implemented': 2}   verified_pct 81.8
```

The two tallies are byte-identical.

**The headline number did not move, and that is a coincidence, not a success.** Two objectives swapped
places and cancelled out:

* COMM-04 left `verified` for `not_implemented` (nothing can record a takeover violation) - **worse, and
  correctly worse**.
* ATHZ-04 left `not_implemented` for `verified` (Q-011 shipped `run_mass_assign`) - better, for a reason
  that has nothing to do with this ticket.

The real change is invisible in the tally and is the point of the work: **6 of the 27 "verified" were
previously incapable of failing.** After the repairs, 26 of the 27 can be contradicted by a finding a
real engine can actually emit, and the 27th (ATHZ-04) is structurally capable but not yet live-validated.
Dropping six dead engines did NOT lower the perfect-run count, because a perfect run also runs the
surviving live engine; what it removes is the PARTIAL run in which only the dead engine fired.

---

## 8. Patches handed off (files this lane does not own)

1. `dns_recon.py` / `tools.py` - promote takeover candidates to findings with `"family": "takeover"`
   (GAP-1). Then COMM-04 flips from `not_implemented` back to verifiable, and its `violated_by` already
   names the right family.
2. `tools.py` `_run_dalfox` - stamp a family (`xss`) on parsed dalfox results, or route them through an
   existing XSS finding builder (GAP-2). Then `run_dalfox` can return to VAL-03's engine tuple.
3. `sqli_tool.py` - give `auth_bypass_finding` its own family (`auth_bypass`) instead of inheriting
   `sqli` from `_base` (GAP-3). AUTHN-02 already lists `auth_bypass` in `violated_by` in anticipation, and
   `run_auth_sqli` can then rejoin its engine tuple.
4. `transport_posture.py` - give the `kind == "cookie"` branch its own family, e.g. `insecure_cookie`,
   rather than the shared `security_misconfig` (GAP-4). Then SESS-02's summary can be widened back to
   Secure/HttpOnly/SameSite and `run_transport_posture` can rejoin its engine tuple.

No change is needed in `report.coverage_rollup`: the status vocabulary is unchanged, and it already
buckets `not_implemented`. COMM-04 simply moves between existing buckets.

---

## 9. The generalisation - a seventh instance of one shape

The Coordinator counts six instances across lanes of *a guard that checks a declaration rather than a
fact*. Q-048 is not a seventh instance so much as evidence about where the shape hides, and the sharpest
version of it I have:

> **Q-012 fixed the declaration and left the fact untouched.** It proved every engine name could RUN.
> It never asked whether the engine could FAIL. SESS-02 was *touched by that repair* - its engine was
> re-pointed - and came out of it still incapable of failing, because `cookie_flags` had no producer.
> A repair that upgrades a declaration from "wrong" to "right" can leave the underlying property
> completely unverified, and the green test that guards it will say the repair worked.

The transferable rule, which is what a future lane should apply rather than the specific fix:

**For any assertion of the form "X passed because check C ran clean", the test that guards it must
verify C is CAPABLE OF FAILING - derived from source, not declared in a table.** Reachability is not
capability. "The engine is dispatchable" (Q-012), "the technique names a lab" (validated_on lane), and
"the objective names a family" (Q-048) are all declarations; "the engine can emit a family that
contradicts this objective" is a fact, and only the fact makes a clean run evidence.

The corollary that cost me the most time here: **an analyser that computes the fact can itself
under-report and manufacture false defects.** Three analyser bugs (ternary families, positional `family`
arguments, module-wide alias leakage) each changed the answer, and one of them made me briefly report
VAL-08 as unfailable when it is not. A negative control on the analyser - assert it resolves the hard
known cases - is now part of the ratchet (`test_the_producer_map_is_not_vacuous`).

---

## 10. Status

- [x] Producer map built from source with `ast`; THREE analyser defects found and fixed
- [x] Baseline tally measured (verified 27/33, 81.8%)
- [x] 6 never-fail objectives + 16 dead engine/objective pairs identified with evidence
- [x] All 6 never-fail objectives repaired; all 16 pairs resolved or classified as gaps
- [x] Ratchet tests: fail before the fix (16 pairs / 6 objectives), pass after
- [x] Mutation tested TWICE with the mutation verified applied first: a reverted family re-point, and a
      NEW objective with an invented family - both killed by both ratchets
- [x] Full regression green (2552 passed, 11 skipped, 9 xfailed, 0 failed - run by the Coordinator with
      these changes in the tree); `tests/test_asvs_model.py` 22 passed against an isolated HEAD snapshot
- [x] 4 capability gaps written up as ticket candidates with patches (section 6, 8)
