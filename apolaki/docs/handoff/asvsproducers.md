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

## 4. Status

- [x] Producer map built from source with `ast`, two analyser defects found and fixed
- [x] Baseline tally measured (verified 27/33, 81.8%)
- [x] 6 never-fail objectives + 16 dead engine/objective pairs identified with evidence
- [ ] Repairs
- [ ] Ratchet test
- [ ] Full regression
