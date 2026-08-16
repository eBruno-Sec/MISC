# Q-053 GAP-3 / GAP-4 - families builder lane

`family` was assigned per-MODULE rather than per-FINDING, so one engine that proves three
different properties emitted one label. Two instances, measured by the Q-048 lane; this lane
fixes them where the finding is BUILT, from what the oracle actually proved.

Owned files: `agent/sqli_tool.py`, `agent/transport_posture.py`, their tests, this document.
`asvs_model.py`, `proof_schema.py`, `tools.py`, `agent.py`, `planner.py` belong to other lanes -
patches for them are handed off below, never applied here.

Every claim is MEASURED (command + real output) or UNVERIFIED.

---

## GAP-3 - a confirmed AUTHENTICATION BYPASS was labelled `sqli`  [LANDED 7ce79bb]

### Reproduced (MEASURED, clean HEAD snapshot, before the fix)

    docker run --rm -v <snap>/agent:/app -w /app apolaki-agent python probe1.py

    family      : sqli
    cwe         : CWE-89
    evidence    : session/JWT token issued for an invalid credential via email="' OR 1=1--"
    proof family: sql_injection
    validate    : (False, ['evidence_signal:union'])
    asvs map    : {'VAL-01': ['finding-0']}
       AUTHN-02 not_tested []
       VAL-01 failed ['finding-0']

The reported defect is confirmed exactly as the Q-048 lane described: a confirmed full
authentication bypass carried `family: "sqli"`, failed VAL-01 (an ordinary-SQLi objective), and
left AUTHN-02 unfailable.

### A SECOND defect found while reproducing it (MEASURED, not previously reported)

`proof_schema.validate_confirmed` **rejected the finding's own `confirmed` label**:
`(False, ['evidence_signal:union'])`. Because the family said `sqli`, `family_of` routed it to the
`sql_injection` proof rule, whose first signal group is
`["union","extracted","sql","sqlstate","ora-","syntax","database"]`. The evidence string
(`"<signal> via <field>=<payload>"`) carries none of them - it has no request, no verb and no
outcome. So the mislabel was not only mis-routing the finding for ASVS, it was failing the proof
gate for the wrong reason: the finding was being judged against an oracle it never ran.

Fixed in the same change by making the evidence a REPLAYABLE EXCHANGE, which is what
`proof_schema`'s own docstring asks of a confirmed finding:

    POST http://localhost:3000/rest/user/login  email="' OR 1=1--"  ->  session/JWT token issued for an invalid credential

### What the finding now emits (MEASURED, from a real emitted record at HEAD)

    family     'auth_bypass'      len 11   hex 617574685f627970617373
                                  ascii True | lower True | no surrounding whitespace
    cwe        'CWE-89'           (unchanged - the MECHANISM really is SQL injection)
    tags       ['sqli', 'auth-bypass']   (unchanged)
    severity   'critical'         confidence 'confirmed'

CWE-89 and the `sqli` tag were KEPT deliberately. They are what the CWE-keyed and tag-keyed
consumers resolve through, so those consumers do not degrade (table below).

### Consumers checked, and what each expects

Swept every `family` literal assigned anywhere outside `tests/` (script: a regex over
`"family": "..."`, `["family"] = "..."`, `family="..."`), then read each consumer.

| Consumer | Keys on | Expects | Effect of the change |
|---|---|---|---|
| `asvs_model.map_findings` | family ONLY (never engine) | `auth_bypass` for AUTHN-02, `sqli` for VAL-01 | INTENDED: AUTHN-02 now failable, VAL-01 no longer wrongly failed |
| `proof_schema.family_of` | family (CWE-522 special-cased) | `auth_bypass` is unmapped -> `_DEFAULT` rule | Was FAILING under `sql_injection`; now PASSES. Patch below makes the rule stricter than `_DEFAULT` |
| `benchmark._canon_class` | family, then CWE fallback | `auth_bypass` not in `_CLASS_MAP` -> falls back to `cwe-89` -> `sqli` | UNCHANGED (CWE-89 retained) |
| `remediation.remediation_for` | `key` + `tags`, NOT family | hint `sqli` in tags | UNCHANGED (tag retained) |
| `main.py:937` | `family == "sqli" OR "cwe-89" in cwe` | either | UNCHANGED (CWE-89 retained) |
| `owasp_bench.FAMILIES["sqli"]` | family, `{"sqli","sql_injection","blind_sqli"}` | would NOT credit `auth_bypass` | NOT REACHABLE - see benchmark note |
| `asset_graph` observations (:387) | family | `sqli` -> `sql_error_seen` | DEGRADES - patch handed off |
| `asset_graph._FINDING_ENABLES` (:545) | family | `sqli` -> `database_read` | DEGRADES - patch handed off |
| `attack_chain._ALIAS` (:25) | family | canonicalises `sql_injection`->`sqli` | DEGRADES - patch handed off |
| `defense_mapping` (:182) | family | `sqli` control set | DEGRADES - patch handed off |
| `remediation_depth` (:40) | family key `sqli` | depth guidance | DEGRADES - patch handed off |

The five DEGRADES are all the same shape: an additive one-line map entry, not a re-pointing. They
are listed as handoffs because those files are not this lane's to write. None of them is a
correctness regression in the finding itself - they are advisory/planner enrichment that loses a
`sqli` lineage entry.

### Benchmark classification - does a published number move?  NO (MEASURED)

`owasp_bench.FAMILIES["sqli"]` does not contain `auth_bypass`, so IF the OWASP Benchmark lane
could emit this finding on a `sqli` case, that case would stop being credited and the published
TPR would drop. It cannot:

- `auth_bypass_finding` is called from exactly ONE place in the tree - `tools.py:7414`, inside
  `_run_auth_sqli` (grep over `agent/`, 1 hit).
- `owasp_bench` dispatches category `sqli` to `_run_sqli` (`tools.py:6992`), a DIFFERENT method.
  `_run_sqli` never calls `auth_bypass_finding`.

So no OWASP Benchmark case can produce an `auth_bypass` finding, and no published Benchmark number
moves. UNVERIFIED: whether any GinAndJuice blind-recall or Juice Shop scoreboard row is scored
through a family set that lists `sqli` - those scorers were not re-run by this lane.

### Tests (all in `agent/tests/test_sqli_tool.py`, a new file)

Failed BEFORE the fix (3 of 4; the negative control passed before and after, as it must):

    FAILED test_auth_bypass_finding_emits_auth_bypass_family
    FAILED test_auth_bypass_finding_fails_authn02_and_not_val01   assert 'not_tested' == 'failed'
    FAILED test_auth_bypass_evidence_satisfies_the_proof_gate     missing=['evidence_signal:union']

Mutation tests - each mutant VERIFIED APPLIED by grepping the mutated line before running:

| Mutant | Applied at | Killed by |
|---|---|---|
| `f["family"] = "sqli"` (revert the fix) | `sqli_tool.py:310` | all 3 assertions |
| `_base` family -> `"auth_bypass"` (OVER-BROADEN) | `sqli_tool.py:217` | `test_every_other_oracle_keeps_the_sqli_family` |
| evidence -> old prose string | `sqli_tool.py:289` | `test_auth_bypass_evidence_satisfies_the_proof_gate` |

The over-broadening mutant is the important one: it is the failure mode Q-048 warned about (a
family many engines emit makes objectives fail spuriously), and the negative control catches it.

### PATCH HANDED OFF - `asvs_model.py`, AUTHN-02

**No functional change is required.** AUTHN-02 already declares
`"violated_by": ("auth_bypass", "broken_auth")`, and `map_findings` keys on FAMILY ALONE - it
never consults `engine`. So the objective went live the moment the family landed. MEASURED at HEAD:

    AUTHN-02 violated_by AT HEAD: ('auth_bypass', 'broken_auth')
    AUTHN-02 with the auth-bypass finding -> failed ['finding-0']
    VAL-01   with the auth-bypass finding -> not_tested
    AUTHN-02 with an ORDINARY sqli      -> not_tested (must not be failed)
    VAL-01   with an ORDINARY sqli      -> failed

The ONLY edit needed is retiring the now-false comment. Replace these two lines
(`asvs_model.py`, the tail of the AUTHN-02 comment block):

    # run_saml is the one dispatchable engine that emits "broken_auth" directly. "auth_bypass" is KEPT
    # with no producer today on purpose: it is the family that handed-off patch would introduce.

with:

    # run_saml is the one dispatchable engine that emits "broken_auth" directly. Q-053 GAP-3 landed the
    # producer for "auth_bypass": sqli_tool.auth_bypass_finding (sqli_tool.py:310) is its SOLE producer
    # in the tree, reachable only from run_auth_sqli (tools.py:7414), so this objective cannot fail
    # spuriously. Ordinary SQLi keeps family "sqli" and still fails VAL-01, not this objective.

Exact family string to key on, character for character, copied from a real emitted record:

    auth_bypass

11 characters, lowercase ASCII, underscore separator, no leading/trailing whitespace,
hex `617574685f627970617373`. NOT `auth-bypass` (that is the TAG and the oracle name), NOT
`sqli_auth_bypass` (that is the TECHNIQUE id in `techniques.py`/`engine_descriptor.py`, a
different vocabulary).

### What else emits `auth_bypass`?  NOTHING (MEASURED)

    PRODUCERS OF 'auth_bypass':
        sqli_tool.py:310

Sole producer. Also checked that no DYNAMIC site can synthesise the string: every
`"family": <identifier>` site outside `tests/` is either a pass-through of an existing finding's
family (`main.py`, `poc_bundle.py`, `retest.py`, `blind_benchmark.py`) or reads from a static
table (`authz_matrix._GAP_META`), and the literal `auth_bypass` appears in none of those tables.

The other family AUTHN-02 declares, `broken_auth`, has three producers - `saml_tool.py:120`,
`saml_tool.py:149` and `agent.py:1447` (a confirmed working exposed credential, CWE-522). That
predates this lane and is unchanged by it, but the Coordinator should know AUTHN-02 is failable
through four producers total, not one.

NOTE for a separate ticket, NOT fixed here (`nosqli_tool.py` is not this lane's file):
`nosqli_tool.auth_bypass_finding` (`nosqli_tool.py:204`) is the SAME defect - it confirms a real
NoSQL authentication bypass with the same oracle discipline and stamps `family: "nosqli"` via its
own `_base`. It should emit `auth_bypass` too. Until it does, AUTHN-02 is blind to NoSQL auth
bypass specifically.

### PATCH HANDED OFF - `proof_schema.py` (optional but recommended)

With `family: "auth_bypass"` the finding now routes to `_DEFAULT`, which demands only one weak
signal group. That is a PASS today but a weaker contract than the class deserves. Adding a real
rule to `_FAMILY` keeps the gate honest. Verified against both signal strings the oracle actually
produces (token case and status case):

    "auth_bypass": {"impact": True, "signals": [
        ["token issued", "session", "authenticated", "logged in", "200"],
        ["invalid credential", "without credentials", "no valid", "injection", "payload", "baseline"],
    ]},

Do NOT instead alias `auth_bypass` -> `access_control`: that rule's first signal group is
`["owner","ownership","role","persona","privileg","cross-user","unauthor","owner-created"]`, and
an authentication-bypass proof carries none of those, so the alias would demote a genuinely
verified bypass to a lead - the exact self-contradiction the CWE-522 comment in that file records.

### Mutation-gate candidate (for `mutation_gate.py`, the Coordinator's file)

Mutant: change `sqli_tool._base`'s `"family": "sqli"` to `"auth_bypass"`. Expected killer:
`tests/test_sqli_tool.py::test_every_other_oracle_keeps_the_sqli_family`. This guards the
over-broadening direction, which no existing gate covers.

---

## GAP-4 - `transport_posture` shares `security_misconfig` across cookie, header and methods

IN PROGRESS - see below.
