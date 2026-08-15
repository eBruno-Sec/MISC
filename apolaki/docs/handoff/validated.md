# VALIDATED BREAKER lane - is `validated_on` a real measurement or a hand-typed string?

Status: IN PROGRESS. Written as I go. Every number carries the command that produced it.

Question under test: `validated_on` is suspected to be (a) minted by hand, (b) counted as
capability, (c) guarded vacuously. Treated as a hypothesis, not a finding.

Headline so far: the hypothesis is **partly confirmed and partly already-fixed**. A prior patch
(`techniques.technique_status`) DID sever the UI's "proven" stat from `validated_on` and says so in
its own docstring. But that fix is local: a second status rule in `technique_model.from_registry`
still reads `validated_on` directly, and `is_generalized()` -> `generalized_total` was never touched.

---

## Q1. WHERE the field lives and WHO writes it - MEASURED

Method: `ast` walk over every `.py` in the repo, classifying each occurrence by structural kind
(keyword arg vs dict-literal key vs subscript store vs `.get()` read). A regex would conflate these.
Script: scratchpad `census.py`.

```
$ MSYS_NO_PATHCONV=1 docker run --rm -v "C:/.../apolaki:/repo:ro" -v "<scratch>:/s:ro" \
    -w /s apolaki-agent python census.py /repo
==============================================================================
PRODUCERS of validated_on  (total=70)
==============================================================================
agent/techniques.py                     dict-literal-key   n=2  literal=0 computed=2
agent/techniques.py                     kwarg:_t()         n=54 literal=54 computed=0
agent/techniques.py                     setdefault()       n=1  literal=1 computed=0
agent/tests/test_technique_pipeline.py  dict-literal-key   n=9  literal=9 computed=0
agent/tests/test_techniques.py          dict-literal-key   n=4  literal=4 computed=0

NON-LITERAL producers (a value COMPUTED from something):
  agent/techniques.py:986   [dict-literal-key]  "validated_on": sorted(validated & set(labs)) if lab_ids else sorted(validated),
  agent/techniques.py:1220  [dict-literal-key]  "generalized": is_generalized(t), "validated_on": t.get("validated_on", []),
```

**Answer to "is any value ever computed from an actual run?" - NO. Zero.**

- All 54 production producers are `_t(validated_on=[...])` keyword arguments with **literal** list
  values. There is exactly one writer: a human typing into `agent/techniques.py`.
- The 2 "computed" hits are false positives of the question: both are in `coverage_matrix()` (line 986)
  and `taxonomy_view()` (line 1220), and both merely RE-EMIT `t["validated_on"]` (filter/sort). They
  read the hand-typed value; they do not derive it.
- `setdefault("validated_on", [])` at `techniques.py:45` is the default for records that declare none.
- Nothing in `agent/liveness.py`, `agent/liveness_run.py`, `agent/benchmark.py` or any runner writes
  the field. The liveness machinery writes a SEPARATE artifact
  (`agent/tests/liveness_baseline.json`), which is the honest, run-derived ledger.

### The 22 consumers (full list, from the same run)

| file | line | expression |
|---|---|---|
| agent/main.py | 2129 | `proven = sum(1 for t in ts if t.get("validated_on"))` |
| agent/technique_model.py | 243 | `validated = rec.get("validated_on") or []` |
| agent/technique_planner.py | 166 | `vo = list(dict.fromkeys(r.get("validated_on") or []))` |
| agent/techniques.py | 951 | `is_generalized()`: `len(set(...)) >= GENERALIZED_MIN_LABS` |
| agent/techniques.py | 961 | `all_labs()` |
| agent/techniques.py | 976 | `coverage_matrix()` |
| agent/techniques.py | 1220 | `taxonomy_view()` row field |
| agent/techniques.py | 1243 | `taxonomy_view()["claimed"]` |
| agent/techniques.py | 1283 | `technique_status()` -> `unverified` vs `catalogued` |
| agent/tests/* | 13 hits | assertions (listed in Q3) |

### The two competing status rules (structural, MEASURED from source)

- `agent/techniques.py:1263-1283` `technique_status()` - **the fixed path**. Its own docstring says:
  *"validated_on is written by hand: four backfill dicts append a lab id with nothing checking the
  claim."* Returns `proven` only when the id appears in `tests/liveness_baseline.json`.
- `agent/technique_model.py:256` `from_registry()` - **the unfixed path**, still the old rule:
  `"status": "proven" if validated else "catalogued"`.

The second one matters because `from_registry` is the adapter into the *canonical first-class
Technique* consumed by the technique store / API, and `technique_model.confidence_score()` then adds
`status:proven = 55 points`, `oracle-validated x N = up to 24 points` (derived from
`evidence[].lab`, which `from_registry` fills from `validated_on` at line 266-267) and
`cross-lab generalized = +8`. So a hand-typed lab id is worth up to **87 confidence points** on the
canonical model, with nothing checking it.

---

## Q2. THE TALLY - MEASURED

Command (registry imported inside the agent image, no network):

```
$ MSYS_NO_PATHCONV=1 docker run --rm -v ".../agent:/app" -v "<scratch>:/s:ro" -w /s \
    apolaki-agent python tally.py
techniques_total: 88
with_validated_on: 48
without: 40
distinct_labs: 13
```

| lab id named in `validated_on` | techniques claiming it | what it actually is |
|---|---|---|
| juiceshop | 24 | REAL third-party app, `bkimminich/juice-shop` pinned by digest in compose |
| conpot | 5 | REAL third-party image, `honeynet/conpot` (ICS honeypot; a foreign stack, deliberately) |
| ginandjuice | 5 | REAL external host (PortSwigger ginandjuice.shop) - not in compose, off-box |
| domsource | 3 | **SELF-AUTHORED fixture** - compose runs `python:3.12-slim` over `./labs/domsource` |
| dvga | 3 | REAL third-party image, `dolevf/dvga` |
| clientauthz | 2 | **SELF-AUTHORED fixture** - `python:3.12-slim` over `./labs/clientauthz` |
| dvwa | 2 | REAL third-party image, `vulnerables/web-dvwa` |
| smb | 2 | REAL service image, `dperson/samba` |
| natas | 1 | REAL external host (OverTheWire) |
| openfmb | 1 | REAL third-party image, `oesinc/openfmb.adapters` |
| openldap | 1 | REAL service image, `osixia/openldap` |
| sessionlife | 1 | **DOES NOT EXIST IN THE COMMITTED REPO** - see below |
| snmpd | 1 | REAL service image, `polinux/snmpd` |

Classification (by technique-claims, 51 lab-claims across 48 techniques):
- **45 claims name a real, independently-authored target** (third-party image or external host).
- **5 claims name a self-authored fixture in `labs/` served by a bare `python:3.12-slim`**
  (domsource x3, clientauthz x2). These are real reachable HTTP servers and they are *paired*
  (vuln/secure mounts), which is the discipline this project wants - but they are Apolaki's own code,
  so a claim against them is "our oracle agreed with our fixture", not "proven against an application".
- **1 claim names a target that does not exist in the repository at all** (sessionlife).
- **0 claims name a pure unit fixture / mock** - checked; no `validated_on` value is a mock name.

### The sessionlife finding - MEASURED, and the sharpest instance of the defect

```
$ git show HEAD:./agent/techniques.py | grep -n "sessionlife\|session_lifecycle"
133:    _t(id="session_lifecycle", vuln_class="session", cwe="CWE-613", owasp="A07:2021", wstg="WSTG-SESS-06",
134:       permission=ACTIVE, transferable=True, validated_on=["sessionlife"],
135:       maps_to={"sessionlife": ["logout does not invalidate", "session survives password change",

$ git show HEAD:./docker-compose.yml | grep -c "sessionlife"
0

$ git ls-files labs/sessionlife | wc -l
0

$ git status --porcelain labs/sessionlife docker-compose.yml
 M apolaki/docker-compose.yml
?? apolaki/labs/sessionlife/
```

A **committed** capability claim (`validated_on=["sessionlife"]`) names a lab that, at HEAD, has no
compose service and no tracked source file. `labs/sessionlife/app.py` exists only in the working tree
as an untracked file. A fresh clone of this repository carries the claim and cannot reproduce, re-run,
or even locate the thing it claims to have been validated against. Nothing in the test suite noticed.

### The gap the codebase already admits

```
taxonomy_view headline: {'total': 88, 'proven': 16, 'unverified': 32, 'solver_only': 0,
                         'claimed': 48, 'transferable': 87, 'generalized': 3}
STATUS HISTOGRAM: catalogued 40 | proven 16 | unverified 32
```

`claimed = 48` (has `validated_on`) vs `proven = 16` (a liveness run confirmed it). The 32-technique
distance IS the honesty debt, and `techniques.py` deliberately keeps both numbers visible rather than
hiding it - credit where due, that is the Q-012 `not_implemented`/`not_tested` pattern applied well.

All 16 liveness-proven ids also carry a non-empty `validated_on` (measured: the "in baseline but empty
validated_on" list came back empty), so the two ledgers do not contradict each other - the typed field
is a superset of the earned one.

### The two engines the ticket asks about

- `mass_assignment`: `validated_on=[]`, `backfill_claim=['juiceshop']`, status `catalogued`.
- There is **no `ws_hijack` / CSWSH technique record at all** (`grep -n "ws_hijack\|cswsh\|websocket"
  agent/techniques.py` -> no technique match).

So neither newly-shipped engine has minted a `validated_on`. Their current state is honest. Any rule
proposed below must let them *earn* a value, not force one.

---

## Q3. WHAT THE GUARD ACTUALLY CHECKS - MEASURED

### There is no single guard. There are five, and every one points the wrong way.

Five tests assert on `validated_on`. Their docstrings are excellent - "the registry must not claim a
validation this file does not replay" - but the assertion each one actually writes is:

```
agent/tests/test_ics_real_stack.py:188      assert "conpot" in T.TECHNIQUES[tid]["validated_on"], tid
agent/tests/test_netsvc_real_stack.py:90    assert lab in T.TECHNIQUES[tid]["validated_on"], tid
agent/tests/test_bie.py:661                 assert "clientauthz" in T.TECHNIQUES[tid]["validated_on"], tid
agent/tests/test_local_import_guard.py:193  assert "dvga" in T.TECHNIQUES[tid]["validated_on"], tid
agent/tests/test_authscan.py:50             assert T.TECHNIQUES["exposed_credentials"]["validated_on"] == ["ginandjuice"]
```

`lab in validated_on` is a **membership** assertion. It fails only when a claim is REMOVED. It cannot
fail when a claim is ADDED. Four of the five are one-directional by construction; only
`test_authscan.py:50` uses `==`, and it pins exactly one technique.

**What would have to be true for these guards to FAIL:** somebody would have to DELETE a
`validated_on` entry. That is the opposite of the failure mode they exist to catch. They enforce that
the claim is present; they never test that it is earned. This is the sixth instance of the
"guard that checks a declaration, not a fact" shape - and here it is inverted into a guard that
actively resists retracting an unearned claim.

The remaining guard, `test_technique_contract.py:22`, is monotone in the wrong direction too:

```python
proven = [r for r in T.TECHNIQUES.values() if r.get("validated_on")]
assert len(proven) >= 30
```

Adding a fabricated `validated_on` makes this pass *harder*.

### Guard coverage - MEASURED

```
$ ... apolaki-agent python guardcov.py
techniques with validated_on: 48
of those, named in a validated_on assertion: 14
of those, NOT named in ANY validated_on assertion: 34
```

| lab | claims | uncovered by any assertion |
|---|---|---|
| juiceshop | 24 | **24** |
| ginandjuice | 5 | 4 |
| conpot | 5 | 0 |
| domsource | 3 | **3** |
| dvga | 3 | 0 |
| clientauthz | 2 | 0 |
| dvwa | 2 | **2** |
| smb | 2 | 0 |
| natas | 1 | **1** |
| openfmb | 1 | **1** |
| openldap | 1 | 0 |
| sessionlife | 1 | **1** |
| snmpd | 1 | 0 |

The beyond-web work (conpot/smb/openldap/snmpd/dvga/clientauthz) is genuinely guarded by recorded
replies. **The entire web side is not**: all 24 juiceshop claims and both dvwa claims have no
assertion of any kind.

### There is no lab-id vocabulary to check against - THE ROOT VACUITY

Nothing anywhere validates that a `validated_on` string names a target. `techniques.all_labs()`
(line 958) **derives the set of valid labs FROM the field itself**:

```python
def all_labs():
    labs = set()
    for t in TECHNIQUES.values():
        labs.update(t.get("validated_on", []))     # the vocabulary IS the typed strings
```

So the answer to "is this a real lab?" is "yes, because you typed it." Measured against the three lab
registries the agent actually owns:

```
$ ... python -c "import bench_all, benchmark, labs, techniques; ..."
validated_on ids: ['clientauthz','conpot','domsource','dvga','dvwa','ginandjuice','juiceshop',
                   'natas','openfmb','openldap','sessionlife','smb','snmpd']
KNOWN to any in-agent lab registry:   ['clientauthz','conpot','dvga','dvwa','ginandjuice',
                                       'juiceshop','openldap','smb','snmpd']
UNKNOWN to every in-agent lab registry: ['domsource','natas','openfmb','sessionlife']
```

**4 of 13 lab ids are unknown to `bench_all.LAB_URLS`, `benchmark.MANIFESTS` and `labs.LABS` alike.**
`sessionlife` is additionally absent from HEAD entirely (Q2).

### THE NEGATIVE CONTROL - the fabricated claim that ought to be rejected and is not

MEASURED. A record carrying two invented lab ids is accepted end to end:

```
$ ... python -c "
import techniques as T, technique_model as TM
fake = {'id':'fabricated','vuln_class':'sql_injection','cwe':'CWE-89','owasp':'A03:2021',
        'validated_on':['fabricated_lab_9000','fabricated_lab_9001'],'oracle':'x','transferable':True}
print('is_generalized      ->', T.is_generalized(fake))
t = TM.from_registry(fake)
print('from_registry status->', t['status'])
print('confidence          ->', t['confidence']['score'], t['confidence']['tier'])
print('factors             ->', t['confidence']['factors'])
print('evidence            ->', t['evidence'])
print('schema validate()   ->', TM.validate(t), '(empty list = valid)')"

is_generalized      -> True
from_registry status-> proven
confidence          -> 90 high
factors             -> [{'name': 'status:proven', 'points': 55},
                        {'name': 'oracle-validated x2', 'points': 24},
                        {'name': 'cross-lab generalized', 'points': 8},
                        {'name': 'has detection logic', 'points': 3}]
evidence            -> [{'lab': 'fabricated_lab_9000', 'challenges': []},
                        {'lab': 'fabricated_lab_9001', 'challenges': []}]
schema validate()   -> [] (empty list = valid)
```

Two strings nobody has ever run anything against produce `status="proven"`, `confidence=90/100` in
the **high** tier, a two-entry evidence list, `generalized=True`, and a **clean schema validation**.
Nothing rejects it. Pinned as an executable strict-xfail in `agent/tests/test_validated_on.py`.

(Self-correction, recorded per house rules: I first wrote 79 in this document from an unrun estimate
and had to replace it with the measured 90. The estimate was wrong because I forgot the
`cross-lab generalized` +8 and undercounted `oracle-validated x2` as x1. The number above is the
command's real output.)

---

## Q4. WHAT CONSUMES IT - MEASURED

The field is **materially worse than decoration**, but it does **not** reach the customer report.
Both halves matter and both are measured.

### It does NOT reach these (checked, negative result)

- **Generated pentest reports**: `grep -rl "validated_on" Pentest_Reports` -> **0 files**.
  `agent/report.py` touches techniques only in `_scope_exclusion_md` (line 172-174), for operator
  scope-exclusion wording; `agent/scan_scope.py` contains no reference to `validated_on`,
  `generalized` or `proven`.
- **ASVS coverage** (`/coverage/asvs` -> `asvs_model.assess`): no reference to `validated_on`.
- **WSTG coverage** (`/coverage/wstg` -> `wstg_catalog.coverage`): no reference to `validated_on`.

So the standards-mapped coverage claims are independent of the typed field. Good news, and it bounds
the severity: **no client-facing document currently carries a fabricated validation claim.**

### It DOES reach these (four consumers, in descending severity)

**1. The live scan planner - it changes what Apolaki attacks and in what order.**
`agent/technique_planner.py:166-172` (`registry_seed`, used *inside* a scan, not just by `/plan`):

```python
vo = list(dict.fromkeys(r.get("validated_on") or []))
score = 60 if len(vo) >= 2 else (40 if vo else 20)
... "status": "proven" if vo else "catalogued",
```

and `plan()` ranks by `conf * 0.5 + (15 if KEV) + (10 if status == "proven")`. Measured:

```
score=20  status=catalogued  n=40
score=40  status=proven      n=45
score=60  status=proven      n=3

plan() with all preconditions satisfied -> 42 techniques
  top: sqli_auth_bypass 30.0, sqli_union_extract 30.0, session_lifecycle 30.0, idor_bola_read 30.0 ...
plan() after stripping EVERY validated_on -> 42 techniques
  top: sqli_auth_bypass 10.0, sqli_union_extract 10.0, nosql_injection 10.0, weak_session_token 10.0 ...
ORDER CHANGED: True      positions differing: 40 of 42
```

Removing the hand-typed field alone reorders **40 of 42** planned techniques. A typed string is
steering live attack ordering. Note `session_lifecycle` sits in the top four on the strength of
`validated_on=["sessionlife"]` - the lab that does not exist at HEAD.

**2. The `/packs` API - a second, contradictory "proven" number.**
`agent/main.py:2129`: `proven = sum(1 for t in ts if t.get("validated_on"))`.

```
/packs sums 'proven' across technique packs = 48
taxonomy_view()['proven'] (liveness-earned)  = 16
```

The same product reports **48** and **16** as "proven", differing by 32, from two endpoints, with the
`/packs` string rendered as `"%d techniques - %d proven, %d generalized."`. The Q-012 fix was applied
to `/techniques` and never propagated to `/packs`.

**3. The canonical Technique model - up to 87 confidence points from a typed string.**
`agent/technique_model.py:243,256,266-267` -> `status="proven"` (55 pts), `evidence[].lab` populated
from `validated_on` -> `oracle-validated xN` (up to 24 pts), `cross-lab generalized` (+8). Measured:

```
sqli_auth_bypass  validated_on=['juiceshop'] -> status=proven confidence=70
   factors: [{'status:proven': 55}, {'oracle-validated x1': 12}, {'has detection logic': 3}]
```

70/100 = "high" tier, 67 of which come from the hand-typed field. `technique_status()` calls the very
same technique **unverified**.

**4. The capability matrix - a `live_proven` claim whose cited evidence is factually wrong.**
`agent/capability_matrix.py:63-64`:

```python
_c("Cross-lab generalization (>=2 independent labs)", "lab", "live_proven",
   "techniques.py generalized set; validated_on across juiceshop/dvwa/ginandjuice",
   ["juiceshop", "dvwa", "ginandjuice"]),
```

Measured against the registry today:

```
generalized set: {'snmp_default_community': ['conpot','snmpd'],
                  'csti': ['juiceshop','ginandjuice'],
                  'vulnerable_component': ['juiceshop','ginandjuice']}
labs actually involved in ANY generalized technique: ['conpot','ginandjuice','juiceshop','snmpd']
labs claimed but NOT in any generalized technique: ['dvwa']
```

The row is state `live_proven` - the matrix's top state, defined in its own docstring as "produced
real evidence on a live authorized target" - and it cites **dvwa**, which backs no generalized
technique at all. `capability_matrix.validate()` checks that evidence is a non-empty *string*; it
never checks that the string is true. That is the same vacuity one layer up.

### UI

`ui/index.html` is the honest consumer. Line 2185-2186 renders `proven` (liveness-earned) and
`unverified` side by side with the tooltip "This number is the honesty debt - it is shown, not
hidden". Line 746-748 explicitly refuses to collapse `unverified` into `catalogued`. No change needed
there; the UI is downstream of the *fixed* rule.

---

## WHAT IN THE FRAMING TURNED OUT TO BE WRONG

Recording these because a disproof is a result.

1. **"guarded vacuously"** - understated in one way, overstated in another. There is no single guard;
   there are five, they are one-directional (fail only on REMOVAL), and 34 of 48 claims have no
   assertion at all. But the beyond-web claims (conpot/smb/openldap/snmpd/dvga/clientauthz, 14
   techniques) ARE backed by recorded replies. That work is real and should not be tarred.
2. **"counted as capability"** - TRUE, and worse than assumed: it also steers live scan ordering
   (40 of 42 positions). But it does NOT reach a customer-facing report, ASVS or WSTG claim.
   `grep -rl validated_on Pentest_Reports` -> 0. The ticket's "materially worse defect" threshold is
   NOT met for client documents; it IS met for scan behaviour.
3. **"minted by hand"** - TRUE without qualification. 54/54 production producers are literals.
4. **The prior fix already exists and is good.** `techniques.technique_status()` + the
   `claimed`/`proven`/`unverified` split is the Q-012 pattern applied correctly, and
   `backfill_claim` was deliberately separated out of `validated_on` by an earlier lane. The defect
   is that the fix was **never propagated**: three other modules (`technique_planner`,
   `technique_model`, `main.py:/packs`) still run the old rule. This is a *containment* failure,
   not an absence of awareness.
5. **`run_ws_hijack` has no technique record at all** (`grep -n "ws_hijack\|cswsh\|websocket"
   agent/techniques.py` -> no technique match), and `mass_assignment` carries `validated_on=[]`.
   Neither of the two engines named in the ticket has minted a claim. Their current state is honest.

---

## PROPOSAL for a Builder (follow-up ticket)

**What `validated_on` should mean:** *this technique's own oracle fired against a NAMED target whose
definition lives in this repository, and the request/response that proved it is retained.*
It must be **derived**, never typed.

Concretely, four changes, smallest first:

1. **Give lab ids a vocabulary.** Add `LAB_TARGETS` (id -> {kind: third_party_image | self_authored_fixture
   | external_host, ref: compose service / labs dir / hostname}). Make `all_labs()` read it instead
   of deriving the vocabulary from the field. A `validated_on` id not in `LAB_TARGETS` is a hard
   error at import. Fixes `sessionlife`, `domsource`, `natas`, `openfmb` today.
2. **Rename the typed field to `validated_claim` and make `validated_on` derived.**
   `validated_on` becomes a function of `tests/liveness_baseline.json` + recorded-capture artifacts -
   the machinery `agent/liveness.py` already owns. Keep `validated_claim` visible (the
   `backfill_claim` precedent) so nothing is lost and the debt stays reportable.
3. **Propagate the Q-012 fix to the three modules that missed it.** `technique_planner.registry_seed`,
   `technique_model.from_registry` and `main.py:/packs` must all call `techniques.technique_status()`
   instead of re-deriving `"proven" if validated_on`. One rule, one place. This alone kills the
   48-vs-16 contradiction and stops a typed string reordering a scan.
4. **Add the third honesty value.** Following `proof_schema.control_status()`'s
   RECORDED / NOT_RECORDED / NOT_APPLICABLE, the honest value when nothing proves it is
   **`NOT_RECORDED`** - distinct from `[]` (never claimed) and from a lab id (earned). A
   self-authored fixture should surface as `kind: self_authored_fixture`, not silently rank equal to
   Juice Shop.

**What this lets the two new engines do truthfully.** `run_ws_hijack` validated against a paired
vulnerable/secure WebSocket server the lane stood up gets
`validated_on=[{lab: "wshijack", kind: "self_authored_fixture"}]` - a real, reportable state that is
explicitly NOT the same as third-party validation, and which does not inflate `generalized`.
`run_mass_assign`, proven only on unit fixtures, stays `NOT_RECORDED` until its live lane lands.
Neither has to lie, and neither has to stay silent.

---

## THE TEST I ADDED

`agent/tests/test_validated_on.py` - results in the next section.

