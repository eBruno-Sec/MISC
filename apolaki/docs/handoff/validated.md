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

## Q3. WHAT THE GUARD ACTUALLY CHECKS - in progress

## Q4. WHAT CONSUMES IT - in progress
