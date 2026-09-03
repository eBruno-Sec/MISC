# Q-164 -- `validated_on` badge audit

Lane: BUILDER. Owns only `docs/handoff/techniques-q164.md`, `agent/techniques.py` (badge
changes only), `agent/tests/test_technique_badges.py`.

DO NOT CHASE THE COUNT. The deliverable is the per-badge verdict, not a bigger `proven` number.

## Question

`agent/techniques.py` carries a `validated_on` list on many technique records. The field is a
literal somebody typed. The audit asks, per badge: is there a code path that RE-RUNS this
technique against that lab and passes?

- EARNED -- something re-runs it against the named lab and it confirms.
- STALE  -- nothing re-runs it. The badge is an unbacked claim.
- WRONG  -- the named lab cannot exercise it at all, or the badge names a lab that is not the
  lab the re-check actually uses.

## Baseline (MEASURED)

Command (throwaway container, read-only over the working tree):

    docker run --rm --network apolaki_default -e PYTHONPATH=/app \
      -v ".../apolaki/agent:/app" -w /app apolaki-agent python /scratch/audit1.py

Output:

    TOTAL techniques: 94
    WITH validated_on: 56
    liveness baseline size: 26
    CHECKS entries: 26 distinct techniques: 26
    baseline ids NOT in CHECKS: []
    CHECKS ids NOT in baseline: []
    CHECKS ids not in registry: ['surface_discovery', 'technology_detection']

So: 56 technique records carry a badge; 59 distinct (technique, lab) badge PAIRS.
`agent/liveness.py:CHECKS` re-runs 26 ids, but 2 of those (`surface_discovery`,
`technology_detection`) are not technique records at all -- they are liveness-only ids. That
leaves **24 badge-carrying techniques with a re-runner and 32 with none**, which is exactly the
split the ticket predicted.

Lab histogram over `validated_on` (59 pairs):

    juiceshop   24    domsource   10    conpot     5    ginandjuice 5
    dvga         3    smb          2    clientauthz 2   dvwa        2
    sessionlife  1    openldap     1    snmpd      1    natas       1
    openfmb      1    vampi        1

Two lab ids do not resolve in `known_labs()` at all: `sessionlife` (session_lifecycle) and
`natas` (header_trust_authz). `techniques.validation_record()` already reports these as
`unresolved` -- they are visible today, not hidden.

## Method for "is it re-run"

Registration is not invocation. For each candidate re-runner I require a path from a
pytest/gate entry point to the SHIPPING executor with the named lab as the target. A test that
constructs a finding dict by hand and asserts the oracle decides correctly proves the ORACLE,
not the badge: the badge claims the wiring carried a real lab all the way through.

## Verdicts

Filled in below as measured. Section per group.

### Group A -- 24 techniques with a liveness CHECK (`agent/liveness.py`)

`agent/liveness.py:CHECKS` + `agent/liveness_run.py` + `scripts/liveness.sh` is a real
end-to-end re-runner: it calls `ToolRegistry._run_*` / module functions against a standing lab
container, requires a `confirmed`/`high` finding with >= 12 chars of evidence, and treats an
absent lab as SKIPPED, never a pass (`agent/liveness.py:verdict`). This is the only mechanism
in the repo that re-earns a badge.

Per-badge, comparing the badge's lab against the CHECK's lab:

| technique | badge lab(s) | check lab | verdict |
|---|---|---|---|
| modbus_exposed | conpot | conpot | EARNED |
| s7comm_exposed | conpot | conpot | EARNED |
| enip_exposed | conpot | conpot | EARNED |
| ipmi_rakp | conpot | conpot | EARNED |
| snmp_default_community | conpot, snmpd | snmpd | EARNED (snmpd) / see WRONG below (conpot) |
| dnp3_exposed | openfmb | dnp3 (`dnp3-outstation`) | EARNED (id alias, see note) |
| ldap_anonymous_read | openldap | openldap | EARNED |
| smb_null_session | smb | smb | EARNED |
| smb_signing_disabled | smb | smb | EARNED |
| graphql_introspection | dvga | dvga | EARNED |
| graphql_argument_injection | dvga | dvga | EARNED |
| dom_data_manipulation | domsource | domsource | EARNED |
| dom_link_manipulation | domsource | domsource | EARNED |
| private_key_disclosed | domsource | domsource | EARNED |
| websocket_url_poisoning | domsource | domsource | EARNED |
| ajax_header_manipulation | domsource | domsource | EARNED |
| ssi_injection | domsource | domsource | EARNED |
| csp_allows_untrusted_script | domsource | domsource | EARNED |
| jwt_signature_not_verified | domsource | domsource | EARNED |
| python_code_injection | domsource | domsource | EARNED |
| client_side_authz | clientauthz | clientauthz | EARNED |
| client_supplied_identity_param | clientauthz | clientauthz | EARNED |
| mass_assignment | vampi | vampi | EARNED |
| dom_xss | **juiceshop** | **domsource** | WRONG lab -- see below |

Notes on the three that are not clean:

- `dom_xss` (`agent/techniques.py`) claims `validated_on=["juiceshop"]`. The only re-runner,
  `agent/liveness.py` CHECKS entry `{"technique": "dom_xss", "lab": "domsource", ...}`, drives
  `http://domsource:8080/hash`. Nothing re-runs dom_xss against juiceshop. The technique is
  proven; the LAB NAMED IS NOT THE LAB PROVEN.
- `snmp_default_community` claims `["conpot", "snmpd"]`. The CHECK targets `snmpd:161` only, and
  `agent/tests/test_ics_real_stack.py:187` names the id in a MEMBERSHIP assertion
  (`assert "conpot" in ... validated_on`) without replaying a single recorded SNMP byte -- unlike
  its four neighbours in that same loop, each of which has a recorded reply above it. So the
  conpot half is a declaration guarded by a declaration.
  MEASURED, and it is not what the compose file suggests. `docker-compose.yml:343` maps conpot's
  SNMP as `127.0.0.1:42162:16100/udp`, i.e. the container listens on **16100**, not 161. Driving
  the shipping engine (`agent/snmp_audit_tool.probe`) from inside `apolaki_default`:

      conpot  :161    probe -> {'reachable': False}
                      analyze -> None
      conpot  :16100  probe -> {'reachable': True, 'community': 'public',
                                'sysdescr': 'Siemens, SIMATIC, S7-200'}
                      analyze -> ('public', 'Siemens, SIMATIC, S7-200')
      snmpd   :161    probe -> {'reachable': True, 'community': 'public',
                                'sysdescr': 'Linux ... WSL2 ... x86_64'}

  So conpot CAN exercise the technique, on a non-standard port nothing points at. The `conpot`
  half is STALE, not WRONG, and is RE-EARNABLE. Re-earned below.
- `dnp3_exposed` claims `["openfmb"]` while the check's lab key is `dnp3` at host
  `dnp3-outstation`. This is a naming alias, not a false claim: the DNP3 outstation container
  IS the OpenFMB adapter (`agent/liveness.py` comment says so explicitly). Recorded as EARNED
  with an alias note; `openfmb` only exists in `known_labs()` because this technique vouches
  for it (`techniques._liveness_vouched_labs`).

### The other candidate re-runners, and why none of them re-runs a badge

Checked each of the mechanisms the ticket named. MEASURED, all negative:

- **`agent/bwapp_solvers.py`** -- a real prover, but `agent/tests/test_bwapp_solvers.py` never
  reaches a live bWAPP: `test_prove_degrades_when_unreachable` probes `http://127.0.0.1:1`,
  `test_synthetic_vulnerable_responses_fire_each_oracle` monkeypatches responses, and
  `test_bwapp_registered_as_a_lab` calls `labs.solve("bwapp", "http://127.0.0.1:1")`. Nothing in
  the suite drives bWAPP. It re-checks no badge -- and in any case NO technique names `bwapp` in
  `validated_on`; bWAPP appears only in `backfill_claim`, which is already segregated.
- **`agent/labs.py:solve()`** -- dispatches to the juiceshop/bwapp/mutillidae solver packs, but its
  only callers are the `/labs` API surface. No gate, no test, no scheduled run invokes it against a
  live lab. Registration, not invocation.
- **`agent/benchmark.py:MANIFESTS` / `agent/bench_all.py:LAB_URLS`** -- target REGISTRIES. They
  supply the legal lab vocabulary to `techniques.known_labs()`; they score class coverage when a
  benchmark is run by hand. Neither maps a lab result back to a technique id, so neither can
  re-earn a badge.
- **`agent/capability_matrix.py`** -- reads `techniques.generalized()` / `validation_record()`. A
  consumer of the field, never a producer of evidence.
- **`scripts/`** -- only `scripts/liveness.sh` touches a technique id, and it is the runner for
  Group A.
- **`agent/tests/test_ics_real_stack.py`, `test_netsvc_real_stack.py`, `test_mass_assign_tool.py`,
  `test_bie.py`, `test_local_import_guard.py`, `test_authscan.py`** -- these carry the five
  existing per-lab guards. Two shapes, and the difference matters:
  - a RECORDED-REPLY replay (real bytes captured off the lab, pushed back through the shipping
    parser) -- genuine independent backing, and it exists for modbus / s7comm / enip / ipmi / dnp3
    / smb signing / smb null session / ldap anonymous read / clientauthz / mass_assignment;
  - a bare MEMBERSHIP or EQUALITY assertion on the field itself, e.g.
    `agent/tests/test_authscan.py:50` `assert TECHNIQUES["exposed_credentials"]["validated_on"] ==
    ["ginandjuice"]` and `agent/tests/test_local_import_guard.py:193` `assert "dvga" in ...
    validated_on`. These re-check NOTHING. They pin a literal against a literal. Every badge whose
    only "backing" is this shape is STALE by this audit's definition.

  `agent/tests/test_validated_on.py:171` already proved the direction of the membership shape:
  adding a fabricated lab leaves the guard's assertion true.

### The gate that already exists, and its blind spot

`agent/tests/test_validated_on.py:249 test_every_validated_on_claim_is_backed_by_a_recorded_artifact`
is a `pytest.mark.xfail(strict=True)` recording this exact defect ("30 of 48 with nothing behind
them"). It is a measurement, not an enforcement -- and it has two blind spots I can name:

1. **It counts a mention as backing.** Its `backed` set grows for any technique id that appears on
   any line of any test file that also contains the string `validated_on`. So
   `assert TECHNIQUES["exposed_credentials"]["validated_on"] == ["ginandjuice"]` marks
   `exposed_credentials` BACKED, when that line re-runs nothing. A guard that accepts a
   declaration as evidence passes exactly what it exists to catch.
2. **It is technique-granular, not (technique, lab)-granular.** `dom_xss` is liveness-confirmed, so
   it is `backed`, and the gate therefore cannot see that the lab it names is the wrong one.

My `agent/tests/test_technique_badges.py` is written at PAIR granularity and refuses the mention
shape, so it catches both.

### Group B -- 32 techniques with NO liveness check

The three-way split the ticket asked for maps onto four observed situations. I keep the ticket's
vocabulary and say explicitly where each situation lands, rather than inventing a bucket that
hides something.

#### B1 -- WRONG: the badge credits the technique for what a lab SOLVER did (7)

MEASURED two independent ways. `engine_descriptor.build()` reports `routable=False, engines=[]`,
and `tools.py` has no `_run_*` coroutine for the class:

| technique | badge lab(s) | engines bound |
|---|---|---|
| exposed_credentials | ginandjuice | [] |
| security_misconfig_errors | juiceshop | [] |
| vulnerable_component | juiceshop, ginandjuice | [] |
| weak_secret_forgery | juiceshop | [] |
| weak_2fa_bypass | juiceshop | [] |
| business_logic_abuse | juiceshop | [] |
| soft_deleted_login | juiceshop | [] |

The labs are fine -- Juice Shop genuinely has a 2FA challenge and a forged-coupon challenge. What
is wrong is the attribution: the product has no executor to point at them, so no run BY THE
PRODUCT could have produced the confirmation. What fired was `juiceshop_solvers`. This is the
`weak_password_reset` shape that `agent/techniques.py`'s own module docstring already names as
the reason `backfill_claim` was split out of `validated_on` -- these seven are the same defect that
survived that split, because they were typed directly into `validated_on` rather than appended by
one of the four backfill dicts.

CAVEAT, recorded rather than smoothed over: `engines=[]` is the descriptor's join, and
`agent/engine_descriptor.py:542` says in its own comment that the derived sources are MEASURED to
miss real engines. `run_js_review` and `agent/dependency_intel.py` do surface outdated JS
libraries, so `vulnerable_component` may have a producer the descriptor does not join. I have not
disproved that, so I do NOT claim "no code can ever produce it" -- only the measured facts: no
engine is bound and no dedicated tool exists.

#### B2 -- STALE, and un-re-runnable from this bench (4)

Named labs that are not local docker containers. This lane is authorized for the local lab bench
only, so I did not touch them and could not have re-earned them.

| technique | badge lab(s) | why |
|---|---|---|
| base64_param | ginandjuice | PortSwigger's public `ginandjuice.shop`, off-bench |
| prototype_pollution | ginandjuice | same |
| csti | juiceshop, ginandjuice | juiceshop half is B4; ginandjuice half is off-bench |
| header_trust_authz | natas | OverTheWire, public internet; ALSO unresolved in `known_labs()` |

#### B3 -- STALE, lab exists only as uncommitted local state (1)

`session_lifecycle` claims `validated_on=["sessionlife"]`. MEASURED:

    $ git show HEAD:apolaki/docker-compose.yml | grep -n sessionlife
    (no output)
    $ git status --short | grep sessionlife
    ?? labs/sessionlife/
    $ docker ps --format '{{.Names}}' | grep sessionlife
    apolaki-sessionlife-1

The lab is running on this machine and is not in the repository at HEAD -- no compose service, no
`labs/sessionlife/` source, no registry entry, no liveness check. `known_labs()` therefore cannot
resolve it and `validation_record()` reports it `unresolved`. A badge that only means something on
one developer's box is not a repository claim.

NOT ACTED ON, deliberately: `docker-compose.yml` is modified in the working tree and
`labs/sessionlife/` is untracked, which is another lane's in-flight work landing this exact lab.
Removing the badge now would race them. Recommendation handed over below.

#### B4 -- STALE, lab is local and alive, nothing re-runs it (20)

These are the honest re-earn candidates: a real engine, a reachable authorized lab, and no check.

    sqli_auth_bypass(juiceshop)        sqli_union_extract(juiceshop)
    idor_bola_read(juiceshop)          browser_persona_bola(juiceshop)
    graphql_batching_enabled(dvga)     request_url_override(domsource)
    missing_authentication(juiceshop)  unrestricted_file_upload(juiceshop)
    exposed_files_harvest(juiceshop)   csti(juiceshop half)
    ssti(juiceshop)                    xxe_file_ssrf(juiceshop)
    target_intel_harvest(juiceshop)    csrf(juiceshop)
    excessive_data_exposure(juiceshop) jsonp_info_leak(juiceshop)
    race_condition(juiceshop)          command_injection(dvwa)
    path_traversal(dvwa)               archive_slip(juiceshop)
    find_hidden_route(juiceshop, transferable=False -- lab trivia, not a capability claim)

Note `graphql_batching_enabled` (dvga): its badge's only backing is
`agent/tests/test_local_import_guard.py:193`, a membership assertion. DVGA is up and answers
introspection through the liveness check, so batching is re-earnable -- nothing re-runs it today.

## Verdict tally

59 badge pairs across 56 technique records, audited one at a time.

| verdict | pairs | techniques |
|---|---|---|
| EARNED (a liveness check re-runs it against the lab named, and the committed baseline records it confirmed) | 25 | 23 |
| WRONG -- badge names a lab the re-runner does not drive | 1 | 1 (`dom_xss`) |
| WRONG -- badge credits the technique for a lab solver's result; no engine is bound to the id | 8 | 7 |
| STALE -- nothing re-runs it | 25 | 25 |

The EARNED row is 25 pairs over 23 techniques because `snmp_default_community` carries two labs and
only one of them (`snmpd`) had a check. `dnp3_exposed`'s `openfmb` is counted EARNED as an alias of
the check's `dnp3` lab key -- same container, recorded rather than silently accepted.

## What was actually changed

Ordered by how confident I am in it.

### Re-earned, 3 pairs (`agent/tests/test_technique_badges.py`)

Each drives the shipping executor against a standing local lab and requires the real oracle to fire.

1. **`snmp_default_community` / `conpot`.** MEASURED above: conpot answers on 16100/udp with
   community `public` and sysDescr `Siemens, SIMATIC, S7-200`; `conpot:161` answers nothing.
   Carries a NEGATIVE CONTROL -- `probe(..., communities=("apolaki-q164-not-a-community",))`
   returns `{'reachable': False}`, so accepting `public` is a discrimination, not a honeypot
   answering anything sent at it.
2. **`graphql_batching_enabled` / `dvga`.** `_run_graphql` against `http://dvga:5013/graphql`
   returns `GraphQL request batching enabled`, `confidence=confirmed`, `CWE-770`, evidence
   `a JSON array of 5 operations POSTed to ... returned 5 results`. Matched by TITLE, not family:
   `agent/liveness.py` records that family matching let the BATCHING finding satisfy the
   INTROSPECTION check, and the same trap runs in reverse here.
3. **`sqli_auth_bypass` / `juiceshop`.** `_run_auth_sqli` against `/rest/user/login` returns
   `SQL injection (auth-bypass) in 'email'`, `confirmed`, `CWE-89`, evidence
   `email="' OR 1=1--" -> session/JWT token issued`. The engine baselines with a fresh random
   benign credential on every call, so this is a differential and not a page that 200s at anything.

### Corrected, 1 pair

`dom_xss`: `["juiceshop"]` -> `["domsource"]`. `maps_to` is untouched, so the Juice Shop challenge
mapping survives; only the proof claim moved to the lab that actually carries it.

### Withdrawn, 8 pairs over 7 records

`header_trust_authz`(natas), `security_misconfig_errors`(juiceshop),
`vulnerable_component`(juiceshop, ginandjuice), `weak_secret_forgery`(juiceshop),
`weak_2fa_bypass`(juiceshop), `business_logic_abuse`(juiceshop), `soft_deleted_login`(juiceshop).

Set to `[]` with an in-place comment rather than deleted: the empty list keeps the record visible as
a deliberate withdrawal, and it also keeps `test_validated_on.py`'s producer census (`>= 50` literal
producers) measuring the same population.

### Deliberately NOT changed

- **`exposed_credentials`(ginandjuice)** -- belongs in the withdrawn set by the same evidence (no
  engine bound, `routable=False`), but `agent/tests/test_authscan.py:50` pins the value with an
  EQUALITY assertion and that file is not mine. Diff below.
- **`session_lifecycle`(sessionlife)** -- another lane has the lab in flight in the working tree.
  Diff below, to apply after that lands or is abandoned.
- **`command_injection`/`path_traversal` on dvwa** -- genuinely re-earnable, but DVWA needs a login
  plus a `security=low` cookie, and the two candidate engines are `_run_cmdi` (a timing sweep,
  hundreds of requests) and `_run_web_probes` (INTRUSIVE; its own docstring records 28 POSTs and 28
  persisted rows against a write-observing lab). Neither belongs in a suite that runs on every
  change. They want a `liveness.py` CHECKS entry instead. Diff below.

## Numbers before and after

MEASURED via `techniques.taxonomy_view("owasp")`:

| | before | after |
|---|---|---|
| records carrying a badge (`claimed`) | 56 | 49 |
| badge pairs | 59 | 51 |
| `proven` (liveness-earned) | 24 | 24 |
| `unresolved_labs` | natas, sessionlife | sessionlife |
| `generalized` | 1 | 1 |

`proven` did not move, and that is the correct result: this ticket was not about raising it.
`generalized` was already gated on a liveness artifact (`techniques.generalized()`), so
`csti` and `vulnerable_component` were never counted there despite each naming two resolvable labs
-- that gate was already right, and this audit did not have to fix it.

## The gate, and its own negative control

`agent/tests/test_technique_badges.py`. It accepts exactly two things as backing for a
(technique, lab) pair: a `liveness.CHECKS` entry whose technique the COMMITTED baseline records as
confirmed, or a live re-run in that file that PASSED IN THIS SESSION. `DEBT` freezes the 24 pairs
that have neither, and the assertion is exact in both directions -- a debt entry that becomes backed
also fails, so the list cannot rot into a permanently-readable exemption.

Falsification, run from OUTSIDE the file (the only kind that counts):

    # temporarily: race_condition validated_on=["juiceshop", "mutillidae"]
    $ ... pytest tests/test_technique_badges.py -q
    E   AssertionError: 1 badge(s) claim a lab that nothing re-runs and that this audit never
        accepted: [('race_condition', 'mutillidae')].
    FAILED test_every_badge_is_backed_by_something_that_RUNS
    FAILED test_a_badge_on_a_lab_nothing_checks_is_reported
    FAILED test_the_gate_goes_red_when_a_REAL_record_gains_an_unchecked_lab
    # reverted; 9 passed

The skip coupling was also exercised: running a subset of the file (`-k test_every_badge_is_backed`)
goes red naming all three live re-earns, because a check that did not run backs nothing.

MEASURED, that this file does not corrupt the neighbouring gate: I re-implemented
`test_validated_on.py`'s `backed` heuristic and ran it with and without
`test_technique_badges.py` present. Both give `claims=49 backed=26 unbacked=23`, byte-identical
lists. That is by construction -- the new file never puts a technique id on a line that also names
the registry field, and never names that field inside a loop over technique ids, because the
neighbouring heuristic scans this directory's source text and would otherwise have marked ~24
unproven techniques as backed simply because the audit file mentions them.

Both strict xfails in `test_validated_on.py` still xfail after this change (verified in the run
below), so nothing was laundered into an XPASS.

## Patches for files this lane does not own

Hand these to the main thread. Each is small and each is the completion of something recorded above.

### 1. `agent/tests/test_authscan.py` -- unblock withdrawing `exposed_credentials`

    -    assert T.TECHNIQUES["exposed_credentials"]["validated_on"] == ["ginandjuice"]
    +    # Q-164: the badge was withdrawn -- no engine is bound to this id (engine_descriptor
    +    # reports routable=False) so no product run could have earned it. What this test is
    +    # really for is that the technique is REGISTERED and PLANNED, which the two assertions
    +    # around it already say. Pinning a proof claim here re-checked nothing.

Then in `agent/techniques.py`, `exposed_credentials`: `validated_on=[]`, and delete
`("exposed_credentials", "ginandjuice")` from `DEBT` in `agent/tests/test_technique_badges.py`.

### 2. `agent/liveness.py` -- promote the three live re-earns into the real gate

The re-runs currently live in a test file because `liveness.py` is not in this lane's write set.
They belong in `CHECKS`, where `scripts/liveness.sh` runs them and the ratchet protects them:

    +    # Q-164. The conpot half of snmp_default_community had no check -- liveness only drove
    +    # snmpd:161, and conpot publishes SNMP on 16100/udp (docker-compose.yml:343), so
    +    # conpot:161 answers nothing at all.
    +    {"technique": "snmp_default_community", "lab": "conpot", "kind": "tool",
    +     "tool": "_run_service_pack",
    +     "input": {"host": "conpot", "port": 16100, "service": "snmp"},
    +     "family": "snmp_default_community"},
    +    # Q-164. Pinned by TITLE: introspection and batching share family "graphql", which is the
    +    # exact confusion the graphql_introspection entry above already documents.
    +    {"technique": "graphql_batching_enabled", "lab": "dvga", "kind": "tool",
    +     "tool": "_run_graphql", "input": {"url": "http://dvga:5013/graphql"},
    +     "family": "graphql", "title": "batching"},
    +    # Q-164. The registry's first record, and nothing re-ran it for the whole life of the file.
    +    {"technique": "sqli_auth_bypass", "lab": "juiceshop", "kind": "tool",
    +     "tool": "_run_auth_sqli",
    +     "input": {"url": "http://juice-shop:3000/rest/user/login",
    +               "fields": ["email", "password"]},
    +     "family": "auth_bypass"},

and in `_LAB_ADDR`: `"juiceshop": ("juice-shop", 3000), "conpot16100": ...` -- conpot's existing
`("conpot", 5020)` entry already makes the host reachable, so no `_LAB_ADDR` change is needed for
the SNMP one.

MEASURED, so the first diff can be applied as written rather than trusted:
`_run_service_pack` forwards `int(port)` straight to `snmp_audit_tool.probe`, and driving it
through the real dispatch gives

    title="SNMP accepts a default community string ('public') at conpot:16100"
    family='snmp_default_community'  confidence='confirmed'
    evidence="The SNMP agent at conpot:16100 answered a GET with the documented default community..."

which is exactly what `liveness._match` requires (confirmed + family + >= 12 chars of evidence).

Once these are in `CHECKS` and the baseline is updated with `scripts/liveness.sh --update`, delete
the three live tests from `test_technique_badges.py` and its `_REEARN_DECLARED` set: they exist
only because the gate could not be reached from this lane.

DVWA (`command_injection`, `path_traversal`) wants the same treatment plus a login step; there is no
authenticated-lab shape in `CHECKS` today, which is why it is a recommendation and not a diff.

### 3. `agent/tests/test_validated_on.py` -- the mention heuristic

`test_every_validated_on_claim_is_backed_by_a_recorded_artifact` counts a technique as backed when
its id appears on any line of any test file that also contains the field name. Two of the ids it
currently calls backed are backed by nothing but an equality assertion. The heuristic should require
the id to appear in a test that INVOKES something -- or simply defer to
`test_technique_badges.liveness_pairs()`, which is derived rather than scanned. Not changed here:
the file is another lane's, and the xfail is a measurement, so weakening or widening it without
owning it would be the worse error.

## Could not classify

One, and only one:

- **`session_lifecycle` / `sessionlife`.** I can say what is true -- no compose service, no lab
  source and no registry entry at HEAD, a container running on this machine, and nothing anywhere
  that re-runs the technique -- but I cannot say whether the badge is STALE or about to become
  EARNED, because the lab is mid-landing in another lane's uncommitted working tree
  (`docker-compose.yml` modified, `labs/sessionlife/` untracked). Classifying it either way would
  be a guess about work I cannot see. It is on the debt list with that reason attached, so whichever
  way the other lane goes, the gate forces the question to be answered: if the lab lands and a check
  re-runs the technique, the debt entry must be deleted; if it does not, the badge must be.


