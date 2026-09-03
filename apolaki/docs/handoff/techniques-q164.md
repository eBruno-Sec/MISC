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

