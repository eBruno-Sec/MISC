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
- `snmp_default_community` claims `["conpot", "snmpd"]`. The CHECK targets `snmpd:161` only.
  Conpot does expose an SNMP service in its default template, but no check points at it.
  The `snmpd` half is EARNED, the `conpot` half is STALE.
- `dnp3_exposed` claims `["openfmb"]` while the check's lab key is `dnp3` at host
  `dnp3-outstation`. This is a naming alias, not a false claim: the DNP3 outstation container
  IS the OpenFMB adapter (`agent/liveness.py` comment says so explicitly). Recorded as EARNED
  with an alias note; `openfmb` only exists in `known_labs()` because this technique vouches
  for it (`techniques._liveness_vouched_labs`).

### Group B -- 32 techniques with NO liveness check

Candidate re-runners still to check for these: `agent/tests/`, `agent/benchmark.py`,
`agent/bwapp_solvers.py`, `agent/capability_matrix.py`, `scripts/`. Findings below.

(in progress -- see next section)
