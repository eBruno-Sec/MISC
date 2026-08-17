# routing lane — Q-066 / Q-020 / Q-065

One root cause, one ticket. This file records what HAPPENED, in order. Every claim is MEASURED
(command + real output) or UNVERIFIED.

Apparatus for every measurement below, unless stated otherwise:

```
MSYS_NO_PATHCONV=1 docker run --rm --network apolaki_default -e PYTHONPATH=/app \
  -v "<repo>/agent:/app" -v "<scratch>:/probe" -w /app apolaki-agent python /probe/probe_join.py
```

---

## STEP 1 — does a join already exist? MEASURED: NO. But the ticket's mechanism is wrong.

**Verdict: no join exists, and Q-066's DoD stands. The ticket's headline measurement is a category
error that points the fix at the wrong pair of tables.**

### What I read (field/attribute names stated, because two probes in this thread lied about theirs)

- `tools.TOOL_PERMISSIONS` — dict, **keys** are the registered engine names. 111.
- `tools.CLAUDE_TOOLS` — list of dicts, **`["name"]`** per item. 76.
- `techniques.TECHNIQUES` — dict, **keys** are technique ids. 88.
- `engine_descriptor.PRECONDITIONS` / `.EFFECTS` / `.ALWAYS_ON` — dict **keys**. 42 / 13 / 45.
- `engine_descriptor.build()` -> `{id: descriptor}`, and `descriptor()`'s full **output keys**.
- every field name present on every technique record, enumerated rather than guessed (25 of them).
- `asvs_model` rows, **`["engine"]`**.

Positive control for the apparatus: `"run_jwt" in tools.TOOL_PERMISSIONS` -> `True`. The registry
was loaded and readable, so a zero below is a fact and not an empty instrument.

### M1 — EFFECTS and PRECONDITIONS are the SAME vocabulary. This is the ticket's error.

```
EFFECTS keys that ARE technique ids   : 13 of 13
EFFECTS keys that ARE engine names    :  0 of 13
PRECONDITIONS keys that ARE tech ids  : 42 of 42
PRECONDITIONS keys that ARE engines   :  0 of 42
technique ids that ARE engine names   :  0 of 88
EFFECTS keys NOT in PRECONDITIONS     : ['browser_persona_bola', 'graphql_introspection']
```

The ticket reads `PRECONDITIONS 42 of 42 ARE technique ids -> techniques DO bind here` against
`EFFECTS 0 of 13 are registered engine names -> nothing binds to the engine registry`. Those two
rows are measured against **different reference sets**, which makes the contrast an artifact of the
probe rather than a property of the code. Measured against the same set: **PRECONDITIONS binds to
the engine registry exactly as poorly as EFFECTS does — 0 of 42.** `jwt_forge` and
`jwt_key_confusion` are not a separate "capability vocabulary": both are technique ids and both
appear in `PRECONDITIONS` (lines 77 and 89) as well as `EFFECTS`.

So the defect is NOT "effects speak a different language from preconditions". They speak the same
one. The defect is that **the technique vocabulary as a whole has no route to the engine registry**,
and that is true for all 88 techniques, not the 13 with effects.

### M2 — no technique record carries an engine binding, in any field

Exact value equality against the 111 registered names, over every field on every record:

```
union of record field names: ['backfill_claim', 'cleanup', 'cwe', 'detect', 'evidence_requirements',
  'execution', 'exploit', 'fixture_source', 'id', 'maps_to', 'mitre', 'needs_fixture',
  'negative_control', 'oracle', 'owasp', 'pack', 'permission', 'refs', 'replayable', 'safety',
  'summary', 'transferable', 'validated_on', 'vuln_class', 'wstg']
fields whose VALUE is exactly a registered engine name: NONE
prose fields mentioning a real engine (run_*/confirm_* token): NONE
```

The prose fields name *modules* (`jwt_tool`, `sqli_tool`, `saml_tool`), never *engines*. A module is
not dispatchable.

### M5 — `descriptor()` and `build()` add nothing. This is the part the Coordinator could not see.

The ticket correctly flagged that only the public surface had been checked. I read the function
bodies. `descriptor(tech, preconditions, always_on)` emits exactly these keys:

```
['always_on','auto','establishes','id','invalidates','oracle','permission','reached_by',
 'requires','transferable','vuln_class']
```

No `engine`, `tool`, `executor` or `dispatch` key. `build()` is `{t["id"]: descriptor(...)}` over
`techniques.TECHNIQUES` — it introduces no new field. **A join is not hiding inside `build()` or
`descriptor()`.**

Positive control that the apparatus would have SEEN an engine binding: the same probe read
`asvs_model` and found **29 of 33 rows carry `["engine"]`**. The instrument detects engine bindings
where they exist.

### M3 — the one join that DOES exist, and its exact extent

`ALWAYS_ON` values are prose reasons, and 23 of them name a real engine in that prose.
`engine_descriptor.verify_always_on()` already exploits this: it extracts identifiers from the
reason and proves each is referenced from code that runs.

```
ALWAYS_ON reasons naming >=1 registered engine: 23 of 45
ALWAYS_ON naming NO registered engine: client_side_authz, client_supplied_identity_param,
  crlf_injection, dnp3_exposed, encoded_data_decode, enip_exposed, ipmi_rakp, ldap_anonymous_read,
  missing_authentication, modbus_exposed, ntp_monlist, rdp_no_nla, rsync_anon, s7comm_exposed,
  security_misconfig_errors, smb_null_session, smb_signing_disabled, snmp_default_community, ssti,
  vnc_no_auth, vulnerable_component, weak_ssh_crypto
```

### M4 — the evidence-gated half has no route at all

```
PRECONDITIONS techniques with an ALWAYS_ON engine name: 0 of 42
PRECONDITIONS techniques with NO route to any engine  : 42 of 42
```

`jwt_forge`, `jwt_key_confusion` and `weak_secret_forgery` are all in that 42.

### Independent corroboration already in the tree

`agent/report.py:1831` states the same fact, reached from the reporting side by the Q-051 lane:

> a technique record carries `maps_to`, `validated_on` and `oracle`, but NO engine binding, so
> nothing links a technique to the tools a mission dispatched

That text is rendered to the reader in both renderers (`report.py:1852` and `:3009`). So the
platform already TELLS the operator it cannot answer "which techniques ran". Q-066 is the same hole
seen from the planner side.

### A correction to Q-065's concrete case, MEASURED

The ticket pairs `run_jwt` with `weak_secret_forgery`. Those are not the same capability.
`techniques.py:832` — `weak_secret_forgery` is CWE-330, "forge a signed artifact (token/coupon/
continue-code) whose secret is weak", precondition `has_coupon`, validated on the Juice Shop
*Forged Coupon* challenge. The JWT techniques are `jwt_forge` / `jwt_key_confusion`, CWE-347,
precondition `authenticated`. Whatever emitted `weak_secret_forgery` was not naming `run_jwt`'s
capability. `codeintel.py:57` binds source-pattern rule `weak_crypto` -> technique
`weak_secret_forgery`, which is a plausible emitter of that string on a JS-heavy target.

This does not weaken Q-066 — it is another instance of the same shape (a technique id surfaced to
the operator with no route to an engine). It does mean the "`run_jwt` never fires" symptom needs its
own measurement rather than being assumed to be a routing miss; see the note under Step 2.

### Status at end of Step 1

- Q-066: **CONFIRMED, reframed.** No join exists. The gap is technique-registry-to-engine-registry,
  all 88 techniques, not effects-vs-preconditions.
- Q-020 / Q-065: still bound to Q-066, not closed separately.
- Nothing built yet. No code written at this point.
