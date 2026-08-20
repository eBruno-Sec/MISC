# Q-022 / Q-053 · report truthfulness — re-measured before any code was written

Lane: report-truthfulness (Builder). Baseline `505ed1c` — 3366 passed / 11 skipped / 12 xfailed / 0 failed.

**The ticket said Q-022 might already be closed by its own successor, and it is. So the first result
here is a disproof, measured against the live corpus in both rendered artifacts, not a build.**

---

## Measurement apparatus, and its positive control

Every number below is read out of the NAMED VOLUME, never a fixture and never `agent:/app`:

    MSYS_NO_PATHCONV=1 docker run --rm --network apolaki_default \
      -v "<repo>/apolaki/agent:/app" -v "apolaki_bbh_data:/data" -v "<scratch>:/meas" \
      -w /app apolaki-agent python /meas/q022_measure.py

    POSITIVE CONTROL  findings=1773 missions=154 tool_call_rows=29945 unparseable=0

Exactly the control the ticket named. A bare `agent:/app` mount gives an empty `/app/data` and every
count below is a silent zero — that false zero has been produced in this repo before.

---

# Q-022 · DISPROVED as open. 1054 findings with no control, 0 of them claiming one.

The ticket: *"626 of 660 findings print a declarative control claim with no recorded control."*

## The headline number, recomputed

    confirmed findings stored                            : 1381
      carry ANY recorded control artifact (top or nested):    3   (all bola)
      carry NONE                                          : 1378

**The 626/660 population no longer exists** (the corpus has grown 660 → 1381 confirmed), and Q-071
already recorded that the "34 carry a control" half was wrong — it is 3. So neither of the ticket's
two numbers reproduces. **That is not the disproof**; a wrong denominator does not make a claim
false. The disproof is that the *behaviour* those numbers were evidence for is gone:

    control_status over ALL 1773 stored findings:
       not_recorded     1054
       not_applicable    716
       recorded            3

    rendered HEADING distribution:
       False-positive safety: NOT ESTABLISHED for this finding                1054
       False-positive safety: rule-level counter-example (no request applies)  716
       How this was confirmed (false-positive safety)                            3

    Q-022 VIOLATIONS (no recorded control, yet the section reads as a record): 0

`negative_control_claim` is three-valued and gated on the artifact, the nested BIE location included
(Q-071 `b2b5051`), and the source-derived third value (Q-082) covers 716 of the 1773.

## The detector was proven able to fire — a zero is worthless without that

Feeding the detector the **pre-fix text** (`technique_model.proof_contract` keyed on family alone) as
it would have rendered on a real no-control `sqli` finding taken out of the corpus:

    DETECTOR NEGATIVE CONTROL: pre-fix (family-only proof_contract) text on a real
       no-control sqli finding would be flagged: True
       pre-fix text: 'An inert control of the same shape but without SQL metacharacters does NOT
                      reproduce the error/boolean/time differential; ...'

So the 0 above is a measured absence, not an apparatus that was never looking.

## END TO END, because a predicate returning the right dict is not the claim under test

Both renderers driven over the real corpus (11 missions, incl. all 3 carrying a recorded control):

    finding kinds covered by the render sweep: {'not_applicable': 716, 'not_recorded': 262, 'recorded': 3}
    MARKDOWN indicative-claim violations : 0
    HTML indicative-claim violations     : 0
    proof_and_retest text != negative_control_claim text: 0   <- oracle 3: one projection, two renderers

Non-vacuity is satisfied by the corpus itself: all three kinds are present in the swept set.

**Regression direction (Q-022 negative control (a)) — the honest case was not deleted:**

    mission 57cc3b49: md 'How this was confirmed' = 1, html = 1
    mission d2a651ca: md 'How this was confirmed' = 1, html = 1
    mission e33c1c96: md 'How this was confirmed' = 1, html = 1

**EMPTY-LEDGER negative control — a report rendered from nothing claims nothing:**

    md 'does NOT reproduce'                0 | html 0
    md 'How this was confirmed'            0 | html 0
    md 'NO NEGATIVE CONTROL WAS RECORDED'  0 | html 0

## Verdict

**Q-022 CLOSE as disproved.** The critical half — a fabricated confirmation narrative on findings that
never had a control — is gone from both artifacts, gated structurally on the stored artifact, and the
gate is pinned by `tests/test_proof_claim_matches_artifact.py` and `tests/test_nested_negative_control.py`
(whose fixtures are verbatim stored rows, which is why they caught the inversion the invented fixture
missed).

---

# Q-053 GAP-4 · the consumer half. 24 real findings were invisible to the entire ASVS model.

## Re-measured first, against the same live corpus

    security_misconfig + transport_posture stored : 24  (all confirmed, all found_by=transport_posture)
      Session cookie without a restrictive SameSite  4      <- cookie hardening on a REAL target
      No Content-Security-Policy                     4
      HSTS not enabled on an HTTPS origin            4
      MIME sniffing not disabled                     4
      No Referrer-Policy                             4
      No Permissions-Policy                          4
    objectives keyed on `security_misconfig`      :  0
    objectives keyed on `transport_posture`       :  0

The predecessor's numbers reproduce exactly. `map_findings` returned nothing for either family, so
every one of the 24 reached the client report with no verification property attached at all.

## The fix: CONF-02, a NEW key those families can carry honestly

`asvs_model.py` gains ONE objective:

    CONF-02  Baseline security configuration is hardened: transport posture, security response
             headers, session-cookie attributes and permitted HTTP methods.
             engine run_transport_posture | violated_by (security_misconfig, transport_posture)

**Q-048's refusal is NOT undone.** SESS-02 still keys only on `insecure_cookie`, and
`test_the_refusal_q048_made_is_not_undone` fails the moment anyone adds `security_misconfig` to it,
with a positive control in the other direction so it cannot be satisfied by a SESS-02 that never
fails at all.

**ONE umbrella objective and not three, and that is FORCED BY THE PRODUCER.**
`transport_posture.finding` picks the family with a single ternary (`transport_posture.py:404`) while
`kind` takes five values, so cookie, header and method findings share one label downstream. Two
objectives keyed on that one label would BOTH fail together -- a missing Permissions-Policy failing
"session cookies are hardened" -- which is exactly the false FAIL Q-048 refused. The honest key is a
property broad enough that all six titles genuinely violate it.

**A tag-keyed split HERE was considered and rejected.** The producer already carries the
discriminator (`tags: ["posture", kind, iid]`), so `map_findings` COULD read it. That would be a
second classification path able to drift from the producer's own label -- the "second copy of the
rule" defect (Q-015). The split belongs where the finding is built. Patch below.

## MEASURED behaviour, all four directions, fixtures built by the REAL producer

    header findings (kind=header) -> CONF-02 failed, 6 finding ids
    cookie finding  (kind=cookie) -> CONF-02 failed
    tls finding     (kind=tls)    -> CONF-02 failed   (family transport_posture, other ternary branch)
    hardened origin, engine RAN   -> CONF-02 verified
    engine never ran              -> CONF-02 not_tested        <- never "verified"
    header findings               -> SESS-02 NOT failed        <- Q-048's refusal, intact
    insecure_cookie finding       -> SESS-02 failed            <- positive control, other direction

End to end rather than at the predicate: the failed objective reaches the markdown "Failed
objectives" list, the HTML, and the client-facing rollup's `vulnerable` count.

## The near-miss that made four of Q-048's six objectives unfailable, ruled out by measurement

`_run_transport_posture` builds `ToolResult("transport_posture", ...)` -- the LABEL -- while
`_engines_from_ledger` reads the DISPATCH name. Over the 29,945 real `tool_call` rows:

    run_transport_posture : 13        transport_posture (as a dispatch name) : absent
    control, same query   : check_takeover 140, takeover absent

## Mutation tests, each verified as LANDED before the result was believed

    drop `security_misconfig` from CONF-02  -> 2 tests fail; the objective reads VERIFIED beside
                                              6 real violations (the flattering direction)
    engine := the ToolResult label          -> 8 tests fail (3 mine, 5 pre-existing)
    add `security_misconfig` to SESS-02     -> test_the_refusal_q048_made_is_not_undone fails

## One boundary crossed, declared rather than hidden

`agent/tests/test_asvs_model.py:461` pins the perfect-run verified tally as a constant (`== 28`).
Adding an objective moves it to 29, so that one line was updated. **It is not weakened**: the same
change adds `test_adding_the_objective_did_not_reclassify_an_existing_one`, which asserts total 34,
verified 29, not_implemented 1, blocked 2, not_tested 0 and the sum identity TOGETHER -- so a model
that dropped an objective to make room fails there even though the single constant would still read
plausibly. Flagged because that file is outside this lane's write list.

## STILL OPEN, and NOT fixed here because the files are not this lane's

**GAP-2 (dalfox, `tools.py`), GAP-3 (`sqli_tool.py`)**: GAP-3's producer landed (`auth_bypass`, see
AUTHN-02's note) and is already keyed. GAP-2 is untouched -- no commit in the tree references it.

**Patch for `agent/transport_posture.py:404`, handed off:**

    -        "family": "transport_posture" if kind in ("tls", "cert") else "security_misconfig",
    +        "family": {"tls": "transport_posture", "cert": "transport_posture",
    +                   "cookie": "insecure_cookie", "header": "security_headers",
    +                   "methods": "http_methods"}.get(kind, "security_misconfig"),

    CAUTION, and it is not optional: routing `kind="cookie"` to `insecure_cookie` makes those
    findings fail SESS-02 ("session cookies carry the Secure attribute, CWE-614"), and the SameSite
    finding is NOT a Secure-attribute finding. Either give cookie posture its own family
    (`cookie_posture`) or widen SESS-02's summary in the same commit -- doing one without the other
    reintroduces the exact false FAIL Q-048 refused. Once the split lands, CONF-02's `violated_by`
    should be narrowed to the header/method/transport families and the new cookie family keyed to
    its own objective; `test_asvs_transport_config_objective.py` will fail until it is, which is the
    coupling that keeps the two halves from drifting.

**Three families with NO objective at all, measured, NOT built here (proposals only):**

    weak_crypto  261 | weak_random 219 | weak_hash 153     (633 findings, all source-derived)
    open_redirect  6
    trust_boundary 83

`open_redirect` is the cheap one -- a single dispatchable producer (`run_injection_probes`) and a
standard ASVS property. The crypto trio is NOT cheap and must not be added carelessly: their producer
is source review, so a clean run over a repository that contains no cryptography at all would read
"verified: approved algorithms in use". That is a false verify with no finding able to contradict it,
and it needs a reachability precondition before the objective can exist honestly.
