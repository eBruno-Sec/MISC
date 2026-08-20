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
