# boolean-oracle lane -- Q-040 and the confirmation-oracle stability audit

Lane: Builder. Files owned: `agent/sqli_tool.py`, `agent/nosqli_tool.py`,
`agent/tests/test_sqli_boolean_noise_floor.py`, new tests, this file.
`agent/tools.py` is NOT this lane's file; every call-site change wanted is written out below as a
patch, not applied.

Written as the work happens. Each section is MEASURED (command + real output) or UNVERIFIED.

---

## 1. The first result: the ticket and the pin are DIFFERENT HALVES, and one of them is closed

The brief warned this might be the whole answer. It is a large part of it.

### The ticket half is CLOSED, and `docs/QUEUE.md` is stale

`docs/QUEUE.md` Q-040 says:

> `tests/test_sqli_oracle_negative_controls.py::test_an_unstable_page_must_not_confirm_blind_sqli`.
> **An unstable page confirms blind SQLi.** ... Fix: the oracle must re-sample the baseline and
> prove stability before crediting a boolean differential. Remove the marker only then.

MEASURED: that test has no marker. It is a plain passing test at
`agent/tests/test_sqli_oracle_negative_controls.py:51`, and `sqli.analyze_boolean` does have the
control the ticket asks for -- `agent/sqli_tool.py:166-177`, added by commit `cbcba79`:

    refs = None
    if baseline_samples is not None:      refs = [baseline] + list(baseline_samples)
    elif baseline_repeat is not _MISSING: refs = [baseline, baseline_repeat]
    if refs is not None:
        if len(refs) < 2 or any(r is None for r in refs):  return False
        if any(r != refs[0] for r in refs):                return False

It demands byte EQUALITY from the reference pair, not a similarity threshold -- the traversal
precedent the brief points at, applied. The production call site supplies it: `tools.py:7416-7421`
takes `sqli.BOOLEAN_BASELINE_SAMPLE_COUNT` samples and passes `baseline_repeat=base_repeat_body`
(`tools.py:7470`), and the POST-form carrier does the same at `tools.py:7543`. It is not an island;
`test_sqli_stability.py:209` is an AST guard that fails if a carrier stops passing it.

**So the QUEUE.md text for Q-040 describes a state of the world that ended at `cbcba79`.** Anyone
reading the queue alone would re-implement a control that is already there and already wired.

### The pin half is a PROOF, not a to-do, and it is not closable in this lane

`agent/tests/test_sqli_boolean_noise_floor.py:123` pins something much narrower: the residual
`BenchmarkTest00494` shape, where BOTH reference samples land in the same run of an alternating
page. Its reason says "PROVABLY not closable in analyze_boolean" and that is correct and is proved
executably one screen below it, at
`test_the_00494_shape_is_undecidable_at_the_two_sample_signature`: the four strings
`(A, A, A, B)` are produced BOTH by a genuine injection on a deterministic page AND by an
alternating page that flipped after the third request. Identical arguments, opposite ground truth.
No pure function of those four strings can separate them.

**Consequence: this xfail cannot be made to XPASS by any change to `analyze_boolean`, and any
change that did make it XPASS would necessarily also break
`test_a_byte_stable_page_with_a_real_differential_still_confirms` (the same input shape with the
opposite ground truth) -- i.e. it would blind the oracle.** The strict xfail is therefore KEPT, and
keeping it is the correct outcome, not a failure to finish. What closes it is one more OBSERVATION
from the transport, and `analyze_boolean` already accepts both forms of it
(`baseline_samples` with an after-probe sample, or `false_repeat`), both covered by passing tests
at `test_sqli_boolean_noise_floor.py:169` and `:187`. The missing piece is in `tools.py`, which
this lane does not own. Patch in section 5.

---

## 2. The half that is genuinely OPEN, and it is in this lane's files

Two defects, both real, both in `agent/nosqli_tool.py` and `agent/sqli_tool.py`.

### 2a. `nosqli.analyze_boolean` has NO baseline-stability control at all

Same defect class as Q-040, same family (a blind boolean injection oracle), never pinned, never
noticed -- because Q-040 was written about the SQL oracle and nobody asked whether its sibling had
the same hole.

MEASURED, by reading the signature and the only call site:

* `agent/nosqli_tool.py:119` -- `analyze_boolean(baseline, operator_body, control_body,
  missing_body=None, thresh=0.97)`. No reference-sample parameter exists.
* `agent/tools.py:7846` -- `base_r = await get(c, url)`. ONE baseline sample. There is no repeat
  request anywhere on this path, so there is nothing to compare even if the oracle wanted to.

The oracle then fingerprints the endpoint from that single sample (`frag = _row_fragment(b)`) and
decides containment against it. If the endpoint's output is not a function of its input, that
fingerprint is a fingerprint of one moment.

MEASURED consequence, live, section 3b: **0.229 false positives per attempt on a clean lab
endpoint -- the exact rate the SQL oracle had before `cbcba79`.**

### 2b. Both oracles fold "I could not measure this" into "clean"

`analyze_boolean` returns `bool`. `False` currently means two different things:

* the reference reproduced and the differential was not there -- a real negative; and
* the reference did NOT reproduce, so the oracle refused to decide -- not a result at all.

`agent/sqli_tool.py:174` and `:177` both `return False` on the refusal path. The engine then reports
`"tested N param(s), 0 confirmed"` for an endpoint it could not measure. That is the third-outcome
defect Q-063/Q-067 landed on: a correct "I could not establish this" folded into a neighbouring
class.

---

## 3. Measurements

All against live authorized local labs, from a throwaway container on `apolaki_default`.

### 3a. Per-request stability sweep -- which live endpoints are measurable at all

12 byte-identical GETs per endpoint, counting distinct response bodies:

    juice-shop:3000/rest/products/search?q=apple    distinct  1/12
    juice-shop:3000/api/Products                    distinct  1/12
    juice-shop:3000/api/Feedbacks                   distinct  1/6
    juice-shop:3000/api/Challenges                  distinct  1/6
    juice-shop:3000/api/Quantitys                   distinct  1/6
    juice-shop:3000/rest/products/1/reviews         distinct  1/6      <- Mongo-backed, STABLE
    juice-shop:3000/rest/track-order/5267-...       distinct  1/8
    vampi:5000/books/v1                             distinct  1/6
    vampi:5000/users/v1                             distinct  1/6
    juice-shop:3000/metrics                         distinct 12/12     <- counter, real noise
    juice-shop:3000/rest/captcha                    distinct 12/12     <- fresh nonce, real noise
    owaspbench:8443/.../BenchmarkTest00023          distinct 12/12     <- java.util.Random

`GET /rest/captcha` is the fixture this lane uses for a noisy JSON endpoint and
`GET /rest/products/1/reviews` for a stable one. Both are transcribed from the responses above, not
invented.

### 3b. THE HEADLINE MEASUREMENT: `nosqli` false-positives on a live lab at the PRE-FIX sqli rate

`POST https://owaspbench:8443/benchmark/cmdi-00/BenchmarkTest00494` with `productID=1&foo=1`, 16
byte-identical requests. This is a CLEAN `cmdi` case -- the application never reads the field --
so every `True` any boolean oracle returns on these bodies is a false positive by construction.

    live distinct states                        2 of 16   (368-byte body, sim(A,B) = 0.9091)
    fixtures NOISE_A/NOISE_B match live         True      (byte-identical to the recorded pair)
    arrival order                               AABAAABBAAABBAAA   <- RUNS, not alternation

Ordered triples over those 16 real responses, the reference sample being the REAL NEXT response in
the sequence (`bs[i+1]`), which is exactly what `tools.py` takes:

    oracle                                        fires        rate
    sqli.analyze_boolean, ungated (pre-cbcba79)   720/3150     0.229
    sqli.analyze_boolean, gated (cbcba79)         438/3150     0.139
    nosqli.analyze_boolean (NO gate exists)       720/3150     0.229

Three things this settles:

1. **`nosqli` is sitting at the exact pre-Q-040 false-positive rate**, 0.229, identical to the
   ungated SQL oracle on the same bodies. The defect in section 2a is not theoretical.
2. The SQL gate **helps and does not fix**: 0.229 -> 0.139. That independently reproduces the
   measurement in the pin's own docstring (0.225 -> 0.150), from a fresh 2026-08-17 run, and it
   reproduces the REASON -- the run structure `AABAAABBAAABBAAA` means two consecutive reference
   samples usually land in the same run, so the gate passes and the oracle confirms. The residual
   is real, is not closable at this signature, and needs patch 5e.
3. Why `nosqli` fires: its body does not start with `[`, so `_row_fragment` returns the WHOLE
   baseline, and `frag in operator_body` is satisfied whenever the operator response happens to be
   byte-identical to the baseline while the control landed in the other state. No injection
   required.

### 3c. NEGATIVE RESULT: whole-body churn does not false-positive either oracle

The same sweep over 8 real `GET /rest/captcha` bodies (12/12 distinct):

    nosqli.analyze_boolean  fires 0/336
    sqli.analyze_boolean    fires 0/336   (ungated)

Positive control for that zero: the identical sweep code, on the `BenchmarkTest00494` bodies above,
fires 720/3150. So the apparatus was looking; the zero is a property of the captcha shape.

The honest reading of the zero: **on whole-body churn the failure is in the OTHER direction.**
Containment (`frag in body`) needs the operator response to contain the entire baseline verbatim,
which a churning body never does, so the oracle returns `False` -- and `False` is reported to the
operator as "tested, clean". An endpoint whose output is not a function of its input is reported as
measured. That is defect 2b, measured live.

One measurement did NOT reproduce and is recorded as such: the sweep over 12 live
`BenchmarkTest00023` weakrand bodies fired **0/1320 ungated**, not the 9.4% quoted in
`test_weak_random_noise_must_not_confirm_at_scale`'s docstring. That shape sits on the threshold
(pairwise 0.9495..0.9766 against a 0.95 cut), so whether any triple fires depends on the exact
digit strings drawn that minute. The docstring's figure is over 123 curated bodies and is not
contradicted, but it is not a positive control either, and this lane does not cite it as one.

---

## 4. What this lane changed

Slice log; each row is its own commit.

| # | slice | state |
|---|-------|-------|
| 0 | diagnosis + this document + real fixtures captured | done |
| 1 | `INCONCLUSIVE` third outcome in `sqli.analyze_boolean` | done |
| 2 | reference-reproduction control + `INCONCLUSIVE` in `nosqli.analyze_boolean` | done |
| 3 | call-site pin for the un-wired nosqli reference sample | done |
| 4 | mutation tests, verified applied | done |
| 5 | confirmation-oracle stability audit (anti-idle) | done |

---

## 5. PATCHES WANTED IN FILES THIS LANE DOES NOT OWN

### 5a. `agent/tools.py` `_run_nosqli` -- take a reference sample (REQUIRED to make slice 2 live)

Slice 2 adds the control but it is INERT until this lands, because the parameter is optional (it
has to be: making it required would break the existing positional call site instantly). Pinned by a
strict xfail in `agent/tests/test_boolean_oracle_stability.py` so that applying this patch turns the
suite RED and forces the marker off, exactly as `test_sqli_stability.py:209` does for the SQL side.

At `agent/tools.py:7846`:

    -            base_r = await get(c, url)
    -            base_body = base_r.text if base_r is not None else ""
    +            base_r = await get(c, url)
    +            base_body = base_r.text if base_r is not None else ""
    +            # Q-040 sibling: the reference request is identical by construction, so on an
    +            # endpoint this oracle can measure at all it MUST come back byte-identical.
    +            base_repeat_body = None
    +            if base_r is not None and params:
    +                _rep = await get(c, url)
    +                base_repeat_body = _rep.text if _rep is not None else None

and at `agent/tools.py:7880`:

    -                    if ns.analyze_boolean(base_body, op_r.text, ctl_body, miss_body):
    +                    _v = ns.analyze_boolean(base_body, op_r.text, ctl_body, miss_body,
    +                                            baseline_repeat=base_repeat_body)
    +                    if _v:

Cost: exactly one extra request per `_run_nosqli` call, not per param -- the same shape and the same
bound `_run_sqli` already pays.

### 5b. `agent/tools.py` -- surface the INCONCLUSIVE verdict on the ledger's typed channel

`nosqli_tool.INCONCLUSIVE_TOKEN` / `sqli_tool.INCONCLUSIVE_TOKEN` is `"NOT MEASURABLE:"`, a sibling
of `main.NEGATIVE_RESULT_TOKEN` (`"NOT PRESENT:"`) with the same contract: a PREFIX the consumer
prefix-matches, never English the consumer classifies. It is deliberately NOT the same literal --
"the thing is not here" and "I could not establish whether the thing is here" are different
verdicts, and folding the second into the first is the same lie in the opposite direction.

In `_run_nosqli`, collect the refusals and return them instead of a bare success:

    +            inconclusive = []                       # near the top, beside `findings, ev = [], []`
    ...
    +                    if ns.is_inconclusive(_v):
    +                        inconclusive.append("%s: %s" % (p, _v.reason))
    ...
    -        return ToolResult("nosqli", url, True,
    -                          f"tested {len(params)} param(s), {len(findings)} confirmed NoSQL injection", findings)
    +        if inconclusive and not findings:
    +            return ToolResult("nosqli", url, False, "", [],
    +                              ns.INCONCLUSIVE_TOKEN + " " + "; ".join(inconclusive[:3]))
    +        return ToolResult("nosqli", url, True,
    +                          f"tested {len(params)} param(s), {len(findings)} confirmed NoSQL injection", findings)

Same shape for `_run_sqli`'s two boolean call sites.

### 5c. `agent/main.py` -- a fourth ledger class, or an explicit decision not to have one

`main._tool_ledger` (`agent/main.py:998`) splits `scope_block` / `tool_negative` / error. A
`"NOT MEASURABLE:"` row currently falls to the `else` branch and reads as `a["error"]`, i.e. a
broken engine. That is better than the status quo (silently clean) but still wrong: the engine
worked and returned a correct verdict of "undecidable here".

Wanted: an `a["inconclusive"]` counter beside `a["negatives"]`, prefix-matched on
`INCONCLUSIVE_TOKEN`, so the Arsenal-coverage summary can say "ran, could not decide" instead of
"errored". `agent/main.py` is not this lane's file and the change is one `elif`.

### 5d. `docs/QUEUE.md` -- Q-040's text is stale (section 1)

Wanted: rewrite the Q-040 entry to say the baseline-stability control shipped in `cbcba79`, that
the live pin is the narrower undecidable residual in `test_sqli_boolean_noise_floor.py`, and that
what closes it is patch 5e, not a change to the oracle.

### 5e. `agent/tools.py` `_run_sqli` -- the after-probe reference sample that closes the residual

This is the one that actually retires the strict xfail. `analyze_boolean` already accepts it and
`test_an_after_probe_reference_sample_closes_the_alternating_page` already proves it works; the
transport simply never takes the sample. Inside the `for pair in sqli.boolean_payloads(orig)` loop
at `agent/tools.py:7463`:

    Send TRUE, send FALSE, then send ONE more unprobed baseline request, and call

        sqli.analyze_boolean(base_body, rt.text, rf.text,
                             baseline_samples=[base_repeat_body, after_probe_body])

    The reference then SPANS the probe window. Either the page held one state across it -- in which
    case TRUE and FALSE are inside that state too and there is no divergence to report -- or it
    flipped, and the after-probe sample no longer reproduces, so the oracle declines.

Cost: one extra request per confirmed-looking pair. Bound it to the pair that is about to confirm
(evaluate the cheap two-sample form first, only pay for the third sample when it says True), so the
common no-injection case pays nothing.
