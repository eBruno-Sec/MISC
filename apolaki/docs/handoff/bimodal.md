# bimodal lane -- Q-070: one repeat cannot establish stability on a BIMODAL page

Lane: Builder. Files owned: `agent/sqli_tool.py`, `agent/nosqli_tool.py`,
`agent/tests/test_boolean_oracle_stability.py`, `agent/tests/test_sqli_boolean_noise_floor.py`,
new tests, this file. `agent/tools.py` is NOT this lane's file; every call-site change wanted is
written out below as a patch, not applied.

Written as the work happens. Every row is MEASURED (command + real output) or UNVERIFIED.

---

## 1. The 18 reproduced, and every one of them is the SAME shape

MEASURED. Throwaway container on `apolaki_default`, current `main`:

```
python - <<'PY'   # itertools.permutations(bodies, 3), ref = bodies[(i+1) % 6]
bodies = [NOISE_A, NOISE_A, NOISE_B, NOISE_A, NOISE_B, NOISE_B]
PY
total triples: 120
ungated: 36  gated: 18
  (A,A,B) ref=A            x10
  (B,B,A) ref=B            x8
len(A)=368 len(B)=358
A in B: False  B in A: False
```

So the 18 are not a scatter of near-misses. They are **exactly** the triples where

* the baseline and the OPERATOR response are the same state (`op == baseline`, byte-for-byte), and
* the CONTROL landed in the other state, and
* the single reference repeat landed in the baseline's state.

That is the shape `test_the_00494_shape_is_undecidable_at_the_two_sample_signature` proves is
undecidable **for the sqli oracle**, whose evidence is `similar()`. The nosqli oracle's evidence is
CONTAINMENT, and containment has an asymmetry `similar()` does not -- see section 3.

`ungated: 36` is the sweep's own positive control: the apparatus fires when the gate is removed, so
the gated count is a measurement rather than an artefact of a sweep that could never fire.

---

## 2. What the call sites actually supply today (read-only; `tools.py` is not this lane's file)

MEASURED by reading `agent/tools.py`:

| carrier | reference samples taken | passed to the oracle |
|---|---|---|
| `_run_sqli` query lane (`tools.py:7457-7463`) | `sqli.BOOLEAN_BASELINE_SAMPLE_COUNT` = 2, **once per call**, before the param loop | `baseline_repeat=base_samples[1]` (`:7513`) |
| `_run_sqli` POST-form lane (`tools.py:7558-7566`) | 2, **per form field** | `baseline_repeat=fbase_samples[1]` (`:7586`) |
| `_run_nosqli` (`tools.py:7890`) | 1 (the baseline itself) | nothing -- the gate is inert, pinned by an existing strict xfail |

Two consequences that decide the whole ticket:

1. `BOOLEAN_BASELINE_SAMPLE_COUNT` lives in **this lane's file**, so the SAMPLE COUNT is under this
   lane's control -- but the call site forwards only `base_samples[1]`, so raising the constant
   alone buys extra requests and no extra evidence. Raising it is only correct together with the
   one-line patch in section 6.
2. Therefore **any change that makes 2+ repeats REQUIRED for a confirmation drops production sqli
   boolean recall to zero until another lane applies that patch.** That is the false-negative half
   of the trap, and it is why the N-sample control is shipped as a measured, documented, opt-in
   strengthening rather than as a new hard requirement.

---

## 3. The live capture, and the thing nobody would have guessed

MEASURED 2026-08-18. 40 byte-identical POSTs to
`https://owaspbench:8443/benchmark/cmdi-00/BenchmarkTest00494` with `productID=1&foo=1`, plus a
replay of the five boolean-blind true positives and of a stable NoSQL-shaped page. Every body used
below comes out of that capture; nothing is invented.

```
LIVE BIMODAL PAGE  https://owaspbench:8443/benchmark/cmdi-00/BenchmarkTest00494
  n=40 distinct=2   arrival: AABBBAABBBAABBBAABBBAABBBAABBBAABBBAABBB
  state lengths: [368, 358]
  pairwise similarity: 0.9091
  run lengths: [2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3]
  pinned NOISE_A/NOISE_B still byte-equal to a live state: True / True
```

**It is a PERIOD-5 CYCLE, not a coin.** The ticket's model ("lands in the same state roughly half
the time") is right about the rate and wrong about the mechanism, and the mechanism is what sets
the answer: **the longest run is 3**, so three agreeing references cannot be produced by anything
except a run of exactly 3, and the probe pair that follows one is then forced into the next run
TOGETHER. The 2026-08-17 capture in the pin's docstring (`AABAAABBAAABBAAA`) has the same
run-structured character. Nobody would have guessed a resolver cycle of period 5; it had to be
measured, which is exactly what "choose by measurement, not by taste" is for.

The five true positives and the stable NoSQL page, same capture:

```
RECALL -- the five live boolean-blind true positives, POST-form lane
  00033  baselines 1 distinct in 6   via ['string-quote', 'string-comment']
  00428  baselines 1 distinct in 6   via ['string-quote', 'string-comment']
  00429  baselines 1 distinct in 6   via ['string-quote', 'string-comment']
  00433  baselines 1 distinct in 6   via ['string-quote', 'string-comment']
  00438  baselines 1 distinct in 6   via ['string-quote', 'string-comment']
  http://juice-shop:3000/rest/languages: 1 distinct in 6
```

A genuinely stable target is stable at ANY sample count. That is why the false-negative half of the
trap is answerable at all.

---

## 4. THE FIX, and it is not the one the ticket expected

The 18 are not a sampling problem in disguise. They are a DEGENERATE FINGERPRINT.

`_row_fragment` strips one enclosing `[...]` pair so the containment test can ask "does the operator
response contain the baseline's ROWS, plus more". `BenchmarkTest00494` serves an HTML page. There is
no bracket pair to strip, so `frag` is the WHOLE body and `frag in op` collapses into `op ==
baseline` -- which is not a broadening test at all. It is satisfied by a page that simply did not
change, and a bimodal page hands that out for free.

So the confirmation criterion now demands the operator response be EVIDENCE of broadening
(`agent/nosqli_tool.py`):

```python
    if not (_matches(op) and not _matches(ctl)):
        return False
    if not (_is_row_collection(b) or len(op) > len(b)):
        return False
    return True
```

Either the fingerprint really is a set of rows inside an envelope this function can open, or the
operator response literally carried more than the baseline did. With neither, all that was observed
is "the operator response equals the baseline while the garbage-value control landed elsewhere".

**This was already a documented bound, not a new opinion.**
`test_the_nosqli_containment_oracle_only_fires_on_a_bare_array` has said since Q-040 that on an
object-wrapped body "the fingerprint is the WHOLE body ... so this oracle is structurally incapable
of confirming on those APIs". Q-070 promotes that observation to an enforced precondition, because
the one thing the degenerate fingerprint COULD still confirm on was noise.

MEASURED, `agent/tests/test_boolean_oracle_stability.py` and the live sweep:

| candidate | pin's 120 ordered triples | FP/attempt, live arrival sequence |
|---|---:|---:|
| ungated, containment as shipped | 36 / 120 | 0.395 (15/38) |
| Q-040 gate, 1 repeat (**the pinned residual**) | **18 / 120** | 0.189 (7/37) |
| Q-040 gate, 2 repeats | 7 / 120 | 0.000 (0/36) |
| **Q-070, broadening required, no repeat at all** | **0 / 120** | **0.000 (0/38)** |

**Cost: zero extra requests.** And the 18 were enumerated, not counted: `(A,A,B) ref=A` x10 and
`(B,B,A) ref=B` x8 -- one shape, entirely inside the degenerate fingerprint.

### RECALL, measured on the same day's live bodies

* `GET http://juice-shop:3000/rest/languages` (1 distinct body in 6 identical requests). A real
  one-row baseline broadened to the real 42-row array: **still confirms**, under the old rule and
  the new one. The same call on `(baseline, baseline, other)` fires under the old rule and does
  not under the new one -- which is the whole change, stated as a pair.
* No recorded benchmark claim in `docs/benchmarks/` contains a `NoSQL injection (boolean-blind)`
  finding (`grep -rl` returns nothing), so **no benchmark number moves**. There is nothing to
  re-measure and nothing was special-cased.
* The false negative this buys is real and narrow, and is stated rather than hidden: a `$ne`
  bypass on a NON-array body whose broadened response does not literally contain the entire
  baseline body no longer confirms. On the labs available that set is empty, because an
  object-wrapped broadening never contains its own envelope verbatim -- the bound the pinned test
  already described.

### What this does NOT close

Bimodality itself. A bimodal endpoint that serves a BARE ARRAY presents the same coin flip, and
nothing but more reference samples answers that. Section 5 is that half.

---

## 5. WHAT N COSTS, and the one-line patch that makes it real

`analyze_boolean` has accepted `baseline_samples` since Q-040. It is INERT: `tools.py` takes
`BOOLEAN_BASELINE_SAMPLE_COUNT` samples and forwards `base_samples[1]` only.

MEASURED through the real `sqli.analyze_boolean`, sliding the transport's actual request order
(baseline, N-1 repeats, TRUE, FALSE) along the real 40-sample arrival sequence. Recall is the five
live true positives, replayed the same day:

| N | references supplied | FP/attempt on the bimodal page | live true positives confirming |
|---:|---|---:|---:|
| 1 | none (ungated) | 0.395 (15/38) | 5 of 5 |
| 2 | 1 repeat -- **what ships today** | 0.189 (7/37) | 5 of 5 |
| 3 | 2 repeats | **0.000** (0/36) | 5 of 5 |
| 4 | 3 repeats | 0.000 (0/35) | 5 of 5 |

**N buys precision at the price of REQUESTS, not at the price of recall.** All five true positives
return one distinct body in six identical requests, so every extra reference is another copy of the
same bytes.

The request price, since this runs per candidate parameter in a sweep:

* **query-string carrier** (`tools.py:7457-7463`): samples are taken ONCE per `_run_sqli` call,
  BEFORE the parameter loop, so N-1 extra requests amortise over every parameter and every payload
  pair. Against ~8 boolean requests per parameter alone, N=4 is under +5% on a two-parameter URL.
* **POST-form carrier** (`tools.py:7558-7566`): samples are taken inside the FIELD loop, so the
  cost is N-1 per field and does NOT amortise. This is the expensive side, and it is also the lane
  that carries every boolean-blind confirmation on this benchmark.

Honest bound on the N=3 zero: it is this page's longest run (3) that makes 3 references sufficient.
A page with longer runs needs a larger N, and the run length is not knowable in advance. More
samples strictly dominate fewer; no N is a proof.

### 5a. PATCH WANTED -- `agent/tools.py`, forward the samples already being taken

Not applied: `agent/tools.py` is not this lane's file. Two hunks, both one line, plus the constant.

```diff
--- a/agent/tools.py       # _run_sqli, query-string carrier, line ~7513
-                     if sqli.analyze_boolean(
-                             base_body, rt.text, rf.text, baseline_repeat=base_repeat_body):
+                     if sqli.analyze_boolean(
+                             base_body, rt.text, rf.text, baseline_samples=base_samples[1:]):

--- a/agent/tools.py       # _run_sqli, POST-form carrier, line ~7586
-                             if sqli.analyze_boolean(
-                                     fbody, rt.text, rf.text, baseline_repeat=fbody_repeat):
+                             if sqli.analyze_boolean(
+                                     fbody, rt.text, rf.text, baseline_samples=fbase_samples[1:]):

--- a/agent/sqli_tool.py   # this lane's file, and it must land in the SAME commit
-BOOLEAN_BASELINE_SAMPLE_COUNT = 2
+BOOLEAN_BASELINE_SAMPLE_COUNT = 4
```

`base_repeat_body` / `fbody_repeat` then become unused and should go. Note the existing guard
`base_samples[1] if len(base_samples) > 1 else None` degrades correctly under the new form too:
`base_samples[1:]` is `[]` when a sample request failed, and `analyze_boolean` already refuses an
empty sample list as "a reference request did not complete".

**Do NOT apply the constant alone.** Raising it without the call-site change buys requests and no
evidence, because the extras are dropped. `test_boolean_bimodal_noise.py` carries a STRICT xfail
that asserts BOTH halves, so it stays red until they land together and XPASSes the moment they do.

### 5b. `docs/QUEUE.md` -- not this lane's file

Q-070's entry should be marked CLOSED against the commits in this lane, with the note that the fix
was the confirmation criterion rather than the sample count, and that the sample-count half is
carried forward by the strict xfail above rather than by an open ticket.

---

## 6. in progress

