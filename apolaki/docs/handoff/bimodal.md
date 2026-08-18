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

## 3. in progress

