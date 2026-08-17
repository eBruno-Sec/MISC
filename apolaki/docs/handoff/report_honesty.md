# Q-063 - the Arsenal summary merged "ran and errored" into "ran and found nothing"

**RECONSTRUCTED BY THE COORDINATOR, 2026-08-17 07:00.** The lane that did this work was killed by a
session limit and **wrote no handoff at all** - a House Rules violation, since write-as-you-go exists
precisely for the kill it did not survive. Its reasoning existed only inside a test docstring and a
diff. Everything below is read out of the code and the tests it left, and re-verified here; nothing is
carried over on the lane's word, because the lane left no word to carry.

The work itself is good. The artifact was missing, which is a different failure from bad work and is
recorded as such.

## The defect

`arsenal_gap()` classified an engine as `silent` with the predicate `calls > 0 and findings == 0`.
That predicate is equally true of three different things:

- an engine that ran, returned, and honestly found nothing (**a RESULT**)
- an engine that **failed on every call** (**an invisible false negative** - the target was never tested)
- an engine that was **skipped** - unconfigured, or every target refused by scope

In the four-way classification of engine outcomes, "ran and errored" is the **most valuable** class and
"ran and found nothing" is the class that means *nothing to see here*. The summary reported the first
as the second. A client reads the summary precisely so they do not have to read the 46-row table.

This is the same merge-two-classes defect as the `blocked_by_mode` one fixed a level down, where
tier-barred engines were rendered as "available but not selected": two classes with **opposite fixes**
collapsed into one number.

## The fix

`silent` is split into `silent` / `errored` / `skipped`, driven by **`main._tool_ledger`'s own
`status` field** - which the producer has always emitted and this consumer never read. Nothing is
inferred from note text.

One row lands in exactly ONE class, with stated precedence: a failure outranks everything (an engine
that errored produced no result to be clean about), then a skip, then findings, then a returning call
with nothing to show. So the counts reconcile and a reader can add up the summary.

**The best decision in the change:** a row with NO `status` - an archived ledger from before the field
existed - keeps the OLD behaviour. As the code says, a missing status is not evidence of failure, and
retro-labelling silence as error would be the same defect pointed the other way.

## MEASURED, on a real producer ledger

Fixture `agent/tests/tool_ledger_57cc3b49.json` is the **verbatim** output of
`main._tool_ledger("57cc3b49")` from the live mission DB, and carries a `_provenance` field with
regeneration instructions. **Coordinator-verified against the live DB**: `mode=active`,
`strategy=deterministic`, **46 tool rows** - matches exactly. This matters because three defects in one
session came from invented fixtures making vacuous tests pass, including a tool-ledger fixture with the
mode string in the wrong key that let a guard never fire in a single real report while every test
stayed green.

```
silent   33 -> 30
errored   0 ->  1     fetch_openapi, failed on 10 of 10 dispatches
skipped   0 ->  2     run_github_recon (unconfigured), run_transport_posture (scope-refused)
```

A **RE-PARTITION, not a re-count**: the classes still sum to the 111-engine registry denominator.

## Two findings that fall out of it

1. **`fetch_openapi` is NOT a broken engine, and I nearly filed it as one.** It shows
   `status=failed, calls=10, findings=0`, which is what the new `errored` class picked up. But the
   recorded error is:

   ```
   Response is not valid JSON (not an OpenAPI spec)
   ```

   That is a **NEGATIVE RESULT, not a failure**: the engine probed 10 candidate paths on Juice Shop
   and correctly determined none of them serves an OpenAPI spec. So the re-partition moved this row
   out of a wrong class into a *differently* wrong one, and the fault is upstream in the producer -
   `main._tool_ledger` marks a row `failed` whenever an error string is present with no successful
   call, and "this is not a spec" arrives as an error string.

   **This is the same defect that was already fixed once for scope blocks** (`936f6bd`: a SCOPE BLOCK
   is correct enforcement, not a tool failure, and a tool that ran fine on its in-scope targets must
   not read "failed"). The same reasoning applies to a negative finding. Filed as **Q-067** against
   the PRODUCER, not the engine.

   Recording the near-miss deliberately: the reason to verify a finding against the live ledger before
   filing it is that "failed 10 of 10" reads like a broken engine and is a much more exciting ticket
   than the true one. The exciting version would have sent someone to fix an engine that works.
2. **`run_transport_posture` appears here as `skipped` (scope-refused)**, which is Q-060 surfacing
   independently in a second instrument. Corroboration, not a new defect.

## Verified by the Coordinator

- `agent/tests/test_arsenal_errored_class.py` (205 lines) and the fixture were left on disk and pass.
- 58 tests green across the arsenal/ledger/island files.
- Full-suite result recorded in `docs/STATUS.md`; do not quote a number from this file.

## NOT established

- Whether the test was **proven to fail before** the fix. Plausible from its construction, but the
  lane recorded no such run and I did not re-derive it.
- ~~Whether the HTML renderer carries the new classes.~~ **RESOLVED - it does.** Coordinator-verified:
  `agent/report.py:2975-2982` renders `Ran and found nothing`, `Ran and errored` and
  `Blocked by permission tier` in the CLIENT-FACING renderer, with a comment saying so explicitly.
  Both halves landed, which is what the brief required and what a previous cycle got wrong.

  Worth recording a deliberate ASYMMETRY the lane built in and did not explain: the errored line
  prints **always, including at zero**, while the tier line prints only when non-zero. That is not an
  oversight and it is correct. "0 engines errored" is a fact the reader needs. "0 blocked by
  permission tier" is NOT safe to print unconditionally, because it is also what an UNKNOWN mode
  produces - which is precisely the false-reassurance case pinned by
  `test_a_ledger_without_a_mode_does_not_silently_claim_nothing_was_blocked`.
- Whether a mutation test was run.
