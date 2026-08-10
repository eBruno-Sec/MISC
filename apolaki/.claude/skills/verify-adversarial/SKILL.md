---
name: verify-adversarial
description: Adversarial verification of a claimed Apolaki improvement — the Breaker's discipline. Trigger on "verify", "prove it", "did that actually work", "is this a real fix", "mutation test", "negative control", or before marking any ticket done. Tries to DISPROVE the claim: kills the mutant with the exact intended assertion, checks the test failed before the fix, hunts false-positive regressions, demands deterministic replay and a clean-environment run, and requires an unseen semantic variant before calling a fix general.
---

# Adversarial verification — try to break the claim

A claimed improvement is a hypothesis. This skill's job is to falsify it. "Tests pass" is the start
of verification, not the end — 1645 tests were green while the product found nothing.

## The eight checks

**1. Did the test fail before the fix?** Revert the change (or stash it) and run the new test. If it
passes without the fix, the test is vacuous and proves nothing. This check is not optional.

**2. Does the exact intended assertion kill the mutant?** Mutate the fixed line (invert the
condition, change the constant, delete the branch) and confirm the **specific** assertion fails.
A crash, timeout, unrelated assertion failure, fixture error, import error, or generic nonzero exit
**does not count** — the suite must fail for the reason the test exists.

**3. Do negative controls stay clean?** For every new detection, run it against a target that is
*known good* for that class. A detector that fires on the secure control is a false positive
generator, whatever it scored on the vulnerable case.

**4. Did false positives increase anywhere?** Re-run the FPR side of the benchmark, not just the TPR
side. A TPR gain paid for with FPR is a loss. Report both numbers or neither.

**5. Does deterministic replay succeed?** Run it twice. Same input, same verdict, same evidence. A
finding that appears only sometimes is not proven — it is a race or an ordering artifact.

**6. Does a clean environment reproduce it?** Nothing may depend on uncommitted files, local-only
state, files copied into a running container, or caches. `/app` is baked — a `docker cp` fix
vanishes on rebuild. Verify from the committed tree.

**7. Do all surfaces agree?** Evidence, graph, planner, API, UI and report must tell the same story
about the same finding. The report once stamped CONFIRMED on rows the proof gate had demoted — the
surfaces disagreed and nothing caught it.

**8. Does it generalize?** Construct an **unseen semantic variant** — same vulnerability class,
different shape, different stack, different parameter name. If the fix only works on the case it was
written against, it is a signature, not a capability. Say so and mark the ticket
`benchmark-proven, not generally proven`.

## Verdicts

- **CONFIRMED** — all eight checks pass, with the commands and output recorded.
- **PLAUSIBLE** — the mechanism is right but a check could not be run; name which and why.
- **REJECTED** — a check failed. Say which, with evidence. Recommend rollback if it increased false
  positives, broke capability, weakened evidence, or failed replay.

Never upgrade a verdict to justify a merge. A rejected claim that gets fixed is a new claim; re-run
all eight.

## Output

Append to `docs/CODEBASE_REVIEW.md` under the ticket id: the eight checks, each with the command run
and its result, then the verdict. Report the verdict to the Coordinator; only the Coordinator moves
the ticket.
