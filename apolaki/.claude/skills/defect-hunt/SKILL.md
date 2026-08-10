---
name: defect-hunt
description: Apolaki's codebase-defect hunting protocol — finding the bugs a green test suite cannot see. Trigger on "review the codebase", "what's wrong with apolaki", "find dead code", "audit", "why did it find nothing", "orchestration is failing", "false positive", or whenever a run produces a suspiciously clean result. Targets the four defect shapes that have actually bitten this project: silent-failure swallows, falsy defaults, guards that check declarations instead of facts, and islands. Every claim is recorded MEASURED or UNVERIFIED in docs/CODEBASE_REVIEW.md.
---

# Defect hunt — the bugs a green suite cannot see

1645 tests were green while a real mission returned **zero findings in 40 seconds** against a target
with 1415 known vulnerabilities. Unit tests test what code does when it runs. These defects are all
about code that does not run, or runs and says nothing. Ledger: `docs/CODEBASE_REVIEW.md`
(append-only; wrong findings stay, marked wrong).

## The four shapes — hunt these specifically

**1. Silent failure.** `except Exception: pass` around a probe. A swallowed exception produces no
finding, and **no finding is byte-identical to a clean target**. Hunt: grep bare/broad excepts on
any path that can emit a finding. Fix pattern: record the swallow (`ToolRegistry.swallowed` /
`_swallow(exc, where, target)`) so "we didn't look" is distinguishable from "nothing there".
Corollary: an unimported name inside a try block is dead code that reports clean.

**2. Falsy default.** `x = arg or DEFAULT` where empty is a *real* input. Has bitten twice, both
times invisible to the suite. Hunt: grep `or ` in parameter defaulting; ask "is empty meaningful
here?" Fix: `if arg is None`.

**3. A guard that checks a declaration, not a fact.** The no-island guard passed engines that were
registered but never invoked (4 cases). Registration is not invocation. A descriptor is not an
executor. `validated_on` in a table is not a validation that ran. Hunt: for every guard, **write the
negative control** — construct the thing the guard exists to catch and prove it fails.

**4. Islands + orchestration gaps.** A capability nothing consumes. Trace the chain hop by hop:
recon -> `derive_observations` -> `plan()` -> advisor -> autonomy loop -> report. A missing hop is
an island. The five orchestration defects that produced the zero-finding mission all lived here
(scoped-path seeding, auth-only crawl, relative links dropped, robots/sitemap unread, dead browser
sensor).

## Method

1. **Reproduce with a real run**, not a unit test. The suite is the thing that missed it.
2. **Observation -> hypothesis -> test -> evidence -> conclusion.** Name the hypothesis before testing.
3. **Falsify.** Try to prove yourself wrong; run the negative control. A mechanism reproduced is not
   a cause proven.
4. **Root cause, not symptom.** Relative links being dropped was the cause; four downstream fixes
   would have been symptom patches.
5. **Verify BOTH halves of a fix.** Tightening a condition that was already failing changes nothing.
   Prove the false positive is gone AND the true positive still fires.
6. **Grade the confidence**: MEASURED (with the command and output) or UNVERIFIED (a reading).

## Traps this codebase sets

- `execute()` dispatches via `getattr(self, "_" + tool_name)`, and `CLAUDE_TOOLS` is a second
  emitter — grepping one file gave a "9 unreachable engines" claim that was wrong by nine.
- `/app` is **baked into the image**, not bind-mounted. Rebuild before testing a change.
- **`docker compose build agent` SIGKILLs any mission running in the container.** Code first,
  missions last.
- `addopts = -q` plus your own `-q` becomes `-qq` and hides the pytest summary line.
- Git Bash: `MSYS_NO_PATHCONV=1` for `docker exec` with absolute paths; `-w /app` must be absolute.
- Never run a regex over structured records. Parse them.

## Output

Append to `docs/CODEBASE_REVIEW.md`, one entry per finding: what was observed, the hypothesis, the
test run, the evidence, MEASURED/UNVERIFIED, the fix, and the negative control that proves it.
