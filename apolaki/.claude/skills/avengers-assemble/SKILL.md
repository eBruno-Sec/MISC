---
name: avengers-assemble
description: Apolaki's multi-agent mode. Trigger on "avengers assemble", "assemble", "multi agent", "multi-agent", "spawn the agents", "spawn them agents", "run the squad", "parallelize this", or any time a long job leaves the main thread waiting. Three agent shapes — Builder, Breaker, Architect — with the Coordinator always on the main thread. Agent count = independent lanes, not a fixed roster. Every agent writes as it goes and commits per slice, so a killed agent still delivers. Never idle; benchmarks are immutable; one owner per file.
---

# Avengers Assemble — Apolaki multi-agent mode

Apolaki is **one unified platform**. Improve the whole system — not isolated scanners, dead-end
features, benchmark hacks, or disconnected experiments.

Repo: `C:\Users\voice\Desktop\GitHub\MISC\apolaki`
Ledgers: `docs/LEDGERS.md` · `docs/CODEBASE_REVIEW.md` · `docs/QUEUE.md` · `docs/STATUS.md` ·
`docs/handoff/<lane>.md` · `docs/benchmarks/PEER_BASELINES.md`

**Mission:** 100% TPR · 0 FP · deterministic proof for every reported vulnerability · full
orchestration of the existing arsenal · generalization beyond benchmark cases · **no modification of
benchmarks, labels, scorers or expected results.**

**Why this exists.** Not parallelism — **context arbitrage**. An agent spends 200k tokens in a window
the Coordinator never has to hold, and returns a 400-word conclusion. Per token it is *worse*; per
session it is ~2.5–3× more work, and per session is what matters. Optimise accordingly: fewer, deeper,
better-briefed lanes — never more chatter.

---

# The rules. Each one is here because it already failed.

**1 · Agents are a budget, not a roster.** Spawn **one agent per independent lane**, plus the
Coordinator on the main thread. Two lanes answering the same question are one lane. Three is a normal
squad. Never spend an agent on coordination — that needs the conversation's full context.

**2 · Losing a reader is cheap; losing a writer is expensive.** Killed research agents still delivered
the funnel diagnosis and ten tickets. A killed Builder that batched left gate-failing code across four
modules. Many readers, at most one or two writers, and keep implementation on the main thread when in
doubt.

**3 · Write-as-you-go, commit-per-slice. PROVEN, not theory.** Three agents killed by one session
limit still landed seven slices plus a rewritten oracle. Every prompt names the file the agent appends
to **as it works**, and every Builder prompt says verbatim: *"land each green slice as its own commit;
do not batch — assume you may be killed at any moment."*

**3c · Ownership covers the CONTAINER, not just the repo.** Disjoint files are not enough. Two lanes
with disjoint write sets still collided inside the shared `apolaki-agent-1`, because both were told to
`docker cp` their work into it — one overwrote the other and died mid-restore. Git isolation did not
help, because the collision was never in git. **Every lane gets its own throwaway container mounting
its own tree.** That instruction was in the House Rules block causing this, and is now fixed there.

**4 · Disjoint write sets, declared before anyone spawns — docs included.** Write the ownership table
into `docs/QUEUE.md` first. Cross-lane needs go to `docs/handoff/<lane>.md`, **never** the shared
queue: routing hand-offs into a file another agent owned forced one lane to "restore the other lane's
block". Exactly one agent writes any given file, markdown included.

**5 · ASCII only when an agent writes a shared doc.** A shell append of em dashes double-encoded the
UTF-8 and corrupted **189 lines**. Use Write/Edit, never shell redirection or PowerShell
`Out-File`/`Set-Content`. If it happens again the mis-decode is **cp1252, not latin-1** (`â€"` holds
U+20AC, which latin-1 cannot encode, so a latin-1 round-trip silently skips every damaged line and
reports success). Reverse per line, keep only clean round-trips, diff against a backup.

**6 · The spawn prompt is the cheap channel; the relay is the expensive one.** Put every measurement
already taken and every wrong turn already ruled out into the prompt. A `SendMessage` correction
arrived *after* the agent had re-derived the finding. Prompts of 800–1200 words are correct here.

**7 · The Coordinator never works inside an assigned lane.** Its failure mode is **duplication**: I
spawned a Builder for a lane and then ran the same evaluation myself; both reached the same result and
we paid twice, in a session where the API limit was the binding constraint. Ownership binds the
Coordinator as hard as it binds an agent. Stay busy on ledgers, sequencing, recovery, and files nobody
owns — **and never return a turn that is only a status report.**

**8 · Scope a lane to ONE completable result.** Agents die mid-task roughly every cycle; that is the
environment. Order the prompt so the **first** output is the thing you would most regret losing. A
lane told "diagnose *then* fix" died holding half a diagnosis; a lane told "detect and report
per-category TPR/FPR" died having already produced a complete measurement.

**8b · A handoff file records what HAPPENED, never what is expected to happen.** A lane wrote D5/D13
outcomes and **fabricated commit hashes** into its handoff before measuring anything, caught itself —
*"I got ahead of myself"* — and corrected the file minutes before being killed. It stayed untracked so
nothing false reached history, but the next one may not self-catch. Write-as-you-go means writing
**results as they land**, not sketching the table you intend to fill. An unmeasured row is `in
progress`, never a number, and a commit hash is copied from `git log` or omitted. The Coordinator
greps every handoff for hash-shaped strings and status claims before committing it.

**8c · Disjoint WRITE sets do not give a disjoint READ of the tree.** Paid for twice in one day. A
lane reported *"the tree is shifting under me from concurrent lanes"*, and a Coordinator full-suite
run produced three failures that were a **torn read** — the suite executing against a working tree
another lane was mid-commit in. Ownership stops two agents editing one file; it does nothing about a
third agent reading all of them at once. **Any full-suite run during a cycle goes against an isolated
snapshot of HEAD plus that agent's own changes**, never the shared tree. A red suite that is really a
torn read costs an hour and, worse, gets attributed to the wrong lane.

**9 · Expect death; budget for recovery.** Staggering helps and does not save you — three staggered
agents still died to one limit. Every cycle the Coordinator must read what landed, repair what
half-landed, and commit what was left green but uncommitted.

**9b · Codex is a metered weekly budget, not a spare lane. Check it before leasing.** It resets weekly
and runs out. **Do not lease it work a Claude lane can do** — spend it only where an outside agent is
genuinely better: independent verification of the Coordinator's own claims, and self-contained tickets
in files no live lane holds. Its two highest-value returns were both of that kind — it caught a
fabricated `tools.py:3296` citation I had repeated in five prompts, and an unimplemented `Retry-After`
policy the documentation asserted. Neither was capability; both were *independence*. When the budget is
low, Claude lanes take the ordinary work and Codex is saved for the check nobody inside can perform.

**10 · Re-decide the shape each cycle.** If a Builder lane returns half-done twice, implementation is
the wrong shape for an agent on that task — take it back to the main thread. The squad shape is a
hypothesis, not a ritual.

---

# The three shapes

**Builder** — takes the highest-priority ready ticket and implements the **smallest general solution**,
using Apolaki as one unit (graph, planner, browser driver, CDP, ZAP, crawlers, scanners, oracle
registry, evidence, replay, UI, reporting). Per change: reproduce → diagnose → implement → targeted
test → negative controls → mutation test → full regression. The targeted test must **fail before** the
fix. **Never hardcode benchmark IDs, labels, endpoint names or case fingerprints.**

**Breaker** — tries to **disprove**. The single highest-ROI role: everything expensive this project got
wrong was caught here (a fake 0% FPR, a reflection detector scoring 69.2%, 626 of 660 findings claiming
controls that never ran). Follow `verify-adversarial` for the eight checks; that skill is the contract,
do not restate it. A crash, timeout, unrelated assertion or generic nonzero exit is **not** proof.

**Architect** — read-only. Derives design from the code, never from a doc or a proposal, and states
what the code **does** before what it should do. Output is a design a Builder can implement from, with
the existing-code audit proving each proposal extends rather than rebuilds.

**Coordinator (main thread, always)** — owns `docs/QUEUE.md`, `docs/STATUS.md`, the ledgers, and
sequencing. Ranks by capability gain × coverage gain × proof strength ÷ (risk × cost). **Only the
Coordinator changes ticket state or folds a lane's numbers into the ledger.**

---

# Step 0 — inspect, decide, declare, then spawn

Read `docs/QUEUE.md`, `docs/STATUS.md`, `docs/LEDGERS.md`. Count the independent lanes — that is your
agent count. Select only skills materially relevant, each with a declared owner and expected output;
**do not force a count**, and never pretend a loadout you do not have. Write the ownership table.
State lanes, owners, skills and the first ticket in chat. Then spawn.

# Merge gates — all must hold

The test fails before the fix · the exact intended assertion passes after · negative controls pass ·
mutation testing proves the test non-vacuous · no false-positive regression · deterministic replay ·
clean-environment reproduction · existing functionality intact · evidence, graph, planner, API, UI and
report stay consistent.

# Benchmarks — immutable

Never modify benchmark applications, cases, labels, scoring code, denominators, or test execution to
skip failures. Macro-average over **all** suite categories; never narrow a denominator. Seal the run
artifact before fetching the key. Benchmark success does not prove capability — validate on an unseen
semantic variant before calling a fix general. See `benchmark-score`.

# House Rules — paste verbatim into every agent prompt

```
- Write findings to <FILE> AS YOU GO, not at the end. If you are killed, that file is your entire
  contribution. Builders: land each green slice as its own commit; do not batch.
- You may WRITE only: <FILES>. Do NOT touch <OFF-LIMITS> — owned by another lane. If you need a change
  there, write the patch into docs/handoff/<YOUR-LANE>.md, NOT the shared queue.
- Write docs with Write/Edit, never shell redirection, and keep them ASCII (`-` not `—`).
- Every claim MEASURED (command + real output) or UNVERIFIED. A disproved hypothesis is a result.
- Never weaken a test, a gate or an oracle to make something pass. SKIPPED is never a pass.
- Measure the baseline before claiming an improvement. Macro over ALL suite categories.
- No islands: registration is not invocation, a descriptor is not an executor, a declaration is not a
  fact. ToolRegistry.execute() dispatches via getattr(self, "_" + tool_name) and CLAUDE_TOOLS is a
  second emitter — check both before calling anything unreachable.
- Benchmarks immutable: never modify apps, cases, labels, scoring or denominators, and never build a
  benchmark-specific signature.
- RUN TESTS IN YOUR OWN THROWAWAY CONTAINER. Never `docker cp` into `apolaki-agent-1` and never
  restart it — it is shared, and two lanes doing that overwrote each other's files mid-run (one died
  holding a half-finished restore of the other's work). Use:
    MSYS_NO_PATHCONV=1 docker run --rm -v "<ABS-WINDOWS-PATH>/agent:/app" -w /app \
      apolaki-agent python -m pytest tests/ -p no:cacheprovider
  This is the pattern five Codex lanes used with zero collisions. It also means /app is your working
  tree rather than a baked image, so there is nothing to deploy and nothing to forget to deploy.
- `curl -s http://localhost:8000/missions` before `docker compose build agent` — a build SIGKILLs a
  running mission (three have died that way). You should not need to build at all.
- Git Bash: MSYS_NO_PATHCONV=1 for docker exec with absolute paths; -w /app absolute. pytest already
  sets addopts = -q. A Git-Bash /tmp path in `docker -v` silently mounts an EMPTY volume and tools
  report success having scanned 0 files — always check the scanned-file count, never trust exit 0.
- Never `git add -A` — other lanes have uncommitted work. Stage named files only.
- No secrets, no machine-specific paths, no reliance on uncommitted local state.
- Authorized targets only: the local docker labs, Natas, and the vulnweb/ginandjuice hosts.
- ANTI-IDLE: pull the next independent ready task as soon as capacity exists. No filler. If blocked,
  say why in your file and move on.
```

# Close out

Keep `docs/STATUS.md` live: lanes and assignments · queue depth and blockers · current TPR/FPR/macro
per suite · improvements since the last clean run · regressions and rollbacks · **unproven claims** ·
next highest-value task. Push to GitHub when a cycle's work is verified green.

Stand down only when the target is met or Erwin says stop, then one completion report: what shipped,
measured before/after, what is still open and why. **No victory claims without a number.**
