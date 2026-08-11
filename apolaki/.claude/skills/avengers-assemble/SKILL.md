---
name: avengers-assemble
description: Apolaki's multi-agent mode, tuned for efficiency. Trigger on "avengers assemble", "assemble", "multi agent", "multi-agent", "spawn the agents", "spawn them agents", "run the squad", "parallelize this", or any time a long job leaves the main thread waiting. Six ROLES — Watcher, Analyst, Coordinator, Builder, Breaker, Conductor — but the number of AGENTS is decided by how many independent read-lanes exist, plus at most one Builder. Every agent writes to a file as it goes so a killed agent still delivers. Never idle; benchmarks are immutable; one owner per file.
---

# Avengers Assemble — Apolaki multi-agent mode

Apolaki is **one unified pentest platform**. Improve the whole system — not isolated scanners,
dead-end features, benchmark hacks, or disconnected experiments.

Repo: `C:\Users\voice\Desktop\GitHub\MISC\apolaki`
Ledgers: `docs/LEDGERS.md` · `docs/CODEBASE_REVIEW.md` · `docs/QUEUE.md` · `docs/research/INBOX.md` ·
`docs/STATUS.md` · `docs/benchmarks/PEER_BASELINES.md`

## Mission

100% true-positive detection · 0 false positives · deterministic proof for every reported
vulnerability · full orchestration of the existing arsenal · generalization beyond benchmark cases ·
**no modification of benchmarks, labels, scorers, or expected results.**

---

# The efficiency rules (learned the hard way — do not relax these)

These come from a measured session where six agents were spawned at once and all six were killed
mid-flight by an API session limit. What survived was not random.

## Rule 1 — Roles are jobs. Agents are a budget. They are not the same number.

There are six roles. **There is no rule that says six agents.** Spawn:

> **(one agent per independent READ lane) + (at most ONE Builder) + the main thread as Coordinator**

A read lane is independent if it can finish without waiting on another lane's output. If two
proposed lanes read the same question, they are one lane. Three or four agents is a normal squad;
six is a lot and needs justifying. The Coordinator is *always* the main thread — never spend an
agent on it, because coordination needs the conversation's full context.

## Rule 2 — Losing a reader is cheap. Losing a Builder is expensive.

Measured: the killed research and analysis agents still delivered — the funnel diagnosis (2756 URLs
discovered, 36 probed) and ten queue tickets both came from agents that died before finishing. The
killed Builder delivered nothing usable and left gate-failing, uncommitted code across four modules
that someone else then had to fence off.

**A dead reader costs one report. A dead writer costs a dirty tree.** So: many readers, one writer.
When in doubt about implementation, keep it on the main thread.

## Rule 3 — Write-as-you-go, or the work does not exist.

This is *the* rule that makes agent death cheap. Every agent prompt must name **the file it writes
to** and instruct it to append findings **as it discovers them**, not at the end. The readers
survived their own deaths purely because they were writing to `QUEUE.md` and `INBOX.md` along the way.

For the Builder the equivalent is: **commit small, commit often.** A Builder that lands one green
slice per commit leaves a commit when it dies. A Builder that plans one big commit leaves wreckage.
Say this explicitly in the prompt: *"land each green slice as its own commit; do not batch."*

## Rule 3b — Commit-per-slice is PROVEN. Insist on it.

Not a theory any more. In the cycle that established it, three agents were killed by one session
limit and still landed **seven Q-021A slices plus a rewritten traversal oracle**, suite green at
1786 passed. The same rule, absent, is what made the earlier Builder's death cost a dirty tree.
Put the sentence *"land each green slice as its own commit; do not batch — assume you may be killed
at any moment"* in every Builder prompt, verbatim.

## Rule 4 — Disjoint write sets, declared before anyone spawns.

Write the ownership table into `docs/QUEUE.md` **first**, then spawn. Every agent gets the list of
files it may write **and** the list it must not touch, with the reason.

**Docs are files too, and this is where it went wrong.** Hand-off notes were routed into
`docs/QUEUE.md` while another agent owned that same file, so two lanes wrote it concurrently and one
had to "restore the other lane's block that I set aside". Cross-lane needs go to a **per-lane file**
— `docs/handoff/<lane>.md` — never into the shared queue. The Coordinator folds them in afterwards.
Exactly one agent may write any given file, including markdown.

Without this, four agents edit four modules, one dies, and the tree state is unattributable.

## Rule 4b — ASCII-only when an agent writes a shared document.

An agent appending em dashes and middle dots to `docs/QUEUE.md` through the Windows shell
double-encoded the UTF-8 and corrupted **189 lines**. The agent noticed and died mid-repair.

- Agents write shared markdown with the **Write/Edit tools**, never via shell redirection, here-docs
  or PowerShell `Out-File`/`Set-Content`.
- If a shell write is unavoidable, restrict the content to **ASCII** — `-` not `—`, `*` not `·`.
- The repair, if it happens again: the mis-decode is **cp1252**, not latin-1 (`â€"` contains U+20AC,
  which latin-1 cannot encode, so a latin-1 round-trip silently skips every damaged line and reports
  success). Reverse per line, keep the result only when it round-trips cleanly, and diff against a
  backup before trusting it.

## Rule 5 — Factor the house rules into every prompt, but keep them short.

An agent starts cold and cannot see the conversation, so a thin prompt wastes a whole run. But
boilerplate costs tokens on every spawn. Paste the House Rules block below verbatim, then add only
what is specific to the lane. What is specific and worth its length: **the measurements already
taken**, so the agent does not re-derive them, and **the wrong turns already ruled out**, so it does
not take them. Telling a Builder "the crawl is already proven clean, do not fix it" is worth more
than a page of process.

## Rule 6 — Stagger, don't stampede — and expect death anyway.

Six simultaneous spawns exhausted the session limit and killed everything at once, including work
already in flight. Spawn the highest-value lane first, confirm it launched, then the rest. If a
spawn fails on a limit, work solo on the main thread rather than retrying in a loop — and say so.

**Staggering helps; it does not save you.** Three staggered agents were still killed by one limit.
So design every lane on the assumption that it ends mid-sentence: write-as-you-go, commit per slice,
and never let an agent hold the only copy of a decision. Agent death is the normal case, not the
failure case. Budget for the Coordinator to spend real time on **recovery** — reading what landed,
repairing what half-landed, and committing what was left green but uncommitted.

## Rule 7 — The main thread never just waits — but it NEVER works inside an assigned lane.

While agents run, the Coordinator does real work: ledger entries, sequencing, verification of claims
that touch its own files, small fixes in files nobody owns. **Never return a turn that is only a
status report.** A wait is working time.

**The Coordinator's own failure mode is DUPLICATION, and it is expensive.** In one cycle I spawned a
Builder for the code-assisted lane and then, on the main thread, ran the entire semgrep evaluation
myself. The agent independently reached the same result — "perfect recall, zero false positives" —
and we had paid twice for one measurement, in a session where the API limit was the binding
constraint. Ownership binds the Coordinator exactly as hard as it binds an agent.

If the Coordinator realises mid-flight that it knows something the lane needs, the answer is
`SendMessage`, not doing the work. And note what that cycle also proved: **a relay usually lands too
late.** The message reached the agent after it had already re-derived the finding. So put everything
you already know into the **spawn prompt** — measurements taken, wrong turns ruled out, traps hit.
The prompt is the cheap channel; the relay is the expensive one.

## Rule 8 — Relay, then re-task.

When an agent finishes, read its output file, route the result (research → distillation → queue →
build), and either `SendMessage` it the next slice (keeps its context — cheaper) or spawn fresh only
for a genuinely new topic. Never leave a finished agent idle while its lane has work.

## Rule 8b — Scope a lane to ONE completable result, not a programme.

Agents are now dying to the API limit roughly every cycle, mid-task. That is the environment, not an
accident. So the unit of work handed to a lane must be something that can **finish**, and the prompt
must name the smallest useful deliverable first: *"measure X and write the number, THEN optimise"*.

A lane told to "diagnose then fix throughput" died holding a half-formed diagnosis. A lane told to
"detect three categories and report per-category TPR/FPR" died having already produced *perfect
recall on 498 clean cases* — a complete, usable result. Same environment, same interruption; the
difference was entirely how the work was cut.

Order every lane's instructions so the **first** thing it produces is the thing you would most
regret losing.

## Rule 9 — Re-decide the shape each cycle.

Before every assemble, ask: *did the last cycle's Builder come back clean?* If yes, keep the Builder
lane. If it came back half-done twice, implementation is the wrong shape for an agent on this task —
take it back to the main thread and use agents purely for read work. The squad shape is a hypothesis,
not a ritual.

---

# Step 0 — Inspect, decide, declare, then spawn

1. Read `docs/QUEUE.md`, `docs/STATUS.md`, `docs/LEDGERS.md`. Learn what the current job actually is.
2. **Count the independent read lanes.** That plus one Builder is your agent count.
3. Inspect available skills. Select only those **materially relevant**, each with a declared purpose,
   owner, input and expected output. **Do not force a count** — more skills are not better. If a
   needed skill does not exist, say so; never pretend a loadout you do not have.
4. Write the ownership table into `docs/QUEUE.md`.
5. State in chat: the lanes, who owns which files, the selected skills, the first ticket. Then spawn.

# The six roles

**Watcher (research).** Missing capabilities, current techniques, standards, papers, competing DAST
behaviour, better deterministic oracles. Every proposal: problem solved · evidence and primary
sources · Apolaki compatibility (name the existing file it builds on) · expected benefit ·
false-positive risk · concrete acceptance test. **Research never enters implementation
automatically.** Writes `docs/research/INBOX.md`.

**Analyst (distillation).** Verifies proposals — and any external audit — against the **actual
repository**. Rejects duplicates, speculation, benchmark-specific signatures, things Apolaki already
has, ideas without deterministic proof, and anything that creates an island. Converts survivors into
tickets: root cause · producer/consumer contracts · files affected · oracle and negative control ·
tests and mutations · dependencies · definition of done. Records rejections so ideas do not return.

**Coordinator (always the main thread).** Owns `docs/QUEUE.md` and `docs/STATUS.md`. Ranks by
capability gain × coverage gain × proof strength ÷ (risk × cost). Tracks `blocked · ready · active ·
verification · completed · rejected · rolled-back`. Enforces disjoint ownership and prerequisite
order. **Only the Coordinator changes ticket state.**

**Builder (implementation).** Highest-priority ready ticket, **smallest general solution**, using
Apolaki as one unit — graph, planner, browser driver, CDP, ZAP, crawlers, scanners, oracle registry,
evidence, replay, UI, reporting. Per change: reproduce → diagnose → implement → targeted test →
negative controls → mutation test → category regression → full regression. **Never hardcode benchmark
test IDs, labels, endpoint names, source lines or case fingerprints.** One green slice per commit.

**Breaker (verification).** Tries to **disprove**. See `verify-adversarial` for the eight checks. A
crash, timeout, unrelated assertion, fixture failure or generic nonzero exit is not proof.

**Conductor (integration).** Findings feed the canonical graph; the planner can consume new facts;
ZAP is orchestrated across initial scan, spider, AJAX crawl, passive/active scan, targeted rescan and
recrawl; browser/CDP observations feed evidence; no capability becomes an island; reports expose only
deterministically proven findings; the UI shows honest capability and benchmark status.

# Operating loop

Research → Distill → Prioritize → Implement → Verify adversarially → Integrate → targeted benchmark
tests → full benchmark regression → orchestration tests → OPTEST + UI validation → code QA → report
QA → record in the ledger → select the next highest-value gap.

# Quality gates — all must hold to merge

1. The intended test **fails before** the fix. 2. The **exact intended assertion** passes after.
3. Negative controls pass. 4. Mutation testing proves the test is non-vacuous. 5. No false-positive
regression. 6. Deterministic replay succeeds. 7. Clean-environment reproduction succeeds.
8. Existing functionality intact. 9. Evidence, graph, planner, API, UI and report stay consistent.

# Benchmark rules — immutable

Never modify benchmark applications, cases, expected-result labels, scoring code, denominators, or
test execution to skip failures. Macro-average over **all** suite categories; never narrow a
denominator. Benchmark success does not prove universal capability — validate on unseen semantic
variants before marking a fix generally proven. See `benchmark-score`.

---

# House Rules — paste verbatim into every agent prompt

```
- Write your findings to <FILE> AS YOU GO, not at the end. If you are killed mid-run, whatever is in
  that file is your entire contribution. (Builders: land each green slice as its own commit; do not
  batch — a killed Builder that batched leaves wreckage, not work.)
- You may WRITE only: <FILES>. Do NOT touch <OFF-LIMITS> — owned by another agent with uncommitted
  work. If you need a change there, write the exact patch into docs/handoff/<YOUR-LANE>.md — your own
  file, NOT the shared queue, which another agent is writing right now.
- Write shared markdown with the Write/Edit tools, never shell redirection or PowerShell
  Out-File/Set-Content, and keep it ASCII (`-` not `—`). A shell append of em dashes double-encoded
  the UTF-8 and corrupted 189 lines of the queue.
- Every claim tagged MEASURED (with the command and its real output) or UNVERIFIED. A disproved
  hypothesis is a result — record it as disproved, never drop it quietly.
- Never weaken a test or a gate to make it pass. SKIPPED is never a pass. Never fake a result.
- Measure the baseline before claiming an improvement. Macro-average over ALL suite categories.
- No islands: registration is not invocation, a descriptor is not an executor, a declaration is not
  a fact. ToolRegistry.execute() dispatches via getattr(self, "_" + tool_name) and CLAUDE_TOOLS is a
  second emitter — check both before calling anything unreachable.
- Benchmarks are immutable: never modify apps, cases, labels, scoring code or denominators, and never
  build a benchmark-specific signature.
- Check `curl -s http://localhost:8000/missions` before `docker compose build agent` — a build
  SIGKILLs any running mission (three have died that way here). Fast deploy:
  `docker cp <f> apolaki-agent-1:/app/<f>` + `docker restart apolaki-agent-1`. /app is BAKED, not
  bind-mounted, so an uncopied change is simply not live.
- Git Bash: MSYS_NO_PATHCONV=1 for docker exec with absolute paths; -w /app must be absolute. pytest
  already sets addopts = -q, so your own -q makes it -qq and hides the summary line.
- Never `git add -A` — other agents have uncommitted work in this tree. Stage named files only.
- No secrets, no machine-specific paths, no reliance on uncommitted local state.
- Authorized targets only: the local docker labs, Natas, and the vulnweb/ginandjuice hosts.
- ANTI-IDLE: pull the next independent ready task the moment capacity exists. Do not generate filler.
  If blocked, say why in your file and move to the next item.
```

# Status dashboard — `docs/STATUS.md`, kept live

Active agents and assignments · selected skills and justification · queue depth and blockers ·
current benchmark TPR / FPR / macro score · per-category results · improvements since the previous
clean run · regressions and rollbacks · **unproven claims** · next highest-value task.

# Stand down

Only when the stated target is met or Erwin says stop. Then one completion report: what shipped,
measured before/after, what is still open and why. **No victory claims without a number.**
