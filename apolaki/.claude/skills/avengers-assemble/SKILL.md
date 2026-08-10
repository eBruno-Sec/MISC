---
name: avengers-assemble
description: Apolaki's coordinated multi-agent mode. Trigger on "avengers assemble", "assemble", "multi agent", "multi-agent", "spawn the agents", "spawn them agents", "run the squad", "parallelize this", or any time a long job (benchmark scan, full mission, docker build) leaves the main thread waiting. Six roles — RESEARCH (the Watcher), DISTILLATION (the Analyst), QUEUE (the Coordinator), IMPLEMENTATION (the Builder), VERIFICATION (the Breaker), INTEGRATION (the Conductor) — driving one operating loop toward 100% TPR / 0% FPR with deterministic proof, treating Apolaki as one unified platform rather than a bag of scanners. Never idle; benchmarks are immutable.
---

# Avengers Assemble — Apolaki multi-agent mode

Apolaki is **one unified pentest platform**. Improve the whole system — not isolated scanners,
dead-end features, benchmark hacks, or disconnected experiments.

Repo: `C:\Users\voice\Desktop\GitHub\MISC\apolaki`
Ledgers: `docs/LEDGERS.md` (index) · `docs/CODEBASE_REVIEW.md` (defects) · `docs/QUEUE.md` (the
canonical queue) · `docs/research/INBOX.md` (raw research) · `docs/STATUS.md` (live dashboard) ·
`docs/benchmarks/PEER_BASELINES.md` (peers).

## Mission

- 100% true-positive detection
- 0 false positives
- Deterministic proof for every reported vulnerability
- Full orchestration of Apolaki's existing arsenal
- Generalization beyond known benchmark cases
- **No modification of benchmarks, labels, scorers, or expected results**

## Step 0 — Inspect, then present, then assemble

Before spawning anything: read the repo state, the available skills, the active benchmark numbers,
the roadmap and the improvement ledger. Then present, in chat, the proposed team, ownership
boundaries, selected skills with justification, the first queue, and the safety gates. **Then**
spawn.

## Step 1 — Select skills honestly

Inspect the available skills. Select only those **materially relevant to the current assignment**.
Do not force an arbitrary count — more skills are not automatically better. Each selected skill
declares: purpose, owner (which agent), input, expected output. If a needed skill does not exist,
say so; write it or work without it, but never pretend a loadout you do not have.

## Step 2 — The six roles

Spawn in ONE message (parallel calls), `run_in_background: true`. Each prompt is self-contained —
an agent starts cold. **One owner per ticket. No two agents editing the same files concurrently.**

**1. RESEARCH — the Watcher.** Continuously research missing capabilities, current techniques,
standards, papers, competing DAST behaviour, better deterministic oracles. Every proposal carries:
problem solved · evidence and primary sources · Apolaki compatibility · expected benchmark or
real-world benefit · false-positive risk · a concrete acceptance test. **Research never enters
implementation automatically.** Writes `docs/research/INBOX.md`.

**2. DISTILLATION — the Analyst.** Review research against the **actual repository**. Reject
duplicates, speculation, benchmark-specific signatures, things Apolaki already has, ideas without
deterministic proof, and anything that creates a capability island. Convert survivors into
implementation-ready tickets: root cause · producer and consumer contracts · files likely affected ·
oracle and negative control · tests and mutations required · dependencies · definition of done.
Writes tickets into `docs/QUEUE.md`.

**3. QUEUE — the Coordinator.** Owns ONE canonical, dependency-ordered queue. Deduplicates, ranks by
expected capability gain / coverage gain / proof strength / risk / cost, tracks
`blocked · ready · active · verification · completed · rejected · rolled-back`, prevents overlapping
file ownership, enforces prerequisite order, keeps every ticket linked to evidence. **Only the
Coordinator changes queue state.**

**4. IMPLEMENTATION — the Builder.** Takes the highest-priority ready ticket and implements the
**smallest general solution**. Uses Apolaki as one whole unit — graph, planner, browser driver, CDP
telemetry, ZAP, crawlers, scanners, oracle registry, evidence system, replay, UI, reporting.
Sequence per change: reproduce -> diagnose -> implement -> targeted test -> negative controls ->
mutation test -> category regression -> full regression. **Never hardcode benchmark test IDs,
expected labels, endpoint names, source lines, or case-specific fingerprints.**

**5. VERIFICATION — the Breaker.** Independently tries to **disprove** every claimed improvement.
Confirms: the exact intended assertion killed the mutant · negative controls stay clean · false
positives did not increase · deterministic replay succeeds · existing capabilities intact · UI, API,
graph, planner, evidence and report agree · a clean-environment run reproduces it · unseen semantic
variants demonstrate generalization. **A crash, timeout, unrelated assertion, fixture failure or
generic nonzero exit is not proof.**

**6. INTEGRATION — the Conductor.** Watches the whole system: findings feed the canonical graph; the
planner can consume new facts; ZAP is orchestrated across initial scan, spider, AJAX crawl,
passive/active scan, targeted rescan and recrawl; browser/CDP observations feed evidence and
decisions; no capability becomes an island; reports expose only deterministically proven findings;
the UI shows honest capability and benchmark status.

## Step 3 — Operating loop

Research -> Distill -> Prioritize -> Implement -> Verify adversarially -> Integrate -> targeted
benchmark tests -> full benchmark regression -> orchestration tests -> OPTEST + UI validation ->
code QA -> report QA -> record in the immutable improvement ledger -> select the next highest-value
gap. Repeat.

## Quality gates — all must hold to merge

1. The intended test **fails before** the fix.
2. The **exact intended assertion** passes after the fix.
3. Negative controls pass.
4. Mutation testing proves the test is non-vacuous.
5. No false-positive regression.
6. Deterministic replay succeeds.
7. Clean-environment reproduction succeeds.
8. Existing functionality intact.
9. Evidence, graph, planner, API, UI and report stay consistent.

## Benchmark rules — immutable

Never modify benchmark applications, vulnerable or clean cases, expected-result labels, scoring
code, denominators, or test execution to skip failures. Macro-average over **all** suite categories;
never narrow the denominator. Benchmark success does not prove universal capability — validate on
unseen semantic variants before marking a fix generally proven. (See `benchmark-score`.)

## Safety and control

Approved: modifying Apolaki when the change improves the platform and passes all gates.
**Not** auto-approved: destructive repository operations · credential exposure · out-of-scope target
activity · benchmark modification · suppressing failing tests · lowering validation thresholds ·
irreversible infrastructure changes. Checkpoint before risky changes. Roll back anything that
increases false positives, breaks capability, weakens evidence, or fails deterministic reproduction.

Operational hazards every agent inherits:
- **`docker compose build agent` SIGKILLs any mission running in the container.** Check for a
  running mission first. Code work first, builds later, missions last.
- `/app` is baked into the image, not bind-mounted — a change is not live until rebuild or
  `docker cp` + `docker restart apolaki-agent-1`.
- Never `git add -A`. Stage named files.
- No secrets, no machine-specific paths, no reliance on uncommitted local state.
- Authorized targets only: the local labs, Natas, and the vulnweb/ginandjuice hosts Erwin authorized.

## Anti-idle rule

Pull the next independent ready task the moment capacity exists. Do **not** generate filler work.
If no implementation task is ready: RESEARCH investigates the highest-value known gap · DISTILLATION
audits unresolved evidence · QUEUE removes blockers and reconciles dependencies · VERIFICATION
attacks completed claims · INTEGRATION audits producer-consumer wiring.

**The main thread never returns a turn that is only a status report.** A wait is working time.

## Status dashboard — `docs/STATUS.md`, kept live

Active agents and assignments · selected skills and justification · queue depth and blockers ·
current benchmark TPR / FPR / macro score · per-category results · improvements since the previous
clean run · regressions and rollbacks · unproven claims · next highest-value task.
