# Q-030 .. Q-034 — the architecture programme (multi-day, queued not started)

Erwin's items 3-7, queued honestly. **Nothing here is implemented.** Each needs a design derived from
the repository before any code, because the standing rule is that we do not build a parallel subsystem
when canonical infrastructure already exists.

Related: [QUEUE.md](QUEUE.md) · [LEDGERS.md](LEDGERS.md) · [handoff/measure.md](handoff/measure.md)

---

## Q-030 · The canonical execution cycle — DERIVE IT, do not adopt a proposal

Erwin explicitly said not to accept his own sketch. Three candidate shapes were offered
(`recon x3 -> enum -> scan -> probe`; a fully repeated pipeline; recon/enum interleaved) and his own
instinct was a graph-driven loop. **Derive the real model from the components that exist** —
`agent/planner.py`, `agent/technique_planner.py`, `agent/asset_graph.py`, the autonomy loop in
`agent/agent.py`, `agent/engine_descriptor.py` — and say what the code actually does today before
proposing what it should do.

Must define exactly: what constitutes a cycle · whether "3 cycles" is a real thing or an artifact ·
what changes between cycles · what triggers another discovery pass · what stops rediscovery · how
duplicate work is prevented · how newly discovered endpoints, credentials, sessions, roles, objects,
APIs, states and attack paths feed the next iteration.

**Maximum throttle is not "repeat everything".** It is maximum useful deterministic work with zero
duplicate work. A convergence criterion is mandatory: the loop must terminate on a deterministic
fixpoint (no new graph facts) or an explicit budget, never on a hardcoded pass count.

## Q-031 · Rediscovery triggers, from the graph rather than a counter

A new discovery pass is justified by a **new fact class**, not by a loop index. Candidate triggers to
evaluate against `asset_graph`: new hostname · route · API · schema · application state · privilege ·
persona · credential · authenticated session · object type · tenant · technology · protocol ·
attack-path prerequisite · a probe result that exposes new surface. The planner/AssetGraph decides;
`fresh()` already dedups planner steps against `done`, so the anti-duplicate mechanism partly exists —
check it before building another.

## Q-032 · Credential -> validated session -> persona, event-driven

Required flow: credential candidate -> deterministic validation -> secure storage by reference ->
identify the auth mechanism -> authenticate in an isolated context -> validate identity -> capture
session through a **secret-safe handle** -> bind to persona + identity + tenant + role -> write the
authenticated capability into AssetGraph -> planner sees the unlocked surface -> authenticated
discovery begins -> anonymous testing CONTINUES.

**Not** "steal a cookie and spray it through every scanner." Sessions are persona-bound,
origin/scope-bound, lifecycle-aware, refreshable, isolated, secret-safe, and replayable **through
handles, never raw credentials in logs or reports**. Timing is graph-driven: credentials found in
cycle 1 unlock authenticated work as soon as validated — never gated on a cycle number.
Existing infrastructure to extend rather than duplicate: `agent/personas.py`, `agent/register.py`,
`agent/session_lifecycle_tool.py` (CWE-613, just shipped), `agent/bie.py` persona-swap.

## Q-033 · Multi-persona coexistence and differential testing

Persona 0 = anonymous and **is never replaced** after login. Each persona isolates browser context,
cookie/session state, token handles, storage, identity/tenant/role facts, discovered states, reachable
endpoints, object ownership. Enables deterministic differentials: anon<->auth, userA<->userB,
user<->admin, tenantA<->tenantB, owner<->non-owner, pre/post-auth, pre/post-privilege. Feeds authz
testing, BOLA/IDOR, BFLA, field-level authz, workflow abuse, session lifecycle, cross-tenant, and
attack-path reasoning. `agent/bie.py` already does runtime persona-swap BOLA — audit what exists
before adding.

## Q-034 · Report chronology and provenance

The report must show WHEN capability transitions happened: discovery iteration · timestamp · producer
· evidence reference · credential-found event · validation event · persona creation · authentication
event · privilege/role · newly unlocked capabilities · findings enabled by that transition · anonymous
vs authenticated coverage separately · attack-path evolution.
**Never expose raw credentials, tokens, cookies or session IDs.** Redacted keyed references only.

---

## Q-035 · Model + effort configuration — an EXPERIMENT, not an opinion

Erwin asked for a measured recommendation across Opus 5 / 4.8 / 4.7 / 4.6 for Builder, cheap parallel
agents, and verification/research. **There is no measured evidence in this repository, so no
recommendation has been given, twice.** Anything asserted without the experiment would be invention
dressed as analysis — the exact failure this project keeps retracting.

The experiment that would settle it: take one ticket of known shape (a small Builder slice with a
negative control, e.g. a `docs/handoff/architecture.md` D-item), run it under each model at fixed
effort, and record **tokens-to-green**, tool calls, whether the negative control was written unasked,
and whether the first patch passed the mutation check. Repeat on one Breaker task, where depth mattered
most (the two highest-value runs so far were 64 and 78 tool calls).

Standing hypothesis, **UNTESTED**: the discipline rules — commit-per-slice, write-as-you-go, mandatory
negative controls — bound the blast radius of a bad decision, which should lower the model requirement
for **Builders** specifically. The **Breaker** and **Architect** roles are where model strength has
visibly paid. Do not act on this until it is measured.

## Q-036 · Fold the 15 verified defects into the canonical queue

`docs/handoff/architecture.md` §6.1 carries **15 VERIFIED DEFECTS, 6 MISSING EVIDENCE, 10 UPGRADE
OPPORTUNITIES**, each with `file:line` and the module to extend. They live in a handoff file, which
means they are evidence, not work — the Coordinator owns folding them into `QUEUE.md` as tickets.

Build order from §6.5, cheapest-first and each independently shippable:

1. **D3, D5, D6, D13** — all small, all revive machinery that is already written and dead.
   (D3 is one line for an immediate coverage gain.)
2. **D1 + D15 + D14** — the loop: delete the inert pass count, add `fact_signature`, fix the budget check.
3. **D2 + D4** — the dedup ledger key (8 probes for 5 URLs; `params` dropped so `q` is never tested).
4. **U1** — execute the ranked actions. **Q-030 is complete at this point.**
5. Section 2 trigger table (needs 1–4).
6. Section 3 secret-safe handle + event-driven credential artery (D7, D9, D10) → Q-032.
7. Section 4 persona-as-ledger-dimension (D11) → Q-033.
8. Section 5 events + timeline (U8) → Q-034, rendered **last** so it can only report what the earlier
   steps actually record.

**Every step needs the negative control proving the OLD behaviour is gone**, not merely that the new
one exists. D5, D6 and D7 are each a case where a mechanism was declared present and was measurably
inert — the exact shape this project has shipped four times.

## Sequencing note

These are large and they all depend on Q-030 being settled first — a credential/persona/report design
built on the wrong cycle model has to be rebuilt. Meanwhile the benchmark score is limited by
something entirely separate and much cheaper (probe repertoire, see `handoff/measure.md` Job 3), so
score work and architecture work do not compete for the same lane.
