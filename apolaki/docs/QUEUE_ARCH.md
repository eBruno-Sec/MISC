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

## Sequencing note

These are large and they all depend on Q-030 being settled first — a credential/persona/report design
built on the wrong cycle model has to be rebuilt. Meanwhile the benchmark score is limited by
something entirely separate and much cheaper (probe repertoire, see `handoff/measure.md` Job 3), so
score work and architecture work do not compete for the same lane.
