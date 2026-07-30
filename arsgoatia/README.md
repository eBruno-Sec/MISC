# ArsGoatia

Unified Deterministic Autonomous Security Validation Platform.

ArsGoatia is a durable, explainable, multi-domain penetration-testing orchestration platform.
Every target interaction is authorized, scoped, policy-gated, signed, and evidence-backed.
AI proposes; deterministic engines decide.

## Architecture

```
┌─────────────┐    ┌─────────────┐    ┌──────────────┐
│   Web UI    │───▶│  FastAPI     │───▶│  PostgreSQL  │
│  React/Vite │    │  Control     │    │  (canonical) │
└─────────────┘    │  Plane       │    └──────────────┘
                   └──────┬───────┘            │
                          │                    │
                   ┌──────▼───────┐    ┌───────▼──────┐
                   │   Temporal   │    │    MinIO      │
                   │  Workflows   │    │  (evidence)   │
                   └──────┬───────┘    └──────────────┘
                          │
              ┌───────────┼───────────┐
              │           │           │
        ┌─────▼────┐ ┌───▼─────┐ ┌──▼──────┐
        │  Recon   │ │  IDOR   │ │ Report  │
        │ Activity │ │ Module  │ │ Gen     │
        └──────────┘ └─────────┘ └─────────┘
```

## Core Invariants

1. **No target interaction without valid authorization** -- engagement must be authorized, in-scope, and within its time window
2. **Immutable revisions** -- engagement specs, evidence, and audit events are append-only
3. **Deny-overrides-allow** -- scope exclusion rules always win
4. **Signed action envelopes** -- every target-facing request carries an HMAC-SHA256 envelope binding action, target, approval, and expiry
5. **Most-restrictive policy wins** -- policy layers evaluate independently; the most restrictive outcome prevails
6. **Exact approval binding** -- approvals bind to a specific action proposal, not a category
7. **Temporal determinism** -- workflows are replay-safe; all IO lives in activities
8. **Tenant isolation** -- row-level security on every table
9. **Secrets as references** -- JWTs/passwords never appear in logs, evidence, prompts, or history
10. **Evidence is immutable and digest-addressed** -- SHA-256 content hashes stored in MinIO
11. **Deterministic confirmation only** -- no AI in the finding-confirmation path
12. **AI proposal-only** -- AI suggests hypotheses and rankings; it never executes, approves, or changes scope

## Risk Tiers

| Tier | Description | Default Decision |
|------|-------------|-----------------|
| R0 | Offline / no target contact | Auto-allow |
| R1 | Passive observation only | Auto-allow |
| R2 | Bounded active (read-only probes) | Allow (may require approval per rules) |
| R3 | State-changing | Require one-person approval |
| R4 | High-impact | Deny by default (two-person auth) |
| R5 | Destructive | Always denied |

## Project Structure

```
arsgoatia/
├── apps/api/          # FastAPI control plane
├── packages/
│   ├── contracts/     # Pydantic v2 schemas (source of truth)
│   ├── crypto/        # HMAC signing, digests, nonces
│   ├── domain/        # Pure domain models (governance, evidence, findings, IAM, ...)
│   ├── persistence/   # SQLAlchemy 2.0 ORM, async sessions
│   ├── policy/        # Deterministic policy engine
│   └── scope/         # Scope enforcement & firewall
├── packs/techniques/  # Technique manifests & confirmation logic
├── services/worker/   # Temporal workflows & activities
├── tests/unit/        # Unit tests (74 tests)
├── deploy/compose/    # Docker Compose
├── infrastructure/    # PostgreSQL init, Temporal config
└── migrations/        # Alembic (async)
```

## Quick Start

```bash
# Prerequisites: Docker, Python 3.12+

# Copy environment
cp .env.example .env

# Start the full stack (core services, UI, lab targets)
docker compose -f deploy/compose/docker-compose.yml \
  --profile core --profile ui --profile lab up --build -d

# Health checks
curl -sf http://localhost:8080/health         # API
curl -sf http://localhost:3100/healthz        # Web console
# Temporal UI at http://localhost:8088
# MinIO console at http://localhost:9101

# Run migrations (once the stack is up)
docker compose -f deploy/compose/docker-compose.yml exec api alembic upgrade head

# Run tests
python -m pytest tests/unit -q
```

## Development

```bash
# Install dependencies
pip install -e ".[test]"

# Lint
ruff check .
ruff format --check .

# Run all unit tests
python -m pytest tests/unit -v

# Start worker (requires Temporal)
python -m services.worker.worker
```

CI runs on every change under `arsgoatia/**`
(`.github/workflows/arsgoatia-tests.yml`).

## Layout

```
apps/        api (FastAPI), web (React/Vite), evidence (content-addressed store)
packages/    contracts, domain, policy, planner, evidence, events, ai_gateway,
             crypto, envelope, scope, approval, capability, cleanup,
             hypothesis, identity, persistence, config, observability
modules/     web/authorization_idor (BOLA slice), + intent stubs
packs/       techniques (bola_differential), tools, labs
services/worker/  Temporal workflows + activities (recon, validation, evidence, ...)
infrastructure/   postgres init.sql
deploy/compose/   docker-compose.yml (profiles: core, ui, graph, lab)
docs/adr/    architecture decision records
tests/       unit, contract, replay, security, integration, isolation, performance, e2e
```

## Deterministic reasoning layer (post-slice)

Extending ArsGoatia toward the Deterministic Cyber Reasoning, Planning and
Execution vision (structured reasoning decides, LLMs never in the control path).
`packages/reasoning/` adds pure, replayable engines:

- **Constraint solver** — fail-closed elimination of any action violating scope,
  testing window, rate, data-handling, mutation, approval, or risk class.
- **Attack graph + pathfinding** — GOAP-style best-first search over capability
  states, ranked by strategy (shortest / highest-confidence / lowest-noise /
  least-privilege / lowest-cost).

Next candidates: truth-maintenance system, HTN/GOAP goal decomposition, Bayesian
confidence, property/metamorphic testing engines, MCTS + multi-armed-bandit
test-order learning.

## Scope

The slice covers spec Phases 0–4. Phases 5–7 (network / cloud / Active Directory
/ Kubernetes / SaaS domains, full standards coverage, multi-region hardening) are
future work. Deviations from the spec are recorded in [`docs/adr/`](docs/adr/).
## Milestones

- **M0** Contracts & scaffold -- Pydantic schemas, project structure, compose
- **M1** Control plane -- PostgreSQL schema, ORM, API, Temporal skeleton
- **M2** Recon & evidence -- HTTP recon, MinIO evidence, digests
- **M3** Policy & identities -- Policy engine, scope firewall, signed envelopes, identity bootstrap
- **M4** IDOR module -- BOLA differential validation, deterministic confirmation, capabilities
- **M5** Planner & AI -- Hypothesis proposals, deterministic ranking, budget/redaction
- **M6** Reporting & e2e -- Atomic + chain reports, SARIF, full slice test, replay

## License

Proprietary. All rights reserved.
