# ArsGoatia

A durable, explainable, multi-domain **penetration-testing orchestration
platform**. Where the other security tools in this repo run recon → web
exploitation, ArsGoatia adds what they lack: a **capability / access-context
model**, **durable orchestration** (Temporal), an **immutable evidence store**,
and **cross-domain attack chaining** — every action policy-checked, scope-fenced,
and signed.

> Status: **building the first vertical slice** (spec Phases 0–4). This is not the
> whole platform; see [Scope](#scope) and [Milestones](#milestones).

## What it does (the slice)

One end-to-end, **lab-safe** assessment against [OWASP Juice
Shop](https://owasp.org/www-project-juice-shop/):

1. Create an **authorized** assessment and compile an explicit **scope** (one web
   target).
2. **Safe HTTP recon** discovers login and object endpoints.
3. Establish **two** standard-user test identities.
4. Run the **object-authorization (IDOR/BOLA)** module.
5. Record an **observation** → propose a **hypothesis** → **policy decision**.
6. Human **approval** (action-bound) gates the differential requests; the
   workflow **pauses** and **resumes** on approval.
7. Store **immutable, content-addressed evidence** (request/response) with hashes.
8. **Deterministically confirm** the finding (positive + negative controls).
9. Produce a `read_foreign_object` **capability** and one **attack-chain step**.
10. Generate an **atomic-finding** and an **attack-chain** report (HTML + JSON +
    SARIF).
11. **Replay** the workflow history after a code change.

## Hard invariants

These are non-negotiable and enforced in code, not convention:

- **Temporal** owns orchestration durability; all IO/AI/tool calls live in
  activities (deterministic replay).
- **PostgreSQL** is canonical: UUID PKs, `tenant_id` everywhere, immutable
  revisions, append-only audit/evidence, row-level security.
- **MinIO** stores immutable, content-addressed evidence.
- Every target-facing action carries a **signed action envelope**; the executor
  re-verifies it and re-runs the **scope firewall**, which **fails closed**.
- The **policy engine** is layered and picks the most restrictive decision.
- **AI proposes only** — it never executes target actions, approves, changes
  scope, invents evidence, or receives raw secrets. AI is optional; the pipeline
  degrades to deterministic without it.
- **Modules never invoke modules** — cross-module progress flows only through
  produced capabilities via the planner.

## Run it

```bash
cp .env.example .env                       # set AI_API_KEY if you want AI (optional)
docker compose --profile lab up --build -d # brings up the stack + Juice Shop
```

| Surface        | URL                     |
|----------------|-------------------------|
| API            | http://localhost:8080/api/v1 |
| Web UI         | http://localhost:3100   |
| Temporal UI    | http://localhost:8088   |
| MinIO console  | http://localhost:9101   |

Ports are chosen to avoid the repo's existing 3000/8000.

## Tests

```bash
pip install -e ".[test]"
python -m pytest tests/ -q
```

CI runs on every change under `arsgoatia/**`
(`.github/workflows/arsgoatia-tests.yml`).

## Layout

```
apps/        api (FastAPI), web (React/Vite), worker-control, worker-web
packages/    schemas, domain, policy, planner, evidence, events, ai_gateway,
             module_sdk, tool_sdk, temporal_common, audit, config
modules/     web/authorization_idor (the slice's module), + intent stubs
temporal/    root + child workflows and their activities
infrastructure/  postgres init, temporal dynamic config
docs/adr/    architecture decision records (deviations from the spec)
tests/       unit, contract, replay, security, e2e
```

## Scope

The slice covers spec Phases 0–4. Phases 5–7 (network / cloud / Active Directory
/ Kubernetes / SaaS domains, full standards coverage, multi-region hardening) are
future work. Deviations from the spec are recorded in [`docs/adr/`](docs/adr/).

## Milestones

- **M0** Contracts & scaffold — schemas, compose, CI. *(done)*
- **M1** Control plane — Postgres schema, RLS, immutability, outbox/audit,
  lifecycle state machine, AssessmentWorkflow skeleton, create/authorize/
  compile-scope/pause/resume API. *(done)*
- **M2** Recon & evidence — scope firewall + target guard (ported), safe HTTP
  recon activity, content-addressed MinIO evidence store, asset/service/endpoint/
  evidence tables, timeline read API. *(current)*
- **M3** Policy, envelope, identities.
- **M4** IDOR module, validation, capability.
- **M5** Planner, chain, AI gateway.
- **M6** Reporting, e2e, replay.

## Authorized use only

ArsGoatia acts against systems only under a verified authorization record and an
explicit scope. The default policy profile is `lab-safe`. Do not point it at
anything you are not authorized to test.
