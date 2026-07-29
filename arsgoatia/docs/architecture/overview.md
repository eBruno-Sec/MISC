# ArsGoatia — Architecture Overview

## Platform Purpose

ArsGoatia is a durable, explainable, multi-domain penetration-testing orchestration platform.
It encodes security knowledge as deterministic modules, enforces layered policy at every
execution boundary, and produces immutable, auditable evidence for every confirmed finding.

## Core Design Invariants

| Invariant | Where enforced |
|-----------|---------------|
| AI proposes only — never executes, approves, or changes scope | `packages/planner`, `packages/ai_gateway` |
| Modules never import modules | static import scan in `tests/replay` |
| Every action requires a signed, policy-evaluated envelope | `packages/envelope`, `packages/policy` |
| Scope firewall runs in every executor, fails closed on ambiguity | `packages/scope` |
| Evidence is append-only and immutable after capture | `packages/application` command handlers |
| Capabilities are emitted only when a finding is confirmed with evidence | `packages/capability` |
| All orchestration IO lives in activities (workflow purity boundary) | `services/worker/workflows` |

## Component Map

```
┌─ apps ─────────────────────────────────────────────────────────────┐
│  api/          FastAPI control plane (engagements, findings,        │
│                approvals, evidence, reports)                        │
│  evidence/     Evidence retrieval service (append-only reads)       │
│  web/          React frontend (Next.js/Vite)                        │
└─────────────────────────────────────────────────────────────────────┘

┌─ services ──────────────────────────────────────────────────────────┐
│  worker/       Temporal worker — root+child workflows + activities  │
│  outbox/       Transactional outbox relay (event fan-out)           │
│  capture/      TrafficMind proxy sidecar (HTTP exchange capture)    │
│  ai-gateway/   AI provider wrapper with budget + redaction          │
│  scheduler/    Engagement lifecycle scheduler                       │
└─────────────────────────────────────────────────────────────────────┘

┌─ packages ──────────────────────────────────────────────────────────┐
│  domain/           Core domain models (engagement, finding, etc.)   │
│  application/      Command/query handlers (CQRS)                    │
│  policy/           8-layer policy engine + scope firewall           │
│  envelope/         Signed action envelope (HMAC-SHA256 in dev)      │
│  planner/          8-layer deterministic scoring + AI advisory      │
│  module_sdk/       Module lifecycle ABC + frozen data types         │
│  capability/       Capability registry (proven-only emission)       │
│  hypothesis/       Hypothesis lifecycle + truth maintenance         │
│  approval/         Approval registry (action-bound, idempotent)     │
│  events/           Event bus + transactional outbox                 │
│  crypto/           HMAC signing, envelope verification              │
│  scope/            Scope firewall (deny-overrides-allow)            │
│  ai_gateway/       Structured AI calls with redaction + budget      │
│  graph/            Attack graph + pathfinding (Dijkstra, BFS)       │
│  reasoning/        Constraint solver + truth maintenance            │
└─────────────────────────────────────────────────────────────────────┘

┌─ modules ───────────────────────────────────────────────────────────┐
│  web/authorization_idor/   BOLA/IDOR differential (R2, §14.1)       │
└─────────────────────────────────────────────────────────────────────┘

┌─ packs ──────────────────────────────────────────────────────────────┐
│  tools/       ToolPack definitions (http_probe, nuclei, ...)        │
│  workflows/   WorkflowPack definitions (BOLA assessment flow)       │
│  labs/        Lab target definitions (Juice Shop, DVWA, ...)        │
│  policy/      PolicyProfile definitions (lab-safe, prod-strict)     │
│  reports/     Report template definitions                           │
│  knowledge/   CWE/OWASP knowledge base                             │
└─────────────────────────────────────────────────────────────────────┘
```

## Engagement Lifecycle (§8.1)

```
DRAFT → AUTHORIZED → SCOPE_COMPILATION → RECON → ACTIVE
  ↓                                                 ↓
CANCELLED                              PAUSED ⇌ ACTIVE
                                           ↓
                                    STOPPING → STOPPED
                                           ↓
                                    REPORTING → COMPLETED
```

All state transitions are recorded as immutable revisions; no row is
ever updated or deleted on the happy path.

## Data Store Roles

| Store | Role |
|-------|------|
| PostgreSQL | Canonical truth: engagements, findings, capabilities, evidence metadata, audit |
| MinIO | Immutable binary evidence (request/response bodies, screenshots, reports) |
| Temporal | Durable orchestration state, signal delivery, activity retry |

## §37 Vertical Slice (First End-to-End)

The first deliverable exercises every hard invariant end-to-end against OWASP Juice Shop:

1. Authorized assessment with scope `juice-shop:3000`
2. Safe HTTP recon → discovers object endpoints
3. Observation → hypothesis → R2 policy → `require_approval`
4. Workflow pauses at approval gate
5. `ProvideApproval` signal resumes workflow
6. IDOR differential execution (4 HTTP exchanges)
7. Deterministic `confirm()` → finding=confirmed
8. Immutable evidence stored in MinIO
9. `read_foreign_object` capability emitted
10. Attack-chain step created
11. Atomic + chain reports generated (JSON + SARIF)
12. Replay test passes after activity-only code change

See `tests/integration/test_vertical_slice.py` for the in-memory slice test.
See `tests/replay/` for structural replay + determinism boundary checks.
