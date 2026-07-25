# ADR 0004 — Single-node Docker Compose for dev; Kubernetes deferred

- Status: Accepted (slice)
- Date: 2026-07-25

## Context
The spec's production deployment (§35) is Kubernetes with separate control/worker
namespaces, network policies, sandbox runtimes, dedicated high-risk worker nodes,
and controlled egress gateways. The vertical slice targets a developer laptop and
CI.

## Decision
Ship a single-node `docker-compose.yml` with compose profiles (`core`, `lab`,
`observability`). Queue separation is modeled by Temporal task queues on two
worker services (`worker-control`, `worker-web`) rather than by K8s node pools.

## Consequences
- The production network zones (§35) and dedicated high-risk validation nodes are
  future work; the slice documents them but does not build them.
- The tool executor still enforces the scope firewall and egress allowlist in
  code, so the safety posture does not depend on K8s network policy for the slice.
