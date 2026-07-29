# ADR-0003: Single-Node Docker Compose for Dev/Lab

**Status:** Accepted
**Date:** 2025-01-15
**Deciders:** Architecture team

## Context

ArsGoatia must be deployable for development and lab-environment testing. The
platform comprises several services (API, worker, scheduler), supporting
infrastructure (PostgreSQL, MinIO, Temporal), and target applications (e.g.,
OWASP Juice Shop). Two deployment strategies were evaluated:

1. **Kubernetes from day one** -- Define Helm charts or Kustomize manifests and
   use a local K8s distribution (minikube, kind) for development.
2. **Docker Compose** -- Define the entire stack in a single
   `docker-compose.yml` with all services on one node.

Key factors:

- The initial user base is a single operator or small team running the platform
  on a workstation or a single cloud VM.
- Kubernetes adds operational complexity (networking, storage classes, RBAC,
  ingress) that provides no benefit at lab scale.
- Fast `docker compose up` startup is critical for developer experience and
  demo environments.

## Decision

Use a single-node Docker Compose file as the primary deployment method for
development and lab environments. Kubernetes manifests are deferred until
multi-node or production deployment is required.

## Consequences

**Positive:**

- **Zero Kubernetes overhead** -- No cluster bootstrap, no kubectl context
  management, no PVC provisioning for local dev.
- **Single command startup** -- `docker compose up -d` brings the entire
  platform online, including target applications.
- **Reproducible** -- The compose file pins image versions and defines all
  networking, making the environment deterministic.
- **Low resource footprint** -- No kubelet, etcd, or control-plane processes
  consuming memory on the developer's machine.

**Negative:**

- **No horizontal scaling** -- Services cannot be scaled across nodes without
  migrating to an orchestrator.
- **No built-in rolling updates** -- Compose `up --build` restarts containers;
  there is no zero-downtime deployment story.
- **Divergence risk** -- The Compose topology may drift from an eventual
  Kubernetes deployment if not carefully managed.

## Notes

- **Production upgrade path:** When multi-node deployment is needed, extract
  the Compose services into Helm charts. The container images and environment
  variable contracts remain identical; only the orchestration layer changes.
- The compose file lives at `docker-compose.yml` in the repository root.
- Target applications (Juice Shop, etc.) are defined as separate compose
  profiles so they can be started independently.
- Related: ADR-0002 (outbox avoids needing a broker in the compose stack).
