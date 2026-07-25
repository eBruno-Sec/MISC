# ADR 0001 — FastAPI + React/Vite instead of Next.js

- Status: Accepted (slice)
- Date: 2026-07-25

## Context
The spec's repo tree names `apps/web` and `apps/api` without mandating a
framework. The rest of this monorepo's security tools (olympus, Yggdrasil,
apolaki) are FastAPI backends with static/SPA frontends served by nginx.

## Decision
Build the control plane as a FastAPI service (`apps/api`) and the UI as a React +
Vite SPA (`apps/web`) served by nginx, which proxies `/api` to the API service.

## Consequences
- No SSR (the control plane is an internal, authenticated app that does not need
  it), and alignment with the team's existing stack and deployment pattern.
- The "AI proposes only" and provider-abstraction invariants are unaffected;
  they live in the API/worker layers, not the frontend.
- If server-rendered public surfaces are ever needed, revisit.
