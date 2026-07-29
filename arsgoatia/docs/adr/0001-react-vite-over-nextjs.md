# ADR-0001: React + Vite over Next.js

**Status:** Accepted
**Date:** 2025-01-15
**Deciders:** Architecture team

## Context

ArsGoatia needs a web frontend for its operator console -- the dashboard where
security engineers configure assessments, review findings, approve gated
actions, and browse attack-chain reports. The two strongest candidates were
Next.js (React meta-framework with SSR/ISR) and plain React with Vite as the
build tool.

Key considerations:

- The console is an internal operator tool, not a public-facing site. SEO and
  server-side rendering provide no benefit.
- The API layer is a FastAPI backend; adding a Node.js server for SSR doubles
  the runtime surface.
- The deployment target is a single-node Docker Compose stack (see ADR-0003).
  Serving static assets through nginx keeps the stack simple.
- Developer iteration speed matters more than framework features we will never
  use.

## Decision

Use React with Vite for the frontend build. The production artifact is a static
bundle served by nginx, which also reverse-proxies API requests to the FastAPI
backend.

No Next.js, no Node.js runtime in production.

## Consequences

**Positive:**

- Faster build and HMR cycles during development (Vite's native ESM dev
  server).
- Smaller production image -- static files only, no Node.js process.
- Single nginx container handles both static serving and API proxying, reducing
  the number of moving parts.
- No framework lock-in on routing or data-fetching conventions.

**Negative:**

- If a public-facing marketing site or documentation portal is added later, SSR
  would need to be reconsidered.
- Client-side routing requires nginx `try_files` configuration for SPA
  fallback.
- No built-in API routes; all server logic lives in the FastAPI backend (this
  is intentional, but means no quick server-side endpoints in the frontend
  repo).

## Notes

- If SSR becomes necessary in the future, Vite's own SSR support or a
  lightweight framework like TanStack Start can be evaluated without replacing
  the entire build toolchain.
- The nginx configuration is defined in `infrastructure/nginx/` and handles
  `/api/*` proxying plus SPA fallback.
