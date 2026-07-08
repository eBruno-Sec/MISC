# OLYMPUS — Engineering Handoff / Project State

Read this first if you're an AI or engineer picking up work on OLYMPUS. It is the
portable source of truth (the git history + this file + the READMEs). Pair it with
`git log --oneline` for the detailed per-feature commit messages.

---

## What it is
Self-hosted, Docker-native AI-orchestrated web pentest / BBH / red-team platform.
Eight "Greek god" agents run in sequence over FastAPI + async SQLAlchemy (asyncpg) +
Postgres + Redis + React/Vite + nginx, plus an OWASP ZAP daemon. Give it a target +
mode; the gods recon → scan → exploit → triage → report.

**Agents (`backend/agents/`):** zeus (orchestrator), athena (AI strategy/scope),
hermes (recon), ares (active scan; mixes `offensive.py` OffensiveEngine + `auth.py`
AuthEngine), hephaestus (payload forge), hades (post-exploit), metis (AI triage),
apollo (report).

---

## How work ships (the workflow)
- **Dev on Windows, run on Kali.** Erwin edits + commits + pushes from Windows; then
  on Kali: `git pull origin main && docker compose up --build -d`. He does NOT compile
  locally on Windows (no Node/Docker there).
- **The Docker build IS the test.** `docker compose up --build` runs backend + the
  frontend's `tsc && vite build`. A frontend type error fails the frontend image build
  (the running UI keeps the old image) — that's the tsc gate. There's no local `tsc`.
- **Frontend caution:** because the frontend can't be compiled on the Windows dev box,
  either (a) push a self-audited change to main and let the Kali `--build` verify, or
  (b) for big UI work use a branch, have Erwin run `docker compose build frontend` /
  `npm run build`, then merge when green. `feat/workbench-ui` was that branch (now
  merged). `npm run build` needs `npm install` first (deps aren't committed).
- **Non-breaking is paramount.** Prefer additive changes. Small, focused commits.
- End commit messages with the Co-Authored-By trailer.

---

## Hard constraints / conventions (learned the hard way)
- **`Base.metadata.create_all` only — NO Alembic migrations.** It creates missing
  *tables* but does NOT add *columns* to existing tables. So: new tables are fine
  (HttpExchange, AuthProfile were added this way); a new **column on an existing table
  will break existing DBs**. Store new mission-level flags in the existing
  `mission.context` JSON instead (that's how `auto_approve` works).
- **Never silently hide findings.** METIS is advisory-only — it annotates
  `analyst_notes`, it never sets `tag=false_positive` or deletes. APOLLO reports every
  finding. (A past regression tagged FPs + hid them, gutting a 466-finding report to 2.)
- **Scope safety on every active probe.** Requests are scoped to the mission's target
  host; form/redirect/spec discovery stay same-host; the workbench refuses off-scope
  hosts. Keep it that way.
- **Single AI provider config.** `core/ai_client.complete()` + env `AI_PROVIDER` /
  `AI_API_KEY` / `AI_MODEL` / `AI_BASE_URL` (anthropic or openrouter). AI is optional —
  METIS/ATHENA/APOLLO-summary no-op without a key; everything else is deterministic.
- **Frontend strict TS** (`tsc`, strict:true). Watch: no `number|null !== undefined`
  (TS2367), narrow `Map.get`/`.find` before use, inline `type` imports.

---

## What's built (all on `main`)
- **Recon (HERMES):** subfinder/crt.sh/DNS-brute, httpx fingerprint, subdomain-takeover,
  explicit `host:port` scanning, **CIDR subnet sweep** (`x.x.x.x/24`, web-liveness,
  cap `OLYMPUS_CIDR_MAX_HOSTS`) + **nmap network sweep** on CIDR ranges (host discovery
  + curated service scan → finds non-web boxes: SSH/RDP/SMB/DB/Redis/Docker; grouped
  exposure findings + an inventory summary; result key `network_hosts`).
- **Active (ARES + offensive.py):** nmap, nuclei (+OAST), katana crawl, Wayback archive
  params, arjun-style param mining, **API/SPA endpoint seeding**, **OpenAPI/Swagger
  import**, **form/POST discovery + injection**, sqlmap (GET + `--forms`), dalfox,
  SSRF/SSTI/CORS/open-redirect/host-header probes, **auto-fuzz**, ffuf, OWASP ZAP,
  authenticated scanning (AI login via auth.py), **redirect mapping**.
- **AI triage (METIS):** FP flag (advisory), CWE/OWASP mapping, **attack-path chaining**.
- **AI/LLM surface detection (`core/ai_surface.py`):** deterministic (no requests, no
  LLM) classifier tags discovered endpoints as chat / completion / embedding / tool-call
  / MCP / vector-DB. ARES emits an advisory finding; `/surface` returns `ai_surface[]` +
  `coverage.ai_endpoints`; SURFACE tab lists them as manual LLM-red-team candidates.
  (Concept borrowed from RedAmon's AI Gauntlet — this is the map; active LLM probing TBD.)
- **Evidence/PoC:** `HttpExchange` model + `core/poc.py` (curl / raw-HTTP / Markdown,
  header redaction) + export endpoints.
- **Manual workbench:** `core/replay.py` (send/fuzz/diff/score/access_verdict) + endpoints
  `/replay` `/fuzz` `/diff` `/profiles` `/access-check` `/surface`.
- **Report (APOLLO):** escaped + nonce-CSP HTML, coverage panel, attack surface,
  discovered paths, manual-test candidates.
- **UI (frontend, 4 tabs):** SURFACE (inventory), WORKBENCH (Repeater+Intruder), ACCESS
  (cross-role IDOR/BOLA), TOPOLOGY (site-map tree, rounded rects + curved edges +
  dashed redirect arrows).
- **Workflow:** pre-authorize/autonomous gate toggle at launch (or env
  `OLYMPUS_AUTO_APPROVE=1`), **mission heartbeat** (`OLYMPUS_HEARTBEAT_SECONDS`, default
  300s), scope-file upload, wordlists, PortSwigger-lab Oracle.
- **Tests:** `backend/tests/` — poc, replay, surface, forms, security, network-sweep,
  ai-surface. Run: `docker compose exec backend python -m pytest tests/ -q`.

---

## Key gotchas (for running / debugging)
- **Local Docker targets (Juice Shop etc.):** put the target container on OLYMPUS's
  network and target it by **container name + internal port** (`juice-shop:3000`), NOT
  `host.docker.internal:PORT` (that's the Docker host, not the container). `0 live hosts`
  = unreachable-from-scanner, not "clean".
- **Juice Shop OOM:** the Node app can exceed the default ~2 GB V8 heap and crash
  (`JavaScript heap out of memory`). Run it with `-e NODE_OPTIONS=--max-old-space-size=4096`.
- **Demo targets aren't "swimming" for scanners.** PortSwigger/Juice Shop bugs are built
  for MANUAL exploitation — automated finds the surface (vuln JS, CSP/CSRF, SPF/DMARC,
  form/GET injection); the deep bugs come from the WORKBENCH/ACCESS tabs. Finding *count*
  is deduped (1 finding = N instances). Live-external scans vary run-to-run (ZAP/nuclei).

---

## Not built yet (candidate next steps)
- **Active LLM red-teaming module.** AI *surface detection* is in (`core/ai_surface.py`);
  the next step is active probing of the tagged endpoints (prompt-injection / jailbreak /
  system-prompt-extraction payloads, ASR scoring), RedAmon-AI-Gauntlet style but lighter.
  Keep it deterministic + scope-safe; gate it behind the approval flow.
- **APOLLO/UI panel for `network_hosts`.** The CIDR nmap network sweep now populates
  `hermes["network_hosts"]` (`[{ip,status,ports:[{port,proto,service,version}]}]`) and
  a coverage count (`surface.coverage.network_hosts`), but there's no dedicated report
  section or TOPOLOGY rendering yet — results surface only via findings + the SURFACE
  stat tile. A "Network Hosts" table in APOLLO/SURFACE is the natural next step.
- **Promote nonstandard web ports into `live_hosts`.** The network sweep may find a web
  server on a port httpx missed (e.g. 8080); those aren't yet fed to ARES for web scans.
- **UDP / full-range sweep.** Network sweep is TCP-connect (`-sT`) over a curated port
  set (`NETWORK_SWEEP_PORTS` in `hermes.py`); no UDP, no full 1-65535.
- Screenshots/artifacts (needs a headless-chromium/Playwright dependency — not installed).
- Redirect edges only cover same-host hops between two *discovered* endpoints.

---

## Config quick reference (`.env`)
`AI_PROVIDER` / `AI_API_KEY` / `AI_MODEL` / `AI_BASE_URL`, `OLYMPUS_API_KEY` (optional
gate), `OLYMPUS_OFFENSIVE_MAX_HOSTS` (default 5), `OLYMPUS_CIDR_MAX_HOSTS` (1024),
`OLYMPUS_AUTO_APPROVE` (autonomous), `OLYMPUS_APPROVAL_TIMEOUT` (0 = wait forever),
`OLYMPUS_HEARTBEAT_SECONDS` (300).
