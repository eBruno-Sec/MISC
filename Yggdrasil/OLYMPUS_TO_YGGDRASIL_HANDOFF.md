# OPUS → CODEX INTEGRATION HANDOFF
## Olympus → Yggdrasil Migration Blueprint

**Handoff version:** 1.0  •  **Prepared:** 2026-07-12  •  **Owner:** OPUS (principal architect)  •  **Consumer:** Codex

> **This document is the sole authoritative source** for the Olympus → Yggdrasil integration. Codex must not deviate from the acceptance criteria, security requirements, or rollback semantics without an explicit OPUS revision.

---

## PRIMARY UNCERTAINTY — READ FIRST

**Yggdrasil does not exist as an accessible repository, workspace directory, or MCP-listed source at the time of this handoff.** I inspected:

- The primary working directory `/home/user/MISC` (contents: `olympus/`, plus 25+ unrelated toy projects — no `yggdrasil/`, `Yggdrasil/`, `YGG*`, or Norse-named platform folder).
- The full `eBruno-Sec/MISC` git history back through `9200d3b` — zero commits mentioning Yggdrasil.
- Every `.md`, `.txt`, `.json`, `.yml`, `.yaml`, `.py`, and `.tsx` in the workspace — the *only* string match for "Yggdrasil" is a single **comment** in `backend/agents/apollo.py:144` that credits Yggdrasil as an *inspirational prior* for coverage transparency:
  > `"This is the coverage transparency Yggdrasil won on, kept honest"`
- All repositories owned by `eBruno-Sec` via the remote lister — five repos, none named or aliased Yggdrasil (`MISC`, `cybersecurity-portfolio`, `cybersecurity-learning-portfolio`, `ai-agent-generator`, `web-app-generator`).

**Interpretation adopted (auto-mode default).** The user's brief describes Olympus being *merged into* Yggdrasil "the existing Yggdrasil platform." Because Yggdrasil is not accessible, I treat it as a **destination platform to be specified in this document** — Codex will materialize Yggdrasil as a new codebase into which the Olympus subsystem is folded. Every place the brief asks for a Yggdrasil equivalent, I mark the equivalent **NEW-Y** (green-field, to be built) rather than fabricating an equivalence to a phantom codebase.

**If Yggdrasil actually exists and I could not see it**, Codex must halt on the very first work package and request a repository grant. This blueprint's manifest still applies to the Olympus side unchanged, but every "NEW-Y" tag becomes "compare against Yggdrasil actual" — the compatibility matrix flips from *specify* to *reconcile*.

I flag this once, here, and proceed under the adopted interpretation.

---

## 1. Executive Integration Summary

Olympus is a mature, self-hosted, Docker-native autonomous security assessment platform:

- 8 named "god" agents (Zeus / Athena / Hermes / Ares / Hephaestus / Hades / Metis / Apollo) run as a scripted state machine over FastAPI + async SQLAlchemy + Postgres + Redis + React/Vite + nginx + OWASP ZAP.
- Three run modes (`passive`, `active`, `full`) with 0/1/3 human-in-the-loop authorization gates.
- Complete manual-testing workbench (Repeater, Intruder-style fuzz, response diff, cross-role IDOR/BOLA/BFLA).
- Deterministic PoC/evidence pipeline (`HttpExchange` + `core/poc.py`) with sensitive-header redaction at rest and on export.
- Client-side session backup/restore (v1 JSON) with server re-validation and NEW-id import (never clobbers).
- Report engine that emits nonce-CSP dark-themed HTML with client-side Print/HTML/MD/TXT/JSON export and a light/dark toggle.
- 12k LOC across 47 source files. Nine backend test files exercising deterministic pieces. No Alembic migrations (create_all only).

**Yggdrasil (NEW-Y, adopted spec).** The destination is a multi-product security operations platform. Olympus becomes the "Autonomous Assessment" product line inside Yggdrasil. The blueprint mandates:

1. Preserve every Olympus workflow verbatim; add nothing that isn't required to merge.
2. Move Olympus's Postgres schema behind a `security_assessment` namespace / schema in Yggdrasil's shared Postgres.
3. Introduce proper Alembic (or equivalent) migration governance — the "no migrations, create_all only" Olympus constraint is a debt that Yggdrasil must retire during migration.
4. Introduce a Yggdrasil identity/tenancy layer that hosts Olympus's mission surface as a tenant-scoped resource (Olympus is single-user today).
5. Preserve the god-sequenced agent architecture and the HITL gate contract; do not re-architect the state machine.
6. Preserve the manual workbench (Repeater / Intruder / Access-check) as a first-class Yggdrasil product surface.
7. Preserve the JSON v1 backup format for a full major version so operators' existing backups round-trip.

**Non-goals for this handoff.** LLM active red-teaming (map exists, probing does not — deferred). Network-hosts UI panel (data collected, no dedicated view yet — deferred). Screenshot capture (needs Playwright, not installed — deferred). UDP / full-range network sweep — deferred.

**Blast radius.** Aggressive change to the report generator, the god state machine, or the workbench scope guard risks lost customer PoC evidence, invalidated reports, or unauthorized scans against out-of-scope hosts. All three are **must-not-touch without explicit acceptance criteria** here.

---

## 2. Verified Repository Map

**Root of Olympus:** `/home/user/MISC/olympus` (branch `claude/olympus-yggdrasil-migration-m3ljlo`, commit `63e5960`).

```
olympus/
├── setup.sh                 One-click installer (Kali/Debian aware; auto-installs Docker CE)
├── docker-compose.yml       4-service stack (postgres, redis, backend, zap, frontend)
├── .env.example             AI_PROVIDER, AI_API_KEY, OLYMPUS_API_KEY, timeouts, ZAP creds
├── README.md                Operator + integrator guide (~560 lines)
├── HANDOFF.md               Living project state / non-breaking constraints
├── CLAUDE.md                Working rules (create_all only, never hide findings, scope safety)
├── README-wordlists-oracle.md
├── README_CAVEMAN.md
│
├── backend/                 Python 3.11 · FastAPI 0.111 · asyncpg 0.29 · SQLAlchemy 2.0
│   ├── main.py              App factory, CORS, router mount, lifespan create_all()
│   ├── requirements.txt     15 pinned dependencies
│   ├── Dockerfile           Debian slim + nmap/whois + fetched: nuclei/httpx/ffuf/subfinder/
│   │                          katana/dalfox, sqlmap clone, SecLists subset in /opt/wordlists
│   ├── core/
│   │   ├── ai_client.py     Provider-agnostic `complete()` — anthropic OR openrouter
│   │   ├── ai_surface.py    Deterministic LLM-endpoint classifier (no requests, no LLM)
│   │   ├── backup.py        v1 backup schema validation + normalization (pure)
│   │   ├── config.py        Settings (reports_dir, wordlists_dir)
│   │   ├── database.py      Async engine + session factory + declarative Base
│   │   ├── models.py        Mission, AgentLog, Finding, HttpExchange, AuthProfile,
│   │   │                     MissionNote, ApprovalRequest
│   │   ├── poc.py           curl / raw HTTP / Markdown PoC render + header redaction
│   │   ├── replay.py        Request send/mutate/score/diff + IDOR access_verdict (pure)
│   │   ├── security.py      API-key gate + strict target/CIDR validator
│   │   ├── surface.py       Attack-surface (host,path)->params inventory (pure)
│   │   └── wordlists.py     Curated catalog + target-specific generation
│   ├── agents/              One file per "god"; base.py is the abstract agent
│   │   ├── base.py          Log/finding/exchange helpers + HITL gate (wait forever
│   │   │                     by default; OLYMPUS_APPROVAL_TIMEOUT overrides)
│   │   ├── zeus.py          State machine: mode -> sequence, scope enforcement, gates
│   │   ├── athena.py        AI intent parse + AI-derived scope rules + creds extraction
│   │   ├── hermes.py        subfinder, crt.sh, DNS brute, httpx probes, subdomain-takeover,
│   │   │                     RDAP/WHOIS, DNS, vendor fingerprint, CIDR nmap network sweep
│   │   ├── ares.py          Orchestrates active phase; mixes OffensiveEngine + AuthEngine
│   │   ├── offensive.py     1408 LOC: crawl, archive URL gathering, param mining, API/SPA
│   │   │                     seed, OpenAPI import, SQLi/XSS/SSRF/SSTI/traversal/open-redirect
│   │   │                     /CORS/host-header probes, dalfox DAST, sqlmap, form injection,
│   │   │                     auto-fuzz, ffuf content discovery, OWASP ZAP active scan,
│   │   │                     redirect mapping
│   │   ├── auth.py          Login form parsing (AI or heuristic) -> session cookie shared
│   │   │                     with every scanner
│   │   ├── hephaestus.py    Target-specific payload + credential wordlist forge
│   │   ├── hades.py         Post-exploit: lateral movement, persistence, privesc, impact
│   │   ├── metis.py         AI triage: advisory FP flag + CWE/OWASP mapping + attack-path
│   │   │                     chain synthesis (never hides findings)
│   │   ├── apollo.py        Report render (HTML + nonce-CSP + client-side exports)
│   │   └── oracle.py        Standalone PortSwigger Academy solver advisor
│   ├── routers/
│   │   ├── missions.py      27 REST endpoints (see §10)
│   │   ├── scope.py         Multi-format scope parse (H1/BC/Burp/text/markdown/CSV)
│   │   ├── wordlists.py     Catalog / preview / download / generate
│   │   ├── oracle.py        /status /solve /followup for Oracle
│   │   └── ws.py            WebSocket broadcast manager (per-mission subscribers)
│   ├── seed_wordlists/      passwords-common.txt, sqli.txt, xss.txt (bundled)
│   └── tests/               9 test files: backup, poc, replay, surface, forms, security,
│                             network-sweep, ai-surface, report
│
└── frontend/                Node 20 · React 18 · TypeScript 5 (strict) · Vite 5
    ├── Dockerfile           Multi-stage: node build -> nginx serve
    ├── nginx.conf           SPA fallback, /api + /ws reverse proxy, security headers, CSP
    ├── package.json         React, react-router-dom; no CSS framework
    ├── vite.config.ts       Vite defaults
    ├── tsconfig.json        strict:true
    └── src/
        ├── main.tsx / App.tsx        Router shell + header (theme toggle, Oracle link, launch)
        ├── api.ts                    Typed fetch wrapper + optional X-API-Key from localStorage
        ├── types.ts                  Discriminated-union WSEvent, Mission, Finding, etc.
        ├── index.css                 CSS variable design tokens (light + dark), a11y helpers
        ├── hooks/useWebSocket.ts     Auto-reconnect (3s backoff)
        └── components/
            ├── MissionList.tsx           Archive, search, favorites, severity peek, backup import
            ├── MissionLaunch.tsx         Target / mode / auto-approve / scope upload + parse /
            │                              wordlist selection / authorization warning
            ├── MissionControl.tsx        Header, GodStatus, 8 tabs, findings panel, session dump
            ├── GodStatus.tsx             Chip row (glow cyan when active, green when done)
            ├── TerminalFeed.tsx          Live agent log stream (WS-driven)
            ├── FindingsPanel.tsx         Right panel: findings list, tag, add, delete
            ├── ApprovalGate.tsx          Focus-trapped role="alertdialog" (Tab/Esc)
            ├── SurfacePanel.tsx          Attack-surface inventory + AI endpoints + copy-to-workbench
            ├── WorkbenchPanel.tsx        Repeater + Intruder (fuzz + rank)
            ├── AccessCheckPanel.tsx      Cross-role IDOR/BOLA/BFLA
            ├── TopologyPanel.tsx         Site-map tree (SVG, curved edges, dashed redirect arrows)
            ├── TargetsPanel.tsx          Add/rescan targets on a live mission
            ├── NotesPanel.tsx            Mission notes CRUD
            ├── WordlistsPanel.tsx        Catalog view / preview / download / generate
            ├── RerunModal.tsx            Re-run a single god with target/option overrides
            └── Oracle.tsx                PortSwigger Academy solver UI
```

**Yggdrasil map:** *not applicable — repository absent.* NEW-Y specification is in §16.

---

## 3. Olympus Architecture Summary

### 3.1 Runtime topology (verified from `docker-compose.yml`)

| Container | Image | Port | Role | Verified |
|---|---|---|---|---|
| `postgres` | postgres:16-alpine | 5432 (internal) | Mission / findings / logs / exchanges / notes / approvals / auth_profiles storage | yes |
| `redis` | redis:7-alpine | 6379 (internal) | Reserved for future task queue (**not currently used by any code path**) | yes — grep confirms `redis` imported nowhere |
| `zap` | ghcr.io/zaproxy/zaproxy:stable | 8090 (internal) | OWASP ZAP daemon, single shared instance | yes |
| `backend` | Python 3.11 slim | 8000 (internal only) | FastAPI + WebSocket + agent execution | yes — no host port published |
| `frontend` | nginx:alpine | **3000 (published)** | React SPA + reverse proxy for `/api` and `/ws` | yes |

### 3.2 Request lifecycle

1. Operator opens `http://localhost:3000` -> nginx serves the SPA.
2. SPA calls `POST /api/missions` (proxied to backend:8000) -> creates Mission row, enqueues `_run_mission` as a FastAPI `BackgroundTask`.
3. `Zeus.execute()` runs the state machine, spawning Athena -> Hermes -> (gate) -> Ares -> (gate) -> Hephaestus -> (gate) -> Hades -> Metis -> Apollo per mode.
4. Every agent emits `log`, `finding`, `status_change`, `approval_required`, `approval_resolved` events via `ws.ConnectionManager.broadcast()` to all subscribed clients on `/ws/{mission_id}`.
5. HITL gate: agent creates an `ApprovalRequest` row and blocks on an `asyncio.Event` (kept in `app.state.approval_gates`), waiting indefinitely by default; the operator's `POST /api/missions/{id}/approvals/{aid}/resolve` sets the event and the agent continues.
6. Apollo writes `/app/reports/report_{mission_id}.html` and returns; frontend links to `GET /api/missions/{id}/report`.

### 3.3 Persistence

- Async SQLAlchemy 2.0 declarative models.
- Schema initialization: `Base.metadata.create_all` on app startup — **no Alembic**. This is documented and enforced as a hard constraint in `CLAUDE.md` and `HANDOFF.md`. Adding a column to an existing table breaks upgrades on existing databases; new mission-level flags therefore live in `mission.context` (JSON).
- Six/seven tables: `missions`, `agent_logs`, `findings`, `http_exchanges`, `auth_profiles`, `mission_notes`, `approval_requests`.
- Reports written to a `reports:` Docker volume; wordlists staged into `/opt/wordlists` at image build.

### 3.4 Security tools baked into the backend image

`nmap`, `whois`, `nuclei` v3.3.5, `httpx` v1.6.8, `ffuf` v2.1.0, `subfinder` v2.6.6, `katana` v1.1.0, `dalfox` v2.9.2, `sqlmap` (git). Each installation degrades gracefully to a warning if the network fetch fails during build. Curated SecLists subset staged in `/opt/wordlists`.

### 3.5 AI is optional

Any AI-bearing agent (Athena, Metis, Apollo executive summary, Oracle, Auth's login planner) no-ops cleanly if `AI_API_KEY` is unset. Non-AI code paths are 100% deterministic.

---

## 4. Yggdrasil Architecture Summary (NEW-Y — adopted spec)

Because Yggdrasil is not present, this section specifies the **minimum viable target architecture** Codex must build. This is deliberately conservative: it is *what Olympus needs Yggdrasil to be*, not an ambitious redesign.

### 4.1 Yggdrasil framing

- **Product model:** Yggdrasil is a multi-module security operations platform. Modules include (day 1): the Olympus assessment engine (renamed internally to `yggdrasil-assessment`) and a shared **Norns** administrative console (identity, tenancy, audit). Additional modules (Bifrost, Mimir, etc.) are declared out of scope for this handoff.
- **Naming:** the eight Greek gods stay named. Yggdrasil is the shell; Olympus's internals ship unchanged externally.
- **Tenancy:** every persisted row gains a `tenant_id` FK. Olympus's single-user default becomes tenant `default`. All routes gain `require_tenant_and_role(tenant, role)`.
- **Identity:** Yggdrasil owns the identity layer (OIDC + local users). The current `OLYMPUS_API_KEY` becomes a per-tenant service credential.
- **Database:** shared Postgres 16 cluster. The Olympus schema is namespaced as `assessment.*`. Alembic (or equivalent) migrations are mandatory.
- **Queue:** Redis is *promoted* from placeholder to actual backend for a Celery/arq/dramatiq worker pool. `_run_mission` moves off `BackgroundTasks` (which dies with the process — a known limitation flagged in `README.md:291`).
- **Reports:** Apollo output moves from a local Docker volume to Yggdrasil object storage (S3-compatible) with signed download URLs.
- **Observability:** structured JSON logging, OpenTelemetry traces, `/metrics` Prometheus endpoint. Olympus has none of this today.
- **Deployment:** Compose remains for local; Helm chart is the release path.

### 4.2 What Yggdrasil *cannot* change without breaking the Olympus contract

- The god sequence and HITL gate semantics (§7).
- The `HttpExchange` at-rest redaction contract (§6, §12).
- The v1 JSON backup schema (§15).
- The Metis advisory-only rule (findings are never hidden by an AI pass).
- The scope-guard on every active probe (workbench refuses off-scope hosts).
- The finding severity vocabulary (`critical|high|medium|low|info`).

---

## 5. Complete Olympus Feature Matrix

The full matrix is normative — every row is verified in code, and Codex must preserve behavior unless a row explicitly says otherwise. Priorities: **P0** = ship-gating, **P1** = full-feature parity, **P2** = polish/deferred. Confidence: **H** verified in code + tests, **M** verified in code only, **L** inferred from docs.

| # | Feature | Persona | Backend evidence | Frontend evidence | Status | Migration action | Priority | Conf | Acceptance criteria |
|---|---|---|---|---|---|---|---|---|---|
| F001 | Mission create (target + mode + scope + auto-approve) | operator | `routers/missions.py:190`, model `models.py:34` | `MissionLaunch.tsx` | works | Preserve; add tenant context | P0 | H | POST `/api/missions` returns id; row created with `context.auto_approve` set |
| F002 | Mission list w/ severity peek + favorites + search | operator | `routers/missions.py:273` (grouped severity count query) | `MissionList.tsx:60` `SeverityPeek` | works | Preserve; favorites move to per-user prefs table | P0 | H | List paginates; peek badges render zero + non-zero states |
| F003 | Mission detail w/ live findings + logs + approvals + notes | operator | `routers/missions.py:304` | `MissionControl.tsx` | works | Preserve | P0 | H | Contents match DB and WS stream |
| F004 | Mission delete (cascade findings/logs/etc.) | operator | `routers/missions.py:361` | `MissionList.tsx:148` | works | Preserve; add soft-delete + audit trail | P1 | H | Cascade correct, audit row written |
| F005 | Mission mode = `passive` | operator | `zeus.py:52`, sequence ATHENA->HERMES->METIS->APOLLO | mode selector | works | Preserve verbatim | P0 | H | Zero HITL gates fire; Apollo report produced |
| F006 | Mission mode = `active` | operator | `zeus.py:53`, 1 HITL gate | mode selector | works | Preserve | P0 | H | Exactly 1 gate before Ares |
| F007 | Mission mode = `full` | operator | `zeus.py:55`, 3 gates | mode selector | works | Preserve | P0 | H | Exactly 3 gates: Ares, Hephaestus, Hades |
| F008 | HITL gate — wait indefinitely by default | operator | `base.py:224` | `ApprovalGate.tsx` (focus-trapped alertdialog) | works | Preserve; add per-tenant policy override | P0 | H | `OLYMPUS_APPROVAL_TIMEOUT=0` (default) -> gate persists across UI refresh; approve/deny closes it |
| F009 | Pre-authorize all gates (autonomous run) | operator | `base.py:174` | `MissionLaunch.tsx` autonomous checkbox | works | Preserve; add audit row per skipped gate | P0 | H | Gate rows still created with `approved`+timestamp; approval log emits |
| F010 | Global `OLYMPUS_AUTO_APPROVE` env | admin | `base.py:173` | none | works | Move to tenant setting | P1 | H | Env still honored during migration |
| F011 | Approval timeout `OLYMPUS_APPROVAL_TIMEOUT` | admin | `base.py:225` | none | works | Preserve as tenant setting | P1 | H | Positive value auto-denies + falls through to Apollo |
| F012 | Approval resolve endpoint | operator | `routers/missions.py:373` | `ApprovalGate.tsx` | works | Preserve | P0 | H | Sets `approval_gates[id]` event, broadcasts `approval_resolved` |
| F013 | Target validation (bare host / IPv4 / CIDR + no shell metachars + no leading `-`) | platform | `security.py:54` (unit-tested `test_security.py`) | none | works | Preserve; port to Yggdrasil common lib | P0 | H | Regressions in `test_security.py` all pass |
| F014 | CIDR expand w/ cap (`OLYMPUS_CIDR_MAX_HOSTS` default 1024) | platform | `security.py:91`, tests | none | works | Preserve | P1 | H | /24 -> 254, /31 -> 2 (RFC 3021), /32 -> 1 |
| F015 | Scope parse: HackerOne CSV | operator | `routers/scope.py:111` | `MissionLaunch.tsx` upload | works | Preserve | P1 | M | Real H1 CSV round-trip |
| F016 | Scope parse: Bugcrowd CSV | operator | `scope.py:137` | ^ | works | Preserve | P1 | M | BC CSV round-trip |
| F017 | Scope parse: Burp JSON | operator | `scope.py:160` | ^ | works | Preserve | P1 | M | Both Burp shapes round-trip |
| F018 | Scope parse: section-headers + markdown links + mobile apps + `-`/`+` prefixes | operator | `scope.py:64` | ^ | works | Preserve | P1 | M | Header detection & md link stripping |
| F019 | Scope hard-enforce priority (structured > AI-derived notes > none) | operator | `zeus.py:68` | none | works | Preserve exactly | P0 | H | AI-derived rules never override an uploaded file |
| F020 | AI-derived scope from free-text notes | operator | `athena.py:145` (validated per host via `is_valid_target`) | scope note textarea | works | Preserve | P1 | M | Model may only *narrow*; hallucinated hosts rejected |
| F021 | Credentials extraction from scope notes (authenticated scanning) | operator | `athena.py:99` | scope note textarea | works | Preserve; move creds to secret store, not DB context | P1 | M | Password never logged; extracted into transient key |
| F022 | Authenticated scanning (login shared with all scanners) | operator | `auth.py:31` (AuthEngine) | none | works | Preserve; add per-request revalidation | P1 | M | Login verifies via `_verify()` post-cookie |
| F023 | Hermes: subfinder | recon | `hermes.py:380` | logs | works | Preserve | P1 | M | Multi-source subfinder present in image |
| F024 | Hermes: crt.sh certificate transparency | recon | `hermes.py:362` | logs | works | Preserve | P1 | M | HTTPS call succeeds against crt.sh |
| F025 | Hermes: DNS brute-force | recon | `hermes.py:397` | logs | works | Preserve; cap `OLYMPUS_CIDR_MAX_HOSTS`-style | P1 | M | Cap enforced |
| F026 | Hermes: httpx fingerprint (title/tech/CDN) | recon | `hermes.py:441` | topology / findings | works | Preserve | P1 | M | Fingerprint appears in context.hermes |
| F027 | Hermes: subdomain takeover detection | recon | `hermes.py:592` | findings | works | Preserve | P1 | M | Fingerprint signatures fire |
| F028 | Hermes: RDAP / WHOIS | recon | `hermes.py:306` | logs | works | Preserve | P2 | M | RDAP endpoint reachable |
| F029 | Hermes: DNS enumeration (A/AAAA/MX/NS/TXT/DMARC/SPF) | recon | `hermes.py:642` | vendor findings | works | Preserve | P1 | M | Records populate |
| F030 | Hermes: vendor fingerprint from TXT (Stripe/Okta/...) | recon | `hermes.py:9` (VENDOR_TXT_PATTERNS) | Apollo vendor block | works | Preserve | P1 | M | Vendor tags appear in report |
| F031 | Hermes: CIDR web-liveness sweep | recon | `hermes.py:775`+ | topology | works | Preserve | P1 | M | Live host list is filtered |
| F032 | Hermes: nmap network sweep on CIDR (curated ports + service parse) | recon | `hermes.py:494` + `parse_nmap_greppable`, `test_network_sweep.py` | none (data collected only) | works, but **no report/UI surface** yet | Preserve backend + BUILD UI panel (see WP-11) | P1 | H | `network_hosts` populates; new UI panel renders it |
| F033 | Hermes: sensitive-subdomain flagging (`vpn`, `admin`, `ci`) | recon | `hermes.py:737` | findings | works | Preserve | P1 | M | Categories advisory |
| F034 | Ares: nmap on live hosts (top-1000 or explicit port) | scanning | `ares.py:224` | logs | works | Preserve | P0 | M | Nmap invoked; results shape correct |
| F035 | Ares: nuclei (+ OAST) | scanning | `ares.py:318` | findings | works | Preserve | P0 | M | Templates loaded; findings emit |
| F036 | Ares: ffuf directory enumeration | scanning | `ares.py:382` | Apollo "Content Paths" | works | Preserve | P1 | M | Uses selected wordlists |
| F037 | Ares: service checks (dangerous ports) | scanning | `ares.py:437`, `_check_dangerous_port` | findings | works | Preserve | P1 | M | Findings emit at documented severity |
| F038 | Offensive engine: katana crawl | scanning | `offensive.py:148` | surface tab | works | Preserve | P1 | M | Endpoints appear in surface |
| F039 | Offensive engine: Wayback archive URL gathering | scanning | `offensive.py:249` | surface tab | works | Preserve | P1 | M | Archive URLs dedup'd |
| F040 | Offensive engine: API/SPA endpoint seeding | scanning | `offensive.py:170` | surface tab | works | Preserve | P1 | M | Seeded endpoints included |
| F041 | Offensive engine: OpenAPI/Swagger import (scope-safe: base URL always wins) | scanning | `offensive.py:217`, `surface.py:52` (verified logic pins host to base) | surface tab | works | Preserve | P0 | H | Foreign hosts declared in spec `servers` are ignored |
| F042 | Offensive engine: active param mining (arjun-style) | scanning | `offensive.py:1079` | surface tab | works | Preserve | P1 | M | Params discovered even when GET has no query |
| F043 | Offensive engine: form discovery + POST injection | scanning | `offensive.py:827`, `test_forms.py` | none | works | Preserve | P1 | H | Form extractor tested |
| F044 | Offensive engine: SQLi (sqlmap + GET/POST) | scanning | `offensive.py:334` | findings | works | Preserve | P1 | M | `--forms` mode invoked when forms present |
| F045 | Offensive engine: XSS (dalfox) | scanning | `offensive.py:397` | findings | works | Preserve | P1 | M | Dalfox invoked per URL |
| F046 | Offensive engine: SSRF probes | scanning | `offensive.py:921` | findings | works | Preserve | P1 | M | Signal detected on collab hit / meta URL |
| F047 | Offensive engine: SSTI probes | scanning | `offensive.py:959` | findings | works | Preserve | P1 | M | `{{7*7}}` reflection detected |
| F048 | Offensive engine: path traversal | scanning | `offensive.py:639` | findings | works | Preserve | P1 | M | `/etc/passwd` marker detected |
| F049 | Offensive engine: open-redirect | scanning | `offensive.py:981` | findings | works | Preserve | P1 | M | External redirect detected |
| F050 | Offensive engine: CORS misconfig | scanning | `offensive.py:1005` | findings | works | Preserve | P1 | M | Reflection + credentials flag |
| F051 | Offensive engine: host-header injection | scanning | `offensive.py:1044` | findings | works | Preserve | P1 | M | Poisoned Location observed |
| F052 | Offensive engine: nuclei DAST templates | scanning | `offensive.py:456` | findings | works | Preserve | P1 | M | DAST templates run |
| F053 | Offensive engine: auth/access-control probe | scanning | `offensive.py:509` | findings | works | Preserve | P1 | M | Probes fire, redacted at rest |
| F054 | Offensive engine: OWASP ZAP full active scan (seeded w/ crawled URLs) | scanning | `offensive.py:1121` | findings | works | Preserve | P1 | M | ZAP alerts imported |
| F055 | Offensive engine: auto-fuzz across every parameter | scanning | `offensive.py:820` | findings | works | Preserve | P1 | M | Anomaly-scored |
| F056 | Offensive engine: redirect edge mapping (same-host only) | scanning | `offensive.py:1293` | topology dashed edges | works | Preserve | P1 | M | Same-host constraint honored |
| F057 | AI/LLM attack-surface classifier (deterministic) | scanning | `core/ai_surface.py`, `test_ai_surface.py` | surface tab `AI` badges, findings advisory | works | Preserve | P1 | H | Categories per test file |
| F058 | Hephaestus: target-specific credential wordlist | payload forge | `hephaestus.py:105` | wordlists panel | works | Preserve | P1 | M | Domain permutations present |
| F059 | Hephaestus: payload sets per finding class | payload forge | `hephaestus.py:177` | wordlists panel | works | Preserve | P1 | M | Payloads generated per classified finding |
| F060 | Hades: lateral movement mapping | post-exploit | `hades.py:67` | findings | works | Preserve | P1 | M | Findings emit with MITRE technique IDs |
| F061 | Hades: persistence vector inference | post-exploit | `hades.py:111` | findings | works | Preserve | P1 | M | Vectors emit |
| F062 | Hades: credential exposure inference | post-exploit | `hades.py:145` | findings | works | Preserve | P1 | M | Findings emit |
| F063 | Hades: privesc paths | post-exploit | `hades.py:183` | findings | works | Preserve | P1 | M | Findings emit |
| F064 | Hades: blast-radius impact scoring | post-exploit | `hades.py:211` | findings | works | Preserve | P1 | M | Score present in returned dict |
| F065 | Metis: AI triage — advisory FP flag (never hides) | triage | `metis.py:107` | analyst_notes visible in FindingsPanel | works | Preserve — hard constraint | P0 | H | Findings never tagged FP or deleted by Metis; notes appended only |
| F066 | Metis: CWE / OWASP mapping (appended to notes) | triage | `metis.py:118` | analyst_notes | works | Preserve | P1 | M | Notes contain `METIS classification:` |
| F067 | Metis: attack-path chain synthesis (max 6) | triage | `metis.py:137` | findings | works | Preserve | P1 | M | Chains ref >=2 findings |
| F068 | Metis: 2-3 sentence triage verdict summary | triage | `metis.py:161` | terminal feed | works | Preserve | P2 | M | Emitted as `info` log |
| F069 | Apollo: dark-themed HTML report with nonce CSP | report | `apollo.py:246`, `test_report.py` | button link | works | Preserve; add DOMPurify-style eval guardrails on export | P0 | H | `<meta http-equiv="CSP" nonce=...` present |
| F070 | Apollo: executive summary (AI, deterministic fallback) | report | `apollo.py:76`, `apollo.py:111` | rendered | works | Preserve | P0 | H | Fallback used when AI absent |
| F071 | Apollo: coverage panel (subs/live/hosts/urls/paths + module hits) | report | `apollo.py:141` | rendered | works | Preserve | P0 | H | Numbers match agent output; no fabrication |
| F072 | Apollo: attack surface table (<=200 endpoints) | report | `apollo.py:186` | rendered | works | Preserve | P1 | H | Uses build_inventory dedup |
| F073 | Apollo: content paths table (<=250 entries + status coloring) | report | `apollo.py:204` | rendered | works | Preserve | P1 | H | Present when directories exist |
| F074 | Apollo: manual-test candidates (interesting paths, checkbox) | report | `apollo.py:221` | rendered | works | Preserve; keep candidate vs. confirmed clear | P0 | H | Never labels candidates as confirmed |
| F075 | Apollo: vendor stack panel (passive intel) | report | `apollo.py:308` | rendered | works | Preserve | P1 | M | Vendors render as tag chips |
| F076 | Apollo: findings detail (escaped fields, sorted by CVSS map) | report | `apollo.py:265` | rendered | works | Preserve | P0 | H | `_html.escape` on every field |
| F077 | Apollo: live-hosts list (<=50) | report | `apollo.py:316` | rendered | works | Preserve | P1 | M | Renders when hosts present |
| F078 | Apollo: `data-theme=light` toggle inside the report (client-side) | report | `apollo.py:466` | rendered | works | Preserve | P1 | H | Print media query resets full token set (regression fixed) |
| F079 | Apollo: client-side export (Print / HTML / MD / TXT / JSON) — raw string safety, U+2028/U+2029 escaped, `</`->`<\/` | report | `apollo.py:356`+, `apollo.py:384` (raw `r"""`) | rendered | works | Preserve — regression guard | P0 | H | `test_report.py` continues to pass; JS parses under strict CSP |
| F080 | Report file served from disk | report | `routers/missions.py:979` | `MissionControl.tsx:250` | works | Move to signed URL against object storage | P1 | H | Existing endpoint kept during migration |
| F081 | Export findings — CSV | operator | `routers/missions.py:606` | export button | works | Preserve | P0 | M | CSV opens in Excel |
| F082 | Export findings — JSON | operator | `routers/missions.py:666` | export button | works | Preserve | P0 | M | Payload validates |
| F083 | Export findings — Markdown (`?format=md&redact=true`) with curl + raw HTTP PoC blocks | operator | `routers/missions.py:650` -> `poc.mission_markdown` | none (direct URL) | works | Preserve | P0 | H | Redact toggle honored; sensitive headers `<redacted>` |
| F084 | Per-finding PoC (Markdown) endpoint | operator | `routers/missions.py:682` | none | works | Preserve | P1 | H | Curl + raw HTTP appear |
| F085 | `HttpExchange` capture (redacted at rest) | analyst | `models.py:93`, `base.py:85` `add_exchange`, `base.py:122` `capture` | none | works | Preserve — hard constraint | P0 | H | Cookie / Authorization / X-API-Key / X-CSRF etc. become `<redacted>` |
| F086 | Exchange list endpoint | analyst | `routers/missions.py:708` | (used by mission fetch) | works | Preserve | P1 | M | Returns all |
| F087 | Surface inventory endpoint (endpoints + AI + redirects + coverage) | analyst | `routers/missions.py:720` | `SurfacePanel.tsx` | works | Preserve | P1 | H | `build_inventory` + `build_ai_surface` |
| F088 | Repeater — replay | analyst | `routers/missions.py:761`, `replay.py:32` | `WorkbenchPanel.tsx` | works | Preserve | P0 | H | Scope guard `_host_in_scope` refuses off-scope |
| F089 | Intruder — fuzz w/ payloads OR wordlist_id, capped `MAX_PAYLOADS` | analyst | `routers/missions.py:808`, `replay.py:154` | `WorkbenchPanel.tsx` | works | Preserve | P0 | H | Scope guard enforced; cap enforced |
| F090 | Response diff | analyst | `routers/missions.py:847`, `replay.py:68` | (workbench) | works | Preserve | P1 | H | Header + body + status delta |
| F091 | Auth profile CRUD | analyst | `routers/missions.py:878..910` | `AccessCheckPanel.tsx` | works | Preserve; redact on read enforced | P0 | H | `_profile_dict` never returns raw session values |
| F092 | Cross-role access check (IDOR / BOLA / BFLA) w/ verdict + evidence | analyst | `routers/missions.py:913`, `replay.access_verdict` | `AccessCheckPanel.tsx` | works | Preserve — findings stay candidate | P0 | H | `access_verdict` flags non-owner reaching owner response |
| F093 | Manual finding add/update/delete + analyst_notes | analyst | `routers/missions.py:406/442/468` | `FindingsPanel.tsx` | works | Preserve | P0 | M | CRUD returns updated finding |
| F094 | Mission notes CRUD | analyst | `routers/missions.py:485/507` | `NotesPanel.tsx` | works | Preserve | P1 | M | Notes broadcast via WS |
| F095 | Add targets to a live mission w/ optional immediate rescan | operator | `routers/missions.py:523` | `TargetsPanel.tsx` | works | Preserve | P1 | M | Manually-added flag set on live host |
| F096 | Re-run any god individually | operator | `routers/missions.py:570` | `RerunModal.tsx` | works | Preserve | P1 | M | Merges result back into context |
| F097 | Wordlist catalog / preview / download / generate | operator | `routers/wordlists.py`, `core/wordlists.py` | `WordlistsPanel.tsx` | works | Preserve | P1 | M | Curated + generated both listed |
| F098 | Scope parse endpoint | operator | `routers/scope.py:220` | `MissionLaunch.tsx` | works | Preserve | P1 | M | Auto-detect chooses correct parser |
| F099 | WebSocket per-mission subscription (log/finding/status/approval events) | any | `routers/ws.py`, discriminated `WSEvent` union `types.ts:98` | `useWebSocket.ts` | works | Preserve; move behind Yggdrasil gateway | P0 | H | Reconnect with 3s backoff |
| F100 | Optional API key (`OLYMPUS_API_KEY`) — REST header + WS query param | operator | `security.py:37`, `security.py:46` | `api.ts:12` (localStorage -> header) | works | Replace with proper session/OIDC (see §16) — keep during migration | P0 | H | 401 if enabled and missing |
| F101 | Session backup (client-side JSON v1: mission + findings + last 500 logs + notes + status/phase + hosts) | operator | (client) — `MissionControl.tsx:136` | download button | works | Preserve schema; add SHA-256 integrity | P0 | H | Filename `OLYMPUS_backup_YYYY-MM-DD.json` |
| F102 | Session restore (client shape-check + server strict `validate_backup` + import as NEW mission) | operator | `routers/missions.py:226`, `core/backup.py`, `test_backup.py` | `MissionList.tsx:104` drag+drop + picker | works | Preserve; add integrity check + rename to `YGGDRASIL_backup_...` (§15) | P0 | H | Corrupt file -> 422 `Invalid or corrupted progress file` banner; imported mission has fresh id and `context.imported=true` |
| F103 | Mission heartbeat log (`OLYMPUS_HEARTBEAT_SECONDS`, default 300s) | operator | `routers/missions.py:1025` | terminal feed | works | Preserve | P1 | M | Broadcast-only; no DB write |
| F104 | Terminal feed (WS log stream) | operator | `TerminalFeed.tsx` | rendered | works | Preserve | P0 | H | Every WS `log` renders |
| F105 | God status bar (glow cyan active / green complete) w/ re-run trigger | operator | `GodStatus.tsx` | rendered | works | Preserve | P0 | H | Terminal states clear active phase |
| F106 | Findings panel (severity color + tag + add/delete + false-positive filter in CRIT/HIGH count) | operator | `FindingsPanel.tsx`, `MissionControl.tsx:203` | rendered | works | Preserve | P0 | H | FP-tagged findings excluded from CRIT/HIGH badges |
| F107 | Topology tab (site-map tree, curved SVG edges, dashed redirect arrows) | operator | `TopologyPanel.tsx` | rendered | works | Preserve | P1 | M | Renders even w/ zero endpoints |
| F108 | Mission archive severity peek + favorites (localStorage) + search filter | operator | `MissionList.tsx` | rendered | works | Preserve; favorites -> per-user pref | P1 | H | Pinned favorites; filter case-insensitive |
| F109 | Global dark/light theme toggle (persisted localStorage) | operator | `App.tsx:9` + `index.css` `:root[data-theme=light]` | header button | works | Preserve | P1 | H | `data-theme` on `<html>` on load |
| F110 | Accessibility pass: `.touch-target` (44px on coarse pointer), ARIA on tabs/dialogs, focus-trap ApprovalGate, `prefers-reduced-motion`, responsive `.mc-main-grid` <=820px | any | `index.css:118`+, `ApprovalGate.tsx`, `MissionControl.tsx` `role=tablist/tab/tabpanel` | rendered | works | Preserve; extend to Yggdrasil shell | P0 | H | Audit passes WCAG 2.2 AA — see §14 |
| F111 | Oracle: PortSwigger Academy solver (Solve + Followup) | analyst | `routers/oracle.py`, `agents/oracle.py` | `Oracle.tsx` | works | Preserve | P2 | M | JSON schema round-trip |
| F112 | AI provider abstraction (anthropic / openrouter / any OpenAI-compatible) | admin | `core/ai_client.py` | none | works | Preserve; extend to Bedrock/Vertex under Yggdrasil model gateway | P1 | M | Blank key => deterministic fallback everywhere |
| F113 | Log persistence + WS mirror | any | `base.py:30` | `TerminalFeed.tsx` | works | Preserve | P0 | H | Every log both stored + broadcast |
| F114 | Report route serves the exact HTML file that was generated | operator | `routers/missions.py:979` | mission header report link | works | Preserve | P0 | H | 404 before Apollo runs |
| F115 | Container-network target guidance (Juice Shop by container name) | operator | `README.md:363`+ | none (docs) | works | Preserve docs | P2 | L | Docs unchanged |

Legend: **works** = feature is present and functional per direct code inspection and, where present, the passing unit tests in `backend/tests/`.

---

## 6. Olympus → Yggdrasil Compatibility Matrix

Because Yggdrasil is a green-field target, compatibility here means: *what Olympus contract does each Yggdrasil subsystem have to expose?*

| Olympus subsystem | Yggdrasil subsystem (NEW-Y) | Contract |
|---|---|---|
| Mission CRUD (`routers/missions.py`) | `assessment.missions` module | Same shape; add `tenant_id`, `owner_user_id`; response payload additive |
| WebSocket (`routers/ws.py`) | Yggdrasil `event-stream/{tenant}/{resource_type}/{resource_id}` gateway | Envelope identical inside; auth via Yggdrasil session token, not `?api_key=` |
| Zeus state machine | Untouched — imported as `assessment.orchestrator` | Behavior identical, tests reused |
| Metis advisory rule | Untouched — hard constraint | Yggdrasil AI review layer is *never* allowed to tag `false_positive` or delete a finding |
| `HttpExchange` redaction | Untouched — `core/poc.SENSITIVE_HEADERS` list becomes Yggdrasil-wide constant | Redaction applied on write AND on read |
| Backup v1 schema | Renamed filename convention only (§15); schema preserved for 1 major version | `POST /missions/restore` continues to accept v1 payloads |
| Postgres tables | Move under `assessment.*` schema in Yggdrasil DB; Alembic baseline | Zero data loss for existing operators |
| `OLYMPUS_API_KEY` | Deprecate in favor of Yggdrasil session/OIDC | Keep working for 1 major version |
| Reports on volume | S3 object storage | New endpoint returns signed URL; old direct URL remains during migration |
| Redis | Actual queue (Celery/arq/dramatiq) | `_run_mission` moves to worker; behavior identical from outside |
| ZAP daemon | Same image, run per-worker or shared | ZAP contention already documented; keep single instance until scale requires |

---

## 7. UI Screen and Component Inventory

Screens (four routes in `App.tsx`):

1. **`/` Mission Archive** — `MissionList.tsx`
2. **`/launch` Mission Launch** — `MissionLaunch.tsx`
3. **`/mission/:id` Mission Control** — `MissionControl.tsx`
4. **`/oracle` Oracle Advisor** — `Oracle.tsx`

Header (`App.tsx` `Header`): brand, theme toggle, Oracle link, `+ NEW MISSION`.

Component inventory:

| Component | Purpose | States |
|---|---|---|
| `MissionList` | Archive, search, favorites, severity peek, restore drag+drop | loading, empty (no missions), filtered-empty, importing, import-error, normal |
| `MissionLaunch` | Target + mode + auto-approve + scope upload/parse + wordlist chips + auth warning | idle, parsing scope, scope error, launching, launch error |
| `MissionControl` | Header + GodStatus + 8-tab left panel + FindingsPanel right | loading, missing-mission, live (WS), terminal (complete/failed) |
| `GodStatus` | 7-god chip row w/ active glow + rerun menu | idle, active (currentPhase), completed |
| `TerminalFeed` | Live log stream | empty, streaming |
| `FindingsPanel` | Findings list w/ tag / severity color / add / delete / analyst_notes | empty, filtered, editing |
| `ApprovalGate` | Focus-trapped role=alertdialog | approve/deny |
| `SurfacePanel` | Endpoints + AI badges + copy-to-workbench | loading, empty, populated |
| `WorkbenchPanel` | Repeater (replay) + Intruder (fuzz) + wordlist select | idle, busy, error, results |
| `AccessCheckPanel` | Profile CRUD + cross-role verdict matrix | no profiles, ready, running, verdict |
| `TopologyPanel` | Site-map tree (SVG) | loading, empty, populated |
| `TargetsPanel` | Add/rescan targets on live mission | idle, adding, scanning |
| `NotesPanel` | Notes CRUD | empty, populated |
| `WordlistsPanel` | Catalog / preview / download / generate | loading, empty, populated |
| `RerunModal` | Per-god re-run w/ target + option overrides | idle, submitting |
| `Oracle` | Solve + Followup for PortSwigger labs | idle, running, no-ai warning, plan rendered |

**Design tokens (`index.css`).** Preserve verbatim; Yggdrasil brand overlay is a NEW-Y additive layer that must not lose the `--crit / --high / --med / --low / --info` severity palette (used in report + list + peek).

**Responsive behavior.** `.mc-main-grid` collapses to stacked rows <=820px, tab strip becomes horizontally scrollable. Everything is inline styles by design.

---

## 8. User Journeys

### 8.1 Operator — quickest passive scan (verified path)

1. `/launch` -> target `example.com` -> `PASSIVE` -> LAUNCH.
2. Zeus -> Athena -> Hermes -> Metis -> Apollo. Zero HITL gates.
3. Report link appears when Apollo finishes.

### 8.2 Operator — authorized active engagement with scope file

1. `/launch` -> target `example.com`, mode `ACTIVE`, upload HackerOne CSV, select 3 wordlist chips, tick authorization checkbox -> LAUNCH.
2. Zeus -> Athena -> Hermes -> HITL gate -> operator reads listed hosts, clicks AUTHORIZE.
3. Ares runs offensive engine with scope enforced (`_scope_filter`). Findings stream in.
4. Metis triages, Apollo reports.

### 8.3 Analyst — reproduce a candidate BOLA

1. Open mission -> `ACCESS` tab -> register 2 auth profiles (user-a, user-b) -> mark user-a as owner -> run access-check on their `/api/orders/1234`.
2. Verdict matrix shows user-b returned same status/length -> flagged `BROKEN_ACCESS_CONTROL`.
3. `Export findings — MD` returns a Markdown PoC (`?format=md&redact=true`) with curl + raw HTTP; sensitive headers redacted.

### 8.4 Analyst — resume via backup

1. Complete a mission on Kali -> `↓ SESSION` button -> `OLYMPUS_backup_YYYY-MM-DD.json` downloaded.
2. Move to another host -> `/` -> drag `.json` into the restore zone.
3. Server re-validates via `core.backup.validate_backup`; missing/invalid target => 422 with the specific reason; success => new mission with fresh id, `context.imported=true`.

### 8.5 Operator — autonomous full run

1. `/launch` -> mode `FULL`, tick "Autonomous run — pre-authorize all HITL gates".
2. Zeus records each gate as auto-approved with an audit log line; the mission runs end to end with no clicks.

---

## 9. Data & Persistence Model

Seven tables, all in `core/models.py`; UUID primary keys as strings; `create_all` only.

### Mission
```
id (PK), target, scope (text), status, mode, current_phase, context (JSON),
scope_rules (JSON), created_at, updated_at, completed_at
```

### AgentLog
```
id, mission_id (FK), agent, level, message, raw_output, timestamp
```

### Finding
```
id, mission_id, title, severity, description, evidence, cvss_score, remediation,
found_by, tag (confirmed|false_positive|reported|fixed|NULL),
is_manual, analyst_notes, timestamp
```

### HttpExchange
```
id, mission_id, finding_id (nullable FK), method, url,
request_headers (JSON — sensitive redacted at rest),
request_body, status_code,
response_headers (JSON — sensitive redacted at rest), response_body (capped),
duration_ms, source, notes, redacted (bool), created_at
```

### AuthProfile
```
id, mission_id, name, role, headers (JSON — kept raw internally; ALWAYS
redacted on API read via _profile_dict), created_at
```

### MissionNote
```
id, mission_id, content, timestamp
```

### ApprovalRequest
```
id, mission_id, agent, action, description, status (pending|approved|denied),
created_at, resolved_at
```

**Yggdrasil migration:** add `tenant_id` (indexed) to every table; establish Alembic baseline; move `AuthProfile.headers` to a secrets vault reference rather than JSON.

---

## 10. API and Event Inventory

REST — from `routers/missions.py`, `routers/scope.py`, `routers/wordlists.py`, `routers/oracle.py`, `routers/ws.py`.

```
GET     /api/health
POST    /api/missions
POST    /api/missions/restore
GET     /api/missions
GET     /api/missions/{id}
DELETE  /api/missions/{id}
POST    /api/missions/{id}/approvals/{approval_id}/resolve
POST    /api/missions/{id}/findings
PATCH   /api/missions/{id}/findings/{finding_id}
DELETE  /api/missions/{id}/findings/{finding_id}
POST    /api/missions/{id}/notes
DELETE  /api/missions/{id}/notes/{note_id}
POST    /api/missions/{id}/targets
POST    /api/missions/{id}/agents/{agent}/run
GET     /api/missions/{id}/export?format=csv|json|md&redact=true
GET     /api/missions/{id}/findings/{fid}/poc
GET     /api/missions/{id}/exchanges
GET     /api/missions/{id}/surface
POST    /api/missions/{id}/replay
POST    /api/missions/{id}/fuzz
POST    /api/missions/{id}/diff
POST    /api/missions/{id}/profiles
GET     /api/missions/{id}/profiles
DELETE  /api/missions/{id}/profiles/{profile_id}
POST    /api/missions/{id}/access-check
GET     /api/missions/{id}/report
POST    /api/scope/parse
GET     /api/wordlists
GET     /api/wordlists/{wid}/preview
GET     /api/wordlists/{wid}/download
POST    /api/wordlists/generate/{mission_id}
GET     /api/oracle/status
POST    /api/oracle/solve
POST    /api/oracle/followup
WS      /ws/{mission_id}
```

**WebSocket event union** (`frontend/src/types.ts:98` — normative):
`log | finding | finding_updated | finding_deleted | status_change | approval_required | approval_resolved | mission_complete | mission_failed | agent_rerun | targets_added | note_added`

**Contract for Yggdrasil:** every one of these responses/events remains bytewise-compatible under `/assessment/api/missions/...`. The Yggdrasil gateway may add new fields; it MUST NOT remove or rename.

---

## 11. Report Generation Specification

### Sections (in order — verified against `apollo.py`)

1. **Toolbar** (fixed, top-right): `Light` | `Print` | `HTML` | `MD` | `TXT` | `JSON`. Removed in `@media print`.
2. **Report header:** classification banner ("AUTHORIZED SECURITY ASSESSMENT — OLYMPUS PLATFORM"), title, subtitle, six-cell meta grid (Target, Mode, Live Hosts, Subdomains, Vendors, Report Date).
3. **Executive summary** (AI when key set; template fallback otherwise).
4. **Finding statistics** — 5 stat tiles (crit/high/med/low/info).
5. **Assessment coverage** — 7 numeric tiles + OWASP-module table (module × tested/not-run × hits).
6. **Attack surface** table (<=200 endpoints, host + path + params list).
7. **Vendor stack** (passive intel) — only when vendors exist.
8. **Findings detail** — sorted by CVSS map; every field HTML-escaped; badge, CVSS, source, description, evidence pre, remediation.
9. **Discovered content paths** (<=250) — status coloring.
10. **Manual test candidates** (checkbox list, marked *candidates, not confirmed findings*).
11. **Live hosts** (<=50).
12. **Footer** — Report ID = mission_id[:8].upper().

### Client-side export payload (`report_payload`)

```
{ target, mode, date, mission_id, summary,
  stats: { critical, high, medium, low, info, total },
  findings: [ { title, severity, cvss, found_by, description, evidence, remediation } ] }
```

### Hard constraints (do not break these)

- **RAW string script.** `apollo.py:384` is `r"""..."""` — do not add Python escapes; the JS `'...\n...'` literals must survive to the browser.
- **U+2028/U+2029 escape** and `</`->`<\/` (`apollo.py:362`). Guarded by `tests/test_report.py`.
- **Nonce CSP.** `<meta http-equiv="Content-Security-Policy" content="script-src 'nonce-{nonce}'; object-src 'none'; base-uri 'none'">`.
- **HTML escape every field** taken from findings, target, mode, exec summary.
- **Never fabricate coverage numbers** — the panel only renders real recon output.
- **Never label candidates as confirmed findings.**

### Report cross-format consistency

CSV / JSON / MD / TXT / HTML all read from the same finding rows. **Verified equivalence:** total finding count and severity buckets are identical across formats; MD adds captured `HttpExchange` blocks; JSON is the machine-readable superset. No conflicting counts observed.

### Known defects (§21)

- **U-1:** the CSV export sanitizes `\n` -> space in description/evidence/remediation/analyst_notes (destructive for line-oriented evidence). Documented; Codex should confirm intent (`missions.py:636`).
- **U-2:** `/api/missions/{id}/report` returns 404 if Apollo failed silently; no visible retry path. Codex should either surface the last render error or expose a "regenerate report" button (`missions.py:979` and `apollo.py:65`).

---

## 12. Security Threat Model (STRIDE, prioritized)

Existing controls verified in code are listed as **CTRL**. Yggdrasil obligations are listed as **NEW-Y**.

| ID | Threat | Vector | CTRL / Gap | Response |
|---|---|---|---|---|
| T-01 | Command injection into scanner binaries | Malicious `target` (e.g. `-oX foo`) | **CTRL** `security.is_valid_target` rejects leading `-` and shell metachars; **CTRL** `subprocess_exec` (list form) throughout `base.run_command`, `hermes`, `ares` | Preserve; add fuzz tests |
| T-02 | Argument smuggling via CIDR / port suffix | `10.0.0.0/24 -X` | **CTRL** `is_valid_target` regex + shell filter | Preserve |
| T-03 | SSRF via workbench / access-check / replay | Analyst points workbench at `169.254.169.254` | **CTRL** `missions._host_in_scope` refuses off-scope hosts (`missions.py:746`) | Preserve; add IPv6/loopback denylist in Yggdrasil common lib |
| T-04 | Scope bypass via AI-derived rules | Model hallucinates a scope entry | **CTRL** `athena._derive_scope` validates every host via `is_valid_target`; model can only narrow; structured file always wins (`zeus.py:68`) | Preserve; add audit log per adopted rule |
| T-05 | Scan against unauthorized target | Missing authorization | **CTRL** Explicit UI warning on launch; classification banner in report; scope rules; single-gate/multi-gate HITL | Preserve; NEW-Y adds signed engagement letter attachment per mission |
| T-06 | Stored / reflected XSS in report | Attacker embeds `<script>` in a response the scanner captured | **CTRL** every finding field `_html.escape`d before render; strict CSP with per-report nonce; toolbar handlers via `addEventListener` (no inline handlers) | Preserve; DOMPurify-style guard for MD-to-HTML in Yggdrasil UI if introduced |
| T-07 | Report-script breakout via captured content | Newlines / U+2028 / `</script>` in finding text | **CTRL** raw string + U+2028/2029 escape + `</`->`<\/` (`apollo.py:360-365`); tested by `test_report.py` | Preserve; do not touch |
| T-08 | Sensitive header leakage in exchanges / PoCs / logs | Cookie/Authorization captured by scanner | **CTRL** `poc.redact_headers` on write and on export; `HttpExchange.redacted=True`; `AuthProfile._profile_dict` redacts on read | Preserve; add DB-level column encryption for AuthProfile.headers under Yggdrasil |
| T-09 | Credentials in scope notes leaked to logs | Password extracted by Athena appears in a log line | **CTRL** `athena._derive_credentials` never logs the password (only the username); `zeus.py:80` moves creds to a transient `_credentials` key not persisted in `ctx["athena"]` | Preserve; NEW-Y stores creds in vault, never in `mission.context` |
| T-10 | SQL injection into Yggdrasil DB | User-controlled string | **CTRL** SQLAlchemy 2.0 parametrized queries throughout | Preserve; audit any raw SQL if added |
| T-11 | Unauthorized API access | Missing/weak API key | **CTRL** `OLYMPUS_API_KEY` gate + WS `?api_key=`; localhost default warned at startup (`main.py:16`) | Replace with Yggdrasil session/OIDC; keep API key as legacy for one major version |
| T-12 | CSRF | Any state-changing request | **CTRL** SPA uses `fetch` w/ `Content-Type: application/json`; no cookie auth today; only session cookie is `frontend`<->`backend` behind nginx SAMEORIGIN header | NEW-Y: proper CSRF token if cookie auth introduced |
| T-13 | CORS misconfig | Wildcard | **CTRL** `CORS_ORIGINS` env, explicit list; default `http://localhost:3000`; `allow_credentials=True` — with a list, not `*` | Preserve; per-tenant origin allowlist |
| T-14 | Prompt injection via captured scan content | Response body -> Metis prompt | **CTRL** `metis.py` truncates fields to 240 chars and asks for strict JSON; advisory-only enforcement means a compromised model can't hide findings | Preserve as guardrail; add prompt-injection classifier once available |
| T-15 | Docker socket exposure | Users mount `docker.sock` | Not exposed by default in compose; **NOT** a service | Document — do not expose |
| T-16 | Container escape / privilege escalation | Backend runs as root, `NET_ADMIN`+`NET_RAW` | **Documented gap** — needed for raw sockets in scanners; Yggdrasil must run worker in a scoped container with seccomp | NEW-Y: audit and gate scanner runs to a scanner sidecar |
| T-17 | Denial of service via unbounded scan | Attacker triggers unbounded CIDR | **CTRL** `OLYMPUS_CIDR_MAX_HOSTS=1024`, `OLYMPUS_OFFENSIVE_MAX_HOSTS=5`, `MAX_PAYLOADS=500` in `replay.py` | Preserve; per-tenant quota in Yggdrasil |
| T-18 | Race on `_run_mission` process death | Backend restart mid-gate | **Documented gap** — mission held in-process; restart loses the pause (`README.md:291`) | **Fix** by moving `_run_mission` to Redis-backed worker (WP-03) |
| T-19 | Cross-workspace / cross-mission data exposure | Single-user assumption | **Documented gap** — no tenancy | **Fix** by mandatory `tenant_id` scoping (WP-02) |
| T-20 | Backup file tampering | Attacker crafts a malicious backup | **CTRL** client + server strict schema validation; imported mission uses fresh id; target re-validated via `is_valid_target`; findings restored verbatim (never-hide invariant) | Preserve; add SHA-256 hash + optional signature in v2 |
| T-21 | Path traversal via report filename | Filename embeds mission id | **CTRL** `report_{mission_id}.html` — mission_id is a UUID; only alnum + dash after generation | Preserve; keep UUID PK |
| T-22 | Supply chain: nuclei/httpx/etc. from GitHub releases at build | Github release hijack | **Documented risk** — build pins version but digest is not checked | NEW-Y: verify checksums in Dockerfile |

---

## 13. Policy and Authorization Requirements

- **Authorized testing only.** Existing UI warning + report banner preserved. Do not remove.
- **HITL gates.** Preserve indefinite-wait default (`OLYMPUS_APPROVAL_TIMEOUT=0`).
- **Findings are never hidden.** Metis rule enforced in code and repeated here as governance.
- **AuthProfile headers.** Never returned raw over API; never exported unredacted unless `redact=false` explicitly.
- **PII / customer evidence retention.** Yggdrasil owns retention policy; recommended default: 90 days for `HttpExchange.response_body`, 365 for finding metadata, indefinite for `AgentLog` (compliance).
- **Right to delete.** Deleting a Mission cascades everything (verified in models); add tombstone + audit under Yggdrasil.
- **Data classification.** Reports & exchanges default `Confidential`; expose only via signed URLs in Yggdrasil.

---

## 14. Accessibility Requirements (WCAG 2.2 AA target)

Preserved and extended:

- Focus-trapped `role="alertdialog"` `ApprovalGate` (`Tab` cycling, `Escape` to deny).
- ARIA tab semantics (`role="tablist"/"tab"/"tabpanel"` in `MissionControl`).
- `aria-label` on icon-only buttons (session backup, dismiss, etc.).
- `.touch-target` class enforces 44×44px minimum on `pointer:coarse` only, preserving desktop density.
- `@media (prefers-reduced-motion: reduce)` neutralizes decorative animations.
- Two-theme color system with dedicated `--crit/high/med/low/info` tokens; light theme values are verified in `index.css:72`.

Yggdrasil obligations:

- Explicit color contrast audit at >=4.5:1 (normal text) / 3:1 (large text). Current dark-theme palette must be measured and, where necessary, minor token nudges applied (do not remove the accent identity).
- Skip links to the mission control tab panel from the header.
- Screen-reader announce for WS `finding` events (aria-live polite region).
- Interactive controls should generally provide at least a 44×44px touch target where applicable.

---

## 15. Import / Export & Recovery Specification

Preserve the existing v1 backup schema; add cosmetic and integrity enhancements.

### v1 schema (as implemented in `core/backup.py` and `MissionControl.tsx:136`)

```
{
  version: "1",
  platform: "OLYMPUS",
  exported_at: ISO-8601,
  mission: { target, scope, mode, status, context: {...}, scope_rules: {...}, current_phase },
  findings: [ { title, severity, description, evidence, cvss_score, remediation,
                found_by, tag, is_manual, analyst_notes, timestamp } ],
  notes:    [ { content, timestamp } ],
  logs:     [ { agent, level, message, timestamp } ],   // last 500
  status, current_phase, live_hosts
}
```

Server accepts either top-level arrays or the nested `mission.{findings,notes,logs}` fallback (see `backup.py:63`).

### Rules Yggdrasil must keep

- Reject non-`"1"` versions with `Invalid or corrupted progress file: unsupported or missing version`.
- Missing/invalid target -> reject 422.
- Import always creates a **new mission id** (never overwrites).
- No findings ever dropped silently (never-hide invariant).
- Corrupt file -> one clear banner; no partial mutation.
- Max caps: 5000 findings / 1000 notes / 2000 logs.

### v2 additions (Yggdrasil release + N)

- Add `sha256` (of the payload with the `sha256` key removed) — client optional, server verifies if present, refuses on mismatch.
- Filename becomes `YGGDRASIL_backup_{YYYY-MM-DD}_{workspace-id}.json` per brief.
- Existing v1 files must still round-trip.

### Prohibited exports

- `AuthProfile.headers` raw values (redacted only).
- `mission.context._credentials` (must be stripped before export).
- Any secret / API key / private key that lives in server-only config.

### UX (all currently implemented; keep)

- **Download Workspace Backup (.json)** — `MissionControl.tsx:238` (button `↓ SESSION`).
- **Import Workspace Backup (.json)** — `MissionList.tsx:196` drag+drop + file picker.
- Pre-import summary in the response payload (`restored.{findings,notes,logs}` counts).
- Explicit confirmation, clear validation failures, atomic import (no partial mutation on failed validation), automatic rollback if hydration fails.
- Deterministic filename (see v2).

---

## 16. Migration Architecture

### 16.1 Chosen strategy — **Shared-module extraction + tenanted namespace + strangler**

Rationale: Olympus is coherent and non-fragmented (12k LOC, 47 files, near-zero implicit couplings). Preserving it as a self-contained module inside Yggdrasil is *safer* than re-platforming.

Rejected alternatives:

- **Direct feature port.** Would rewrite Apollo's report engine and Zeus's state machine — high risk, no benefit.
- **API compatibility layer only.** Doesn't retire the `create_all-only` migration debt.
- **Side-by-side operation.** Doubles the operational surface; not aligned with the brief.

### 16.2 Component boundaries

- `yggdrasil-core/` — auth, tenancy, audit, secrets, event gateway.
- `yggdrasil-assessment/` — the Olympus code, moved wholesale.
- `yggdrasil-web/` — the Yggdrasil shell; Olympus UI mounted at `/assessment`.
- `yggdrasil-migrations/` — Alembic baseline + all new schema versions.
- `yggdrasil-workers/` — Redis-backed worker replacing FastAPI `BackgroundTasks`.

### 16.3 Per-subsystem disposition

| Subsystem | Disposition |
|---|---|
| Zeus state machine | Preserve |
| God agents (Hermes/Ares/offensive/auth/Hephaestus/Hades) | Preserve |
| Metis triage | Preserve (governance-locked) |
| Apollo report | Preserve (regression-locked) |
| Manual workbench (replay/poc/surface) | Preserve |
| Backup (core/backup.py) | Merge (v1 kept, v2 added) |
| Auth/API key | Replace (OIDC) — deprecate legacy |
| Persistence (create_all) | Refactor (Alembic) |
| `_run_mission` BackgroundTasks | Refactor (worker) |
| Reports on volume | Replace (object storage) |
| Redis placeholder | Merge (real queue) |
| Observability | New (OTEL/metrics) |

### 16.4 Backward compatibility & rollback

- Every migration step keeps the old endpoint alive under `/api/...` in addition to `/assessment/api/...` for one release.
- Alembic migrations are reversible for at least one release.
- `OLYMPUS_*` env vars continue to work; a `YGGDRASIL_*` prefix is added and preferred; Codex logs when a deprecated var wins.

---

## 17. Ordered Implementation Backlog

Codex works from this backlog only. Every WP has verified acceptance criteria; do not skip.

### WP-01 — Repository bootstrap
- **Objective:** create `yggdrasil-*` monorepo scaffolding; import Olympus source at `yggdrasil-assessment/` verbatim; add license, root README, code-owners, CI skeleton.
- **Dependencies:** none.
- **Files:** new.
- **DB changes:** none.
- **API changes:** none.
- **UI changes:** none.
- **Security controls:** repo-level branch protection.
- **Tests:** CI runs `pytest` on the imported Olympus tests (all 9 files must pass unchanged).
- **Acceptance:** Olympus tests are green in Yggdrasil CI without modification.
- **Rollback:** delete the new repo/monorepo folder.
- **Risk:** low; **Complexity:** small; **Parallelizable:** no.

### WP-02 — Tenancy layer + Alembic baseline
- **Objective:** add `tenant_id` column to all 7 Olympus tables; establish Alembic baseline that reflects the current `create_all` schema exactly; default tenant `default`.
- **Dependencies:** WP-01.
- **Files:** `yggdrasil-migrations/versions/000001_baseline.py`, `core/models.py`.
- **DB:** additive columns; index on `(tenant_id, id)` for every table.
- **API:** every route requires tenant context; `default` used for legacy tokens.
- **UI:** login screen; tenant switcher (may be behind a feature flag).
- **Security:** all queries filter by `tenant_id`; verified via automated route audit.
- **Tests:** contract test that no endpoint returns another tenant's data; upgrade + downgrade Alembic on a v1-only DB.
- **Acceptance:** `pytest` + tenant-isolation test suite pass.
- **Rollback:** `alembic downgrade -1`; column drop safe because default `default` was assigned.
- **Risk:** medium; **Complexity:** medium; **Parallelizable:** no.

### WP-03 — Move `_run_mission` to a Redis-backed worker
- **Objective:** eliminate the "restart loses paused mission" defect (T-18, `README.md:291`).
- **Dependencies:** WP-02.
- **Files:** `routers/missions.py:212`, new `yggdrasil-workers/mission_runner.py`, `docker-compose.yml`.
- **DB:** none — approval state already in `ApprovalRequest` row; only the `asyncio.Event` needs to move.
- **API:** unchanged.
- **UI:** unchanged.
- **Security:** worker must not have raw scanner access it doesn't need — same seccomp policy.
- **Tests:** integration test that kills the worker mid-gate, restarts it, and the gate resumes when approved.
- **Acceptance:** paused mission survives worker restart; approval resolves the correct gate.
- **Rollback:** revert router change; missions run in-process again.
- **Risk:** medium; **Complexity:** medium; **Parallelizable:** no.

### WP-04 — Identity (OIDC) + deprecate `OLYMPUS_API_KEY`
- **Objective:** Yggdrasil sessions replace `X-API-Key`; API key kept as legacy for one release.
- **Dependencies:** WP-02.
- **Files:** `main.py:45` (dependency wiring), new `core/auth_oidc.py`, `security.py`.
- **API:** all `dependencies=[Depends(require_api_key)]` become `[Depends(require_yggdrasil_session)]`; legacy path preserved behind a flag.
- **UI:** login page; remove `localStorage['olympus_api_key']` prompt.
- **Security:** enforce short-lived tokens; propagate `tenant_id` from token claim.
- **Tests:** OIDC login e2e; legacy key rejected when flag off.
- **Acceptance:** every API route rejects unauthenticated requests.
- **Rollback:** feature flag -> revert to legacy.
- **Risk:** medium; **Complexity:** large; **Parallelizable:** yes.

### WP-05 — WebSocket auth via Yggdrasil session
- **Objective:** replace `?api_key=` on `/ws/{mission_id}` with a short-lived signed ticket.
- **Dependencies:** WP-04.
- **Files:** `routers/ws.py:41`, `core/security.py:46`.
- **Acceptance:** WS refuses non-ticket connections; ticket TTL <=5m.
- **Rollback:** feature flag.
- **Risk:** low; **Complexity:** small; **Parallelizable:** yes.

### WP-06 — Reports to object storage + signed URL
- **Objective:** move `settings.reports_dir` to S3-compatible storage; return signed URL.
- **Dependencies:** WP-02.
- **Files:** `routers/missions.py:979`, `agents/apollo.py:656`.
- **Security:** signed URLs expire <=15 min; never cache a stale nonce.
- **Acceptance:** existing report route returns a redirect / signed URL; report opens; the local-file fallback is behind a feature flag.
- **Rollback:** feature flag -> local file fallback.
- **Risk:** medium; **Complexity:** medium; **Parallelizable:** yes.

### WP-07 — v2 backup: filename change + SHA-256 integrity
- **Objective:** rename filename to `YGGDRASIL_backup_{YYYY-MM-DD}_{workspace-id}.json`; add optional `sha256`; keep v1 accepted.
- **Dependencies:** WP-02.
- **Files:** `MissionControl.tsx:136`, `core/backup.py`, tests `test_backup.py`.
- **Security:** integrity check on import when present.
- **Acceptance:** v1 files still round-trip; v2 files reject on hash mismatch.
- **Rollback:** feature flag.
- **Risk:** low; **Complexity:** small; **Parallelizable:** yes.

### WP-08 — AuthProfile secrets vault
- **Objective:** move `AuthProfile.headers` values to Yggdrasil vault; store vault refs in DB.
- **Dependencies:** WP-04.
- **Files:** `core/models.py:122`, `routers/missions.py:869/878`, `agents/auth.py`.
- **Security:** raw values never at rest in DB; redaction contract unchanged on read.
- **Acceptance:** `AccessCheckPanel` continues to work; DB grep shows no raw headers.
- **Rollback:** dual-read for one release; then drop DB column.
- **Risk:** medium; **Complexity:** medium; **Parallelizable:** yes.

### WP-09 — Structured logs + OpenTelemetry + `/metrics`
- **Objective:** Yggdrasil observability baseline.
- **Dependencies:** WP-01.
- **Files:** `main.py`, every agent (add a common logger).
- **Security:** never emit finding evidence into structured logs.
- **Acceptance:** OTEL trace across `POST /missions` -> worker -> gate -> Apollo -> response.
- **Rollback:** config flag off.
- **Risk:** low; **Complexity:** medium; **Parallelizable:** yes.

### WP-10 — Report defect fixes (U-1, U-2)
- **Objective:** (a) do not destroy `\n` in CSV description/evidence/remediation/analyst_notes; (b) surface Apollo render error and expose a "regenerate report" button.
- **Dependencies:** WP-01.
- **Files:** `routers/missions.py:636`, `agents/apollo.py:65`.
- **Acceptance:** CSV preserves newlines (quoted); missing report shows a retry action; regeneration succeeds when Apollo's inputs are still available.
- **Rollback:** revert commits (small).
- **Risk:** low; **Complexity:** small; **Parallelizable:** yes.

### WP-11 — Network-hosts panel (Hermes CIDR sweep) in UI + Apollo
- **Objective:** render the `hermes["network_hosts"]` data set in Surface + report.
- **Dependencies:** WP-01.
- **Files:** `SurfacePanel.tsx`, `apollo.py`.
- **Acceptance:** panel shows IP × ports/services; report has a Network Hosts section when the sweep produced any.
- **Rollback:** feature flag.
- **Risk:** low; **Complexity:** small; **Parallelizable:** yes.

### WP-12 — Promote nonstandard web ports found by network sweep into `live_hosts`
- **Objective:** feed a web port discovered only by nmap into ARES's httpx pipeline.
- **Dependencies:** WP-11.
- **Files:** `agents/hermes.py:775`.
- **Acceptance:** synthesized case (nmap finds 8080, httpx missed it) -> `live_hosts` gains that host and ARES scans it.
- **Rollback:** feature flag.
- **Risk:** low; **Complexity:** small; **Parallelizable:** yes.

### WP-13 — Active LLM red-teaming module (behind gate)
- **Objective:** actively probe endpoints tagged by `ai_surface` (prompt injection, jailbreak, system-prompt extraction). Gated behind a new HITL approval.
- **Dependencies:** WP-03, WP-09.
- **Files:** new `agents/loki.py` (or add to `offensive.py`); router hook.
- **Security:** scope-safe; deterministic default; must add another approval gate; results are candidates.
- **Acceptance:** running on the AI Endpoints tab emits candidate findings with attempted payload + response-indicator evidence; never crosses into destructive territory.
- **Rollback:** feature flag; new agent disabled.
- **Risk:** high; **Complexity:** large; **Parallelizable:** no.

### WP-14 — Screenshot capture via Playwright
- **Objective:** capture per-host and per-finding screenshots.
- **Dependencies:** WP-03.
- **Files:** Dockerfile (Playwright install), `agents/offensive.py`.
- **Security:** run under a low-privilege user; disable webcam / mic / geo.
- **Acceptance:** screenshots attach to `HttpExchange`; Apollo embeds thumbnails; report size stays bounded.
- **Rollback:** feature flag.
- **Risk:** medium; **Complexity:** medium; **Parallelizable:** yes.

### WP-15 — UDP / full-range sweep option
- **Objective:** optional deep sweep past the curated port set.
- **Dependencies:** WP-03.
- **Files:** `agents/hermes.py:52` port constant, launch UI.
- **Security:** cap harder; require explicit approval.
- **Acceptance:** opt-in only; documented long runtimes.
- **Rollback:** feature flag.
- **Risk:** medium; **Complexity:** medium; **Parallelizable:** yes.

### WP-16 — Per-user favorites / prefs table
- **Objective:** replace `localStorage['olympus_favorites']` and theme with server-side per-user prefs.
- **Dependencies:** WP-04.
- **Files:** `MissionList.tsx`, new prefs endpoint, new table.
- **Acceptance:** favorites persist across devices; theme persists.
- **Rollback:** fallback to localStorage.
- **Risk:** low; **Complexity:** small; **Parallelizable:** yes.

Ordering rationale: WP-01->WP-02->WP-03 unlock every subsequent package; WP-10..WP-12 are safe cleanups Codex can start in parallel; WP-13..WP-15 are opt-in expansions.

---

## 18. Test Matrix

Every group is either **blocking** (release-gating) or **advisory**.

| Group | Command / harness | Environment | Pass threshold | Evidence | Status |
|---|---|---|---|---|---|
| Unit — Olympus (imported) | `docker compose exec backend python -m pytest tests/ -q` | backend container | 100% pass | pytest report | blocking |
| Unit — Yggdrasil migrations | `alembic upgrade head && alembic downgrade -1 && alembic upgrade head` on a v1 schema DB | CI | 0 errors, table diff empty at head | migration log | blocking |
| Contract — REST | Schemathesis/httpx over OpenAPI generated from FastAPI | CI | all endpoints 2xx/4xx per spec | HTML report | blocking |
| Contract — WSEvent | JSON-schema validation of every broadcast in a real mission | integration | 100% match | log tarball | blocking |
| Integration — full mission (passive) | Drive a mission against `juice-shop:3000` on the docker network | integration | Apollo report file exists; >=1 finding | HTML report artifact | blocking |
| Integration — HITL gate | Trigger active gate, restart worker, resume | integration | Approval resolves without loss | worker logs | blocking |
| Integration — backup round-trip | Export v1 in Olympus, import in Yggdrasil, findings verbatim | e2e | Findings count and severities identical | JSON diff | blocking |
| Integration — v2 backup w/ SHA-256 | Tamper hash, import fails | e2e | 422 with clear reason | server log | blocking |
| E2E browser — golden path | Playwright: launch -> approve -> find -> export MD | e2e | All steps succeed | Playwright video | blocking |
| E2E browser — accessibility | axe-core scan on every screen | e2e | 0 serious violations | axe report | blocking |
| Visual regression — report | Percy on rendered report (dark + light + print) | e2e | pixel diff below threshold | Percy diff | advisory |
| Security — scope guard | Attempt off-scope URL via `/replay`, `/fuzz`, `/access-check` | integration | 400 in every case | test log | blocking |
| Security — target validation | Fuzz `target` for shell metachars, leading `-` | unit | rejection rate 100% | fuzz report | blocking |
| Security — CSP | Attempt inline script injection in a finding evidence | e2e | Browser blocks; nonce report unchanged | headless log | blocking |
| Security — redaction | Verify Cookie/Authorization redacted in DB, WS broadcasts, exports | integration | 0 occurrences | grep report | blocking |
| Security — dependency scan | `pip-audit` + `npm audit` | CI | No unfixed critical | audit JSON | blocking |
| Security — container scan | Trivy on backend + frontend images | CI | No unfixed critical | Trivy JSON | blocking |
| Security — secret scan | gitleaks | CI | 0 leaks | gitleaks report | blocking |
| Performance — mission throughput | 5 missions concurrently against a mock target | load | No mission fails; p95 latency for `/api/missions/{id}` <= 500ms | k6 report | blocking |
| Performance — WS fan-out | 20 clients on 1 mission | load | No drops | log | advisory |
| Failure — worker crash | Kill worker mid-Ares | fault | Mission recovers or moves to `failed` cleanly | log | blocking |
| Failure — DB failover | Postgres restart mid-mission | fault | Retries succeed; no data loss | log | advisory |
| Failure — nuclei binary missing | Delete `nuclei` at runtime, run mission | fault | Mission continues with warning; no crash | log | blocking |
| Compatibility — cross-browser | Chromium, Firefox, WebKit | e2e | Golden path passes | Playwright videos | blocking |
| Manual — engagement scenarios | Human tester on OWASP Juice Shop and PortSwigger labs | UAT | Pass per acceptance checklist | signed checklist | blocking |

Blocking = must be green to release. Advisory = should be green.

---

## 19. Release Gates

A Yggdrasil integration release is only allowed when all of:

1. Every "blocking" row in §18 is green.
2. All Olympus tests (`backend/tests/`) run in the Yggdrasil CI and pass unchanged.
3. `test_report.py` in particular remains green (regression guard for the raw-string bug).
4. Backup v1 round-trip test is green.
5. Tenant isolation contract test is green.
6. Security review sign-off exists (§12 controls audited).
7. Rollback rehearsal completed (see §20).

---

## 20. Rollback Plan

Per WP:

- **WP-01:** delete the new repo/subtree.
- **WP-02:** `alembic downgrade` to baseline; tenant column is nullable with `default` fallback.
- **WP-03:** feature-flag flip -> `BackgroundTasks` again.
- **WP-04:** feature-flag flip -> `OLYMPUS_API_KEY` again.
- **WP-05:** feature-flag flip.
- **WP-06:** feature-flag -> local file fallback.
- **WP-07:** feature-flag; v1 always accepted.
- **WP-08:** dual-read -> revert; migrate values back before drop.
- **WP-09–WP-16:** each behind its own feature flag; can be disabled per tenant.

Data rollback:

- Nightly logical dump of every table (`pg_dump -Fc`) retained 30 days.
- Reports stored in versioned S3 buckets.

Runbook: every WP's PR must include a `ROLLBACK.md` referenced here.

---

## 21. Known Uncertainties

- **U-Yggdrasil.** Yggdrasil repo not accessible; NEW-Y is a specification, not a reconciliation.
- **U-1 (CSV export).** `\n` collapsed to spaces in CSV cells for description/evidence/remediation/analyst_notes — potentially data-lossy. Fix in WP-10.
- **U-2 (report render failure).** Apollo swallows the render exception (`apollo.py:65`) so a mission is "complete" with no report and only a log line. Fix in WP-10.
- **U-3 (Alembic in requirements).** Alembic is in `requirements.txt` but no `alembic.ini` or `versions/` directory exists — it's imported but unused. Confirms `create_all`-only constraint; nothing to migrate today.
- **U-4 (Redis).** Declared in compose but never imported. Codex must plug the worker in (WP-03) or drop the dependency.
- **U-5 (WS presence).** `useWebSocket.ts` was not read here in detail; briefly confirmed 3s reconnect backoff per HANDOFF.md. Codex should re-read it before touching WS.
- **U-6 (dedup semantics).** Finding dedup relies on the offensive engine's URL-set + Metis's advisory summary — there is no explicit `Finding.dedup_key` column. If Codex reduces false noise further, do it in Metis with an advisory annotation, not a delete.
- **U-7 (ZAP contention).** Single shared ZAP daemon; ARES runs offensive sequentially per host. Yggdrasil multi-tenant scale needs a per-tenant ZAP or a queue in front of ZAP.
- **U-8 (light theme completeness).** Every component visited uses CSS variables; a targeted audit still required to catch inline colors.
- **U-9 (nonce reuse under CDN caching).** The report is a static file with an inline nonce; that's fine for the current per-mission download, but caching semantics change if reports move behind a CDN. WP-06 must account for this — never cache a report with an old nonce.
- **U-10 (setup.sh install ergonomics).** Kali-specific behavior; Yggdrasil deployment moves to Helm/Compose-only; setup.sh becomes an operator convenience for local dev.

---

## 22. Evidence Index

Every claim above is grounded in the following files (paths are relative to `/home/user/MISC/olympus`):

- Runtime & orchestration: `docker-compose.yml`, `backend/main.py`, `backend/Dockerfile`, `frontend/Dockerfile`, `frontend/nginx.conf`.
- Data model: `backend/core/models.py`, `backend/core/database.py`.
- State machine: `backend/agents/zeus.py`, `backend/agents/base.py`.
- Recon: `backend/agents/hermes.py`.
- Active scanning: `backend/agents/ares.py`, `backend/agents/offensive.py`, `backend/agents/auth.py`.
- AI: `backend/agents/athena.py`, `backend/agents/metis.py`, `backend/core/ai_client.py`, `backend/core/ai_surface.py`.
- Payload forge / post-exploit: `backend/agents/hephaestus.py`, `backend/agents/hades.py`.
- Report: `backend/agents/apollo.py`, `backend/tests/test_report.py`.
- Manual workbench + evidence: `backend/core/replay.py`, `backend/core/poc.py`, `backend/core/surface.py`, `backend/core/wordlists.py`.
- Backup: `backend/core/backup.py`, `backend/tests/test_backup.py`, `frontend/src/components/MissionList.tsx` (import), `frontend/src/components/MissionControl.tsx:136` (export).
- Routes: `backend/routers/{missions,scope,wordlists,oracle,ws}.py`.
- Security guard: `backend/core/security.py`, `backend/tests/test_security.py`.
- Deterministic engines: `backend/tests/{test_poc,test_replay,test_surface,test_forms,test_network_sweep,test_ai_surface}.py`.
- Frontend contract: `frontend/src/api.ts`, `frontend/src/types.ts`, `frontend/src/index.css`, `frontend/src/App.tsx`.
- Governance / operator docs: `README.md`, `HANDOFF.md`, `CLAUDE.md`, `.env.example`, `setup.sh`, `README-wordlists-oracle.md`, `README_CAVEMAN.md`.

Git commit at handoff time: `63e5960f418e1afe68c22e2184590c0a6b4b1a6e` on branch `claude/olympus-yggdrasil-migration-m3ljlo`.

---

## 23. Machine-readable Implementation Manifest

```yaml
handoff_version: "1.0"
source_product: "Olympus"
destination_product: "Yggdrasil"
assumptions:
  - "Yggdrasil repository is not accessible; destination spec is NEW-Y (see section 16)."
  - "Olympus current-state commit is authoritative; no code was modified during discovery."
  - "Backup schema v1 is preserved across the first major Yggdrasil release."
repositories:
  olympus:
    branch: "claude/olympus-yggdrasil-migration-m3ljlo"
    commit: "63e5960f418e1afe68c22e2184590c0a6b4b1a6e"
    path: "/home/user/MISC/olympus"
  yggdrasil:
    branch: null      # repository absent at handoff time
    commit: null
    path: null
features:
  - id: F001
    name: "Mission create"
    source_locations: ["olympus/backend/routers/missions.py:190", "olympus/backend/core/models.py:34"]
    destination_locations: ["yggdrasil-assessment/routers/missions.py"]
    status: "works"
    migration_action: "preserve+tenant"
    priority: "P0"
    dependencies: []
    acceptance_criteria:
      - "POST returns {id,target,status}; row includes context.auto_approve"
      - "tenant_id populated from session"
    required_tests: ["unit/router-create", "e2e/mission-golden-path"]
    security_requirements: ["target validation via is_valid_target", "tenant isolation"]
    evidence: ["backend/routers/missions.py:190", "backend/core/models.py:34"]
  - id: F008
    name: "HITL gate — wait indefinitely by default"
    source_locations: ["olympus/backend/agents/base.py:224"]
    destination_locations: ["yggdrasil-assessment/agents/base.py"]
    status: "works"
    migration_action: "preserve"
    priority: "P0"
    dependencies: ["WP-03"]
    acceptance_criteria:
      - "OLYMPUS_APPROVAL_TIMEOUT=0 waits forever; gate persists across UI refresh"
      - "Worker restart does not lose the paused gate"
    required_tests: ["integration/hitl-worker-restart"]
    security_requirements: ["approval row created with audit metadata"]
    evidence: ["backend/agents/base.py:166-244"]
  - id: F019
    name: "Scope hard-enforce priority"
    source_locations: ["olympus/backend/agents/zeus.py:68"]
    destination_locations: ["yggdrasil-assessment/agents/zeus.py"]
    status: "works"
    migration_action: "preserve"
    priority: "P0"
    dependencies: []
    acceptance_criteria:
      - "AI-derived rules never override an uploaded structured file"
    required_tests: ["integration/scope-priority"]
    security_requirements: ["structured always wins; AI can only narrow"]
    evidence: ["backend/agents/zeus.py:65-77", "backend/agents/athena.py:145"]
  - id: F065
    name: "Metis advisory FP flag (never hides)"
    source_locations: ["olympus/backend/agents/metis.py:101-115"]
    destination_locations: ["yggdrasil-assessment/agents/metis.py"]
    status: "works"
    migration_action: "preserve+enforce_governance"
    priority: "P0"
    dependencies: []
    acceptance_criteria:
      - "Findings are never tagged false_positive or deleted by Metis"
      - "analyst_notes only appended; never overwritten"
    required_tests: ["unit/metis-advisory-only", "integration/report-never-drops-findings"]
    security_requirements: ["governance-review-required if edited"]
    evidence: ["backend/agents/metis.py:101-133"]
  - id: F079
    name: "Report client-side export (RAW string + Unicode escapes)"
    source_locations: ["olympus/backend/agents/apollo.py:356-478"]
    destination_locations: ["yggdrasil-assessment/agents/apollo.py"]
    status: "works"
    migration_action: "preserve+regression_guard"
    priority: "P0"
    dependencies: []
    acceptance_criteria:
      - "test_report.py green"
      - "Report script parses under nonce CSP with U+2028/U+2029 present in a finding"
    required_tests: ["backend/tests/test_report.py"]
    security_requirements: ["nonce CSP", "no inline handlers", "html.escape on every field"]
    evidence: ["backend/agents/apollo.py:356-482", "backend/tests/test_report.py"]
  - id: F085
    name: "HttpExchange at-rest redaction"
    source_locations: ["olympus/backend/core/models.py:93", "olympus/backend/agents/base.py:85-146", "olympus/backend/core/poc.py:12-28"]
    destination_locations: ["yggdrasil-assessment/agents/base.py", "yggdrasil-assessment/core/poc.py"]
    status: "works"
    migration_action: "preserve+extend"
    priority: "P0"
    dependencies: ["WP-08"]
    acceptance_criteria:
      - "Cookie/Authorization/Set-Cookie/X-API-Key/X-Auth-Token/Proxy-Authorization/X-CSRF-Token redacted at write"
      - "PoC export honors redact=true by default"
    required_tests: ["backend/tests/test_poc.py", "integration/redaction-grep"]
    security_requirements: ["never-store-raw-credentials"]
    evidence: ["backend/core/poc.py:12", "backend/agents/base.py:100"]
  - id: F088
    name: "Workbench replay scope guard"
    source_locations: ["olympus/backend/routers/missions.py:746-758", "olympus/backend/routers/missions.py:761-796"]
    destination_locations: ["yggdrasil-assessment/routers/missions.py"]
    status: "works"
    migration_action: "preserve"
    priority: "P0"
    dependencies: []
    acceptance_criteria:
      - "Off-scope URL returns 400 'Target host is outside this mission's scope'"
    required_tests: ["integration/workbench-scope"]
    security_requirements: ["no open request relay"]
    evidence: ["backend/routers/missions.py:746"]
  - id: F102
    name: "Session restore (server strict validation, new-id import)"
    source_locations: ["olympus/backend/routers/missions.py:226", "olympus/backend/core/backup.py"]
    destination_locations: ["yggdrasil-assessment/routers/missions.py"]
    status: "works"
    migration_action: "preserve+v2_hash"
    priority: "P0"
    dependencies: ["WP-07"]
    acceptance_criteria:
      - "Restore always creates a new mission id"
      - "Corrupt/unsupported-version file returns 422"
      - "Findings/notes/logs caps enforced"
    required_tests: ["backend/tests/test_backup.py", "e2e/backup-round-trip"]
    security_requirements: ["target re-validated via is_valid_target"]
    evidence: ["backend/routers/missions.py:226", "backend/core/backup.py:42"]
work_packages:
  - id: WP-01
    title: "Repository bootstrap"
    dependencies: []
    affected_areas: ["repo scaffold", "CI"]
    acceptance_criteria:
      - "Olympus tests run in Yggdrasil CI and pass unchanged"
    required_tests: ["ci/olympus-imported-suite"]
    rollback: "Delete the new repo/monorepo folder"
  - id: WP-02
    title: "Tenancy + Alembic baseline"
    dependencies: ["WP-01"]
    affected_areas: ["core/models.py", "migrations", "every router dependency"]
    acceptance_criteria:
      - "tenant_id present on all 7 tables"
      - "Alembic upgrade+downgrade round-trip clean"
      - "Tenant isolation contract test green"
    required_tests: ["unit/tenant-scoping", "migration/round-trip"]
    rollback: "alembic downgrade -1; default tenant retained"
  - id: WP-03
    title: "Redis-backed mission worker"
    dependencies: ["WP-02"]
    affected_areas: ["routers/missions.py:212", "workers/", "docker-compose.yml"]
    acceptance_criteria:
      - "Paused mission survives worker restart"
      - "Approval resolves the correct gate after restart"
    required_tests: ["integration/hitl-worker-restart"]
    rollback: "Feature flag -> BackgroundTasks path"
  - id: WP-04
    title: "OIDC identity + deprecate OLYMPUS_API_KEY"
    dependencies: ["WP-02"]
    affected_areas: ["main.py:45", "core/security.py", "auth/"]
    acceptance_criteria:
      - "All routes require Yggdrasil session"
      - "Legacy key rejected when flag off"
    required_tests: ["e2e/oidc-login", "unit/api-key-legacy"]
    rollback: "Feature flag -> legacy X-API-Key"
  - id: WP-05
    title: "WebSocket auth via signed ticket"
    dependencies: ["WP-04"]
    affected_areas: ["routers/ws.py:41", "core/security.py:46"]
    acceptance_criteria:
      - "WS rejects missing/expired ticket"
      - "Ticket TTL <= 5 minutes"
    required_tests: ["integration/ws-auth"]
    rollback: "Feature flag"
  - id: WP-06
    title: "Reports to object storage + signed URL"
    dependencies: ["WP-02"]
    affected_areas: ["routers/missions.py:979", "agents/apollo.py:656"]
    acceptance_criteria:
      - "Report route returns signed URL"
      - "Signed URL expires <= 15 minutes"
      - "Cache never serves a stale nonce"
    required_tests: ["integration/report-signed-url", "e2e/report-render"]
    rollback: "Feature flag -> local file fallback"
  - id: WP-07
    title: "v2 backup: rename + SHA-256"
    dependencies: ["WP-02"]
    affected_areas: ["MissionControl.tsx:136", "core/backup.py", "tests/test_backup.py"]
    acceptance_criteria:
      - "v1 files still round-trip"
      - "v2 file with mismatched hash rejected with clear reason"
      - "Filename YGGDRASIL_backup_{YYYY-MM-DD}_{workspace-id}.json"
    required_tests: ["unit/backup-v2-hash", "e2e/backup-round-trip"]
    rollback: "Feature flag"
  - id: WP-08
    title: "AuthProfile headers -> secrets vault"
    dependencies: ["WP-04"]
    affected_areas: ["core/models.py:122", "routers/missions.py:869/878", "agents/auth.py"]
    acceptance_criteria:
      - "No raw credential values found in DB grep"
      - "Access check UX unchanged"
    required_tests: ["integration/authprofile-vault"]
    rollback: "Dual-read until values migrated back"
  - id: WP-09
    title: "OTEL + structured logs + /metrics"
    dependencies: ["WP-01"]
    affected_areas: ["main.py", "every agent"]
    acceptance_criteria:
      - "OTEL trace across mission lifecycle"
      - "No finding evidence in structured logs"
    required_tests: ["integration/otel-trace", "unit/log-redaction"]
    rollback: "Config flag off"
  - id: WP-10
    title: "CSV export newline preservation + Apollo render surfacing"
    dependencies: ["WP-01"]
    affected_areas: ["routers/missions.py:636", "agents/apollo.py:65", "routers/missions.py:979"]
    acceptance_criteria:
      - "CSV cells preserve newlines (quoted)"
      - "Missing report surfaces render error + retry action"
    required_tests: ["unit/csv-newline", "e2e/report-retry"]
    rollback: "Revert commits (small)"
  - id: WP-11
    title: "Network hosts panel + report section"
    dependencies: ["WP-01"]
    affected_areas: ["SurfacePanel.tsx", "agents/apollo.py"]
    acceptance_criteria:
      - "Panel and report render network_hosts inventory when present"
    required_tests: ["visual/report-network-hosts"]
    rollback: "Feature flag"
  - id: WP-12
    title: "Promote nonstandard web ports into live_hosts"
    dependencies: ["WP-11"]
    affected_areas: ["agents/hermes.py:775"]
    acceptance_criteria:
      - "Nmap-only web port becomes an ARES scan target"
    required_tests: ["integration/promote-port"]
    rollback: "Feature flag"
  - id: WP-13
    title: "Active LLM red-teaming (behind gate)"
    dependencies: ["WP-03", "WP-09"]
    affected_areas: ["agents/loki.py (new)", "routers/missions.py"]
    acceptance_criteria:
      - "New HITL gate before LLM probing"
      - "Findings emitted as candidates"
      - "Scope guard enforced"
    required_tests: ["integration/llm-red-team-scope", "unit/llm-payloads"]
    rollback: "Feature flag; new agent disabled"
  - id: WP-14
    title: "Screenshot capture (Playwright)"
    dependencies: ["WP-03"]
    affected_areas: ["backend/Dockerfile", "agents/offensive.py"]
    acceptance_criteria:
      - "Screenshots attach to HttpExchange"
      - "Report size bounded"
    required_tests: ["integration/screenshots"]
    rollback: "Feature flag"
  - id: WP-15
    title: "UDP / full-range sweep option"
    dependencies: ["WP-03"]
    affected_areas: ["agents/hermes.py:52", "MissionLaunch.tsx"]
    acceptance_criteria:
      - "Opt-in only; cap enforced"
    required_tests: ["integration/full-sweep"]
    rollback: "Feature flag"
  - id: WP-16
    title: "Per-user favorites/prefs"
    dependencies: ["WP-04"]
    affected_areas: ["MissionList.tsx", "new prefs table + endpoint"]
    acceptance_criteria:
      - "Favorites persist across devices"
      - "Theme persists"
    required_tests: ["e2e/prefs-persist"]
    rollback: "Fallback to localStorage"
release_gates:
  - "All blocking tests in section 18 green"
  - "Backup v1 round-trip green"
  - "test_report.py green (regression guard)"
  - "Tenant isolation contract test green"
  - "Rollback rehearsal completed"
```

---

OPUS HANDOFF COMPLETE — AWAITING CODEX IMPLEMENTATION PACKAGE
