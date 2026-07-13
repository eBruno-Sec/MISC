# Yggdrasil to Olympus Handoff

## 1. Executive Summary

Yggdrasil is a self-hosted, Docker-native security assessment workspace for authorized pentesting and bug bounty workflows. It is not only a scanner UI: it has mission orchestration, explicit approval gates, recon, active web testing, scope parsing, live logs, findings, analyst notes, relaunch, agent reruns, CSV/JSON export, and HTML reporting.

The strongest parts worth comparing against Olympus are:

- The mission orchestration flow in `backend/agents/zeus.py`.
- The active web testing engine in `backend/agents/offensive.py`.
- Deterministic scope/probe helpers in `backend/core/web_security.py`.
- Scope parser support in `backend/routers/scope.py`.
- Mission health/heartbeat handling in `backend/core/mission_health.py`.
- Findings workflow fields in `backend/core/models.py` and `frontend/src/components/FindingsPanel.tsx`.
- Approval gate behavior in `backend/agents/base.py`, `backend/routers/missions.py`, and `frontend/src/components/ApprovalGate.tsx`.
- Report/export surfaces in `backend/agents/apollo.py` and `backend/routers/missions.py`.

Yggdrasil is weaker as a proof-of-concept workbench. It stores findings, evidence text, notes, and reports, but it does not have first-class records for HTTP requests/responses, replay, screenshots, artifacts, reproduction steps, auth/session profiles, role comparison, GraphQL/API collections, file upload cases, or business-logic workflows.

Claude Code should not blindly port all scanner logic. First inspect Olympus for equivalent modules. Integrate only the Yggdrasil pieces that improve pentester evidence quality, reproducibility, and workflow clarity.

## 2. Repository Map

Root:

- `README.md` - Yggdrasil overview, modes, environment variables, reports, notes.
- `README_CAVEMAN.md` - simplified usage notes.
- `docker-compose.yml` - Postgres, Redis, backend, frontend/nginx.
- `setup.sh` - small setup helper.
- `yggdrasil.sh` - larger local control script.
- `.env` - local environment file. Do not commit this.
- `.env.example` - safe environment template.
- `YGGDRASIL_TO_OLYMPUS_HANDOFF.md` - this handoff.

Backend:

- `backend/main.py` - FastAPI app, router registration, CORS, startup recovery.
- `backend/Dockerfile` - installs OS tools and security tools, then Python app.
- `backend/requirements.txt` - Python dependencies.
- `backend/core/models.py` - SQLAlchemy mission/log/finding/approval/note models.
- `backend/core/database.py` - async SQLAlchemy session/engine.
- `backend/core/config.py` - pydantic settings.
- `backend/core/security.py` - API-key checks and target validation.
- `backend/core/ai_client.py` - Anthropic/OpenRouter completion helper.
- `backend/core/mission_health.py` - one-minute mission heartbeat state/logging.
- `backend/core/web_security.py` - deterministic scope/probe/diff helpers.
- `backend/routers/missions.py` - mission CRUD, approvals, findings, notes, targets, reruns, exports, reports.
- `backend/routers/scope.py` - scope import/parser.
- `backend/routers/ws.py` - WebSocket connection manager.
- `backend/agents/base.py` - logging, finding creation, command runner, approval gates.
- `backend/agents/zeus.py` - Odin orchestrator.
- `backend/agents/athena.py` - Frigg strategy/scope interpretation.
- `backend/agents/hermes.py` - Heimdall recon.
- `backend/agents/ares.py` - Tyr active service checks and offensive engine entry.
- `backend/agents/offensive.py` - active web-app testing modules.
- `backend/agents/hephaestus.py` - Brokkr payload forge.
- `backend/agents/hades.py` - Skuld impact review.
- `backend/agents/apollo.py` - Saga report writer.
- `backend/tests/test_web_security.py` - scope/probe/parameter generation tests.
- `backend/tests/test_approval_flow.py` - scope summary and approval waiter tests.

Frontend:

- `frontend/package.json` - React/Vite/TypeScript app.
- `frontend/Dockerfile` - Vite build served by nginx.
- `frontend/nginx.conf` - proxy for `/api` and `/ws`.
- `frontend/src/App.tsx` - routes and header.
- `frontend/src/api.ts` - REST API client.
- `frontend/src/types.ts` - shared UI types.
- `frontend/src/brand.ts` - Yggdrasil/Norse stage names.
- `frontend/src/index.css` - friendly green/white UI theme.
- `frontend/src/hooks/useWebSocket.ts` - live mission event stream.
- `frontend/src/components/MissionList.tsx` - mission archive, delete, relaunch.
- `frontend/src/components/MissionLaunch.tsx` - launch wizard and scope import.
- `frontend/src/components/MissionControl.tsx` - live mission workspace.
- `frontend/src/components/GodStatus.tsx` - stage status/rerun controls.
- `frontend/src/components/ApprovalGate.tsx` - active-operation authorization modal.
- `frontend/src/components/FindingsPanel.tsx` - findings CRUD, tags, notes field.
- `frontend/src/components/TargetsPanel.tsx` - targets list, add targets, rerun Tyr.
- `frontend/src/components/NotesPanel.tsx` - mission notes.
- `frontend/src/components/TerminalFeed.tsx` - live activity log.
- `frontend/src/components/RerunModal.tsx` - rerun stage options.

Generated/local folders present:

- `frontend/node_modules/` - should not be committed.
- `frontend/dist/` - should normally not be committed unless Olympus intentionally vendors built assets.
- `backend/**/__pycache__/` - should not be committed.

## 3. Tech Stack

Runtime:

- Docker Compose.
- Backend: Python 3.11, FastAPI, Uvicorn, SQLAlchemy async, asyncpg, Pydantic, httpx, dnspython.
- Storage: PostgreSQL 16 for persisted missions/logs/findings/approvals/notes, Redis service present but not deeply used in inspected code.
- Frontend: React 18, TypeScript, Vite, React Router, nginx static hosting/proxy.
- Live updates: WebSocket endpoint at `/ws/{mission_id}`.
- Reports: HTML report files in `/app/reports`, exposed through `/api/missions/{id}/report`.

Security tooling installed by `backend/Dockerfile`:

- `nmap`
- `whois`
- `dig`/`dnsutils`
- `subfinder`
- `nuclei`
- ProjectDiscovery `httpx`
- `ffuf`
- `katana`
- `dalfox`
- `sqlmap`
- SecLists
- `wfuzz`
- `arjun`
- `ParamSpider`

Tooling currently referenced in code:

- `katana` crawl in `OffensiveEngine.crawl`.
- `paramspider` in `OffensiveEngine.paramspider_parameter_mining`.
- `arjun` in `OffensiveEngine.arjun_parameter_discovery`.
- `x8` support exists in `OffensiveEngine.x8_parameter_discovery`, but current `backend/Dockerfile` does not install `x8`.
- `sqlmap` in `OffensiveEngine.test_sqli`.
- `dalfox` in `OffensiveEngine.test_xss`.
- `nuclei` in `Ares._nuclei_scan` and `OffensiveEngine.nuclei_dast`.
- `nmap` in `Ares._nmap_scan`.
- `ffuf` in content discovery.

Authentication model:

- Optional API key, checked in `backend/core/security.py`.
- REST `/api` routes require `X-API-Key` only if `YGGDRASIL_API_KEY` or legacy `OLYMPUS_API_KEY` is set.
- WebSocket accepts `?api_key=` because browsers cannot set custom WS headers.
- Current frontend API client in `frontend/src/api.ts` does not send `X-API-Key`; if API auth is enabled, Claude must add a frontend key configuration flow or deployment-time injection.
- No user accounts, sessions, roles, RBAC, or multi-user auth.

Data flow:

1. User creates mission through `MissionLaunch`.
2. Frontend calls `POST /api/missions`.
3. `backend/routers/missions.py` validates target and creates `Mission`.
4. Background task runs `Zeus.execute`.
5. Zeus/Odin runs Frigg, Heimdall, approval gates, Tyr, Brokkr, Skuld, Saga based on mode.
6. Agents log via `BaseAgent.log`, create findings via `BaseAgent.add_finding`, and persist context into `Mission.context`.
7. WebSocket broadcasts logs, findings, status, approvals, target additions, notes, and heartbeats.
8. Frontend `MissionControl` renders live state and polls every 3 seconds during active runs.
9. Saga writes HTML report; exports are generated on demand from database findings.

## 4. Current Feature Inventory

### Mission orchestration

- Relevant files: `backend/agents/zeus.py`, `backend/routers/missions.py`, `backend/core/models.py`, `frontend/src/components/MissionControl.tsx`.
- What it does: Runs staged workflows for passive, active, and full missions.
- Maturity: Partial/complete for single-node local use.
- Dependencies: SQLAlchemy session, in-process background tasks, WebSocket manager.
- Pentest usefulness: High; gives clear assessment lifecycle.
- Risks/limitations: Background tasks are in-process and cannot survive backend restart. Startup recovery marks orphaned missions failed.

### Approval gates

- Relevant files: `backend/agents/base.py`, `backend/agents/zeus.py`, `backend/routers/missions.py`, `frontend/src/components/ApprovalGate.tsx`.
- What it does: Requires explicit operator authorization before active stages. Approval waits indefinitely. Stale gates are detected after restart.
- Maturity: Good for local/single-user use.
- Dependencies: In-memory `asyncio.Event` gate map plus database `ApprovalRequest`.
- Pentest usefulness: High; reduces accidental active testing.
- Risks/limitations: Approval state is not durable because the waiting task lives only in process memory.

### Mission health heartbeat

- Relevant files: `backend/core/mission_health.py`, `backend/agents/zeus.py`, `backend/routers/missions.py`, `frontend/src/components/MissionControl.tsx`.
- What it does: Records and broadcasts one-minute heartbeat with phase elapsed time and hold-up message.
- Maturity: Useful/partial.
- Dependencies: Background task and mission context JSON.
- Pentest usefulness: Medium/high; helps distinguish long scans from stuck jobs.
- Risks/limitations: Heartbeat stops if process restarts; no worker queue state.

### Scope parsing and enforcement

- Relevant files: `backend/routers/scope.py`, `backend/agents/athena.py`, `backend/core/web_security.py`, `backend/agents/hermes.py`, `backend/agents/ares.py`, `frontend/src/components/MissionLaunch.tsx`.
- What it does: Parses pasted/uploaded scope formats, supports in/out rules, extracts declared paths and vulnerability hints, enforces host/path scope before active testing.
- Maturity: Good but should be reviewed against Olympus parser.
- Dependencies: CSV/JSON/plain text parser, local validation helpers.
- Pentest usefulness: High; bug bounty work is scope-driven.
- Risks/limitations: Parser is heuristic. It can misclassify unusual programs; keep validation tests.

### Reconnaissance

- Relevant files: `backend/agents/hermes.py`.
- What it does: RDAP/WHOIS, crt.sh CT lookup, DNS A/MX/TXT/NS/SOA, DMARC/SPF checks, subdomain categorization, sensitive subdomain flags, liveness checks, tech fingerprinting, vendor extraction from TXT.
- Maturity: Partial/good.
- Dependencies: `whois`, `dig`, httpx, crt.sh, DNS.
- Pentest usefulness: Medium/high for organizing attack surface.
- Risks/limitations: CT source can fail; fingerprinting is lightweight; no robust asset graph.

### Active service scanning

- Relevant files: `backend/agents/ares.py`.
- What it does: Nmap service detection, Nuclei templates, directory enumeration, service-specific dangerous port checks.
- Maturity: Partial/good.
- Dependencies: `nmap`, `nuclei`, `ffuf`, SecLists.
- Pentest usefulness: High if scoped and rate-limited.
- Risks/limitations: `RerunModal` exposes `nmap_flags` and `nuclei_severity`, but inspected `Ares` code does not appear to consume those options. Avoid promising unsupported UI options.

### Web spidering and URL harvesting

- Relevant files: `backend/agents/offensive.py`.
- What it does: Uses katana, then a custom HTTP spider that extracts `href`, `src`, `action`, JS route strings, and form-derived parameterized candidates.
- Maturity: Useful/partial.
- Dependencies: `katana`, `httpx`.
- Pentest usefulness: High.
- Risks/limitations: No browser-based crawl with JS execution; no authenticated crawl state; no request/response archive.

### Parameter discovery

- Relevant files: `backend/agents/offensive.py`, `backend/tests/test_web_security.py`.
- What it does: ParamSpider/archive mining, route-aware generated parameter URLs, Arjun external discovery, optional x8 support, native differential hidden-parameter probing.
- Maturity: Strong conceptually; implementation should be regression-tested after Docker rebuild.
- Dependencies: ParamSpider, Arjun, optional x8, httpx.
- Pentest usefulness: High for bug bounty.
- Risks/limitations: `x8` is called if present but not installed by current `backend/Dockerfile`; generated parameters can create noise if not prioritized.

### SQL injection testing

- Relevant files: `backend/agents/offensive.py`.
- What it does: Runs `sqlmap` on up to 25 parameterized URLs with conservative batch flags.
- Maturity: Partial.
- Dependencies: `sqlmap`.
- Pentest usefulness: High for lab and authorized targets.
- Risks/limitations: No request capture, cookies, auth profiles, POST body replay, or safe impact boundary beyond flags and approval.

### XSS testing

- Relevant files: `backend/agents/offensive.py`.
- What it does: Runs `dalfox` on up to 40 parameterized URLs, then falls back to basic reflection detection.
- Maturity: Partial.
- Dependencies: `dalfox`, httpx.
- Pentest usefulness: Medium/high.
- Risks/limitations: Reflection fallback is candidate-only. No browser execution confirmation, CSP context review, screenshot evidence, or DOM workflow crawl.

### Nuclei DAST

- Relevant files: `backend/agents/offensive.py`.
- What it does: Runs Nuclei DAST injection templates against parameterized URLs.
- Maturity: Partial.
- Dependencies: `nuclei`.
- Pentest usefulness: Medium/high.
- Risks/limitations: Template coverage depends on local templates; no explicit template update workflow.

### Path traversal/LFI checks

- Relevant files: `backend/agents/offensive.py`, `backend/core/web_security.py`, `backend/tests/test_web_security.py`.
- What it does: Builds probes only for path-like parameters; safe canary payloads by default; lab mode adds `/etc/passwd`/Windows payloads; compares baseline/probe responses.
- Maturity: Good deterministic primitive.
- Dependencies: httpx.
- Pentest usefulness: High.
- Risks/limitations: Needs richer evidence capture and route/POST/body support.

### IDOR/BOLA checks

- Relevant files: `backend/agents/offensive.py`, `backend/core/web_security.py`, `backend/tests/test_web_security.py`.
- What it does: Builds neighbor-ID probes from query/path IDs; supports heuristic unauthenticated checks and cross-role analysis if multiple auth profiles exist in options.
- Maturity: Partial.
- Dependencies: httpx.
- Pentest usefulness: High.
- Risks/limitations: No UI/API for defining auth profiles; current run often uses heuristic checks only.

### Auth/exposure checks

- Relevant files: `backend/agents/offensive.py`.
- What it does: Checks public sensitive endpoints, weak/default exposure classes, declared dependency hints, and some auth/access-control surfaces.
- Maturity: Partial.
- Dependencies: httpx and static path lists.
- Pentest usefulness: Medium.
- Risks/limitations: Can produce generic findings; should avoid overclaiming without confirmation.

### Content discovery

- Relevant files: `backend/agents/offensive.py`, `backend/core/web_security.py`, `backend/Dockerfile`.
- What it does: Uses SecLists and generated words, `ffuf` when available, Python fallback, plus high-value exposure paths.
- Maturity: Good local feature.
- Dependencies: `ffuf`, SecLists, httpx.
- Pentest usefulness: High.
- Risks/limitations: Timeout/noise controls need tuning per program.

### Declared vulnerability hint checks

- Relevant files: `backend/agents/athena.py`, `backend/agents/offensive.py`.
- What it does: Reads pasted scope/path/vulnerability tables and adds low-severity manual candidates for declared vulnerable paths/classes.
- Maturity: Useful for PortSwigger-style labs and target-specific notes.
- Dependencies: Scope notes parsing.
- Pentest usefulness: Medium/high for organizing lab or program-provided hints.
- Risks/limitations: Must remain candidate-only; do not mark as confirmed vulnerability.

### Payload forge

- Relevant files: `backend/agents/hephaestus.py`.
- What it does: Builds target-aware wordlist, generic web payloads, template payloads, and candidate-target lists from Tyr findings.
- Maturity: Partial.
- Dependencies: Findings/context from Heimdall/Tyr.
- Pentest usefulness: Medium.
- Risks/limitations: Deterministic, not AI-powered. Should not become uncontrolled exploitation. Confirmed vs candidate target handling should remain conservative.

### Impact review

- Relevant files: `backend/agents/hades.py`.
- What it does: Maps lateral movement, persistence vectors, credential exposure, privilege escalation, and high-level blast radius.
- Maturity: Mostly heuristic/stub.
- Dependencies: Port results, vendors, vulnerabilities, Brokkr exploitable targets.
- Pentest usefulness: Low/medium unless tied to confirmed evidence.
- Risks/limitations: Can read like speculative post-exploit analysis. Keep labels conservative.

### Reporting

- Relevant files: `backend/agents/apollo.py`, `backend/routers/missions.py`, `frontend/src/components/MissionControl.tsx`.
- What it does: Generates HTML report, AI or default executive summary, finding stats, active scan coverage, discovered content paths, findings detail, live hosts. Exposes CSV/JSON exports.
- Maturity: Good for basic reporting.
- Dependencies: reports volume, optional AI key.
- Pentest usefulness: High.
- Risks/limitations: Report is not a full PoC package; lacks request/response artifacts, screenshots, repro steps, affected endpoint tables.

### Findings workflow

- Relevant files: `backend/core/models.py`, `backend/routers/missions.py`, `frontend/src/components/FindingsPanel.tsx`.
- What it does: Manual findings, edit/delete, severity/CVSS/remediation/evidence, tags (`confirmed`, `false_positive`, `reported`, `fixed`), analyst notes.
- Maturity: Useful/partial.
- Dependencies: Postgres.
- Pentest usefulness: High.
- Risks/limitations: Evidence is a text blob; no structured artifacts or timeline.

### Notes workflow

- Relevant files: `backend/core/models.py`, `backend/routers/missions.py`, `frontend/src/components/NotesPanel.tsx`.
- What it does: Mission-level analyst notes.
- Maturity: Basic/complete.
- Dependencies: Postgres.
- Pentest usefulness: Medium/high.
- Risks/limitations: No tags, links to endpoints/findings, attachments, or markdown rendering.

### Targets workflow

- Relevant files: `backend/routers/missions.py`, `frontend/src/components/TargetsPanel.tsx`.
- What it does: Shows live/active targets, lets analyst add targets, optionally rerun Tyr.
- Maturity: Useful/partial.
- Dependencies: Mission context JSON.
- Pentest usefulness: High.
- Risks/limitations: Targets are stored inside mission context JSON, not first-class rows.

### Agent rerun

- Relevant files: `backend/routers/missions.py`, `frontend/src/components/GodStatus.tsx`, `frontend/src/components/RerunModal.tsx`.
- What it does: Allows rerunning selected agents on same or overridden targets.
- Maturity: Partial.
- Dependencies: In-process background tasks.
- Pentest usefulness: Medium/high for iterative testing.
- Risks/limitations: Re-run status forces mission complete after agent finishes; options UI may not be fully honored by backend.

### Relaunch

- Relevant files: `backend/routers/missions.py`, `frontend/src/components/MissionList.tsx`.
- What it does: Creates a new mission row from an old mission's target/mode/scope/scope_rules.
- Maturity: Good.
- Dependencies: Mission table.
- Pentest usefulness: Medium/high.
- Risks/limitations: Does not copy notes/findings/auth profiles/artifacts.

## 5. PoC / Bug Bounty Feature Review

Request/response capture:

- Exists in Yggdrasil: no.
- Current substitute: finding evidence text and logs.
- Relevant files: `backend/core/models.py`, `backend/routers/missions.py`.
- Needed: first-class `HttpExchange` or `EvidenceArtifact` model with method, URL, headers, body, response status, response headers/body snippet, timestamps, redaction state, and link to finding/endpoint.

Replay functionality:

- Exists in Yggdrasil: no.
- Current substitute: rerun agents and scanner modules.
- Needed: safe request replay with editable request, auth/session binding, diff viewer, and evidence capture.

Payload management:

- Exists in Yggdrasil: partial.
- Relevant files: `backend/agents/hephaestus.py`, `backend/agents/offensive.py`.
- Current state: deterministic payload lists and generated target wordlists.
- Needed: user-editable payload library, payload runs tied to requests/findings, and provenance.

Screenshot storage:

- Exists in Yggdrasil: no.
- Needed: artifact upload/capture model and report embedding.

Notes:

- Exists in Yggdrasil: yes, mission-level.
- Relevant files: `backend/core/models.py`, `backend/routers/missions.py`, `frontend/src/components/NotesPanel.tsx`.
- Missing: notes linked to target, endpoint, request, or finding.

Vulnerability templates:

- Exists in Yggdrasil: partial.
- Current state: scanner-generated findings and manual add form.
- Missing: reusable templates for common bug bounty classes with fields for impact, repro, remediation, evidence, CWE/CVSS.

Markdown/report export:

- Exists in Yggdrasil: partial.
- Current state: HTML, CSV, JSON.
- Missing: Markdown export, platform-specific report templates, copy-ready PoC blocks.

Severity scoring:

- Exists in Yggdrasil: partial.
- Current state: severity and CVSS fields; static CVSS defaults in Saga.
- Missing: CVSS calculator, CWE mapping, evidence-based confidence.

Reproduction steps:

- Exists in Yggdrasil: no structured model.
- Current substitute: text evidence in finding.
- Needed: ordered repro steps with request references, screenshots, expected/actual result.

Evidence timeline:

- Exists in Yggdrasil: partial.
- Current state: logs and finding timestamps.
- Missing: timeline combining requests, notes, screenshots, payload runs, findings.

Affected endpoints:

- Exists in Yggdrasil: partial.
- Current state: URLs in context and evidence strings.
- Missing: first-class endpoint inventory with params, methods, auth requirements, sources, last tested.

Parameter tracking:

- Exists in Yggdrasil: partial/good in scanner context.
- Relevant files: `backend/agents/offensive.py`.
- Missing: persistent parameter inventory visible/editable in UI.

Auth/session context:

- Exists in Yggdrasil: no UI, partial backend option support for `auth_profiles`.
- Relevant files: `backend/agents/offensive.py`.
- Needed: session profile manager with cookies/headers/tokens, role labels, validation checks, and safe storage/redaction.

Role-based testing:

- Exists in Yggdrasil: partial backend concept only.
- Relevant files: `backend/core/web_security.py`, `backend/agents/offensive.py`.
- Needed: UI/API to define two or more roles and compare responses per endpoint/object.

API testing helpers:

- Exists in Yggdrasil: partial.
- Current state: OpenAPI/GraphQL high-value discovery paths, Nuclei DAST, URL/parameter tests.
- Missing: OpenAPI import, endpoint collection, body parameter fuzzing, JSON/XML/POST support, auth profile binding.

GraphQL helpers:

- Exists in Yggdrasil: minimal discovery only.
- Relevant files: `backend/core/web_security.py`.
- Missing: introspection test, query/mutation inventory, depth/complexity checks, auth comparison.

JWT helpers:

- Exists in Yggdrasil: minimal/unclear.
- Current state: auth/access-control checks mention JWT-style weaknesses but no dedicated JWT workbench was found.
- Needed: decode, claim diff, alg none check in lab mode, expiration/role claim notes.

OAuth helpers:

- Exists in Yggdrasil: no.
- Needed only if Olympus lacks a practical auth workflow module; prioritize request capture/session profiles first.

File upload testing helpers:

- Exists in Yggdrasil: no.
- Needed: upload endpoint tracking, safe test payload set, content-type/extension matrix, evidence capture.

Access control comparison helpers:

- Exists in Yggdrasil: partial backend.
- Relevant files: `backend/core/web_security.py`, `backend/agents/offensive.py`.
- Missing: UI-driven role comparison and request replay.

Business logic workflow mapping:

- Exists in Yggdrasil: no.
- Needed: user-defined workflow steps, expected state transitions, replay/diff, and notes per step.

## 6. Missing or Partial Features

Highest-value missing pieces for Olympus/Yggdrasil convergence:

- First-class HTTP request/response evidence model.
- Request replay and diff UI.
- Screenshot/artifact storage.
- Endpoint inventory with parameter/method/source tracking.
- Auth/session profile manager.
- Cross-role access-control comparison UI.
- Structured PoC builder with repro steps.
- Markdown/platform report export.
- API/OpenAPI import and JSON/POST body fuzzing.
- GraphQL helper module.
- File upload testing helper.
- Business logic workflow map.
- Redaction/sensitive-data controls for evidence.
- Persistent worker/queue model for long scans and approvals.
- `.gitignore` hygiene before pushing to GitHub.

Partial features that should be merged carefully:

- `backend/agents/offensive.py` parameter generation and mining.
- `backend/routers/scope.py` parser.
- `backend/core/web_security.py` scope/probe primitives.
- `backend/core/mission_health.py` heartbeat.
- `frontend/src/components/FindingsPanel.tsx` finding tags/analyst notes.
- `frontend/src/components/TargetsPanel.tsx` add/rerun targets.
- `backend/agents/apollo.py` active coverage reporting.

## 7. Compare Checklist for Claude Code

- [ ] Mission orchestration
  - Exists in Yggdrasil: yes
  - Relevant files: `backend/agents/zeus.py`, `backend/routers/missions.py`
  - Why it matters: keeps scans staged and auditable.
  - Suggested action for Claude: merge if Olympus has weaker stage control; ignore if Olympus already has durable orchestration.

- [ ] Indefinite approval gates
  - Exists in Yggdrasil: yes
  - Relevant files: `backend/agents/base.py`, `backend/routers/missions.py`, `frontend/src/components/ApprovalGate.tsx`
  - Why it matters: prevents unintended active traffic.
  - Suggested action for Claude: add/merge if Olympus auto-denies or auto-continues.

- [ ] Stale approval recovery
  - Exists in Yggdrasil: yes
  - Relevant files: `backend/main.py`, `backend/routers/missions.py`
  - Why it matters: avoids stuck UI after backend restart.
  - Suggested action for Claude: merge if Olympus lacks clear stale gate failure.

- [ ] Mission heartbeat
  - Exists in Yggdrasil: yes
  - Relevant files: `backend/core/mission_health.py`, `frontend/src/components/MissionControl.tsx`
  - Why it matters: shows long scans are alive.
  - Suggested action for Claude: merge if Olympus lacks live health signal.

- [ ] Scope parser
  - Exists in Yggdrasil: yes
  - Relevant files: `backend/routers/scope.py`, `frontend/src/components/MissionLaunch.tsx`
  - Why it matters: bug bounty scope quality prevents unsafe scans.
  - Suggested action for Claude: merge strongest parser tests and format support.

- [ ] Declared path/vulnerability hint extraction
  - Exists in Yggdrasil: yes
  - Relevant files: `backend/agents/athena.py`, `backend/agents/offensive.py`
  - Why it matters: turns pasted lab/program tables into test seeds and manual candidates.
  - Suggested action for Claude: add if Olympus lacks it; keep candidate-only.

- [ ] Route-aware parameter URL generation
  - Exists in Yggdrasil: yes
  - Relevant files: `backend/agents/offensive.py`, `backend/tests/test_web_security.py`
  - Why it matters: feeds tools with `/catalog?searchTerm=...`-style candidates even when crawler misses params.
  - Suggested action for Claude: merge if Olympus has weaker parameter discovery.

- [ ] ParamSpider/archive mining
  - Exists in Yggdrasil: yes
  - Relevant files: `backend/agents/offensive.py`, `backend/Dockerfile`
  - Why it matters: finds historical parameters.
  - Suggested action for Claude: add if missing; keep fallback behavior.

- [ ] Arjun integration
  - Exists in Yggdrasil: partial/yes in code
  - Relevant files: `backend/agents/offensive.py`, `backend/Dockerfile`
  - Why it matters: real parameter discovery suite.
  - Suggested action for Claude: merge after verifying CLI output parsing and Docker install.

- [ ] x8 integration
  - Exists in Yggdrasil: partial
  - Relevant files: `backend/agents/offensive.py`
  - Why it matters: strong hidden parameter discovery.
  - Suggested action for Claude: add Docker install only if Olympus wants the dependency; otherwise keep optional fallback.

- [ ] Native hidden parameter probing
  - Exists in Yggdrasil: yes
  - Relevant files: `backend/agents/offensive.py`
  - Why it matters: Param Miner-like behavior without Burp extension.
  - Suggested action for Claude: merge if Olympus lacks differential parameter probing.

- [ ] HTML/form spider
  - Exists in Yggdrasil: yes
  - Relevant files: `backend/agents/offensive.py`
  - Why it matters: collects routes and form-derived params.
  - Suggested action for Claude: merge if Olympus crawler is only katana/passive.

- [ ] Browser-based crawl
  - Exists in Yggdrasil: no
  - Relevant files: none
  - Why it matters: JS-heavy apps need browser execution.
  - Suggested action for Claude: add only if Olympus has Playwright/browser infra; otherwise backlog.

- [ ] SQLi testing
  - Exists in Yggdrasil: yes
  - Relevant files: `backend/agents/offensive.py`
  - Why it matters: common bounty class.
  - Suggested action for Claude: merge if Olympus lacks sqlmap orchestration, but add auth/request support later.

- [ ] XSS testing
  - Exists in Yggdrasil: yes
  - Relevant files: `backend/agents/offensive.py`
  - Why it matters: common bounty class.
  - Suggested action for Claude: merge if Olympus lacks Dalfox/reflection fallback; avoid overclaiming reflection as confirmed XSS.

- [ ] Traversal/LFI checks
  - Exists in Yggdrasil: yes
  - Relevant files: `backend/core/web_security.py`, `backend/agents/offensive.py`
  - Why it matters: safe canary mode plus lab mode.
  - Suggested action for Claude: merge deterministic primitives and tests.

- [ ] IDOR/BOLA heuristic checks
  - Exists in Yggdrasil: partial
  - Relevant files: `backend/core/web_security.py`, `backend/agents/offensive.py`
  - Why it matters: high-value bug bounty class.
  - Suggested action for Claude: merge backend probes, then add auth-profile UI.

- [ ] Cross-role IDOR confirmation
  - Exists in Yggdrasil: partial backend only
  - Relevant files: `backend/agents/offensive.py`, `backend/core/web_security.py`
  - Why it matters: real access-control proof needs two roles.
  - Suggested action for Claude: add session/role manager before relying on it.

- [ ] Content discovery
  - Exists in Yggdrasil: yes
  - Relevant files: `backend/agents/offensive.py`, `backend/core/web_security.py`
  - Why it matters: endpoint discovery.
  - Suggested action for Claude: merge if Olympus lacks SecLists/generated word support.

- [ ] Sensitive endpoint checks
  - Exists in Yggdrasil: yes
  - Relevant files: `backend/core/web_security.py`, `backend/agents/offensive.py`
  - Why it matters: quick wins like `.env`, `.git`, metrics, swagger.
  - Suggested action for Claude: merge, but tune severity and confirmation.

- [ ] Finding CRUD/tags
  - Exists in Yggdrasil: yes
  - Relevant files: `backend/core/models.py`, `backend/routers/missions.py`, `frontend/src/components/FindingsPanel.tsx`
  - Why it matters: analyst triage.
  - Suggested action for Claude: merge if Olympus lacks tags/manual findings.

- [ ] Analyst notes
  - Exists in Yggdrasil: yes
  - Relevant files: `backend/core/models.py`, `backend/routers/missions.py`, `frontend/src/components/NotesPanel.tsx`
  - Why it matters: records hypotheses and manual observations.
  - Suggested action for Claude: merge, then link notes to findings/endpoints later.

- [ ] Request/response evidence model
  - Exists in Yggdrasil: no
  - Relevant files: none
  - Why it matters: critical for PoC reproducibility.
  - Suggested action for Claude: add if Olympus lacks it. This is a top priority.

- [ ] Replay/diff workbench
  - Exists in Yggdrasil: no
  - Relevant files: none
  - Why it matters: proves impact and access-control bugs.
  - Suggested action for Claude: add after request/response model.

- [ ] Screenshot/artifact storage
  - Exists in Yggdrasil: no
  - Relevant files: none
  - Why it matters: better reports and proof.
  - Suggested action for Claude: add if Olympus lacks artifacts.

- [ ] Report coverage counters
  - Exists in Yggdrasil: yes
  - Relevant files: `backend/agents/apollo.py`
  - Why it matters: explains quiet scans.
  - Suggested action for Claude: merge if Olympus reports lack active coverage detail.

- [ ] Relaunch mission
  - Exists in Yggdrasil: yes
  - Relevant files: `backend/routers/missions.py`, `frontend/src/components/MissionList.tsx`
  - Why it matters: repeated tests without retyping scope.
  - Suggested action for Claude: merge if missing.

- [ ] Agent rerun
  - Exists in Yggdrasil: partial
  - Relevant files: `backend/routers/missions.py`, `frontend/src/components/RerunModal.tsx`
  - Why it matters: iterative testing.
  - Suggested action for Claude: merge only after verifying option support.

- [ ] Optional API key auth
  - Exists in Yggdrasil: backend yes, frontend partial/no
  - Relevant files: `backend/core/security.py`, `frontend/src/api.ts`, `frontend/src/hooks/useWebSocket.ts`
  - Why it matters: safer local deployment.
  - Suggested action for Claude: merge backend guard, add frontend key support if enabled.

## 8. Recommended Integrations

Priority 1: PoC evidence core

- Add `EvidenceArtifact` and `HttpExchange` models.
- Link artifacts to mission, finding, endpoint, and note.
- Store method, URL, request headers/body, response status/headers/body snippet, timing, tool/source, redaction metadata.
- Add UI panels for captured requests and finding-linked evidence.

Priority 2: Replay and diff

- Build a safe request replay API using stored `HttpExchange`.
- Let analyst edit params/body/headers and attach result to a finding.
- Add side-by-side response diff and status/length/header delta.
- Add redaction before saving/exporting.

Priority 3: Auth/session profiles

- Add session profiles with role labels, headers/cookies/tokens, validation URL, and redacted display.
- Wire profiles into Tyr access-control checks.
- Add cross-role replay matrix for IDOR/BOLA.

Priority 4: Endpoint and parameter inventory

- Persist discovered endpoints, methods, params, source (`katana`, `spider`, `ParamSpider`, `Arjun`, generated, manual), first/last seen, and last test result.
- UI should let tester promote endpoint to PoC, rerun selected modules, or attach notes.

Priority 5: Report/PoC builder

- Add structured repro steps linked to requests/screenshots.
- Add Markdown export and copy-ready bug bounty report blocks.
- Keep HTML report, but make PoC evidence richer.

Priority 6: API testing

- Add OpenAPI import.
- Add JSON/body parameter fuzzing.
- Add GraphQL introspection/query helper if Olympus lacks it.

Priority 7: Keep Yggdrasil scanner improvements

- Merge route-aware parameter generation, ParamSpider/archive mining, Arjun, native hidden-param probing, safe traversal probes, IDOR primitives, and active coverage report counters.
- Avoid adding every external param tool unless it adds distinct value.

## 9. Files Claude Should Inspect First

Backend first pass:

1. `backend/agents/offensive.py` - largest feature delta; inspect before changing scanner logic.
2. `backend/core/web_security.py` - deterministic helpers and tests.
3. `backend/agents/zeus.py` - flow/gates/heartbeat orchestration.
4. `backend/agents/base.py` - logging, findings, command runner, approval implementation.
5. `backend/routers/missions.py` - API surface and background task behavior.
6. `backend/routers/scope.py` - scope parser.
7. `backend/core/models.py` - current storage limits.
8. `backend/agents/apollo.py` - report layout and active coverage.
9. `backend/agents/hephaestus.py` - payload forge; avoid overclaiming.
10. `backend/Dockerfile` - installed tools and missing optional `x8`.

Frontend first pass:

1. `frontend/src/api.ts` - API methods and missing API-key injection.
2. `frontend/src/types.ts` - current frontend data model.
3. `frontend/src/components/MissionControl.tsx` - live workspace layout.
4. `frontend/src/components/FindingsPanel.tsx` - manual findings/tags/analyst notes.
5. `frontend/src/components/MissionLaunch.tsx` - scope import and mission launch.
6. `frontend/src/components/TargetsPanel.tsx` - target selection/rerun.
7. `frontend/src/components/ApprovalGate.tsx` - approval UX.
8. `frontend/src/hooks/useWebSocket.ts` - live event handling.

Tests:

1. `backend/tests/test_web_security.py` - scope/probe/parameter generation.
2. `backend/tests/test_approval_flow.py` - scope extraction and approval waiter.

## 10. Architecture Risks

- Background task model is in-process. Long missions, approval waits, and reruns are lost on backend restart.
- Approval gates are durable in database only as records; the continuation event is in memory.
- Mission context JSON is doing too much. It stores nested agent outputs, live hosts, coverage, health, and more. This makes querying and migration hard.
- Targets/endpoints/parameters are not first-class relational records.
- Findings evidence is a text blob, not an artifact graph.
- Frontend polls every 3 seconds while also using WebSockets; this is acceptable locally but may not scale.
- Redis is provisioned but not clearly used for queues or pub/sub in inspected code.
- Agent rerun UI exposes options that backend may not honor.
- `x8` code support exists, but `backend/Dockerfile` currently does not install `x8`.
- `frontend/node_modules`, `frontend/dist`, and `backend/__pycache__` exist locally. Add `.gitignore` before publishing.
- No migrations are used despite Alembic dependency; schema is created with `Base.metadata.create_all`.

## 11. Security Risks

- `.env` exists in project root. Do not commit it.
- API key auth is disabled if no key is configured. Safe for localhost, risky if exposed.
- Frontend does not send `X-API-Key`; enabling API auth will break REST calls unless Claude adds key support.
- WebSocket API key uses query parameter, which can leak in logs. Acceptable for local use but not ideal for shared deployments.
- Backend container has `NET_ADMIN` and `NET_RAW`. Needed for some scans, but raises blast radius.
- Command execution uses subprocess with argument lists, which is better than shell strings, but scanner target validation must remain strict.
- Active scanners can produce traffic that violates bounty rules if scope parser or user input is wrong; keep explicit approval gates and scope enforcement.
- Reports and exports may include sensitive evidence and should support redaction before sharing.
- AI summaries could overstate risk if not grounded in confirmed findings. Keep fallback conservative.
- Deterministic payload forge should not escalate into uncontrolled exploitation.

## 12. Suggested Implementation Order

1. Inspect Olympus for equivalent mission orchestration, approvals, scope parsing, findings, and scanner modules.
2. Add `.gitignore` and remove generated/local folders from Git tracking before publishing.
3. Preserve or merge the stronger approval gate and stale-recovery behavior.
4. Merge scope parser improvements and tests.
5. Merge `core/web_security.py` deterministic scope/probe helpers and tests.
6. Merge Tyr parameter discovery improvements if Olympus lacks them:
   - ParamSpider/archive mining
   - route-aware generated parameter URLs
   - Arjun discovery
   - optional x8 support
   - native differential hidden-param probing
7. Merge active coverage counters into reports.
8. Merge findings tags/manual findings/analyst notes if Olympus lacks them.
9. Add first-class request/response evidence storage.
10. Add endpoint/parameter inventory UI.
11. Add replay/diff workbench.
12. Add auth/session profiles and cross-role access-control checks.
13. Add structured PoC builder and Markdown/platform export.
14. Add screenshots/artifact support.
15. Add OpenAPI/GraphQL/API helpers after evidence/replay foundations exist.

## 13. Final Instructions for Claude Code

Claude Code should:

1. First inspect Olympus for each feature in the checklist.
2. If Olympus already has a better version, ignore Yggdrasil's version.
3. If Yggdrasil has a better or missing feature, integrate it.
4. If both exist, merge the strongest parts.
5. Skip features that do not help pentesters or bug bounty hunters produce better PoCs.
6. Preserve existing Olympus conventions unless Yggdrasil's implementation is clearly better.
7. Keep scanner behavior authorized, scoped, and non-destructive by default.
8. Keep candidate findings distinct from confirmed vulnerabilities.
9. Make small, reviewable commits.
10. Add or update tests for scope parsing, parameter generation, traversal, IDOR, approvals, and exports.
11. Add `.gitignore` before pushing:
    - `.env`
    - `frontend/node_modules/`
    - `frontend/dist/`
    - `backend/**/__pycache__/`
    - `*.pyc`
    - local reports/database artifacts
12. Do not commit secrets, reports with real target evidence, or local scan output.
13. After implementation, summarize every change with file paths and validation commands.

