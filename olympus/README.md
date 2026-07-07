# OLYMPUS

**Autonomous AI Security Platform**

OLYMPUS is a self-hosted, Docker-native security assessment platform built around eight AI agents named after Greek gods. Give it a target domain and an assessment mode, and the gods run in sequence, each passing intelligence to the next, until APOLLO generates a full dark-themed HTML report. Every active phase requires your explicit approval through a real-time web UI.

> **Authorized testing only.** Unauthorized scanning may violate the CFAA, ECPA, and equivalent laws in your jurisdiction. By using OLYMPUS you confirm you have written authorization to test the specified target.

---

## The Eight Gods

| God | Symbol | Role | Tools |
|---|---|---|---|
| ZEUS | ⚡ | Orchestrator and state machine | Coordinates all agents, manages HITL gates |
| ATHENA | 🦉 | AI strategy and intent parsing | Claude API, threat modeling |
| HERMES | ☿ | OSINT and passive recon | subfinder (multi-source), crt.sh, DNS brute-force, httpx fingerprint (title/tech/CDN), subdomain-takeover detection, RDAP/WHOIS, DNS, vendor fingerprinting |
| ARES | ⚔ | Active scanning and vuln assessment | Nmap, Nuclei, ffuf, katana crawl, Wayback archive param discovery (ParamSpider/gau style), sqlmap, dalfox, OWASP ZAP, authenticated scanning (AI login) |
| HEPHAESTUS | 🔥 | Payload forge and exploit prep | Custom wordlists, vuln-class payloads |
| HADES | 💀 | Post-exploitation analysis | Lateral movement mapping, persistence vectors, blast radius scoring |
| METIS | ⚖ | AI triage and correlation | Cross-tool false-positive suppression, CWE/OWASP mapping, attack-path chaining (AI, optional) |
| APOLLO | ☀ | Reporting | Claude API, styled HTML report |

---

## Quick Start

```bash
# Recommended: clone olympus only
git clone --filter=blob:none --sparse https://github.com/eBruno-Sec/MISC.git
cd MISC && git sparse-checkout set olympus && cd olympus
./setup.sh
```

`setup.sh` handles Docker install, Compose install, `.env` creation, build, and browser open automatically.

> Full repo clone (includes 25+ other projects): `git clone https://github.com/eBruno-Sec/MISC.git && cd MISC/olympus`

---

## Prerequisites

| Requirement | Version | Notes |
|---|---|---|
| Docker | 24.0+ | Auto-installed by `setup.sh` if missing |
| Docker Compose | 2.20+ | Auto-installed as part of Docker CE (`docker-compose-plugin`) |
| Anthropic API key | Any | Optional. Enables ATHENA analysis and APOLLO AI summaries. Get one at [console.anthropic.com](https://console.anthropic.com) |

No Python, Node.js, or Go required on your host machine. Everything runs inside containers.

> **Kali Linux note:** `setup.sh` detects Kali and installs Docker CE from the Debian bookworm repo (Docker does not publish a `kali-rolling` release). No manual repo configuration needed.

---

## Installation

### Option A: One-Click (Recommended)

```bash
./setup.sh
```

The script does the following automatically:

1. Detects your OS
2. If Docker is missing, asks to install it (apt update + upgrade + Docker CE + Compose plugin in one shot)
3. If Docker Compose is missing, asks to install it separately
4. Checks ports 3000 and 8000 are available
5. Creates `.env` from `.env.example` if it does not exist
6. Prompts for your Anthropic API key (skip to disable AI features)
7. Runs `docker compose up --build -d`
8. Polls the backend health endpoint until it responds
9. Opens `http://localhost:3000` in your browser

**Other setup.sh flags:**

```bash
./setup.sh --rebuild   # Full clean rebuild (no cache)
./setup.sh --logs      # Stream all container logs
./setup.sh --stop      # Stop all containers
```

### Option B: Manual Docker

```bash
# 1. Copy and configure environment
cp .env.example .env
# Edit .env and add your ANTHROPIC_API_KEY

# 2. Build and start
docker compose up --build -d

# 3. Check status
docker compose ps

# 4. Open the UI
open http://localhost:3000
```

---

## Configuration

Edit `.env` before starting. All values have safe defaults for local use.

| Variable | Default | Required | Description |
|---|---|---|---|
| `ANTHROPIC_API_KEY` | *(empty)* | No | Enables ATHENA and APOLLO AI features. Without it, recon and scanning still work. |
| `DB_USER` | `olympus` | No | PostgreSQL username |
| `DB_PASSWORD` | `olympus_secret` | **Yes, change for production** | PostgreSQL password |
| `SECRET_KEY` | `change-me-in-production` | **Yes, change for production** | FastAPI session secret |
| `OLYMPUS_OFFENSIVE_MAX_HOSTS` | `5` | No | How many live hosts get the full spider + OWASP ZAP active scan per mission. Each host is a heavy active scan; raise only when you have time. |

> **Security note:** The default DB password and secret key are fine for local use. Change them before exposing OLYMPUS to any network.

---


## AI Configuration

OLYMPUS supports Anthropic directly or any OpenRouter model. Edit `.env` to switch.

### Adding your API key (step by step)

**1. Open the `.env` file:**

The file lives in the same directory as `docker-compose.yml`:

```bash
cd ~/Desktop/Olympus/MISC/olympus   # or wherever you cloned
nano .env
```

If `.env` does not exist yet (you skipped `setup.sh`):

```bash
cp .env.example .env
nano .env
```

**2. Find and replace the placeholder:**

```env
# Change this line:
AI_API_KEY=sk-ant-your-key-here

# To your actual key:
AI_API_KEY=sk-ant-api03-...
```

Save: `Ctrl+O` → `Enter` → `Ctrl+X`

**3. Apply the change:**

```bash
docker compose restart backend
```

Done. No rebuild needed, just a restart.

**Anthropic (default):**
```env
AI_PROVIDER=anthropic
AI_API_KEY=sk-ant-...
AI_MODEL=claude-sonnet-4-6
```

**OpenRouter** (access Claude, GPT-4o, Gemini, Llama, Mistral, and 200+ models with one key):
```env
AI_PROVIDER=openrouter
AI_API_KEY=sk-or-...
AI_MODEL=anthropic/claude-sonnet-4-6
```

Popular OpenRouter model strings: `anthropic/claude-opus-4`, `openai/gpt-4o`, `google/gemini-pro`, `meta-llama/llama-3.1-70b-instruct`

Full model list: https://openrouter.ai/models

**Self-hosted / proxy** (any OpenAI-compatible endpoint):
```env
AI_PROVIDER=openrouter
AI_API_KEY=your-key
AI_MODEL=your-model
AI_BASE_URL=http://localhost:11434/v1
```

AI is optional. If `AI_API_KEY` is blank, ATHENA and APOLLO AI summaries are skipped but all recon and scanning runs normally.

After editing `.env`, restart the backend:
```bash
docker compose restart backend
```

## Scope Upload

OLYMPUS accepts program scope files from bug bounty platforms directly in the mission launch form. In-scope and out-of-scope rules are enforced inside HERMES (subdomain filtering) and ARES (target filtering before scanning).

### How scope is resolved

There are three ways scope is set, in priority order:

1. **Structured scope file** (upload/paste in the launch form). Parsed deterministically and enforced as-is. Always authoritative.
2. **Free-text scope notes** (the notes box). When AI is enabled, ATHENA interprets the notes into in-scope / out-of-scope host rules. The model only *proposes*: every derived host is validated (hostname, wildcard, IPv4, or CIDR) and anything malformed is dropped, and derived rules can only narrow the target's own discovered subdomains, never add an unrelated target. Adopted only when no structured file was provided. Review the derived scope in the terminal feed, and (in Active/Full mode) at the approval gate before any scanning.
3. **No scope at all.** OLYMPUS spiders the target and every discovered live host, and runs the full OWASP/injection suite against each endpoint and URL found. Nothing is filtered.

> Without an AI key, free-text notes are **not** auto-enforced (there is no interpreter). Use a structured scope file when you need hard enforcement offline.

### Authenticated scanning

Put test credentials in the scope notes and OLYMPUS tests the authenticated surface. ATHENA extracts them, then ARES logs in and shares the session cookie with the crawler and every scanner (katana, sqlmap, dalfox, nuclei, ffuf, the httpx probes, and OWASP ZAP).

```
login creds: alice@example.com / hunter2, login at /account/login
```

The AI reads the login form (action, field names, CSRF token) and submits it; a deterministic parser is the fallback. If the login cannot be verified, the scan continues unauthenticated with a warning rather than guessing. Requires an AI key.

> Credentials placed in scope notes are stored in the mission record. Rotate test accounts after the engagement.

**Supported formats:**

| Platform | Format | Detection |
|---|---|---|
| HackerOne | CSV with `asset_identifier` and `eligible_for_bounty` columns | Auto |
| Bugcrowd | CSV with `target` and `category` columns | Auto |
| Burp Suite | JSON scope export (`target.scope.include/exclude`) | Auto |
| Plain text / TXT | One target per line, section headers, or `-` prefix to exclude | Auto |
| Generic CSV | Two columns: `scope_marker, target` | Auto |

Section headers are detected automatically:
```
# IN-SCOPE (Eligible)
*.example.com
example.com
# OUT-OF-SCOPE (Ineligible)
internal.example.com
```

Markdown links (`[label](https://domain.com)`) and mobile app identifiers (`com.package.name (Android)`, `123456789 (iOS)`) are parsed and classified correctly.

**Where to upload:** Mission launch form → SCOPE RULES section → click **UPLOAD CSV** (drag-and-drop) or **PASTE** to type/paste directly.

After parsing, a preview shows green in-scope and red out-of-scope targets. Review before launching.

**HackerOne export:** Program page → Scope → Export CSV → upload to OLYMPUS.

**Plain text example:**
```
example.com
*.example.com
- internal.example.com
- staging.example.com
```

Parsed scope is shown as a preview before launch so you can confirm what is in and out before the mission starts.

---

## Usage

### Launching a Mission

1. Open `http://localhost:3000`
2. Click **+ NEW MISSION**
3. Enter a target domain (e.g. `example.com`)
4. Select an assessment mode:

| Mode | Sequence | HITL Gates |
|---|---|---|
| **Passive** | ATHENA → HERMES → METIS → APOLLO | None. Fully automated. |
| **Active** | ATHENA → HERMES → ARES → METIS → APOLLO | 1 gate before ARES activates |
| **Full** | ATHENA → HERMES → ARES → HEPHAESTUS → HADES → METIS → APOLLO | 3 gates |

> METIS is the AI triage pass (false-positive suppression, CWE/OWASP mapping, attack-path chaining). It runs before APOLLO in every mode and is skipped automatically when no AI key is set.

5. Add optional scope notes (exclusions, focus areas)
6. Click **LAUNCH MISSION**

### Mission Control

Once launched, the Mission Control view shows:

- **God status bar** at the top: each god glows cyan when active and green when complete
- **Terminal feed** on the left: real-time log stream from every agent
- **Findings panel** on the right: live findings sorted by severity with CVSS scores, evidence, and remediation guidance

### Human-in-the-Loop (HITL) Gates

In Active and Full modes, OLYMPUS pauses before each offensive phase and shows an approval modal. You review the exact action being requested (which hosts, which tools, scope) and click **AUTHORIZE** or **DENY**. Denying routes directly to APOLLO for a report on what was gathered so far. By default a gate **waits indefinitely** — the mission stays paused until you click, however long that takes, even if you close the tab and come back later (reopen the mission and the gate is still there). To make gates auto-deny after a set time instead, set `OLYMPUS_APPROVAL_TIMEOUT` to a number of seconds.

> **Note:** A paused mission is held in the live backend process. If you restart or rebuild the backend container while a mission is waiting at a gate, that mission cannot resume (its approval stays pending but nothing is listening). Finish or deny open gates before running `docker compose up --build`.

### Viewing Reports

When APOLLO completes, a **VIEW REPORT** button appears in the mission header. Reports are also served directly:

```
http://localhost:8000/api/missions/{mission-id}/report
```

Reports are standalone dark-themed HTML files. They include the executive summary, finding statistics, vendor stack intelligence, full findings detail with evidence and remediation, and live host inventory.

---

## Architecture

```
olympus/
├── setup.sh                 One-click installer
├── docker-compose.yml       4-container stack
├── .env.example
├── backend/                 FastAPI + asyncpg + SQLAlchemy
│   ├── agents/              One Python file per god
│   │   ├── zeus.py          Orchestrator state machine
│   │   ├── athena.py        Claude API intent parsing
│   │   ├── hermes.py        OSINT and passive recon
│   │   ├── ares.py          Nmap, Nuclei, ffuf
│   │   ├── hephaestus.py    Payload forge and wordlist builder
│   │   ├── hades.py         Post-exploitation analysis
│   │   ├── metis.py         AI triage, correlation, attack-path chaining
│   │   └── apollo.py        Report generation
│   ├── core/                Config, database, models
│   └── routers/             REST endpoints and WebSocket
└── frontend/                React + TypeScript + Vite
    └── src/
        ├── components/      MissionControl, TerminalFeed, FindingsPanel,
        │                    GodStatus, ApprovalGate, MissionLaunch, MissionList
        └── hooks/           useWebSocket (auto-reconnect)
```

**Containers:**

| Container | Port | Role |
|---|---|---|
| `postgres` | 5432 (internal) | Mission, findings, and log storage |
| `redis` | 6379 (internal) | Reserved for future task queue |
| `backend` | 8000 | FastAPI, WebSocket, agent execution |
| `frontend` | 3000 | React UI served via nginx |

---

## Docker Reference

```bash
# View logs from a specific container
docker compose logs -f backend
docker compose logs -f frontend

# Restart a single container
docker compose restart backend

# Stop everything (preserves data volumes)
docker compose down

# Stop and delete all data
docker compose down -v

# Rebuild a single container
docker compose up --build -d backend

# Open a shell in the backend container
docker compose exec backend bash

# Access PostgreSQL directly
docker compose exec postgres psql -U olympus -d olympus

# View reports directory
docker compose exec backend ls /app/reports
```

---

## Security Tools Installed in the Backend Container

The backend Dockerfile downloads pre-built binaries at build time. If network access is restricted during build, tools that fail to install are skipped with a warning and OLYMPUS still runs (passive recon uses Python libraries, not these binaries).

| Tool | Purpose | Installed via |
|---|---|---|
| `nmap` | Port scanning and service detection | apt |
| `whois` | WHOIS lookups | apt |
| `nuclei` | Vulnerability template scanning | GitHub release |
| `httpx` | Live host detection | GitHub release |
| `ffuf` | Directory and path fuzzing | GitHub release |
| `subfinder` | Subdomain enumeration | GitHub release |

---

## API Reference

The backend exposes a REST API documented at `http://localhost:8000/api/docs`.

Key endpoints:

```
POST   /api/missions              Launch a new mission
GET    /api/missions              List all missions
GET    /api/missions/{id}         Get mission details (logs, findings, approvals)
POST   /api/missions/{id}/approvals/{approval_id}/resolve  Approve or deny a gate
GET    /api/missions/{id}/report  Download the HTML report
DELETE /api/missions/{id}         Delete a mission
GET    /ws/{mission_id}           WebSocket for real-time updates
GET    /api/health                Health check
```

---

## Troubleshooting

**Backend fails to start**

```bash
docker compose logs backend | tail -50
```

Check that `DATABASE_URL` in `.env` matches the postgres container credentials.

**Port already in use**

```bash
lsof -Pi :3000 -sTCP:LISTEN
lsof -Pi :8000 -sTCP:LISTEN
```

Kill the blocking process or change port mappings in `docker-compose.yml`.

**Security tool binary not found (nmap, nuclei, etc.)**

These tools are installed at Docker build time. If the build had no internet access, they silently skipped. Rebuild with network access:

```bash
docker compose build --no-cache backend
```

**ATHENA / APOLLO AI features not working**

Confirm your `ANTHROPIC_API_KEY` is set in `.env` and starts with `sk-ant-`. Restart the backend after editing `.env`:

```bash
docker compose restart backend
```

**WebSocket disconnects**

The frontend reconnects automatically with 3-second backoff. If the mission control terminal feed goes blank, refresh the page. The mission state is persisted in PostgreSQL and will reload.

**Docker install fails on Kali Linux with "kali-rolling Release" error**

A previous failed run left a broken Docker apt source. The current `setup.sh` cleans this automatically. If you have an older version:

```bash
sudo rm -f /etc/apt/sources.list.d/docker.list /etc/apt/keyrings/docker.asc
git pull
./setup.sh
```

**Frontend build fails with `npm ci` / missing lockfile error**

Pull the latest version. The Dockerfile now uses `npm install` instead of `npm ci`, which does not require a committed `package-lock.json`.

```bash
git pull
docker compose up --build -d
```

---

## Legal Disclaimer

OLYMPUS is a security research and authorized penetration testing tool. You are solely responsible for ensuring you have explicit written authorization from the system owner before running any assessment. The tool author assumes no liability for misuse.

---

## License

MIT License. See `LICENSE` for details.

---

*Built by eBruno-Sec*
