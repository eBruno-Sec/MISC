# OLYMPUS

**Autonomous AI Security Platform**

OLYMPUS is a self-hosted, Docker-native security assessment platform built around seven AI agents named after Greek gods. Give it a target domain and an assessment mode, and the gods run in sequence, each passing intelligence to the next, until APOLLO generates a full dark-themed HTML report. Every active phase requires your explicit approval through a real-time web UI.

> **Authorized testing only.** Unauthorized scanning may violate the CFAA, ECPA, and equivalent laws in your jurisdiction. By using OLYMPUS you confirm you have written authorization to test the specified target.

---

## The Seven Gods

| God | Symbol | Role | Tools |
|---|---|---|---|
| ZEUS | ⚡ | Orchestrator and state machine | Coordinates all agents, manages HITL gates |
| ATHENA | 🦉 | AI strategy and intent parsing | Claude API, threat modeling |
| HERMES | ☿ | OSINT and passive recon | crt.sh, RDAP/WHOIS, DNS, httpx, vendor fingerprinting |
| ARES | ⚔ | Active scanning and vuln assessment | Nmap, Nuclei, ffuf |
| HEPHAESTUS | 🔥 | Payload forge and exploit prep | Custom wordlists, vuln-class payloads |
| HADES | 💀 | Post-exploitation analysis | Lateral movement mapping, persistence vectors, blast radius scoring |
| APOLLO | ☀ | Reporting | Claude API, styled HTML report |

---

## Quick Start

```bash
git clone https://github.com/eBruno-Sec/MISC.git
cd MISC/olympus
./setup.sh
```

That is it. The script handles everything else.

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

> **Security note:** The default DB password and secret key are fine for local use. Change them before exposing OLYMPUS to any network.

---

## Usage

### Launching a Mission

1. Open `http://localhost:3000`
2. Click **+ NEW MISSION**
3. Enter a target domain (e.g. `example.com`)
4. Select an assessment mode:

| Mode | Sequence | HITL Gates |
|---|---|---|
| **Passive** | ATHENA → HERMES → APOLLO | None. Fully automated. |
| **Active** | ATHENA → HERMES → ARES → APOLLO | 1 gate before ARES activates |
| **Full** | ATHENA → HERMES → ARES → HEPHAESTUS → HADES → APOLLO | 3 gates |

5. Add optional scope notes (exclusions, focus areas)
6. Click **LAUNCH MISSION**

### Mission Control

Once launched, the Mission Control view shows:

- **God status bar** at the top: each god glows cyan when active and green when complete
- **Terminal feed** on the left: real-time log stream from every agent
- **Findings panel** on the right: live findings sorted by severity with CVSS scores, evidence, and remediation guidance

### Human-in-the-Loop (HITL) Gates

In Active and Full modes, OLYMPUS pauses before each offensive phase and shows an approval modal. You review the exact action being requested (which hosts, which tools, scope) and click **AUTHORIZE** or **DENY**. Denying routes directly to APOLLO for a report on what was gathered so far. Gates time out after 10 minutes and auto-deny to prevent zombie missions.

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
