# BBH Agent

AI-powered bug bounty hunting assistant built on Claude claude-sonnet-4-6. Runs a full recon-to-report pipeline against in-scope targets using a ReAct loop with hard scope enforcement at the tool wrapper level.

Built specifically for Tier 1 HackerOne/Bugcrowd public programs with BBH-safe guardrails.

---

## Install

### Option 1: One-command installer (recommended)

Handles Docker install, API key setup, image build, and startup automatically. Works on macOS, Kali, Ubuntu, Debian, Fedora, RHEL, and Arch.

```bash
git clone https://github.com/eBruno-Sec/MISC.git
cd MISC/bbh-agent
chmod +x install.sh
./install.sh
```

The script will ask for your Anthropic API key (`sk-ant-...`), save it, build the image, start the container, and open `http://localhost:8000`.

### Option 2: Manual

**Step 1: Install Docker**

- macOS: https://docs.docker.com/desktop/install/mac-install/
- Kali/Ubuntu/Debian: `sudo apt-get install -y docker-ce docker-compose-plugin`
- Fedora: `sudo dnf install -y docker-ce docker-compose-plugin`

**Step 2: Clone and configure**

```bash
git clone https://github.com/eBruno-Sec/MISC.git
cd MISC/bbh-agent
cp .env.example .env
# Open .env and replace the placeholder with your Anthropic API key
```

**Step 3: Build and run**

```bash
docker compose build    # 10-15 min first time
docker compose up -d
```

**Step 4: Open**

Go to `http://localhost:8000` in Chrome or Firefox.

### Update

```bash
cd MISC/bbh-agent
./update.sh
```

Pulls latest code, rebuilds clean, restarts.

### Stop / Restart

```bash
docker compose down       # stop
docker compose up -d      # start again
```

### Troubleshoot

```bash
docker compose logs -f
```

Copy the last 20 lines if something breaks.

---

## Usage

1. Enter the program name (e.g. `Shopify Bug Bounty`)
2. Paste in-scope domains, one per line. Wildcards supported: `*.shopify.com`
3. Optionally paste out-of-scope domains
4. Optionally write a custom objective (e.g. "focus on API authorization and admin panels")
5. Click **Start Hunt**
6. Watch the live terminal stream. Events are color-coded by permission level
7. When complete, click **View Report** to get the full HackerOne/Bugcrowd-formatted markdown

---

## How It Works

```
Browser UI (port 8000)
     |
FastAPI (main.py)  --  SSE stream  -->  Browser
     |
BBHAgent (agent.py)  --  Claude claude-sonnet-4-6 ReAct loop
     |
ToolRegistry (tools.py)  --  scope-checked subprocess wrappers
     |
  subfinder  httpx  nmap  nuclei  ffuf  whatweb
     |
ScopeEngine (scope.py)  --  wildcard domain matching, deny-overrides-allow
```

---

## Tools

| Tool | Permission | What It Does |
|------|-----------|--------------|
| subfinder | PASSIVE | Subdomain enumeration via OSINT sources |
| crtsh | PASSIVE | Certificate transparency log lookup |
| httpx | ACTIVE | Live host probing, status codes, tech detection |
| whatweb | ACTIVE | Web tech fingerprinting |
| nmap | ACTIVE | Port scan and service/version detection |
| nuclei | ACTIVE/INTRUSIVE | Template-based vuln scanner |
| ffuf | INTRUSIVE | Directory and endpoint fuzzing |
| store_finding | PASSIVE | Saves confirmed finding to report |

**PASSIVE:** No direct contact with target. Auto-run.
**ACTIVE:** Direct target contact. Auto-run within scope.
**INTRUSIVE:** High-impact. Scope verified at the wrapper level before execution.

---

## Scope Enforcement

Scope is enforced at the tool wrapper level, not just at the prompt level.

- Out-of-scope domains are checked first. A deny entry always overrides an allow entry
- Wildcard patterns (`*.example.com`) match all subdomains and sub-subdomains
- Multi-target tools (httpx) filter out-of-scope targets individually instead of blocking the whole call
- Every scope block surfaces to the UI as a `[SCOPE]` event

---

## Requirements

- Docker 24+ and Docker Compose v2
- Anthropic API key (`sk-ant-...`) from console.anthropic.com
- Internet access from container (subfinder OSINT sources, crt.sh, nuclei template downloads)

---

## Notes

- First nuclei run downloads templates (~300MB) in the background on container start. Wait 2-3 minutes before nuclei calls return results
- Nuclei templates persist across restarts via a named Docker volume (`nuclei_templates`)
- Build time is 10-15 minutes on first run due to Go compilation. Subsequent builds use cache
- nmap requires `NET_RAW` and `NET_ADMIN` capabilities set in `docker-compose.yml`. Do not remove them
- Sessions are in-memory. Export your report before stopping the container

---

## File Structure

```
bbh-agent/
├── .env.example
├── docker-compose.yml
├── install.sh          # cross-platform auto-installer
├── update.sh           # pull + rebuild + restart
├── README.md
├── agent/
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── scope.py        # scope enforcement engine
│   ├── tools.py        # subprocess tool wrappers
│   ├── agent.py        # Claude ReAct orchestrator
│   ├── report.py       # HackerOne/Bugcrowd report generator
│   └── main.py         # FastAPI server + SSE streaming
└── ui/
    └── index.html      # terminal-style browser UI
```

---

## Authorized Use Only

For authorized security research only. Use exclusively against HackerOne/Bugcrowd programs that explicitly include the target domains in scope. Never test assets outside the defined scope.
