# BBH Agent

AI-powered bug bounty hunting platform in a single Docker container. An LLM ReAct
loop drives a full recon-to-report pipeline against in-scope targets, with hard
scope enforcement at the tool-wrapper level, human-in-the-loop gates before
intrusive probing, a manual testing workbench, a rule-based test-playbook engine,
and persistent findings/evidence.

Built for Tier 1 HackerOne/Bugcrowd public programs with BBH-safe guardrails.

> This release folds the distinctive capabilities of three sibling projects —
> **Round Table** (rule-based test playbooks, scoped cURL console, topology,
> multi-format reports), **Olympus** (HITL gates, manual workbench, cross-role
> access-check, PoC evidence, scope-file parsing, advisory triage, persistence),
> and **Yggdrasil** (scope-aware traversal/IDOR probing, body-validated
> sensitive-path detection) — into the single-container BBH Agent.

---

## Install

### Option 1: One-command installer (recommended)

Handles Docker install, API key setup, image build, and startup. Works on macOS,
Kali, Ubuntu, Debian, Fedora, RHEL, and Arch.

```bash
git clone https://github.com/eBruno-Sec/MISC.git
cd MISC/bbh-agent
chmod +x install.sh
./install.sh
```

The script asks for your API key, saves it, builds the image, starts the
container, and opens `http://localhost:8000`.

### Option 2: Manual

```bash
git clone https://github.com/eBruno-Sec/MISC.git
cd MISC/bbh-agent
cp .env.example .env
# edit .env: pick a provider and paste your key
docker compose build    # 10-15 min first time (Go tool compilation)
docker compose up -d
```

Open `http://localhost:8000` in Chrome or Firefox.

### Update / Stop / Restart / Logs

```bash
./update.sh               # pull + rebuild clean + restart
docker compose down       # stop
docker compose up -d      # start
docker compose logs -f    # troubleshoot
```

---

## What you get

| | |
|---|---|
| 🤖 **Agentic hunt** | An LLM decides the tool order in a ReAct loop; every tool is scope-checked at the wrapper level. |
| 🎚️ **Assessment modes** | **Passive** (recon + playbook only), **Active** (+ scanning, one intrusive gate), **Full** (+ deep probing). |
| ⛔ **HITL approval gate** | Intrusive probing pauses for one operator authorization (or pre-authorize for an autonomous run). Waits indefinitely by default. |
| 📋 **Test playbooks** | A 100% rule-based engine (OWASP WSTG + PortSwigger + PayloadsAllTheThings) emits, per surface: what/how/payloads/confidence/tools/step-by-step cURL/WSTG refs. |
| 🧪 **Request workbench** | Repeater (replay), Intruder (single-param fuzz, anomaly-ranked), and response diff — all scope-guarded. |
| 🔑 **Cross-role access check** | Register roles (auth headers) and replay one request as each + anon to flag IDOR/BOLA/BFLA. Headers redacted on read. |
| 🗺️ **Topology** | 2D map of domain → hosts → endpoints from the discovered attack surface. |
| 🧭 **cURL console** | Send scope-guarded manual requests; get the exact `curl` back. |
| 📄 **PoC evidence** | Every scanned request/response is captured with sensitive headers redacted **at rest**, and rendered to copy-ready curl + raw HTTP + Markdown. |
| 🧠 **Advisory triage** | CWE/OWASP mapping, false-positive advisories, and attack-path chaining — advisory only, findings are never hidden. |
| 🌐 **DNS + takeover recon** | DNS-over-HTTPS intel (SPF/DMARC/CAA/vendors) and subdomain-takeover detection (dangling-CNAME provider fingerprints). |
| 🔐 **Authenticated scanning** | Paste session headers (Cookie/Authorization) or an auto-login (URL + creds); the session is shared with every scanner to reach the post-login surface. |
| 📦 **Persistence + archive** | Missions, findings, evidence, notes, and the event log persist in SQLite on a Docker volume. The **Archive** tab reloads any past mission; backup/restore a session as JSON. |
| 📊 **Reports** | HackerOne/Bugcrowd Markdown, a dark-themed standalone HTML report (every field escaped), plus CSV / JSON / PoC-Markdown export. |

---

## How It Works

```
Browser UI (port 8000)  — tabs: Feed · Findings · Surface · Playbooks ·
     |                            Workbench · Access · Topology · cURL · Report
FastAPI (main.py)  --  SSE stream  -->  Browser
     |
BBHAgent (agent.py)  --  ReAct loop, mode gate, HITL approval, phase tracking
     |
ToolRegistry (tools.py)  --  scope-checked wrappers + recon accumulator + evidence capture
     |
  subfinder crtsh wayback dns httpx nmap nuclei whatweb katana ffuf takeover
  http_probe fetch_openapi content_discovery web_probes injection_probes zap dalfox sqlmap
     |
Engines:  scope · security · surface · replay · web_security · guidance · triage ·
          poc · report · dns_recon · auth · zap_client   (deterministic, no AI required)
     |
SQLite (db.py, /app/data volume)  --  missions · findings · exchanges · logs · notes · profiles
```

---

## Tools

| Tool | Permission | What It Does |
|------|-----------|--------------|
| run_subfinder | PASSIVE | Subdomain enumeration via OSINT |
| run_crtsh | PASSIVE | Certificate-transparency lookup |
| run_wayback | PASSIVE | Historical URLs from the Wayback Machine (seeds surface) |
| run_dns | PASSIVE | DNS-over-HTTPS: A/NS/MX/TXT/CAA, SPF+DMARC policy, vendor fingerprints |
| generate_playbook | PASSIVE | Rule-based per-surface test playbook (advisory) |
| run_httpx | ACTIVE | Live host probing, status, title, tech |
| http_probe | ACTIVE | Fetch one URL, capture redacted evidence, read security headers, seed surface |
| run_whatweb | ACTIVE | Web tech fingerprinting |
| run_nmap | ACTIVE | Port scan + service/version detection |
| run_nuclei | ACTIVE | Template-based vuln scanner |
| fetch_openapi | ACTIVE | Import OpenAPI/Swagger endpoints (host-pinned, scope-safe) |
| run_katana | ACTIVE | Crawl for links/forms/JS endpoints (optional binary) |
| check_takeover | ACTIVE | Subdomain-takeover detection (CNAME + provider fingerprints) |
| run_ffuf | INTRUSIVE | Directory/endpoint fuzzing |
| run_content_discovery | INTRUSIVE | Body-validated content discovery (defeats catch-all SPA 200s) |
| run_web_probes | INTRUSIVE | Scope-aware traversal + IDOR probing with baseline comparison |
| run_injection_probes | INTRUSIVE | CORS / open-redirect / host-header / SSTI reflection probes |
| run_zap | INTRUSIVE | Full OWASP ZAP DAST (spider + AJAX spider + active scan), scope-fenced (optional daemon) |
| run_dalfox / run_sqlmap | INTRUSIVE | XSS / SQLi confirmation (optional binaries) |
| store_finding | PASSIVE | Save a confirmed finding + attach evidence |

**PASSIVE:** No direct target contact. Auto-run.
**ACTIVE:** Direct target contact. Auto-run within scope.
**INTRUSIVE:** High-impact. Requires one operator approval (unless pre-authorized) and is scope-verified at the wrapper.

---

## Scope Enforcement & Safety

Scope is enforced at the tool-wrapper level, not just in the prompt.

- Out-of-scope domains are checked first; a deny entry always overrides an allow.
- Wildcards (`*.example.com`) match all subdomains.
- Multi-target tools filter out-of-scope targets individually instead of blocking the whole call.
- The workbench, cURL console, and access-check refuse off-scope hosts with a 400.
- Target strings are validated against shell-metacharacter and argument-injection (`-flag`) abuse before ever reaching a subprocess.
- Sensitive headers (Cookie/Authorization/API tokens) are redacted at rest and on export.
- **Scope-file import:** paste or upload a HackerOne CSV, Bugcrowd CSV, Burp JSON, or section/prefix text; non-web assets (mobile app ids) are skipped.

---

## Assessment Modes & the Approval Gate

| Mode | Tools that run | Intrusive gate |
|------|----------------|----------------|
| **Passive** | passive only | n/a (active/intrusive disabled) |
| **Active** | passive + active auto; intrusive gated | one approval before the first intrusive tool |
| **Full** | passive + active auto; intrusive gated, deeper probing | one approval before the first intrusive tool |

When an intrusive tool is first requested, the UI shows an authorization modal.
Approve to authorize the intrusive phase for the whole engagement; deny to keep
the hunt to passive/active work. Tick **Autonomous** at launch to pre-authorize.
Set `BBH_APPROVAL_TIMEOUT` (seconds) to auto-deny after a timeout; `0` (default)
waits forever.

---

## API Reference (selected)

```
POST /engage                          Launch a mission (program, scope, mode, auto_approve)
GET  /stream/{id}                     SSE event stream (agent run)
POST /stop/{id}                       Stop a running hunt
POST /approve/{id}/{approval_id}      Resolve the HITL gate (?approved=true|false)
GET  /missions                        Mission archive
GET  /missions/{id}                   Mission detail (findings, logs, playbook, chains)
GET  /report/{id}[/html|/csv|/json|/poc]   Report in each format
GET  /surface/{id}                    Attack-surface inventory
GET  /playbook/{id}                   Rule-based test playbook
GET  /exchanges/{id}                  Captured request/response evidence (redacted)
POST /workbench/{id}/replay|fuzz|diff Repeater / Intruder / diff (scope-guarded)
POST /curl/{id}                       Scoped manual request, returns the curl
POST /profiles/{id} + /access-check/{id}   Cross-role IDOR/BOLA/BFLA check
POST /scope/parse                     Parse an uploaded/pasted scope file
GET  /wordlists  POST /wordlists/generate   Seed catalog + target-specific generation
GET  /backup/{id}  POST /restore      Session backup / import as a new mission
```

---

## Configuration (`.env`)

| Variable | Default | Purpose |
|---|---|---|
| `AI_PROVIDER` | `openrouter` | `openrouter` or `anthropic` |
| `OPENROUTER_API_KEY` | — | required when provider is openrouter |
| `OPENROUTER_MODEL` | `meta-llama/llama-3.3-70b-instruct:free` | any tool-calling OpenRouter model |
| `ANTHROPIC_API_KEY` | — | required when provider is anthropic |
| `ANTHROPIC_MODEL` | `claude-sonnet-4-6` | Anthropic model id |
| `BBH_APPROVAL_TIMEOUT` | `0` | seconds before an unanswered intrusive gate auto-denies (`0` = wait forever) |
| `BBH_DB_PATH` | `/app/data/bbh.db` | SQLite path (mounted volume) |

---

## OWASP ZAP DAST (optional)

`run_zap` drives a full OWASP ZAP scan (spider + AJAX spider for SPAs + active
scan) fenced to a ZAP **context** built from the mission scope, so ZAP is
physically constrained to in-scope hosts on top of the wrapper scope. It seeds
ZAP with the URLs BBH already discovered and imports ZAP alerts as findings.

ZAP is a separate optional container that does **not** start by default (the
single-container quickstart is unchanged). To enable it:

```bash
# in .env, set:  ZAP_ADDR=http://zap:8090
ZAP_ADDR=http://zap:8090 docker compose --profile zap up -d
```

With `ZAP_ADDR` unset, `run_zap` skips cleanly and the rest of the agent runs
normally. Because it is INTRUSIVE, a ZAP scan rides the same approval gate as
every other intrusive tool.

---

## Requirements

- Docker 24+ and Docker Compose v2
- An OpenRouter (free models available) or Anthropic API key
- Internet access from the container (OSINT sources, crt.sh, Wayback, nuclei templates)

---

## Notes

- First nuclei run downloads templates (~300MB) in the background on start. Wait 2-3 minutes before nuclei calls return results. Templates persist via the `nuclei_templates` volume.
- Missions, findings, and evidence persist in the `bbh_data` volume — they survive `docker compose down`. Export a report or `↓ Backup session` before deleting the volume.
- First build is 10-15 min (Go compilation of subfinder/httpx/nuclei/katana/ffuf/dalfox). Subsequent builds use cache.
- `nmap` needs `NET_RAW`/`NET_ADMIN` (set in `docker-compose.yml`). Do not remove them.
- Optional binaries (katana, dalfox, sqlmap) degrade gracefully: if a build could not fetch one, its tool reports "not installed" and the hunt continues. The binary-free `http_probe`, `run_wayback`, `run_content_discovery`, and `run_web_probes` cover most of the same ground.

---

## File Structure

```
bbh-agent/
├── docker-compose.yml     # single service + persistence volume
├── install.sh / update.sh
├── agent/
│   ├── Dockerfile         # Go tools -> Kali runtime
│   ├── requirements.txt
│   ├── main.py            # FastAPI server + SSE + all endpoints
│   ├── agent.py           # ReAct orchestrator, modes, HITL gate, phase + triage
│   ├── tools.py           # scope-checked wrappers + recon accumulator + evidence
│   ├── scope.py           # scope engine + multi-format scope-file parsing
│   ├── security.py        # target validation + CIDR + flag hardening
│   ├── surface.py         # attack-surface inventory + OpenAPI import
│   ├── replay.py          # workbench: replay/fuzz/diff/access-verdict
│   ├── web_security.py    # scope-aware traversal/IDOR + injection probes + path validation
│   ├── dns_recon.py       # DoH DNS/SPF/DMARC/CAA intel + takeover fingerprints
│   ├── auth.py            # heuristic form login for authenticated scanning
│   ├── zap_client.py      # OWASP ZAP daemon REST client + alert->finding mapping
│   ├── guidance.py        # rule-based test-playbook engine
│   ├── remediation.py     # developer-facing fix catalog
│   ├── wordlists.py       # seed catalog + target-specific generation
│   ├── triage.py          # advisory CWE/OWASP mapping + attack-path chaining
│   ├── poc.py             # curl / raw HTTP / Markdown PoC + header redaction
│   ├── report.py          # Markdown + dark HTML + CSV/JSON export
│   ├── db.py              # SQLite persistence
│   └── tests/             # deterministic pytest suite (34 tests)
└── ui/
    └── index.html         # multi-tab terminal-style SPA
```

Run the tests:

```bash
docker compose exec agent python3 -m pytest tests/ -q
```

---

## Authorized Use Only

For authorized security research only. Use exclusively against HackerOne/Bugcrowd
programs that explicitly include the target domains in scope. Never test assets
outside the defined scope.
