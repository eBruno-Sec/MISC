# ⚔ ROUND TABLE

**Recon &amp; test-guidance platform for authorized web-app testing.**
Give it a target. It maps the attack surface and hands you a per-endpoint
**test playbook** — *what* to test, *where*, *how*, which *payloads*, a
*confidence* score, the right *tool*, and *step-by-step cURL*. Then **you** run
the tests.

> Round Table is **advisory only**. It performs reconnaissance and enumeration
> and tells you exactly how to test each surface. It does **not** exploit
> anything — exploitation is the human's job (pentester / bug-bounty hunter /
> red teamer). Test only within a scope you are authorized to assess.

```
git clone https://github.com/eBruno-Sec/MISC.git
cd MISC/round-table
./roundtable.sh            #  → http://localhost:3000
```

That single command builds one container (recon tools baked in), starts it, and
opens the dashboard. No host installs, no database to configure, no AI key
required.

---

## What you get

| | |
|---|---|
| 🧭 **Missions** | Launch a target in Passive / Active / Full mode; watch a live WebSocket feed. |
| 🗺️ **2D topology** | Force-directed map of domain → hosts → ports → endpoints, colored by test severity. |
| 📋 **Test playbooks** | Per surface: what to test, how, payloads, confidence, tools, step-by-step cURL, and WSTG / PortSwigger references. |
| 🧪 **Advanced cURL console** | Compose &amp; send scope-guarded requests for manual verification; copy-paste `curl` for anything. |
| 🖥️ **Headless DAST** *(opt-in)* | Renders candidate URLs in real Chromium to **confirm** DOM XSS and client-side template injection (CSTI) — the things curl can't see. |
| 🔑 **Authenticated scans** *(opt-in)* | Paste a session cookie / bearer / headers; the whole scan (httpx · ffuf · nuclei · detectors · DAST) runs logged-in to reach post-login surface. |
| 📄 **Reports** | One-click HTML, plus Markdown / CSV / JSON export (session secrets redacted). |
| 🤖 **AI (optional)** | Add an OpenRouter key for an executive summary + attack chains. Everything works without it. |

The guidance engine is **100% rule-based** — knowledge distilled from OWASP WSTG,
the PortSwigger Web Security Academy, and PayloadsAllTheThings. AI is a bonus,
never a dependency.

---

## The pipeline (Knights of the Round Table)

```
Percival   passive recon      DNS/DoH, crt.sh CT, RDAP WHOIS, HTTP headers, TLS, email, vendors
Galahad    active enum        subfinder · httpx · nmap · ffuf · nuclei · CORS/VCS · takeover
Guidance   test playbooks     maps every signal → what/how/payload/confidence/tool/cURL
Topology   2D graph           attack-surface map colored by severity
Excalibur  reporting          HTML · Markdown · CSV · JSON
Merlin     AI (optional)      executive summary + attack chains via OpenRouter/Anthropic
```

**Modes**

| Mode | Runs | Sends packets to target? |
|---|---|---|
| **Passive** | Percival + guidance | No — public data sources only |
| **Active** | + Galahad enumeration | Yes — enumeration/discovery (no exploitation) |
| **Full** | Active + all checks | Yes |

---

## Setup

### Requirements
Docker + Docker Compose. That's it. (Recon tools — subfinder, httpx, nuclei,
ffuf, nmap — plus a headless Chromium for the opt-in DAST phase are built into
the image. The Chromium layer makes the first build larger/slower; it's only
exercised when a mission ticks **Headless DAST**.)

### Run it

```bash
./roundtable.sh            # build + start, open http://localhost:3000
./roundtable.sh --logs     # follow logs
./roundtable.sh --stop     # stop
./roundtable.sh --rebuild  # rebuild from scratch
```

Prefer raw Docker?

```bash
cp .env.example .env       # optional — defaults work as-is
docker compose up --build -d
```

### Optional AI

Round Table needs no AI. To add an executive-summary narrative, copy
`.env.example` to `.env` and set a key:

```env
AI_PROVIDER=openrouter
AI_API_KEY=sk-or-v1-...
AI_MODEL=nvidia/nemotron-3-ultra-550b-a55b:free
AI_BASE_URL=https://openrouter.ai/api/v1
```

Get a free OpenRouter key at <https://openrouter.ai/keys>. Anthropic direct is
also supported (`AI_PROVIDER=anthropic`, `AI_MODEL=claude-sonnet-4-6`).

---

## Using it

1. **Launch** — enter a domain, pick a mode, optionally paste a scope
   (one entry per line; prefix `!` for out-of-scope). Hit **Launch Mission**.
2. **Watch** the live feed on the Overview tab as Percival/Galahad work.
3. **Playbooks** — filter by severity or search; expand any card for the full
   how-to, payloads (copy buttons), and step-by-step cURL. Hit
   *Open in cURL console →* to jump straight to testing.
4. **Topology** — explore the surface map; click an endpoint node to jump to its
   playbook.
5. **cURL console** — craft requests (headers, body, options), send them
   scope-guarded, and read the response. Copy the exact `curl` for your notes.
6. **Report** — open the HTML report or export Markdown / CSV / JSON.

Reports and mission history persist in the `rt_data` Docker volume.

---

## Scope &amp; safety

- The cURL console only sends requests to hosts within the mission scope (or,
  standalone, the host you typed). It will refuse out-of-scope targets.
- Active/Full modes send enumeration traffic. Only launch them against targets
  you are **authorized** to test.
- Round Table never sends exploit payloads on its own. Recommended payloads are
  presented as text for **you** to use deliberately.

---

## CLI (still here)

The original one-shot CLI remains for terminal workflows:

```bash
python3 merlin.py -t target.com            # full pipeline
python3 merlin.py -t target.com --passive  # passive only
```

See [`caveman_readme.md`](caveman_readme.md) for the plain-language version.

---

## Architecture

```
round-table/
  roundtable.sh          one-command control
  docker-compose.yml     single service, SQLite volume, nmap caps
  .env.example           optional AI + scan tuning
  merlin.py              CLI orchestrator (unchanged)
  knights/               Percival/Galahad recon (reused by the web engine)
  server/
    Dockerfile           multi-stage: Go tools → python slim + nmap
    main.py              FastAPI app (serves API + WS + SPA)
    core/                db · hub · ai_client · scope · curl · guidance · report
    engine/              passive · active · pipeline (streams events)
    routers/             missions · curl · websocket
    web/                 vanilla-JS SPA (dashboard, topology, cURL console)
```

One process serves the JSON API, the WebSocket feed, and the SPA on port 8000
(published as `:3000`). Storage is SQLite in a mounted volume — nothing else to
run.

---

Built by Erwin Bruno · github.com/eBruno-Sec · recon &amp; advisory only.
