# OLYMPUS: Wordlists + ORACLE

Two additions: a curated-plus-generated wordlist system, and ORACLE, a PortSwigger lab-solving advisor.

## 1. Wordlist system

**Curated bundle.** The Docker image no longer clones the full 1GB+ SecLists. It fetches a verified ~660KB subset into `/opt/wordlists` (raft-medium dirs/files, common, api-endpoints, DNS top-20k, LFI, usernames) and ships built-in SQLi, XSS, and password lists in `backend/seed_wordlists/`. First build is now seconds, not minutes.

**Generated per-target lists.** HEPHAESTUS builds a content-discovery wordlist deterministically from HERMES recon (subdomain labels, vendor names, tech stack, discovered paths). No AI, no network: pure permutation, reproducible. ARES also generates one at the start of its offensive phase and feeds it to `ffuf` ahead of the curated lists.

**Selection.** Pick curated lists at mission launch (chips under the mode selector). Selection is stored in `scope_rules.wordlist_ids` and consumed by ARES content discovery. Per-mission catalog, generate button, preview, and download live in the **WORDLISTS** tab of Mission Control.

### API
```
GET  /api/wordlists                      # catalog (curated + generated), counts, sizes
GET  /api/wordlists/{id}/preview?lines=50
GET  /api/wordlists/{id}/download
POST /api/wordlists/generate/{mission_id}   # build target list from stored recon
```

## 2. ORACLE (PortSwigger companion)

An advisor, not an automator. Paste a lab title + description (and optionally a request captured from Burp); ORACLE returns the vulnerability class, exact exploit steps, ready-to-copy payloads, and the raw HTTP request to fire from Repeater. Follow-up box refines the plan when an attempt fails. You send every request yourself, which keeps it inside PortSwigger's intended use and reliable against their anti-automation.

Reach it from the **ORACLE** link in the header (`/oracle`).

### API
```
GET  /api/oracle/status      # provider / model / configured
POST /api/oracle/solve       # {lab_title, description, lab_url?, category?, captured_request?}
POST /api/oracle/followup    # {lab_title, description, prior, what_happened, captured_response?}
```

ORACLE uses the same `ai_client` as ATHENA. Configure in `.env`:
```
AI_PROVIDER=anthropic
AI_API_KEY=sk-ant-...
AI_MODEL=claude-sonnet-4-5
```
A stronger model gives noticeably better exploit chains for expert labs. Switching providers is a `.env` change only.

## Deploy
```
git pull
docker compose up --build -d
```
First build pulls tool binaries (nmap, nuclei, ffuf, katana, dalfox, sqlmap) and the curated wordlists, so it takes a couple of minutes. Subsequent builds are cached.
