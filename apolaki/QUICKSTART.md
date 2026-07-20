# Apolaki — Quick Start (Plain English)

Follow these steps in order. Do not skip any.

---

## Step 1: Get the code

Open a terminal and run:

```bash
git clone https://github.com/eBruno-Sec/MISC.git
cd MISC/bbh-agent
```

---

## Step 2: Run the installer

```bash
chmod +x install.sh
./install.sh
```

The installer will:
- Install Docker if you do not have it
- Ask for your Anthropic API key (get one at console.anthropic.com)
- Build everything automatically
- Open `http://localhost:8000` in your browser

First build takes 10-15 minutes. That is normal. It only happens once.

---

## Step 3: Use it

1. Type in the program name (e.g. `Shopify`)
2. Pick an **assessment mode**:
   - **Passive** — recon + a test playbook only, no target contact beyond OSINT
   - **Active** — adds scanning; intrusive probing asks for one approval
   - **Full** — adds deep probing (content discovery, traversal/IDOR)
3. Paste the in-scope domains (e.g. `*.shopify.com`), or click
   **Import scope file** to load a HackerOne/Bugcrowd/Burp export
4. (Optional) Tick **Autonomous** to pre-authorize the intrusive gate
5. Click **Start Hunt** and watch the **Feed** tab stream live
6. If the agent requests intrusive probing, an **authorization modal** appears —
   click Authorize or Deny
7. Explore the tabs while it runs:
   - **Findings** — confirmed vulns with severity, CWE, steps
   - **Surface** — discovered endpoints + parameters
   - **Playbooks** — per-surface what/how/payloads/cURL (rule-based)
   - **Workbench** — Repeater + Intruder (scope-guarded)
   - **Access** — register roles and run an IDOR/BOLA check
   - **Topology** — 2D map of the attack surface
   - **cURL** — send scoped manual requests
8. On the **Report** tab: open the HTML report, or export CSV / JSON / PoC
   Markdown. Click **Backup session** to save your progress as JSON.

---

## Update

```bash
cd MISC/bbh-agent
./update.sh
```

---

## Stop

```bash
docker compose down
```

## Start again

```bash
docker compose up -d
```

Then go to `http://localhost:8000`.

---

## Something broke

```bash
docker compose logs -f
```

Copy the output and bring it here.
