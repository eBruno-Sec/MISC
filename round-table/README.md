# ROUND TABLE // Bug Bounty Intelligence Suite

**One command. One target. Full recon to AI triage.**

```
python merlin.py -t target.com
```

Merlin orchestrates the full pipeline:

```
Percival  (Phase 1)  Passive recon      DNS, WHOIS, crt.sh, HTTP headers, SSL, tech stack
Galahad   (Phase 2)  Active enumeration subfinder, amass, httpx, nmap, ffuf, nuclei
Lancelot  (Phase 3)  AI triage          OpenRouter (Claude, GPT-4o, Llama, Gemini)
Excalibur (Phase 4)  Report engine      TXT + DOCX + JSON output
```

---

## Installation

### Kali Linux (recommended)

```bash
# Clone the repo
git clone https://github.com/eBruno-Sec/MISC.git
cd MISC/round-table

# Run Merlin -- it handles everything else automatically
python3 merlin.py --setup-only
```

Merlin will:
1. Run `apt update && apt upgrade -y && apt autoremove && autoclean`
2. Install all Python dependencies via pip
3. Install Go if missing
4. Install subfinder, amass, httpx, nuclei, ffuf, gobuster via `go install`
5. Install nmap, curl, git via apt
6. Download SecLists wordlist
7. Create `config.yaml` if missing

### Ubuntu / Debian / WSL

Same as Kali. WSL on Windows works identically:

```bash
# Open WSL terminal (Ubuntu)
git clone https://github.com/eBruno-Sec/MISC.git
cd MISC/round-table
python3 merlin.py --setup-only
```

### macOS

```bash
# Install Homebrew first if not installed
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

git clone https://github.com/eBruno-Sec/MISC.git
cd MISC/round-table
python3 merlin.py --setup-only
```

Merlin will use `brew` for system tools and `go install` for security tools.

### Windows (Native)

Native Windows has limited support for security tooling. WSL is strongly recommended.
If you must use native Windows:

```powershell
git clone https://github.com/eBruno-Sec/MISC.git
cd MISC\round-table
python merlin.py --setup-only
```

Merlin will install what it can via `winget` and flag tools that require WSL.

---

## AI Setup (OpenRouter)

OpenRouter gives you one API key that works with every major AI model.

### Step 1: Get a free key

Go to [https://openrouter.ai/keys](https://openrouter.ai/keys) and create an account.
Click **Create Key**. Copy the key (starts with `sk-or-v1-...`).

### Step 2: Add it to config.yaml

Open `config.yaml` in any text editor:

```bash
nano config.yaml
```

Find this line:

```yaml
api_key: "YOUR_KEY_HERE"
```

Replace `YOUR_KEY_HERE` with your actual key:

```yaml
api_key: "sk-or-v1-abc123yourkeyhere"
```

Save and close.

### Step 3: Choose your model

In `config.yaml`, set the model you want:

```yaml
model: "meta-llama/llama-3.3-70b-instruct:free"   # free, good quality
```

**Free models** (no cost, may use prompts for training):

| Model | Notes |
|---|---|
| `meta-llama/llama-3.3-70b-instruct:free` | Best free option. Strong reasoning. |
| `google/gemini-2.0-flash-exp:free` | Fast, large context window. |
| `mistralai/mistral-7b-instruct:free` | Lightweight fallback. |

**Paid models** (recommended for real targets -- keeps data private):

| Model | Notes |
|---|---|
| `anthropic/claude-sonnet-4-6` | Best triage quality. Extended thinking. |
| `openai/gpt-4o` | Strong reasoning and context. |
| `google/gemini-2.5-pro` | Large context, good code analysis. |

Typical cost per scan: $0.01 to $0.05 using paid models.

---

## Usage

### Full scan (passive + active + AI triage)

```bash
python3 merlin.py -t target.com
```

### Passive only (no active scanning -- safe for initial recon)

```bash
python3 merlin.py -t target.com --passive
```

### Override AI model per run

```bash
python3 merlin.py -t target.com --model openai/gpt-4o
python3 merlin.py -t target.com --model anthropic/claude-sonnet-4-6
python3 merlin.py -t target.com --model google/gemini-2.0-flash-exp:free
```

### Skip system update (faster subsequent runs)

```bash
python3 merlin.py -t target.com --skip-update
```

### Skip checkpoint (auto-proceed from passive to active)

```bash
python3 merlin.py -t target.com --no-checkpoint
```

### Bootstrap environment only (no scan)

```bash
python3 merlin.py --setup-only -t dummy.com
```

---

## Output

All results are saved to `output/<target>_<timestamp>/`:

```
output/
  target.com_20250702_143022/
    percival_raw.json          Full Phase 1 data
    galahad_raw.json           Full Phase 2 data
    subdomains.txt             All discovered subdomains (plain list)
    all_subdomains.txt         Merged subfinder + amass + crt.sh list
    live_hosts.txt             Live hosts (plain URLs)
    live_hosts.json            Live hosts with status, tech, titles
    subfinder_subs.txt         Raw subfinder output
    amass_subs.txt             Raw amass output
    nmap_scan.txt              Human-readable nmap output
    nmap_scan.xml              Machine-readable nmap XML
    nuclei_results.txt         Nuclei findings plain text
    nuclei_results.json        Nuclei findings JSON
    ffuf_<host>.json           Directory busting per host
    report_target.com.txt      Final TXT report
    report_target.com.docx     Final DOCX report (Word)
    report_target.com_raw.json Complete raw JSON dump of all phases
```

---

## config.yaml Reference

```yaml
ai:
  api_key: "sk-or-v1-YOUR-KEY"      # OpenRouter API key
  model: "meta-llama/llama-3.3-70b-instruct:free"  # model to use
  timeout: 60                         # seconds to wait for AI response

scan:
  threads: 10                         # concurrent threads for enumeration
  timeout: 8                          # HTTP request timeout in seconds
  passive_only: false                 # true = skip Galahad entirely
  checkpoint: true                    # pause before active scanning
  wordlist: "wordlists/common.txt"    # path to ffuf/gobuster wordlist
  nuclei_severity: "medium,high,critical"  # severity filter for nuclei
  ports: "80,443,8080,8443,8888,3000,5000,9090,9200,27017"  # nmap ports
```

---

## Scope Warning

Galahad sends active packets to the target. Only run within an authorized
bug bounty program scope. Merlin shows a checkpoint and asks for confirmation
before launching any active scanning.

Percival (passive mode) uses only public data sources:
Google DNS over HTTPS, crt.sh certificate transparency, RDAP WHOIS, HTTP HEAD requests.

---

## Knights

| Knight | Phase | Tools |
|---|---|---|
| Percival | Passive Recon | Google DoH, crt.sh, RDAP, HTTP |
| Galahad | Active Enumeration | subfinder, amass, httpx, nmap, ffuf, gobuster, nuclei |
| Lancelot | AI Triage | OpenRouter (any model) |
| Excalibur | Reporting | TXT, DOCX, JSON |

---

Built by Erwin Bruno -- github.com/eBruno-Sec
