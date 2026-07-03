#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║              ROUND TABLE — Bug Bounty Intelligence Suite         ║
║                      MERLIN  //  Orchestrator                    ║
║                                                                  ║
║  Usage:  python merlin.py -t target.com                          ║
║          python merlin.py -t target.com --passive                ║
║          python merlin.py -t target.com --model openai/gpt-4o    ║
║          python merlin.py -t target.com --skip-update            ║
╚══════════════════════════════════════════════════════════════════╝
"""

import sys
import os
import subprocess
import shutil
import platform
import argparse
import json
import time
from pathlib import Path
from datetime import datetime

# ─── ANSI COLORS ───────────────────────────────────────────────────────────────
R  = "\033[91m"
Y  = "\033[93m"
G  = "\033[92m"
B  = "\033[94m"
C  = "\033[96m"
M  = "\033[95m"
W  = "\033[97m"
DIM= "\033[2m"
BOLD="\033[1m"
RST= "\033[0m"

BANNER = f"""
{R}{BOLD}
  ██████╗  ██████╗ ██╗   ██╗███╗   ██╗██████╗     ████████╗ █████╗ ██████╗ ██╗     ███████╗
  ██╔══██╗██╔═══██╗██║   ██║████╗  ██║██╔══██╗    ╚══██╔══╝██╔══██╗██╔══██╗██║     ██╔════╝
  ██████╔╝██║   ██║██║   ██║██╔██╗ ██║██║  ██║       ██║   ███████║██████╔╝██║     █████╗
  ██╔══██╗██║   ██║██║   ██║██║╚██╗██║██║  ██║       ██║   ██╔══██║██╔══██╗██║     ██╔══╝
  ██║  ██║╚██████╔╝╚██████╔╝██║ ╚████║██████╔╝       ██║   ██║  ██║██████╔╝███████╗███████╗
  ╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝╚═════╝        ╚═╝   ╚═╝  ╚═╝╚═════╝ ╚══════╝╚══════╝
{RST}
{DIM}  Knights of the Round Table  //  Bug Bounty Intelligence Suite{RST}
{DIM}  MERLIN orchestrates: Percival -> Galahad -> Lancelot -> Gawain -> Excalibur{RST}
"""

BASE_DIR   = Path(__file__).parent.resolve()
OUTPUT_DIR = BASE_DIR / "output"
WORDS_DIR  = BASE_DIR / "wordlists"
CONFIG_FILE= BASE_DIR / "config.yaml"

# ─── PLATFORM DETECTION ────────────────────────────────────────────────────────
def detect_os():
    s = platform.system().lower()
    if s == "darwin":
        return "mac"
    if s == "windows":
        return "windows"
    # Linux - check distro
    try:
        with open("/etc/os-release") as f:
            content = f.read().lower()
        if "kali" in content:
            return "kali"
        if "ubuntu" in content or "debian" in content:
            return "ubuntu"
        return "linux"
    except:
        return "linux"

OS_TYPE = detect_os()

def run(cmd, capture=False, check=False):
    if capture:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        return r.stdout.strip(), r.returncode
    return subprocess.run(cmd, shell=True, check=check).returncode

def ok(msg):  print(f"  {G}[+]{RST} {msg}")
def info(msg):print(f"  {C}[*]{RST} {msg}")
def warn(msg):print(f"  {Y}[!]{RST} {msg}")
def err(msg): print(f"  {R}[-]{RST} {msg}")
def hdr(msg): print(f"\n{B}{BOLD}{'─'*60}{RST}\n{B}{BOLD}  {msg}{RST}\n{B}{BOLD}{'─'*60}{RST}")

def has_sudo():
    return os.geteuid() == 0 if OS_TYPE != "windows" else False

def sudo_prefix():
    if OS_TYPE == "windows": return ""
    if os.geteuid() == 0: return ""
    return "sudo "

# ─── SYSTEM UPDATE ─────────────────────────────────────────────────────────────
def system_update(skip=False):
    hdr("STEP 0  //  SYSTEM UPDATE & CLEANUP")
    if skip:
        warn("Skipping system update (--skip-update flag set)")
        return

    if OS_TYPE in ("kali", "ubuntu", "linux"):
        info("Running apt update + upgrade + autoremove + autoclean ...")
        cmds = [
            f"{sudo_prefix()}apt-get update -qq",
            f"{sudo_prefix()}apt-get upgrade -y -qq",
            f"{sudo_prefix()}apt-get autoremove -y -qq",
            f"{sudo_prefix()}apt-get autoclean -qq",
        ]
        for cmd in cmds:
            rc = run(cmd)
            if rc != 0:
                warn(f"Command returned non-zero: {cmd}")
        ok("System packages updated and cleaned")

    elif OS_TYPE == "mac":
        if shutil.which("brew"):
            info("Running brew update + upgrade + cleanup ...")
            run("brew update")
            run("brew upgrade")
            run("brew cleanup")
            ok("Homebrew updated and cleaned")
        else:
            warn("Homebrew not found. Install from https://brew.sh first.")

    elif OS_TYPE == "windows":
        info("Running winget upgrade --all ...")
        run("winget upgrade --all --accept-source-agreements --accept-package-agreements")
        ok("Windows packages upgraded")

# ─── PYTHON DEPS ───────────────────────────────────────────────────────────────
PYTHON_DEPS = [
    "requests", "pyyaml", "rich", "dnspython",
    "python-docx", "colorama", "tqdm", "httpx",
]

def install_python_deps():
    hdr("STEP 1  //  PYTHON DEPENDENCIES")
    info(f"Installing Python packages: {', '.join(PYTHON_DEPS)}")
    pip = "pip3" if shutil.which("pip3") else "pip"
    rc = run(f"{pip} install --quiet --upgrade {' '.join(PYTHON_DEPS)}")
    if rc == 0:
        ok("All Python dependencies installed")
    else:
        warn("Some pip installs may have failed. Check manually if errors occur.")

# ─── BINARY TOOLS ──────────────────────────────────────────────────────────────
GO_TOOLS = {
    "subfinder":  "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    "httpx":      "github.com/projectdiscovery/httpx/cmd/httpx@latest",
    "nuclei":     "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
    "ffuf":       "github.com/ffuf/ffuf/v2@latest",
    "gobuster":   "github.com/OJ/gobuster/v3@latest",
    "amass":      "github.com/owasp-amass/amass/v4/...@master",
}

APT_TOOLS = {
    "nmap":       "nmap",
    "curl":       "curl",
    "git":        "git",
    "golang":     "golang-go",
}

BREW_TOOLS = {
    "nmap":       "nmap",
    "go":         "go",
    "git":        "git",
}

def ensure_go():
    if shutil.which("go"):
        ver, _ = run("go version", capture=True)
        ok(f"Go found: {ver}")
        return True

    info("Go not found. Installing...")
    if OS_TYPE in ("kali", "ubuntu", "linux"):
        run(f"{sudo_prefix()}apt-get install -y golang-go -qq")
    elif OS_TYPE == "mac":
        run("brew install go")
    elif OS_TYPE == "windows":
        run("winget install GoLang.Go --accept-package-agreements -h")

    if shutil.which("go"):
        ok("Go installed successfully")
        return True
    else:
        err("Go installation failed. Install manually from https://go.dev/dl/")
        return False

def install_binary_tools():
    hdr("STEP 2  //  SECURITY TOOL BOOTSTRAP")

    # APT tools first (non-Go)
    if OS_TYPE in ("kali", "ubuntu", "linux"):
        for tool, pkg in APT_TOOLS.items():
            if shutil.which(tool):
                ok(f"{tool} already installed")
            else:
                info(f"Installing {tool} via apt...")
                rc = run(f"{sudo_prefix()}apt-get install -y {pkg} -qq")
                if rc == 0:
                    ok(f"{tool} installed")
                else:
                    warn(f"Failed to install {tool} via apt")

    elif OS_TYPE == "mac":
        for tool, pkg in BREW_TOOLS.items():
            if shutil.which(tool):
                ok(f"{tool} already installed")
            else:
                info(f"Installing {tool} via brew...")
                run(f"brew install {pkg}")
                ok(f"{tool} installed")

    elif OS_TYPE == "windows":
        if not shutil.which("nmap"):
            info("Installing nmap via winget...")
            run("winget install Insecure.Nmap --accept-package-agreements -h")

    # Go-based tools
    if not ensure_go():
        warn("Skipping Go-based tools (Go not available)")
        return

    # Set GOPATH
    gopath, _ = run("go env GOPATH", capture=True)
    gobin = Path(gopath) / "bin"
    os.environ["PATH"] = str(gobin) + os.pathsep + os.environ.get("PATH","")

    for tool, pkg in GO_TOOLS.items():
        if shutil.which(tool):
            ok(f"{tool} already installed")
        else:
            info(f"Installing {tool} via go install...")
            rc = run(f"go install {pkg}")
            if rc == 0:
                ok(f"{tool} installed")
            else:
                warn(f"Failed to install {tool}. Try manually: go install {pkg}")

    # Update nuclei templates
    if shutil.which("nuclei"):
        info("Updating nuclei templates...")
        run("nuclei -update-templates -silent")
        ok("Nuclei templates updated")

# ─── DIRECTORIES & WORDLIST ────────────────────────────────────────────────────
WORDLIST_URL = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt"

def setup_dirs():
    hdr("STEP 3  //  DIRECTORIES & WORDLISTS")
    OUTPUT_DIR.mkdir(exist_ok=True)
    WORDS_DIR.mkdir(exist_ok=True)
    ok(f"Output dir: {OUTPUT_DIR}")

    wl = WORDS_DIR / "common.txt"
    if wl.exists():
        ok(f"Wordlist exists: {wl}")
    else:
        info("Downloading SecLists common.txt wordlist...")
        rc = run(f"curl -s -L \"{WORDLIST_URL}\" -o \"{wl}\"")
        if rc == 0 and wl.exists():
            ok(f"Wordlist downloaded: {wl}")
        else:
            warn("Wordlist download failed. Falling back to built-in minimal list.")
            wl.write_text("\n".join([
                "admin","login","api","dashboard","test","dev","staging",
                ".git","wp-admin","wp-login.php","phpinfo.php","config",
                "backup","uploads","static","assets","v1","v2","swagger",
                "graphql","robots.txt","sitemap.xml",".env",".htaccess",
            ]))
            ok("Minimal built-in wordlist created")

# ─── CONFIG ────────────────────────────────────────────────────────────────────
DEFAULT_CONFIG = """# ══════════════════════════════════════════════════════
# ROUND TABLE  //  config.yaml
# ══════════════════════════════════════════════════════
#
# SETUP:
#   1. Get a free OpenRouter key at https://openrouter.ai/keys
#   2. Paste it below replacing YOUR_KEY_HERE
#   3. Choose a model (free options marked with :free)
#   4. Run: python merlin.py -t target.com
#
# FREE MODELS (good for general use):
#   meta-llama/llama-3.3-70b-instruct:free   (recommended free)
#   google/gemini-2.0-flash-exp:free
#   mistralai/mistral-7b-instruct:free
#
# PAID MODELS (better triage quality, ~$0.01 per scan):
#   anthropic/claude-sonnet-4-6
#   openai/gpt-4o
#   google/gemini-2.5-pro
#
# NOTE: Free models may use prompts for training.
# For sensitive bug bounty targets, use a paid model.
# ══════════════════════════════════════════════════════

ai:
  api_key: "YOUR_KEY_HERE"
  model: "meta-llama/llama-3.3-70b-instruct:free"
  timeout: 60

scan:
  threads: 10
  timeout: 8
  passive_only: false
  checkpoint: true
  wordlist: "wordlists/common.txt"
  nuclei_severity: "medium,high,critical"
  ports: "80,443,8080,8443,8888,3000,5000,9090,9200,27017"
"""

def setup_config():
    if not CONFIG_FILE.exists():
        CONFIG_FILE.write_text(DEFAULT_CONFIG)
        warn(f"Config created at {CONFIG_FILE}")
        warn("Add your OpenRouter API key to config.yaml before scanning.")
        warn("Get a free key at: https://openrouter.ai/keys")
        return None

    import yaml
    with open(CONFIG_FILE) as f:
        cfg = yaml.safe_load(f)

    key = cfg.get("ai",{}).get("api_key","")
    if not key or key == "YOUR_KEY_HERE":
        err("No API key set in config.yaml")
        err("Edit config.yaml and set your OpenRouter key under ai.api_key")
        err("Get a free key at: https://openrouter.ai/keys")
        return None

    ok(f"Config loaded. Model: {cfg['ai']['model']}")
    return cfg

# ─── PRE-FLIGHT CHECK ──────────────────────────────────────────────────────────
def preflight(cfg, passive_only):
    hdr("PRE-FLIGHT CHECK")
    all_ok = True

    critical = ["nmap", "curl"]
    optional = list(GO_TOOLS.keys())

    for tool in critical:
        if shutil.which(tool):
            ok(f"{tool}")
        else:
            err(f"{tool} NOT FOUND (critical)")
            all_ok = False

    for tool in optional:
        if shutil.which(tool):
            ok(f"{tool}")
        else:
            if passive_only and tool in ("nmap","ffuf","gobuster","nuclei"):
                warn(f"{tool} not found (skipped in passive mode)")
            else:
                warn(f"{tool} not found (some checks will be skipped)")

    wl = BASE_DIR / cfg["scan"]["wordlist"]
    if wl.exists():
        ok(f"Wordlist: {wl}")
    else:
        warn(f"Wordlist not found: {wl}")

    if cfg["ai"]["api_key"] and cfg["ai"]["api_key"] != "YOUR_KEY_HERE":
        ok(f"AI API key set. Model: {cfg['ai']['model']}")
    else:
        warn("No AI key set. Lancelot triage will be skipped.")

    print()
    return all_ok

# ─── MAIN ORCHESTRATOR ─────────────────────────────────────────────────────────
def main():
    print(BANNER)

    parser = argparse.ArgumentParser(
        description="MERLIN  //  Round Table Bug Bounty Orchestrator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-t","--target",  required=True, help="Target domain (e.g. target.com)")
    parser.add_argument("--passive",      action="store_true", help="Phase 1 only (no active scanning)")
    parser.add_argument("--model",        default=None, help="Override AI model (e.g. openai/gpt-4o)")
    parser.add_argument("--skip-update",  action="store_true", help="Skip apt/brew system update")
    parser.add_argument("--no-checkpoint",action="store_true", help="Skip confirmation between phases")
    parser.add_argument("--no-playbook",  action="store_true", help="Skip Gawain manual hunting playbook")
    parser.add_argument("--setup-only",   action="store_true", help="Bootstrap environment only, no scan")
    args = parser.parse_args()

    target = args.target.replace("https://","").replace("http://","").replace("www.","").strip("/").lower()

    # ── Bootstrap ──
    system_update(skip=args.skip_update)
    install_python_deps()
    install_binary_tools()
    setup_dirs()

    # ── Config ──
    hdr("STEP 4  //  CONFIGURATION")
    cfg = setup_config()
    if cfg is None:
        sys.exit(1)

    if args.model:
        cfg["ai"]["model"] = args.model
        ok(f"Model overridden to: {args.model}")

    if args.setup_only:
        ok("Setup complete. Run merlin.py -t <target> to begin a scan.")
        sys.exit(0)

    # ── Pre-flight ──
    preflight(cfg, args.passive)

    # ── Import knights ──
    sys.path.insert(0, str(BASE_DIR / "knights"))
    from percival  import run_percival
    from galahad   import run_galahad
    from lancelot  import run_lancelot
    from gawain    import run_gawain
    from excalibur import run_excalibur

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    run_dir = OUTPUT_DIR / f"{target}_{timestamp}"
    run_dir.mkdir(parents=True, exist_ok=True)

    print(f"\n{G}{BOLD}TARGET   : {target}{RST}")
    print(f"{C}OUTPUT   : {run_dir}{RST}")
    print(f"{C}MODE     : {'PASSIVE ONLY' if args.passive else 'FULL (passive + active + AI triage)'}{RST}")
    print(f"{C}MODEL    : {cfg['ai']['model']}{RST}\n")

    results = {"target": target, "timestamp": timestamp, "run_dir": str(run_dir)}

    # ── PERCIVAL — Phase 1 ──
    hdr("PERCIVAL  //  PHASE 1 — PASSIVE RECON")
    t0 = time.time()
    p1 = run_percival(target, run_dir, cfg)
    results["percival"] = p1
    ok(f"Percival complete in {time.time()-t0:.1f}s")

    if args.passive:
        hdr("PASSIVE MODE  //  Skipping Galahad (active)")
        results["galahad"] = {}
    else:
        # ── Checkpoint ──
        if cfg["scan"]["checkpoint"] and not args.no_checkpoint:
            print(f"\n{Y}{BOLD}CHECKPOINT — Review Phase 1 results before active scanning.{RST}")
            print(f"{Y}Active scanning will send packets to: {target}{RST}")
            print(f"{Y}Ensure this target is in scope for your bug bounty program.{RST}\n")
            try:
                ans = input(f"  {BOLD}Proceed with active scanning? [y/N]: {RST}").strip().lower()
            except KeyboardInterrupt:
                print(f"\n{Y}Cancelled.{RST}")
                sys.exit(0)
            if ans != "y":
                print(f"{Y}Stopping after Phase 1.{RST}")
                run_excalibur(target, results, run_dir, cfg)
                sys.exit(0)

        # ── GALAHAD — Phase 2 ──
        hdr("GALAHAD  //  PHASE 2 — ACTIVE ENUMERATION")
        t1 = time.time()
        p2 = run_galahad(target, run_dir, cfg, p1)
        results["galahad"] = p2
        ok(f"Galahad complete in {time.time()-t1:.1f}s")

    # ── LANCELOT — Phase 3 ──
    hdr("LANCELOT  //  PHASE 3 — AI TRIAGE")
    t2 = time.time()
    p3 = run_lancelot(target, results, cfg)
    results["lancelot"] = p3
    ok(f"Lancelot complete in {time.time()-t2:.1f}s")

    # ── GAWAIN — Phase 3.5 (manual hunting playbook) ──
    if not args.no_playbook:
        hdr("GAWAIN  //  PHASE 3.5 — MANUAL HUNTING PLAYBOOK")
        t25 = time.time()
        p35 = run_gawain(target, results, cfg)
        results["gawain"] = p35
        ok(f"Gawain complete in {time.time()-t25:.1f}s")

    # ── EXCALIBUR — Phase 4 ──
    hdr("EXCALIBUR  //  PHASE 4 — REPORT GENERATION")
    t3 = time.time()
    run_excalibur(target, results, run_dir, cfg)
    ok(f"Excalibur complete in {time.time()-t3:.1f}s")

    print(f"\n{G}{BOLD}{'═'*60}{RST}")
    print(f"{G}{BOLD}  ROUND TABLE COMPLETE  //  {target}{RST}")
    print(f"{G}{BOLD}  Results: {run_dir}{RST}")
    print(f"{G}{BOLD}{'═'*60}{RST}\n")

if __name__ == "__main__":
    main()
