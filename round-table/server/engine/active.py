"""
Active enumeration (Galahad).

subfinder / httpx / nmap / ffuf / nuclei. These send packets to the target and
run only when the operator launches an Active or Full mission (an explicit,
per-mission choice). Round Table still never exploits — this maps the surface;
the human tests it.
"""
import os
from pathlib import Path

import galahad as GAL  # from knights/ (see engine.__init__ path setup)


def _wordlist() -> str:
    wl = os.getenv("ROUNDTABLE_WORDLIST", "/app/wordlists/common.txt")
    p = Path(wl)
    if p.exists():
        return str(p)
    # Repo fallback for non-container runs.
    local = Path(__file__).resolve().parents[2] / "wordlists" / "common.txt"
    return str(local)


def run_active(target: str, run_dir: Path, recon: dict, log, cfg: dict) -> dict:
    threads = int(cfg.get("threads", 10))
    timeout = int(cfg.get("timeout", 8))
    severity = cfg.get("nuclei_severity", "medium,high,critical")
    ports = cfg.get("ports", "80,443,8080,8443,8888,3000,5000,9090,9200,27017,6379,5432,3306,2375,5601")
    wordlist = _wordlist()

    tools = {t: GAL.has(t) for t in ("subfinder", "amass", "httpx", "nmap", "ffuf", "gobuster", "nuclei")}
    log(f"tool availability: {', '.join(t for t, ok in tools.items() if ok) or 'none'}", "info", "active")

    log("Subdomain enumeration (subfinder + amass)", phase="active")
    new_subs = GAL.phase_subdomain_enum(target, run_dir, threads)
    all_subs = sorted(set(recon.get("subdomains", []) + new_subs))
    recon["all_subdomains"] = all_subs
    log(f"{len(all_subs)} unique subdomains after merge", "ok", "active")

    log("Live host detection (httpx)", phase="active")
    live = GAL.phase_live_hosts(all_subs, run_dir, threads, timeout)
    recon["live_hosts"] = live
    log(f"{len(live)} live hosts", "ok", "active")

    log("Port scan (nmap)", phase="active")
    recon["nmap"] = GAL.phase_port_scan(target, run_dir, ports)
    log(f"{len(recon['nmap'].get('open_ports', []))} open ports", "ok", "active")

    log("Directory discovery (ffuf/gobuster)", phase="active")
    recon["dir_bust"] = GAL.phase_dir_bust(live, run_dir, wordlist, threads)
    total_paths = sum(len(v) for v in recon["dir_bust"].values())
    log(f"{total_paths} paths across {len(recon['dir_bust'])} hosts", "ok", "active")

    log("Vulnerability signatures (nuclei)", phase="active")
    recon["nuclei"] = GAL.phase_nuclei(target, live, run_dir, severity)
    log(f"{len(recon['nuclei'])} nuclei findings", "ok", "active")

    log("CORS + exposed-VCS checks", phase="active")
    recon["misc"] = GAL.phase_misc_checks(target, live, run_dir)
    log(f"{len(recon['misc'])} config findings", "ok", "active")

    log("Subdomain takeover candidates", phase="active")
    recon["takeover_candidates"] = GAL.phase_takeover_check(all_subs, run_dir)
    crit = [t for t in recon["takeover_candidates"] if t.get("severity") == "CRITICAL"]
    log(f"{len(crit)} critical takeover candidates", "ok", "active")

    return recon
