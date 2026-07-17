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

from ..core.scope import split_host_port


def _wordlist() -> str:
    wl = os.getenv("ROUNDTABLE_WORDLIST", "/app/wordlists/common.txt")
    p = Path(wl)
    if p.exists():
        return str(p)
    # Repo fallback for non-container runs.
    local = Path(__file__).resolve().parents[2] / "wordlists" / "common.txt"
    return str(local)


def _ensure_target_live(target: str, recon: dict, log) -> None:
    """
    httpx can intermittently miss a single host:port target (esp. via the docker
    host-gateway). Guarantee the target is registered as a live host by reusing
    passive recon's own HTTP probe result, so results are deterministic.
    """
    from ..core.scope import normalize_target

    hp = normalize_target(target)
    if any(hp in (h.get("url") or "") for h in recon.get("live_hosts", [])):
        return
    http = recon.get("http") or {}
    if http.get("ok"):
        url = (http.get("final_url") or (("https://" if http.get("is_https") else "http://") + hp)).rstrip("/")
        recon.setdefault("live_hosts", []).append({
            "url": url,
            "status-code": http.get("status"),
            "title": "",
            "tech": [],
            "webserver": (http.get("headers") or {}).get("server", ""),
        })
        log(f"target registered as live host from passive HTTP probe: {url}", "ok", "active")


def run_active(target: str, run_dir: Path, recon: dict, log, cfg: dict, run_config: dict = None, scope: dict = None) -> dict:
    from ..core import runconfig

    rc = runconfig.normalize(run_config)
    sp = runconfig.speed_profile(rc)
    en = lambda t: runconfig.tool_enabled(rc, t)

    threads = int(sp["threads"] or cfg.get("threads", 10))
    timeout = int(cfg.get("timeout", 8))
    severity = cfg.get("nuclei_severity", "medium,high,critical")
    ports = cfg.get("ports", "80,443,8080,8443,8888,3000,5000,9090,9200,27017,6379,5432,3306,2375,5601")
    wordlist = _wordlist()

    host, port = split_host_port(target)
    if port and port not in ports.split(","):
        ports = f"{port},{ports}"  # make sure the target's own port is scanned

    enabled = [t for t in runconfig.TOOLS if en(t)]
    log(f"enabled tools: {', '.join(enabled) or 'none'}  ·  speed={rc['speed']}", "info", "active")

    log("Subdomain enumeration (subfinder + amass)", phase="active")
    if en("subfinder") or en("amass"):
        new_subs = GAL.phase_subdomain_enum(host, run_dir, threads, use_subfinder=en("subfinder"), use_amass=en("amass"))
    else:
        new_subs = []
        log("subdomain enumeration disabled by toggles", "info", "active")
    all_subs = sorted(set(recon.get("subdomains", []) + new_subs))
    recon["all_subdomains"] = all_subs
    # Always probe the exact target (incl. host:port) so a single app is detected
    # even when it has no subdomains (e.g. juice-shop:3000).
    probe = sorted(set(all_subs + [target]))

    # Respect out-of-scope: never send active traffic to a discovered host that
    # matches a program's out-of-scope rule (e.g. an imported HackerOne scope).
    if scope and (scope.get("out_of_scope") or scope.get("in_scope")):
        from ..core import scope as scope_mod
        kept, dropped = [], []
        for h in probe:
            ok, _ = scope_mod.in_scope(h, scope)
            (kept if ok else dropped).append(h)
        if dropped:
            log(f"scope filter: skipping {len(dropped)} out-of-scope host(s) (e.g. {', '.join(dropped[:3])})", "warn", "active")
        probe = kept or [target]
        recon["all_subdomains"] = [s for s in all_subs if s in set(kept)]
    log(f"{len(recon['all_subdomains'])} subdomains (+ target) → probing {len(probe)}", "ok", "active")

    log("Live host detection (httpx)", phase="active")
    if en("httpx"):
        live = GAL.phase_live_hosts(probe, run_dir, threads, timeout, extra=sp["httpx_extra"])
    else:
        live = []
        log("httpx disabled by toggle — no live-host detection", "info", "active")
    recon["live_hosts"] = live
    _ensure_target_live(target, recon, log)
    live = recon["live_hosts"]
    log(f"{len(live)} live hosts", "ok", "active")

    log("Port scan (nmap)", phase="active")
    recon["nmap"] = GAL.phase_port_scan(host, run_dir, ports, timing=sp["nmap_timing"]) if en("nmap") else {}
    log(f"{len(recon['nmap'].get('open_ports', []))} open ports", "ok", "active")

    log("Directory discovery (ffuf/gobuster)", phase="active")
    recon["dir_bust"] = GAL.phase_dir_bust(live, run_dir, wordlist, threads, extra=sp["ffuf_extra"]) if en("ffuf") else {}
    total_paths = sum(len(v) for v in recon["dir_bust"].values())
    log(f"{total_paths} paths across {len(recon['dir_bust'])} hosts", "ok", "active")

    log("Vulnerability signatures (nuclei)", phase="active")
    recon["nuclei"] = GAL.phase_nuclei(host, live, run_dir, severity, extra=sp["nuclei_extra"]) if en("nuclei") else []
    log(f"{len(recon['nuclei'])} nuclei findings", "ok", "active")

    log("CORS + exposed-VCS checks", phase="active")
    recon["misc"] = GAL.phase_misc_checks(host, live, run_dir)
    log(f"{len(recon['misc'])} config findings", "ok", "active")

    log("Subdomain takeover candidates", phase="active")
    recon["takeover_candidates"] = GAL.phase_takeover_check(all_subs, run_dir)
    crit = [t for t in recon["takeover_candidates"] if t.get("severity") == "CRITICAL"]
    log(f"{len(crit)} critical takeover candidates", "ok", "active")

    return recon
