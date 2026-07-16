"""
GALAHAD  //  Phase 2 — Active Enumeration
subfinder, amass, httpx, nmap, ffuf/gobuster, nuclei.
ACTIVE: sends packets to target. Only run within authorized scope.
"""

import subprocess
import shutil
import json
import os
from pathlib import Path

R="\033[91m"; Y="\033[93m"; G="\033[92m"; C="\033[96m"; BOLD="\033[1m"; RST="\033[0m"

def ok(m):  print(f"  {G}[+]{RST} {m}")
def info(m):print(f"  {C}[*]{RST} {m}")
def warn(m):print(f"  {Y}[!]{RST} {m}")
def err(m): print(f"  {R}[-]{RST} {m}")

def has(tool): return bool(shutil.which(tool))

def run_cmd(cmd, outfile=None, timeout=300):
    try:
        if outfile:
            with open(outfile, "w") as f:
                r = subprocess.run(cmd, shell=True, stdout=f, stderr=subprocess.DEVNULL, timeout=timeout)
        else:
            r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return r.returncode, getattr(r, "stdout", ""), getattr(r, "stderr", "")
    except subprocess.TimeoutExpired:
        warn(f"Timeout ({timeout}s) on: {cmd[:60]}...")
        return -1, "", "timeout"
    except Exception as e:
        return -1, "", str(e)

def read_lines(path):
    p = Path(path)
    if not p.exists():
        return []
    return [l.strip() for l in p.read_text().splitlines() if l.strip()]

# ─── SUBDOMAIN ENUM ────────────────────────────────────────────────────────────
def phase_subdomain_enum(domain, run_dir, threads, use_subfinder=True, use_amass=True):
    info("Subdomain enumeration (subfinder + amass)...")
    all_subs = set()

    # subfinder
    sf_out = run_dir / "subfinder_subs.txt"
    if use_subfinder and has("subfinder"):
        run_cmd(f"subfinder -d {domain} -silent -o {sf_out} -t {threads}", timeout=180)
        subs = read_lines(sf_out)
        all_subs.update(subs)
        ok(f"subfinder: {len(subs)} subdomains")
    elif not use_subfinder:
        info("subfinder disabled by toggle — skipping")
    else:
        warn("subfinder not found — skipping")

    # amass passive only (no active brute-force to stay safe by default)
    am_out = run_dir / "amass_subs.txt"
    if use_amass and has("amass"):
        run_cmd(f"amass enum -passive -d {domain} -o {am_out} -timeout 3", timeout=240)
        subs = read_lines(am_out)
        all_subs.update(subs)
        ok(f"amass: {len(subs)} subdomains")
    elif not use_amass:
        info("amass disabled by toggle — skipping")
    else:
        warn("amass not found — skipping")

    # merge with Percival's crt.sh results (passed in)
    merged_file = run_dir / "all_subdomains.txt"
    merged_file.write_text("\n".join(sorted(all_subs)))
    ok(f"Total unique subdomains: {len(all_subs)}")
    return sorted(all_subs)

# ─── LIVE HOST DETECTION ───────────────────────────────────────────────────────
def phase_live_hosts(subs, run_dir, threads, timeout, extra=""):
    info("Live host detection via httpx...")
    if not has("httpx"):
        warn("httpx not found — skipping live host detection")
        return []

    if not subs:
        warn("No subdomains to probe")
        return []

    sub_input = run_dir / "all_subdomains.txt"
    sub_input.write_text("\n".join(subs))

    live_out  = run_dir / "live_hosts.txt"
    live_json = run_dir / "live_hosts.json"

    cmd = (
        f"httpx -l {sub_input} -silent "
        f"-status-code -title -tech-detect -content-length -web-server "
        f"-json -o {live_json} "
        f"-threads {threads} -timeout {timeout} {extra}"
    ).strip()
    run_cmd(cmd, timeout=300)

    hosts = []
    if live_json.exists():
        for line in live_json.read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                hosts.append(json.loads(line))
            except:
                pass

    # Also write plain list
    live_out.write_text("\n".join(h.get("url","") for h in hosts))
    ok(f"Live hosts: {len(hosts)}")
    for h in hosts[:10]:
        status = h.get("status-code","?")
        title  = h.get("title","")[:40]
        tech   = ",".join(h.get("tech",[])[:3])
        print(f"    {C}{h.get('url','')}{RST}  [{status}] {title} {G}{tech}{RST}")
    if len(hosts) > 10:
        info(f"  ... and {len(hosts)-10} more. See {live_json}")
    return hosts

# ─── PORT SCAN ─────────────────────────────────────────────────────────────────
def phase_port_scan(domain, run_dir, ports, timing="-T4"):
    info(f"Port scan via nmap (ports: {ports})...")
    if not has("nmap"):
        warn("nmap not found — skipping port scan")
        return {}

    nmap_out = run_dir / "nmap_scan.xml"
    nmap_txt = run_dir / "nmap_scan.txt"

    cmd = (
        f"nmap -sV -sC {timing} -p {ports} "
        f"--open -oX {nmap_out} -oN {nmap_txt} {domain}"
    )
    rc, stdout, _ = run_cmd(cmd, timeout=300)

    result = {"raw_file": str(nmap_txt), "xml_file": str(nmap_out)}
    if nmap_txt.exists():
        result["summary"] = nmap_txt.read_text()
        open_ports = [l for l in result["summary"].splitlines() if "/tcp" in l and "open" in l]
        result["open_ports"] = open_ports
        ok(f"Nmap complete. Open ports: {len(open_ports)}")
        for p in open_ports[:10]:
            print(f"    {G}{p.strip()}{RST}")
    else:
        warn("Nmap output not found")
    return result

# ─── DIRECTORY BUST ────────────────────────────────────────────────────────────
def _catch_all_sig(url, timeout=6):
    """
    Probe a random non-existent path. If the app answers it as if it existed
    (SPA catch-all / soft-404), return that (status,length) signature so we can
    filter identical directory-busting hits. Redirects are NOT followed, to
    match ffuf/gobuster behaviour.
    """
    import urllib.request, urllib.error, ssl, random, string

    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k):
            return None

    rand = "rt_" + "".join(random.choices(string.ascii_lowercase + string.digits, k=22))
    ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    opener = urllib.request.build_opener(_NoRedirect, urllib.request.HTTPSHandler(context=ctx))
    req = urllib.request.Request(f"{url.rstrip('/')}/{rand}", headers={"User-Agent": "RoundTable/1.0"})
    try:
        with opener.open(req, timeout=timeout) as r:
            return {"status": getattr(r, "status", 200), "length": len(r.read(2_000_000))}
    except urllib.error.HTTPError as e:
        try:
            body = e.read(2_000_000)
        except Exception:
            body = b""
        return {"status": e.code, "length": len(body)}
    except Exception:
        return None


def _is_catch_all(finding, sig):
    if not sig:
        return False
    if finding.get("status") != sig["status"]:
        return False
    fl = finding.get("length")
    if fl is None:
        return True  # same status, no length info (gobuster) → treat as catch-all
    return abs(fl - sig["length"]) <= max(24, int(sig["length"] * 0.05))


def phase_dir_bust(live_hosts, run_dir, wordlist, threads, extra=""):
    info("Directory busting via ffuf...")
    if not live_hosts:
        warn("No live hosts to bust")
        return {}

    if not has("ffuf") and not has("gobuster"):
        warn("ffuf and gobuster not found — skipping directory busting")
        return {}

    results = {}
    targets = live_hosts[:5]  # limit to avoid scan flooding

    for host in targets:
        url = host.get("url", "")
        if not url:
            continue

        # Soft-404 / SPA catch-all calibration: apps that 200 on everything.
        sig = _catch_all_sig(url)
        if sig:
            info(f"catch-all signature for {url}: status={sig['status']} len~{sig['length']} (will filter matches)")

        safe_name = url.replace("https://", "").replace("http://", "").replace("/", "_").replace(":", "_")
        out_json = run_dir / f"ffuf_{safe_name}.json"

        if has("ffuf"):
            # -ac = ffuf auto-calibration (its own wildcard/soft-404 filter).
            cmd = (
                f"ffuf -u {url}/FUZZ -w {wordlist} "
                f"-t {threads} -mc 200,201,301,302,401,403 -ac "
                f"-o {out_json} -of json -s {extra}"
            ).strip()
        else:
            out_txt = run_dir / f"gobuster_{safe_name}.txt"
            cmd = (
                f"gobuster dir -u {url} -w {wordlist} "
                f"-t {threads} -q -o {out_txt} "
                f"--status-codes 200,201,301,302,401,403"
            )
            out_json = out_txt

        run_cmd(cmd, timeout=180)

        findings = []
        if out_json.exists():
            try:
                if has("ffuf"):
                    data = json.loads(out_json.read_text())
                    findings = [{"url": r.get("url", ""), "status": r.get("status", 0), "length": r.get("length", 0)}
                                for r in data.get("results", [])]
                else:
                    for line in out_json.read_text().splitlines():
                        if line.strip():
                            findings.append({"url": line.strip()})
            except Exception:
                pass

        # Post-filter catch-all matches (belt-and-suspenders over ffuf -ac; also
        # covers gobuster). If nearly everything matches, drop it all as noise.
        raw = len(findings)
        filtered = [f for f in findings if not _is_catch_all(f, sig)]
        dropped = raw - len(filtered)
        if dropped:
            warn(f"{url}: filtered {dropped}/{raw} catch-all/soft-404 hits")
        findings = filtered

        results[url] = findings
        if findings:
            ok(f"{url}: {len(findings)} paths found")
            for f in findings[:5]:
                print(f"    {G}{f.get('url','')} [{f.get('status','')}]{RST}")

    return results

# ─── NUCLEI SCAN ───────────────────────────────────────────────────────────────
def phase_nuclei(domain, live_hosts, run_dir, severity, extra=""):
    info(f"Nuclei vulnerability scan (severity: {severity})...")
    if not has("nuclei"):
        warn("nuclei not found — skipping vuln scan")
        return []

    targets_file = run_dir / "nuclei_targets.txt"
    targets = [domain] + [h.get("url","") for h in live_hosts[:20] if h.get("url")]
    targets_file.write_text("\n".join(targets))

    nuclei_out  = run_dir / "nuclei_results.txt"
    nuclei_json = run_dir / "nuclei_results.json"

    cmd = (
        f"nuclei -l {targets_file} "
        f"-severity {severity} "
        f"-o {nuclei_out} "
        f"-jsonl -je {nuclei_json} "
        f"-silent -nc {extra}"
    ).strip()
    run_cmd(cmd, timeout=600)

    findings = []
    if nuclei_json.exists():
        raw = nuclei_json.read_text().strip()
        if raw:
            parsed = None
            try:
                # -je writes a JSON array; -jsonl writes one object per line.
                parsed = json.loads(raw)
            except Exception:
                parsed = None
            if isinstance(parsed, list):
                findings = [x for x in parsed if isinstance(x, dict)]
            elif isinstance(parsed, dict):
                findings = [parsed]
            else:
                for line in raw.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                        if isinstance(obj, dict):
                            findings.append(obj)
                    except Exception:
                        pass
    if not findings and nuclei_out.exists():
        findings = [{"raw": l} for l in nuclei_out.read_text().splitlines() if l.strip()]

    ok(f"Nuclei findings: {len(findings)}")
    for f in findings[:10]:
        if not isinstance(f, dict):
            continue
        info_b = f.get("info", {}) if isinstance(f.get("info"), dict) else {}
        name  = info_b.get("name", "") or str(f.get("raw", ""))[:80]
        sev   = info_b.get("severity", "?")
        host  = f.get("host", "")
        color = R if sev in ("critical","high") else Y if sev == "medium" else G
        print(f"    {color}[{sev.upper()}]{RST} {name}  {C}{host}{RST}")
    return findings

# ─── VCS content validators (defeat SPA catch-all false positives) ─────────────
def _looks_html(b):
    s = (b or "").lstrip().lower()
    return s.startswith("<!doctype") or s.startswith("<html") or "<script" in s[:300] or "<body" in s[:300]

def _git_head_ok(b):
    b = (b or "").strip()
    return b.startswith("ref:") or (len(b) == 40 and all(c in "0123456789abcdef" for c in b.lower()))

def _svn_entries_ok(b):
    b = (b or "").strip()
    return b[:12].strip().split("\n")[0].isdigit() or b.startswith("<?xml")

def _hg_requires_ok(b):
    return any(k in (b or "") for k in ("revlogv1", "dotencode", "fncache", "generaldelta", "sparserevlog", "store"))


# ─── CORS & VCS CHECK ──────────────────────────────────────────────────────────
def phase_misc_checks(domain, live_hosts, run_dir):
    info("Checking CORS misconfiguration and exposed VCS...")
    findings = []

    for host in live_hosts[:10]:
        url = host.get("url","")
        if not url:
            continue

        # CORS check
        try:
            import urllib.request, ssl
            req = urllib.request.Request(url)
            req.add_header("Origin", "https://evil.com")
            req.add_header("User-Agent", "RoundTable/1.0")
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with urllib.request.urlopen(req, timeout=6, context=ctx) as r:
                acao = r.headers.get("access-control-allow-origin","")
                acac = r.headers.get("access-control-allow-credentials","")
                if acao in ("*", "https://evil.com"):
                    severity = "HIGH" if (acao == "https://evil.com" and acac.lower()=="true") else "MEDIUM"
                    findings.append({
                        "type": "CORS Misconfiguration",
                        "url": url,
                        "severity": severity,
                        "detail": f"ACAO: {acao}  ACAC: {acac}",
                    })
                    warn(f"[{severity}] CORS misconfiguration: {url}  ACAO={acao}")
        except:
            pass

        # VCS exposure — CONTENT-validated so a SPA catch-all (200-for-everything)
        # cannot fake it. We confirm the body actually looks like VCS metadata.
        for path, valid in [
            ("/.git/HEAD", _git_head_ok),
            ("/.svn/entries", _svn_entries_ok),
            ("/.hg/requires", _hg_requires_ok),
        ]:
            try:
                req = urllib.request.Request(f"{url}{path}")
                req.add_header("User-Agent", "RoundTable/1.0")
                with urllib.request.urlopen(req, timeout=5, context=ctx) as r:
                    if r.status != 200:
                        continue
                    body = r.read(4096).decode("utf-8", "ignore")
                    if _looks_html(body) or not valid(body):
                        continue  # SPA catch-all / not real VCS content
                    findings.append({
                        "type": "Exposed VCS",
                        "url": f"{url}{path}",
                        "severity": "HIGH",
                        "detail": f"VCS content confirmed at {path}",
                    })
                    err(f"[HIGH] Exposed VCS: {url}{path}")
            except:
                pass

    ok(f"Misc checks complete. Findings: {len(findings)}")
    return findings

# ─── SUBDOMAIN TAKEOVER CANDIDATES ────────────────────────────────────────────
def phase_takeover_check(subs, run_dir):
    info("Checking subdomain takeover candidates...")
    # Common fingerprints for dangling CNAME targets
    TAKEOVER_SIGS = [
        ("There is no app here","Heroku"),
        ("NoSuchBucket","AWS S3"),
        ("The specified bucket does not exist","AWS S3"),
        ("Repository not found","Bitbucket"),
        ("Help Center Closed","Zendesk"),
        ("Sorry, we could not find your page","GitHub Pages"),
        ("No settings were found for this company","Intercom"),
        ("This UserVoice subdomain is currently available","UserVoice"),
        ("project not found","GitLab"),
        ("This page is reserved","Fastly"),
    ]

    candidates = []
    import urllib.request, ssl

    for sub in subs[:50]:  # limit to avoid flooding
        try:
            import socket
            socket.setdefaulttimeout(4)
            socket.gethostbyname(sub)
        except socket.gaierror:
            # NXDOMAIN or unresolved — could be dangling
            candidates.append({"subdomain": sub, "reason": "DNS NXDOMAIN", "severity": "MEDIUM"})
            continue
        except:
            continue

        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            req = urllib.request.Request(f"https://{sub}")
            req.add_header("User-Agent","RoundTable/1.0")
            with urllib.request.urlopen(req, timeout=5, context=ctx) as r:
                body = r.read(2048).decode("utf-8", errors="ignore")
                for sig, provider in TAKEOVER_SIGS:
                    if sig.lower() in body.lower():
                        candidates.append({
                            "subdomain": sub,
                            "reason": f"Takeover fingerprint: {provider}",
                            "severity": "CRITICAL",
                        })
                        err(f"[CRITICAL] Takeover candidate: {sub} ({provider})")
                        break
        except:
            pass

    ok(f"Takeover check complete. Candidates: {len(candidates)}")
    return candidates

# ─── MAIN ──────────────────────────────────────────────────────────────────────
def run_galahad(domain, run_dir, cfg, percival_data):
    run_dir  = Path(run_dir)
    scan_cfg = cfg.get("scan", {})
    threads  = scan_cfg.get("threads", 10)
    timeout  = scan_cfg.get("timeout", 8)
    severity = scan_cfg.get("nuclei_severity", "medium,high,critical")
    ports    = scan_cfg.get("ports", "80,443,8080,8443,8888,3000,5000")
    wordlist = Path(cfg.get("scan",{}).get("wordlist","wordlists/common.txt"))
    if not wordlist.is_absolute():
        wordlist = Path(__file__).parent.parent / wordlist

    data = {}

    # Use Percival's crt.sh subs as seed + expand with subfinder/amass
    seed_subs = percival_data.get("subdomains", [])
    new_subs  = phase_subdomain_enum(domain, run_dir, threads)
    all_subs  = sorted(set(seed_subs + new_subs))
    data["all_subdomains"] = all_subs
    ok(f"Total subdomains after merge: {len(all_subs)}")

    # Live host detection
    live_hosts = phase_live_hosts(all_subs, run_dir, threads, timeout)
    data["live_hosts"] = live_hosts

    # Port scan on root domain + top targets
    data["nmap"] = phase_port_scan(domain, run_dir, ports)

    # Directory busting
    data["dir_bust"] = phase_dir_bust(live_hosts, run_dir, str(wordlist), threads)

    # Nuclei
    data["nuclei"] = phase_nuclei(domain, live_hosts, run_dir, severity)

    # CORS + VCS
    data["misc"] = phase_misc_checks(domain, live_hosts, run_dir)

    # Takeover candidates
    data["takeover_candidates"] = phase_takeover_check(all_subs, run_dir)

    # Save
    out = run_dir / "galahad_raw.json"
    out.write_text(json.dumps(data, indent=2, default=str))
    ok(f"Galahad raw data saved: {out}")

    return data
