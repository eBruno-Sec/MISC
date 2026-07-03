"""
GAWAIN  //  Phase 3.5 — Manual Hunting Instructor
Reads all recon data and produces a prioritized, step-by-step
manual hunting playbook. Sends NO packets. You execute each step by hand.
"""

import json
from pathlib import Path

# Reuse Lancelot's OpenRouter caller
from lancelot import call_openrouter

R="\033[91m"; Y="\033[93m"; G="\033[92m"; C="\033[96m"; M="\033[95m"; BOLD="\033[1m"; RST="\033[0m"

def ok(m):  print(f"  {G}[+]{RST} {m}")
def info(m):print(f"  {C}[*]{RST} {m}")
def warn(m):print(f"  {Y}[!]{RST} {m}")
def err(m): print(f"  {R}[-]{RST} {m}")

SYSTEM_PROMPT = """You are a world-class bug bounty mentor training a hunter one step at a time.
You are given reconnaissance data for an authorized target. Produce a MANUAL hunting playbook
the hunter executes BY HAND. You never run anything yourself. Every step is a single, concrete
action the hunter performs, then reports back before moving on.

Output a numbered playbook. For EACH step provide exactly this block:

STEP N: <short action title>
  TARGET:   <exact URL, host, parameter, or asset to work on>
  WHY:      <one line: why this is worth testing based on the recon data>
  DO:       <the exact manual action: the precise Burp Suite steps, the exact curl
            command to type, the exact browser action, or the exact payload to place
            where. Be literal. Give copy-paste-ready commands.>
  LOOK FOR: <the specific response, string, status code, timing, or behavior that
            confirms a finding>
  IF FOUND: <what it means, severity, and the single next action to escalate to PoC>

Rules:
- Order steps by bounty potential and likelihood, highest first.
- Ground every step in the ACTUAL recon data provided. Reference real hosts, real
  subdomains, real tech, real missing headers. No generic filler steps.
- Prefer manual Burp Suite and curl workflows. One payload or action per step.
- Include injection tests (XSS, SQLi, SSTI, open redirect, IDOR, SSRF) ONLY as manual
  steps the hunter chooses to run, with the exact payload and where it goes.
- Include JS analysis steps: which JS files to open, what regex to grep for
  (API keys, S3 buckets, internal endpoints, tokens).
- Include auth and access-control tests (IDOR, forced browsing, JWT tampering) where
  the data supports it.
- Include one final step: how to write the PoC and which program severity to claim.
- Plain text only. No markdown. No emojis. Keep each step tight.
- Aim for 15 to 25 steps."""

def build_gawain_prompt(target, percival_data, galahad_data):
    s = [f"TARGET: {target}", ""]

    # Tech + headers drive injection/framework choices
    http = percival_data.get("http", {})
    if http.get("ok"):
        h = http.get("headers", {})
        missing = [n for n in ["strict-transport-security","content-security-policy",
                   "x-frame-options","x-content-type-options","referrer-policy",
                   "permissions-policy"] if n not in h]
        s.append(f"MISSING SECURITY HEADERS: {missing}")
        if h.get("server"):       s.append(f"SERVER: {h['server']}")
        if h.get("x-powered-by"): s.append(f"X-POWERED-BY: {h['x-powered-by']}")
        if h.get("set-cookie"):   s.append(f"SET-COOKIE: {h['set-cookie'][:200]}")

    vendors = percival_data.get("vendors", [])
    if vendors:
        s.append(f"TECH STACK: {[(v['name'],v['cat']) for v in vendors]}")

    # High-value subdomains
    sub_cats = percival_data.get("sub_cats", {})
    for cat in ["CI/CD & DevOps","Security Infrastructure","Admin & Management",
                "Payment & Financial","Exposed Dev/Test","Data & Storage"]:
        if cat in sub_cats:
            names = [x["name"] for x in sub_cats[cat]][:12]
            s.append(f"SUBDOMAINS [{cat}]: {names}")

    em = percival_data.get("email", {})
    s.append(f"SPF: {em.get('spf','MISSING')}  DMARC: {em.get('dmarc','MISSING')}")

    if galahad_data:
        live = galahad_data.get("live_hosts", [])
        if live:
            lite = [{"url": x.get("url"), "status": x.get("status-code"),
                     "tech": x.get("tech",[]), "title": x.get("title","")[:40]}
                    for x in live[:20]]
            s.append(f"LIVE HOSTS: {json.dumps(lite)}")

        nmap = galahad_data.get("nmap", {})
        if nmap.get("open_ports"):
            s.append(f"OPEN PORTS: {nmap['open_ports'][:20]}")

        nuclei = galahad_data.get("nuclei", [])
        if nuclei:
            nl = [{"name": n.get("info",{}).get("name","") or n.get("raw","")[:50],
                   "severity": n.get("info",{}).get("severity","?"),
                   "host": n.get("host","")} for n in nuclei[:20]]
            s.append(f"NUCLEI FINDINGS: {json.dumps(nl)}")

        misc = galahad_data.get("misc", [])
        if misc:
            s.append(f"CORS/VCS: {json.dumps(misc[:10])}")

        db = galahad_data.get("dir_bust", {})
        for url, paths in list(db.items())[:5]:
            if paths:
                s.append(f"PATHS ON {url}: {[p.get('url','') for p in paths[:12]]}")

        to = [t for t in galahad_data.get("takeover_candidates",[]) if t.get("severity")=="CRITICAL"]
        if to:
            s.append(f"TAKEOVER CANDIDATES: {to[:8]}")

    return "\n".join(s)

def run_gawain(target, results, cfg):
    ai      = cfg.get("ai", {})
    api_key = ai.get("api_key","")
    model   = ai.get("model","meta-llama/llama-3.3-70b-instruct:free")
    timeout = ai.get("timeout", 60)

    if not api_key or api_key == "YOUR_KEY_HERE":
        warn("No OpenRouter API key. Skipping Gawain playbook.")
        return {"skipped": True, "reason": "No API key"}

    percival = results.get("percival", {})
    galahad  = results.get("galahad", {})

    info("Building manual hunting playbook prompt...")
    user_prompt = build_gawain_prompt(target, percival, galahad)

    info(f"Generating step-by-step playbook (model: {model})...")
    try:
        content, usage, model_used = call_openrouter(
            api_key, model, SYSTEM_PROMPT, user_prompt, timeout
        )
    except Exception as e:
        err(f"Gawain error: {e}")
        return {"error": str(e)}

    ok(f"Playbook generated. Model: {model_used}")

    print(f"\n{M}{BOLD}{'='*64}{RST}")
    print(f"{M}{BOLD}  GAWAIN  //  MANUAL HUNTING PLAYBOOK{RST}")
    print(f"{M}{BOLD}  Execute one step at a time. The tool sends nothing.{RST}")
    print(f"{M}{BOLD}{'='*64}{RST}\n")
    print(content)
    print(f"\n{M}{BOLD}{'='*64}{RST}\n")

    return {
        "model": model_used,
        "playbook": content,
        "usage": usage,
    }
